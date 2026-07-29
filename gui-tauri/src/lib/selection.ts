import { get, writable } from "svelte/store";
import { isTauri, TauriBackend } from "./tauri_backend";
import { MockBackend, type SparkBackend, type ServerInfo } from "./spark_backend";

// The user's selection *mode*, shared between the home tile and the selection screen:
//   null   → auto (the latency-ranked "Smart location")
//   number → a manually pinned pool index
//
// A pool index is only meaningful within one config generation. When a refresh reorders or drops
// members, a held index silently names a different server — which is how the home tile came to show
// a location the tunnel wasn't using. So this is a MIRROR of the tunnel's own pin (which the tunnel
// tracks by identity and reports as `isPinned`), refreshed from every live snapshot via
// `syncFromSnapshot`, not an independent record of the pin.
//
// `initSelectedIndex()` seeds it from the plugin on mount so the mode survives a UI reload and matches
// the tray. It is still not persisted across an app restart, and a fresh tunnel starts on auto.
export const selectedIndex = writable<number | null>(null);

function newBackend(): SparkBackend {
  return isTauri() ? new TauriBackend() : new MockBackend();
}

/// Load the persisted pin (tray/window shared state) into the store, so it survives a UI reload and
/// matches the tray. Constructs a backend inline, like the routes do.
export async function initSelectedIndex(): Promise<void> {
  try {
    selectedIndex.set(await newBackend().getSelectedServer());
  } catch (err) {
    // Keep the current value on a transient read failure rather than clobbering a good pin. The
    // store already defaults to null (auto) on first load, so a failure there leaves it at auto.
    console.error("[selection] getSelectedServer failed, keeping current value:", err);
  }
}

// Picks still being applied. A pick reaches the tunnel asynchronously, so a `servers()` poll issued
// before it lands returns a snapshot that predates it; adopting that would bounce the user's fresh
// choice back for a whole poll interval. While this is non-zero the local echo wins.
let picksInFlight = 0;

// WHICH SERVER the user picked, described the way the UI showed it. An index is only a handle into one
// particular list and cannot be re-applied to another: the pre-connect list is built from the app's own
// `config_raw.json` (an independent `config-new` fetch from the tunnel's, so a different order — see
// `AppleControl::servers`), and a refresh reorders the tunnel's pool too. Re-applying a bare index
// across either boundary pins whatever server happens to occupy that slot, which is the very bug this
// module exists to prevent — so `reapplyIfDropped` resolves this instead.
//
// A location is also the right granularity: the UI offers a flag and a country — city, so that is what
// the user chose. Any member serving it satisfies the intent.
type PickedLocation = { country?: string | null; city?: string | null; name?: string | null };
let picked: PickedLocation | null = null;

function sameLocation(s: ServerInfo, p: PickedLocation): boolean {
  return s.country === p.country && s.city === p.city && s.name === p.name;
}

/** Pin a server (or `null` for auto): echo it locally at once, so the ✓ moves under the user's finger,
 *  then hand it to the tunnel. A failed live apply (no pool yet) leaves the echo standing, and `from`
 *  records which server it was so it can be re-applied to a pool this index doesn't address. */
export async function selectServer(index: number | null, from?: ServerInfo): Promise<void> {
  picksInFlight++;
  selectedIndex.set(index);
  picked =
    index == null || !from ? null : { country: from.country, city: from.city, name: from.name };
  try {
    await newBackend().selectServer(index);
  } catch (err) {
    console.error("[selection] selectServer failed, keeping the local pick:", err);
  } finally {
    picksInFlight--;
  }
}

/** Re-point the store at the pin's CURRENT index, from the tunnel's own snapshot — the fix for an index
 *  outliving the config generation it was chosen in. The tunnel tracks the pin by identity and carries
 *  it across a refresh, so the snapshot's `isPinned` is where that server ended up.
 *
 *  Absence of a pin deliberately does NOT clear the store: it's ambiguous (auto, or a pick that hasn't
 *  reached the tunnel yet — see `reapplyIfDropped`), and pre-connect lists never carry one. Nothing is
 *  lost by keeping it, because the home tile prefers the snapshot's own `isPinned`/`isCurrent` over this
 *  index and so still names the server actually in use. */
export function syncFromSnapshot(servers: ServerInfo[]): void {
  if (picksInFlight > 0) return;
  const pinned = servers.find((s) => s.isPinned);
  if (!pinned) return;
  selectedIndex.set(pinned.index);
  // Track the identity too, so a pin adopted from the tunnel (rather than made here — a UI reload, or
  // the tray) can still be re-applied later.
  picked = { country: pinned.country, city: pinned.city, name: pinned.name };
}

/** Push the local pin to the tunnel when a live snapshot shows it isn't in effect. A pick made before
 *  there was a pool to pin fails at the time (chosen while disconnected, or applied while the tunnel was
 *  still bootstrapping), and a fresh tunnel starts on auto — so without this the UI keeps an intent the
 *  tunnel never took up. Runs off the same poll that reads the snapshot, so it retries until the pool
 *  exists.
 *
 *  Resolves the picked LOCATION in this pool rather than re-using the stored index, which addresses a
 *  different list (see `picked`). Terminates: an unresolvable pick drops to auto instead of retrying
 *  forever, and so does one whose identity was never recorded, since pushing it would be a guess. */
export async function reapplyIfDropped(servers: ServerInfo[]): Promise<void> {
  if (picksInFlight > 0) return;
  if (get(selectedIndex) == null) return; // auto — nothing to apply
  // `isCurrent` marks a live snapshot: the tunnel always names exactly one current member, while the
  // pre-connect builders leave it false throughout. Pinning without a pool just fails.
  if (!servers.some((s) => s.isCurrent) || servers.some((s) => s.isPinned)) return;
  const match = picked && servers.find((s) => sameLocation(s, picked!));
  if (!match) {
    selectedIndex.set(null); // not on offer here (or never identified) — auto is the honest reading
    picked = null;
    return;
  }
  await selectServer(match.index, match);
}
