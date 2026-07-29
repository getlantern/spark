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

/** Pin a pool index (or `null` for auto): echo it locally at once, so the ✓ moves under the user's
 *  finger, then hand it to the tunnel. A failed live apply (no pool yet) leaves the echo standing. */
export async function selectServer(index: number | null): Promise<void> {
  picksInFlight++;
  selectedIndex.set(index);
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
  if (pinned) selectedIndex.set(pinned.index);
}

/** Push the local pin to the tunnel when a live snapshot shows it isn't in effect. Picks made before
 *  there was a pool to pin (chosen while disconnected, or applied while the tunnel was still
 *  bootstrapping) fail at the time, and a fresh tunnel starts on auto — so without this the UI keeps an
 *  intent the tunnel never took up. Runs off the same poll that reads the snapshot, so it retries until
 *  the pool exists, and terminates: a pin the pool no longer contains drops to auto rather than
 *  retrying forever. */
export async function reapplyIfDropped(servers: ServerInfo[]): Promise<void> {
  if (picksInFlight > 0) return;
  const desired = get(selectedIndex);
  if (desired == null) return; // auto — nothing to apply
  // `isCurrent` marks a live snapshot: the tunnel always names exactly one current member, while the
  // pre-connect builders leave it false throughout. Pinning without a pool just fails.
  if (!servers.some((s) => s.isCurrent) || servers.some((s) => s.isPinned)) return;
  if (!servers.some((s) => s.index === desired)) {
    selectedIndex.set(null); // the pool dropped that member; auto is the honest reading
    return;
  }
  await selectServer(desired);
}
