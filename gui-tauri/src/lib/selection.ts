import { writable } from "svelte/store";
import { isTauri, TauriBackend } from "./tauri_backend";
import { MockBackend, type SparkBackend } from "./spark_backend";

// The user's selection *mode*, shared between the home tile and the selection screen:
//   null   → auto (the latency-ranked "Smart location")
//   number → a manually pinned pool index
//
// The core resets a fresh tunnel's pin to auto (None), so defaulting to null matches a newly
// started tunnel. This drives the auto-vs-pinned display (the ⚡ bolt and the ✓ marker); which
// member actually carries traffic is `isCurrent` from the live snapshot. Mode is not persisted
// across a full UI reload — a known v1 limitation, harmless because a tunnel restart also resets
// the pin to auto.
export const selectedIndex = writable<number | null>(null);

/// Load the persisted pin (tray/window shared state) into the store, so it survives a UI reload and
/// matches the tray. Constructs a backend inline, like the routes do.
export async function initSelectedIndex(): Promise<void> {
  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();
  try {
    selectedIndex.set(await backend.getSelectedServer());
  } catch (err) {
    console.error("[selection] getSelectedServer failed, defaulting to auto:", err);
  }
}
