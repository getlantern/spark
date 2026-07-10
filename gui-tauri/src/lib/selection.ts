import { writable } from "svelte/store";
import { isTauri, TauriBackend } from "./tauri_backend";
import { MockBackend, type SparkBackend } from "./spark_backend";

// The user's selection *mode*, shared between the home tile and the selection screen:
//   null   → auto (the latency-ranked "Smart location")
//   number → a manually pinned pool index
//
// The core resets a fresh tunnel's pin to auto (None), so defaulting to null matches a newly
// started tunnel. This drives the auto-vs-pinned display (the ⚡ bolt and the ✓ marker); which
// member actually carries traffic is `isCurrent` from the live snapshot. `initSelectedIndex()`
// reloads this from the plugin on mount, so the mode now survives a UI reload (in Tauri); it is
// still not persisted across an app restart (the plugin holds it in memory) — harmless, since a
// tunnel restart also resets the pin to auto.
export const selectedIndex = writable<number | null>(null);

/// Load the persisted pin (tray/window shared state) into the store, so it survives a UI reload and
/// matches the tray. Constructs a backend inline, like the routes do.
export async function initSelectedIndex(): Promise<void> {
  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();
  try {
    selectedIndex.set(await backend.getSelectedServer());
  } catch (err) {
    // Keep the current value on a transient read failure rather than clobbering a good pin. The
    // store already defaults to null (auto) on first load, so a failure there leaves it at auto.
    console.error("[selection] getSelectedServer failed, keeping current value:", err);
  }
}
