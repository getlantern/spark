import { writable } from "svelte/store";

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
