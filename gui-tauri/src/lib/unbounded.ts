// The Unbounded volunteer-proxy tab is strictly opt-in and server-gated: it only
// surfaces when the server enables the feature AND the user hasn't hidden it. Both
// conditions default off, so an unknown feature flag keeps the tab invisible.
export function unboundedVisible(serverEnabled: boolean, hidden: boolean): boolean {
  return serverEnabled && !hidden;
}

/**
 * Which peers in a status snapshot are NEW arrivals worth celebrating.
 *
 * A pure function with its state passed in, rather than three flags inside the page's `$effect`,
 * because getting it wrong is invisible on screen — a false burst on page open looks exactly like a
 * real one — and because the two ways it went wrong are both about sequences of snapshots, which is
 * only testable if the sequence can be driven directly. See `unbounded.test.ts`.
 *
 * `state` is mutated in place: `seen` accumulates the session ids already celebrated, and `baselined`
 * records that the first real snapshot has been absorbed.
 */
export interface ArrivalTracker {
  seen: Set<string>;
  baselined: boolean;
}

export function newArrivalTracker(): ArrivalTracker {
  return { seen: new Set(), baselined: false };
}

/**
 * @param loaded whether `peers` came from a real snapshot rather than the page's initial placeholder.
 *   The FIRST real snapshot is the baseline and never celebrates: someone opening the screen while
 *   people are already connected has not just been joined by all of them. Keying this off "the first
 *   call" instead would baseline against the placeholder's empty list and then celebrate everyone on
 *   the next call, which is the same bug one tick later.
 */
export function arrivals<T extends { sessionId: string }>(
  state: ArrivalTracker,
  peers: readonly T[],
  loaded: boolean,
): T[] {
  const live = new Set(peers.map((p) => p.sessionId));
  // Forget peers that have gone, so a reconnecting session can be celebrated again. UNCONDITIONALLY:
  // pruning only on ticks that had no arrivals left a peer that departed in the same tick as another
  // arrived stuck in the set, and its reconnect then went unnoticed.
  for (const id of state.seen) if (!live.has(id)) state.seen.delete(id);
  if (!loaded) return [];
  if (!state.baselined) {
    state.baselined = true;
    for (const id of live) state.seen.add(id);
    return [];
  }
  const fresh = peers.filter((p) => !state.seen.has(p.sessionId));
  for (const p of fresh) state.seen.add(p.sessionId);
  return fresh;
}
