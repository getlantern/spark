// The Unbounded volunteer-proxy tab is strictly opt-in and server-gated: it only
// surfaces when the server enables the feature AND the user hasn't hidden it. Both
// conditions default off, so an unknown feature flag keeps the tab invisible.
export function unboundedVisible(serverEnabled: boolean, hidden: boolean): boolean {
  return serverEnabled && !hidden;
}
