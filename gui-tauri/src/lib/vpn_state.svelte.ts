// Last-known VPN connected state, shared across routes. The bottom tab bar's VPN status
// dot lives on both the home and Unbounded screens; without a shared cache each screen
// would mount with a default (disconnected) and only flip to the real state after its
// first async status poll — a visible one-frame flicker of the dot every tab switch.
// Module state survives client-side navigation, so whichever screen last polled seeds the
// dot for the next one, and it renders correct immediately.
let connected = $state(false);

export const vpnState = {
  get connected() {
    return connected;
  },
  set connected(v: boolean) {
    connected = v;
  },
};
