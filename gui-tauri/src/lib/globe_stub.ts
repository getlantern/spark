// Stand-in for the globe renderer on MOBILE builds.
//
// `globe.gl` (plus its `three` dependency) is a ~1.9 MB lazy chunk that exists only for the Unbounded
// volunteer tab — and that tab is desktop-only: the `unbounded_*` commands aren't registered on
// iOS/Android, so `unboundedAvailable()` fails closed and the tab never renders. Shipping the chunk in
// the IPA/APK anyway is pure dead weight (~740 KB compressed in the iOS build), so vite.config.js
// aliases the renderer to this module when TAURI_ENV_PLATFORM is ios/android.
//
// Deliberately `undefined` rather than a throwing getter: `Globe.svelte` reads `.default` and calls it,
// which fails immediately and lands in its try/catch, degrading to the static placeholder. That keeps
// the failure path identical to a genuine chunk-load failure, which is already handled.
export default undefined;
