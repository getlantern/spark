// Stand-in for the globe renderer on MOBILE builds.
//
// `globe.gl` (plus its `three` dependency) is a ~1.9 MB lazy chunk that exists only for the Unbounded
// volunteer tab — and that tab is desktop-only: the `unbounded_*` commands aren't registered on
// iOS/Android, so `unboundedAvailable()` fails closed and the tab never renders. Shipping the chunk in
// the IPA/APK anyway is pure dead weight (~740 KB compressed in the iOS build), so vite.config.js
// aliases the renderer to this module when TAURI_ENV_PLATFORM is ios/android.
//
// Importing this SUCCEEDS — it just yields no renderer. `Globe.svelte` therefore cannot rely on its
// try/catch (that only covers a rejected import); it explicitly checks `typeof GlobeGl !== "function"`
// after the await and degrades to the static placeholder. Keep those two in step: if this module ever
// exports something callable, that guard stops firing.
export default undefined;
