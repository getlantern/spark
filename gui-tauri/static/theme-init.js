// Zero-flash appearance: resolve the persisted theme and set data-theme on <html> BEFORE first
// paint, so a dark-mode user never sees a light flash during the i18n render-gate. Served as an
// external asset from 'self' (NOT inline) to satisfy the Tauri CSP (`script-src 'self'`, no
// 'unsafe-inline'). Mirrors src/lib/theme.ts resolveTheme; +layout.svelte re-applies data-theme
// reactively after hydration. Referenced render-blocking in <head> so it runs before <body> paints.
(function () {
  try {
    var t = localStorage.getItem("spark.theme") || "system";
    var dark =
      t === "dark" ||
      (t !== "light" && matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
  } catch (e) {
    /* localStorage/matchMedia unavailable — layout applies the theme after hydration */
  }
})();
