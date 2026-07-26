import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";
import { fileURLToPath } from "node:url";

const host = process.env.TAURI_DEV_HOST;

// Tauri sets TAURI_ENV_PLATFORM for `tauri build` / `tauri dev`
// ("ios" | "android" | "darwin" | "windows" | "linux").
//
// Mobile builds drop the globe renderer: `globe.gl` and its `three` dependency are a ~1.9 MB lazy
// chunk that exists only for the Unbounded volunteer tab, and that tab is desktop-only — the
// `unbounded_*` commands aren't registered on iOS/Android, so `unboundedAvailable()` fails closed and
// the tab never renders. Shipping the chunk anyway was ~740 KB of never-executed code in the IPA.
// `Globe.svelte` already degrades to its static placeholder when the renderer can't load, so the stub
// takes the same path as a genuine chunk-load failure.
const isMobile = ["ios", "android"].includes(process.env.TAURI_ENV_PLATFORM ?? "");
const globeStub = fileURLToPath(new URL("./src/lib/globe_stub.ts", import.meta.url));
/** @type {Record<string, string>} */
const mobileAliases = isMobile
  ? {
      "globe.gl": globeStub,
      "topojson-client": globeStub,
      "world-atlas/countries-110m.json": globeStub,
    }
  : {};

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [sveltekit()],

  resolve: { alias: mobileAliases },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
