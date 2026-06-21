# Spark — Tauri UI shell

The macOS (and future cross-platform) desktop client UI for Spark, built with **Tauri v2 + SvelteKit** (adapter-static SPA, `ssr=false`). The Rust side drives the macOS NetworkExtension directly via `objc2` (NE Model A — see `../docs/adr/0008-tauri-ui.md`); the system extension lives in `../platforms/apple`.

- `src/routes/+page.svelte` — the connect screen (matches `getlantern/lantern`'s Flutter home).
- `src/lib/` — the `SparkBackend` interface, a `MockBackend` (browser/dev), and the `TauriBackend` that drives the Rust commands over `invoke()`.
- `src-tauri/` — the Tauri app: NE commands (`spark_status`/`spark_connect`/`spark_disconnect`), config resolution, and the embedded system extension.

## Develop

```bash
npm install
npm run tauri dev      # run the full app (Rust + webview); drives the real NE backend on macOS
npm run dev            # frontend only in a browser (uses MockBackend) — fast UI iteration
```

## Check

```bash
npm run check          # svelte-check (type + template checks)
(cd src-tauri && cargo check && cargo clippy && cargo fmt --all --check)
```

## Build a signed + notarized DMG

The product build (Tauri app + embedded, signed, notarized system extension) is driven by the repo-level script, not `tauri build` directly:

```bash
../packaging/macos/build-tauri-dmg.sh           # signed + notarized → ../dist/Spark.dmg
SKIP_NOTARIZE=1 ../packaging/macos/build-tauri-dmg.sh   # fast signed-only local build
```

It needs a Developer ID Application identity in the keychain and notary creds (`AC_USERNAME`/`AC_PASSWORD` or a `NOTARY_PROFILE`). See the script header for env knobs.

## Recommended IDE setup

[VS Code](https://code.visualstudio.com/) + [Svelte](https://marketplace.visualstudio.com/items?itemName=svelte.svelte-vscode) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).
