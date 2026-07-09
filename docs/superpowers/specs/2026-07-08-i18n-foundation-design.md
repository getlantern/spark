# Spark Desktop i18n Foundation — Design

**Status:** Approved (2026-07-08)

**Goal:** Localize the Spark desktop (Tauri + SvelteKit) UI into all 20 Lantern
languages — including the RTL scripts (Farsi, Arabic, Urdu, Pashto) — by reusing
Lantern's existing translated strings, with live in-app language switching. This is
the **foundation** phase: stand up the i18n layer and retrofit every current screen.
The Settings screen (which will host the Language picker) is a **separate, later
spec** that builds on this.

## Context

- The UI is `gui-tauri/` (SvelteKit static-adapter WebView in a Tauri app). Current
  routes: `+page.svelte` (home/hub), `/routing`, `/servers`, `/split-tunneling`
  (+`/apps`, +`/websites`). All strings are currently hardcoded English.
- Theme is CSS-variable based in `+layout.svelte` (Lantern palette) with an
  OS-following dark palette already in place.
- Lantern ships **20 gettext `.po` locales** at `lantern/assets/locales/*.po`
  (`ar bn en es es-cu fa fr fr-ca hi ms my ps ru th tk tr ur vi zh-Hans zh-Hant`),
  keyed by semantic ids (`settings`, `upgrade_to_pro`, …). Four are RTL: `fa ar ur ps`.

## Decisions (confirmed with stakeholder)

1. **Sequencing:** i18n foundation first (this spec), Settings screen after. The new
   Settings screen will be i18n-native from day one.
2. **Library:** `svelte-i18n` (runtime message dictionaries, `$_('key')` store, ICU
   formatting, live locale switch). Chosen over Paraglide for simplest integration
   with an external `.po` source and lowest risk for a small UI.
3. **String source:** **vendor** Lantern's 20 `.po` into the spark repo and convert
   them at build time to per-locale JSON. Ship all 20; missing keys fall back to
   English. Spark-specific strings not in Lantern's `.po` live in a separate Spark
   overlay.
4. **Persistence:** the chosen locale lives in the WebView's **`localStorage`**, not
   the Rust plugin durable store — locale is pure front-end state the tunnel core/NE
   never needs (unlike routing-mode/ad-block, which ride `providerConfiguration`).
   Zero FFI.
5. **RTL:** set `dir="rtl"` on the root for RTL locales and convert layout CSS to
   **logical properties** (`margin-inline`, `inset-inline`, `text-align: start`).
6. **Scope:** infra + retrofit **all current screens** (home, routing, servers,
   split-tunneling ×3) so the app is coherently localized at the end of this phase.
   The Language **picker UI** is deferred to the Settings spec; this phase ships the
   locale store + OS detection + live-switch API + RTL so the picker just calls it.

## Architecture

### Message layer (`src/lib/i18n/`)

```
src/lib/i18n/
  po/                     # vendored: the 20 Lantern .po files (source of truth)
    en.po ar.po fa.po …
  spark/                  # Spark-specific strings NOT in Lantern's .po
    en.json               # authored (source); other locales fall back to en
  generated/              # build output (gitignored) — {locale}.json per locale
    en.json fa.json …
  index.ts                # register() all locales + init(); rtl set; helpers
  locales.ts              # the supported-locale list + display names + RTL set
```

- **`index.ts`** registers each supported locale with a lazy loader that dynamically
  imports the merged dictionary (Lantern base + Spark overlay), and calls
  `init({ fallbackLocale: 'en', initialLocale: resolveInitialLocale() })`. It also
  exports `setLocale(code)` (persists + `locale.set`) and a `$derived` `isRtl`.
- **`locales.ts`** is the single source of the supported set: `[{code, name,
  nativeName, rtl}]` (e.g. `{code:'fa', name:'Persian', nativeName:'فارسی',
  rtl:true}`). `RTL = {fa, ar, ur, ps}`.

### Build pipeline

- `scripts/po-to-json.mjs` (Node, uses **`gettext-parser`** — new dev dep) reads each
  `src/lib/i18n/po/*.po`, extracts `msgid → msgstr` (skipping the header entry and
  empty `msgstr`, which fall back to English), and writes
  `src/lib/i18n/generated/{locale}.json`.
- Wired into `package.json` as `i18n:build`, invoked by `predev`, `prebuild`, and
  `precheck` hooks. `generated/` is **gitignored** (always regenerated; no drift).
- The per-locale loader in `index.ts` merges `generated/{locale}.json` (Lantern base)
  with `spark/{locale}.json` when present, Spark keys taking precedence/extending.

### Locale resolution (startup)

`resolveInitialLocale()`:
1. `localStorage['spark.locale']` if set and supported → use it.
2. else OS locale (`@tauri-apps/plugin-os` `locale()` if available, else
   `navigator.language`) matched to the nearest supported code (exact, then base
   language, e.g. `fa-IR` → `fa`, `zh` → `zh-Hans`).
3. else `en`.

Switching: `setLocale(code)` writes `localStorage['spark.locale']`, calls
`locale.set(code)`, which reactively updates `$_` everywhere and the `dir` attribute.
No reload.

### RTL

- `+layout.svelte`: `<svelte:element>` / root wrapper gets `dir={isRtl ? 'rtl' :
  'ltr'}` bound to the current locale.
- Convert existing screens' layout CSS from physical → logical properties. Flip
  directional glyphs (nav chevrons `›`, back arrows) with `[dir="rtl"] { transform:
  scaleX(-1) }` on those specific elements.

## Components / files

**Add:**
- `gui-tauri/src/lib/i18n/po/*.po` (vendored, 20 files)
- `gui-tauri/src/lib/i18n/spark/en.json` (Spark-specific strings)
- `gui-tauri/src/lib/i18n/locales.ts`, `gui-tauri/src/lib/i18n/index.ts`
- `gui-tauri/scripts/po-to-json.mjs`
- Vitest specs: converter (`scripts/po-to-json.test.mjs` or under `src/lib/i18n`),
  key-coverage test.

**Modify:**
- `gui-tauri/package.json` — deps (`svelte-i18n`, `@tauri-apps/plugin-os` if not
  present; `gettext-parser` dev), `i18n:build` script + `predev`/`prebuild`/`precheck`
  hooks.
- `gui-tauri/src/routes/+layout.svelte` — import + init i18n before render, `dir`
  attribute, logical-property CSS.
- `gui-tauri/src/routes/**/+page.svelte` — replace hardcoded strings with `$_('key')`.
- `.gitignore` — `src/lib/i18n/generated/`.

**No Rust changes** (locale persists in localStorage).

## Key mapping

- Reuse Lantern `.po` keys where a matching string exists (`settings`,
  `upgrade_to_pro`, …).
- Spark strings absent from Lantern (e.g. `routing_mode`, `split_tunneling`,
  `ad_blocking`, `smart`, `full`, server-selection labels) → new keys in
  `spark/en.json`. Establish a naming convention (snake_case, screen-prefixed where
  helpful: `routing_smart_title`).
- An initial audit maps each hardcoded string in the current screens to either an
  existing Lantern key or a new Spark key; the audit table lives in the plan.

## Error handling

- Missing key → svelte-i18n emits the key id and (in dev) warns; `fallbackLocale:
  'en'` covers missing translations. The key-coverage test prevents shipping a
  `$_('…')` with no English entry.
- `.po` parse failure in the build script → hard-fail the build (a broken locale must
  not silently ship as empty).
- OS-locale API failure → caught, falls through to `navigator.language` → `en`.

## Testing

- **Unit (Vitest):** `po-to-json` converter against a `.po` fixture — msgid/msgstr
  extraction, header skipped, empty `msgstr` omitted (→ English fallback), UTF-8 +
  escaped quotes/newlines preserved.
- **Key coverage:** scan `src/**/*.svelte` for `$_('literal')` / `$format('literal')`
  usages and assert each exists in `spark/en.json` ∪ `generated/en.json`.
- **`svelte-check`** green (generated JSON present via `precheck`).
- **Manual RTL smoke:** switch to `fa`, verify the whole app mirrors (nav, rows,
  chevrons, text alignment) and reads correctly.

## New dependencies

- `svelte-i18n` (runtime) — approved.
- `gettext-parser` (dev, build script only).
- `@tauri-apps/plugin-os` (runtime) **only if** not already present — used for OS
  locale detection; if adding it is undesirable, fall back to `navigator.language`
  alone (acceptable) and drop this dep.

## Out of scope (later specs)

- The Settings screen and the Language **picker UI** (next spec; will call
  `setLocale`).
- Translating Spark-specific strings into non-English locales (they fall back to
  English until translated; a translation task/pipeline is future work).
- Android/iOS UI localization (this is the desktop WebView; mobile shares the Svelte
  UI via the Tauri-on-mobile pivot but is validated separately).
