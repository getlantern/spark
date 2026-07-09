# Spark Desktop Settings Screen — Design

**Status:** Approved (2026-07-08)

**Goal:** A Figma-matched Settings screen (`/settings`) reachable from the home
hamburger, hosting the three rows Spark can back today — **Appearance**, **Language**,
and **Ad blocking** — with the two nav rows opening sub-screen pickers. Fully
i18n-native and RTL-correct from day one. Builds on the i18n foundation (PR #57) and the
ad-block backend (PR #56).

## Context

- The UI is `gui-tauri/` (SvelteKit static-adapter WebView in a Tauri app). Current
  routes: `+page.svelte` (home), `/routing`, `/servers`, `/split-tunneling` (+`/apps`,
  +`/websites`). There is **no** Settings route yet.
- The home app bar (`src/routes/+page.svelte`) has an **inert** hamburger (top-left) and
  account avatar (top-right) — neither navigates today.
- **i18n foundation (PR #57, prerequisite):** `$lib/i18n` exports `_` (`$_('key')`),
  `setLocale(code)`, `locale` store, `isRtl`, and `SUPPORTED` (the 20 locales with
  `code`/`name`/`nativeName`/`rtl`). Locale persists in `localStorage['spark.locale']`.
- **Ad-block backend (PR #56, prerequisite):** core matcher + `RwLock<bool>` gate,
  Apple/Android FFI, and Tauri plugin commands; the flag rides
  `providerConfiguration["adBlock"]` and is applied live (like routing-mode / split-tunnel).
  The **TS backend seam does not exist yet** — `SparkBackend`/`TauriBackend` have no
  ad-block methods. This spec adds them.
- **Theme today:** purely OS-following via `@media (prefers-color-scheme: dark)` in
  `src/routes/+layout.svelte`. There is **no** manual override. "Appearance"
  (System/Light/Dark) is therefore net-new front-end work, not backend wiring.
- **Lantern `.po` already ships translated keys** for every Settings label:
  `settings`, `appearance`, `language`, `system`, `light`, `dark`, `built_in_ad_blocking`
  (verified present in fa/ar/etc.). Reusing them means the screen is localized in all 19
  non-English locales with **no new translation debt**.

## Decisions (confirmed with stakeholder)

1. **Structure: flat minimal, Figma-styled.** One `/settings` screen matching the Figma
   (node 19-1850) visual language — back-arrow "Settings" app bar, grouped rows, leading
   icons, value-on-the-right for nav rows. It shows exactly three functional rows:
   Appearance, Language (Group 1, nav rows) and Ad blocking (Group 2, toggle). The
   Figma's Pro / Account / Sign-In / Unbounded / Support / Check-for-Updates / Restore
   rows are **omitted** — no backend in Spark; add them when backends exist.
2. **Pickers: sub-screen lists.** Both Language (`/settings/language`, 20 options) and
   Appearance (`/settings/appearance`, 3 options) are full push screens with a back
   arrow and radio-style rows, consistent with the existing `/servers` screen. Tapping a
   row applies the change live and pops back.
3. **Entry point: the home hamburger** (top-left) navigates to `/settings`. The avatar
   stays inert (reserved for a future account screen).
4. **Appearance is a real theme override** (System/Light/Dark), default **System**
   (preserves today's OS-following behavior). Persisted in `localStorage['spark.theme']`
   — pure front-end state, zero FFI, symmetric with the i18n locale store.
5. **Theme mechanism: attribute-based, mirroring i18n** (approach A). A `data-theme`
   attribute on `<html>`; the existing dark palette moves from the media query to
   `:root[data-theme="dark"]`. Chosen over CSS `light-dark()` (large palette churn) and a
   class-based variant (no advantage).
6. **Ad blocking rides `providerConfiguration["adBlock"]`** via PR #56's plugin commands;
   the toggle is optimistic with revert-on-failure. A new TS seam
   (`getAdBlock`/`setAdBlock`) fronts it.
7. **Sequencing:** implementation branches off `main` **after #57 and #56 merge**. This
   spec + its plan are authored now on `fisk/settings-screen` and rebased onto `main`
   when those land.
8. **No new npm dependencies.** The theme store is a hand-rolled Svelte store.

## Architecture

### Routes (`src/routes/settings/`)

```
settings/
  +page.svelte              # Settings hub (Appearance, Language, Ad blocking)
  language/+page.svelte     # locale picker (20 native names, radio)
  appearance/+page.svelte   # theme picker (System / Light / Dark, radio)
```

- **`/settings`** — app bar (back → `/`, title `$_('settings')`). Group 1 (nav rows):
  - *Appearance* — icon, `$_('appearance')`, value = label for the **chosen** mode
    (`$_('system'|'light'|'dark')`), chevron → `/settings/appearance`.
  - *Language* — icon, `$_('language')`, value = the current locale's `nativeName` (from
    `SUPPORTED`), chevron → `/settings/language`.
  Group 2 (toggle row):
  - *Ad blocking* — icon, `$_('built_in_ad_blocking')`, a switch (the same component as
    the split-tunneling screen) bound to the ad-block backend.
- **`/settings/language`** — radio list over `SUPPORTED`, each row showing `nativeName`
  (and `name` as secondary), the current `$locale` checked. Tap → `setLocale(code)` +
  `goto('/settings')`. Live: `$_` and `dir` update reactively (no reload).
- **`/settings/appearance`** — radio list System / Light / Dark
  (`$_('system'|'light'|'dark')`), the current `$theme` checked. Tap → `setTheme(t)` +
  `goto('/settings')`. Live: `data-theme` updates reactively.

### Theme module (`src/lib/theme.ts`) — new

```ts
export type Theme = "system" | "light" | "dark";
// writable store `theme`, initialized from localStorage['spark.theme'] (default 'system')
export const theme;                                  // Svelte store<Theme>
export function setTheme(t: Theme): void;            // persist + theme.set(t)
export function resolveTheme(t: Theme, prefersDark: boolean): "light" | "dark";
```

- `resolveTheme('system', prefersDark) === prefersDark ? 'dark' : 'light'`; explicit
  `'light'`/`'dark'` pass through.
- `setTheme` writes `localStorage['spark.theme']` (guarded try/catch) and updates the store.
- Store init reads localStorage once; unsupported/missing → `'system'`.

### Layout integration (`src/routes/+layout.svelte`) — modify

- Add a reactive `let prefersDark = $state(...)` seeded from
  `matchMedia('(prefers-color-scheme: dark)').matches`, updated by a `change` listener so
  `system` tracks the OS live.
- Add an `$effect` that sets `document.documentElement.dataset.theme =
  resolveTheme($theme, prefersDark)` — alongside the existing `dir`/`lang` effect.
- **CSS refactor (values unchanged):** move the current
  `@media (prefers-color-scheme: dark) { :global(:root) { … } }` block to
  `:global(:root[data-theme="dark"]) { … }`. The light palette stays on `:global(:root)`.
  Net behavior with default `theme='system'` is identical to today.

### Zero-flash (`src/app.html`) — modify

A tiny inline `<script>` reads `localStorage['spark.theme']`, resolves against
`matchMedia`, and sets `document.documentElement.dataset.theme` **before first paint** —
so a dark-mode user never sees a light flash during the i18n render-gate. Kept minimal and
dependency-free.

### Ad-block backend seam

- **`src/lib/spark_backend.ts`** — `SparkBackend` gains:
  ```ts
  getAdBlock(): Promise<boolean>;
  setAdBlock(enabled: boolean): Promise<void>;
  ```
  `MockBackend` gets an `adBlock: boolean` field (default `false`) with get/set.
- **`src/lib/tauri_backend.ts`** — `TauriBackend` implements them over
  `invoke("plugin:spark-vpn|get_ad_block_enabled")` and
  `invoke("plugin:spark-vpn|set_ad_block_enabled", { enabled })`.
  **Prerequisite to verify at implementation:** confirm PR #56's exact command name and
  argument shape, and that a **getter** command exists (returns the persisted flag). If
  #56 shipped only a setter, the plan adds the getter to the plugin (Rust) as its first
  task. `setAdBlock` persists + live-applies (the NE reads `providerConfiguration["adBlock"]`).
- The `/settings` toggle is **optimistic with revert-on-failure** (the `/split-tunneling/apps`
  pattern): flip UI state, call `setAdBlock`, revert + snackbar on error.

### Entry point (`src/routes/+page.svelte`) — modify

The home hamburger button gains `onclick={() => goto("/settings")}`. No other home change.

## i18n

All Settings labels reuse **translated** Lantern keys — no new keys required:

| String | Key | Source |
| --- | --- | --- |
| Settings (title) | `settings` | Lantern (translated) |
| Appearance | `appearance` | Lantern (translated) |
| Language | `language` | Lantern (translated) |
| System / Light / Dark | `system` / `light` / `dark` | Lantern (translated) |
| Ad blocking (row) | `built_in_ad_blocking` | Lantern (translated) |
| Back (aria) | `back` | Spark overlay (from #57) |

Native language names in the picker come from `SUPPORTED[].nativeName` (not translated
keys — they are self-labels). If a snackbar string is needed for an ad-block save failure,
add one Spark overlay key (e.g. `err_ad_block`, English-until-translated).

## RTL

All three screens follow the established pattern: logical-property CSS
(`text-align: start`, `padding-inline-start`, `margin-inline-*`), and
`:global([dir="rtl"])` flips for the back-arrow SVG and any nav chevrons. Radio rows
mirror naturally. Theme is orthogonal to direction (a locale can be RTL in either theme).

## Error handling

- **Ad-block get/set failure:** caught; `getAdBlock` keeps last-known state, `setAdBlock`
  reverts the optimistic toggle and shows a snackbar. Never leaves the UI out of sync with
  persisted state.
- **Theme:** `localStorage` unavailable → default `system`, all access try/caught. An
  unknown stored value falls back to `system`.
- **Language:** delegated to the shipped `setLocale` (already guarded).

## Testing

- **Unit (Vitest)** `src/lib/theme.test.ts`: `resolveTheme` mapping
  (`system`+prefersDark→`dark`, `system`+!prefersDark→`light`, explicit `light`/`dark`
  pass through); `setTheme` persists to `localStorage`; store default is `system`; unknown
  stored value → `system`.
- **Key-coverage guard** (from #57) automatically fails if any `$_('key')` on the new
  screens lacks an English entry — all keys used here are reused Lantern keys, so it stays
  green.
- **`svelte-check`** and **`vite build`** green.
- **Headless smoke (Chrome, preview build):** home hamburger → `/settings`; Appearance →
  Dark sets `<html data-theme="dark">` and the dark palette applies; Language → `fa`
  switches labels live and sets `dir="rtl"`; Ad blocking toggle flips and persists (mock),
  reverts on a forced failure.

## Components / files

**Add:**
- `gui-tauri/src/routes/settings/+page.svelte`
- `gui-tauri/src/routes/settings/language/+page.svelte`
- `gui-tauri/src/routes/settings/appearance/+page.svelte`
- `gui-tauri/src/lib/theme.ts`, `gui-tauri/src/lib/theme.test.ts`

**Modify:**
- `gui-tauri/src/routes/+layout.svelte` — `data-theme` effect + CSS refactor (media query
  → attribute selector).
- `gui-tauri/src/app.html` — zero-flash inline theme script.
- `gui-tauri/src/routes/+page.svelte` — hamburger → `/settings`.
- `gui-tauri/src/lib/spark_backend.ts` — `SparkBackend` + `MockBackend` ad-block methods.
- `gui-tauri/src/lib/tauri_backend.ts` — `TauriBackend` ad-block invokes.
- `gui-tauri/src/lib/i18n/spark/en.json` — only if an ad-block-error snackbar key is added.

**Reuse:** `$lib/i18n` (`_`, `setLocale`, `locale`, `isRtl`, `SUPPORTED`); the split-tunnel
switch styling; the servers-screen radio-row + app-bar patterns; the optimistic-toggle
pattern from `/split-tunneling/apps`.

## Dependencies & sequencing

- Requires **PR #57** (i18n foundation) and **PR #56** (ad-block backend) merged to `main`.
  Implementation branches off `main` after both land; this spec/plan rebase onto `main`
  then. No new npm dependencies. No Rust changes **unless** #56 lacks an ad-block getter
  command, in which case the plan adds it as its first task.

## Out of scope (future work)

- Pro / Account / Sign-In / Upgrade / Restore Purchase rows (no auth/billing backend).
- Unbounded Settings, Support, Check for Updates, Lantern Projects link (no backend).
- Per-theme custom accent or scheduling; translating any new Spark overlay strings.
- Mobile-specific Settings layout (the Tauri-on-mobile UI shares this Svelte screen;
  validated separately).
