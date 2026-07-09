# Settings Screen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Figma-matched `/settings` screen (reachable from the home hamburger) hosting Appearance (theme), Language, and Ad blocking, with the two nav rows opening sub-screen pickers — fully i18n-native and RTL-correct.

**Architecture:** Three new SvelteKit routes under `/settings`; a hand-rolled theme store (`data-theme` on `<html>`, localStorage-persisted, default System = today's OS-following behavior); a new ad-block TS backend seam over PR #56's plugin commands. All labels reuse already-translated Lantern `.po` keys. No new npm deps, no Rust changes (unless #56 lacks an ad-block getter — Task 1).

**Tech Stack:** SvelteKit (static adapter, Svelte 5 runes), TypeScript, `svelte-i18n` (from #57), `svelte/store`, `vitest`.

**Spec:** `docs/superpowers/specs/2026-07-08-settings-screen-design.md`

**Branch:** `fisk/settings-screen`. **Prerequisite:** PR #57 (i18n) and PR #56 (ad-block backend) merged to `main`; rebase this branch onto `main` before starting Task 2. All paths relative to `gui-tauri/` unless noted; run `npm`/`node` from `gui-tauri/`.

---

## File Structure

- `gui-tauri/src/lib/theme.ts` — theme store: `Theme` type, `theme` store, `setTheme()`, `resolveTheme()`. Sole owner of appearance state + persistence.
- `gui-tauri/src/lib/theme.test.ts` — Vitest for `resolveTheme` + `setTheme`.
- `gui-tauri/src/routes/settings/+page.svelte` — Settings hub (Appearance + Language nav rows, Ad blocking toggle).
- `gui-tauri/src/routes/settings/appearance/+page.svelte` — theme picker (System/Light/Dark).
- `gui-tauri/src/routes/settings/language/+page.svelte` — locale picker (20 native names).
- Modified: `gui-tauri/src/lib/spark_backend.ts` (ad-block interface + Mock), `gui-tauri/src/lib/tauri_backend.ts` (ad-block invokes), `gui-tauri/src/routes/+layout.svelte` (`data-theme` effect + CSS refactor), `gui-tauri/src/app.html` (zero-flash script), `gui-tauri/src/routes/+page.svelte` (hamburger → `/settings`).

---

## Task 1: Confirm (or add) #56 ad-block plugin commands

**Files:** (verify) `gui-tauri/tauri-plugin-spark-vpn/src/{commands,desktop,mobile}.rs`, `gui-tauri/tauri-plugin-spark-vpn/permissions/`

This task runs after rebasing onto `main` (with #56 merged). The TS seam (Task 2) calls a **getter** and a **setter**; #56 shipped the setter but its command name and the presence of a getter must be confirmed.

- [ ] **Step 1: Discover the ad-block command surface**

Run:
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
grep -rn "ad_block\|adBlock\|AdBlock" gui-tauri/tauri-plugin-spark-vpn/src gui-tauri/tauri-plugin-spark-vpn/permissions
```
Expected: at least a setter command (e.g. `set_ad_block_enabled`) registered in `commands.rs` and exposed in `desktop.rs`/`mobile.rs`, plus a permission entry. Note the exact command name and argument shape (likely `{ enabled: bool }`).

- [ ] **Step 2: Decide getter presence**

If a getter command that returns the persisted flag (e.g. `get_ad_block_enabled`) already exists → **skip to Task 2** (record the exact names). If only a setter exists, add the getter in Steps 3–5, mirroring the existing `get_routing_mode` command.

- [ ] **Step 3: Add the getter command (only if missing)**

Follow the `get_routing_mode` pattern exactly (find it with `grep -rn "get_routing_mode" gui-tauri/tauri-plugin-spark-vpn/src`). In `commands.rs`, add alongside `get_routing_mode`:
```rust
#[tauri::command]
pub(crate) async fn get_ad_block_enabled<R: Runtime>(
    app: AppHandle<R>,
) -> Result<bool> {
    app.spark_vpn().get_ad_block_enabled()
}
```
Register it in the `generate_handler!`/`invoke_handler` list next to `get_routing_mode`, and implement `get_ad_block_enabled(&self) -> Result<bool>` on the desktop and mobile controllers exactly where `get_routing_mode` is implemented (read the persisted flag from the same durable store #56 writes to; default `false`). Add a `get-ad-block-enabled` entry to the permissions/capability files next to the routing-mode ones.

- [ ] **Step 4: Verify the plugin builds (only if Step 3 ran)**

Run:
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
cargo build -p tauri-plugin-spark-vpn
```
Expected: builds clean.

- [ ] **Step 5: Commit (only if Step 3 ran)**

```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/tauri-plugin-spark-vpn/src gui-tauri/tauri-plugin-spark-vpn/permissions
git commit -m "feat(spark-vpn): add get_ad_block_enabled plugin command

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 6: Record the confirmed command names** for Task 2 (getter + setter + setter arg key). If they differ from `get_ad_block_enabled` / `set_ad_block_enabled` / `{ enabled }`, use the real names in Task 2's code.

---

## Task 2: Ad-block backend seam (TDD)

**Files:** Modify `gui-tauri/src/lib/spark_backend.ts`, `gui-tauri/src/lib/tauri_backend.ts`; Test `gui-tauri/src/lib/spark_backend.test.ts`

- [ ] **Step 1: Write the failing test** — create `gui-tauri/src/lib/spark_backend.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { MockBackend } from "./spark_backend";

describe("MockBackend ad-block", () => {
  it("defaults to disabled and round-trips the setting", async () => {
    const b = new MockBackend();
    expect(await b.getAdBlock()).toBe(false);
    await b.setAdBlock(true);
    expect(await b.getAdBlock()).toBe(true);
    await b.setAdBlock(false);
    expect(await b.getAdBlock()).toBe(false);
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `cd gui-tauri && npx vitest run src/lib/spark_backend.test.ts` → FAIL (`getAdBlock` is not a function).

- [ ] **Step 3: Add to the `SparkBackend` interface** — in `gui-tauri/src/lib/spark_backend.ts`, add after the `setExcludedApps` line (before the closing `}` of the interface, ~line 66):
```ts
  /** Whether built-in ad blocking is enabled (persisted; rides providerConfiguration["adBlock"]). */
  getAdBlock(): Promise<boolean>;
  /** Persist + live-apply the ad-block flag. */
  setAdBlock(enabled: boolean): Promise<void>;
```

- [ ] **Step 4: Add the field + methods to `MockBackend`** — in `spark_backend.ts`, add `adBlock: boolean;` to the `mockState` type and `adBlock: false` to its initializer (the object literal ~line 83). Then add these methods to the `MockBackend` class (next to `setExcludedApps`):
```ts
  async getAdBlock(): Promise<boolean> { return mockState.adBlock; }
  async setAdBlock(enabled: boolean): Promise<void> { mockState.adBlock = enabled; }
```

- [ ] **Step 5: Add to `TauriBackend`** — in `gui-tauri/src/lib/tauri_backend.ts`, add these methods (next to `setRoutingMode`), using the command names confirmed in Task 1 (shown here with the expected defaults):
```ts
  async getAdBlock(): Promise<boolean> {
    return await invoke<boolean>("plugin:spark-vpn|get_ad_block_enabled");
  }
  async setAdBlock(enabled: boolean): Promise<void> {
    await invoke("plugin:spark-vpn|set_ad_block_enabled", { enabled });
  }
```

- [ ] **Step 6: Run to verify it passes** — `cd gui-tauri && npx vitest run src/lib/spark_backend.test.ts` → PASS. Then `npm run check` → 0 errors (TauriBackend now satisfies the interface).

- [ ] **Step 7: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/lib/spark_backend.ts gui-tauri/src/lib/tauri_backend.ts gui-tauri/src/lib/spark_backend.test.ts
git commit -m "feat(gui-tauri/settings): ad-block backend seam (get/setAdBlock)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Theme store (TDD)

**Files:** Create `gui-tauri/src/lib/theme.ts`; Test `gui-tauri/src/lib/theme.test.ts`

- [ ] **Step 1: Write the failing test** — create `gui-tauri/src/lib/theme.test.ts`:
```ts
import { describe, it, expect, beforeEach } from "vitest";
import { get } from "svelte/store";
import { resolveTheme, setTheme, theme } from "./theme";

describe("resolveTheme", () => {
  it("passes explicit modes through", () => {
    expect(resolveTheme("dark", false)).toBe("dark");
    expect(resolveTheme("light", true)).toBe("light");
  });
  it("resolves 'system' against the OS preference", () => {
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
  });
});

describe("setTheme", () => {
  beforeEach(() => {
    const store: Record<string, string> = {};
    (globalThis as unknown as { localStorage: Storage }).localStorage = {
      getItem: (k: string) => (k in store ? store[k] : null),
      setItem: (k: string, v: string) => { store[k] = v; },
      removeItem: (k: string) => { delete store[k]; },
      clear: () => { for (const k of Object.keys(store)) delete store[k]; },
      key: () => null,
      length: 0,
    } as Storage;
  });
  it("updates the store and persists the choice", () => {
    setTheme("dark");
    expect(get(theme)).toBe("dark");
    expect(localStorage.getItem("spark.theme")).toBe("dark");
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `cd gui-tauri && npx vitest run src/lib/theme.test.ts` → FAIL (`./theme` missing).

- [ ] **Step 3: Implement** — create `gui-tauri/src/lib/theme.ts`:
```ts
// Appearance state: System (follow OS) / Light / Dark. Pure front-end state persisted in
// localStorage — the tunnel core never needs it (unlike routing/ad-block). Mirrors the i18n
// locale store. The layout maps `theme` -> a `data-theme` attribute on <html>; the dark palette
// keys off `:root[data-theme="dark"]`. Default 'system' preserves the OS-following behavior.
import { writable } from "svelte/store";

export type Theme = "system" | "light" | "dark";

const STORAGE_KEY = "spark.theme";
const THEMES: Theme[] = ["system", "light", "dark"];

function initialTheme(): Theme {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v && (THEMES as string[]).includes(v)) return v as Theme;
  } catch {
    /* localStorage unavailable (SSR / node) */
  }
  return "system";
}

export const theme = writable<Theme>(initialTheme());

export function setTheme(t: Theme): void {
  try {
    localStorage.setItem(STORAGE_KEY, t);
  } catch {
    /* ignore */
  }
  theme.set(t);
}

/** Resolve the effective palette. 'system' follows the OS; explicit modes pass through. */
export function resolveTheme(t: Theme, prefersDark: boolean): "light" | "dark" {
  if (t === "dark") return "dark";
  if (t === "light") return "light";
  return prefersDark ? "dark" : "light";
}
```

- [ ] **Step 4: Run to verify it passes** — `cd gui-tauri && npx vitest run src/lib/theme.test.ts` → PASS (4 assertions).

- [ ] **Step 5: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/lib/theme.ts gui-tauri/src/lib/theme.test.ts
git commit -m "feat(gui-tauri/settings): theme store (system/light/dark + resolveTheme)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Apply `data-theme` in the layout + CSS refactor

**Files:** Modify `gui-tauri/src/routes/+layout.svelte`

- [ ] **Step 1: Add theme wiring to the `<script>`** — in `gui-tauri/src/routes/+layout.svelte`, extend the existing script. After the i18n import line (`import { setupI18n, isRtl, locale, isLoading } from "$lib/i18n";`) add:
```ts
  import { theme, resolveTheme } from "$lib/theme";
```
Then, after the existing `$effect` that sets `lang`/`dir`, add:
```svelte
  // Track the OS dark-mode preference reactively so `theme === "system"` follows it live.
  let prefersDark = $state(false);
  $effect(() => {
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    prefersDark = mql.matches;
    const onChange = (e: MediaQueryListEvent) => (prefersDark = e.matches);
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  });
  $effect(() => {
    document.documentElement.dataset.theme = resolveTheme($theme, prefersDark);
  });
```

- [ ] **Step 2: Refactor the dark palette from a media query to an attribute selector** — in the `<style>` block, replace this exact block:
```css
  @media (prefers-color-scheme: dark) {
    :global(:root) {
      --bg: #16181b;
      --surface: #1e2124;
      --brand: #00bdd6;
      --off: #4b5056;
      --knob: #ffffff;
      --text-primary: #f4f6f7;
      --text-secondary: #c2c7cc;
      --text-tertiary: #9aa0a6;
      --border: #2a2e33;
      --success: #34c759;
      --indicator-off: #3a3f45;
      --shadow: rgba(0, 0, 0, 0.45);
      --bolt: #ffc105;
      --lat-good: #34c759;
      --lat-amber: #b7c94a;
      --lat-slow: #e0a52a;
      --snack-bg: #2e3439;
      --switch-off: #4b5056;
      /* Light-on-dark tints — a black overlay is invisible on the dark surface. */
      --hover: rgba(255, 255, 255, 0.04);
      --pill-bg: rgba(255, 255, 255, 0.08);
    }
  }
```
with (same values, now keyed off the attribute the layout sets):
```css
  /* Dark palette applies when the resolved theme is dark (data-theme is set by +layout.svelte /
     the app.html pre-paint script). 'system' resolves to dark/light against the OS; explicit
     Light/Dark force it. Values identical to the former prefers-color-scheme block. */
  :global(:root[data-theme="dark"]) {
    --bg: #16181b;
    --surface: #1e2124;
    --brand: #00bdd6;
    --off: #4b5056;
    --knob: #ffffff;
    --text-primary: #f4f6f7;
    --text-secondary: #c2c7cc;
    --text-tertiary: #9aa0a6;
    --border: #2a2e33;
    --success: #34c759;
    --indicator-off: #3a3f45;
    --shadow: rgba(0, 0, 0, 0.45);
    --bolt: #ffc105;
    --lat-good: #34c759;
    --lat-amber: #b7c94a;
    --lat-slow: #e0a52a;
    --snack-bg: #2e3439;
    --switch-off: #4b5056;
    /* Light-on-dark tints — a black overlay is invisible on the dark surface. */
    --hover: rgba(255, 255, 255, 0.04);
    --pill-bg: rgba(255, 255, 255, 0.08);
  }
```

- [ ] **Step 3: Build + check** — `cd gui-tauri && npm run check && npm run build` → 0 svelte-check errors, build OK.

- [ ] **Step 4: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/routes/+layout.svelte
git commit -m "feat(gui-tauri/settings): drive theme via data-theme attribute (was OS-only)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Zero-flash theme script in `app.html`

**Files:** Modify `gui-tauri/src/app.html`

- [ ] **Step 1: Add the pre-paint script** — in `gui-tauri/src/app.html`, insert this immediately before `%sveltekit.head%` (inside `<head>`):
```html
    <script>
      // Zero-flash appearance: resolve the persisted theme before first paint so a dark-mode user
      // never sees a light flash during the i18n render-gate. Mirrors src/lib/theme.ts resolveTheme;
      // inline + dependency-free on purpose. +layout.svelte re-applies data-theme reactively after.
      (function () {
        try {
          var t = localStorage.getItem("spark.theme") || "system";
          var dark = t === "dark" || (t !== "light" && matchMedia("(prefers-color-scheme: dark)").matches);
          document.documentElement.dataset.theme = dark ? "dark" : "light";
        } catch (e) {}
      })();
    </script>
```

- [ ] **Step 2: Build** — `cd gui-tauri && npm run build` → build OK (adapter-static inlines app.html).

- [ ] **Step 3: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/app.html
git commit -m "feat(gui-tauri/settings): zero-flash theme resolution before first paint

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Home hamburger opens Settings

**Files:** Modify `gui-tauri/src/routes/+page.svelte`

- [ ] **Step 1: Wire the hamburger** — in `gui-tauri/src/routes/+page.svelte`, change the menu button (currently `<button class="iconbtn" aria-label={$_("menu")}>{@render menu()}</button>`) to:
```svelte
    <button class="iconbtn" aria-label={$_("menu")} onclick={() => goto("/settings")}>{@render menu()}</button>
```
(`goto` is already imported from `$app/navigation` in this file. Leave the account button inert.)

- [ ] **Step 2: Check** — `cd gui-tauri && npm run check` → 0 errors. (The `/settings` route lands in Task 7; svelte-check does not validate `goto` targets, so this passes now.)

- [ ] **Step 3: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/routes/+page.svelte
git commit -m "feat(gui-tauri/settings): home hamburger navigates to /settings

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Settings hub screen

**Files:** Create `gui-tauri/src/routes/settings/+page.svelte`; Modify `gui-tauri/src/lib/i18n/spark/en.json`

- [ ] **Step 1: Add the ad-block error snackbar key** — in `gui-tauri/src/lib/i18n/spark/en.json`, add (valid JSON, keep existing keys):
```
"err_ad_block": "Couldn't update ad blocking"
```
Then `cd gui-tauri && npm run i18n:build`.

- [ ] **Step 2: Create the hub** — `gui-tauri/src/routes/settings/+page.svelte`:
```svelte
<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { MockBackend, type SparkBackend } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";
  import { _, locale } from "$lib/i18n";
  import { SUPPORTED } from "$lib/i18n/locales";
  import { theme } from "$lib/theme";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let adBlock = $state(false);
  let snack = $state<string | null>(null);
  let snackTimer: ReturnType<typeof setTimeout> | undefined;

  onMount(async () => { try { adBlock = await backend.getAdBlock(); } catch {} });

  function showSnack(msg: string) {
    snack = msg;
    clearTimeout(snackTimer);
    snackTimer = setTimeout(() => (snack = null), 2500);
  }

  // Optimistic toggle with revert-on-failure (matches the apps screen).
  async function toggleAdBlock() {
    const prev = adBlock;
    adBlock = !adBlock;
    try {
      await backend.setAdBlock(adBlock);
    } catch {
      adBlock = prev;
      showSnack($_("err_ad_block"));
    }
  }

  const languageLabel = $derived(
    SUPPORTED.find((l) => l.code === $locale)?.nativeName ?? ($locale ?? "English"),
  );
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label={$_("back")} onclick={() => goto("/")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">{$_("settings")}</span>
  </header>

  <div class="scroll">
    <div class="card">
      <button class="row nav" onclick={() => goto("/settings/appearance")}>
        <span class="ic">{@render gear()}</span>
        <div class="meta"><div class="name">{$_("appearance")}</div></div>
        <span class="value">{$_($theme)}</span>
        <span class="chev">{@render chevron()}</span>
      </button>
      <div class="divider"></div>
      <button class="row nav" onclick={() => goto("/settings/language")}>
        <span class="ic">{@render globe()}</span>
        <div class="meta"><div class="name">{$_("language")}</div></div>
        <span class="value">{languageLabel}</span>
        <span class="chev">{@render chevron()}</span>
      </button>
    </div>

    <div class="card" style="margin-top:12px">
      <div class="row toggle-row">
        <span class="ic">{@render shield()}</span>
        <div class="meta"><div class="name">{$_("built_in_ad_blocking")}</div></div>
        <button class="switch" class:on={adBlock} role="switch" aria-checked={adBlock} aria-label={$_("built_in_ad_blocking")} onclick={toggleAdBlock}><span class="knob"></span></button>
      </div>
    </div>
  </div>

  {#if snack}<div class="snack">{snack}</div>{/if}
</main>

{#snippet chevron()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
{/snippet}
{#snippet gear()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
{/snippet}
{#snippet globe()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z"/></svg>
{/snippet}
{#snippet shield()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg>
{/snippet}

<style>
  .app { height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
  .appbar {
    height: 56px; flex-shrink: 0; display: flex; align-items: center; gap: 4px; padding: 0 8px;
    background: var(--bg); border-bottom: 1px solid var(--border);
    box-shadow: 0 4px 12px rgba(0, 97, 98, 0.06);
  }
  .iconbtn {
    width: 40px; height: 40px; border: none; background: none; cursor: pointer;
    display: grid; place-items: center; color: var(--text-tertiary); border-radius: 8px;
  }
  .title { font-size: 19px; font-weight: 700; letter-spacing: -0.2px; color: var(--text-primary); }

  .scroll { flex: 1; overflow-y: auto; padding: 12px 16px 20px; }

  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 14px 16px;
    background: none; border: none; font-family: var(--font); text-align: start;
    transition: background 0.12s ease;
  }
  .row.nav { cursor: pointer; }
  .row.nav:hover { background: var(--hover); }
  .toggle-row { cursor: default; }
  .ic { width: 24px; display: inline-flex; justify-content: center; color: var(--text-secondary); flex-shrink: 0; }
  .meta { flex: 1; min-width: 0; }
  .name {
    font-size: 15px; font-weight: 600; color: var(--text-primary);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .value { font-size: 14px; font-weight: 500; color: var(--text-tertiary); white-space: nowrap; }
  .chev { color: var(--text-tertiary); display: inline-flex; }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  .snack { position: fixed; left: 16px; right: 16px; bottom: 20px; background: var(--snack-bg); color: #fff; padding: 12px 16px; border-radius: 10px; font-size: 14px; text-align: center; box-shadow: 0 6px 24px rgba(0,0,0,.25); }

  /* Small toggle, matched to the split-tunnel screen. */
  .switch {
    width: 46px; height: 28px; border-radius: 999px; border: none; background: var(--switch-off);
    position: relative; cursor: pointer; transition: background 0.15s ease; flex-shrink: 0;
  }
  .switch.on { background: var(--brand, #1f9d55); }
  .knob {
    position: absolute; top: 3px; left: 3px; width: 22px; height: 22px;
    border-radius: 50%; background: #fff; transition: transform 0.15s ease;
  }
  .switch.on .knob { transform: translateX(18px); }

  /* RTL: flip the back-arrow and the nav chevrons; leave the toggle knob LTR (calibrated). */
  :global([dir="rtl"]) .iconbtn svg { transform: scaleX(-1); }
  :global([dir="rtl"]) .chev { transform: scaleX(-1); }
</style>
```

- [ ] **Step 3: Verify** — `cd gui-tauri && npm test && npm run check` → all vitest green (converter + match + coverage + theme + backend), coverage guard confirms every `$_()` key (`settings`, `appearance`, `language`, `system`/`light`/`dark` via `$_($theme)`, `built_in_ad_blocking`, `back`, `err_ad_block`) resolves; 0 svelte-check errors.

Note: the coverage guard's regex reads `$_("literal")`; the dynamic `$_($theme)` is NOT a literal so the guard can't check it — the three keys `system`/`light`/`dark` are exercised by the appearance picker in Task 8 (which uses literals) and all exist in `en.json`, so this is covered.

- [ ] **Step 4: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/routes/settings/+page.svelte gui-tauri/src/lib/i18n/spark/en.json
git commit -m "feat(gui-tauri/settings): Settings hub (Appearance/Language/Ad blocking)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: Appearance picker

**Files:** Create `gui-tauri/src/routes/settings/appearance/+page.svelte`

- [ ] **Step 1: Create the picker** — `gui-tauri/src/routes/settings/appearance/+page.svelte`:
```svelte
<script lang="ts">
  import { goto } from "$app/navigation";
  import { _ } from "$lib/i18n";
  import { theme, setTheme, type Theme } from "$lib/theme";

  const OPTIONS: Theme[] = ["system", "light", "dark"];

  function choose(t: Theme) {
    setTheme(t);
    goto("/settings");
  }
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label={$_("back")} onclick={() => goto("/settings")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">{$_("appearance")}</span>
  </header>

  <div class="scroll">
    <div class="card" role="radiogroup" aria-label={$_("appearance")}>
      {#each OPTIONS as opt, i (opt)}
        {#if i > 0}<div class="divider"></div>{/if}
        <button class="row" role="radio" aria-checked={$theme === opt} onclick={() => choose(opt)}>
          <div class="meta"><div class="name">{$_(opt)}</div></div>
          <span class="radio" class:on={$theme === opt} aria-hidden="true"></span>
        </button>
      {/each}
    </div>
  </div>
</main>

<style>
  .app { height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
  .appbar {
    height: 56px; flex-shrink: 0; display: flex; align-items: center; gap: 4px; padding: 0 8px;
    background: var(--bg); border-bottom: 1px solid var(--border);
    box-shadow: 0 4px 12px rgba(0, 97, 98, 0.06);
  }
  .iconbtn {
    width: 40px; height: 40px; border: none; background: none; cursor: pointer;
    display: grid; place-items: center; color: var(--text-tertiary); border-radius: 8px;
  }
  .title { font-size: 19px; font-weight: 700; letter-spacing: -0.2px; color: var(--text-primary); }

  .scroll { flex: 1; overflow-y: auto; padding: 12px 16px 20px; }
  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 15px 16px;
    background: none; border: none; cursor: pointer; font-family: var(--font); text-align: start;
    transition: background 0.12s ease;
  }
  .row:hover { background: var(--hover); }
  .meta { flex: 1; min-width: 0; }
  .name { font-size: 15px; font-weight: 600; color: var(--text-primary); }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  .radio { width: 22px; height: 22px; border-radius: 50%; border: 2px solid var(--text-tertiary); flex-shrink: 0; position: relative; }
  .radio.on { border-color: var(--brand); }
  .radio.on::after { content: ""; position: absolute; inset: 4px; border-radius: 50%; background: var(--brand); }

  :global([dir="rtl"]) .iconbtn svg { transform: scaleX(-1); }
</style>
```

- [ ] **Step 2: Verify** — `cd gui-tauri && npm test && npm run check` → coverage guard now sees literal `$_("appearance")`, `$_("back")` (and `$_(opt)` is dynamic — the three `system`/`light`/`dark` values it renders all exist); 0 svelte-check errors.

- [ ] **Step 3: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/routes/settings/appearance/+page.svelte
git commit -m "feat(gui-tauri/settings): appearance picker (System/Light/Dark)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: Language picker

**Files:** Create `gui-tauri/src/routes/settings/language/+page.svelte`

- [ ] **Step 1: Create the picker** — `gui-tauri/src/routes/settings/language/+page.svelte`:
```svelte
<script lang="ts">
  import { goto } from "$app/navigation";
  import { _, locale, setLocale } from "$lib/i18n";
  import { SUPPORTED } from "$lib/i18n/locales";

  function choose(code: string) {
    setLocale(code);
    goto("/settings");
  }
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label={$_("back")} onclick={() => goto("/settings")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">{$_("language")}</span>
  </header>

  <div class="scroll">
    <div class="card" role="radiogroup" aria-label={$_("language")}>
      {#each SUPPORTED as l, i (l.code)}
        {#if i > 0}<div class="divider"></div>{/if}
        <button class="row" role="radio" aria-checked={$locale === l.code} onclick={() => choose(l.code)}>
          <div class="meta">
            <div class="name">{l.nativeName}</div>
            <div class="sub">{l.name}</div>
          </div>
          <span class="radio" class:on={$locale === l.code} aria-hidden="true"></span>
        </button>
      {/each}
    </div>
  </div>
</main>

<style>
  .app { height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
  .appbar {
    height: 56px; flex-shrink: 0; display: flex; align-items: center; gap: 4px; padding: 0 8px;
    background: var(--bg); border-bottom: 1px solid var(--border);
    box-shadow: 0 4px 12px rgba(0, 97, 98, 0.06);
  }
  .iconbtn {
    width: 40px; height: 40px; border: none; background: none; cursor: pointer;
    display: grid; place-items: center; color: var(--text-tertiary); border-radius: 8px;
  }
  .title { font-size: 19px; font-weight: 700; letter-spacing: -0.2px; color: var(--text-primary); }

  .scroll { flex: 1; overflow-y: auto; padding: 12px 16px 20px; }
  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 13px 16px;
    background: none; border: none; cursor: pointer; font-family: var(--font); text-align: start;
    transition: background 0.12s ease;
  }
  .row:hover { background: var(--hover); }
  .meta { flex: 1; min-width: 0; }
  .name { font-size: 15px; font-weight: 600; color: var(--text-primary); }
  .sub { margin-top: 2px; font-size: 12px; font-weight: 500; color: var(--text-tertiary); }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  .radio { width: 22px; height: 22px; border-radius: 50%; border: 2px solid var(--text-tertiary); flex-shrink: 0; position: relative; }
  .radio.on { border-color: var(--brand); }
  .radio.on::after { content: ""; position: absolute; inset: 4px; border-radius: 50%; background: var(--brand); }

  :global([dir="rtl"]) .iconbtn svg { transform: scaleX(-1); }
</style>
```

- [ ] **Step 2: Verify** — `cd gui-tauri && npm test && npm run check` → all green; 0 svelte-check errors.

- [ ] **Step 3: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/routes/settings/language/+page.svelte
git commit -m "feat(gui-tauri/settings): language picker (native names -> setLocale)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 10: Final gate + headless smoke

**Files:** none (verification only)

- [ ] **Step 1: Full gate** — `cd gui-tauri && npm test && npm run check && npm run build` → all vitest green (converter, match, coverage, theme, backend), 0 svelte-check errors, build OK.

- [ ] **Step 2: Serve the build** — run:
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling/gui-tauri
npm run preview -- --port 4173 > /tmp/spark-settings-preview.log 2>&1 &
sleep 3
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:4173/
```
Expected: `200`.

- [ ] **Step 3: Headless smoke (chrome-devtools MCP or manual browser).** Load `http://localhost:4173/`, then verify, in order:
  1. **Nav:** click the top-left hamburger → URL becomes `/settings`; the page shows the Settings title, Appearance + Language rows, and an Ad blocking toggle.
  2. **Appearance → Dark:** go to `/settings/appearance`, choose Dark → returns to `/settings`; assert `document.documentElement.dataset.theme === "dark"` and `getComputedStyle(document.body).backgroundColor` is the dark `--bg`. Choose System → resolves to the OS value.
  3. **Language → fa:** go to `/settings/language`, choose فارسی → returns to `/settings`; assert `document.documentElement.getAttribute("dir") === "rtl"`, `lang === "fa"`, and the Settings title reads `تنظیمات`. Back-arrow shows `transform: matrix(-1, 0, 0, 1, 0, 0)`. Reset to English.
  4. **Ad blocking:** toggle it on → `aria-checked="true"`; reload → the mock resets (expected for MockBackend; the real persistence is exercised in-app against the plugin).

  Example (chrome-devtools MCP `evaluate_script` after navigating + clicking):
```js
() => ({
  route: location.pathname,
  dataTheme: document.documentElement.dataset.theme,
  dir: document.documentElement.getAttribute("dir"),
  lang: document.documentElement.getAttribute("lang"),
  title: document.querySelector(".title")?.textContent,
})
```

- [ ] **Step 4: Stop the preview server** — `pkill -f "vite preview"`.

- [ ] **Step 5: Completion commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git commit --allow-empty -m "chore(gui-tauri/settings): Settings screen complete

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-review

- **Spec coverage:** structure/flat-minimal (T7); pickers as sub-screens (T8, T9); hamburger entry (T6); theme override + `data-theme` + CSS refactor (T3, T4); zero-flash (T5); ad-block seam + #56 command confirmation (T1, T2); i18n reuse of translated Lantern keys (T7–T9, all labels); RTL logical CSS + flips (T7–T9); Vitest theme + backend + key-coverage (T2, T3); svelte-check + build (T4, T10); headless smoke (T10); no new npm deps; no Rust unless getter missing (T1). ✔
- **Type consistency:** `Theme`, `theme`, `setTheme`, `resolveTheme` (T3) used identically in T4/T7/T8; `getAdBlock`/`setAdBlock` (T2) used in T7; `SUPPORTED`/`setLocale`/`locale`/`_` (from #57) used in T7/T9; `$_($theme)` renders `system`/`light`/`dark` keys that T8 also references as literals so the coverage guard covers them. ✔
- **Placeholders:** none — every code step shows complete code; T1 is conditional-but-specified (confirm names, add getter via the `get_routing_mode` template only if absent). ✔
- **Ordering note:** T6 wires the hamburger before T7 creates `/settings`; svelte-check doesn't resolve `goto` targets, so the tree stays green between them, and the route exists by T7. ✔
