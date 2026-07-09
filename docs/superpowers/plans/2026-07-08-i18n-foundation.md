# i18n Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Localize the Spark desktop (Tauri + SvelteKit) UI into all 20 Lantern languages incl. RTL, reusing Lantern's `.po` strings, with live in-app locale switching.

**Architecture:** Vendor Lantern's 20 `.po` into the repo; a Node build script converts them (merged with a Spark-specific overlay) to per-locale JSON; `svelte-i18n` loads those at runtime; locale persists in `localStorage`; RTL via `dir` on `<html>` + logical-property CSS. All current screens are retrofitted to `$_()`. The Language picker UI is a later (Settings) spec.

**Tech Stack:** SvelteKit (static adapter), TypeScript, `svelte-i18n` (runtime dep), `gettext-parser` (dev), `vitest` (dev), `@tauri-apps/plugin-os` (runtime, optional). No Rust changes.

**Spec:** `docs/superpowers/specs/2026-07-08-i18n-foundation-design.md`

**Branch:** `fisk/i18n-foundation` (off `main`). All paths relative to `gui-tauri/` unless noted; run `npm`/`node` from `gui-tauri/`.

---

## File Structure

- `gui-tauri/src/lib/i18n/po/*.po` — vendored Lantern locale sources (20). Source of truth.
- `gui-tauri/src/lib/i18n/spark/en.json` — Spark-specific strings absent from Lantern's `.po`.
- `gui-tauri/src/lib/i18n/generated/{locale}.json` — build output (gitignored): Lantern `.po` -> JSON merged with the Spark overlay.
- `gui-tauri/src/lib/i18n/locales.ts` — supported list + display names + RTL set + `matchLocale()`.
- `gui-tauri/src/lib/i18n/index.ts` — register() all locales, init(), setLocale(), resolveInitialLocale(), isRtl.
- `gui-tauri/scripts/po-to-json.mjs` (+ `.test.mjs`) — converter.
- `gui-tauri/src/lib/i18n/coverage.test.ts`, `gui-tauri/src/lib/i18n/match.test.ts` — Vitest guards.
- Modified: `gui-tauri/package.json`, `gui-tauri/vitest.config.ts`, `gui-tauri/.gitignore`, `gui-tauri/src/routes/+layout.svelte`, all `gui-tauri/src/routes/**/+page.svelte`.

---

## Task 1: Vendor `.po`, add deps, gitignore generated output

**Files:** Create `gui-tauri/src/lib/i18n/po/*.po`; Modify `gui-tauri/package.json`, `gui-tauri/.gitignore`

- [ ] **Step 1: Vendor the 20 `.po`**
```bash
cd gui-tauri
mkdir -p src/lib/i18n/po src/lib/i18n/spark src/lib/i18n/generated
cp ../../lantern/assets/locales/*.po src/lib/i18n/po/
ls src/lib/i18n/po/ | wc -l   # expect 20
```
Canonical source: `getlantern/lantern/assets/locales/*.po` (adjust relative path if the sibling checkout differs).

- [ ] **Step 2: Add dependencies**
```bash
cd gui-tauri
npm install svelte-i18n @tauri-apps/plugin-os
npm install -D gettext-parser vitest
```
(If `@tauri-apps/plugin-os` is undesirable, skip it; `resolveInitialLocale` then uses `navigator.language`, and Task 6 omits its import.)

- [ ] **Step 3: Gitignore generated + keep the folder**
Append to `gui-tauri/.gitignore`:
```gitignore
# i18n build output (regenerated from src/lib/i18n/po by scripts/po-to-json.mjs)
src/lib/i18n/generated/
```
```bash
cd gui-tauri && touch src/lib/i18n/generated/.gitkeep && git add -f src/lib/i18n/generated/.gitkeep
```

- [ ] **Step 4: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/lib/i18n/po gui-tauri/src/lib/i18n/generated/.gitkeep gui-tauri/package.json gui-tauri/package-lock.json gui-tauri/.gitignore
git commit -m "chore(gui-tauri/i18n): vendor Lantern .po locales + add svelte-i18n/gettext-parser/vitest"
```

---

## Task 2: `.po` -> JSON converter (TDD)

**Files:** Create `gui-tauri/scripts/po-to-json.mjs`; Test `gui-tauri/scripts/po-to-json.test.mjs`

- [ ] **Step 1: Write the failing test** — `gui-tauri/scripts/po-to-json.test.mjs`:
```js
import { describe, it, expect } from "vitest";
import { poToMap } from "./po-to-json.mjs";

const SAMPLE = `msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\\n"

msgid "settings"
msgstr "Settings"

msgid "greeting"
msgstr "Hello \\"world\\"\\nline2"

msgid "empty_one"
msgstr ""
`;

describe("poToMap", () => {
  it("extracts msgid->msgstr, drops header and empty translations", () => {
    const map = poToMap(SAMPLE);
    expect(map.settings).toBe("Settings");
    expect(map.greeting).toBe('Hello "world"\nline2');
    expect(map).not.toHaveProperty("");
    expect(map).not.toHaveProperty("empty_one");
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `cd gui-tauri && npx vitest run scripts/po-to-json.test.mjs` → FAIL (`poToMap` undefined).

- [ ] **Step 3: Implement** — `gui-tauri/scripts/po-to-json.mjs`:
```js
#!/usr/bin/env node
// Convert vendored Lantern .po (+ a Spark overlay) to per-locale JSON for svelte-i18n.
// Output src/lib/i18n/generated/{locale}.json = { key: string }. Header + empty msgstr dropped
// so missing strings fall back to English (svelte-i18n fallbackLocale).
import gettextParser from "gettext-parser";
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, basename } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const PO_DIR = join(HERE, "..", "src", "lib", "i18n", "po");
const SPARK_DIR = join(HERE, "..", "src", "lib", "i18n", "spark");
const OUT_DIR = join(HERE, "..", "src", "lib", "i18n", "generated");

export function poToMap(poText) {
  const parsed = gettextParser.po.parse(poText, "utf-8");
  const ctx = parsed.translations[""] || {};
  const out = {};
  for (const [msgid, entry] of Object.entries(ctx)) {
    if (msgid === "") continue;                 // header
    const value = entry.msgstr && entry.msgstr[0];
    if (!value) continue;                        // empty -> English fallback
    out[msgid] = value;
  }
  return out;
}

export function build() {
  mkdirSync(OUT_DIR, { recursive: true });
  const poFiles = readdirSync(PO_DIR).filter((f) => f.endsWith(".po"));
  if (poFiles.length === 0) throw new Error(`no .po files in ${PO_DIR}`);
  for (const file of poFiles) {
    const locale = basename(file, ".po");
    const base = poToMap(readFileSync(join(PO_DIR, file), "utf-8"));
    const overlayPath = join(SPARK_DIR, `${locale}.json`);
    const overlay = existsSync(overlayPath) ? JSON.parse(readFileSync(overlayPath, "utf-8")) : {};
    writeFileSync(join(OUT_DIR, `${locale}.json`), JSON.stringify({ ...base, ...overlay }, null, 2) + "\n");
  }
  return poFiles.map((f) => basename(f, ".po"));
}

if (process.argv[1] && process.argv[1].endsWith("po-to-json.mjs")) {
  const locales = build();
  console.log(`i18n: generated ${locales.length} locales -> src/lib/i18n/generated/`);
}
```

- [ ] **Step 4: Run to verify it passes** — `cd gui-tauri && npx vitest run scripts/po-to-json.test.mjs` → PASS.

- [ ] **Step 5: Smoke the full build** — `cd gui-tauri && node scripts/po-to-json.mjs` → "generated 20 locales"; `cat src/lib/i18n/generated/en.json | head` shows `"settings": "Settings"`.

- [ ] **Step 6: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/scripts/po-to-json.mjs gui-tauri/scripts/po-to-json.test.mjs
git commit -m "feat(gui-tauri/i18n): .po -> per-locale JSON converter (+ Spark overlay merge)"
```

---

## Task 3: Wire vitest + i18n build into npm scripts

**Files:** Modify `gui-tauri/package.json`; Create `gui-tauri/vitest.config.ts`

- [ ] **Step 1: vitest config** — `gui-tauri/vitest.config.ts`:
```ts
import { defineConfig } from "vitest/config";
export default defineConfig({
  test: { environment: "node", include: ["src/**/*.test.ts", "scripts/**/*.test.mjs"] },
});
```

- [ ] **Step 2: scripts + hooks** — merge into `package.json` `"scripts"` (keep existing):
```json
{
  "scripts": {
    "i18n:build": "node scripts/po-to-json.mjs",
    "predev": "npm run i18n:build",
    "prebuild": "npm run i18n:build",
    "precheck": "npm run i18n:build",
    "pretest": "npm run i18n:build",
    "test": "vitest run",
    "dev": "vite dev",
    "build": "vite build",
    "preview": "vite preview",
    "check": "svelte-kit sync && svelte-check --tsconfig ./tsconfig.json",
    "check:watch": "svelte-kit sync && svelte-check --tsconfig ./tsconfig.json --watch",
    "tauri": "tauri"
  }
}
```

- [ ] **Step 3: Verify** — `cd gui-tauri && rm -rf src/lib/i18n/generated/*.json && npm test` → pretest regenerates 20 locales, converter test PASSES.

- [ ] **Step 4: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/package.json gui-tauri/vitest.config.ts
git commit -m "chore(gui-tauri/i18n): i18n:build hooks + vitest wiring"
```

---

## Task 4: Locale registry + `matchLocale` (TDD)

**Files:** Create `gui-tauri/src/lib/i18n/locales.ts`; Test `gui-tauri/src/lib/i18n/match.test.ts`

- [ ] **Step 1: Failing test** — `gui-tauri/src/lib/i18n/match.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { matchLocale, SUPPORTED, RTL_LOCALES } from "./locales";

describe("matchLocale", () => {
  it("matches exact codes", () => {
    expect(matchLocale("fa")).toBe("fa");
    expect(matchLocale("zh-Hans")).toBe("zh-Hans");
  });
  it("matches by base language", () => {
    expect(matchLocale("fa-IR")).toBe("fa");
    expect(matchLocale("fr-FR")).toBe("fr");
  });
  it("maps zh variants", () => {
    expect(matchLocale("zh")).toBe("zh-Hans");
    expect(matchLocale("zh-CN")).toBe("zh-Hans");
    expect(matchLocale("zh-TW")).toBe("zh-Hant");
  });
  it("returns null for unsupported/empty", () => {
    expect(matchLocale("xx")).toBeNull();
    expect(matchLocale("")).toBeNull();
    expect(matchLocale(undefined)).toBeNull();
  });
  it("declares the RTL set", () => {
    expect(RTL_LOCALES.has("fa")).toBe(true);
    expect(RTL_LOCALES.has("en")).toBe(false);
    expect(SUPPORTED.some((l) => l.code === "en")).toBe(true);
  });
});
```

- [ ] **Step 2: Run to verify it fails** — `cd gui-tauri && npx vitest run src/lib/i18n/match.test.ts` → FAIL (`./locales` missing).

- [ ] **Step 3: Implement** — `gui-tauri/src/lib/i18n/locales.ts`:
```ts
// Supported locales (one per vendored .po), display names, RTL set. `code` MUST equal the .po
// basename in src/lib/i18n/po/ so the generated JSON filename matches.
export interface LocaleInfo { code: string; name: string; nativeName: string; rtl: boolean; }

export const SUPPORTED: LocaleInfo[] = [
  { code: "en", name: "English", nativeName: "English", rtl: false },
  { code: "ar", name: "Arabic", nativeName: "العربية", rtl: true },
  { code: "bn", name: "Bengali", nativeName: "বাংলা", rtl: false },
  { code: "es", name: "Spanish", nativeName: "Español", rtl: false },
  { code: "es-cu", name: "Spanish (Cuba)", nativeName: "Español (Cuba)", rtl: false },
  { code: "fa", name: "Persian", nativeName: "فارسی", rtl: true },
  { code: "fr", name: "French", nativeName: "Français", rtl: false },
  { code: "fr-ca", name: "French (Canada)", nativeName: "Français (Canada)", rtl: false },
  { code: "hi", name: "Hindi", nativeName: "हिन्दी", rtl: false },
  { code: "ms", name: "Malay", nativeName: "Bahasa Melayu", rtl: false },
  { code: "my", name: "Burmese", nativeName: "မြန်မာ", rtl: false },
  { code: "ps", name: "Pashto", nativeName: "پښتو", rtl: true },
  { code: "ru", name: "Russian", nativeName: "Русский", rtl: false },
  { code: "th", name: "Thai", nativeName: "ไทย", rtl: false },
  { code: "tk", name: "Turkmen", nativeName: "Türkmençe", rtl: false },
  { code: "tr", name: "Turkish", nativeName: "Türkçe", rtl: false },
  { code: "ur", name: "Urdu", nativeName: "اردو", rtl: true },
  { code: "vi", name: "Vietnamese", nativeName: "Tiếng Việt", rtl: false },
  { code: "zh-Hans", name: "Chinese (Simplified)", nativeName: "简体中文", rtl: false },
  { code: "zh-Hant", name: "Chinese (Traditional)", nativeName: "繁體中文", rtl: false },
];

export const RTL_LOCALES = new Set(SUPPORTED.filter((l) => l.rtl).map((l) => l.code));
const CODES = new Set(SUPPORTED.map((l) => l.code));

export function matchLocale(requested: string | undefined | null): string | null {
  if (!requested) return null;
  if (CODES.has(requested)) return requested;
  const lower = requested.toLowerCase();
  const base = lower.split("-")[0];
  if (base === "zh") return /hant|tw|hk|mo/.test(lower) ? "zh-Hant" : "zh-Hans";
  const exactBase = SUPPORTED.find((l) => l.code === base);
  if (exactBase) return exactBase.code;
  const anyBase = SUPPORTED.find((l) => l.code.toLowerCase().split("-")[0] === base);
  return anyBase ? anyBase.code : null;
}
```

- [ ] **Step 4: Run to verify it passes** — `cd gui-tauri && npx vitest run src/lib/i18n/match.test.ts` → PASS.

- [ ] **Step 5: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/lib/i18n/locales.ts gui-tauri/src/lib/i18n/match.test.ts
git commit -m "feat(gui-tauri/i18n): supported-locale registry + matchLocale()"
```

---

## Task 5: Spark English overlay

**Files:** Create `gui-tauri/src/lib/i18n/spark/en.json`

- [ ] **Step 1: Author** — `gui-tauri/src/lib/i18n/spark/en.json`:
```json
{
  "app_name_spark": "SPARK",
  "vpn_status": "VPN status",
  "routing_mode": "Routing Mode",
  "routing_smart_title": "Smart Routing",
  "routing_smart_desc": "Routes only blocked traffic through the VPN",
  "routing_full_title": "Full Tunnel",
  "routing_full_desc": "Routes all traffic through VPN",
  "split_tunneling": "Split Tunneling",
  "split_tunneling_desc": "Add apps & websites to bypass the VPN",
  "split_apps": "Apps",
  "split_websites": "Websites",
  "app_split_tunneling_title": "App Split Tunneling",
  "search_apps": "Search apps",
  "website_split_tunneling_title": "Website Split Tunneling",
  "website_enter_url": "Enter URL or IP Address",
  "website_none_selected": "No websites selected",
  "website_comma_hint": "Use commas to separate multiple URLs",
  "server_selection": "Server selection",
  "server_smart_location": "Smart location",
  "server_fastest": "Fastest server",
  "server_all_locations": "All locations"
}
```
Match exact English wording to each screen verbatim while retrofitting (Tasks 9-13); this file is the single place to edit copy.

- [ ] **Step 2: Rebuild + verify** — `cd gui-tauri && npm run i18n:build && node -e "const e=require('./src/lib/i18n/generated/en.json'); console.log(e.routing_mode,'|',e.settings)"` → `Routing Mode | Settings`.

- [ ] **Step 3: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/lib/i18n/spark/en.json
git commit -m "feat(gui-tauri/i18n): Spark-specific English string overlay"
```

---

## Task 6: i18n runtime (`index.ts`)

**Files:** Create `gui-tauri/src/lib/i18n/index.ts`

- [ ] **Step 1: Implement** — `gui-tauri/src/lib/i18n/index.ts`:
```ts
import { register, init, locale, _, isLoading, waitLocale } from "svelte-i18n";
import { derived } from "svelte/store";
import { SUPPORTED, RTL_LOCALES, matchLocale } from "./locales";

const STORAGE_KEY = "spark.locale";
const FALLBACK = "en";

// Register every supported locale with a lazy loader for its generated dictionary.
const dicts = import.meta.glob("./generated/*.json");
for (const { code } of SUPPORTED) {
  const loader = dicts[`./generated/${code}.json`];
  if (loader) register(code, () => loader() as Promise<Record<string, string>>);
}

export async function resolveInitialLocale(): Promise<string> {
  try {
    const saved = matchLocale(localStorage.getItem(STORAGE_KEY));
    if (saved) return saved;
  } catch { /* localStorage unavailable */ }
  let osLocale: string | null = null;
  try {
    const os = await import("@tauri-apps/plugin-os");
    osLocale = await os.locale();
  } catch {
    osLocale = typeof navigator !== "undefined" ? navigator.language : null;
  }
  return (
    matchLocale(osLocale) ??
    matchLocale(typeof navigator !== "undefined" ? navigator.language : null) ??
    FALLBACK
  );
}

export async function setupI18n(): Promise<void> {
  const initialLocale = await resolveInitialLocale();
  init({ fallbackLocale: FALLBACK, initialLocale });
  await waitLocale();
}

export function setLocale(code: string): void {
  try { localStorage.setItem(STORAGE_KEY, code); } catch { /* ignore */ }
  locale.set(code);
}

export const isRtl = derived(locale, ($locale) => !!$locale && RTL_LOCALES.has($locale));

export { _, locale, isLoading };
```
If `@tauri-apps/plugin-os` was skipped in Task 1, delete the `const os = await import(...)` line and its `osLocale = await os.locale()` (keep the `navigator.language` fallback).

- [ ] **Step 2: Type-check** — `cd gui-tauri && npm run check` → 0 svelte-check errors.

- [ ] **Step 3: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/lib/i18n/index.ts
git commit -m "feat(gui-tauri/i18n): svelte-i18n runtime (register/init/setLocale/isRtl)"
```

---

## Task 7: Initialize i18n in the layout + `dir` attribute

**Files:** Modify `gui-tauri/src/routes/+layout.svelte`

- [ ] **Step 1: Update the layout** — replace its `<script>` + markup (keep the existing `<style>` + font imports):
```svelte
<script lang="ts">
  import "@fontsource/urbanist/latin-400.css";
  import "@fontsource/urbanist/latin-500.css";
  import "@fontsource/urbanist/latin-600.css";
  import "@fontsource/urbanist/latin-700.css";

  import { setupI18n, isRtl, locale, isLoading } from "$lib/i18n";

  let { children } = $props();

  let ready = $state(false);
  setupI18n().then(() => (ready = true));

  $effect(() => {
    const code = $locale ?? "en";
    document.documentElement.lang = code;
    document.documentElement.dir = $isRtl ? "rtl" : "ltr";
  });
</script>

{#if ready && !$isLoading}
  {@render children()}
{/if}
```
`$lib` is SvelteKit's alias for `src/lib`; if unavailable use `../lib/i18n`.

- [ ] **Step 2: Build + check** — `cd gui-tauri && npm run check && npm run build` → 0 errors, build OK. (No Tauri shell needed; `vite build` proves the web layer.)

- [ ] **Step 3: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/routes/+layout.svelte
git commit -m "feat(gui-tauri/i18n): init i18n in layout + reactive dir/lang on <html>"
```

---

## Task 8: Key-coverage test (TDD guard)

**Files:** Create `gui-tauri/src/lib/i18n/coverage.test.ts`

- [ ] **Step 1: Write the test** — `gui-tauri/src/lib/i18n/coverage.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import en from "./generated/en.json";

function svelteFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...svelteFiles(p));
    else if (e.name.endsWith(".svelte")) out.push(p);
  }
  return out;
}

function usedKeys(src: string): string[] {
  const keys: string[] = [];
  const re = /\$(?:_|format)\(\s*["']([^"']+)["']/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) keys.push(m[1]);
  return keys;
}

describe("i18n key coverage", () => {
  it("every \$_() key used in .svelte exists in English", () => {
    const dict = en as Record<string, string>;
    const missing = new Set<string>();
    for (const file of svelteFiles(join(__dirname, "..", "..", "routes"))) {
      for (const key of usedKeys(readFileSync(file, "utf-8"))) {
        if (!(key in dict)) missing.add(key);
      }
    }
    expect([...missing].sort()).toEqual([]);
  });
});
```

- [ ] **Step 2: Run — expected PASS** (no `$_` usages yet; guard starts green, fails when a retrofit adds a key with no English entry). `cd gui-tauri && npx vitest run src/lib/i18n/coverage.test.ts` → PASS.

- [ ] **Step 3: Commit**
```bash
cd /Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling
git add gui-tauri/src/lib/i18n/coverage.test.ts
git commit -m "test(gui-tauri/i18n): key-coverage guard"
```

---

## Tasks 9-13: Retrofit each screen

Same shape per screen: (1) add `import { _ } from "$lib/i18n";`; (2) replace visible literals with `{$_('key')}` per the audit table (add any missing key to `spark/en.json` then `npm run i18n:build`); (3) convert that file's physical-direction CSS (`margin-left/right`, `padding-left/right`, `left/right`, `text-align: left/right`) to logical properties (`margin-inline-start/end`, `padding-inline-start/end`, `inset-inline-start/end`, `text-align: start/end`), and flip directional glyphs with `[dir="rtl"] .selector { transform: scaleX(-1) }`; (4) run `cd gui-tauri && npm test && npm run check` (coverage + svelte-check must pass); (5) commit `feat(gui-tauri/i18n): localize <screen> + logical-property CSS`. `placeholder`/`aria-label` use `{$_('key')}` too.

**Key-mapping audit (verbatim string -> key):**

| Screen | String | Key |
| --- | --- | --- |
| `+page.svelte` | SPARK | `app_name_spark` |
| | VPN status | `vpn_status` |
| | Routing Mode | `routing_mode` |
| | Split Tunneling | `split_tunneling` |
| `routing/+page.svelte` | Routing Mode | `routing_mode` |
| | Smart Routing | `routing_smart_title` |
| | (smart desc — verify copy) | `routing_smart_desc` |
| | Full Tunnel | `routing_full_title` |
| | Routes all traffic through VPN | `routing_full_desc` |
| `servers/+page.svelte` | Server selection | `server_selection` |
| | Smart location | `server_smart_location` |
| | Fastest server | `server_fastest` |
| | All locations | `server_all_locations` |
| `split-tunneling/+page.svelte` | Split Tunneling | `split_tunneling` |
| | Add apps & websites to bypass the VPN | `split_tunneling_desc` |
| | Apps | `split_apps` |
| | Websites | `split_websites` |
| `split-tunneling/apps/+page.svelte` | App Split Tunneling | `app_split_tunneling_title` |
| | Search apps | `search_apps` |
| `split-tunneling/websites/+page.svelte` | Website Split Tunneling | `website_split_tunneling_title` |
| | Enter URL or IP Address | `website_enter_url` |
| | No websites selected | `website_none_selected` |
| | Use commas to separate multiple URLs | `website_comma_hint` |

Grep each file for any visible string the audit missed (button labels, `aria-label`, `placeholder`, snackbar/toast text) and add a key.

### Task 9: `src/routes/+page.svelte` (home)
Wordmark, VPN-status text, settings-card nav tiles (flip tile chevrons under RTL).

### Task 10: `src/routes/routing/+page.svelte`
Smart/Full titles + descriptions; radio-row layout uses logical properties.

### Task 11: `src/routes/servers/+page.svelte`
Header, smart-location/fastest labels, list rows; keep latency pills LTR-numeric (do NOT mirror numbers).

### Task 12: `src/routes/split-tunneling/+page.svelte`
Title, description, Apps/Websites tiles.

### Task 13: `src/routes/split-tunneling/apps/+page.svelte` and `.../websites/+page.svelte`
Titles, search/enter placeholders, empty states, hint/snackbar text. Two files; commit together.

---

## Task 14: Final gate + RTL smoke

- [ ] **Step 1:** `cd gui-tauri && npm test && npm run check && npm run build` → all vitest green (converter, match, coverage), 0 svelte-check errors, build OK.
- [ ] **Step 2 (manual RTL smoke):** `cd gui-tauri && npm run dev`; in devtools console `localStorage.setItem('spark.locale','fa'); location.reload()` → Persian where translated (English fallback elsewhere), `<html dir="rtl">`, layout mirrored (rows, chevrons flipped, text right-aligned). Reset with `'en'`.
- [ ] **Step 3:** `git status --porcelain gui-tauri/src/lib/i18n/generated` → no output (only `.gitkeep` tracked).
- [ ] **Step 4:** `git commit --allow-empty -m "chore(gui-tauri/i18n): i18n foundation complete"`

---

## Self-review

- **Spec coverage:** library (T6); vendored .po + build-convert + all-20 + English fallback (T1-3); Spark overlay (T5); localStorage + OS-detect + live switch (T6); RTL dir + logical props (T7,9-13); retrofit all screens (T9-13); tests converter+match+coverage (T2,4,8); no Rust changes. Picker out of scope. ✔
- **Refinement vs spec:** Spark overlay merged at build time (converter) not register time — same result, simpler runtime. Documented T2/T5.
- **Type consistency:** matchLocale/SUPPORTED/RTL_LOCALES/setLocale/setupI18n/resolveInitialLocale/isRtl consistent across T4/6/7.
