# Spark Android — Phase 3 (Localization fa/ru/en + RTL) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Localize the Phase 2 Compose UI into English, Russian, and Farsi (with full RTL for Farsi), reusing Lantern's existing translations.

**Architecture:** Standard Android resource localization — `res/values/strings.xml` (en, default), `res/values-ru/strings.xml`, `res/values-fa/strings.xml`. Compose reads them via `stringResource(R.string.…)`. Android auto-selects the locale from the device language and auto-mirrors layout for the RTL (fa) locale (the manifest already declares `android:supportsRtl="true"`). No in-app language picker in v1 (no settings screen) — the device language drives it.

**Tech Stack:** Android string resources, Jetpack Compose `stringResource`, `LocalConfiguration`/system locale, RTL via `supportsRtl`.

---

## String table

Sourced from `getlantern/lantern/assets/locales/{en,ru,fa}.po` where available (✓ Lantern); the few marked **NEW** are best-effort translations to be confirmed by a native reviewer.

| resource id | en | ru | fa | source |
|---|---|---|---|---|
| `app_name` | Spark | Spark | Spark | brand |
| `vpn` | VPN | VPN | VPN | brand/abbr |
| `vpn_status` | VPN status | Статус VPN | وضعیت VPN | ✓ vpn_status |
| `status_connected` | Connected | Подключено | متصل | ✓ status_on |
| `status_connecting` | Connecting… | Подключение… | در حال اتصال… | NEW |
| `status_disconnected` | Disconnected | Отключено | قطع شده | ✓ status_off |
| `status_failed` | Failed | Ошибка | خطا | ✓ error (reused) |
| `smart_location` | Smart location | Умное расположение | مکان هوشمند | ✓ smart_location |
| `selected_location` | Selected location | Выбранное расположение | مکان انتخاب‌شده | NEW |
| `fastest_server` | Fastest server | Самый быстрый сервер | سریع‌ترین سرور | ✓ fastest_server |
| `routing` | Routing | Маршрутизация | مسیریابی | ✓ routing_mode (shortened) |
| `full_tunnel` | Full tunnel | Полный туннель | تونل کامل | ✓ full_tunnel |
| `server_selection` | Server selection | Выбор сервера | انتخاب سرور | ✓ server_selection |
| `all_locations` | ALL LOCATIONS | ВСЕ РЕГИОНЫ | همه مکان‌ها | ✓ server_locations (upper) |
| `auto_fastest_help` | Automatically chooses the fastest location. | Автоматически выбирает расположение с самым быстрым сервером. | انتخاب سریع‌ترین مکان را به طور خودکار انجام می‌دهد. | ✓ automatically_chooses_fastest_location |
| `no_servers_available` | No servers available. Connect first to choose a location. | Нет доступных серверов. Сначала подключитесь, чтобы выбрать расположение. | هیچ سروری در دسترس نیست. ابتدا متصل شوید تا یک مکان انتخاب کنید. | NEW |
| `connect` | Connect | Подключиться | اتصال | ✓ connect |
| `disconnect` | Disconnect | Отключиться | قطع اتصال | ✓ disconnect |

Latency uses `"%1$d ms"` via a plain format (digits localize via the locale; keep the `ms` unit). Protocol names (Hysteria2, Samizdat, Meek, …) are proper nouns — **not** translated.

---

## Task 1: String resources (en default + ru + fa)

**Files:** Create `platforms/android/demo/app/src/main/res/values/strings.xml`, `res/values-ru/strings.xml`, `res/values-fa/strings.xml`.

- [ ] **Step 1:** Write `values/strings.xml` with every id from the table (en column), plus `app_name`. Use `…` for the ellipsis and escape apostrophes (`\'`). Add `ms_format` = `"%1$d ms"`.
- [ ] **Step 2:** Write `values-ru/strings.xml` (ru column), same ids.
- [ ] **Step 3:** Write `values-fa/strings.xml` (fa column), same ids. Mark the NEW rows with an XML comment `<!-- NEW: confirm with native reviewer -->`.
- [ ] **Step 4:** `./gradlew :app:assembleDebug` — expected BUILD SUCCESSFUL (resources compile, no missing-translation lint error; if lint blocks on untranslated, it won't because all ids exist in all three).
- [ ] **Step 5:** Commit `feat(android): string resources (en/ru/fa)`.

## Task 2: Wire the UI to string resources

**Files:** Modify `ui/HomeScreen.kt`, `ui/ServersScreen.kt`, `ui/components.kt` (and remove `android:label` literal reliance — `app_name` now drives it; manifest `android:label="@string/app_name"`).

- [ ] **Step 1:** Replace every hardcoded user-facing string literal in the three Compose files with `stringResource(R.string.<id>)`. Map: "Spark"→`app_name`, "VPN status"→`vpn_status`, the four status words→`status_*`, "Smart location"/"Selected location"→`smart_location`/`selected_location`, "Fastest server"→`fastest_server`, "Routing"→`routing`, "Full tunnel"→`full_tunnel`, "Server selection"→`server_selection`, "ALL LOCATIONS"→`all_locations`, the helper sentence→`auto_fastest_help`, the empty state→`no_servers_available`, the toggle `onClickLabel`/`contentDescription` "Connect"/"Disconnect"/"VPN"→`connect`/`disconnect`/`vpn`. Latency pill text→`stringResource(R.string.ms_format, ms)`. `import org.getlantern.spark.R` and `androidx.compose.ui.res.stringResource`.
- [ ] **Step 2:** Set `android:label="@string/app_name"` in `AndroidManifest.xml` (it stays "Spark" but via the resource).
- [ ] **Step 3:** `./gradlew :app:assembleDebug` — BUILD SUCCESSFUL.
- [ ] **Step 4:** Commit `feat(android): localize Compose UI via stringResource`.

## Task 3: RTL verification + device pass

- [ ] **Step 1:** Build/install. On the emulator, verify English renders unchanged.
- [ ] **Step 2:** Switch the emulator system language to **Russian** (`adb shell settings put system system_locales ru-RU` then `setprop`/restart, or via Settings UI) and relaunch: home + server screens show Russian strings, LTR layout. Screenshot.
- [ ] **Step 3:** Switch to **Farsi/Persian** (fa-IR) and relaunch: strings are Farsi AND the layout is **mirrored** (RTL) — the menu icon on the right, the back chevron flipped, row content right-aligned, status-card leading/trailing swapped. Screenshot. Confirm `View.getLayoutDirection()` / Compose `LocalLayoutDirection` is RTL (automatic from the fa resources + supportsRtl).
- [ ] **Step 4:** Fix any string that overflows/truncates or any layout that doesn't mirror (use `Modifier.padding(start=…)` not `left`, `Arrangement.Start` not absolute — audit for absolute offsets; the toggle's `offset(x=…)` is a knob position and is fine since the switch is symmetric).
- [ ] **Step 5:** Commit `chore(android): RTL pass (fa) + locale verification`.

## Phase 3 completion gate
Device renders English, Russian, and Farsi from the device language; Farsi is fully mirrored (RTL); no clipped/overflowing strings; protocol names stay Latin. PR opened, Copilot loop run.

## Notes
- NEW translations (`status_connecting`, `selected_location`, `no_servers_available`) are best-effort; flag in the PR for a native fa/ru reviewer.
- No in-app language picker in v1 (no settings screen) — Android selects the locale from the device language. A picker can come later via the (currently decorative) menu icon.
