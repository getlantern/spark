# Spark Android — Phase 2 (Compose UI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the demo's two-button harness with a polished Jetpack Compose UI — a home screen (connect toggle + status + smart-location) and a server-selection screen (flag · latency · protocol) — mirroring the Tauri/macOS app, fed by the Phase 1 JNI bridge.

**Architecture:** Single process (Activity + `SparkVpnService` + native core all in-process), so the Compose UI calls `SparkBridge` directly and observes a shared `MutableStateFlow<VpnState>` the service updates. Compose + Material3, simple state-based navigation between two screens, a `SparkTheme` translating the Lantern design tokens, the Urbanist typeface bundled locally.

**Tech Stack:** Jetpack Compose (BOM), Material3, `activity-compose`, `lifecycle-runtime-compose`; Kotlin 2.1.21 / AGP 8.9.1 / compileSdk 35 / minSdk 24; the Phase 1 JNI bridge (`nativeServers`/`nativeSelectServer`).

**Spec:** `docs/superpowers/specs/2026-06-25-spark-android-standalone-app-design.md` (§3). **Branch:** `fisk/android-phase2-ui` off `main`.

**Reference (mirror these exactly):**
- Tokens/font: `gui-tauri/src/routes/+layout.svelte` (Lantern palette + Urbanist).
- Home: `gui-tauri/src/routes/+page.svelte` (AppBar, VPN toggle switch geometry, status card).
- Servers: `gui-tauri/src/routes/servers/+page.svelte` (smart-location card, country grouping, latency pills, protocol subtitle).

**Locked decisions (from the spec/brainstorm):** mirror Tauri in Compose; **no settings screen**; **no Protocol row on the home screen** (protocol shows only on the server screen, per the #28/#29 subtitle); kill-switch = fail-open (unchanged). Verification reality: Compose screens are device/emulator-verified via the running app + `@Preview`; the JSON parser is the one genuinely unit-testable unit (TDD it).

**Decisions made in this plan (flag for review):**
- Keep building in `platforms/android/demo/app` (do NOT rename `demo/app` → `app` yet — high-churn, zero functional value; defer to a Phase 4 cleanup).
- Home card rows: **VPN status**, **Smart location** (→ servers), **Routing** ("Full tunnel", static). The Tauri **Protocol** row is omitted per the locked decision.
- Navigation: simple `mutableStateOf(Screen)` in the root composable (2 screens) — no `navigation-compose` dependency.
- Status is derived from a service-updated `StateFlow` (no `nativeStatus` JNI; the Phase 1 plan deferred it). Localization (fa/ru, RTL) is **Phase 3** — Phase 2 ships English strings (hardcoded is fine; Phase 3 extracts them).

---

## File structure

**Create (all under `platforms/android/demo/app/src/main/`):**
- `kotlin/org/getlantern/spark/ui/SparkTheme.kt` — Color tokens, Urbanist `FontFamily`, `Typography`, `SparkTheme {}` wrapper.
- `kotlin/org/getlantern/spark/ui/HomeScreen.kt` — home composable (AppBar, toggle switch, status card).
- `kotlin/org/getlantern/spark/ui/ServersScreen.kt` — server-selection composable.
- `kotlin/org/getlantern/spark/ui/components.kt` — shared composables (latency pill, flag emoji helper, server row).
- `kotlin/org/getlantern/spark/VpnState.kt` — `enum class VpnState` + `object SparkState { val state: MutableStateFlow<VpnState> }`.
- `kotlin/org/getlantern/spark/ServerInfo.kt` — `data class ServerInfo` + `parseServers(json: String?): List<ServerInfo>`.
- `kotlin/org/getlantern/spark/VpnController.kt` — connect/disconnect helpers (consent flow + start/stop the service) shared by the UI.
- `res/font/urbanist_{regular,medium,semibold,bold}.ttf` — bundled Urbanist (OFL).
- `test/kotlin/org/getlantern/spark/ServerInfoTest.kt` — unit tests for `parseServers`.

**Modify:**
- `app/build.gradle` + `settings.gradle` — add Compose plugin + deps.
- `kotlin/org/getlantern/spark/MainActivity.kt` — become a `ComponentActivity` hosting `setContent { SparkApp() }`; drop auto-connect + the two buttons.
- `kotlin/org/getlantern/spark/SparkVpnService.kt` — update `SparkState.state` at the lifecycle points; expose connect/disconnect entry the controller uses.

---

## Task 1: Add Compose to the build

**Files:** Modify `platforms/android/demo/settings.gradle`, `platforms/android/demo/app/build.gradle`.

- [ ] **Step 1: Add the Compose compiler plugin to `settings.gradle` pluginManagement.plugins** (Kotlin 2.0+ needs the separate compose plugin, version == Kotlin version):

```groovy
        id 'org.jetbrains.kotlin.plugin.compose' version '2.1.21'
```

- [ ] **Step 2: In `app/build.gradle`**, add the plugin id, enable Compose, and add deps via the BOM. Replace the empty `dependencies {}` block:

```groovy
plugins {
    id 'com.android.application'
    id 'org.jetbrains.kotlin.android'
    id 'org.jetbrains.kotlin.plugin.compose'
}
```
Add inside `android { ... }`:
```groovy
    buildFeatures {
        compose true
    }
```
Replace `dependencies { }` with:
```groovy
dependencies {
    def composeBom = platform('androidx.compose:compose-bom:2025.06.00')
    implementation composeBom
    implementation 'androidx.compose.ui:ui'
    implementation 'androidx.compose.ui:ui-graphics'
    implementation 'androidx.compose.ui:ui-tooling-preview'
    implementation 'androidx.compose.material3:material3'
    implementation 'androidx.activity:activity-compose:1.10.1'
    implementation 'androidx.lifecycle:lifecycle-runtime-compose:2.8.7'
    debugImplementation 'androidx.compose.ui:ui-tooling'

    testImplementation 'junit:junit:4.13.2'
}
```

> **Verify (Verification Discipline):** these versions must actually resolve against `google()`/`mavenCentral()`. If `compose-bom:2025.06.00`, `activity-compose:1.10.1`, or `lifecycle-runtime-compose:2.8.7` don't resolve, pin the latest stable that does (the BOM governs the `androidx.compose.*` artifact versions; only the BOM + activity + lifecycle versions are pinned directly). The compose-plugin version MUST equal the Kotlin version (2.1.21).

- [ ] **Step 3: Verify it builds** (the `.so` from Phase 1 is needed; place it first):

```bash
cd platforms/android && cargo ndk -t arm64-v8a -t x86_64 -P 24 -o demo/app/src/main/jniLibs build --release -p spark-android
cd demo && ./gradlew assembleDebug
```
Expected: `BUILD SUCCESSFUL` (the existing framework UI still compiles; Compose is now available).

- [ ] **Step 4: Commit**
```bash
git add platforms/android/demo/settings.gradle platforms/android/demo/app/build.gradle
git commit -m "build(android): add Jetpack Compose (BOM + material3 + activity-compose)"
```

---

## Task 2: Theme — Lantern tokens + Urbanist + Typography

**Files:** Create `ui/SparkTheme.kt`, `res/font/urbanist_*.ttf`.

- [ ] **Step 1: Bundle the Urbanist typeface.** Obtain Urbanist (OFL) weights 400/500/600/700 as `.ttf` and place them at `res/font/` named all-lowercase, no hyphens (Android resource rules): `urbanist_regular.ttf`, `urbanist_medium.ttf`, `urbanist_semibold.ttf`, `urbanist_bold.ttf`. Source: Google Fonts "Urbanist" (download family → the static `.ttf` weights). 

> **Fallback (if the .ttf can't be fetched in this environment):** skip `res/font/` and define `Urbanist = FontFamily.SansSerif` in Step 2, leaving a `// TODO(phase2): bundle Urbanist .ttf` and noting it in the task report. The layout/colors still match the Tauri app; only the typeface differs. Do not block the rest of Phase 2 on the font download.

- [ ] **Step 2: Create `ui/SparkTheme.kt`** with the exact Lantern tokens (from `+layout.svelte`):

```kotlin
package org.getlantern.spark.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import org.getlantern.spark.R

// Lantern palette (gui-tauri/src/routes/+layout.svelte). Names mirror the CSS vars.
object SparkColors {
    val bg = Color(0xFFF8FAFB)
    val surface = Color(0xFFFFFFFF)
    val brand = Color(0xFF00BDD6)
    val off = Color(0xFF616569)
    val knob = Color(0xFFFFFFFF)
    val textPrimary = Color(0xFF1B1C1D)
    val textSecondary = Color(0xFF3E464E)
    val textTertiary = Color(0xFF616569)
    val border = Color(0xFFEDEFEF)
    val success = Color(0xFF00531F)
    val indicatorOff = Color(0xFFDEDFDF)
    val bolt = Color(0xFFF5B800)
    val latGood = Color(0xFF1F9D55)
    val latAmber = Color(0xFFC98A00)
    val latSlow = Color(0xFFC0341D)
    val shadow = Color(0x19006162) // teal-tinted elevation
}

// If the .ttf weights aren't bundled, replace this whole val with: val Urbanist = FontFamily.SansSerif
val Urbanist = FontFamily(
    Font(R.font.urbanist_regular, FontWeight.Normal),
    Font(R.font.urbanist_medium, FontWeight.Medium),
    Font(R.font.urbanist_semibold, FontWeight.SemiBold),
    Font(R.font.urbanist_bold, FontWeight.Bold),
)

private val SparkTypography = Typography().let { base ->
    base.copy(
        bodyLarge = base.bodyLarge.copy(fontFamily = Urbanist),
        bodyMedium = base.bodyMedium.copy(fontFamily = Urbanist),
        titleLarge = base.titleLarge.copy(fontFamily = Urbanist, fontWeight = FontWeight.Bold),
        labelLarge = base.labelLarge.copy(fontFamily = Urbanist),
    )
}

@Composable
fun SparkTheme(content: @Composable () -> Unit) {
    val scheme = lightColorScheme(
        primary = SparkColors.brand,
        background = SparkColors.bg,
        surface = SparkColors.surface,
        onBackground = SparkColors.textPrimary,
        onSurface = SparkColors.textPrimary,
    )
    MaterialTheme(colorScheme = scheme, typography = SparkTypography, content = content)
}
```

- [ ] **Step 3: Build to verify** (`./gradlew assembleDebug`). Expected `BUILD SUCCESSFUL`. If the font path is the fallback, confirm `Urbanist = FontFamily.SansSerif` compiles (no `R.font` references).

- [ ] **Step 4: Commit** (`feat(android): SparkTheme — Lantern tokens + Urbanist typography`).

---

## Task 3: Data — VpnState, SparkState, ServerInfo + parser (TDD)

**Files:** Create `VpnState.kt`, `ServerInfo.kt`, `test/.../ServerInfoTest.kt`.

- [ ] **Step 1: Write the failing parser test** `test/kotlin/org/getlantern/spark/ServerInfoTest.kt`:

```kotlin
package org.getlantern.spark

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerInfoTest {
    @Test fun parses_full_member() {
        val json = """[{"index":0,"name":"sfo","country":"United States","countryCode":"US",
            "city":"Phoenix","protocol":"hysteria2","latencyMs":502,"healthy":true,"isCurrent":true}]"""
        val s = parseServers(json).single()
        assertEquals(0, s.index); assertEquals("United States", s.country)
        assertEquals("US", s.countryCode); assertEquals("hysteria2", s.protocol)
        assertEquals(502L, s.latencyMs); assertTrue(s.healthy); assertTrue(s.isCurrent)
    }
    @Test fun handles_nulls_and_missing() {
        val s = parseServers("""[{"index":1,"healthy":false,"isCurrent":false}]""").single()
        assertEquals(1, s.index); assertEquals(null, s.country); assertEquals(null, s.latencyMs)
    }
    @Test fun null_and_empty_and_garbage_yield_empty_list() {
        assertEquals(emptyList<ServerInfo>(), parseServers(null))
        assertEquals(emptyList<ServerInfo>(), parseServers("[]"))
        assertEquals(emptyList<ServerInfo>(), parseServers("not json"))
    }
}
```

- [ ] **Step 2: Run it, confirm it fails** (`./gradlew :app:testDebugUnitTest --tests '*ServerInfoTest*'`) — Expected: compile failure (parseServers/ServerInfo undefined).

- [ ] **Step 3: Implement `ServerInfo.kt`** using `org.json` (bundled in Android; no dependency):

```kotlin
package org.getlantern.spark

import org.json.JSONArray

/** One pool member, mirroring the Rust snapshot JSON (fd_tunnel::snapshot_to_json). */
data class ServerInfo(
    val index: Int,
    val name: String? = null,
    val country: String? = null,
    val countryCode: String? = null,
    val city: String? = null,
    val protocol: String? = null,
    val latencyMs: Long? = null,
    val healthy: Boolean = false,
    val isCurrent: Boolean = false,
)

/** Parse the nativeServers() JSON array. Null/empty/garbage → empty list (never throws). */
fun parseServers(json: String?): List<ServerInfo> {
    if (json.isNullOrBlank()) return emptyList()
    return try {
        val arr = JSONArray(json)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            ServerInfo(
                index = o.getInt("index"),
                name = o.optStringOrNull("name"),
                country = o.optStringOrNull("country"),
                countryCode = o.optStringOrNull("countryCode"),
                city = o.optStringOrNull("city"),
                protocol = o.optStringOrNull("protocol"),
                latencyMs = if (o.isNull("latencyMs")) null else o.optLong("latencyMs"),
                healthy = o.optBoolean("healthy", false),
                isCurrent = o.optBoolean("isCurrent", false),
            )
        }
    } catch (_: Exception) {
        emptyList()
    }
}

private fun org.json.JSONObject.optStringOrNull(key: String): String? =
    if (isNull(key) || !has(key)) null else optString(key)
```

- [ ] **Step 4: Run the test, confirm it passes** (`./gradlew :app:testDebugUnitTest --tests '*ServerInfoTest*'`) — Expected: PASS.

- [ ] **Step 5: Create `VpnState.kt`**:

```kotlin
package org.getlantern.spark

import kotlinx.coroutines.flow.MutableStateFlow

enum class VpnState { DISCONNECTED, CONNECTING, CONNECTED, FAILED }

/** Process-global tunnel state. The service is the only writer; the UI observes it.
 *  (Activity + service + core share one process, so a plain singleton is correct here.) */
object SparkState {
    val state = MutableStateFlow(VpnState.DISCONNECTED)
}
```
(`kotlinx.coroutines` comes transitively via `lifecycle-runtime-compose`; if unresolved, add `implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1'` and note it.)

- [ ] **Step 6: Commit** (`feat(android): VpnState/SparkState + ServerInfo JSON parser (tested)`).

---

## Task 4: Service updates SparkState

**Files:** Modify `SparkVpnService.kt`.

- [ ] **Step 1: Set the state at each lifecycle point.** In `startTunnel`, right after the foreground promotion / before the worker starts, set `SparkState.state.value = VpnState.CONNECTING`. In the `spark-ready` thread's current-generation branch: on `rc == 0` set `VpnState.CONNECTED`; on `rc != 0` (the existing stop path) set `VpnState.FAILED`. In `stopTunnel`, set `VpnState.DISCONNECTED`. Add `import` for `org.getlantern.spark.VpnState` (same package — no import needed) and reference `SparkState`.

Concretely, the readiness branch becomes:
```kotlin
            if (rc != 0) {
                Log.e(TAG, "tunnel did not become ready (config unavailable?); stopping VPN")
                SparkState.state.value = VpnState.FAILED
                SparkBridge.nativeStop()
                stopSelf()
            } else {
                Log.i(TAG, "tunnel data path ready")
                SparkState.state.value = VpnState.CONNECTED
            }
```
and add `SparkState.state.value = VpnState.CONNECTING` in `startTunnel` (after `tunnelGeneration.incrementAndGet()`), and `SparkState.state.value = VpnState.DISCONNECTED` at the top of `stopTunnel`.

> Note on restart: `restartTunnel` calls `startTunnel` which sets CONNECTING then the new readiness thread sets CONNECTED — correct (a brief CONNECTING blip during a network-change reconnect is accurate).

- [ ] **Step 2: Build** (`./gradlew assembleDebug`) — Expected `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit** (`feat(android): publish tunnel state to SparkState for the UI`).

---

## Task 5: VpnController — connect/disconnect + consent

**Files:** Create `VpnController.kt`.

- [ ] **Step 1: Create `VpnController.kt`** — the consent + start/stop logic the UI calls:

```kotlin
package org.getlantern.spark

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build

object VpnController {
    /** The consent Intent to launch, or null if already granted (caller then calls [start]). */
    fun consentIntent(ctx: Context): Intent? = VpnService.prepare(ctx)

    fun start(ctx: Context) {
        val intent = Intent(ctx, SparkVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(intent)
        else ctx.startService(intent)
    }

    fun stop(ctx: Context) {
        ctx.startService(Intent(ctx, SparkVpnService::class.java).setAction(SparkVpnService.ACTION_STOP))
    }
}
```

- [ ] **Step 2: Build + commit** (`feat(android): VpnController (consent + start/stop)`).

---

## Task 6: Home screen

**Files:** Create `ui/HomeScreen.kt`, `ui/components.kt`; modify `MainActivity.kt`.

Mirror `gui-tauri/src/routes/+page.svelte`. **Omit the Protocol row.** Rows: VPN status, Smart location (→ servers, shows current member's flag + label + ⚡ + latency), Routing ("Full tunnel").

- [ ] **Step 1: Create `ui/components.kt`** with the shared pieces (flag emoji, latency pill, server row used by both screens):

```kotlin
package org.getlantern.spark.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** ISO-3166 alpha-2 → flag emoji (regional indicators); blank/odd → 🏳. Mirrors lib/format.ts. */
fun flagEmoji(code: String?): String {
    if (code == null || code.length != 2) return "🏳️"
    val base = 0x1F1E6
    val a = code[0].uppercaseChar() - 'A'; val b = code[1].uppercaseChar() - 'A'
    if (a !in 0..25 || b !in 0..25) return "🏳️"
    return String(Character.toChars(base + a)) + String(Character.toChars(base + b))
}

/** Latency band → pill color (good <80, amber <160, else slow; null → slow). Mirrors latencyClass. */
private fun latColors(ms: Long?): Pair<Color, Color> = when {
    ms == null -> SparkColors.latSlow to Color(0x1FC0341D)
    ms < 80 -> SparkColors.latGood to Color(0x1F1F9D55)
    ms < 160 -> SparkColors.latAmber to Color(0x1FC98A00)
    else -> SparkColors.latSlow to Color(0x1FC0341D)
}

@Composable
fun LatencyPill(ms: Long) {
    val (fg, bg) = latColors(ms)
    Box(
        Modifier.background(bg, RoundedCornerShape(999.dp)).padding(horizontal = 8.dp, vertical = 3.dp),
    ) { Text("$ms ms", color = fg, fontSize = 12.sp, fontWeight = FontWeight.Bold) }
}
```

- [ ] **Step 2: Create `ui/HomeScreen.kt`.** Compose the AppBar ("Spark" wordmark, hairline + soft elevation), the VPN toggle switch (track 140×70dp / knob 60dp / 70dp travel / brand when connected / animated / spinner while connecting — geometry from `+page.svelte` lines 233-265), and the status card (surface, 16dp radius, the teal shadow) with the three rows. Drive it from `SparkState.state` (collected) + `parseServers(SparkBridge.nativeServers())` (polled every 2s with `LaunchedEffect`). Connect/disconnect via `VpnController` + a `rememberLauncherForActivityResult` for consent. The full composable is built against the cited Tauri source; key contract: `HomeScreen(onOpenServers: () -> Unit)`.

> Build the switch with `animateDpAsState` for the knob offset and a `CircularProgressIndicator` (44dp, 8dp stroke, white) for the connecting state. Status row text: Disconnected/Connecting…/Connected/Failed, dot color `indicatorOff`/`brand`/`success`. Smart-location row: `flagEmoji(current.countryCode)` + `serverLabel(current)` (Country – City) + ⚡ (if auto) + latency subtitle; `current` = the member with `isCurrent==true` (or the pinned index). Tapping it calls `onOpenServers()`.

- [ ] **Step 3: Convert `MainActivity.kt`** to host Compose:

```kotlin
package org.getlantern.spark

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import org.getlantern.spark.ui.SparkApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { SparkApp() }
    }
}
```
Create `SparkApp()` (in `ui/SparkTheme.kt` or a new `ui/SparkApp.kt`) wrapping `SparkTheme {}` with the simple nav:
```kotlin
@Composable
fun SparkApp() {
    var onServers by remember { mutableStateOf(false) }
    SparkTheme {
        if (onServers) ServersScreen(onBack = { onServers = false })
        else HomeScreen(onOpenServers = { onServers = true })
    }
}
```

- [ ] **Step 4: Build + run on the emulator.** `./gradlew assembleDebug`, install, launch. Expected: the home screen renders in Lantern styling; the toggle connects (consent → CONNECTING → CONNECTED), the status row + smart-location update live. **Device gate (user).**

- [ ] **Step 5: Commit** (`feat(android): Compose home screen (toggle + status + smart location)`).

---

## Task 7: Server-selection screen

**Files:** Create `ui/ServersScreen.kt`; extend `ui/components.kt` with the server row.

Mirror `gui-tauri/src/routes/servers/+page.svelte`: a "Smart location" card (auto, ⚡) then "ALL LOCATIONS" grouped by country (single-member countries = one row; multi-member = expandable city rows), each row = flag + `serverLabel`/city + `LatencyPill` + **protocol subtitle** (`protocolLabel(protocol)`), pin via `SparkBridge.nativeSelectServer(index)` / auto via `nativeSelectServer(-1)`.

- [ ] **Step 1: Add `protocolLabel` to `ui/components.kt`** (mirror `lib/format.ts`):
```kotlin
fun protocolLabel(p: String?): String = when (p?.lowercase()) {
    null, "" -> ""
    "anytls" -> "AnyTLS"; "samizdat" -> "Samizdat"; "shadowsocks" -> "Shadowsocks"
    "hysteria2" -> "Hysteria2"; "wasm" -> "WASM"; "fronted-meek" -> "Meek"; "tunnel" -> "Tunnel"
    else -> p
}
fun serverLabel(s: org.getlantern.spark.ServerInfo): String =
    listOfNotNull(s.country, s.city).filter { it.isNotBlank() }.joinToString(" – ").ifEmpty { s.name ?: "Server" }
```

- [ ] **Step 2: Create `ui/ServersScreen.kt`** with `ServersScreen(onBack: () -> Unit)`: a top bar with a back chevron + "Server selection"; poll `parseServers(SparkBridge.nativeServers())` every 3s; group by `country`; render the smart-location card + the grouped list (LazyColumn), each member row showing flag + label + protocol subtitle + latency pill + a ✓ when selected. Track the pinned index in a `mutableStateOf<Int?>(null)` (null = auto); on tap call `SparkBridge.nativeSelectServer(index ?: -1)` off the main thread (`LaunchedEffect`/`rememberCoroutineScope` + `Dispatchers.IO`) and pop back. Built against the cited Svelte source (latency-pill colors, the country grouping, the protocol subtitle layout, the ⚡ on auto).

- [ ] **Step 3: Build + run.** Connect, open the server screen. Expected: live pool with flags/latency/protocol; pinning a server re-routes (smart-location tile on home updates). **Device gate (user).**

- [ ] **Step 4: Commit** (`feat(android): Compose server-selection screen (flag · latency · protocol)`).

---

## Task 8: Cleanup + on-device verification

**Files:** Remove dead code from `MainActivity.kt` (old buttons/REQ_VPN/onActivityResult) if any remains; verify the manifest still launches `.MainActivity`.

- [ ] **Step 1: Remove any leftover framework-UI code** (the old `LinearLayout`/`Button` harness, `connect()/disconnect()/startVpn()/onActivityResult` in `MainActivity` — the Compose `VpnController` + launcher replace them). Confirm no `import android.widget.*`.
- [ ] **Step 2: Full clean build** (`./gradlew clean assembleDebug`) — Expected `BUILD SUCCESSFUL`.
- [ ] **Step 3: On-device (emulator) full pass (user gate):** launch → home renders (Urbanist, Lantern colors) → toggle connects (status CONNECTING→CONNECTED) → smart-location shows the current member → open servers → pick a server → back → home reflects the pick → toggle disconnects (status DISCONNECTED). No crash, no ANR.
- [ ] **Step 4: Commit** (`chore(android): remove demo framework UI; Compose is the app`).

---

## Phase 2 completion gate
On the emulator: the app launches into the Compose home (Lantern styling + Urbanist), connects/disconnects via the toggle with live status, the server screen lists the live pool (flag · latency · protocol) and pinning works, and home reflects the selection. `parseServers` unit tests pass. Then Phase 3 (localization fa/ru + RTL) and Phase 4 (gradle cargo-ndk wiring; optional demo→app rename) follow as their own plans.

## Self-review notes
- Spec §3 coverage: home (no protocol row) = Task 6; server screen w/ protocol subtitle = Task 7; mirror-Tauri tokens/font = Task 2; consume JNI bridge = Tasks 6/7; Compose = Task 1. ✓
- Localization (§4) is explicitly Phase 3 (English strings now). Gradle cargo-ndk wiring (§5) is Phase 4. ✓
- The screen composables (Tasks 6/7 Step 2) are described + contracted rather than fully transcribed because they're large and device-verified; every load-bearing helper (theme, parser, pill, flag, protocolLabel, state, controller) has complete code, and the screens cite exact Tauri sources. Implementers build the screens against those references and the `@Preview` + emulator gates.
