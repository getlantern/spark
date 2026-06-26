# Spark Android — Phase 1 (Foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the standalone Spark Android tunnel survive real-world use — expose live pool data to a UI, survive backgrounding (foreground service), stop leaking IPv6 (on Android *and* Apple), and reconnect across network changes — without touching the Rust transport/fetch core beyond thin JNI glue.

**Architecture:** Two new JNI methods wrap existing `spark_core::fd_tunnel` seams (`servers_json`, `select_server`) the Apple shim already uses; the Kotlin `SparkVpnService` gains a foreground service + notification, IPv6 capture, and a `ConnectivityManager` reconnection callback; the Apple `PacketTunnelProvider` gets the parity `NEIPv6Settings` fix. Connection status is derived in Kotlin from the service lifecycle (no new native seam).

**Tech Stack:** Rust + `jni` crate (`spark-android` → `libspark_android.so`, built via `cargo-ndk` + NDK 28), Kotlin/Android `VpnService` (targetSdk 35, minSdk 24), Swift NetworkExtension (Apple parity).

**Spec:** `docs/superpowers/specs/2026-06-25-spark-android-standalone-app-design.md` (§1, §2, §6).

**Branch:** `fisk/android-standalone-app` (already created off `main`).

**Verification reality:** Android `VpnService`/JNI and Apple NE code are **device/emulator-verified**, not unit-testable in isolation (the existing `nativeRun`/`nativeStop` have no unit tests either). The Rust *seam* additions reuse already-tested functions (`snapshot_to_json` is unit-tested). So tasks gate on **compile** (`cargo ndk build`) + explicit **on-device checks**, with TDD applied only where a pure-logic seam exists.

---

## File structure

- `core/src/fd_tunnel.rs` — already exposes `pub fn servers_json() -> String` (line ~141) and `pub fn select_server(index: Option<usize>) -> bool` (line ~152). **No change needed**; the JNI methods call these.
- `platforms/android/src/lib.rs` — JNI lib. **Modify:** add `nativeServers` + `nativeSelectServer` extern functions.
- `platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkBridge.kt` — **Modify:** add the two `external fun` declarations.
- `platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkVpnService.kt` — **Modify:** foreground service + notification, IPv6 capture, reconnection callback.
- `platforms/android/demo/app/src/main/AndroidManifest.xml` — **Modify:** add `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS`; declare `foregroundServiceType` + the special-use property; `supportsRtl="true"`.
- `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift` — **Modify:** add `NEIPv6Settings` default route (lines ~79–81 region).

> Note: Phase 2 promotes `platforms/android/demo/app` → `platforms/android/app`. Phase 1 stays in `demo/app` to keep the diff small; the rename is a Phase 2 task.

---

## Task A: JNI bridge — `nativeServers` + `nativeSelectServer`

**Files:**
- Modify: `platforms/android/src/lib.rs`
- Modify: `platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkBridge.kt`

- [ ] **Step 1: Add the two JNI extern functions in `platforms/android/src/lib.rs`**

Place these next to the existing `Java_org_getlantern_spark_SparkBridge_nativeStop` function, inside the same `#[cfg(target_os = "android")]` module. They wrap the existing `fd_tunnel` seams.

```rust
    /// `SparkBridge.nativeServers()` — the live pool snapshot as a JSON array (see
    /// `spark_core::fd_tunnel::servers_json` / `snapshot_to_json`): one object per member with
    /// index, location metadata, `protocol`, `latencyMs`, `healthy`, `isCurrent`. `[]` when no pool
    /// is active (direct / single relay / not yet connected).
    #[no_mangle]
    pub extern "system" fn Java_org_getlantern_spark_SparkBridge_nativeServers<'local>(
        env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) -> jni::sys::jstring {
        let json = spark_core::fd_tunnel::servers_json();
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// `SparkBridge.nativeSelectServer(index)` — pin which pool member new flows dial first:
    /// `index >= 0` pins that member, `index < 0` returns to auto (latency-ranked). Returns whether
    /// it applied (false if out of range / no active pool). Mirrors the Apple `spark_select`.
    #[no_mangle]
    pub extern "system" fn Java_org_getlantern_spark_SparkBridge_nativeSelectServer<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
        index: jint,
    ) -> jboolean {
        let pin = if index < 0 { None } else { Some(index as usize) };
        u8::from(spark_core::fd_tunnel::select_server(pin))
    }
```

Ensure the `use` block at the top of the module imports what these need (it already imports `JNIEnv`; add `JClass` and the sys types if not present):

```rust
    use jni::objects::JClass;
    use jni::sys::{jboolean, jint};
    use jni::JNIEnv;
```

- [ ] **Step 2: Verify `servers_json` / `select_server` signatures** before relying on them.

Run: `grep -nE "pub fn (servers_json|select_server)" core/src/fd_tunnel.rs`
Expected: `pub fn servers_json() -> String` and `pub fn select_server(index: Option<usize>) -> bool`. If either differs, adjust the wrapper to match (do **not** change `fd_tunnel`).

- [ ] **Step 3: Add the Kotlin declarations in `SparkBridge.kt`**

Add inside the `SparkBridge` object, after `nativeWaitReady`:

```kotlin
    /** The live server pool as a JSON array (see native `servers_json`): one object per member with
     *  index, location metadata, protocol, latencyMs, healthy, isCurrent. "[]" when no pool is
     *  active. Safe to call any time; returns "[]" before connect. */
    external fun nativeServers(): String

    /** Pin which pool member new flows dial: [index] >= 0 pins it, [index] < 0 = auto (fastest).
     *  Returns true if applied (false if out of range / no active pool). */
    external fun nativeSelectServer(index: Int): Boolean
```

- [ ] **Step 4: Cross-compile to verify the JNI symbols link**

Run: `cargo ndk -t arm64-v8a build --release -p spark-android`
Expected: `Finished` with no errors. (The symbol names must be exactly `Java_org_getlantern_spark_SparkBridge_nativeServers` / `...nativeSelectServer` to match the Kotlin `external fun`s.)

- [ ] **Step 5: Confirm the symbols are exported in the `.so`**

Run: `nm -D target/aarch64-linux-android/release/libspark_android.so | grep -E "nativeServers|nativeSelectServer"`
Expected: both symbols listed (text symbols `T`).

- [ ] **Step 6: Commit**

```bash
git add platforms/android/src/lib.rs platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkBridge.kt
git commit -m "feat(android): JNI bridge for live server pool + selection"
```

---

## Task B: Foreground service + notification

**Files:**
- Modify: `platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkVpnService.kt`
- Modify: `platforms/android/demo/app/src/main/AndroidManifest.xml`

**Why:** targetSdk 35 + no `startForeground()` → the system kills the `VpnService` when the app is backgrounded (the moment the user switches apps). The fix is a foreground service with a persistent notification, started before `establish()`.

- [ ] **Step 1: Add the manifest permissions + service type**

In `AndroidManifest.xml`, add these `<uses-permission>` entries next to the existing `INTERNET`:

```xml
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
```

Set `android:supportsRtl="true"` on `<application>` (needed for the Phase 3 Farsi RTL; harmless now).

Change the `<service>` to declare the foreground type + special-use subtype:

```xml
        <service
            android:name=".SparkVpnService"
            android:exported="false"
            android:foregroundServiceType="specialUse"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <property
                android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="vpn" />
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
        </service>
```

> **API note (verify during impl):** Android 14+ requires a declared `foregroundServiceType`. There is no dedicated `vpn` type, so `specialUse` + the subtype property is the documented path for a non-Play / sideloaded VPN. Confirm against current `VpnService` + foreground-service-types docs; if a newer dedicated type exists for VPN, prefer it.

- [ ] **Step 2: Add a notification channel + `startForeground` in `SparkVpnService.kt`**

Add imports:

```kotlin
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.ServiceInfo
import android.os.Build
```

Add a helper and call it at the very top of `startTunnel(...)` (before building the tunnel), and on the `ACTION_STOP` path call `stopForeground`:

```kotlin
    private fun startInForeground() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            nm.getNotificationChannel(CHANNEL_ID) == null
        ) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Spark VPN", NotificationManager.IMPORTANCE_LOW),
            )
        }
        // Tapping the notification opens the app.
        val tap = PendingIntent.getActivity(
            this, 0,
            packageManager.getLaunchIntentForPackage(packageName),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notif: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Spark")
            .setContentText("Connected")
            .setSmallIcon(android.R.drawable.ic_lock_lock) // Phase 2 swaps in the real icon
            .setOngoing(true)
            .setContentIntent(tap)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }
```

Add to the `companion object`:

```kotlin
        private const val CHANNEL_ID = "spark_vpn"
        private const val NOTIF_ID = 1
```

In `startTunnel(...)`, make `startInForeground()` the first line (before `Builder()`). In `stopTunnel()`, add before `stopSelf()`:

```kotlin
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
```

- [ ] **Step 3: Launch the service as a foreground service from the activity**

In `MainActivity.kt` `startVpn()`, replace `startService(...)` with:

```kotlin
    private fun startVpn() {
        Log.i(TAG, "consent granted; starting SparkVpnService")
        val intent = Intent(this, SparkVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent)
        else startService(intent)
    }
```

Add `import android.os.Build` to `MainActivity.kt`.

- [ ] **Step 4: Build the APK**

Run (after Task A's `.so` is in `jniLibs` per the README step):
```bash
cargo ndk -t arm64-v8a -t x86_64 -P 24 -o platforms/android/demo/app/src/main/jniLibs build --release -p spark-android
cd platforms/android/demo && ./gradlew assembleDebug
```
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 5: On-device verification (manual gate)**

Install, connect, then press Home / switch to another app for 2–3 minutes. Expected: the VPN key icon stays, a persistent "Spark — Connected" notification is shown, and traffic still flows (open a site). Before this change the service was killed when backgrounded.

- [ ] **Step 6: Commit**

```bash
git add platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkVpnService.kt \
        platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/MainActivity.kt \
        platforms/android/demo/app/src/main/AndroidManifest.xml
git commit -m "feat(android): run the VpnService in the foreground (survive backgrounding)"
```

---

## Task C: IPv6 capture (no leak)

**Files:**
- Modify: `platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkVpnService.kt`

**Why:** the tunnel only routes `0.0.0.0/0` → IPv6 leaks past the proxy on dual-stack carriers (common in Iran/Russia). Capture IPv6 too; if the core can't proxy a v6 flow it fails closed (no leak).

- [ ] **Step 1: Add a v6 address + default v6 route to the builder**

In `startTunnel(...)`, extend the `Builder()` chain (after `.addRoute("0.0.0.0", 0)`):

```kotlin
            .addAddress(TUN_ADDR6, TUN_PREFIX6) // in-tunnel client v6 address (ULA)
            .addRoute("::", 0) // capture all IPv6 (fail-closed if the core can't proxy v6)
```

Add to the `companion object`:

```kotlin
        private const val TUN_ADDR6 = "fd00::2"
        private const val TUN_PREFIX6 = 64
```

- [ ] **Step 2: Build the APK**

Run:
```bash
cd platforms/android/demo && ./gradlew assembleDebug
```
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: On-device verification (manual gate) — the leak test**

On a **dual-stack** network (or an emulator with IPv6), with the VPN connected, visit an IPv6-reveal page (e.g. `test-ipv6.com` or `https://api6.ipify.org`). Expected: the IPv6 connectivity test does **not** show your real ISP IPv6 address — either it routes through the tunnel or v6 fails closed. Critically: no request should reach an IPv6 destination on the physical interface. (Re-run with the VPN off to confirm the page *can* see v6 normally, proving the test is meaningful.)

- [ ] **Step 4: Commit**

```bash
git add platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkVpnService.kt
git commit -m "fix(android): capture IPv6 in the tunnel (no v6 leak)"
```

---

## Task D: Reconnect on network change

**Files:**
- Modify: `platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkVpnService.kt`

**Why:** mobile users constantly move between Wi-Fi and cellular; the tunnel's underlying socket dies on the switch. Re-establish on default-network change so the connection survives.

- [ ] **Step 1: Register a default-network callback that restarts the tunnel**

Add imports:

```kotlin
import android.net.ConnectivityManager
import android.net.Network
```

Add fields + register/unregister around the tunnel lifecycle. Register in `startTunnel(...)` after the worker starts; unregister in `stopTunnel()`. Debounce by ignoring the first callback (registration fires immediately for the current network) and only acting on a *changed* network handle:

```kotlin
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private var currentNet: Network? = null

    private fun registerNetworkWatcher() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val prev = currentNet
                currentNet = network
                // First callback = current network at registration: adopt it, don't restart.
                if (prev != null && prev != network) {
                    Log.i(TAG, "default network changed; restarting tunnel")
                    restartTunnel()
                }
            }
        }
        netCallback = cb
        cm.registerDefaultNetworkCallback(cb)
    }

    private fun restartTunnel() {
        // Re-establish from scratch: stop the data path, then start a fresh tunnel with the last
        // config. Self-fetch reuses the disk cache, so this is fast.
        val cfg = lastConfig
        SparkBridge.nativeStop()
        worker?.join(2000)
        worker = null
        startTunnel(cfg)
    }
```

Store the config so a restart can reuse it — add a field `private var lastConfig: String? = null` and set it at the top of `startTunnel(config)`: `lastConfig = config`. Guard `startTunnel` against the existing `if (worker != null) return` (already present) — `restartTunnel` clears `worker` first, so the guard won't block it. In `stopTunnel()`, unregister:

```kotlin
        netCallback?.let {
            (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                .unregisterNetworkCallback(it)
        }
        netCallback = null
```

Call `registerNetworkWatcher()` once, at the end of `startTunnel(...)` — but only on the first start, not on a restart, to avoid stacking callbacks. Guard with `if (netCallback == null) registerNetworkWatcher()`.

- [ ] **Step 2: Build the APK**

Run: `cd platforms/android/demo && ./gradlew assembleDebug`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: On-device verification (manual gate)**

Connect on Wi-Fi, start a continuous download or a live page, then toggle Wi-Fi off (device falls to cellular). Expected: within a few seconds the tunnel re-establishes (logcat: "default network changed; restarting tunnel" then "tunnel data path ready") and traffic resumes. Toggle back to Wi-Fi; same.

- [ ] **Step 4: Commit**

```bash
git add platforms/android/demo/app/src/main/kotlin/org/getlantern/spark/SparkVpnService.kt
git commit -m "feat(android): reconnect the tunnel on default-network change"
```

---

## Task E: Apple IPv6 parity backport

**Files:**
- Modify: `platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift` (lines ~79–85)

**Why:** the Apple tunnel sets only `ipv4Settings`, so it leaks IPv6 exactly like the old Android build. Add the v6 settings for parity.

- [ ] **Step 1: Add `NEIPv6Settings` alongside the existing v4 settings**

Find the block:

```swift
        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()] // capture all IPv4
        settings.ipv4Settings = ipv4
```

Add immediately after `settings.ipv4Settings = ipv4`:

```swift
        let ipv6 = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()] // capture all IPv6 (parity with Android)
        settings.ipv6Settings = ipv6
```

- [ ] **Step 2: Build the macOS app**

Run: `./packaging/macos/build-tauri-dmg.sh` (or the xcframework build alone: `platforms/apple/build-xcframework.sh`).
Expected: build succeeds (the Swift change is additive; if `NEIPv6Route.default()` differs in the SDK, the compiler will say so — verify the symbol).

- [ ] **Step 3: On-device verification (manual gate)**

Install the macOS build, connect, run the same IPv6-reveal check (`test-ipv6.com`). Expected: no real IPv6 leak (captured or fails closed), and v4 still works exactly as before (the change is additive).

- [ ] **Step 4: Commit**

```bash
git add platforms/apple/Sources/SparkNE/PacketTunnelProvider.swift
git commit -m "fix(apple): capture IPv6 in the NE tunnel (parity with Android, no v6 leak)"
```

---

## Phase 1 completion gate

After Tasks A–E, on a physical Android device with the release `.so` for both ABIs:
1. The tunnel **survives backgrounding** (foreground service + notification).
2. **No IPv4 or IPv6 leak** (egress via `addDisallowedApplication`; v6 captured/fail-closed).
3. The tunnel **reconnects** across a Wi-Fi↔cellular switch.
4. `nativeServers()` returns a non-empty JSON array (with `protocol`) while connected, and `nativeSelectServer(i)` returns `true` for a valid index. (Quick check: log it from `MainActivity` until Phase 2's UI consumes it.)
5. The Apple build still connects, with IPv6 now captured.

Then proceed to the Phase 2 plan (Compose UI).
