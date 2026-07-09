# Android `:vpn` process split — on-device measurement (Redmi)

Device: Redmi (`HQAEJJWG6HYDWW9P`), Android 15 / API 36, 720×1600, low-RAM class.
Build: **debug** arm64 APK of branch `fisk/android-vpn-process-split` (`app-universal-debug.apk`).
Date: 2026-07-09. Tunnel connected, live traffic.

> **Debug-build caveat:** these are *debug* builds (unstripped, `opt-level=0`), so absolute
> native-heap/PSS numbers run higher than a release build (the core targets <3 MB stripped). The
> point of this measurement is the **structural** result — where the memory lives and what survives
> a UI-process kill — not the absolute MB, which release will shrink.

## Before — single process (pre-split baseline)

Everything (`VpnService` + Rust core + Tauri WebView) ran in **one** process,
`org.getlantern.spark`. Prior profiling of that build (connected):

- Whole-process PSS ~63 MB idle → ~121 MB under YouTube traffic; ~56 MB swapped.
- The WebView (Chromium: ~54 MB "System", ~24 Mali GPU threads, ~95 threads total) shared the
  process with the foreground `VpnService`, so **none of it could be reclaimed while connected** —
  the foreground service pins the whole process resident. On a low-RAM device that WebView memory
  is what gets swap-thrashed and risks an LMK kill of the tunnel.

## After — two processes (`android:process=":vpn"`)

Connected, both processes present:

| Metric | `org.getlantern.spark` (UI/WebView) | `org.getlantern.spark:vpn` (core) |
|---|---:|---:|
| TOTAL PSS | 158,668 KB (~155 MB) | 77,752 KB (~76 MB) |
| TOTAL RSS | 250,244 KB | 159,492 KB |
| **TOTAL SWAP PSS** | **27,857 KB** | **442 KB** |
| EGL mtrack (GPU) | 21,420 KB | — (none) |
| GL mtrack (GPU) | 12,600 KB | — (none) |
| Native Heap | 11,676 KB | 35,632 KB |
| Dalvik Heap | 5,356 KB | 712 KB |

The ~34 MB of GPU graphics memory and **essentially all the swap pressure (27.9 MB vs 0.4 MB)**
are isolated to the UI process. The `:vpn` core carries no EGL/GL and near-zero swap.

## The core win — UI process killed, tunnel survives

Backgrounded the app (HOME) then `adb shell am kill org.getlantern.spark`:

- **UI process: reclaimed** (absent from `ps`). Its ~155 MB PSS / 27.9 MB swap / ~34 MB GPU are freed.
- **`:vpn` process: survives.** PSS 78,207 KB, SWAP **302 KB** — unchanged.
- Foreground `SparkVpnService` still running. Its `ServiceRecord` shows **both** bind intents live —
  `act=org.getlantern.spark.CONTROL` (our control Messenger) and `act=android.net.VpnService` (the
  framework) — confirming the dual-path `onBind` works.
- **VPN still CONNECTED and validated:** `NetworkAgentInfo{ ni{VPN CONNECTED extra:
  VPN:org.getlantern.spark} }`, `tun0` = `10.0.0.2/24` + `fd00::2/64`, default routes `0.0.0.0/0 ->
  tun0` / `::/0 -> tun0`, `IS_VALIDATED`.
- **Through-tunnel connectivity intact:** `ping -c2 8.8.8.8` → 2/2 received, 0% loss, with the UI
  process dead.

Reopening the app re-syncs the UI to CONNECTED via the REGISTER-time state snapshot (no reconnect).

## Conclusion

The split delivers exactly what it was designed for on a low-RAM device: the WebView's GPU +
swap-heavy footprint lives in a UI process the OS can trim/kill under memory pressure, while the
lean `:vpn` core keeps the tunnel established and routing. The prior single-process design could not
reclaim any of that while connected.

## Gates (host / CI)

- Kotlin host unit tests: 10 pass (control protocol mapper ×3, correlation registry ×6, SparkState
  onChange ×1).
- `tauri-plugin-spark-vpn` Rust crate: `cargo fmt --check`, `cargo clippy -D warnings`, 15 tests — clean.
- `spark-android` JNI (arm64) `cargo ndk clippy -D warnings` — clean.

The Messenger / `onBind` / `bindService` glue is not host-unit-testable (no Robolectric); it is
validated on-device here (as above), mirroring the Windows SCM/pipe posture.
