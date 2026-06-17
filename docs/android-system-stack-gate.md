# On-device gate: the system (kernel-TCP) netstack on Android

- **Status:** Scoped runbook — not yet executed (needs a physical device + a `VpnService` host app).
- **Goal:** prove spark's `stack = system` works on a real Android device, and that it **fixes the
  concurrent-download collapse** there (the mobile payoff of `docs/system-stack-design.md`).
- **Prereqs in-tree:** the system stack is built + feature-enabled for Android and the aarch64 build
  is verified (`cargo ndk … check/clippy` clean). What's missing is the host app + on-device run.

## 0. Why this is lower-risk than it looks

sing-box ships `stack: system` on Android using the *same* redirect-to-local-listener mechanism (it
adopts the `VpnService` Linux tun fd — verified against `sing-tun@v0.7.11`). So the approach is
known-good on Android; this gate is validating **our implementation**, not whether the technique is
possible. That reframes most "will Android allow this?" risks below to "does our impl have a bug?"

## 1. Pass criteria

With `systemStack = 1`:
1. **TCP works** — load an HTTPS page / `curl` through the tunnel.
2. **DNS/UDP works** — name resolution succeeds (proves the mixed stack's UDP datagram path).
3. **No concurrent-download collapse** — the A/B (§5): on `systemStack = 0` (userspace) ≥2 parallel
   downloads collapse (as in the netns gate); on `systemStack = 1` they hold. This is the point.
4. **Stable under churn** — sustained transfer + many short connections (exercises FIN/RST NAT
   removal); no crash, no unbounded memory/port growth, no leaked flows in logcat.

## 2. Build the native library

The `system-stack` feature is target-gated **on** for Android, so a normal Android build includes it
(no extra flag). Drop the `.so` straight into the app's `jniLibs`:

```bash
# arm64 device (add -t armeabi-v7a / x86_64 as needed; x86_64 covers the emulator)
cargo ndk -t arm64-v8a -o app/src/main/jniLibs build --release -p spark-android
```

(Release profile is `opt-level=3` — note the `.so` size; it's well under any concern.)

## 3. The app-side contract (the missing piece)

A minimal `VpnService` host. The load-bearing details:

```kotlin
package org.getlantern.spark

object SparkBridge {
    init { System.loadLibrary("spark_android") }
    // addr = tun IPv4 packed big-endian into an Int; systemStack: 1 = kernel-TCP, 0 = userspace.
    external fun nativeRun(fd: Int, mtu: Int, addr: Int, prefix: Int, systemStack: Int): Int
    external fun nativeStop()
}

// IPv4 "10.0.0.1" -> 0x0A000001 (big-endian), matching Ipv4Addr::from(u32) on the Rust side.
fun packV4(a: Int, b: Int, c: Int, d: Int) = (a shl 24) or (b shl 16) or (c shl 8) or d

class SparkVpnService : VpnService() {
    fun connect() {
        val mtu = 1500
        val builder = Builder()
            .setMtu(mtu)
            .addAddress("10.0.0.1", 24)        // prefix MUST cover addr+1 = 10.0.0.2 (the gateway)
            .addRoute("0.0.0.0", 0)            // full tunnel (or a /32 test route)
            .addDnsServer("1.1.1.1")           // exercised via the mixed (UDP) stack
            .addDisallowedApplication(packageName) // upstream dials bypass the tun — loop avoidance
        val pfd = builder.establish() ?: return
        val fd = pfd.detachFd()
        Thread {
            // nativeRun blocks until nativeStop(); 0 = clean stop, -1 = error.
            SparkBridge.nativeRun(fd, mtu, packV4(10, 0, 0, 1), 24, /* systemStack = */ 1)
        }.start()
    }
    fun disconnect() = SparkBridge.nativeStop()
}
```

Three things that *must* line up:
- The `addr` passed to `nativeRun` **equals** the `addAddress(...)` address (the system stack binds
  its kernel listener there).
- `prefix` **covers `addr + 1`** — the synthetic gateway (`10.0.0.2` here) must route via the tun.
- `addDisallowedApplication(packageName)` is what keeps the app's own upstream sockets off the tun,
  so there's **no per-socket `protect()`** to do (the Linux `IP_UNICAST_IF` analog is handled by the
  framework excluding the app's UID).

A `systemStack` toggle (1/0) in the app's UI is what makes the §5 A/B one tap.

## 4. Functional checks (do these first)

Run with `adb logcat -s spark` open — the core routes its `tracing` to logcat (tag `spark`).

| check | how | logcat signal |
|---|---|---|
| tunnel up | connect, `systemStack=1` | `spark tunnel up (fd mode)` |
| TCP | open `https://example.com` in a browser | `tcp flow completed to_upstream=… to_app=…` |
| DNS/UDP | resolve a fresh hostname (clear DNS cache) | flows to `:53`; resolution succeeds |
| teardown/churn | load a busy page (many conns), disconnect | many `tcp flow completed`, clean stop |

Red flags in logcat: **no flows at all** → the redirect isn't reaching the listener (routing/rp_filter,
§6); `tcp flow error … Connection reset` on *every* flow → upstream dials looping or blocked;
`accepted connection has no NAT mapping` → NAT/timing.

## 5. The collapse A/B (the headline measurement)

Mirror the netns gate on-device. Need a throughput source reachable from the device — e.g. a DO
droplet running `iperf3 -s`, or an HTTP server with a large file.

1. **Userspace baseline:** `systemStack=0`, run **≥2 concurrent downloads** (iperf3 `-P 4 -R`, or 4
   parallel large-file fetches). Expect the netns pattern: aggregate **download collapses** well
   below single-stream.
2. **System stack:** same test, `systemStack=1`. Expect download to **hold** (~single-stream-each,
   no collapse) — download symmetric with upload.
3. Compare aggregate Mbps. The win is the *ratio at concurrency*, not the absolute number (mobile
   CPU/radio caps the absolute well below the netns droplet's loopback numbers).

Tooling: an `iperf3` Android build, Termux `iperf3`, or a scripted parallel `curl`/`OkHttp` fetch.

## 6. Risk register (what to watch, Android-specific)

Ordered by likelihood of biting:

1. **Local delivery of the redirect.** spark writes a packet to the tun fd with `dst = 10.0.0.1`
   (the tun's own address) expecting the kernel to deliver it to the listener. This is the crux and
   the thing the gate most directly proves. *De-risked by sing-box doing exactly this on Android.*
2. **Per-UID / fwmark routing.** Android routes per-app via `fwmark` + multiple tables; the
   VpnService tun + `addDisallowedApplication` use it. The redirect loop must still deliver to the
   app's listener. If flows never appear in logcat, this (or #3) is why. sing-box works, so it's
   solvable — but it's the most likely place behavior differs from the netns gate.
3. **`rp_filter`.** The redirected ingress packet has `src = 10.0.0.2` arriving on the tun; under
   *strict* `rp_filter` the reverse route to `10.0.0.2` is via the tun = the arrival iface, so it
   **should pass naturally** (the netns gate set `rp_filter=0` only defensively — likely
   unnecessary). **Residual risk:** if it *does* drop, an unprivileged app **cannot** `sysctl` it —
   that'd be a hard blocker on unrooted devices. Verify early; if flows are missing, test a rooted
   device with `rp_filter=0` to isolate.
4. **IPv6.** Only v4 is wired (`server_v6 = None`), so v6 TCP isn't intercepted. For the gate,
   configure a v4 address and avoid handing the tun a v6 default route (or accept v6 passes through
   unhandled). Full v6 support is a follow-up.
5. **SELinux.** Binding a listener + tun fd ops should be within the `untrusted_app` domain's
   allowances (VpnService apps do this); low risk, but a denial would show in `adb logcat -b events`
   / `dmesg` as an `avc:` line.
6. **CPU/battery.** The single pump task + double kernel-TCP on a mobile core — watch CPU during the
   sustained transfer; this is where the "single pump = serialization point" (→ multi-pump/GSO
   future work) shows up, if anywhere.

## 7. Runbook (condensed)

1. `cargo ndk -t arm64-v8a -o app/src/main/jniLibs build --release -p spark-android`.
2. Build/install the host app (5-arg `SparkBridge`, the `VpnService.Builder` of §3).
3. `adb logcat -c && adb logcat -s spark` in a terminal.
4. Connect with `systemStack=1`; run the §4 functional checks (TCP, DNS, churn).
5. Run the §5 A/B (toggle `systemStack` 0↔1; ≥2 concurrent downloads each).
6. **Pass** = §1 criteria met: TCP + DNS work on the system stack, and concurrent download doesn't
   collapse the way userspace does.

## 8. If it fails

- **No flows in logcat** → routing/rp_filter (§6.1–6.3). Try a rooted device with `rp_filter=0` and
  a packet capture (`VpnService` tun via `adb shell tcpdump` on rooted, or `pcap` of the upstream)
  to see whether redirected packets reach the listener.
- **Every flow RSTs** → upstream dials are looping (confirm `addDisallowedApplication`) or blocked.
- **Works but slow / collapses anyway** → that's data, not a failure: it means the mobile bottleneck
  is elsewhere (per-packet fd crossing); feed it into the multi-pump/GSO decision.
