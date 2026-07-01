# Smart-routing / ad-block — on-device validation checklist

Everything in the smart-routing feature is verified in CI **except the TUN boundary itself** —
real IP packets through `utun` / `VpnService`, real DoH resolution, and the real kindling `.srs`
fetch over the network. This checklist is the on-device/staging pass that closes those gaps before
relying on the feature in a release.

Run it on a real device (ideally a low-end Redmi-class Android phone — MIUI/HyperOS is the harshest
for foreground-service VPNs; see the standalone-app notes) with a `config_raw.json` whose
`smart_routing` / `ad_block` / `route` sections are populated and whose `.srs` `rule_sets` are hosted
on a **frontable CDN** (CloudFront / Akamai / Aliyun — kindling can't front a raw-GitHub/Fastly URL).

## Prerequisites

- A build with the `smart-routing` cargo feature on (already enabled in the Android + Apple slices).
- A config that carries rules (fetched via `lantern-api`, or a local `config_raw.json`).
- Log visibility:
  - **Android:** `adb logcat -s spark_android` (the JNI shim routes the core's `tracing` events to
    logcat; smart-routing logs at target `spark`).
  - **Apple:** `log stream --predicate 'subsystem == "org.getlantern.spark"'`.

## 1. Functional — routing decisions (the core deliverable)

- [ ] **Ad/malware domain is blocked.** Visit a known `ad_block`-listed domain (e.g. an ad/tracker
      the `banad`/`category-ads` lists cover). The request fails/drops; the forwarder logs a
      `tcp flow rejected by routing rule` at debug. No connection to the ad server.
- [ ] **Direct-listed domain egresses direct.** A `smart_routing`-common / `route.rules` domain
      (e.g. a local-CDN or Quad9 `9.9.9.9`) connects **without** going through the proxy — confirm via
      the exit's absence in the path (e.g. the direct site sees the device's real egress IP, not the
      proxy's) and a `Direct` decision in the log.
- [ ] **Ordinary domain is proxied.** Any unlisted site loads normally through the proxy pool
      (`Proxy` decision; exit IP visible to the site).
- [ ] **No DNS loop / no hang.** The tunnel comes up promptly and browsing is responsive — the
      fake-IP resolvers' own sockets must bypass the TUN (`addDisallowedApplication` / NE bypass). A
      loop would manifest as DNS timeouts / connect hangs.
- [ ] **QUIC / UDP honored.** A QUIC site (e.g. a Google property over HTTP/3) works — DNS `:53` is
      intercepted and other UDP is proxied; confirm no UDP blackhole.
- [ ] **Fake-IP correctness.** DNS answers for browsed domains return `198.18.x.x` (v4) / `fd00:2018::`
      (v6) fake IPs, and connections to them resolve to the right domain in the routing log.

## 2. Footprint (M5 — the piece that needs the low-end device)

- [ ] **RAM.** With the full rule-sets loaded, resident memory is within budget for the target device
      (measure via `adb shell dumpsys meminfo <pkg>` at steady state). Record the number.
- [ ] **No jank / ANR at connect.** Toggling the VPN on doesn't freeze the UI or trigger an ANR while
      the rule-sets parse. (The `.srs` parse was optimized O(n²)→O(n log n); `banad_v1` is ~0.01 s in
      release on desktop — confirm the release build stays snappy on the slower ARM CPU.)
- [ ] **Parse timing on-device.** Log/measure `srs::parse` + matcher build time for the full list set
      at startup; confirm it's well under a second on the target CPU. If not, revisit compaction /
      subsetting (deferred per the spec).

## 3. Rule-set fetch (M6 — needs a frontable host)

- [ ] **Cold fetch populates the cache.** On first connect with an empty cache, the background loop
      fetches each `.srs` via kindling and writes `<data_dir>/rulesets/<tag>.srs` (`ruleset: cache
      updated` in the log). Rules apply on the **next** connect (no live router swap in v1).
- [ ] **Offline uses the cache.** With the network to the rule-set host blocked, the tunnel still
      comes up and routing works from the last-good cache (`fetch failed; keeping cached .srs`).
- [ ] **Corrupt/absent cache degrades safely.** A missing or unparseable cache never fails the
      tunnel — it degrades to proxy-everything for that list.
- [ ] **Refresh picks up an update.** After the interval (12 h; shorten for the test), an updated
      `.srs` on the host is fetched and applied on the following connect.

## 4. Kill switch / safety

- [ ] Disabling smart-routing (feature off, or a config with no rules) falls back cleanly to
      proxy-everything with no fake-IP DNS interception — i.e. exactly today's behavior.

## Recording results

Note the device model, OS/skin version, build commit, and the RAM + parse-timing numbers here (or in
the tracking issue) so the footprint budget has a concrete baseline for the target hardware.
