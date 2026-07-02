# UDP per-flow routing + universal domain-carrying — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give UDP the same per-flow smart-routing TCP already has — recover the fake-IP domain, decide Direct/Proxy/Reject, and (for Proxy) carry the domain to the exit — so QUIC/HTTP-3 to domains works under fake-IP, DoT/DoH is intercepted, and UDP is split-tunneled. No client-side DNS leak for proxied UDP.

**Architecture:** Add `UdpTransport::dial_udp_addr(Address)` (mirroring `Transport::dial_addr`), make every UDP-capable transport carry a domain in its UDP frame (UoT/hysteria2/shadowsocks/wasm/tcp_tunnel; Direct resolves locally; fronted-meek stays Unsupported), then rewrite `proxy::udp::run_udp` to consult `RouteHooks` per association exactly like `proxy::tcp::forward`. Encrypted-DNS interception (`is_encrypted_dns`) is a shared TCP+UDP Reject case.

**Tech Stack:** Rust, `async_trait`, the `Address`(=`tcp_tunnel::header::Address`) enum with `Address::encode`, `proxy::RouteHooks` (`router`/`recoverer`/`direct_resolver`/`proxy_resolver`), tokio.

**Preflight / invariants (spark CLAUDE.md):** no `unwrap`/`expect` outside tests; `thiserror` at boundaries; `cargo fmt` + `cargo clippy -D warnings` across the feature matrix; **build/clippy the WHOLE workspace** after any spark-core API change (cli+service call `run_udp`) — `-p spark-core` hides their breaks. The `run_udp` signature change touches 5 call sites: `core/src/fd_tunnel.rs` (×3), `cli/src/main.rs`, `service/src/engine.rs`, plus the test in `core/src/proxy/udp.rs`.

---

### Task 1: `UdpTransport::dial_udp_addr(Address)` trait method

**Files:**
- Modify: `core/src/transport/mod.rs` (the `UdpTransport` trait, ~line 934)
- Test: inline in `core/src/transport/mod.rs`

- [ ] **Step 1: Add the trait method with a default**, mirroring `Transport::dial_addr` (mod.rs:892):

```rust
/// Open a connected UDP association to a target that may be an unresolved **domain** — the fake-IP
/// path, where a flow's real destination is a name recovered from its fake IP. Default: `Ip`
/// delegates to [`dial_udp`](Self::dial_udp); a `Domain` is rejected as `Unsupported` so the
/// forwarder can tell "this transport can't carry a UDP name" from a real failure. Transports whose
/// UDP frame carries an address (UoT / hysteria2 / shadowsocks / wasm / the plain tunnel) override
/// this so the exit resolves — no client-side DNS.
async fn dial_udp_addr(
    &self,
    target: Address,
) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
    match target {
        Address::Ip(sa) => self.dial_udp(sa).await,
        Address::Domain { host, port } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("transport does not support UDP domain targets ({host}:{port})"),
        )),
    }
}
```

- [ ] **Step 2: Verify** — `cargo build -p spark-core --no-default-features --features multi-server` (UdpTransport is always compiled). Existing UDP impls inherit the default, so nothing breaks yet.
- [ ] **Step 3: Commit** — `feat(transport): UdpTransport::dial_udp_addr default (Ip→dial_udp, Domain→Unsupported)`

---

### Task 2: UoT carries a domain (samizdat + anytls)

**Files:**
- Modify: `core/src/transport/uot.rs` (`associate`, line 34)
- Modify: `core/src/transport/samizdat/transport.rs` (add `dial_udp_addr`)
- Modify: `core/src/transport/anytls/transport.rs` + `core/src/transport/anytls/udp.rs` (add `dial_udp_addr`)

- [ ] **Step 1: Make `uot::associate` take an `Address`** — it already encodes via `Address::encode`, so the change is the signature + dropping the `Address::Ip(...)` wrapper:

```rust
pub async fn associate<S>(
    mut stream: S,
    target: Address,                      // was: SocketAddr
) -> io::Result<(BoxedPacketSink, BoxedPacketSource)>
where S: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    let mut hdr = BytesMut::new();
    hdr.put_u8(1);                        // IsConnect=1 (connected mode)
    target.encode(&mut hdr);             // was: Address::Ip(target).encode(&mut hdr)
    stream.write_all(&hdr).await?;
    // …unchanged…
}
```

- [ ] **Step 2: samizdat** — keep `dial_udp(target: SocketAddr)` delegating via `dial_udp_addr(Address::Ip(target))`; add `dial_udp_addr(target: Address)` that opens the UoT-magic CONNECT stream and calls `uot::associate(stream, target)`. (The magic authority is unchanged; only the in-band UoT target gains a domain.)
- [ ] **Step 3: anytls** — same shape in `anytls/udp.rs`: the UoT association now passes `Address` through to `uot::associate`; add `dial_udp_addr` on `AnytlsTransport`.
- [ ] **Step 4: Test** — extend the UoT framing test in `uot.rs` (or `transport::uot`) to assert a `Domain` target encodes as ATYP=3 and round-trips; run `cargo test -p spark-core --features samizdat,anytls transport::`.
- [ ] **Step 5: Commit** — `feat(transport): UoT carries a domain target (samizdat + anytls dial_udp_addr)`

---

### Task 3: hysteria2, shadowsocks, wasm, tcp_tunnel carry a UDP domain

**Files:** `core/src/transport/{hysteria2/mod.rs, shadowsocks/mod.rs, wasm/transport.rs, tcp_tunnel/client.rs}`

- [ ] **Step 1: tcp_tunnel** (easiest — already `Address::encode`): add `dial_udp_addr(target: Address)` that writes `udp_associate_sentinel().encode(&mut header); target.encode(&mut header);` (was `Address::Ip(target).encode`); `dial_udp` delegates via `Address::Ip`.
- [ ] **Step 2: shadowsocks** — the UDP datagram's SOCKS address header already uses the `Address` grammar; add `dial_udp_addr` that encodes the `Address` (domain → ATYP=3) into the datagram header instead of `Address::Ip(target)`.
- [ ] **Step 3: hysteria2** — its UDP message address field is a string host:port; add `dial_udp_addr` that formats the `Address` (domain preserved) into that field rather than the socket-addr string.
- [ ] **Step 4: wasm** — add `dial_udp_addr` carrying the `Address` in the wasm transport's target field.
- [ ] **Step 5: Direct + fronted-meek** — Direct keeps the default (the forwarder resolves a Direct flow before dialing, so `dial_udp` by IP suffices). fronted-meek keeps its `Unsupported` `dial_udp`/inherited `dial_udp_addr` (TCP-polling; no UDP).
- [ ] **Step 6: Test** each: a `dial_udp_addr` with a `Domain` target encodes the domain into the frame (unit test with a captured/echoed header where feasible, mirroring the TCP `dial_addr` tests). `cargo test -p spark-core --features hysteria2,shadowsocks,wasm-transport,anytls`.
- [ ] **Step 7: Commit** — `feat(transport): carry UDP domain targets (hysteria2/shadowsocks/wasm/tcp_tunnel)`

---

### Task 4: SelectingTransport delegates `dial_udp_addr`

**Files:** `core/src/transport/select.rs` (~line 300)

- [ ] **Step 1:** add `dial_udp_addr` mirroring the existing `dial_udp` member-iteration + fail-open-to-direct, but treat `ErrorKind::Unsupported` like `dial_addr` does (skip a member that can't carry a UDP name rather than demoting it). If the chosen member is UDP-unsupported (e.g. fronted-meek), fall through to the next member; if none can, fall open to `direct_udp` (which resolves locally). This fixes the "current-best is fronted-meek → UDP hangs" edge.
- [ ] **Step 2: Test** — a pool of `NoUdp`/`OkUdp` members asserts `dial_udp_addr` skips unsupported and reaches a capable member (extend the existing select udp tests). 
- [ ] **Step 3: Commit** — `feat(transport): SelectingTransport::dial_udp_addr (skip UDP-incapable members)`

---

### Task 5: `is_encrypted_dns` helper (shared TCP + UDP)

**Files:** `core/src/proxy/mod.rs`; wire into `core/src/proxy/tcp.rs`

- [ ] **Step 1: Add the detector** to `proxy/mod.rs` (already imported `SocketAddr`): match port 853 (DoT/DoQ, any IP) or port 443 to a well-known DoH resolver (by recovered hostname, or raw IP — Google/Cloudflare/Quad9/AliDNS/OpenDNS, v4+v6, exact IPs; use `9..=11` style ranges to satisfy clippy `manual_range_patterns`). Full code:

```rust
pub(crate) fn is_encrypted_dns(dst: SocketAddr, domain: Option<&str>) -> bool {
    match dst.port() {
        853 => true,
        443 => domain.is_some_and(is_doh_hostname) || is_public_resolver_ip(dst.ip()),
        _ => false,
    }
}
// is_doh_hostname: dns.google / cloudflare-dns.com / one.one.one.one / dns.quad9.net /
//   dns.alidns.com / doh.opendns.com (trailing-dot- and case-insensitive).
// is_public_resolver_ip: exact v4/v6 resolver IPs (see dns/resolver.rs::known_resolver_sni for the set).
```

- [ ] **Step 2: TCP** — in `proxy/tcp.rs::forward`, before the router decision, when `hooks.is_some()` and `is_encrypted_dns(original_dst, domain)`, set `Decision::Reject` and `debug!` "encrypted DNS → reject, fall back to plain :53".
- [ ] **Step 3: Test** — `encrypted_dns_detection` in `proxy/mod.rs`: `:853` any-IP true; `:443` to `8.8.8.8`/`[2001:4860:4860::8844]`/`dns.google` true; ordinary `:443` + `example.com` false; `:53` false. `cargo test -p spark-core proxy::`.
- [ ] **Step 4: Commit** — `feat(proxy): detect + TCP-Reject encrypted DNS (DoT/DoH) so it falls back to plain :53`

---

### Task 6: Per-flow routing in `run_udp`

**Files:** `core/src/proxy/udp.rs` (`run_udp` sig + `handle_inbound`)

- [ ] **Step 1: Signature** — add `hooks: Option<Arc<RouteHooks>>` and `direct_transport: Arc<dyn UdpTransport>` to `run_udp` (thread both into `handle_inbound`).
- [ ] **Step 2: Route on new association** — before `dial_udp`, when `hooks` is `Some`:
  1. `domain = recoverer.recover(original_dst.ip())`.
  2. `is_encrypted_dns(original_dst, domain)` → drop (return; no association).
  3. `router.decide(original_dst.ip(), domain)`:
     - `Reject` → drop.
     - `Direct` → domain: `direct_resolver.resolve` → `direct_transport.dial_udp(real)`; real-IP: `direct_transport.dial_udp(original_dst)`.
     - `Proxy` → domain: `transport.dial_udp_addr(Address::domain(dom, port))`; on `Unsupported`, fall back to `proxy_resolver.resolve` + `transport.dial_udp(real)`; real-IP: `transport.dial_udp(original_dst)`.
  When `hooks` is `None`: `transport.dial_udp(original_dst)` (today's behavior).
  Keep the association keyed by `(client_src, original_dst)` so the reply pump maps replies back to the **fake** IP the app used (unchanged).
- [ ] **Step 3: Test** — extend `run_udp_round_trips_via_direct_transport`: (a) a fake-IP domain datagram with a stub recoverer+router+resolver dials the resolved real target and round-trips; (b) an encrypted-DNS datagram (`:853`) is dropped (no association); (c) `hooks=None` still proxies by `original_dst`. `bin/testsetup`-free (uses in-memory duplex like the existing test).
- [ ] **Step 4: Commit** — `feat(proxy): per-flow UDP routing (recover/decide/dial-by-name) mirroring TCP`

---

### Task 7: Wire the call sites + whole-workspace gate

**Files:** `core/src/fd_tunnel.rs` (×3 `run_udp`), `cli/src/main.rs`, `service/src/engine.rs`

- [ ] **Step 1: fd_tunnel** — in `setup_routing_and_udp`, pass the just-built `hooks` (Some when smart-routing active, else None) + a direct UDP transport to the smart-routing `run_udp` spawn; the no-rules and `#[cfg(not(smart-routing))]` spawns pass `None` + the direct transport.
- [ ] **Step 2: cli + service** — pass `None` hooks + a `DirectTransport` for the direct-UDP arg (they have no smart-routing hooks) → behavior unchanged.
- [ ] **Step 3: Gate** — `cargo fmt --all --check`; clippy across `--no-default-features`, `smart-routing`, `smart-routing,bootstrap-dns`, and `--workspace --all-features`; `cargo build --workspace`; `cargo test -p spark-core` full-feature. Android-target compile-check via `cargo ndk -t arm64-v8a build -p spark-android --locked`.
- [ ] **Step 4: Commit** — `feat(proxy): thread RouteHooks + direct UDP transport through run_udp call sites`

---

### Task 8: On-device re-test (Redmi 15C) + PR

**Files:** none (validation)

- [ ] **Step 1:** rebuild the APK from this branch; `adb push` + manual install on the Redmi (Xiaomi gates block `adb install`/`input`; user installs + taps Connect); leave **Private DNS on** (default).
- [ ] **Step 2: Validate over adb (read-only works):** logcat shows encrypted-DNS `:853`/`:443`-resolver flows **Rejected**, plain `:53` fake-IP answering, QUIC/HTTP-3 to domains now returning bytes (`to_app>0`), and ad domains `decision=Reject`. Confirm browsing works with Private DNS on. Capture `dumpsys meminfo` for the footprint record (§2).
- [ ] **Step 3:** open the PR (mermaid sequence diagram of the UDP route→dial-by-name flow per the PR-diagram convention), request Copilot, run the `/review-pr` loop.

---

## Self-review

- **Coverage:** trait (T1) → UoT (T2) → other transports (T3) → select (T4) → encrypted-DNS (T5) → run_udp routing (T6) → call sites/gate (T7) → device/PR (T8). Every UDP transport gets `dial_udp_addr`; fronted-meek stays Unsupported (documented).
- **Backward-compatible:** `hooks=None` preserves today's proxy-everything UDP (cli/service unaffected).
- **No client DNS leak for Proxy UDP:** `dial_udp_addr` carries the name to the exit; client-side resolve is only the `Unsupported` fallback.
- **Whole-workspace:** the `run_udp` signature change is called out with all 5 call sites (spark-verify-whole-workspace memory).
- **Type consistency:** `Address` = `tcp_tunnel::header::Address` throughout; `dial_udp_addr` mirrors `dial_addr`'s `Unsupported`-on-domain contract so `SelectingTransport` can skip incapable members.
