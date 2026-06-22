# Hysteria 2 Transport Implementation Plan

> **For implementers:** work this plan task-by-task — TDD each task (failing test first), keep the tree green at every boundary, and commit per task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Hysteria 2 client `Transport` + `UdpTransport` to spark, interoperable with deployed `apernet/hysteria` servers — spark's first QUIC transport, on `quinn` (rustls/ring), with Salamander + Gecko obfuscation.

**Architecture:** A `hysteria2`-feature-gated module under `core/src/transport/hysteria2/`. A single authenticated `quinn` connection per transport; TCP rides raw QUIC bidi streams (`0x401` TCPRequest), UDP rides QUIC datagrams (UDPMessage + fragmentation). Auth is one hand-rolled HTTP/3 `POST /auth` (→ `233`). Salamander + Gecko are a custom `quinn::AsyncUdpSocket` that transforms whole QUIC packets below quinn.

**Tech Stack:** Rust, tokio, `quinn` 0.11 (+ `quinn-udp` 0.5) on **rustls 0.23 with the ring provider** (NOT aws-lc-rs), `blake2` (Salamander), `bytes`, `async-trait`. Spec: `docs/hysteria2-design.md` (ADR 0010). Protocol: `https://v2.hysteria.network/docs/developers/Protocol/`.

**Conventions (spark CLAUDE.md — apply every task):** one `thiserror` `Error` enum per module; no `unwrap()`/`expect()` outside tests/startup; `BytesMut` (not `Vec<u8>`) on data paths; no `MutexGuard` across `.await`; only cancel-safe futures in `select!`/poll; `cargo fmt` + `cargo clippy --all-targets -- -D warnings` clean before each commit. **Verification discipline:** quinn/quinn-udp/rustls are version-sensitive — every step touching them carries a "VERIFY at docs.rs" note; confirm the exact signature before writing, don't guess. Pure-Rust deterministic code (codecs, obfs transforms, QPACK, config) is given complete.

**The authoritative oracle is the live interop gate (Task 12), not this prose** — where a byte layout here disagrees with what a real `apernet/hysteria` server accepts, the server is right.

---

## File Structure

| File | Responsibility |
|---|---|
| `core/src/config/mod.rs` (modify) | `Hysteria2Config`, `Hysteria2Tls`, `Hysteria2Obfs`, `ServerSpec::Hysteria2`, `TransportConfig.hysteria2`, `first_unresolved_host` arm |
| `core/src/bootstrap/mod.rs` (modify) | `resolve_endpoints` arm (SNI applies) |
| `core/src/transport/mod.rs` (modify) | `hysteria2_transport` builder, `from_config` precedence, `build_one` arm, `pub mod hysteria2` gate |
| `core/src/transport/hysteria2/mod.rs` (create) | `Hysteria2Transport` (impl `Transport`+`UdpTransport`); quinn endpoint/connect/auth; dial/dial_udp; UDP receive pump; `Error` enum |
| `core/src/transport/hysteria2/obfs.rs` (create) | Salamander + Gecko transform fns + `GeckoReassembler` + `SalamanderGeckoSocket` (`AsyncUdpSocket`) |
| `core/src/transport/hysteria2/tcp.rs` (create) | varint + TCPRequest encode / TCPResponse decode + the bidi-stream `BoxedStream` adapter |
| `core/src/transport/hysteria2/udp.rs` (create) | UDPMessage encode/decode + fragmentation/reassembly + sink/source |
| `core/src/transport/hysteria2/auth.rs` (create) | minimal HTTP/3 `POST /auth` request encode + `233` response decode (QPACK, no dynamic table) |
| `core/Cargo.toml`, `Cargo.toml` (modify) | `hysteria2` feature; `quinn`/`quinn-udp`/`blake2` optional deps |
| `docs/adr/0010-hysteria2-transport.md` (create) | the ADR |

---

## Task 1: Feature + deps + module skeleton + config types

**Files:** `Cargo.toml`, `core/Cargo.toml`, `core/src/transport/mod.rs`, `core/src/config/mod.rs`, create `core/src/transport/hysteria2/{mod,obfs,tcp,udp,auth}.rs`.

- [ ] **Step 1: Workspace + core deps.** Root `Cargo.toml` `[workspace.dependencies]`:
```toml
quinn = { version = "0.11", default-features = false, features = ["runtime-tokio", "rustls-ring", "log"] }
quinn-udp = "0.5"
blake2 = { version = "0.10", default-features = false }
```
VERIFY at `docs.rs/crate/quinn/latest/features`: the ring feature is `rustls-ring` (NOT `rustls-aws-lc-rs`); confirm `runtime-tokio` is present; confirm `default-features = false` still yields `quinn::crypto::rustls::QuicClientConfig`. `core/Cargo.toml` `[dependencies]`:
```toml
quinn = { workspace = true, optional = true }
quinn-udp = { workspace = true, optional = true }
blake2 = { workspace = true, optional = true }
```
`[features]`:
```toml
# Hysteria 2 transport (ADR 0010): QUIC (quinn/rustls-ring) client interoperable with apernet/hysteria,
# with Salamander+Gecko obfuscation. Off by default so the base build pulls no QUIC stack.
hysteria2 = ["dep:quinn", "dep:quinn-udp", "dep:blake2"]
```

- [ ] **Step 2: Module gate.** In `core/src/transport/mod.rs`, beside the other gates:
```rust
/// Hysteria 2 transport (ADR 0010): a QUIC client (quinn/rustls-ring) interoperable with deployed
/// apernet/hysteria servers, with Salamander+Gecko obfuscation. Behind the `hysteria2` feature so the
/// base build pulls no QUIC stack.
#[cfg(feature = "hysteria2")]
pub mod hysteria2;
```
Create the five module files, each with a `//!` line; `mod.rs` declares `mod obfs; mod tcp; mod udp; mod auth;`.

- [ ] **Step 3: Write the failing config test** (in `core/src/config/mod.rs` tests):
```rust
#[test]
fn hysteria2_config_round_trips_through_toml() {
    let toml = r#"
[transport.hysteria2]
server = "proxy.example.com:443"
auth = "secret"

[transport.hysteria2.obfs]
type = "salamander"
password = "obfskey"
gecko = true
"#;
    let cfg = Config::from_toml_str(toml).unwrap();
    let h = cfg.transport.hysteria2.clone().unwrap();
    assert_eq!(h.server, "proxy.example.com:443".parse().unwrap());
    assert_eq!(h.auth, "secret");
    let obfs = h.obfs.unwrap();
    assert_eq!(obfs.password, "obfskey");
    assert!(obfs.gecko);
    assert!(matches!(h.tls.mode, Hysteria2TlsMode::SystemRoots)); // default
}
```

- [ ] **Step 4: Run → fail.** `cargo test -p spark-core config::tests::hysteria2` (compile error).

- [ ] **Step 5: Add the config types** in `core/src/config/mod.rs` (next to `ShadowsocksConfig`):
```rust
/// Hysteria 2 transport configuration (ADR 0010). A QUIC client interoperable with apernet/hysteria.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Config {
    /// Server address — `IP:port` or `host:port` (resolved at startup).
    pub server: Endpoint,
    /// `Hysteria-Auth` credential.
    pub auth: String,
    /// TLS SNI. When omitted: bootstrap fills it with the hostname; for an IP it defaults to the IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Client receive-rate hint sent as `Hysteria-CC-RX` (Mbps; 0 = unknown → server uses BBR).
    #[serde(default)]
    pub down_mbps: u32,
    /// TLS verification mode.
    #[serde(default)]
    pub tls: Hysteria2Tls,
    /// Optional Salamander/Gecko obfuscation. Omit for plain QUIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Hysteria2Obfs>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Tls {
    #[serde(default)]
    pub mode: Hysteria2TlsMode,
    /// Hex SHA-256 of the server cert; required when `mode = "pin-sha256"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Hysteria2TlsMode {
    #[default]
    SystemRoots,
    PinSha256,
    Insecure,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Obfs {
    /// Only `"salamander"` in v1.
    #[serde(rename = "type")]
    pub kind: String,
    /// Obfuscation pre-shared key.
    pub password: String,
    /// Wrap Salamander with Gecko handshake-fragmentation.
    #[serde(default)]
    pub gecko: bool,
}
```
Add `ServerSpec::Hysteria2(Hysteria2Config)` (tag `kind = "hysteria2"`), `TransportConfig.hysteria2: Option<Hysteria2Config>` (`#[serde(skip_serializing_if = "Option::is_none")]`), the `shadowsocks: None`-style entry in the **manual `impl Default for TransportConfig`**, and the `ServerSpec::Hysteria2(c) => Some(&c.server)` arm + `transport.hysteria2` single in `first_unresolved_host`.

- [ ] **Step 6: Run → pass.** `cargo test -p spark-core config::tests::hysteria2`.

- [ ] **Step 7: Fix literal sites + sweep.** `cargo build --all-targets`; add `hysteria2: None` to any broken `TransportConfig { .. }` literal (cli, tests). `cargo build -p spark-core --features hysteria2` (empty modules compile). `cargo fmt`.

- [ ] **Step 8: Commit.**
```bash
git add -A && git commit -m "feat(hysteria2): cargo feature + config types + module skeleton"
```

---

## Task 2: Salamander obfuscation transform (`obfs.rs`)

Pure functions, fully testable without a socket.

- [ ] **Step 1: Failing tests.**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_round_trips() {
        let key = b"presharedkey";
        let packet = b"a fake QUIC packet payload";
        let on_wire = salamander_obfuscate(key, packet);
        assert_eq!(on_wire.len(), 8 + packet.len()); // salt + xored
        let back = salamander_deobfuscate(key, &on_wire).unwrap();
        assert_eq!(back, packet);
    }

    #[test]
    fn salamander_rejects_too_short() {
        assert!(salamander_deobfuscate(b"k", &[0u8; 4]).is_none()); // < 8-byte salt
    }

    #[test]
    fn salamander_keystream_matches_blake2b() {
        // hash = BLAKE2b-256(key ‖ salt); payload[i] ^= hash[i % 32]
        let key = b"k";
        let salt = [9u8; 8];
        let mut p = vec![0u8; 40];
        let mut wire = salt.to_vec();
        wire.extend_from_slice(&p); // obfuscating zeros yields the raw keystream
        let out = salamander_xor_with_salt(key, &salt, &mut p); // helper used internally
        let expected = blake2b256(&[key.as_slice(), &salt].concat());
        for i in 0..p.len() {
            assert_eq!(out[i], expected[i % 32]);
        }
    }
}
```

- [ ] **Step 2: Run → fail.** `cargo test -p spark-core --features hysteria2 hysteria2::obfs::tests::salamander`.

- [ ] **Step 3: Implement.**
```rust
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

type Blake2b256 = Blake2b<U32>;

fn blake2b256(input: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(input);
    h.finalize().into()
}

const SALT_LEN: usize = 8;

/// Salamander: prepend an 8-byte random salt and XOR the packet with BLAKE2b-256(key‖salt) keystream.
pub fn salamander_obfuscate(key: &[u8], packet: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt)
        .expect("system rng"); // startup/infallible OS RNG; matches repo convention in tests/dialers
    let mut payload = packet.to_vec();
    salamander_xor_with_salt(key, &salt, &mut payload);
    let mut out = Vec::with_capacity(SALT_LEN + payload.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&payload);
    out
}

/// Reverse of `salamander_obfuscate`. `None` if too short to carry a salt.
pub fn salamander_deobfuscate(key: &[u8], datagram: &[u8]) -> Option<Vec<u8>> {
    if datagram.len() < SALT_LEN {
        return None;
    }
    let (salt, body) = datagram.split_at(SALT_LEN);
    let mut payload = body.to_vec();
    let salt: [u8; SALT_LEN] = salt.try_into().ok()?;
    salamander_xor_with_salt(key, &salt, &mut payload);
    Some(payload)
}

/// XOR `payload` in place with the BLAKE2b-256(key‖salt) keystream (repeating every 32 bytes).
/// Returns a copy of the result too, for test assertions.
fn salamander_xor_with_salt(key: &[u8], salt: &[u8; SALT_LEN], payload: &mut [u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(key.len() + SALT_LEN);
    material.extend_from_slice(key);
    material.extend_from_slice(salt);
    let hash = blake2b256(&material);
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= hash[i % 32];
    }
    payload.to_vec()
}
```
> The `.expect("system rng")` on `SystemRandom::fill` is the one sanctioned infallible-OS-RNG use (ring's fill only fails if the OS entropy source is unavailable). If you prefer, thread a `Result` — but obfuscation runs per packet on the hot path and a failed OS RNG is unrecoverable; keep the expect with the comment. VERIFY `blake2` 0.10 API: `Blake2b<U32>` + `Digest`.

- [ ] **Step 4: Run → pass.** Same filter.
- [ ] **Step 5: Commit.** `git commit -m "feat(hysteria2): Salamander obfuscation transform"`

---

## Task 3: Gecko obfuscation transform + reassembler (`obfs.rs`)

- [ ] **Step 1: Failing tests.**
```rust
    #[test]
    fn gecko_short_header_passes_through() {
        // high bit clear => short header => one piece, unchanged
        let packet = vec![0x40, 1, 2, 3];
        let frames = gecko_split(&packet, 7);
        assert_eq!(frames, vec![packet]);
    }

    #[test]
    fn gecko_long_header_splits_and_reassembles() {
        let packet: Vec<u8> = std::iter::successors(Some(0xC0u8), |b| Some(b.wrapping_add(1)))
            .take(300).collect(); // high bit set => long header
        let frames = gecko_split(&packet, 0x55);
        assert!(frames.len() >= 2 && frames.len() <= 8);
        let mut r = GeckoReassembler::new();
        let mut done = None;
        for f in &frames {
            // each frame is a complete Gecko datagram (flags=0x80, ...)
            if let Some(pkt) = r.accept(f) {
                done = Some(pkt);
            }
        }
        assert_eq!(done.unwrap(), packet);
    }

    #[test]
    fn gecko_reassembler_rejects_malformed() {
        let mut r = GeckoReassembler::new();
        assert!(r.accept(&[0x80, 1]).is_none()); // truncated frame
        assert!(r.accept(&[0x00, 1, 2]).is_none()); // not a gecko frame (flags != 0x80)
    }
```

- [ ] **Step 2: Run → fail.**

- [ ] **Step 3: Implement.** `gecko_split` returns `Vec<Vec<u8>>`: for a short-header packet (`packet[0] & 0x80 == 0`) → `vec![packet.to_vec()]`; for long-header → split into `n ∈ [2,8]` chunks, each wrapped:
```rust
const GECKO_FLAG: u8 = 0x80;

/// Split a QUIC packet into Gecko frames. Short-header packets pass through unchanged (one element).
/// Long-header packets are split into 2..=8 chunks, each wrapped in a Gecko frame with random padding.
/// `seed` varies the msgID + split per call (callers pass a per-packet value; tests pass a fixed one).
pub fn gecko_split(packet: &[u8], seed: u8) -> Vec<Vec<u8>> {
    if packet.is_empty() || packet[0] & GECKO_FLAG == 0 {
        return vec![packet.to_vec()];
    }
    let rng = ring::rand::SystemRandom::new();
    let mut nbuf = [0u8; 2];
    let _ = ring::rand::SecureRandom::fill(&rng, &mut nbuf);
    let total = 2 + (nbuf[0] % 7) as usize; // 2..=8
    let msg_id = nbuf[1] ^ seed;
    let base = packet.len() / total;
    let mut frames = Vec::with_capacity(total);
    let mut off = 0;
    for idx in 0..total {
        let end = if idx == total - 1 { packet.len() } else { off + base };
        let chunk = &packet[off..end];
        off = end;
        let mut pad = [0u8; 1];
        let _ = ring::rand::SecureRandom::fill(&rng, &mut pad);
        let pad_len = (pad[0] % 16) as usize; // bounded random padding
        let mut padding = vec![0u8; pad_len];
        let _ = ring::rand::SecureRandom::fill(&rng, &mut padding);
        let mut frame = Vec::with_capacity(5 + pad_len + chunk.len());
        frame.push(GECKO_FLAG); // flags
        frame.push(msg_id); // msgID
        frame.push(((idx as u8) << 4) | (total as u8)); // chunkIdx:4 | totalChunks:4
        frame.extend_from_slice(&(pad_len as u16).to_be_bytes()); // padLen
        frame.extend_from_slice(&padding);
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }
    frames
}

/// Reassembles Gecko frames keyed by msgID. Bounded: caps concurrent msgIDs and total buffered bytes.
pub struct GeckoReassembler {
    partial: std::collections::HashMap<u8, GeckoEntry>,
}

struct GeckoEntry {
    total: u8,
    chunks: Vec<Option<Vec<u8>>>,
    have: u8,
}

const GECKO_MAX_MSGS: usize = 16;

impl GeckoReassembler {
    pub fn new() -> Self {
        GeckoReassembler { partial: std::collections::HashMap::new() }
    }

    /// Feed one (already Salamander-deobfuscated) datagram. Returns the reassembled QUIC packet when a
    /// frame completes its msgID, else `None`. A short-header datagram (flags != 0x80) is itself a
    /// complete QUIC packet and is returned as-is.
    pub fn accept(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        let &flags = datagram.first()?;
        if flags & GECKO_FLAG == 0 {
            return Some(datagram.to_vec()); // short-header passthrough (handled by caller normally)
        }
        if datagram.len() < 5 {
            return None;
        }
        let msg_id = datagram[1];
        let idx = (datagram[2] >> 4) as usize;
        let total = (datagram[2] & 0x0f) as usize;
        if !(2..=8).contains(&total) || idx >= total {
            return None;
        }
        let pad_len = u16::from_be_bytes([datagram[3], datagram[4]]) as usize;
        let chunk_start = 5 + pad_len;
        let chunk = datagram.get(chunk_start..)?.to_vec();

        if self.partial.len() >= GECKO_MAX_MSGS && !self.partial.contains_key(&msg_id) {
            self.partial.clear(); // bound state; reassembly is best-effort (QUIC retransmits)
        }
        let entry = self.partial.entry(msg_id).or_insert_with(|| GeckoEntry {
            total: total as u8,
            chunks: vec![None; total],
            have: 0,
        });
        if entry.total as usize != total || idx >= entry.chunks.len() {
            self.partial.remove(&msg_id);
            return None;
        }
        if entry.chunks[idx].is_none() {
            entry.chunks[idx] = Some(chunk);
            entry.have += 1;
        }
        if entry.have as usize == total {
            let entry = self.partial.remove(&msg_id)?;
            let mut out = Vec::new();
            for c in entry.chunks {
                out.extend_from_slice(&c?);
            }
            return Some(out);
        }
        None
    }
}
```
> `gecko_split`'s chunk sizing/padding distribution and `msg_id` are sender-side choices (not negotiated, per spec §Gecko), so exact values needn't match the Go impl — only the *frame format* must. The interop gate (Task 12) confirms the server reassembles ours. VERIFY the frame layout (`flags,msgID,chunkIdx|totalChunks,padLen,padding,chunk`) against the spec before shipping.

- [ ] **Step 4: Run → pass.** **Step 5: Commit.** `git commit -m "feat(hysteria2): Gecko obfuscation transform + reassembler"`

---

## Task 4: `SalamanderGeckoSocket` — the custom `AsyncUdpSocket`

Wraps a real UDP socket; applies Gecko (if enabled) then Salamander on send, reverse on recv. **This is the spike-y, quinn-version-sensitive task** — verify every quinn/quinn-udp signature.

**Files:** `core/src/transport/hysteria2/obfs.rs`.

- [ ] **Step 1: VERIFY the quinn-udp surface** at `docs.rs/quinn-udp/0.5`: `Transmit<'_>` fields (`destination: SocketAddr`, `contents: &[u8]`, `ecn`, `segment_size: Option<usize>`, `src_ip`), `RecvMeta` fields (`addr`, `len`, `stride`, `ecn`, `dst_ip`), and `UdpSocketState::new(UdpSockRef) -> io::Result<Self>` + `send(&self, UdpSockRef, &Transmit)` + `try_send`/`poll_recv` shapes. The quinn `AsyncUdpSocket` trait (verified): `create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>>`, `try_send(&self, &Transmit) -> io::Result<()>`, `poll_recv(&self, &mut Context, &mut [IoSliceMut], &mut [RecvMeta]) -> Poll<io::Result<usize>>`, `local_addr() -> io::Result<SocketAddr>`, provided `max_transmit_segments`.

- [ ] **Step 2: Implement the socket** (shape below — fill in the verified quinn-udp calls). Hold the inner tokio UDP socket + a `quinn_udp::UdpSocketState`, the obfs key, and the Gecko reassembler:
```rust
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::task::{Context, Poll};

#[derive(Debug)]
pub struct SalamanderGeckoSocket {
    inner: tokio::net::UdpSocket,
    state: quinn_udp::UdpSocketState,
    key: Vec<u8>,
    gecko: bool,
    reassembler: Mutex<GeckoReassembler>, // never held across .await (poll_recv is sync)
}

impl SalamanderGeckoSocket {
    pub fn new(inner: tokio::net::UdpSocket, key: Vec<u8>, gecko: bool) -> io::Result<Self> {
        let state = quinn_udp::UdpSocketState::new((&inner).into())?; // VERIFY UdpSockRef::from
        Ok(Self { inner, state, key, gecko, reassembler: Mutex::new(GeckoReassembler::new()) })
    }

    /// Build the list of on-wire datagrams for one outgoing QUIC packet.
    fn encode_out(&self, packet: &[u8], seed: u8) -> Vec<Vec<u8>> {
        let pieces = if self.gecko { gecko_split(packet, seed) } else { vec![packet.to_vec()] };
        pieces.iter().map(|p| salamander_obfuscate(&self.key, p)).collect()
    }
}
```
Then `impl quinn::AsyncUdpSocket`:
- `max_transmit_segments(&self) -> usize { 1 }` — disable GSO so each `try_send` is exactly one QUIC packet (clean per-packet obfs).
- `try_send(&self, t: &Transmit)`: `for dg in self.encode_out(t.contents, /*seed*/ t.destination.port() as u8) { send dg to t.destination via self.state/self.inner }`. Use `quinn_udp::UdpSocketState::try_send` (or `send`) with a freshly-built `Transmit { destination, contents: &dg, ecn: t.ecn, segment_size: None, src_ip: t.src_ip }`. On `WouldBlock`, return it (quinn will retry); a partial Gecko burst is acceptable — QUIC retransmits the lost packet.
- `poll_recv(&self, cx, bufs, meta)`: loop — `self.state`/`self.inner` `poll_recv` into a scratch `[IoSliceMut]`; for each raw datagram: `salamander_deobfuscate(&self.key, raw)?`; if `gecko`, feed to `self.reassembler.lock()...accept(&plain)` → emit only completed packets; else the plain bytes are the packet. Copy each completed packet into `bufs[i]` and fill `meta[i]` (addr, `len`, `stride = len`, ecn). Return `Ready(Ok(count))` once ≥1 packet is ready; if a batch yields only buffered fragments, loop again; propagate `Pending` from the inner `poll_recv`.
- `create_io_poller(self: Arc<Self>)`: delegate to a `UdpPoller` over the inner socket's writable readiness (VERIFY the idiom — likely wrap `self.inner`'s `poll_send_ready`/an `UdpPoller` that calls `inner.writable()`).
- `local_addr(&self) -> io::Result<SocketAddr> { self.inner.local_addr() }`.

> No standalone unit test drives the `AsyncUdpSocket` trait (it needs quinn). The transform fns (Tasks 2–3) are the unit-tested core; this socket is validated end-to-end by the interop gate (Task 12) with obfs on. Keep the trait impl a thin shell over the tested transforms.

- [ ] **Step 3: `cargo build -p spark-core --features hysteria2`** clean (no test). **Step 4: clippy + fmt + commit.** `git commit -m "feat(hysteria2): Salamander+Gecko AsyncUdpSocket"`

---

## Task 5: TCP codec (`tcp.rs`)

- [ ] **Step 1: Failing tests.**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_request_encodes_0x401() {
        let req = encode_tcp_request("example.com:80");
        // 0x401 is a 2-byte QUIC varint: 0x44 0x01
        assert_eq!(&req[..2], &[0x44, 0x01]);
        // followed by varint(addrlen=15) "example.com:80"... + varint padlen + padding
        let (id, rest) = read_varint(&req).unwrap();
        assert_eq!(id, 0x401);
        let (alen, rest) = read_varint(rest).unwrap();
        assert_eq!(alen, 14);
        assert_eq!(&rest[..14], b"example.com:80");
    }

    #[test]
    fn tcp_response_decodes_ok_and_error() {
        // status 0x00 OK, msg "", pad ""
        assert!(decode_tcp_response(&[0x00, 0x00, 0x00]).unwrap());
        // status 0x01 Error
        assert!(!decode_tcp_response(&[0x01, 0x00, 0x00]).unwrap());
        assert!(decode_tcp_response(&[]).is_err());
    }

    #[test]
    fn varint_round_trips() {
        for v in [0u64, 63, 64, 16383, 16384, 0x401, 1 << 30] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            assert_eq!(read_varint(&buf).unwrap().0, v);
        }
    }
}
```

- [ ] **Step 2: Run → fail.**

- [ ] **Step 3: Implement** QUIC varints (RFC 9000 §16: 2-bit length prefix in the top bits) + the framing:
```rust
use crate::transport::hysteria2::Hysteria2Error; // defined in mod.rs (Task 8); for now use io::Error

/// Append a QUIC varint (RFC 9000 §16).
pub fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < 64 {
        out.push(v as u8);
    } else if v < 16384 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1_073_741_824 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Read a QUIC varint; returns (value, rest). `None` if truncated.
pub fn read_varint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len)?;
    let mut v = (first & 0x3f) as u64;
    for &b in &bytes[1..] {
        v = (v << 8) | b as u64;
    }
    Some((v, &buf[len..]))
}

const TCP_REQUEST_ID: u64 = 0x401;

/// Encode a TCPRequest: varint(0x401) ‖ varint(addrlen) ‖ addr ‖ varint(padlen) ‖ padding.
pub fn encode_tcp_request(addr: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(addr.len() + 8);
    write_varint(&mut out, TCP_REQUEST_ID);
    write_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    write_varint(&mut out, 0); // no padding (client MAY pad; 0 is valid)
    out
}

/// Decode a TCPResponse head: status byte (0x00 OK / 0x01 Error), msg, padding. Returns Ok(is_ok).
/// Only the status byte is load-bearing; msg/padding are read past but ignored.
pub fn decode_tcp_response(buf: &[u8]) -> Result<bool, io::Error> {
    let status = *buf
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "empty TCPResponse"))?;
    Ok(status == 0x00)
}
```
(The `BoxedStream` adapter — pairing the quinn bidi stream halves — lives in Task 9 where the stream type is available.)

- [ ] **Step 4: Run → pass. Step 5: clippy/fmt/commit.** `git commit -m "feat(hysteria2): TCP request/response codec + QUIC varints"`

---

## Task 6: UDP codec (`udp.rs`)

UDPMessage encode + fragmentation, and decode + a reassembler.

- [ ] **Step 1: Failing tests.**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_message_round_trips_single_fragment() {
        let msgs = encode_udp_message(7, 3, "8.8.8.8:53", b"query", 1500);
        assert_eq!(msgs.len(), 1);
        let m = decode_udp_message(&msgs[0]).unwrap();
        assert_eq!(m.session_id, 7);
        assert_eq!(m.packet_id, 3);
        assert_eq!(m.frag_count, 1);
        assert_eq!(m.addr, "8.8.8.8:53");
        assert_eq!(m.payload, b"query");
    }

    #[test]
    fn udp_message_fragments_when_over_max() {
        let big = vec![0xabu8; 4000];
        let msgs = encode_udp_message(1, 1, "8.8.8.8:53", &big, 1200);
        assert!(msgs.len() > 1);
        let mut r = UdpReassembler::new();
        let mut done = None;
        for m in &msgs {
            if let Some(p) = r.accept(decode_udp_message(m).unwrap()) {
                done = Some(p);
            }
        }
        assert_eq!(done.unwrap(), big);
    }
}
```

- [ ] **Step 2: Run → fail.**

- [ ] **Step 3: Implement** the header `[u32 session][u16 packet][u8 fragId][u8 fragCount][varint addrlen][addr][payload]` with fragmentation when the encoded message would exceed `max_datagram`:
```rust
use crate::transport::hysteria2::tcp::{read_varint, write_varint};

pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub payload: Vec<u8>,
}

fn header_len(addr: &str) -> usize {
    let mut v = Vec::new();
    write_varint(&mut v, addr.len() as u64);
    4 + 2 + 1 + 1 + v.len() + addr.len()
}

/// Encode (and fragment) one UDP packet into one or more UDPMessage datagrams, each ≤ `max_datagram`.
pub fn encode_udp_message(
    session_id: u32,
    packet_id: u16,
    addr: &str,
    payload: &[u8],
    max_datagram: usize,
) -> Vec<Vec<u8>> {
    let hlen = header_len(addr);
    let room = max_datagram.saturating_sub(hlen).max(1);
    let frag_count = payload.len().div_ceil(room).max(1).min(255) as u8;
    let mut out = Vec::with_capacity(frag_count as usize);
    for frag_id in 0..frag_count {
        let start = frag_id as usize * room;
        let end = (start + room).min(payload.len());
        let chunk = &payload[start..end.max(start)];
        let mut m = Vec::with_capacity(hlen + chunk.len());
        m.extend_from_slice(&session_id.to_be_bytes());
        m.extend_from_slice(&packet_id.to_be_bytes());
        m.push(frag_id);
        m.push(frag_count);
        write_varint(&mut m, addr.len() as u64);
        m.extend_from_slice(addr.as_bytes());
        m.extend_from_slice(chunk);
        out.push(m);
    }
    out
}

/// Decode a UDPMessage datagram.
pub fn decode_udp_message(buf: &[u8]) -> Option<UdpMessage> {
    let session_id = u32::from_be_bytes(buf.get(0..4)?.try_into().ok()?);
    let packet_id = u16::from_be_bytes(buf.get(4..6)?.try_into().ok()?);
    let frag_id = *buf.get(6)?;
    let frag_count = *buf.get(7)?;
    let (alen, rest) = read_varint(buf.get(8..)?)?;
    let alen = alen as usize;
    let addr = std::str::from_utf8(rest.get(..alen)?).ok()?.to_owned();
    let payload = rest.get(alen..)?.to_vec();
    Some(UdpMessage { session_id, packet_id, frag_id, frag_count, addr, payload })
}

/// Reassembles fragments keyed by (session_id, packet_id). Bounded; drops on capacity.
pub struct UdpReassembler {
    partial: std::collections::HashMap<(u32, u16), Vec<Option<Vec<u8>>>>,
}

const UDP_MAX_PARTIAL: usize = 256;

impl UdpReassembler {
    pub fn new() -> Self {
        UdpReassembler { partial: std::collections::HashMap::new() }
    }

    /// Returns the reassembled payload when `m` completes its packet, else `None`.
    pub fn accept(&mut self, m: UdpMessage) -> Option<Vec<u8>> {
        if m.frag_count <= 1 {
            return Some(m.payload);
        }
        let key = (m.session_id, m.packet_id);
        if self.partial.len() >= UDP_MAX_PARTIAL && !self.partial.contains_key(&key) {
            self.partial.clear();
        }
        let slot = self
            .partial
            .entry(key)
            .or_insert_with(|| vec![None; m.frag_count as usize]);
        if slot.len() != m.frag_count as usize {
            self.partial.remove(&key);
            return None;
        }
        if let Some(cell) = slot.get_mut(m.frag_id as usize) {
            if cell.is_none() {
                *cell = Some(m.payload);
            }
        } else {
            return None;
        }
        if slot.iter().all(|c| c.is_some()) {
            let slot = self.partial.remove(&key)?;
            let mut out = Vec::new();
            for c in slot {
                out.extend_from_slice(&c?);
            }
            return Some(out);
        }
        None
    }
}
```
> `div_ceil` is stable (Rust ≥1.73; MSRV 1.85 OK). The `addr` is the per-message target `host:port`.

- [ ] **Step 4: Run → pass. Step 5: commit.** `git commit -m "feat(hysteria2): UDPMessage codec + fragmentation/reassembly"`

---

## Task 7: HTTP/3 `/auth` handshake (`auth.rs`)

Hand-rolled minimal H3: one HEADERS frame request, parse one HEADERS-frame response for `:status`. QPACK with an empty dynamic table (static-table indices + literal-with-name-reference / literal-with-literal-name).

- [ ] **Step 1: VERIFY** the HTTP/3 frame format (RFC 9114 §7.1: `varint type`=`0x01` HEADERS, `varint length`, payload) and QPACK (RFC 9204): a request stream's field section starts with the **encoded field section prefix** (Required Insert Count `0` + Delta Base `0` = two `0x00` bytes when no dynamic table). Static table indices needed: `:method POST`=20, `:path /`=1 (but `/auth` is a literal), `:scheme https`=23, `:authority`=0 (name only). Confirm indices against the RFC 9204 Appendix A static table before encoding.

- [ ] **Step 2: Failing tests.**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_request_is_an_h3_headers_frame() {
        let f = encode_auth_request("mysecret", 0);
        assert_eq!(f[0], 0x01); // HEADERS frame type
        let (flen, rest) = crate::transport::hysteria2::tcp::read_varint(&f[1..]).unwrap();
        assert_eq!(flen as usize, rest.len()); // length covers the field section
        assert_eq!(&rest[..2], &[0x00, 0x00]); // QPACK prefix: RIC=0, Base=0
    }

    #[test]
    fn parse_233_status_from_response() {
        // a HEADERS frame whose field section literally encodes :status 233
        let resp = make_test_response_headers(233);
        assert_eq!(decode_auth_status(&resp).unwrap(), 233);
        let resp_fail = make_test_response_headers(404);
        assert_eq!(decode_auth_status(&resp_fail).unwrap(), 404);
    }
}
```
(`make_test_response_headers` is a test helper you write that emits a HEADERS frame with `:status N` as a QPACK literal — mirrors what the server sends.)

- [ ] **Step 3: Implement** `encode_auth_request(auth: &str, cc_rx: u64) -> Vec<u8>` and `decode_auth_status(headers_frame: &[u8]) -> Result<u16, Hysteria2Error>`. Encode the field section as QPACK literals (prefix `00 00`, then for each header a `Literal Field Line With Literal Name` (`0x20|...` pattern) or `With Name Reference` against the static table) for: `:method POST`, `:scheme https`, `:authority hysteria`, `:path /auth`, `Hysteria-Auth: <auth>`, `Hysteria-CC-RX: <cc_rx>`, `Hysteria-Padding: <random>`; wrap in a HEADERS frame (`write_varint(0x01)`, `write_varint(section_len)`, section). For decode: read the HEADERS frame, parse the QPACK field section, find `:status`, return it. **Use literal-with-literal-name encoding throughout** (simplest correct QPACK; no static-table-index bugs) — it's larger on the wire but valid, and the request is tiny. Provide the complete QPACK literal encoder/decoder helpers (string = `[H=0][len varint(7-bit prefix)][bytes]`, no Huffman).

> This is the fiddliest deterministic task. Keep Huffman OFF (the `H` bit = 0) on both encode and decode — valid per RFC 9204 and far simpler. The interop gate confirms the server accepts it. If hand-rolling QPACK proves error-prone against the live server, the fallback is the `h3`/`h3-quinn` crates for the auth stream only (documented in design §5 as the alternative) — but try hand-rolled first.

- [ ] **Step 4: Run → pass. Step 5: commit.** `git commit -m "feat(hysteria2): minimal H3/QPACK /auth handshake codec"`

---

## Task 8: quinn endpoint + connect + auth (`mod.rs`)

**VERIFY-heavy.** Build the authenticated connection.

- [ ] **Step 1: `Hysteria2Error` enum** (thiserror) — `Connect`, `Auth(u16)`, `Tls`, `Quic(quinn::ConnectionError)`, `Io(io::Error)`, `Codec`.

- [ ] **Step 2: rustls ClientConfig (ring) + verifier.** VERIFY at `docs.rs/rustls/0.23` + `docs.rs/quinn/0.11`:
```rust
fn rustls_client_config(cfg: &Hysteria2Config) -> Result<rustls::ClientConfig, Hysteria2Error> {
    use std::sync::Arc;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Hysteria2Error::Tls)?;
    let mut tls = match cfg.tls.mode {
        Hysteria2TlsMode::SystemRoots => builder
            .with_root_certificates(load_native_roots()?)
            .with_no_client_auth(),
        Hysteria2TlsMode::PinSha256 | Hysteria2TlsMode::Insecure => builder
            .dangerous()
            .with_custom_certificate_verifier(make_verifier(&cfg.tls)?)
            .with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(tls)
}
```
`make_verifier` returns an `Arc<dyn rustls::client::danger::ServerCertVerifier>`: for `Insecure`, accept all; for `PinSha256`, accept iff `sha256(end_entity_cert) == configured pin`. VERIFY the `ServerCertVerifier` trait methods (`verify_server_cert`, `verify_tls12_signature`, `verify_tls13_signature`, `supported_verify_schemes`) for rustls 0.23. `load_native_roots` — use `rustls`'s platform verifier or bundle webpki-roots; VERIFY whether to add `rustls-platform-verifier` (a small dep) or `webpki-roots` — prefer the platform verifier behind the feature.

- [ ] **Step 3: Endpoint + connect.** VERIFY the quinn 0.11 endpoint-with-custom-socket API:
```rust
async fn connect(cfg: &Hysteria2Config, server: SocketAddr) -> Result<quinn::Connection, Hysteria2Error> {
    let udp = std::net::UdpSocket::bind(("0.0.0.0", 0)).map_err(Hysteria2Error::Io)?; // or protected
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client_config(cfg)?)
        .map_err(|_| Hysteria2Error::Tls)?;
    let mut client_config = quinn::ClientConfig::new(std::sync::Arc::new(quic_client));
    // optional: client_config.transport_config(...) for datagram/idle tuning
    let mut endpoint = match &cfg.obfs {
        Some(o) => {
            let tokio_udp = tokio::net::UdpSocket::from_std(udp).map_err(Hysteria2Error::Io)?;
            let sock = std::sync::Arc::new(obfs::SalamanderGeckoSocket::new(
                tokio_udp, o.password.clone().into_bytes(), o.gecko,
            ).map_err(Hysteria2Error::Io)?);
            quinn::Endpoint::new_with_abstract_socket(
                Default::default(), None, sock, std::sync::Arc::new(quinn::TokioRuntime),
            ).map_err(Hysteria2Error::Io)?
        }
        None => quinn::Endpoint::new(Default::default(), None, udp, std::sync::Arc::new(quinn::TokioRuntime))
            .map_err(Hysteria2Error::Io)?,
    };
    endpoint.set_default_client_config(client_config);
    let sni = cfg.sni.clone().unwrap_or_else(|| server.ip().to_string());
    let conn = endpoint.connect(server, &sni).map_err(|_| Hysteria2Error::Connect)?.await
        .map_err(Hysteria2Error::Quic)?;
    Ok(conn)
}
```
VERIFY: `Endpoint::new_with_abstract_socket(EndpointConfig, Option<ServerConfig>, Arc<dyn AsyncUdpSocket>, Arc<dyn Runtime>)`, `Endpoint::new(EndpointConfig, Option<ServerConfig>, std::net::UdpSocket, Arc<dyn Runtime>)`, and `Endpoint::connect(SocketAddr, &str) -> Result<Connecting>`.

- [ ] **Step 4: auth over a bidi stream.**
```rust
async fn authenticate(conn: &quinn::Connection, cfg: &Hysteria2Config) -> Result<(), Hysteria2Error> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(Hysteria2Error::Quic)?;
    let cc_rx = (cfg.down_mbps as u64) * 125_000; // Mbps -> bytes/s; 0 stays 0 (unknown)
    let frame = auth::encode_auth_request(&cfg.auth, cc_rx);
    use tokio::io::AsyncWriteExt;
    send.write_all(&frame).await.map_err(|e| Hysteria2Error::Io(e.into()))?;
    send.finish().map_err(|_| Hysteria2Error::Codec)?; // VERIFY finish() signature (0.11)
    use tokio::io::AsyncReadExt;
    let mut resp = Vec::new();
    recv.take(64 * 1024).read_to_end(&mut resp).await.map_err(|e| Hysteria2Error::Io(e.into()))?;
    let status = auth::decode_auth_status(&resp).map_err(|_| Hysteria2Error::Codec)?;
    if status != 233 { return Err(Hysteria2Error::Auth(status)); }
    Ok(())
}
```
VERIFY quinn 0.11 `SendStream::write_all`/`finish` and `RecvStream::read_to_end` (quinn streams impl `tokio::io::AsyncWrite`/`AsyncRead` under runtime-tokio — confirm; else use quinn's native `write_all`/`read_to_end` inherent methods).

- [ ] **Step 5:** A test here is hard without a server (defer real validation to Task 12). Add a `#[cfg(test)]` test only for the `Mbps -> bytes/s` conversion + the error enum `Display`. **clippy/fmt/commit.** `git commit -m "feat(hysteria2): quinn endpoint, connect, /auth handshake"`

---

## Task 9: `Hysteria2Transport` + `dial` (TCP) (`mod.rs`)

- [ ] **Step 1:** `Hysteria2Transport { cfg: Hysteria2Config, server: SocketAddr, conn: tokio::sync::Mutex<Option<quinn::Connection>> }` with `new(...)` and an `async fn connection(&self) -> Result<quinn::Connection, Hysteria2Error>` that returns the cached connection or (re)connects + authenticates (quinn `Connection` is cheap to clone — it's an `Arc` handle; store the clone). Don't hold the mutex across the connect `.await` if avoidable — use a connect-once pattern (re-check after acquiring).

- [ ] **Step 2:** `impl Transport for Hysteria2Transport`:
```rust
async fn dial(&self, target: SocketAddr) -> io::Result<BoxedStream> {
    let conn = self.connection().await.map_err(io::Error::other)?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    send.write_all(&tcp::encode_tcp_request(&target.to_string())).await?;
    // read the TCPResponse head: status + msg + padding. Read the status byte, then drain the
    // varint-prefixed msg and padding so the stream is positioned at the relayed payload.
    let mut status = [0u8; 1];
    recv.read_exact(&mut status).await?;
    if status[0] != 0x00 {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "hysteria2 TCP error status"));
    }
    drain_varint_blob(&mut recv).await?; // msg
    drain_varint_blob(&mut recv).await?; // padding
    Ok(Box::new(tokio::io::join(recv, send)))
}
```
`drain_varint_blob` reads a QUIC varint length then discards that many bytes. `tokio::io::join(recv, send)` pairs the quinn `RecvStream` (AsyncRead) + `SendStream` (AsyncWrite) into one AsyncRead+AsyncWrite → `BoxedStream`. VERIFY quinn streams impl tokio AsyncRead/Write (runtime-tokio); if not, wrap each with `tokio_util::compat` — but quinn 0.11 provides tokio impls, so `join` should work directly.

- [ ] **Step 3:** Unit-test `drain_varint_blob` against an in-memory cursor; the full dial is covered by the interop gate. **clippy/fmt/commit.** `git commit -m "feat(hysteria2): Transport::dial over QUIC bidi streams"`

---

## Task 10: `dial_udp` (UDP) + receive pump (`mod.rs`, `udp.rs`)

- [ ] **Step 1:** On the shared connection, a single spawned **receive pump** reads datagrams (`conn.read_datagram().await`), `decode_udp_message`, feeds a per-connection `UdpReassembler`, and routes completed payloads to the right session's `mpsc::Sender` (map `session_id -> Sender`, behind a `Mutex`/`DashMap`-style, not held across await). `dial_udp(target)` allocates a random `session_id`, registers a channel, and returns:
- `Hysteria2UdpSink { conn, session_id, target, packet_id: AtomicU16, max_datagram }` — `send` = `encode_udp_message(session_id, packet_id++, target, payload, max_datagram)` then `conn.send_datagram(Bytes)` per fragment. VERIFY `Connection::max_datagram_size() -> Option<usize>` and `send_datagram(Bytes)` (0.11).
- `Hysteria2UdpSource { rx: mpsc::Receiver<Vec<u8>> }` — `recv` = `rx.recv().await` → copy into `buf`.

- [ ] **Step 2:** Honor the server's `Hysteria-UDP: false` from auth (capture it in Task 8 into the transport) — `dial_udp` returns `io::ErrorKind::Unsupported` if the server didn't offer UDP.

- [ ] **Step 3:** Loopback-style unit test of the pump routing is hard without quinn; unit-test the sink's fragment-encode path (reuse Task 6) and the source's channel delivery. Full path → interop gate. **clippy/fmt/commit.** `git commit -m "feat(hysteria2): UdpTransport::dial_udp + datagram receive pump"`

---

## Task 11: Wiring — builder, from_config, build_one, resolver

Mirror the Shadowsocks wiring exactly.

- [ ] **Step 1:** In `core/src/transport/mod.rs`: add `Hysteria2Config` to the config import; add `hysteria2_transport(cfg, protector) -> io::Result<(Arc<dyn Transport>, Arc<dyn UdpTransport>)>` (feature build: resolve `cfg.server.socket_addr()?`, construct `Hysteria2Transport`, return as both trait objects) + the `#[cfg(not(feature = "hysteria2"))]` hard-error stub. Add the `from_config` precedence arm (after shadowsocks) and the `build_one` arm `ServerSpec::Hysteria2(cfg) => hysteria2_transport(cfg, protector.cloned())`.
- [ ] **Step 2:** In `core/src/bootstrap/mod.rs` `resolve_endpoints`: add `ServerSpec::Hysteria2(c) => entries.push((&mut c.server, Some(&mut c.sni)))` (and the single `transport.hysteria2`). (`first_unresolved_host` arm was added in Task 1.)
- [ ] **Step 3: from_config tests** (gated `all(test, feature = "hysteria2")`): a `[transport.hysteria2]` config builds a transport; a pool `kind = "hysteria2"` entry parses.
- [ ] **Step 4: Full feature-combo sweep** (these were broken by the new `ServerSpec` variant until now):
```bash
cargo build --all-targets
cargo build -p spark-core --features "hysteria2 multi-server bootstrap-dns" --all-targets
cargo test -p spark-core --features hysteria2
cargo test -p spark-core --features "multi-server bootstrap-dns"
cargo clippy --all-targets -- -D warnings
cargo clippy -p spark-core --features "hysteria2 multi-server bootstrap-dns anytls shadowsocks" --all-targets -- -D warnings
```
Confirm base build pulls no quinn/blake2: `cargo tree -p spark-core 2>/dev/null | grep -E "quinn|blake2" && echo LEAK || echo "base clean"`.
- [ ] **Step 5: commit.** `git commit -m "feat(hysteria2): wire into from_config/build_one/resolver"`

---

## Task 12: Live interop gate vs apernet/hysteria

**Files:** `core/tests/hysteria2_interop.rs`.

- [ ] **Step 1:** Env-gated test (`#![cfg(feature = "hysteria2")]`), skip unless `SPARK_HY2_SERVER`/`SPARK_HY2_AUTH` set. `tcp_http_get_through_live_server` (dial example.com:80, GET, assert `HTTP/1.1 `) and `udp_dns_through_live_server` (dial_udp 8.8.8.8:53, send a DNS A-query, assert an answer). Build the `Config` from env (incl. `SPARK_HY2_OBFS` password + `SPARK_HY2_GECKO`).
- [ ] **Step 2: Stand up a real server** and run BOTH obfs-off and obfs-on (Salamander + Gecko). Install hysteria (`bash <(curl -fsSL https://get.hy2.sh/)` or a release binary); minimal `config.yaml`: `listen: :443`, `tls: { cert, key }` (self-signed → client uses `tls.mode = "insecure"` or `pin-sha256`), `auth: { type: password, password: <pw> }`, and for the obfs run `obfs: { type: salamander, salamander: { password: <obfspw> } }`. Run:
```bash
SPARK_HY2_SERVER=127.0.0.1:443 SPARK_HY2_AUTH=<pw> \
  cargo test -p spark-core --features hysteria2 --test hysteria2_interop -- --nocapture
# then again with SPARK_HY2_OBFS=<obfspw> SPARK_HY2_GECKO=1
```
If a test fails with a QUIC handshake/auth/decrypt error, it's a real bug in the codec/auth/obfs — fix until the live server accepts spark, **obfs off and on**. Capture frozen vectors where useful.
- [ ] **Step 3: commit.** `git commit -m "test(hysteria2): live interop gate vs apernet/hysteria (obfs off + on)"`

---

## Task 13: ADR 0010 + docs/state sync + final sweep

- [ ] **Step 1:** Write `docs/adr/0010-hysteria2-transport.md` (format per ADR 0009): hysteria2 client on quinn/rustls-ring; quinn-now-noq-later (multipath future); v1 = core + Salamander + Gecko; Brutal/port-hop/mimicry/multipath deferred; hand-rolled H3 auth; `blake2` dep. Status Accepted (live-gated), date from commit.
- [ ] **Step 2:** Update `docs/STATE.md` (hysteria2 shipped — QUIC, TCP+UDP, Salamander+Gecko, live-gated) and flip `docs/hysteria2-design.md` Status to Accepted.
- [ ] **Step 3: Final sweep + size:** `cargo fmt --all --check`; the clippy/test combos from Task 11; `cargo build --release` and report the base binary size (<3 MB gate — hysteria2 off in base); confirm `base clean`.
- [ ] **Step 4: commit.** `git commit -m "docs(hysteria2): ADR 0010 + state/design sync"`

---

## Self-Review notes (for the implementer)

- **Spec coverage:** design §3 wire → codecs (T5/T6) + auth (T7) + obfs (T2/T3/T4); §2 quinn/rustls-ring → T1 deps + T8 config; §5 auth → T7/T8; §6 data paths → T9/T10; §7 obfs → T2/T3/T4; §9 config → T1; §11 testing → unit tests per task + T12; §12 build order is exactly T1→T12; §13 risks (ring provider, AsyncUdpSocket/Gecko, 233 status, UDP-off) are each addressed (T1, T4, T7, T10). Brutal/port-hop/multipath are out of scope (design §1) — no tasks, correctly.
- **Type consistency:** `write_varint`/`read_varint` (tcp.rs) reused by udp.rs + auth.rs; `salamander_obfuscate`/`deobfuscate`/`gecko_split`/`GeckoReassembler` (obfs.rs); `encode_udp_message`/`decode_udp_message`/`UdpReassembler`/`UdpMessage` (udp.rs); `encode_auth_request`/`decode_auth_status` (auth.rs); `Hysteria2Transport`/`Hysteria2Error`/`SalamanderGeckoSocket` (mod.rs/obfs.rs); `Hysteria2Config`/`Hysteria2Tls`/`Hysteria2TlsMode`/`Hysteria2Obfs`/`ServerSpec::Hysteria2` (config). Names consistent across tasks.
- **Verification flags are not placeholders:** T1/T4/T7/T8/T9/T10 carry explicit "VERIFY at docs.rs" notes on the version-sensitive quinn/quinn-udp/rustls/QPACK calls (per spark's verification discipline for unfamiliar APIs) — confirm each signature before writing, since quinn 0.11/quinn-udp 0.5 are exact pins. The deterministic cores (config, varints, TCP/UDP codecs, Salamander/Gecko transforms, QPACK literal codec) are given complete.
- **`obfs.rs` `expect` on RNG:** the one sanctioned non-test `.expect()` (OS RNG, infallible-in-practice) — mirror the SS decision or thread a Result if the reviewer prefers; flag for the quality review.
