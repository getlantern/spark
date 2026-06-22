# Shadowsocks 2022 transport — design

- **Status:** Accepted — implemented and live-gated end-to-end against shadowsocks-rust 1.24.0 (2026-06-21). ADR 0009.
- **Scope:** Add **Shadowsocks 2022 (SIP022)** as a spark client `Transport` + `UdpTransport`,
  **wire-interoperable with deployed `shadowsocks-rust` (and sing-box) SS-2022 servers** (client side
  only; the server stays as-is). Implemented **from scratch** in Rust — no `shadowsocks-rust`
  dependency — so the wire format is ours to audit and the binary stays lean.
- **Builds on:** the `Transport`/`UdpTransport` trait seam (`core/src/transport/mod.rs`), the
  `ServerSpec`/`ServerEntry` config model (`core/src/config/mod.rs`), the bootstrap endpoint resolver
  (`core/src/bootstrap/mod.rs`), and the per-kind `build_one` / `from_config` builders. Mirrors the
  feature-gating + config-wiring pattern established by AnyTLS (ADR 0001) and Samizdat (ADR 0007).
- **Reference spec:** `Shadowsocks-NET/shadowsocks-specs` →
  `2022-1-shadowsocks-2022-edition.md` (SIP022). Reference impl for interop + test vectors:
  `shadowsocks/shadowsocks-rust` (`crypto/src/v2/*`, `relay/src/...`).

---

## 1. Goal & scope

Make spark's Rust client tunnel TCP and UDP through an **unmodified, already-deployed Shadowsocks
2022 server**. That pins every wire detail: the BLAKE3 session-subkey derivation, the salted
length-chunk AEAD framing with standalone header chunks, the timestamp/salt replay binding, and the
session-ID/packet-ID UDP packet format.

Shadowsocks is added as an **interop arm**, not a frontline evasion protocol. See §10 (threat model):
plain SS-2022 is high-entropy "look-like-nothing" traffic and is defeated by the GFW's fully-encrypted-
traffic (FET) classifier. It earns its place for (a) interop with the large SS ecosystem, (b)
less-sophisticated censors, and (c) use as an inner layer beneath an obfuscation/cover transport later.

**In scope (v1):**
- A `shadowsocks` client `Transport` (TCP) and `UdpTransport` (UDP), behind a cargo feature,
  selectable via `[transport.shadowsocks]` or a `kind = "shadowsocks"` pool entry.
- The three SS-2022 methods on **TCP**: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`,
  `2022-blake3-chacha20-poly1305`.
- The two AES methods on **UDP** (`2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`), native
  SS-2022 packet format (session ID + packet ID + sliding-window replay protection).
- Full replay-resistance the spec mandates on the client side: per-stream random salt, monotonic
  timestamp, request-salt binding check on the TCP response; per-session sliding window on UDP recv.

**Out of scope (v1), explicitly:**
- **ChaCha-over-UDP** (`2022-blake3-chacha20-poly1305` on UDP). Its construction is XChaCha20-Poly1305
  with the PSK directly (SIP022 §4.1) — a primitive `ring` lacks. UDP with the chacha method returns
  a clear "unsupported in this build" error; the chacha method still works fully on **TCP**. Adding it
  later is a localized increment (one more cipher arm + the `chacha20poly1305` crate) — §11.
- The reduced-round `2022-blake3-chacha8/12-poly1305` methods (SIP022 §4, niche).
- **Legacy Shadowsocks AEAD** (SIP004/SIP007: `aes-256-gcm`, `chacha20-ietf-poly1305`, HKDF-SHA1
  subkeys, no replay protection). Deliberately omitted — it is FET-detectable *and* replay-weak.
- **EIH / multi-user** (multiple PSKs with the identity-subkey header). Single PSK only.
- **UDP-over-TCP (UoT)** for SS. Native SS-2022 UDP is what we implement.
- The Shadowsocks **server**. spark is a client.
- Any obfuscation/cover layer (`v2ray-plugin`, `shadow-tls`, `simple-obfs`). SS is the inner protocol;
  cover is a separate transport that may later wrap it.

---

## 2. What Shadowsocks 2022 is (the wire, from SIP022)

SS-2022 is a pre-shared-key AEAD tunnel — no handshake, no forward secrecy. The PSK is a fixed-length
random key (base64 in config), **not** a password run through `EVP_BytesToKey`. Per-session subkeys
come from BLAKE3's key-derivation mode.

**Key & subkey (SIP022 §2).** Key/salt sizes are method-bound:

| Method | Key bytes | Salt bytes |
|---|---:|---:|
| `2022-blake3-aes-128-gcm` | 16 | 16 |
| `2022-blake3-aes-256-gcm` | 32 | 32 |
| `2022-blake3-chacha20-poly1305` | 32 | 32 |

```
session_subkey := blake3::derive_key(context = "shadowsocks 2022 session subkey",
                                     key_material = PSK ‖ salt)        // first key_len bytes used
```

**TCP (SIP022 §3.1).** A proxy TCP connection carries a request stream and a response stream, each
with its own random salt and subkey. AEAD nonce = a **12-byte little-endian counter**, incremented per
seal/open, per direction, starting at 0. Payload is the AEAD length-chunk / payload-chunk model;
SS-2022 raises the chunk cap to **0xFFFF** (the 0x3FFF AEAD cap does not apply).

```
Request stream:
  salt(16/32) ‖ enc[fixed header] ‖ enc[variable header] ‖ enc[len] ‖ enc[payload] ‖ …
    fixed header (11B):    type(1)=0 ‖ timestamp(u64be) ‖ length(u16be = len of variable header)
    variable header:       ATYP ‖ address ‖ port(u16be) ‖ padding_len(u16be) ‖ padding ‖ [initial payload]
Response stream:
  salt(16/32) ‖ enc[fixed header] ‖ enc[payload] ‖ enc[len] ‖ enc[payload] ‖ …
    fixed header (27/43B): type(1)=1 ‖ timestamp(u64be) ‖ request_salt(16/32) ‖ length(u16be)
                           (the fixed header doubles as the first length chunk)
```

Replay rules the **client** must honor: send a fresh random salt per stream; the request header must
carry either an initial payload or non-zero padding (we always send random padding for simplicity);
on the response, verify `request_salt` equals our request salt and the timestamp is within 30 s. The
salt + both header chunks MUST be written in **one** socket write (size-fingerprint defense).

**UDP, AES methods (SIP022 §3.2).** Each session has a random 8-byte session ID; a u64be packet ID
counts packets. The 16-byte **separate header** (session ID ‖ packet ID) is encrypted with a **raw AES
block cipher keyed by the PSK directly** (single block — ECB). The body is AEAD'd with a per-session
subkey:

```
separate_header        = session_id(8) ‖ packet_id(u64be 8)            // 16B = one AES block
enc_separate_header    = AES_encrypt_block(key = PSK, separate_header)  // raw block, no mode
session_subkey         = blake3::derive_key("shadowsocks 2022 session subkey", PSK ‖ session_id)
enc_body               = AES_GCM(session_subkey).seal(nonce = separate_header[4..16], body)
packet                 = enc_separate_header(16) ‖ enc_body(var + 16B tag)

Client→server body (main header): type(1)=0 ‖ timestamp(u64be) ‖ padding_len(u16be) ‖ padding ‖ ATYP ‖ address ‖ port
Server→client body (main header): type(1)=1 ‖ timestamp(u64be) ‖ client_session_id(8) ‖ padding_len(u16be) ‖ padding ‖ ATYP ‖ address ‖ port
```

Replay protection: a **sliding-window filter per session ID** (WireGuard-style). Packet ID may be
checked once the separate header is decrypted, but the window MUST NOT advance before the body decrypts
and the header (type, timestamp) validates. Servers route by session ID, not source address.

**UDP, chacha method (SIP022 §4.1) — out of scope v1.** XChaCha20-Poly1305 with the PSK directly and a
random 24-byte nonce per packet; session/packet IDs merged into the main header. Deferred (§1, §11).

---

## 3. Where it sits in spark

A new `Transport` + `UdpTransport` impl alongside `anytls`, `samizdat`, and `wasm`, reusing spark's
dialing and config machinery. Unlike the TLS-based transports it carries **no ClientHello and no
shaping plan** (it is not TLS), so the `WirePlan` is irrelevant to it.

| Need | Reuse |
|---|---|
| Protected dial (bypass tunnel route) | `transport::protected_tcp_connect`, `transport::protected_udp_socket` |
| AEAD (AES-GCM, ChaCha20-Poly1305, 96-bit nonce) | `ring::aead::LessSafeKey` + explicit `Nonce` |
| Config gating + `from_config` precedence + feature stub | `transport/mod.rs`, `config/mod.rs` |
| Pool membership (latency selection) | `ServerSpec::Shadowsocks` → `build_one` arm |
| Startup hostname resolution | `bootstrap::resolve_endpoints`, `config::first_unresolved_host` |

New surface under `core/src/transport/shadowsocks/`:

```
shadowsocks/
  mod.rs      ShadowsocksTransport: impl Transport + UdpTransport; method/key plumbing; version/label consts
  method.rs   SsMethod enum (3 methods) + key/salt sizes + AEAD construction selection
  crypto.rs   PSK parse (base64), blake3 subkey derivation, ring AEAD wrappers, raw-AES block (udp header)
  tcp.rs      TCP request/response codec + the AsyncRead+AsyncWrite chunk-framing stream adapter
  udp.rs      native SS-2022 UDP: packet build/parse, per-session state, sliding-window replay filter
```

Feature gate: a new `shadowsocks` cargo feature pulling `dep:blake3` + `dep:aes`. `ring`, `bytes`,
`tokio`, `async-trait` are already in base. The base build remains rustls/ring-only and cmake-free.

---

## 4. Crypto primitives & dependencies

`ring` covers the AEADs (all three TCP ciphers and the AES-UDP body use 96-bit-nonce AES-GCM /
ChaCha20-Poly1305 — `ring::aead::LessSafeKey` with an explicit `Nonce::assume_unique_for_key`, which is
exactly the SS-2022 "caller supplies the nonce" model). Two primitives `ring` does not expose:

1. **BLAKE3 key-derivation mode** for session subkeys → the **`blake3`** crate
   (`blake3::derive_key(context: &str, key_material: &[u8]) -> [u8; 32]`; take the first `key_len`).
2. **A raw AES block** (single-block ECB) for the UDP separate header → the **`aes`** crate
   (RustCrypto: `Aes128`/`Aes256` implementing `BlockEncrypt`/`BlockDecrypt`).

**Decision (approved):** use the pure-Rust RustCrypto crates `blake3` + `aes` rather than CLAUDE.md's
named `aws-lc-rs` fallback. `aws-lc-rs` would pull the AWS-LC C/cmake library (heavy, and an
awkward/unstable API for raw AES); both new crates are small, audited, pure-Rust, **cmake-free**, and
pulled **only under the `shadowsocks` feature** — so the <3 MB base build is untouched. This is a
deliberate, scoped deviation from the letter of the locked-stack crypto fallback, recorded in ADR 0009.
The `chacha20poly1305` crate (XChaCha20, for chacha-over-UDP) is **not** added in v1 (§1, §11).

Dependency hygiene: pin `blake3` and `aes` to current versions; prefer `default-features = false`
where it still exposes `derive_key` / block traits, to keep the feature build lean. Verify the exact
`blake3`/`aes`/`ring` APIs against docs.rs at implementation time (verification discipline — do not
guess signatures).

---

## 5. Config

A new per-kind config struct, a `ServerSpec` variant, and a single-transport field — mirroring AnyTLS.

```rust
/// Shadowsocks 2022 (SIP022) transport configuration (ADR 0009). Pre-shared-key AEAD tunnel,
/// wire-interoperable with shadowsocks-rust / sing-box SS-2022 servers. See docs/shadowsocks-design.md.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksConfig {
    /// The SS server address — `IP:port` or `host:port` (resolved at startup).
    pub server: Endpoint,
    /// The SS-2022 method (cipher). Determines key/salt size and the AEAD construction.
    pub method: SsMethod,
    /// The pre-shared key, base64-encoded (decoded length MUST equal the method's key size).
    pub password: String,
}

/// The SS-2022 methods spark implements. `lowercase`+`kebab` rename matches the canonical names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum SsMethod {
    #[serde(rename = "2022-blake3-aes-128-gcm")]      Aes128Gcm,
    #[serde(rename = "2022-blake3-aes-256-gcm")]      Aes256Gcm,
    #[serde(rename = "2022-blake3-chacha20-poly1305")] Chacha20Poly1305, // TCP only in v1
}
```

- `ServerSpec` gains `Shadowsocks(ShadowsocksConfig)` (tag `kind = "shadowsocks"`).
- `TransportConfig` gains `shadowsocks: Option<ShadowsocksConfig>` (single-transport convenience,
  same shape as `anytls`/`samizdat`/`wasm`).
- The PSK is a proxy secret — it lives in the privileged store and is never echoed back over IPC
  (CLAUDE.md). Config validation: `password` base64-decodes to exactly the method's key length, else a
  clear build-time error (mirrors `server_pubkey must be 32-byte hex` in samizdat).

Example:

```toml
[transport.shadowsocks]
server   = "proxy.example.com:8388"
method   = "2022-blake3-aes-256-gcm"
password = "<base64 32-byte PSK>"
```

---

## 6. TCP design (`tcp.rs`)

`ShadowsocksTransport::dial(target)`:

1. `protected_tcp_connect(server, protector)` — dial the SS server off-tunnel.
2. **Send request** (one buffered write): random salt → derive subkey → AEAD-seal the fixed header
   (`type=0`, `timestamp=now`, `length=len(variable header)`) and the variable header
   (`ATYP+addr+port` from `target`, random non-zero padding, no initial payload). Nonce counter starts
   at 0 and increments per chunk.
3. **Read response head**: read salt, derive the response subkey, AEAD-open the fixed header; verify
   `type==1`, `|timestamp - now| ≤ 30 s`, and `request_salt == our salt`. The fixed header's `length`
   field gives the first payload chunk's size.
4. Return a `BoxedStream` — an `AsyncRead + AsyncWrite` adapter that, going forward, encrypts on write
   (length chunk then payload chunk, ≤ 0xFFFF) and decrypts on read (length chunk → payload chunk),
   each via the per-direction counter nonce.

Per CLAUDE.md: the read path is an explicit **enum state machine** (`ReadLen → ReadPayload → Drain`)
driven by cancel-safe `read_buf` into a `BytesMut` (never `read_exact` inside `select!`); buffers are
`BytesMut` with explicit capacity (16 KiB) and frozen to `Bytes` on hand-off; no `Vec<u8>` on the data
path. One transport instance per config; **one SS connection per `dial()`** (SS-2022 maps TCP 1:1, so
there is no session pool to manage — simpler than AnyTLS/Samizdat).

---

## 7. UDP design (`udp.rs`)

`ShadowsocksTransport::dial_udp(target)` (AES methods only; chacha returns "unsupported in this build"):

1. `protected_udp_socket(server, protector)` — a connected UDP socket to the SS server.
2. Generate a random 8-byte **client session ID**; a u64 **packet ID** counter starts at 0.
3. Return `(BoxedPacketSink, BoxedPacketSource)`:
   - **Sink (`send`)** owns the send-side state (client session ID, packet-ID counter, the AES block
     cipher keyed by PSK, the per-session AEAD subkey from `blake3(PSK ‖ session_id)`). Per datagram:
     build `separate_header = session_id ‖ packet_id`; `enc_sep = AES_block_encrypt(PSK, sep)`; build
     the client main header (`type=0`, timestamp, padding, `ATYP+addr+port` of `target`) ‖ payload;
     `enc_body = AES_GCM(subkey).seal(nonce = sep[4..16], …)`; send `enc_sep ‖ enc_body`; `packet_id += 1`.
   - **Source (`recv`)** owns the recv-side state: a map of **server session ID → sliding-window
     filter** (+ that session's derived subkey, cached on first sight). Per datagram: `recv`; AES-block-
     decrypt the 16-byte header → `server_session_id`, `packet_id`; derive/lookup the server subkey
     (`blake3(PSK ‖ server_session_id)`); `AES_GCM.open(nonce = sep[4..16], body)`; parse the server
     main header (`type==1`, timestamp ≤ 30 s, `client_session_id == ours`); run the sliding-window
     check then **advance the window only after** header validation; strip the header, deliver payload.
4. The PSK-keyed AES block cipher + the method are shared by both halves (cheap to clone / `Arc`).

Single target per `dial_udp` (spark's connected-UDP model) → one SS session per flow; the per-packet
SOCKS address is always `target`. The receive map tolerates a server restart (a new server session ID)
per SIP022 §3.2.4 — accept the new session, keep the old one ≥ 60 s.

---

## 8. Dial flow

```mermaid
sequenceDiagram
    autonumber
    participant Net as netstack<br/>(original dst)
    participant T as ShadowsocksTransport<br/>mod.rs
    participant C as crypto.rs<br/>(blake3 / ring / aes)
    participant Co as tcp.rs / udp.rs<br/>(codec)
    participant S as SS-2022 server<br/>(shadowsocks-rust, deployed)

    Net->>T: dial(target) / dial_udp(target)
    rect rgba(200,220,255,0.25)
    Note over T,Co: TCP
    T->>Co: protected_tcp_connect(server)
    T->>C: salt → blake3 subkey
    Co->>S: salt ‖ enc[fixed hdr type0,ts,len] ‖ enc[var hdr ATYP+addr+port,pad]  (one write) ⚠️
    S-->>Co: salt ‖ enc[fixed hdr type1,ts,request_salt,len] ‖ enc[payload]…
    Co->>C: verify request_salt == ours, |ts|≤30s 🐛 replay binding
    Co-->>Net: BoxedStream (length+payload AEAD chunks ⇄ bytes)
    end
    rect rgba(220,255,220,0.25)
    Note over T,Co: UDP (AES methods)
    T->>Co: protected_udp_socket(server); rand session_id, packet_id=0
    Co->>C: AES_block(PSK, session_id‖packet_id); subkey=blake3(PSK‖session_id)
    Co->>S: enc_sep_header(16) ‖ AES_GCM(subkey, nonce=sep[4..16], main hdr ‖ payload)
    S-->>Co: enc_sep_header ‖ enc_body (server session)
    Co->>C: AES_block_decrypt; subkey(server_session_id); AES_GCM.open
    Co->>Co: sliding-window replay check (advance after header validates) 🐛
    Co-->>Net: payload (PacketSource::recv)
    end
```

---

## 9. Testing & gates

1. **Crypto KATs (`crypto.rs`)** — `blake3::derive_key` subkey vectors and AES-GCM/ChaCha20-Poly1305
   seal/open round-trips against vectors captured from `shadowsocks-rust`. Raw-AES block KATs (FIPS-197
   AES test vectors) for the UDP header.
2. **TCP codec unit tests** — build a request, parse it back; build a response, verify the
   `request_salt` binding + timestamp window; chunk framing round-trips through the stream adapter
   (including a 0xFFFF-sized chunk and a partial-read split across `poll_read` calls).
3. **UDP codec unit tests** — packet build/parse round-trip; sliding-window filter accepts in-order,
   rejects replays and out-of-window IDs, advances only after header validation; chacha-on-UDP returns
   the "unsupported" error.
4. **Interop gate (the real one)** — spark's client reaches a target through a **live
   `shadowsocks-rust` server** (`ssserver -m 2022-blake3-aes-256-gcm -k <PSK>`), TCP **and** UDP →
   HTTP 200 / DNS answer. Live-gated like the AnyTLS/Samizdat interop tests (skipped without the env
   var that supplies a server).
5. **Full `sudo spark run` TUN gate** — curl + a UDP DNS query → TUN → netstack → ShadowsocksTransport
   → live SS server → internet; log-hygiene clean (no PSK/secret in logs).
6. **Workspace sweep** — `cargo build`/`clippy -D warnings`/`fmt` clean with **and** without the
   `shadowsocks` feature; the base build pulls neither `blake3` nor `aes`.

---

## 10. Threat model — why SS is an arm, not the spearhead

Plain Shadowsocks (all editions, incl. 2022) is **look-like-nothing**: the wire is "indistinguishable
from a random byte stream" — which is precisely the signature the GFW's **fully-encrypted-traffic
detection** (Wu et al., USENIX Security 2023) keys on (high entropy + no recognizable protocol header →
block). SS-2022 hardens **active-probing and replay** (typed messages, timestamps, salt pool, sliding
window) — it does **not** defeat passive entropy classification. So:

- **Useful where** the censor is less sophisticated, against active-probing/replay attacks, for
  interop with the large SS server ecosystem, and as an **inner layer** under a cover/obfuscation
  transport (the cover hides the entropy; SS provides the AEAD tunnel).
- **Not useful as** a standalone frontline protocol against the GFW's FET classifier. spark's
  mimicry-first transports (AnyTLS/Samizdat) remain the spearhead; SS broadens reach and interop.

This framing is the reason chacha-over-UDP and EIH are deferrable without hurting the protocol's role.

---

## 11. Build order (chunks, one per session, green at each boundary)

1. **`method.rs` + `crypto.rs`** — `SsMethod`, key/salt sizes, base64 PSK parse, `blake3` subkey,
   `ring` AEAD wrappers, raw-`aes` block. Pure crypto; KATs vs shadowsocks-rust + FIPS-197. (No I/O.)
2. **`tcp.rs`** — request/response codec + the `AsyncRead+AsyncWrite` chunk-framing adapter, unit-tested
   in isolation (in-memory duplex; no socket).
3. **`udp.rs`** — packet build/parse, per-session state, sliding-window filter; unit-tested.
4. **`mod.rs` + config + wiring** — `ShadowsocksConfig`/`SsMethod`/`ServerSpec::Shadowsocks`/
   `transport.shadowsocks`; `shadowsocks_transport` builder; `from_config` precedence; `build_one` arm;
   `first_unresolved_host` arm; `resolve_endpoints` arm (see §12); `shadowsocks` cargo feature + the
   `cfg(not(feature))` hard-error stub. Workspace sweep green with/without the feature.
5. **Interop + TUN gates** — against a live `shadowsocks-rust` server (TCP + UDP).

---

## 12. Wiring notes (exact integration points)

- **`from_config` precedence** (`transport/mod.rs`): add Shadowsocks to the single-transport chain
  alongside anytls/samizdat/wasm (`if let Some(ss) = &config.transport.shadowsocks { return
  shadowsocks_transport(ss, protector); }`). No `WirePlan` argument — SS is not TLS.
- **`build_one`** (`transport/mod.rs`): add `ServerSpec::Shadowsocks(cfg) =>
  shadowsocks_transport(cfg, protector.cloned())` (ignores the `wire` param the other arms use).
- **`first_unresolved_host`** (`config/mod.rs`): add `ServerSpec::Shadowsocks(c) => Some(&c.server)`
  to the pool match, and the single `transport.shadowsocks` to the `singles` array.
- **`resolve_endpoints`** (`bootstrap/mod.rs`): Shadowsocks has **no SNI** (not TLS). The current
  `entries: Vec<(&mut Endpoint, &mut Option<String>)>` assumes every transport has an SNI slot. Refactor
  the SNI slot to optional — `Vec<(&mut Endpoint, Option<&mut Option<String>>)>` — push
  `(&mut c.server, None)` for the Shadowsocks arm (single + pool), and in the resolve loop only default
  the SNI to the hostname when the slot is `Some`. (The exhaustive `ServerSpec` match makes the compiler
  enforce that this arm is added in both `first_unresolved_host` and `resolve_endpoints`.)
- **`shadowsocks_transport(cfg, protector)`** builder: validate the method↔key-length, build a
  `ShadowsocksTransport`, return it as both `Arc<dyn Transport>` and `Arc<dyn UdpTransport>` (UDP arm
  errors for the chacha method). Provide the `cfg(not(feature = "shadowsocks"))` hard-error stub
  mirroring `anytls_transport`/`samizdat_transport`.

---

## 13. Open questions / risks

- **Byte-exactness.** The §2/§6/§7 layouts are transcribed from SIP022; the authoritative oracle is the
  interop gate (§9.4) against `shadowsocks-rust`. Capture KAT vectors from that impl and treat any
  mismatch as the bug — do not trust the prose over the wire.
- **Timestamp skew.** The 30 s replay window means a client with a badly-skewed clock fails handshake.
  Use system time; surface a clear error if the server rejects on timestamp (don't silently retry).
- **UDP session lifecycle.** The recv-side server-session map must bound memory (cap sessions, expire
  ≥ 60 s per spec) and tolerate server restart (new server session ID). Keep the map small for the
  connected single-target case.
- **chacha-over-UDP deferral.** A config pairing `2022-blake3-chacha20-poly1305` with a UDP flow gets a
  clear error, not a silent TCP-only fallback. Revisit as a localized increment (+`chacha20poly1305`).
- **ADR.** On approval, record the decision (SS-2022 from scratch; RustCrypto `blake3`+`aes` over the
  aws-lc-rs fallback; AES-UDP-only v1) as **ADR 0009**.
