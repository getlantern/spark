# Hysteria 2 transport — design

- **Status:** Accepted — implemented and **live-gated** end-to-end against `apernet/hysteria` v2.9.2
  (TCP HTTP 200 + UDP DNS through the tunnel; obfs off + Salamander + Gecko all green), 2026-06-22.
  Recorded as **ADR 0010**.
- **Scope:** Add **Hysteria 2** (the apernet/hysteria "v2"/internally-"v4" protocol) as a spark client
  `Transport` + `UdpTransport`, **wire-interoperable with deployed `apernet/hysteria` servers** (client
  side only; the server stays Go). spark's **first QUIC transport** — built on **`quinn`** (pure-Rust
  QUIC on rustls/ring, spark's locked TLS baseline), intended as the foundation for future QUIC work.
- **Builds on:** the `Transport`/`UdpTransport`/`PacketSink`/`PacketSource` trait seam
  (`core/src/transport/mod.rs`), the `ServerSpec`/`ServerEntry` config model, the bootstrap resolver,
  and the per-kind `build_one`/`from_config` builders. Mirrors the feature-gating + config-wiring
  pattern of AnyTLS (ADR 0001), Samizdat (ADR 0007), and Shadowsocks (ADR 0009).
- **Reference spec:** hysteria.network "Hysteria 2 Protocol Specification"
  (`https://v2.hysteria.network/docs/developers/Protocol/`). Reference impl for interop + vectors:
  `github.com/apernet/hysteria` (Go, `core/`, `extras/obfs/`).

---

## 1. Goal & scope

Make spark's Rust client tunnel TCP and UDP through an **unmodified, already-deployed Hysteria 2
server**. That pins every wire detail: the QUIC + datagram transport, the HTTP/3 `POST /auth`
handshake (`233 HyOK`), the `0x401` TCPRequest framing on raw QUIC bidi streams, the UDPMessage
datagram envelope with fragmentation, and the Salamander/Gecko obfuscation layers.

**In scope (v1):**
- A `hysteria2` client `Transport` (TCP) and `UdpTransport` (UDP), behind a cargo feature, selectable
  via `[transport.hysteria2]` or a `kind = "hysteria2"` pool entry.
- QUIC transport via **quinn** (rustls/ring), with the HTTP/3 auth handshake (hand-rolled minimal H3).
- TCP proxying over raw QUIC **bidirectional streams** (TCPRequest/TCPResponse).
- UDP relay over QUIC **unreliable datagrams** (UDPMessage envelope + fragmentation/reassembly).
- **Salamander** obfuscation (BLAKE2b-256 XOR keystream) **and Gecko** obfuscation (handshake-packet
  fragmentation wrapping Salamander) — both v1, since Gecko is the layer that defeats recent QUIC
  blocking and is a hard requirement for the China use case.
- TLS verification modes: system-roots (default), pinned SHA-256, insecure-skip.

**Out of scope (v1), explicitly:**
- **Brutal** congestion control. v1 uses quinn's default CC (BBR); the client advertises its rx rate
  via `Hysteria-CC-RX` (or `0` = unknown) and the server falls back to BBR — fully interoperable.
  Brutal (the fixed-rate `quinn::congestion::Controller`) is a self-contained speed follow-up (§11).
- **Port hopping** (client rotates the server's UDP port over a range). Operational layer; later.
- **QUIC fingerprint mimicry** ("look like real Chrome QUIC/HTTP-3"). Salamander/Gecko obfuscate the
  whole packet stream, so the QUIC TLS fingerprint is hidden on the wire when obfs is on; mimicry is a
  separate future concern (and would need a uTLS-for-QUIC that doesn't yet exist).
- **Multipath / NAT-traversal** — the future "QUIC foundation" direction (slipstream, unbounded-over-
  QUIC, p2p). v1 is single-path quinn; see §2 for the planned migration to **noq** when multipath is
  actually needed.
- The Hysteria **server** (auth backend, masquerade/ACME, UDP port management). spark is a client.

---

## 2. QUIC stack decision — quinn now, noq later (ADR 0010)

spark has no QUIC today. The chosen stack is **`quinn`**: pure-Rust QUIC built on **rustls**, which is
spark's *locked* TLS baseline (CLAUDE.md). It exposes everything hysteria2 needs:
- `Connection::open_bi()` (TCP-over-stream), `send_datagram()`/`read_datagram()` (UDP-over-datagram).
- A custom **`AsyncUdpSocket`** seam — the clean place to implement Salamander/Gecko (they operate on
  whole QUIC packets, below quinn).
- A pluggable **`congestion::Controller`** — where Brutal slots in later.

**rustls provider:** quinn/rustls must be configured with the **ring** crypto provider, NOT the
default `aws-lc-rs` — aws-lc-rs would link a *second* C crypto library next to the `boring2` used by
the anytls/samizdat mimicry transports. ring is already in the base build and coexists cleanly.
(Implementation note: pin quinn + rustls versions and select the ring provider explicitly; verify the
exact feature flags at build time.)

**Why not quiche / s2n-quic.** quiche is BoringSSL-backed: it vendors its *own* BoringSSL, which would
be a second, separately-pinned BoringSSL alongside `boring2` — duplicate C builds and static-link
symbol-collision risk (`SSL_*`/`EVP_*`). s2n-quic defaults to aws-lc-rs (same second-C-lib problem) and
has a smaller proxy/tunnel ecosystem. quinn keeps spark on one rustls/ring crypto stack for QUIC.

**noq later.** Multipath QUIC + NAT-traversal (the slipstream / unbounded-over-QUIC / p2p direction)
is not in mainline quinn; the iroh team's **`noq`** (a quinn hard-fork) has a full QUIC-Multipath +
NAT-traversal + address-discovery implementation, pure-Rust on rustls, in production. Because the QUIC
library lives **entirely inside the hysteria2 module behind spark's `Transport`/`UdpTransport`
traits** (exactly as `boring2` lives inside anytls/samizdat), the eventual quinn→noq migration is
contained to the QUIC transport modules and noq's quinn-descended API keeps the same obfs/CC seams.
v1 ships on mature quinn (hysteria2 is single-path, needs no multipath); noq is adopted when a future
transport actually requires multipath.

---

## 3. What Hysteria 2 is (the wire, from the spec)

QUIC (RFC 9000) + Unreliable Datagram Extension (RFC 9221). All multibyte numbers big-endian; varints
per QUIC. To a prober the server looks like a plain HTTP/3 web server; only an authenticated client
gets proxy behavior.

**Auth (HTTP/3).** On connect, the client sends one HTTP/3 request:
```
:method POST   :path /auth   :authority hysteria
Hysteria-Auth:   <credential string>
Hysteria-CC-RX:  <uint>     # client's max receive rate, bytes/s; 0 = unknown
Hysteria-Padding: <random>  # obfuscation only; ignored
```
Success → HTTP `233 HyOK` with `Hysteria-UDP: true/false`, `Hysteria-CC-RX: <uint|"auto">`, and
`Hysteria-Padding` (the client walks past / ignores the response padding — it reads only `:status`
and `Hysteria-UDP`). Any status ≠ 233 → auth failed, disconnect. After 233 (and only then) the QUIC
connection is a proxy connection; **all subsequent proxying uses raw QUIC streams/datagrams, not H3.**

**TCP (raw QUIC bidi stream, per connection).** Client opens a bidi stream and sends:
```
[varint] 0x401 (TCPRequest ID)   [varint] addr len   [bytes] host:port   [varint] pad len   [bytes] pad
```
Server replies `TCPResponse`: `[uint8] status (0x00 OK / 0x01 Error)  [varint] msg len  [bytes] msg
[varint] pad len  [bytes] pad`. On OK, the stream is a transparent relay until either side closes.

**UDP (QUIC datagram).** Each UDP packet is wrapped in a UDPMessage and sent over an unreliable
datagram (both directions):
```
[uint32] Session ID   [uint16] Packet ID   [uint8] Frag ID   [uint8] Frag count
[varint] addr len   [bytes] host:port   [bytes] payload
```
A UDP packet larger than QUIC's max datagram is **fragmented** (same Packet ID across fragments,
Frag ID `0..Frag count`); a lost fragment drops the whole packet; unfragmented → Frag count = 1.
Client uses a unique Session ID per UDP session; no explicit close (server times out idle sessions).

**Congestion control (rate negotiation).** Client sends its rx rate in `Hysteria-CC-RX`; server
returns its rx rate (or `auto`). `0`/`auto` → use a standard CC (BBR/Cubic). v1 advertises the
configured rate (or 0) and uses quinn's BBR; **Brutal** (the fixed-rate CC that consumes the
negotiated rate) is deferred (§1, §11).

**Salamander obfuscation (optional, per QUIC packet).** `[8 bytes salt][payload]`, where
`hash = BLAKE2b-256(key ‖ salt)` and `payload[i] ^= hash[i % 32]`. Applied to every QUIC packet;
invalid packets dropped.

**Gecko obfuscation (wraps Salamander).** Disguises the QUIC *handshake* datagram shape. Per outgoing
QUIC packet, inspect the first byte: **short-header** (`0x80` clear) → send as-is through Salamander;
**long-header** (`0x80` set) → split into `N ∈ [2,8]` fragments, each wrapped in a Gecko frame and
sent as an independent Salamander datagram:
```
[1] flags=0x80   [1] msgID   [1] chunkIdx:4|totalChunks:4   [2] padLen(be)   [padLen] padding   [..] chunk
```
Receiver: Salamander-deobfuscate → if short-header, pass through; else parse the Gecko frame, buffer
chunks by `(source, msgID)` until `totalChunks` arrive, reassemble, deliver to QUIC. Bounded
reassembly state (per-source + total + TTL); drop malformed/duplicate/inconsistent frames.

---

## 4. Where it sits in spark

A new `Transport` + `UdpTransport` impl alongside `anytls`, `samizdat`, `wasm`, `shadowsocks`. Unlike
the TLS-stream transports, the data path is QUIC; unlike Shadowsocks it carries no in-stream AEAD
framing of its own (QUIC provides confidentiality/integrity). New surface under
`core/src/transport/hysteria2/`:

```
hysteria2/
  mod.rs    Hysteria2Transport: impl Transport + UdpTransport; quinn Endpoint/Connection setup
            (lazy connect + auth, reconnect on failure); dial() -> bidi-stream relay; dial_udp() ->
            datagram session; the shared receive pump for UDP datagrams.
  auth.rs   the one HTTP/3 POST /auth handshake → 233 (hand-rolled minimal H3 HEADERS + QPACK).
  tcp.rs    TCPRequest/TCPResponse codec + the AsyncRead+AsyncWrite adapter over a quinn bidi stream.
  udp.rs    UDPMessage encode/decode, fragmentation + reassembly, per-session sink/source halves.
  obfs.rs   Salamander + Gecko as a custom quinn AsyncUdpSocket wrapping the real UDP socket.
```

Feature gate: a new `hysteria2` cargo feature pulling `quinn` + `rustls` (ring) + `blake2`. The base
build stays rustls/ring-only and untouched; the binary budget is relaxed under the feature (as with
anytls/samizdat/shadowsocks).

---

## 5. Connection + auth (`mod.rs`, `auth.rs`)

`Hysteria2Transport` holds the config and a lazily-established, reconnect-on-failure quinn
`Connection`:
1. Build a quinn `Endpoint`. Its UDP socket is the real socket, or — if `obfs` is configured — wrapped
   by `obfs::SalamanderGeckoSocket` (a custom `AsyncUdpSocket`).
2. rustls `ClientConfig` (ring provider): SNI = configured server name; cert verifier per the
   `tls` mode (system-roots / pinned-sha256 / insecure). ALPN `h3` (hysteria masquerades as HTTP/3).
3. `connect()` → on the connection, run **auth** (`auth.rs`): open a bidi stream, write one HTTP/3
   HEADERS frame (the `POST /auth` request above, QPACK-encoded), read the response HEADERS frame,
   require `:status == 233`. Capture `Hysteria-UDP` (whether UDP relay is available).
4. After 233, the `Connection` is cached and reused: each `dial()`/`dial_udp()` uses raw quinn
   streams/datagrams on it.

**Auth implementation — hand-rolled minimal H3/QPACK (decided).** hysteria2 needs exactly one H3
request and then raw streams; a full `h3` crate wants to own the connection's stream management, which
fights the raw-stream data path (hysteria-go uses a minimal H3 for this reason). `auth.rs` encodes a
fixed request (static-table indices where possible, literals for `/auth`, `hysteria`, and the
`Hysteria-*` headers; QPACK with an empty dynamic table) and parses one response (status + a few
headers). ~150–200 lines, no `h3`/`hyper` dependency, and the data path never touches H3 again.

---

## 6. TCP & UDP data paths

**TCP (`tcp.rs`, `dial`).** Open a quinn bidi stream → write the `TCPRequest` (`0x401` varint, address,
random padding) → read + validate the `TCPResponse` (status `0x00` = OK; `0x01` → error, close) →
return a `BoxedStream`. quinn's `SendStream`/`RecvStream` already implement `AsyncWrite`/`AsyncRead`,
so the adapter is a thin newtype that pairs the two halves (no manual chunk framing — QUIC handles the
byte stream), unlike Shadowsocks' hand-rolled AEAD framing.

**UDP (`udp.rs`, `dial_udp`).** `dial_udp(target)` allocates a unique 32-bit Session ID on the shared
connection and returns split halves:
- **Sink (`send`)** encodes a UDPMessage for `target` (session ID, incrementing packet ID, address,
  payload). If the encoded message exceeds the connection's max datagram size, it is **fragmented**
  (same packet ID, `frag_count` parts); each fragment is sent via `Connection::send_datagram`.
- A per-connection **receive pump** (spawned once after auth) reads datagrams, decodes the UDPMessage
  header, reassembles fragments keyed by `(session_id, packet_id)` with a bounded buffer + TTL (drop
  on missing fragment), and routes the reassembled payload to the matching session's **Source
  (`recv`)** via an mpsc channel. Sessions map session ID → channel; bounded, idle-expired.

Both share the one authenticated `Connection` (TCP streams + UDP datagrams coexist on it).

---

## 7. Salamander + Gecko obfuscation (`obfs.rs`)

Implemented as one custom `quinn::AsyncUdpSocket` (`SalamanderGeckoSocket`) wrapping the OS socket —
the only layer that sees whole QUIC packets, which is what both schemes transform. Gecko wraps
Salamander, so the send pipeline is `QUIC packet → [Gecko if long-header] → Salamander → wire` and
recv is the reverse.

- **Salamander**: send — per datagram, random 8-byte salt, `hash = BLAKE2b-256(key ‖ salt)`, XOR the
  payload with the repeating 32-byte hash, emit `salt ‖ xored`. recv — split salt, recompute hash,
  de-XOR; drop datagrams too short to carry a salt. (`blake2` crate.)
- **Gecko**: send — inspect the QUIC packet's first byte; short-header → Salamander-wrap unchanged;
  long-header → split into `N ∈ [2,8]` chunks with random per-chunk padding, each wrapped in a Gecko
  frame (`0x80`, msgID, chunkIdx|totalChunks, padLen, padding, chunk) and Salamander-wrapped as its
  own datagram. recv — Salamander-deobfuscate; if first byte's high bit clear, deliver as a QUIC
  packet; else parse the Gecko frame and buffer by `(peer, msgID)` until `totalChunks` arrive, then
  reassemble in `chunkIdx` order and deliver. Bounded reassembly (per-peer cap, total cap, TTL);
  malformed/duplicate/`totalChunks`-inconsistent frames dropped.

Config: `obfs = { type = "salamander", password = "...", gecko = true }`. Absent obfs = plain QUIC
(`AsyncUdpSocket` = the OS socket directly).

---

## 8. Dial flow

```mermaid
sequenceDiagram
    autonumber
    participant Net as netstack<br/>(original dst)
    participant T as Hysteria2Transport<br/>mod.rs
    participant O as obfs.rs<br/>(Salamander/Gecko socket)
    participant Q as quinn<br/>(QUIC/rustls-ring)
    participant A as auth.rs<br/>(H3 /auth)
    participant S as Hysteria 2 server<br/>(apernet/hysteria)

    Net->>T: dial(target) / dial_udp(target)
    rect rgba(220,225,255,0.25)
    Note over T,S: connect + auth (once per connection)
    T->>Q: Endpoint over O (if obfs); rustls ClientConfig (ring, SNI, verifier), ALPN h3
    Q->>O: QUIC Initial packets
    O->>S: Gecko-fragment (long-header) → Salamander-XOR → UDP 🔒
    Q->>A: open bidi stream
    A->>S: HTTP/3 POST /auth (Hysteria-Auth, CC-RX, padding)
    S-->>A: :status 233 HyOK (Hysteria-UDP) ✅
    end
    rect rgba(200,240,210,0.25)
    Note over T,S: TCP
    T->>Q: open_bi(); send TCPRequest 0x401 ‖ addr ‖ pad
    S-->>Q: TCPResponse status=0x00 OK
    Q-->>Net: BoxedStream (quinn Send/Recv halves ⇄ bytes)
    end
    rect rgba(255,240,200,0.25)
    Note over T,S: UDP
    T->>Q: send_datagram(UDPMessage: sid,pid,frag,addr,payload) [fragmented if > max]
    S-->>Q: datagram(s) for sid
    Q->>T: receive pump reassembles fragments → session channel
    Q-->>Net: payload (PacketSource::recv)
    end
```

---

## 9. Config

`Hysteria2Config` in `core/src/config/mod.rs` (always-compiled, like the other transport configs),
`ServerSpec::Hysteria2`, and `transport.hysteria2`:

```toml
[transport.hysteria2]
server   = "proxy.example.com:443"   # IP:port or host:port (resolved at startup)
auth     = "<credential string>"      # Hysteria-Auth value
sni      = "proxy.example.com"         # optional; defaults to the server hostname
# congestion-control advertisement (Brutal deferred; this just sets Hysteria-CC-RX)
down_mbps = 0                          # 0 = unknown -> server uses BBR

[transport.hysteria2.tls]
mode       = "system-roots"            # "system-roots" | "pin-sha256" | "insecure"
pin_sha256 = "<hex>"                    # required when mode = "pin-sha256"

[transport.hysteria2.obfs]              # omit for plain QUIC
type     = "salamander"
password = "<obfs key>"
gecko    = true
```

`auth`/`obfs.password` are proxy secrets — privileged store only, never echoed over IPC (CLAUDE.md).

---

## 10. Dependencies (all behind the `hysteria2` feature)

- **`quinn`** (+ `quinn-proto`) — QUIC; configured with the rustls **ring** provider (NOT aws-lc-rs).
- **`rustls`** — the locked baseline TLS, arrives via quinn; custom `ServerCertVerifier` for
  pin-sha256 / insecure.
- **`blake2`** — Salamander's BLAKE2b-256 (pure-Rust; ring has no BLAKE2).
- Reused: `bytes`, `tokio`, `async-trait`. **No** `h3`/`hyper` (hand-rolled auth).

Pin exact versions and verify the quinn/rustls ring-provider feature wiring at implementation time
(verification discipline — do not guess the provider flags). The base build pulls none of these.

---

## 11. Testing & gates

1. **Codec unit tests** — TCPRequest/TCPResponse round-trip; UDPMessage encode/decode incl.
   fragmentation + reassembly (in/out of order, missing-fragment drop, > max-datagram split);
   QPACK auth request encode + a canned `233` response decode.
2. **Salamander KAT** — XOR keystream vs BLAKE2b-256 vectors; round-trip obfuscate/deobfuscate.
3. **Gecko round-trip** — long-header packet split into 2–8 frames then reassembled byte-identically;
   short-header pass-through; malformed/duplicate/inconsistent-`totalChunks` dropped; bounded state.
4. **Interop gate (authoritative)** — spark reaches a target through a **live `apernet/hysteria`
   server** (stand one up with a known auth + obfs config): TCP (HTTP 200) **and** UDP (DNS answer),
   with **obfs off and obfs on (Salamander+Gecko)**. Env-gated like the Shadowsocks interop test.
5. **Full `sudo spark run` TUN gate** — curl + a UDP DNS query → TUN → netstack → Hysteria2Transport
   → live server → internet; log-hygiene clean (no auth/obfs secret in logs).
6. **Workspace sweep** — build/clippy/test clean with **and** without the `hysteria2` feature; the
   base build pulls neither `quinn` nor `blake2`; release binary size reported.

---

## 12. Build order (chunks, one per session, green at each boundary)

1. **Feature + module skeleton + config types** — `hysteria2` feature, deps, `Hysteria2Config`/
   `ServerSpec::Hysteria2`/`transport.hysteria2`, empty module. (No QUIC logic yet.)
2. **`obfs.rs`** — Salamander then Gecko, as a standalone custom `AsyncUdpSocket`, unit-tested in
   isolation (no network: feed packets through the socket's transform functions). KAT + round-trips.
3. **`tcp.rs` + `udp.rs` codecs** — pure encode/decode (TCPRequest/Response, UDPMessage + fragment),
   unit-tested without a connection.
4. **`auth.rs`** — the minimal H3/QPACK request encoder + response decoder, unit-tested against canned
   bytes.
5. **`mod.rs` — quinn wiring** — Endpoint/ClientConfig (ring, verifier modes), connect + auth, then
   `dial` (bidi stream + TCP codec → `BoxedStream`) and `dial_udp` (datagram session + receive pump).
6. **Config wiring** — `from_config` precedence, `build_one` arm, `first_unresolved_host` +
   `resolve_endpoints` arms (SNI applies), `shadowsocks`-style `cfg(not(feature))` hard-error stub.
7. **Interop + TUN gates** — against a live `apernet/hysteria` server (obfs off, then on).

Non-negotiable order: prove `obfs.rs` and the codecs in isolation (steps 2–4) before wiring quinn
(step 5) before the live gate (step 7) — QUIC/obfs/codec bugs look alike from the outside; keep them
separable until each is proven.

---

## 13. Open questions / risks

- **quinn ↔ rustls ring provider.** The single most important build detail: quinn must use the rustls
  ring `CryptoProvider`, not aws-lc-rs, or we link a second C crypto lib next to `boring2`. Verify the
  exact crate/feature wiring (quinn version, `rustls` `ring` feature, explicit provider install) early
  — it gates the whole transport's dependency cleanliness.
- **Custom `AsyncUdpSocket` API surface.** Salamander (1:1 datagram transform) fits the trait cleanly;
  **Gecko turns one QUIC packet into N datagrams on send and N→1 on recv**, which means the wrapper
  buffers/splits within `poll_send`/`poll_recv`. Confirm quinn's current `AsyncUdpSocket` (batched
  `Transmit`s, GSO/GRO segment sizes) supports this cleanly; the spike for step 2 settles it.
- **Gecko currency.** Gecko is the newest obfs layer and is a hard v1 requirement (recent-blocking
  bypass). The protocol-doc layout is the design source; the **live interop gate (obfs on) is the
  authoritative oracle** — treat any mismatch as the bug, and capture frozen vectors from a real
  server.
- **`233` status in QPACK.** `233 HyOK` is a non-standard status not in the QPACK static table — the
  response decoder must handle it as a literal; the auth check keys on `== 233`.
- **UDP availability.** Honor the server's `Hysteria-UDP: false` — `dial_udp` returns a clear
  "server does not offer UDP relay" error in that case rather than silently dropping datagrams.
- **Brutal / port-hopping / multipath** — deferred (§1); Brutal is a contained `Controller`, multipath
  is the noq-migration (§2). None blocks v1 interop.
- **ADR.** On approval, record the decision (hysteria2 client on quinn/rustls-ring; quinn-now-noq-later;
  v1 = core + Salamander + Gecko; Brutal/port-hop/multipath deferred) as **ADR 0010**.
