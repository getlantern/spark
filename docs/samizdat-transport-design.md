# Samizdat transport — design (M11)

- **Status:** Proposed — 2026-06-19. Direction agreed in session; the load-bearing TLS assumption
  (the `kID` SessionID-injection trick) is being validated by a throwaway spike before commit.
- **Scope:** Add Lantern's **Samizdat** protocol as a spark `Transport`, **wire-interoperable with the
  deployed `lantern-box` / sing-box `"samizdat"` servers** (client side only; the server stays Go).
- **Builds on:** ADR 0001 (BoringSSL Chrome-mimicry TLS backend), ADR 0006 (opening-gambit /
  `Capability::SessionIdInject`), the `m11-transport-candidates-anytls-samizdat` memory, and the
  in-tree AnyTLS transport (`core/src/transport/anytls/`) it reuses heavily.
- **Reference implementation:** `github.com/getlantern/samizdat` (Go), studied at
  `/Users/afisk/go/src/github.com/getlantern/samizdat` — `auth.go`, `client.go`, `h2transport.go`,
  `samizdat.go`.

---

## 1. Goal & scope

Make spark's Rust client able to tunnel through an **unmodified, already-deployed Samizdat server**.
That pins every wire detail: the auth bytes in the TLS SessionID, the single-TLS-1.3 + H2-CONNECT
structure, and a Chrome ClientHello the server's REALITY path accepts.

**In scope (v1):**
- A `samizdat` client `Transport` (TCP), behind a cargo feature, selectable via `[transport.samizdat]`.
- REALITY-style auth embedded in the TLS `legacy_session_id`.
- One outer TLS 1.3 session (Chrome-mimicking ClientHello, reusing the AnyTLS boring connector) with
  proxied flows multiplexed as **HTTP/2 CONNECT** streams.
- Connection pooling / multiplexing across CONNECT streams (mirrors the Go client's `connPool`).
- Reuse of spark's existing opening-handshake **ClientHello fragmentation** (`shaping/sni.rs`) and
  timing knobs to match Samizdat's Geneva-style fragmentation + jitter.

**Out of scope (v1), explicitly:**
- The Samizdat **server** (masquerade fallback, short-ID registry) — stays in Go/`lantern-box`.
- **UDP over Samizdat.** The Go protocol is TCP-only (it proxies TCP via H2 CONNECT). spark's
  `UdpTransport` for the samizdat config will return "unsupported" in v1; DNS/UDP continues on
  whatever non-samizdat path the config provides. UDP-over-CONNECT (UoT) is a later increment and
  needs server support, so it is deferred (§11).
- Firefox/Safari fingerprints (the Go client offers them; spark mimics Chrome only, per ADR 0001).

---

## 2. What Samizdat is (the wire, from the Go source)

Samizdat makes proxy traffic look like a browser visiting a real site over HTTP/2, using **one** TLS
layer (no TLS-in-TLS) plus REALITY-style auth and a masquerade fallback.

**Auth (`auth.go`).** Pre-shared between client and server: the server's 32-byte X25519 **public key**
and an 8-byte **short ID**. The client derives a PSK and stamps a 32-byte TLS SessionID:

```
PSK        = HKDF-SHA256(ikm = serverPubKey, salt = shortID, info = "SAMIZDAT")   → 32 bytes
SessionID  = shortID(8) ‖ nonce(8) ‖ HMAC-SHA256(PSK, nonce)[:16]                 → 32 bytes
```

Note the client auth path needs **no ECDH** — `derivePSK` HKDFs the server public-key *bytes*
directly as IKM. So the client only needs HKDF-SHA256 + HMAC-SHA256 + a random nonce — all in `ring`.

**Handshake (`client.go`).** uTLS Chrome ClientHello, `InsecureSkipVerify` (auth is REALITY, not PKI),
ALPN `h2`, SNI = a cover-site name. The auth SessionID is injected by
`BuildHandshakeState` → set `HandshakeState.Hello.SessionId` → `MarshalClientHello` — i.e. **before**
the hello is marshaled, so it is part of the TLS transcript (this is the crux spark must reproduce; §5).

**Transport (`h2transport.go`).** Stock `golang.org/x/net/http2.Transport` over the one TLS conn;
each proxied flow is an **HTTP/2 `CONNECT`** request whose `:authority`/`Host` is the destination,
request body = upload, response body = download. Streams are multiplexed on the single TLS connection
(default 100/conn). The H2 layer is entirely inside TLS, so its fingerprint is encrypted — Go's stock
H2 fingerprint is fine, and so is any compliant Rust H2 client (§4).

**Server (out of scope, for context).** Reads the SessionID from the raw ClientHello; valid auth →
proxy mode; otherwise transparently TCP-proxies to the real cover domain (`masquerade.go`) so a prober
sees a genuine site. The server does **not** validate the client's JA3/JA4 — the fingerprint is for
evading the censor, not for passing the server. So for *interop* the load-bearing requirement is the
exact SessionID; the Chrome CH is for evasion (and spark already has it).

---

## 3. Where it sits in spark

A new `Transport` impl alongside `anytls` and `wasm`, reusing existing machinery rather than
duplicating it:

| Need | Reuse |
|---|---|
| Chrome ClientHello (boring2 + Chrome-137 profile, JA4-verified) | `anytls/tls.rs` connector + `anytls/profile.rs` |
| ClientHello fragmentation + timing | `transport/shaping/` (`SegmentShapingStream`, SNI boundary) |
| HKDF / HMAC / RNG | `ring` (already in core) |
| Session pool / reconnect / idle sweep pattern | `anytls/session.rs` + `AnytlsTransport` pool |
| Config gating + `from_config` precedence + feature stub | `transport/mod.rs`, `config/mod.rs` |
| Capability model for SessionID injection | `gambit::Capability::SessionIdInject`, `profile.rs` gating |

New surface lives under `core/src/transport/samizdat/`:

```
samizdat/
  mod.rs        layering doc + version/label consts
  auth.rs       PSK derivation + SessionID build (ring); test vectors vs the Go impl
  session_id.rs the SessionID-injection seam (primary: kID trick; fallback: boring patch)
  h2.rs         H2 CONNECT mux over the TLS stream via the `h2` crate (stream <-> AsyncRead+AsyncWrite)
  transport.rs  SamizdatTransport: pool of TLS+H2 conns, dial() -> CONNECT stream; impl Transport
```

Feature gate: a new `samizdat` cargo feature. It depends on the `anytls` feature's boring stack
(reuses the connector) plus the new `h2` dependency. Base build stays rustls/ring-only.

---

## 4. HTTP/2 CONNECT mux — the `h2` crate

CLAUDE.md forbids `hyper`/`reqwest`. We reviewed *why* (session: openssl-sys avoidance + the <3 MB
budget + "you relay bytes, not HTTP"). Samizdat is the first case that genuinely needs HTTP/2
semantics on the data path, and the budget is relaxed (~10 MB, ADR 0001). The H2 layer is **inside
TLS**, so its wire fingerprint (SETTINGS/HPACK/Akamai) is encrypted and is **not** an evasion
surface — the production Go client just uses stock Go http2. So the choice is about correct CONNECT
interop + flush control + dependency weight, not mimicry.

**Decision: the `h2` crate (sans-hyper).** It is the HTTP/2 protocol implementation hyper builds on,
but lower-level — we drive SETTINGS/streams, it has no `http`-server/`tower`/openssl baggage. This is
a **scoped locked-stack exception** in the same spirit as boring2: documented, justified, and the
*smallest* dependency that does the job (full hyper was the heavier thing the rule actually targeted).

Shape (verify exact API at implementation time):
- `h2::client::handshake(tls_stream)` → `(SendRequest, Connection)`; spawn the `Connection` future as
  the per-conn driver task (cancel on pool eviction).
- Per flow: `http::Request` with method `CONNECT`, `:authority` = destination `host:port`, no
  `:scheme`/`:path` (RFC 7540 §8.3) — matching the Go client's `MethodConnect` + `req.Host`.
  `send_request(req, end_of_stream=false)` yields a `SendStream` (upload); the response yields a
  `RecvStream` (download).
- Wrap `(SendStream, RecvStream)` as a `BoxedStream` (`AsyncRead+AsyncWrite`): writes → `send_data`,
  reads ← `RecvStream` + flow-control release; `poll_shutdown` → `send_data(end_of_stream)` (the H2
  half-close, matching `h2transport.go`'s `CloseWrite`). Pin `h2` to a current version.

Precondition: ALPN must negotiate `h2` (assert `ssl.selected_alpn_protocol() == b"h2"`); the boring
connector already offers `h2,http/1.1`.

---

## 5. The crux — SessionID injection (interop-exact, pre-transcript)

The 32 auth bytes must be the ClientHello `legacy_session_id` **and** be present before the TLS
library computes its transcript hash (TLS 1.3 binds Finished/keys to the full ClientHello). uTLS
injects pre-marshal; an on-wire splice after boring builds the hello would desync the transcript and
fail Finished. `boring2` 4.15 exposes no client SessionID setter (verified: `ConnectConfiguration`
has only `set_session` = resumption). Two interop-correct paths:

### Primary — the `kID` session trick (no fork)

Source-confirmed in BoringSSL `handshake_client.cc`:

```c
const bool enable_compatibility_mode = hs->max_version >= TLS1_3_VERSION && !quic && !dtls;
if (session_type == SSLSessionType::kID) {
  hs->session_id = ssl->session->session_id;          // ← the SET session's id, checked FIRST
} else if (session_type == kTicket || enable_compatibility_mode) {
  RAND_bytes(hs->session_id, ...);                     // ← random compat id (tickets + fresh)
}
```

So a **TLS 1.2, session-ID-based (`kID`), ticketless, resumable** `SSL_SESSION` whose `session_id`
is our 32 auth bytes makes boring emit those bytes as `legacy_session_id` **even in a 1.3-offering
Chrome hello** — and because boring builds the hello itself, the transcript is correct. Session
*tickets* (and TLS 1.3 sessions) fall to the random branch and do **not** work — only ID-based.

Construct via public BoringSSL setters (through `boring-sys2` FFI), not internal DER:
`SSL_SESSION_new` → `SSL_SESSION_set_protocol_version(TLS1_2_VERSION)` →
`SSL_SESSION_set_cipher(<a cipher already in Chrome's list>)` → `SSL_SESSION_set1_id(<32 auth bytes>)`
→ `SSL_SESSION_set1_master_key(<dummy>)` + `set_time`/`set_timeout` (so it is "resumable") → wrap as
`SslSession` → `ConnectConfiguration::set_session(&s)` before connect. The fabricated session is never
actually resumed (the server negotiates a fresh 1.3 handshake); it only steers the hello field.

**Spike must confirm (before commit):** (1) the fabricated session classifies as `kID`/resumable and
its id appears as `legacy_session_id`; (2) offering it leaves `max_version` at 1.3 (no version cap —
Chrome must still offer 1.3); (3) the JA4 is unchanged (classic 1.2 ID-resumption can nudge the
cipher list — set the session cipher to one already present and assert JA4 parity via the drift
check). Throwaway crate at `/tmp/kid-spike` (§ spike).

### Fallback — patch `boring-sys2` (only if the spike fails any check)

Add one patch file to `boring-sys/patches/` (the fork already carries its mimicry deltas this way):
a `SSL_set1_client_session_id()` plus a copy-from-buffer at the compat session-id fill site, exposed
via bindgen and called on `ssl.as_ptr()`. Fork **only `boring-sys2`** via Cargo
`[patch.crates-io]`; `boring2`/`tokio-boring2` stay upstream and auto-track. This is the path ADR 0001
anticipated and lets `profile.rs` advertise `Capability::SessionIdInject` (filling the one executor
gap the codebase already modeled), and it reuses for REALITY later.

**Maintenance (fallback only).** Chrome-fingerprint currency does **not** come from the fork — it
comes from the Chrome profile tables (already copied into `tls.rs`) + the JA4-drift CI check. The
patch is a tiny, additive overlay at a very stable call site. A scheduled CI job: watch upstream
boring2/btls → bump pin → re-apply patch → build → run the JA4-drift check vs live Chrome → PR if
green / alert if red. Upstream the patch to `0x676e67/btls` to drop the delta to zero (REALITY/uTLS
SessionID injection is squarely in that fork's wheelhouse).

---

## 6. Auth crypto (exact)

All in `ring`; unit-tested against vectors captured from the Go impl.

- `PSK = HKDF-SHA256(ikm = serverPubKey[32], salt = shortID[8], info = b"SAMIZDAT")`, 32 bytes.
  `ring::hkdf`: `Salt::new(HKDF_SHA256, shortID).extract(serverPubKey).expand(&[b"SAMIZDAT"], 32)`.
- `nonce = 8 random bytes` (`ring::rand::SystemRandom`).
- `tag = HMAC-SHA256(PSK, nonce)[:16]` (`ring::hmac::Key::new(HMAC_SHA256, &psk).sign(&nonce)`, first 16).
- `SessionID = shortID ‖ nonce ‖ tag` (8 + 8 + 16 = 32).

Config supplies `server` (host:port), `server_pubkey` (hex, 32 bytes), `short_id` (hex, 8 bytes),
`sni` (cover-site name). Secrets live in the privileged store (never echoed over IPC — CLAUDE.md).

---

## 7. Dial flow

```mermaid
sequenceDiagram
    autonumber
    participant Net as netstack<br/>(original dst)
    participant T as SamizdatTransport<br/>transport.rs
    participant A as auth.rs
    participant TLS as boring connector<br/>tls.rs (reused)
    participant H2 as h2.rs<br/>(h2 crate)
    participant S as Samizdat server<br/>(Go, deployed)

    Net->>T: dial(target)
    T->>T: acquire pooled TLS+H2 conn (or create)
    rect rgba(200,220,255,0.25)
    Note over T,TLS: create path (per new conn)
    T->>A: build SessionID(serverPubKey, shortID)
    A-->>T: shortID‖nonce‖HMAC[:16]
    T->>TLS: set_session(kID session w/ id = SessionID)  ⚠️ pre-transcript
    T->>TLS: connect(SNI, Chrome profile) over shaping stream (frag CH)
    TLS->>S: ClientHello (Chrome JA4, legacy_session_id = auth) 🐛 the injection
    S-->>TLS: ServerHello … (auth ok → proxy mode; else masquerade)
    T->>H2: h2 handshake over TLS; spawn Connection driver
    end
    T->>H2: CONNECT :authority=target
    H2->>S: HEADERS (CONNECT)
    S-->>H2: 200
    H2-->>Net: BoxedStream (DATA frames <-> bytes)
```

Pool: `Mutex<Vec<Arc<Conn>>>`, reuse newest healthy under a per-conn stream cap (Go default 100),
evict dead, connect outside the lock, idle sweep — same shape as `AnytlsTransport`.

---

## 8. Dependencies & locked-stack exceptions

- **New:** `h2` crate (pinned). Scoped exception to the no-hyper rule (§4); not hyper, no openssl-sys,
  no tower. Pull only under the `samizdat` feature.
- **Reused:** `boring2`/`tokio-boring2` (already an ADR-0001 exception), `ring`, `bytes`, `tokio`,
  `async-trait`, `http` (a transitive of `h2`; data types only).
- **Conditional (fallback only):** a `boring-sys2` fork via `[patch.crates-io]` carrying the
  SessionID patch — only if the kID spike fails.

---

## 9. Testing & gates

1. **Auth unit tests** — `SessionID`/PSK match vectors captured from the Go `BuildSessionID`/`derivePSK`.
2. **kID spike** (throwaway) — boring emits our `legacy_session_id`, still offers 1.3, JA4 unchanged.
3. **H2 CONNECT unit/integration** — `(SendStream,RecvStream)` ⇄ `AsyncRead+AsyncWrite` round-trips
   through a local h2 server doing CONNECT→echo.
4. **Interop gate (the real one)** — spark's client reaches a target through a **live Samizdat server**
   (stand up `getlantern/samizdat` or a `lantern-box` instance with a known pubkey/shortID) → HTTP 200.
5. **Full `sudo spark run` TUN gate** — curl → TUN → netstack → SamizdatTransport → live server →
   internet, log-hygiene clean.
6. **JA4-drift CI** — the existing planned check also guards samizdat (same connector).

---

## 10. Build order (chunks, one per session, green at each boundary)

1. **`auth.rs`** — PSK + SessionID, pure `ring`, vectors vs Go. (No TLS.)
2. **kID spike** — validate §5 primary; decide primary vs fallback. (Throwaway.)
3. **`session_id.rs`** — the injection seam realizing the spike's winning method.
4. **`h2.rs`** — H2 CONNECT mux + stream adapter, tested against a local h2 CONNECT echo.
5. **`transport.rs` + config wiring** — `SamizdatTransport` (pool) impl `Transport`; `[transport.samizdat]`;
   `from_config` precedence + feature stub.
6. **Interop + TUN gates** — against a live Samizdat server.

---

## 11. Open questions / risks

- **kID spike outcome** — the whole primary path. If any of the three checks fails → fallback patch.
- **UDP** — out for v1 (samizdat is TCP-only). If parity needs UDP-over-samizdat, it is UoT-inside-
  CONNECT and needs server support; revisit as a separate increment.
- **Server-side `h2` quirks** — the Go server uses stock x/net/http2; confirm spark's `h2` CONNECT
  (pseudo-headers, half-close, GOAWAY handling) interops cleanly (gate 4 settles it).
- **Cover-SNI / pubkey / shortID provisioning** — these come from lantern's config distribution; spark
  consumes them. Mirrors how AnyTLS gets `server`/`password`.
- **ADR** — on approval, record the decision as ADR 0007 (Samizdat: kID injection + h2 CONNECT).
