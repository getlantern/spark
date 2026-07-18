# Bitcoin (BIP324) opening-move transport — design

- **Status:** Proposed — 2026-07-18. No code yet. Recorded as **ADR 0012**. This doc is the analysis
  behind that ADR.
- **Scope:** Add a spark client `Transport` (TCP byte-stream) that carries proxied traffic inside the
  **genuine Bitcoin P2P v2 encrypted transport (BIP324)** on **TCP 8333**, so DPI classifies the flow
  as a Bitcoin node connection. The blockable part — the opening choreography and framing — is a
  signed, dynamically-delivered **opening move** (an "opening move" WASM byte-transform in spark's
  Path-B sandbox); the heavy, stable crypto stays native. The matching server runs a real `bitcoind`
  with a keyed side-door for probe resistance (new infrastructure Lantern deploys).
- **Builds on:** the `Transport` trait seam (`core/src/transport/mod.rs`); the dynamic-transport WASM
  sandbox (**ADR 0003**, `core/src/transport/wasm/`) — pure byte-transform, no WASI/sockets, native
  crypto via `env` host imports; the early-bytes / opening shaping thesis (**ADR 0006**); the signed,
  key-pinned, versioned delivery + capability-gating model used for gambits
  (`core/src/transport/wasm/signing.rs`); and the feature-gating + `ServerSpec` config-wiring pattern
  of AnyTLS (ADR 0001), Shadowsocks (ADR 0009), Hysteria 2 (ADR 0010), DNS-tunnel (ADR 0011).
- **Reference specs:** BIP324 ("v2 transport protocol"), BIP155 (`addrv2`), Bitcoin P2P message format
  (the legacy "v1" framing), and the ElligatorSwift construction for secp256k1 (BIP324 §"ellswift").

## 1. Why Bitcoin, and why it is *easier* than TLS

The Opening Book thesis (ADR 0006) is that a censor classifies each connection from its opening and
then applies a policy — so the leverage is in the opening. For TLS that opening is a large **cleartext
fingerprint surface** (ClientHello cipher/extension ordering, GREASE, ALPN, JA3/JA4, the certificate
chain), which is exactly why the `flint` gambit machinery has to stay pinned to a genuine Chrome and
is fragile.

Bitcoin's v2 transport removes the fingerprint entirely. **BIP324 was designed so that every byte on
the wire is pseudorandom and carries no distinguisher** — its explicit goal was to deny DPI a Bitcoin
signature. The opening is a 64-byte ElligatorSwift-encoded ephemeral public key (uniform by
construction) followed by 0–4095 bytes of arbitrary garbage, after which all traffic is
ChaCha20-Poly1305 packets whose length fields are themselves encrypted (FSChaCha20). There is no
"correct" byte pattern for a censor to pin.

The consequence: **we do not mimic Bitcoin — we implement genuine BIP324 and place our tunnel bytes
where the Bitcoin messages would go.** To a DPI box, a BIP324 session carrying proxy data is
byte-indistinguishable from one carrying real `tx` / `block` / `inv` traffic, because both are an
unfingerprintable opening followed by AEAD ciphertext. That is "looks exactly like Bitcoin" in the
only sense that survives inspection: it *is* the wire protocol.

This is the opposite of the "Parrot is Dead" trap (Houmansadr et al., IEEE S&P 2013), where mimicry
fails because you must replicate every behavior and side-channel of a protocol you are not actually
running. Here we run the real protocol.

## 2. Threat model

| Adversary capability | Outcome | Handled by |
|---|---|---|
| Generic DPI / protocol classification from the opening (CN/IR/RU) | classified as Bitcoin v2 | BIP324 by construction |
| Active probing (GFW replays / connects to `:8333`) | prober reaches a **real node** | server-side `bitcoind` + keyed side-door (§5) |
| TLS/JA3 fingerprinting | N/A — no TLS on the wire | — |
| Entropy / fully-encrypted-traffic detection (USENIX '23) | Bitcoin v2 is *expected* high-entropy on `:8333` | port + protocol context |
| Behavioral / statistical flow analysis | **residual risk** — a bulk flow ≠ a gossiping node | partial shaping only (§6) |
| Bitcoin-specific / port-8333 targeting | **weak collateral freedom** — blocking Bitcoin is politically cheap for some censors | none; use as one regional gambit, not a default (§6) |

## 3. Exact wire behavior

**Port:** TCP **8333** (mainnet) — the classifier target. Nodes may listen on any port and advertise
it via `addr`/`addrv2` gossip, but 8333 is what a port-based classifier keys on.

### 3.1 v2 / BIP324 (primary)

1. Host dials TCP to `server:8333`.
2. Initiator sends **`ellswift_pubkey` (64 B) ‖ `garbage` (0–4095 B)**. The first bytes must **not**
   equal the v1 network magic `F9 BE B4 D9`; a responder uses "first bytes ≠ v1 magic" to detect v2.
   ellswift output is uniform, so this holds automatically.
3. Responder replies with its own `ellswift_pubkey (64 B) ‖ garbage`. Both sides run X-only ECDH on
   the ellswift-decoded points → HKDF-SHA256 to derive session keys, then exchange 16-byte
   **garbage terminators** and optional decoy packets.
4. All subsequent traffic is length-prefixed **ChaCha20-Poly1305** packets; the 3-byte length prefix
   is encrypted with FSChaCha20 (periodic rekey). Our proxy byte-stream is the packet contents.

### 3.2 v1 (reference / fallback only)

Legacy framing: `magic(4) ‖ command(12, NUL-padded ASCII) ‖ length(4, LE) ‖ checksum(4 = first 4 B of
SHA256d(payload)) ‖ payload`. Handshake: `version` → peer `version` + `verack` → `verack`, with a
plausible `version` payload (protocol version, `services` bitfield, `timestamp` within skew, `nonce`,
a real-looking user-agent such as `/Satoshi:26.0.0/`, `start_height` near the current chain tip,
`relay`). We would only fall back to v1 to blend with the still-large v1 population, and it is
**strictly worse** for us: the handshake is cleartext (must be byte-perfect) and tunnel data must
masquerade as `tx`/`block` payloads with valid double-SHA256 checksums. **Recommendation: v2-only**,
accepting v2's growing-but-minority share.

## 4. The opening move in spark's WASM sandbox

spark's dynamic-transport sandbox (ADR 0003, `core/src/transport/wasm/`) is a **pure byte-transform**:
no WASI, no sockets, no filesystem; the module exports `memory` + `alloc` and a transform pair (plus
optional `init`/`reset` and a `gambit-compute` export), and its **entire** capability is the host
functions under `env`. This is a better fit than raw WATER and it lands directly on the design doc's
"performance escape hatch" — keep the heavy, stable crypto native; make only the light,
frequently-changing choreography dynamic.

- **Host owns the socket.** `Transport::dial(target)` connects TCP to `server:8333` and drives I/O;
  the module never touches the network.
- **Module = BIP324 opening move + framing.** An explicit `enum` state machine (spark's stated
  preference for handshake cores, not nested async): `init(config)` receives per-deployment config
  (server static key / PSK, garbage-length distribution, decoy policy); the outbound transform emits
  the ellswift pubkey + keyed garbage + terminator, runs the handshake, then frames plaintext into
  BIP324 packets; the inbound transform reverses it.
- **Native crypto via `env` imports** (the escape hatch): secp256k1 ellswift decode + X-only ECDH,
  HKDF-SHA256, ChaCha20-Poly1305 / FSChaCha20. These are stable and fast, so they stay native
  (`secp256k1` with the ellswift module; `chacha20poly1305`; `hkdf`), the WASM stays tiny and
  iOS-interpreter-safe, and only the choreography — garbage lengths, decoy timing, the keyed-auth
  encoding, v1-vs-v2 selection — lives in the sandboxed module (the part you change when blocked).
- **Delivery = the gambit model.** The module and its parameter set (a *Bitcoin gambit*) are
  Ed25519-signed, key-pinned, versioned (anti-rollback), and capability-gated (`requires` the host to
  expose the ellswift/AEAD primitives), delivered over the config/fronting channel. The
  `gambit-compute` export emits the polymorphic opening parameters (garbage-length sampling, decoy
  count, v1 user-agent) so the repertoire stays ever-changing without reshipping the module — the
  Opening Book philosophy, extended from ClientHello to BIP324.

## 5. Server side — being a real node is the point

Wire mimicry alone fails active probing and IP-reputation checks. The strong posture:

- **Run a real `bitcoind` on the server, on `:8333`.** It genuinely joins the network — appears in
  `addr`/`addrv2` gossip, serves real blocks and transactions to real peers, and shows up in node
  crawlers (e.g. bitnodes). That is authentic cover, not simulation.
- **The tunnel is a keyed side-door on the same port.** A thin BIP324-terminating front accepts on
  `:8333`. The client's BIP324 `garbage` (arbitrary per spec) carries a keyed MAC over the client's
  `ellswift_pubkey` under a shared PSK. On accept:
  - **MAC matches** → this connection is a tunnel client; the front handles it.
  - **No match** (a real Bitcoin peer, or an active prober speaking real BIP324/v1) → the front hands
    the raw connection to the local `bitcoind`. The prober gets a genuine node — indistinguishable
    because it *is* one. This is the REALITY move (probe resistance by being real), adapted to Bitcoin.

### 5.1 The side-door: keyed-garbage authenticator

The server must decide tunnel-vs-node from the **cleartext prefix alone** — before it generates its
own ephemeral key or does ECDH — so the node path can stay a zero-crypto raw TCP splice to `bitcoind`.
(Once the front does ECDH it has committed to a responder key `bitcoind` doesn't share, and can no
longer hand the connection off.) That rules out putting the token in the encrypted stream or at the
ECDH-derived garbage terminator, and points to a **fixed-offset MAC at the very start of the garbage**.

Wire layout the tunnel client emits (everything after the 64-byte ellswift is, to anyone without the
PSK, just garbage):

```
ellswift_pubkey (64 B, uniform)      — BIP324
mac             (16 B)               — keyed; the first bytes of the garbage
filler          (random, var. len)   — pads garbage to a Core-matching length
```

**MAC** = `HMAC-SHA256(k_srv, ellswift_pubkey ‖ epoch ‖ "spark-btc-v1")[:16]`, where
- `k_srv = HKDF(PSK, server_id)` — a per-server subkey (kills cross-server replay; no shared global secret);
- `ellswift_pubkey` — the 64 wire bytes, binding the MAC to this connection's fresh ephemeral key;
- `epoch = floor(unixtime / 600)` — a 10-minute window; the server accepts `epoch-1 … epoch+1` for
  clock skew (≤ ~30-minute replay bound);
- 16-byte tag → a real peer's random garbage matching by chance = 2⁻¹²⁸ (no legit peer is ever
  misrouted into the tunnel path).

The front reads exactly **64 + 16 bytes**, computes the expected MAC for each accepted epoch, compares:

- **Match** → tunnel client; the front becomes the BIP324 responder (own ephemeral, ECDH, session).
- **No match / replay-cache hit / MAC fail** → the front opens a connection to the local `bitcoind`,
  **replays the 64 + 16 bytes it already read**, and pipes bytes both ways with zero interpretation.
  `bitcoind` runs the full responder role; our 16 MAC bytes are simply the first 16 bytes of the
  garbage it authenticates as AAD. No BIP324 crypto in the front on this path. (A real client that
  sent 0 garbage — whose first 16 post-ellswift bytes are actually its garbage terminator — fails the
  MAC and takes this same splice; it works.)

Why it holds:

- **Uniform to an observer.** ellswift, the MAC tag, and the filler are all uniform. The one
  distributional constraint is **garbage length**, and it *is* observable: the initiator sends
  `ellswift ‖ garbage` and then pauses a full RTT for the responder's ellswift before it can compute
  the terminator, so an on-path observer reads the first-flight size as `64 + garbage_len`. Verified
  against Bitcoin Core (`src/net.cpp GenerateRandomGarbage`): length is `randrange(MAX_GARBAGE_LEN+1)`
  = **uniform over [0, 4095], random content** (`MAX_GARBAGE_LEN = 4095`, `net.h`). We therefore draw
  total garbage length uniform over [0, 4095] **clamped to ≥ 16** (the MAC floor). The only deviation
  from Core is the absent [0, 15] tail — 16/4096 ≈ **0.39%** of the distribution — a statistically
  tiny, though not strictly zero, tell.
- **No BIP324 weakening.** The MAC never touches the ECDH or key schedule; it is spec-legal arbitrary
  garbage on both paths.
- **PSK-gated.** A prober without the PSK sending fresh `ellswift + random garbage` never matches →
  node path → real `bitcoind`, indistinguishable from any peer connecting.
- **Replay-resistant.** Primary defense is a **fresh-ellswift LRU cache** (bounded; TTL ≥ the ~30-min
  epoch span): legit clients never reuse an ephemeral, so a repeated ellswift → node path (real
  `bitcoind`, trivially indistinguishable). Secondary: a replay that evicts past the cache still can't
  complete — the replayer captured only the *public* ellswift, so it can't derive session keys (needs
  the initiator's ephemeral *private* key) or send valid tunnel frames. For that cache-edge case the
  front's responder behavior (own ellswift+garbage, first-packet size, idle-timeout) should mirror
  `bitcoind`'s, but the cache carries the load so this need not be byte-perfect.

## 6. Detectability & residual risks (stated plainly)

1. **Traffic shape is the real weakness.** A bulk proxy flow does not look like a gossiping node
   (many peers, periodic `inv`/`addr`/`ping`, ~10-min block bursts, mostly small messages). Partial
   mitigations: pace/cap toward relay-like patterns, run several concurrent "peer" connections, inject
   decoy `inv`/`ping` cadence. None fully resolve "bulk throughput looks wrong" — the ceiling every
   tunnel hits; BIP324 does not lift it. Fine under an opening-move threat model (classify on the
   open, no per-flow behavioral ML at scale); exposed against a determined behavioral analyzer.
2. **Bitcoin is politically blockable.** Unlike TLS-to-a-CDN, blocking `:8333` / Bitcoin is cheap for
   censors who already restrict crypto (e.g. China). Collateral freedom here is **weak** — we defeat
   generic DPI, not a decision to target Bitcoin. Use as one regional gambit where Bitcoin is
   tolerated, not a universal default.
3. **v2 is still a minority** of the network (growing since Bitcoin Core 26). Plausible, not dominant.
4. **IP reputation.** A bare `:8333` that is not a known node is itself a signal — only solved by
   actually running the node (§5).

## 7. Build order

1. This design + **ADR 0012**.
2. Native `env` primitives (ellswift/ECDH via `secp256k1`, `chacha20poly1305`, `hkdf`), advertised as
   host capabilities the gambit `requires`.
3. The BIP324 WASM transform module (Rust → `wasm32`), delivered/signed via the existing gambit path.
4. `BitcoinTransport` `Transport` impl that dials `:8333` and drives the module; behind a `bitcoin`
   feature, mirroring `anytls`/`hysteria2` gating and `ServerSpec` wiring.
5. Server: `bitcoind` + the BIP324-terminating front (keyed-garbage check, tunnel-vs-node fork).
6. Instrumentation: per-gambit handshake-completion + probe-detection counters (a connection that
   completes BIP324 but fails the keyed-garbage check = probe/real-peer signal).

## 8. Open questions

- **Keyed-garbage authenticator** — specified in §5.1. Remaining sub-question: whether the
  front-as-responder path is worth hardening to byte-level timing/size parity with `bitcoind`, or
  whether the fresh-ellswift cache makes that moot.
- **v2 adoption trajectory** — is v2-only acceptable now, or do we need a v1 gambit for some regions?
- **Shaping budget** — how much decoy/pacing is worth the throughput cost for the target user segment.
- **Reusing `bitcoind`'s own BIP324 stack** on the server vs. a standalone terminator (the former is
  more faithful; the latter is easier to fork tunnel-vs-node).
