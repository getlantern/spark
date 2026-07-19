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
| Entropy / fully-encrypted-traffic detection (USENIX '23) | **not defeated** — a v2 opening *is* high-entropy; flagged on monitored VPS ranges | IP placement: residential / non-flagged ASNs (§6 item 5) |
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

> **Engine placement is settled in §7, and it is not "run the handshake in the transform."** This
> section is the *logical* decomposition of the opening move. §7 shows that BIP324's *interactive*
> handshake cannot run inside today's byte-transform ABI (no inbound-triggered outbound write, and the
> KEX menu is X25519-only), so the live handshake runs in a **native BIP324 engine** while the signed
> *gambit* carries the polymorphic opening — mirroring how the TLS side pairs a native boring engine
> with a flint gambit. Read §4 for the shape, §7 for what actually executes where.

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

### 5.2 Why this survives "The Parrot is Dead"

Houmansadr et al. (IEEE S&P 2013) showed that a *partial reimplementation* of a protocol is undone by
an active censor who can **perturb and probe** — drop/malform packets, drive error paths, engage
side-protocols — because the mimic diverges from the real software somewhere. Their prescribed escape
is to *run the actual software*, not to mimic harder; byte/timing parity of a fake is therefore not
merely expensive but **insufficient** against a probe that can engage the protocol.

The design is shaped by that result, through an asymmetry between the two paths:

- **Node path = genuine `bitcoind`** (raw TCP splice). Real peers and probers reach Core's actual
  BIP324 stack; perturb it however you like and it reacts as `bitcoind` because it *is* `bitcoind` —
  exactly the "run the real software" escape. This is also why raw-splice beats a terminate-and-relay
  front: relay would place *our* BIP324-transport reimplementation in front of probers, which Parrot
  *would* defeat; splicing hands them Core's stack.
- **Tunnel path = our reimplementation**, so a prober must never reach it — and cannot. Every deep
  Parrot attack requires *engaging* the session (producing valid packets, driving error paths), which
  requires the session keys, which require **both** a fresh ephemeral private key **and** the PSK. A
  credential-less adversary has neither: no PSK → no valid MAC → routed to real `bitcoind`; a replayed
  MAC → no ephemeral private key → can't derive keys → can't send a single valid packet.

So the path where mimicry is fatal is the path a credential-less prober cannot reach, and the path it
can reach is real. The lone residual — a keyless replay that slips the fresh-ellswift cache onto the
tunnel path — is **shallow**: keyless, it can only observe the responder's opening flight and
disconnect timing (it cannot derive keys to perturb anything). That narrow surface is what the coarse
size/timing parity in §5.1 covers, and the cache makes it rare. Full byte parity is thus neither
required nor — per Parrot — sufficient were the path actually exposed; the real defense is **gating
access, not perfecting the fake**.

**Boundary of the probe-resistance claim (stated honestly):** it holds against a **credential-less**
censor. A censor who extracts a valid PSK from a captured client can forge MACs with fresh keys,
complete real sessions, reach the tunnel path, and then run full Parrot perturbation against our
partial front — and win. This is inherent to every credentialed probe-resistant design (REALITY
included: steal the client secret and you can confirm the server). The answer is containment, not
prevention: **per-track / per-server PSKs** so one compromise doesn't burn the fleet, plus rotation.

## 6. Detectability & residual risks (stated plainly)

1. **Traffic shape is the real weakness.** A bulk proxy flow does not look like a gossiping node
   (many peers, periodic `inv`/`addr`/`ping`, ~10-min block bursts, mostly small messages). Partial
   mitigations: pace/cap toward relay-like patterns, run several concurrent "peer" connections, inject
   decoy `inv`/`ping` cadence. None fully resolve "bulk throughput looks wrong" — the ceiling every
   tunnel hits; BIP324 does not lift it. Fine under an opening-move threat model; exposed against a
   determined behavioral analyzer — and flow/behavioral analysis *is* deployed in practice, though as
   a secondary layer, which sets the shaping budget (§6.1).
2. **Bitcoin is politically blockable.** Unlike TLS-to-a-CDN, blocking `:8333` / Bitcoin is cheap for
   censors who already restrict crypto (e.g. China). Collateral freedom here is **weak** — we defeat
   generic DPI, not a decision to target Bitcoin. Use as one regional gambit where Bitcoin is
   tolerated, not a universal default.
3. **v2 is the majority** of global Bitcoin P2P traffic as of early 2026 (Wuille, *Bitcoin Magazine*,
   Feb 2026; on-by-default since Core 27.0, Apr 2024). A v2 flow is the *common* case — v2-only blends
   fine and needs no v1 fallback for cover.
4. **IP reputation.** A bare `:8333` that is not a known node is itself a signal — only solved by
   actually running the node (§5).
5. **Entropy / fully-encrypted-traffic detection is *not* defeated by BIP324 — it is the one opening
   filter BIP324's randomness walks *into*.** The GFW's fully-encrypted detector (USENIX '23) blocks
   high-entropy first packets (avg set-bits/byte in [3.4, 4.6], no TLS/HTTP exemption) on ~2% of IPs —
   specifically VPS provider ranges (DigitalOcean/Linode/Alibaba) — at ~26% sampling. A BIP324 opening
   (ellswift + random garbage) *is* exactly such a packet, so a v2 flow to a **monitored VPS IP is
   flagged like any other look-like-random protocol.** Wuille frames the only-out as collateral cost
   ("to block Bitcoin using v2 you must block anything that looks random") — but on those ranges the
   GFW already pays it. **Defense is IP placement, not wire shape:** run the node on residential /
   non-flagged ASNs — which also supplies the real-node reputation item 4 wants and matches the
   residential-peer strategy. This is the sharpest China-specific constraint.

### 6.1 Shaping budget — grounded in deployed-censor evidence

"How much performance do we spend making the flow look node-like?" is a real, region-dependent
decision, not a settled spec line. What the evidence (deployed vs. academic) says:

- **Flow / behavioral analysis is deployed — but as a secondary layer.** The clearest deployed case
  is the exported Chinese **Tiangou Secure Gateway** (Geedge/MESA leak; InterSecLab, *The Internet
  Coup*, 2025) — a commercial stack with **ML + traffic-shape classifiers** sold to Kazakhstan,
  Ethiopia, Pakistan, and Myanmar, characterized as "the hardest component to defeat with static
  mimicry … trained on real circumvention traffic and updated over time." DomainTools' analysis of the
  same leak reports a GFW `PROTO_DEVIATE` flag keyed on **connection duration, session timing, and
  connection frequency**. NDSS 2025 adds protocol-agnostic **cross-layer RTT fingerprinting**. Master
  & Garman (FOCI 2023) find NGFW / encrypted-traffic-analysis flow classification in ~6–13% of
  countries, "underdetected — assume higher."
- **…but the primary at-scale passive filters are opening-based and don't reassemble flows.** What
  BIP324 defeats is byte-*pattern* DPI (the v1 Bitcoin magic, protocol signatures) — Wuille/Optech
  (Feb 2026) put it exactly: today's v2 implementations "only defeat protocol signatures that involve
  patterns in the sent bytes, not in traffic." And the GFW's fully-encrypted detector (USENIX '23)
  inspects **only the first packet, not the flow.** So flow-shape analysis is a real *escalation* —
  not the first thing that runs. (Flip side, kept honest: that same entropy detector is *not* defeated
  by BIP324 — its random opening is caught on monitored ranges, §6 item 5 — but that's an
  opening/IP-placement problem, not a flow-shape one.)

Design consequences:

- **Low default budget, region-tunable escalation.** Rely on the opening + BIP324 + `:8333` against
  the dominant deployed methods; expose shaping (decoy cadence, volume pacing, burst matching) as a
  **signed gambit parameter dialed up per-region only where telemetry shows a TSG-class classifier** —
  the "discovered against the live network" Opening Book approach, which also counters the fact that a
  *static* shaping profile gets learned around (the ML classifiers retrain cheaply).
- **Bitcoin inverts samizdat's shaping priorities — do not copy them blindly.** samizdat (a
  TLS/browsing cover) rotates sessions because long-lived connections are *suspicious* for browsing. A
  Bitcoin cover is the opposite: real nodes hold peers for hours, so long-lived is *expected* —
  rotating would make us **less** node-like. The behavioral tell against a Bitcoin cover is not
  duration but **bulk asymmetric volume** (nodes exchange small bidirectional relay + ~10-min block
  bursts; a proxy pulls megabytes downstream). So the budget here is spent on **volume / burst pacing,
  not session rotation** — while RTT jitter (shared with samizdat) is still worth carrying against
  NDSS-2025-class timing analysis.
- **The ceiling stands.** No shaping fully disguises a heavy bulk user as a gossiping node; past a
  point you can only throttle to a trickle. This transport fits an opening-classification threat model
  and TSG-light regions — not a censor running heavy per-flow ML, where a bulk tunnel is inherently
  exposed regardless of shaping.

## 7. Implementation

### 7.1 What the existing "gambit" machinery reaches — and what it doesn't

"Gambit" means two different things here:

- **The flint `Gambit` genome** (what `compute_gambit` returns) — a `Chrome137` anchor plus deltas over
  three TLS layers (ClientHello content / TLS record framing / TCP segment-timing), *executed by the
  native boring TLS engine*. **TLS-only, not reusable**: there is no BIP324 executor, and the genome
  models a TLS handshake.
- **The signed-delivery envelope** (`SignedModule` / `signing.rs` — Ed25519, versioned,
  capability-gated) and the **Opening Book concept** (a signed opening plan run by a native engine,
  shippable without a client release). **Fully reusable** — this is what makes any of this a "gambit."

So the concept transfers; the TLS genome and its executor do not.

### 7.2 WASM sandbox: most crypto is present, three gaps

The host `env` menu already provides, natively: `host_rand` (CSPRNG), `host_hash` (SHA-256),
`host_hkdf_extract/expand` (HKDF-SHA256), and `host_aead_seal/open` (**ChaCha20-Poly1305**). HKDF-SHA256
is BIP324's KDF and ChaCha20-Poly1305 is its AEAD exactly — most of BIP324's crypto is already native,
validating the escape hatch. The gaps:

| Gap | What BIP324 needs | Status in spark |
|---|---|---|
| **Key exchange** | secp256k1 **ElligatorSwift** encoding + secp256k1 X-only ECDH (`ellswift_ecdh`) | KEX menu is **X25519-only** (built for TLS 1.3). Add native `host_secp256k1_ellswift_keygen` / `host_secp256k1_ellswift_ecdh` (rust-bitcoin `secp256k1`) as a `bip324` capability. In-guest secp256k1 in the interpreter is a non-starter. |
| **Length-field cipher** | raw ChaCha20 keystream (FSChaCha20, no tag) for the 3-byte packet length | menu exposes ChaCha20-**Poly1305** only. Add a raw-ChaCha20 host fn, or diverge on framing (breaks byte-faithfulness). Minor. |
| **Interactive handshake** | an inbound read must trigger an outbound wire write (recv peer ellswift ⇒ send garbage-terminator + version packet), plus emit-at-connect | `stream.rs` is a one-way-per-direction obfuscator (`transform_out(app)→wire`, `transform_in(wire)→app`); **there is no channel for inbound-triggered outbound.** `compute_gambit` can't help — it's bound to the TLS genome + boring executor. **Structural.** |

### 7.3 The build: native BIP324 engine + signed `BitcoinGambit`

Because of the interactive-handshake gap, don't run the handshake in the transform. Mirror the native
transports (samizdat / hysteria2 / anytls) — which is also exactly how a flint gambit relates to the
native boring engine:

```
core/src/transport/bitcoin/
  transport.rs  // impl Transport: dial ":8333", run handshake, return BoxedStream.
                //   behind a `bitcoin` feature; ServerSpec-wired like hysteria2/anytls.
  handshake.rs  // enum Bip324State { SendKey, AwaitPeerKey, DeriveKeys, SendTerminator, Ready }
                //   — explicit state machine (spark's stated preference for handshake cores).
  framing.rs    // FSChaCha20Poly1305 packet framing over the live stream.
  gambit.rs     // BitcoinGambit { garbage_len_dist, decoy_policy, mac_spec, shaping } — a NEW genome,
                //   delivered via the reused SignedModule / SignedGambit envelope (Ed25519, versioned).
```

Crypto runs native via the `secp256k1` (ellswift), `chacha20poly1305`, and `hkdf` crates — no
interpreter on the data path. The **gambit** is the signed, per-region opening plan: the Core-matching
garbage-length distribution (§6.1), decoy cadence, the §5.1 keyed-garbage MAC spec, and the §6.1
shaping budget. This *is* the Opening Book model — a BIP324 engine parameterized by a signed gambit,
in place of the boring TLS engine parameterized by a flint gambit.

### 7.4 Build order

1. This design + **ADR 0012**.
2. `BitcoinGambit` genome + reuse the `SignedModule` delivery/verify path.
3. Native `core/src/transport/bitcoin/` (handshake + framing) on `secp256k1` / `chacha20poly1305` /
   `hkdf`; behind a `bitcoin` feature; `ServerSpec`-wired like hysteria2/anytls.
4. Server: `bitcoind` on `:8333` + the keyed-garbage front (tunnel-vs-node fork, §5).
5. Instrumentation: handshake-completion + probe-detection counters (a connection that completes
   BIP324 but fails the keyed-garbage MAC = probe / real-peer signal).

### 7.5 If we later want WASM-swappable *framing*

Close all three gaps: add the secp256k1/ellswift + raw-ChaCha20 host fns, and extend the ABI with a
handshake channel (e.g. `transform_handshake(inbound) -> (outbound_wire, done)`). That's real ABI
work and not worth it for v1 — the stable engine belongs native; the gambit already carries the part
that changes when a region blocks us.

## 8. Open questions

- **Keyed-garbage authenticator** — specified in §5.1; the timing-parity-vs-cache question is
  resolved in §5.2 (byte parity is *insufficient* per Parrot-is-Dead, so we gate access with auth +
  the fresh-ellswift cache rather than perfect a fake — raw-splice is the Parrot-optimal node path).
  Residual limit: probe resistance assumes a credential-less censor (PSK-compromise caveat, §5.2).
- **v2 adoption** — resolved: v2 is the majority of global Bitcoin P2P traffic (Wuille, Feb 2026), so
  v2-only blends fine and no v1 gambit is needed for cover. The v1 framing (§3.2) stays documented only
  as a contingency, not a shipped path.
- **Shaping budget** — framed and grounded in §6.1 (low default; region-tunable escalation vs.
  TSG-class classifiers; pace volume, don't rotate sessions). Open only as a per-region, telemetry-driven
  tuning call, not a design question.
- **Server front: raw-splice vs. terminate-and-relay** — §5.2 settles this in favor of raw-splice
  (probers reach Core's real BIP324 stack, not our reimplementation). Reopen only if a future need to
  shape/relay real-peer traffic is judged to outweigh that probe-resistance advantage.
