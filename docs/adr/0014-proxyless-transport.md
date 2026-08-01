# ADR 0014 — Proxyless transport: reach the destination directly

**Status:** accepted · **Date:** 2026-07-30 · **Supersedes:** none · **Related:** ADR 0006 (opening-gambit shaping), ADR 0011 (dns-tunnel), flint PRs #13–#16

## Context

Every transport spark has routes through *something*: a proxy server, a CDN edge, an authoritative NS.
Each costs infrastructure, and each is a thing a censor can enumerate and block. There is a class of
blocking that needs none of that to defeat:

- **DNS poisoning** — the name resolves to a lie. Defeated by resolving somewhere the censor cannot
  rewrite.
- **SNI/ClientHello classification** — the connection is cut because the first flight is legible.
  Defeated by making the first flight illegible to a stream-reassembling middlebox.

Neither requires an exit hop. The Outline SDK calls this **proxyless** (`x/smart`,
`findDNS × findTLS`): search a declared space of DNS resolvers and TLS wire-shapings until one reaches
the *real destination*. flint PRs #13–#16 ported that search to Rust as `flint-proxyless`, over two
independent axes — a resolver `Kind` (DoH/DoT/plaintext/system) and a `WirePlan` (record fragmentation,
segment splitting, inter-segment jitter).

This ADR records how spark consumes it.

## Decision

Add a `proxyless` feature and a `[transport.proxyless]` transport that dials destinations directly,
using a `(resolver, shaping)` pairing found by `flint_proxyless::find_cached`.

### spark does not terminate TLS

This is the load-bearing decision, and it differs from how flint's own kindling transport uses the same
crate.

`flint_proxyless::dial` completes a **certificate-verified** TLS handshake and returns the TLS stream.
That is correct where flint *is* the client — a kindling config fetch, where flint speaks HTTP/2 over it
itself. It is wrong here. `Transport::dial` must return a **raw byte stream** that the application's own
bytes are spliced into; if spark terminated TLS, the browser's ClientHello would never reach the origin,
end-to-end TLS would be broken, and the transport would have made itself a MITM of its own user.

So spark returns shaped **TCP**. The shaping applies to whatever the application writes first, which for
HTTPS is precisely its ClientHello — the bytes we wanted to shape anyway.

**Authentication is not weakened by this; it moves to where it belongs.** The application verifies the
origin certificate itself, end to end. That is a stronger guarantee than this layer could offer on its
behalf, because it covers the whole path rather than one hop of it.

### Consequence: strategy selection happens out of band

Because spark holds no certificate on the data path, it has no per-flow success oracle. So selection is
separated from use:

| Step | What runs | Cost |
|---|---|---|
| Choose (once per network) | `find_cached` — proves a candidate against **all** test domains with verified handshakes | a search |
| Use (per flow) | resolve via the chosen resolver, protected TCP connect, shape the opening write | one dial |

The winning pairing is memoized behind an `RwLock` (read-locked on the steady path, never held across an
`.await`) and cached per network fingerprint by `flint-proxyless`. `forget()` drops it so a caller that
has observed failure can force a re-search.

This gives flint's two entry points distinct, real consumers: `connect_cached` for kindling (where the
target is its own oracle) and `find_cached` for spark (where nothing on the data path can be).

### The DNS half needs a name to work with

`Transport::dial` receives a `SocketAddr` — the netstack surfaces the address the application *already
resolved*, so there is no name left to un-poison and only the shaping half applies. The resolver half
bites on `dial_addr(Address::Domain)`, which is spark's fake-IP smart-routing path (`[dns] fake_ip` plus
the DoH resolvers in `crate::dns`).

**So proxyless is materially weaker without spark's own DNS in front of it.** An application that
resolved through a poisoned system resolver hands us a bogus address, and shaping cannot rescue a
connection to the wrong host. This is worth stating plainly rather than discovering: the two halves are
independent, and deploying only one gets only one's benefit.

### UDP goes straight out, unshaped

The shaping axis is TCP-segment and TLS-record framing; neither exists for a datagram, and there is no
proxy to relay through. So `dial_udp` is a plain protected socket, identical to `DirectTransport`. A
QUIC/HTTP-3 flow therefore gets un-poisoned DNS where spark resolved the name and no first-flight
obfuscation at all. Documented rather than implied, because a user choosing proxyless for evasion should
know which of their traffic it does not cover.

### A missing feature is an error, not a fallback

With `[transport.proxyless]` configured but the `proxyless` feature absent, `from_config` errors rather
than falling through to the proxy. The user asked for **no exit hop**; quietly giving them one would
misrepresent where their traffic goes. Mirrors anytls/samizdat/wasm.

### Precedence

Proxyless sits last among the configured single transports. Everything above it routes through
something; this deliberately does not, so it should not shadow a configured proxy.

## Scope and non-goals

No exit hop means traffic leaves the user's own address for the real destination. Proxyless defeats
**blocking**, not **observation** — an on-path censor still sees which host is contacted, it just cannot
classify or cut the handshake — and it does nothing against IP-level blackholing, where no resolver or
shaping choice helps.

It is therefore a **reachability** tool, not an anonymity one, and is off by default and separately
selectable rather than a silent substitute for the proxy pool. A user who believes a VPN is carrying
their traffic must not get this instead without asking for it.

## Follow-ups

- ~~**`rules::Action::Proxyless`**~~ **Done** (spark#138) — a distinct routing action, so a ruleset can
  send chosen flows proxyless while the rest use the pool. Deliberately *not* an upgrade of
  `Action::Direct`: in spark "direct" means a plain connection with no tricks, and silently changing
  that would alter the meaning of every existing rule. Landed across `rules::Action`,
  `config::RouteAction`, `matcher::action_index`'s per-action covering arrays, `rules::router`
  (including the `Action → proxy::Decision` mapping), and the `lantern.rs` string mapping.
- ~~**Re-selection needs a signal this layer does not have.**~~ **Partly done.** flint#18 added
  `indicts_resolver`, separating "the resolver failed" from "the name does not resolve", so the
  transport now self-heals in-band: a resolver that is unreachable, times out, or answers unbelievably
  drops the strategy, while NXDOMAIN for a mistyped host does not. That is what made the eviction
  reverted during this PR's review safe to reinstate.
  **Still open: proactive re-selection.** The in-band signal only fires once a flow has already
  failed, so the first flow after a network change still pays for a dead strategy. A control handle
  carrying an explicit network-change notification would re-select before that, and remains worth doing
  on its own merits — `from_config` returning trait objects with no handle is the obstacle.
- ~~**IPv6-only networks cannot complete strategy selection.**~~ **Done upstream** (flint#17). The pool
  entries carry `v6()` addresses and the probe races A/AAAA, so selection completes where only IPv6
  egress exists. One caveat worth keeping: for Quad9 the v6 entry is the *service* address
  `2620:fe::10`, not the resolver hostname's AAAA `2620:fe::fe` — the latter is the "no-block" variant
  and answers differently. Addresses are `dig`-verified only; **live verification on a v6-only network
  is still outstanding**, as no machine here has v6 egress.
- ~~**A missing trust store is indistinguishable from a blocked network.**~~ **Done.** The search reads
  dial failures as evidence *about strategies*, so a process with no CA anchors does not merely fail —
  it drives the search to exhaust every resolver × wire combination, each failing for a reason that has
  nothing to do with any of them, and reports a network that blocks everything. flint#19 added
  `flint_tls::check_default_trust_anchors()`, and `ca_roots.rs` now calls it as a post-condition after
  installing the bundled roots on Android/iOS, so the misconfiguration names itself instead of
  masquerading as censorship. The same work fixed a latent bug here: `ca_roots` honored
  `SSL_CERT_FILE=""` as an operator override and skipped its install, which is the one value that
  guarantees zero anchors — boring treats a present-but-empty variable as the override and never falls
  back to the compiled-in default, which on mobile is empty regardless.
- **`disorder`/TTL shaping** — the last outline primitive not yet ported (`x/disorder` + `x/sockopt`).
  Deprioritized: it is probabilistic (upstream acknowledges a flush race), topology-dependent (TTL=1 only
  desynchronizes a middlebox before the expiry point), and unverifiable in CI without packet capture.
