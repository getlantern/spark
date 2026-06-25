# Fronted-meek transport (Shir-o-Khorshid CDN-fronting)

A self-bootstrapping, domain-fronted meek **polling** transport for the Rust
client. Tunnels flows to Lantern's meek-server through a CDN edge the censor
can't block, with **no MITM** and **no server-delivered config required**.

## The model (and what it is NOT)

Pure domain fronting, the Shir-o-Khorshid / Psiphon "CDN Fronting" technique:

```
app flow ─► meek polling client ─► [TLS to a CDN edge IP, benign/empty SNI]
          ─► CDN routes by the encrypted Host header ─► Lantern meek-server
          ─► microsocks (SOCKS5) ─► target
```

The client opens an ordinary Chrome-fingerprinted TLS connection to a CDN edge IP
(Akamai/CloudFront/Aliyun), presents an **empty or benign SNI**, and carries the
real meek host in the **encrypted HTTP Host header**. The CDN re-originates to the
meek property → our server → SOCKS5 → the internet ("the Psiphon trick": front to
*our* server, so any destination is reachable, not just the front's own domain).

This is **not** `patterniha/MITM-DomainFronting`: there is no local root CA, no
certificate generation, and the user's own TLS is never intercepted. Cert
verification (against `verify_hostname`, never the decoy SNI) only guards against a
third party impersonating the edge.

## Self-bootstrapping (the unique property)

With no server front list, the transport discovers working edges **from the
user's own network** (`flint_fronted::scanner`):

- **Akamai (primary):** resolve `a248.e.akamai.net` (+ alternates) through the
  **system/ISP resolver** (`SystemResolver`, `getaddrinfo`). This is the
  load-bearing trick — a censor returns truthful, geo-local Akamai edge IPs
  because blocking Akamai breaks domestic banking/government sites. flint's other
  resolver is DoH, which would bypass exactly the local answers we want.
- **CloudFront / Aliyun:** sample IPs from embedded prefix lists, weighted by
  prefix size (Aliyun = Alibaba Cloud international CDN ranges).

Candidates are **raced** (`dial_fronts`); the race doubles as the probe — a dead
or wrong-CDN edge just loses. The **winning front is cached** so later flows skip
the scan. A server-provided front list, when present, is only an accelerator.

> Note: the currently-deployed meek endpoint (`meek.dsa.akamai.getiantem.org`) is
> an **Akamai** property, so only Akamai candidates route to it today; CloudFront/
> Aliyun candidates lose the race. They're scanned for forward-compat with
> multi-CDN meek deployments.

## HTTP/1.1 and HTTP/2

The meek wire protocol (ported from lantern-box `protocol/meek` PR #282) is
discrete `POST`s, each keyed by `X-Session-Id` and a monotonic `X-Meek-Seq` the
server dedupes (replaying the buffered response for a repeated seq) so a lost
request/response is safe to retry without gap or duplication. A 256 KB body cap is
negotiated via `X-Meek-Max-Body`.

Both transports are implemented: **h2** (a fresh multiplexed stream per poll) and
**h1** (one keep-alive connection, sequential POSTs). The deployed Akamai path
negotiates **HTTP/1.1**, so that is the default; `http_version = "h2"` selects h2
for endpoints whose CDN re-originates h2.

**Follow-up:** `flint_dial::TlsStream` doesn't surface the negotiated ALPN (it's a
blanket-impl trait), so the client can't yet auto-select h1/h2 per connection.
Threading the selected ALPN out of the boring stream would let each front use its
negotiated protocol; until then the protocol is chosen by config (default h1).

## Where it lives

- **flint** (`crates/flint-fronted`, branch `fisk/fronted-meek`):
  - `meek_poll` — the polling client (`MeekPollConn`: AsyncRead+AsyncWrite),
    h1+h2 backends, retry/seq, the `FrontedMeekPollDialer` glue, `open_meek_poll`.
  - `sys_dns` — `SystemResolver` (the local-DNS `FrontResolver`).
  - `scanner` — Akamai local-DNS + CloudFront/Aliyun prefix sampling, ranked probe.
  - `socks5` — minimal SOCKS5 client `CONNECT` over the tunnel.
  - `dial_fronts` — race scanner-discovered fronts (no `Config` needed).
- **spark** (`core/src/transport/fronted_meek.rs`): `FrontedMeekTransport`
  (`Transport`; `UdpTransport` reports unsupported). Config `FrontedMeekConfig`
  (all fields optional), `ServerSpec::FrontedMeek`, feature `fronted-meek`.

## Configuration

```toml
# Minimal — self-bootstraps to the default meek endpoint:
[transport.fronted_meek]

# Or explicit:
[transport.fronted_meek]
meek_host = "meek.dsa.akamai.getiantem.org"
country_code = "ir"     # SNI selection
http_version = "h1"     # or "h2"
```

## Validation

- Hermetic (flint, no network): meek polling over real h2 incl. multi-poll
  reassembly and **retry-replay under dropped responses with no gap/dup**; SOCKS5
  framing; scanner candidate generation + ranking for all three CDNs; the full
  FrontedConnection→meek glue.
- **Live (passing):** dial a real Akamai edge (system-resolved) → meek over h1 →
  the **deployed** meek-server → SOCKS5 → `example.com` → 200. See
  `flint/crates/flint-fronted/tests/meek_live.rs`.

## Known limitations / follow-ups

1. **ALPN auto-select** (above) — pick h1/h2 per connection from the negotiated
   protocol instead of from config.
2. **Socket protection:** the front TLS dial happens inside `flint`, which doesn't
   take spark's `SocketProtector`, so meek's own dials aren't pinned to the
   physical interface yet (a routing-loop risk on macOS forwarding).
3. **Cache persistence:** the winning front is cached in-memory per process;
   persisting it (and a working-front list) across restarts would cut cold-start
   latency, mirroring radiance's on-disk scanner cache.
4. **Build patch:** spark's workspace `Cargo.toml` currently `[patch]`es flint to a
   local checkout. Replace with a flint rev bump once the flint branch merges.
