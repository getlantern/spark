# Phase 1 spec — socket-layer handshake framing/timing + ClientHello anchor capture

Build-ready spec for **ADR 0006 / `handshake-gambit-design.md` Phase 1**: the native, socket-layer
ability to fragment the opening handshake across TCP segments (especially at the **SNI boundary**)
with controllable inter-segment timing — plus a tool to **capture the byte-exact Chrome ClientHello
anchor**. This is Layer **C** of the gambit genome (and a sliver of B), realized as a reusable
primitive that P2's signed config and P3's Path-B plan will both drive. **No genome, no WASM, no CH
content knobs yet** — those are P2/P3.

Why this first: SNI-boundary fragmentation is the single highest-value early-byte evasion (defeats
SNI-keyword DPI), it's executor-agnostic (pure socket-layer), and it needs nothing from the rest of
the system. Buildable now and live-testable against a TLS endpoint.

## Scope

- **In:** a `SegmentShapingStream` socket wrapper; a minimal ClientHello/SNI offset parser; the
  `WirePlan` config type (genome Layer C); wiring into the transport dial path (AnyTLS first); a
  `capture-clienthello` tool + a JA4-drift test.
- **Out (later phases):** CH content knobs (P2), the gambit genome decode + signed envelope (P2),
  Path-B module computing the plan (P3), the byte-level builder (P4), the discovery loop (P5).

## Component 1 — `SegmentShapingStream<S>`

A `tokio` `AsyncRead + AsyncWrite` wrapper around the upstream `TcpStream` that shapes only the
**opening window** (the handshake bytes), then becomes a zero-overhead passthrough.

```rust
// core/src/transport/shaping/mod.rs  (new module)

pub enum SegmentSplit { None, SniBoundary, Explicit(Vec<usize>) }      // absolute byte offsets into the window
pub enum DelaySpec    { None, Fixed(Duration), Jitter { min: Duration, max: Duration } }

/// Genome Layer C (the `wire` object), as a native plan.
pub struct WirePlan {
    pub segment_split: SegmentSplit,
    pub inter_segment_delay: DelaySpec,
    pub tcp_nodelay: bool,           // each split write becomes its own segment (else the kernel coalesces)
    pub first_data_delay: Option<Duration>,
    pub window_len: usize,           // shape only the first N bytes (e.g. ≥ one ClientHello); then passthrough
}

pub struct SegmentShapingStream<S> { /* inner: S, plan, bytes_written: usize, sni_offset: OnceCell<usize>, ... */ }

impl<S: AsyncRead + AsyncWrite + Unpin> SegmentShapingStream<S> {
    pub fn new(inner: S, plan: WirePlan) -> Self;
}
```

Behavior of `poll_write` while `bytes_written < window_len`:
1. On `SniBoundary`, lazily parse the buffer to locate the SNI offset (Component 2) the first time we
   see enough bytes; cache it. Resolve `Explicit`/`SniBoundary` to concrete split points within the
   current write's absolute byte range `[bytes_written, bytes_written + buf.len())`.
2. Write each sub-chunk, **flush** it (with `TCP_NODELAY` set so it leaves as a distinct segment),
   then `sleep` the `inter_segment_delay` before the next sub-chunk.
3. Past `window_len`, hand the buffer straight to `inner` (no parsing, no copy, no delay).

Reads pass through unchanged. `tcp_nodelay` is set on the underlying socket for the window and may be
restored afterward. Cancel-safety: the per-chunk `sleep` is the only extra await; a partial write
resumes from `bytes_written`.

## Component 2 — minimal ClientHello / SNI offset parser

`core/src/transport/shaping/sni.rs`. Pure function, no allocation beyond a slice walk:

```rust
/// Return the absolute byte offset (into the TLS record stream) of the SNI host bytes, or None.
pub fn sni_offset(buf: &[u8]) -> Option<usize>;
```

Walk: TLS record header (`type=22` handshake, version, len) → handshake header (`type=1` ClientHello,
len) → skip legacy_version(2)+random(32)+session_id(u8-len)+cipher_suites(u16-len)+compression(u8-len)
→ extensions(u16-len) → find extension `type=0` (`server_name`) → its `ServerNameList`→`HostName` →
return the offset of the host bytes. Return `None` (⇒ shaper falls back to `Explicit`/no-split) on any
truncation or non-match, so a malformed/absent SNI never breaks the connection. Unit-tested against
the captured anchor (Component 4) and hand-built truncations.

## Component 3 — wiring into the transport

The shaper sits **between the TCP connect and the TLS/relay layer**, so the bytes a TLS library emits
(the ClientHello) get fragmented regardless of which library produced them:

- **AnyTLS (boring2):** in `core/src/transport/anytls/`, wrap the connected `TcpStream` in a
  `SegmentShapingStream` *before* handing it to the boring connector → boring's ClientHello write is
  shaped. (boring is unaware; it writes to a normal `AsyncWrite`.)
- **Plain `TunnelClient`:** wrap the relay socket too (mostly passthrough; can still fragment the first
  bytes). Lower value (no TLS CH) but keeps one code path.
- The `WirePlan` comes, for now, from **static config** (a new `[transport.shaping]` block) — the same
  struct P2 will populate from a signed gambit and P3 from a Path-B plan.

`protected_tcp_connect` already returns the socket; the shaper wraps its result. No change to the
`Transport` trait.

## Component 4 — `capture-clienthello` tool + JA4-drift test

A small bin/test that runs the boring2 AnyTLS connector with the Chrome-137 profile against a target,
**taps the first socket write** (the ClientHello — via a recording `AsyncWrite` wrapper, no network
tricks), and emits:
- the raw CH bytes (hex) → `testdata/anchors/chrome-137.clienthello` (the **anchor template**),
- the computed **JA4** → pinned in a test.

A `#[test]` (or CI job) re-derives JA4 from a fresh capture and asserts it equals the pinned Chrome
JA4 — the **drift check** (generalizing the `/tmp/ja4-check` spike). The anchor file is the fixture
Component 2's parser test reads, and the seed for P2's "deltas over the anchor."

## Verification

- **Unit:** `sni_offset` returns the correct offset on the `chrome-137` anchor and `None` on
  truncations; `SegmentShapingStream` over a recording mock stream splits at the expected offsets with
  the expected delays, and is a byte-exact passthrough past `window_len`.
- **JA4 drift:** the capture test reproduces the pinned Chrome JA4.
- **Live gate (human, sudo — like other spark gates):** point AnyTLS-with-shaping at a TLS endpoint
  (run `openssl s_server`/`socat OPENSSL-LISTEN` on the existing DO box, or any public TLS host) and
  confirm with `sudo tcpdump`/`tshark` on the client that the ClientHello **spans ≥2 segments split at
  the SNI** with the configured inter-segment delay. Record as `docs/...gate` runbook (mirrors the
  M-series live gates). The DO relay (`137.184.47.220`) can host the TLS listener for this.

## Acceptance

`cargo test --workspace` green (new shaping unit tests + JA4 drift); clippy + fmt clean;
`[transport.shaping] segment_split="sni_boundary"` demonstrably fragments the AnyTLS ClientHello at
the SNI under packet capture against the DO endpoint. At that point Layer C is real and reusable, and
P2 (the constrained CH knobs + the genome decode) can build on the same `WirePlan` struct.
