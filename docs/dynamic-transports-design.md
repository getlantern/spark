# Design: Dynamically-loaded transports (WATER, and the alternatives)

- **Status:** Proposed / exploration — 2026-06-17. No code. A decision doc for *how* spark should
  let transports be delivered/updated independently of client releases. Promote the chosen tier(s)
  to an ADR when we commit to building.
- **Scope:** A `Transport` (and `UdpTransport`) whose *logic* is data — delivered out-of-band over
  the existing config/fronting channel, signed, and loaded at runtime — so a blocked protocol can be
  answered in hours instead of an app-store-release cycle. Does not change the proxy core, netstack,
  or forwarder: a dynamic transport is just another impl behind the existing trait seam.
- **Grounding:** local `getlantern/water` (Go/wazero), `refraction-networking/water` (water-rs,
  Rust/wasmtime), `getlantern/lantern-water` (delivery layer); FOCI 2024 *Just add WATER*
  (`2024-chi-just`); the circumvention corpus; and a research-agent synthesis (2026-06-17).

## 1. Why — and why the *release pipeline itself* is the target

Censorship is adversarial and fast. When a protocol is blocked, the only question that matters is
"hours or weeks to ship a counter?" Baking transports into the client makes the **release pipeline a
censorship chokepoint**: app-store review is days-to-weeks, globally observable, and censors race it.
Dynamic transports collapse the response time, and as a bonus: keep the binary lean, let you target
transports per-region/per-user without a release, and mean cracking one client binary doesn't reveal
every transport you ship. NDSS 2024 (`2024-wails-precisely`, §VI) makes the academic case directly —
it recommends "programmable or polymorphic protocols (Geneva, WATER/WASM, Marionette)" as *the*
counter to host-based ML traffic classification.

## 2. Where it fits spark (the easy part)

Same seam we used for the system stack and AnyTLS: `Transport::dial(target) -> BoxedStream`. A dynamic
transport is a `Transport` impl that delegates to a loaded module/spec. The netstack, forwarder, and
every other transport are untouched. **All the hard questions live inside the loading mechanism**,
and they are dominated by three constraints spark already lives under (§4).

> **The performance escape hatch, stated once up front:** a transport's *bulk* cost is the crypto
> (TLS/AEAD); its *blockable* part is the handshake choreography + framing/padding. Keep the heavy,
> stable crypto **native** (the module calls a host-provided primitive) and let only the light,
> frequently-changing control logic be dynamic. "Is WASM fast enough?" then becomes "we don't run
> AES in the sandbox — only the part that changes when we get blocked."

## 3. WATER, precisely (verified)

A transport is a `.wasm` module (a "WATM"). A thin host loads it and exposes a `net.Conn`-like
surface; the module does the handshake/framing/obfuscation.

- **ABI** (from `getlantern/water/transport/{v0,v1}`): the module *exports* `_water_init`,
  `_water_dial`, `_water_accept`, `_water_associate`, `_water_worker`, `_water_cancel_with`,
  `_water_v`, plus WASI `_start`/`_initialize`. The host *imports* `water_dial`, `water_dial_fixed`,
  `water_accept` — the module never touches a raw socket; it asks the host, which hands back a
  host-chosen WASI fd (`InsertConn`/`InsertListener`, `water/core.go`). Data crosses via WASI
  preview1 + linear-memory copies through "virtual socket pairs."
- **Capability surface** (`water/wazero_config.go`, `core.go`): WASI preview1, walltime/nanotime/
  nanosleep, `crypto/rand`, an in-memory `/conf/watm.cfg`, and host I/O *only* via those three
  functions. No ambient filesystem, no socket-creation, no `mmap`-exec. This narrow surface is worth
  emulating regardless of which approach we pick.
- **Runtimes:** Go (`getlantern/water`, `refraction-networking/water`) → **wazero**, pure-Go,
  zero-CGO, with a JIT *Compiler* mode (amd64/arm64) and an *Interpreter* fallback everywhere.
  Rust (`refraction-networking/water-rs`) → **wasmtime 17 + Cranelift** (JIT/AOT). **wasmtime 17 has
  no interpreter at all** — its portable interpreter (Pulley) only landed in wasmtime ≥29/30 (2025).
- **Authoring:** TinyGo (not stock Go) or Rust → `wasm32-wasi`. The FOCI shadowsocks WATM was ~417
  LOC. Delivery (`lantern-water`): HTTPS **and BitTorrent magnet** (so the module itself can be
  fetched over a censorship-resistant channel), 7-day cache GC, **SHA-256 integrity only — no
  signature** (a real gap, §7).

### 3.1 The real numbers (vs the marketing)

From `getlantern/water/BENCHMARKS.md` (M4 Pro, localhost):

| metric (1KB echo) | raw TCP | native shadowsocks | WATER + SS (wasm) |
|---|---|---|---|
| throughput | 62.9 MB/s | 15.3 MB/s | **1.64 MB/s** |
| latency/op | 16 µs | 67 µs | **626 µs** |
| allocs/op | 0 | 0 | **30** |
| conn setup | — | — | **4.3 ms, ~1.7 MB, 6231 allocs** |

Pure-runtime overhead ≈ **15–22× TCP**. **But over a real 37 ms link: 38.4 ms vs 37.1 ms native =
+3.5%.** The honest framing: **WASM overhead is irrelevant for RTT-bound traffic and brutal for
throughput-bound traffic**, with a per-connection ceiling around ~1.6 MB/s on a fast desktop core
(worse on mobile, worse again in interpreter mode).

## 4. The three constraints that decide everything

1. **iOS forbids non-Apple JIT (W^X).** Third-party apps can't make executable pages; true JIT needs
   the `dynamic-codesigning` entitlement Apple keeps for JavaScriptCore. So **wasmtime/Cranelift
   won't run on iOS at all** (and water-rs@17 has no interpreter to fall back to). wazero
   auto-degrades to its interpreter on iOS. A downloaded native `.so` via `dlopen` is doubly dead
   (no exec pages + App-Store policy).
2. **Lean, no-C-preferred, perf-critical.** `wasmtime + Cranelift ≈ 15–20 MB` linked into the binary
   — **5–7× spark's entire <3 MB target**. The only way down (no-default-features ≈ 2.1 MB) removes
   the compiler and runs only *precompiled* `.cwasm`, which **destroys the dynamic-delivery value**.
   There is no configuration of water-rs that is both lean and dynamically-loadable. (wazero is free
   because it's pure-Go — which is exactly why getlantern's mobile WATER path is Go, not Rust.)
3. **Network-delivered code is hostile input aimed at a process with full network access + the
   tunnel plaintext.** Whatever the mechanism: signed + key-pinned before load, sandboxed, and
   capability-scoped (§7).

## 5. The design-space spectrum

Most expressive / most dangerous → least. (Ratings relative; sizes/perf from §3 + research.)

| approach | expressiveness | runtime size | data-path perf | sandbox | iOS | Android | decouples from release? |
|---|---|---|---|---|---|---|---|
| **a. downloaded native `.so`** | full | ~0 | native | ❌ RCE | ❌ banned | ❌ Play bans DL'd `.so` | desktop only |
| **b. WASM, JIT (wasmtime)** | full | **~15–20 MB** | ~10× (negligible/RTT) | ✅ | ❌ no JIT | ⚠ | full (desktop/Android) |
| **c. WASM, interpreted (`wasmi`/wazero-interp)** | full | smaller, pure-Rust | ~40–100× (interp×wasm) | ✅ | ✅ runs | ✅ (interp carve-out) | full (desktop/Android), iOS policy-grey |
| **d. purpose-built transport DSL / bytecode VM** | medium (handshakes, framing, mimicry, state machines) | **tiny (you own it)** | native if hot path stays native | ✅ by construction | ✅ | ✅ | params+composition+novel *wire formats*; not new primitives |
| **e. config-composition of native primitives** | low–medium (recombinations) | ~0 | native | ✅ no foreign code | ✅ trivially | ✅ | **partial** — params/composition only |

The spectrum's spine: **expressiveness + decoupling rise a→c; size + safety + mobile-viability rise
c→e.** (d) and (e) are the engineering sweet spot for a lean Rust client; the agent's independent
read reached the same conclusion.

## 6. Prior art (delivery model is the column that matters)

| system | logic shipped as | delivery / update | sandbox |
|---|---|---|---|
| IETF PT 2.x, obfs4/`lyrebird`, Cloak | native binary | app release | OS process |
| Snowflake | native; *rendezvous* is the dynamic part | brokered discovery (not code) | process |
| **Marionette** (`2015-dyer-marionette`) | **DSL** (prob. state machines + CFG templates) | spec, server-updatable | interpreter |
| **FTE / libFTE** (`2013-dyer-protocol`,`2014-luchaup-libfte`) | regex format strings | config | native lib |
| **Proteus** (`2023-wails-proteus`) | **safety-bounded DSL** (PSF) | spec files, **parallel PSFs** | bounded DSL VM |
| **Geneva** | **DSL** (tiny strategy string) | a few bytes, pushable | native engine |
| **WATER** (`2024-chi-just`) | **WASM** | `.wasm` over HTTPS/magnet | WASM + WASI |

Lessons that bear directly on spark:
- **Proteus**: a *safety-bounded DSL* expressed a full Noise NK handshake in **<4 hours**, and runs
  **multiple specs in parallel** server-side — solving flag-day upgrades *without a version field on
  the wire* (a candidate is eliminated by parse failure). Its known gap — un-normalized error
  responses → active-prober-distinguishable — is the reminder that a delivered spec must include the
  probe-resistant fallback, not assume it.
- **Geneva**: the leanest "dynamic" point on the map — ship a *few-byte strategy string*
  (`[TCP:flags:PA]-fragment{tcp:4:True}-`), native engine interprets it. Lantern's own **Samizdat**
  already embeds Geneva-style SNI-boundary fragmentation (corpus `samizdat`).
- **obfs4 is now `blocked-broadly`** (GFW fully-encrypted detection, USENIX Sec 2023): the cautionary
  tale that "look-like-nothing" + native + release-coupled is the anti-pattern — exactly what dynamic
  transports exist to escape.
- **Most real censor escalations are answered by *parameter* changes** (SNI fragmentation, a 6-byte
  printable-ASCII preamble to defeat the GFW entropy test — `2023-wails-proteus` §3.2; uTLS
  fingerprint rotation — Snowflake's 2026 DTLS-fingerprint scramble), not new protocols. This is the
  empirical case for putting tier-1 (config-composition) first.

## 7. Security / threat model for delivered transport logic

The weakest part of the existing (lantern-water) implementation, and where spark must do better:

- **Integrity ≠ authenticity (current gap).** lantern-water checks a **SHA-256** of the module
  (`downloader/downloader.go:93`) but does **no signature check** — if the channel that serves the
  module also serves the hash, an attacker substitutes both. **spark must require a detached
  signature (Ed25519) over the module/spec, verified against a public key pinned in the signed
  binary, plus a monotonic version counter (anti-rollback).** Authenticity roots in the shipped app,
  never in the wire.
- **Runtime as attack surface.** Whatever loads the blob parses untrusted input (a `.wasm`
  validator/compiler; or our DSL parser). wasmtime's *Winch* baseline compiler had a 2026 sandbox
  escape — "don't run untrusted modules through immature codegen." A small, hand-audited DSL VM whose
  parser we fully own is *less* surface than a general WASM runtime, and pure-Rust beats C either way.
  (CLAUDE.md already treats the vendored netstack as attack surface "because it parses untrusted
  packets" — a downloaded transport runtime is the same class, larger.)
- **The transport sees tunnel plaintext → exfiltration.** Mitigation = capability scoping: hand the
  module exactly *one* host-chosen upstream fd (WATER's `InsertConn` model), forbid a second egress,
  keep long-term secrets out of the module (CLAUDE.md already mandates secrets stay privileged-side).
  A DSL VM can go further — expose *no* dial/file opcodes at all, only bytes-in/bytes-out + crypto/
  format primitives, so the module *physically cannot* reach a second destination.

## 8. Recommendation — a two-tier strategy, not "WASM yes/no"

**Full WASM via water-rs is the wrong default for spark**, on concrete grounds: size disqualifies it
(15–20 MB ≫ budget; the lean build can't load dynamically), iOS is a double wall (no JIT + Guideline
2.5.2 policy risk on downloaded modules that add a *new* protocol — defensible reading, not
adjudicated), and the expressiveness it buys is mostly unneeded. Instead:

- **Tier 1 — config-composition of native primitives (build first).** Ship audited Rust building
  blocks — uTLS-style ClientHello fingerprints, a post-handshake padding/timing shaper
  (`2025-pereira-extended`), Geneva-style fragmentation strings, byte-prefix/preamble, framing, H2
  multiplex, TLS-record framing — composed by a **signed, versioned config**. Leanest (~0 size),
  native speed, fully mobile-store-compliant, cleanest security (no foreign code), and a direct
  extension of what spark *already does* (AnyTLS adopts a server-pushed padding scheme via
  `cmdUpdatePaddingScheme`, carries a Chrome fingerprint profile). This covers the ~80% of real
  censor responses that are recombinations/parameter tweaks.
- **Tier 2 — `wasmi` (interpreted WASM) as the full-logic escape hatch.** When recombination isn't
  enough (a genuinely new wire format / Turing-complete logic), load a WASM module run by **`wasmi`**
  — a pure-Rust, no-JIT, iOS-safe interpreter. Transports are written in real Rust/Go (→`wasm32`)
  with real libraries; bulk crypto/copy stays **native** via host functions (interpret only the
  control path — §8.1 shows why this is mandatory). Capability surface as narrow as WATER's
  (bytes-in/bytes-out + crypto/format host fns, no second egress). Run multiple modules in parallel
  for flag-day-free upgrades (the Proteus lesson). **The §8.1 micro-bench picked this over the
  alternatives on measured size + speed.**
  - *A purpose-built bytecode VM / transport DSL* (Proteus/Marionette lineage) remains a fallback
    **only if** you need to beat `wasmi`'s +0.84 MB or want a sandbox-by-construction parser you fully
    own — but you'd design+maintain an ISA and cap expressiveness, and `wasmi` is already small.
  - *Embedded scripting interpreters (Rhai/Rune)* are **dominated** for this use — measured larger
    *and* slower than `wasmi`, and you'd write transports in a niche scripting language (§8.1).
  - `wasmtime` (JIT, ~15–20 MB, iOS-dead) is never linked into the lean Rust core; getlantern's
    Go/wazero WATER path stays an option only where a Go runtime already exists.

Honest decoupling limits: tier 1 decouples *parameters + composition* from releases; tier 2 adds
*novel wire formats*; neither decouples a genuinely new *primitive* (a new AEAD, a new substrate) —
that still needs a client release. That's an acceptable line: empirically, new primitives are rare
and new *compositions/formats* are the norm.

### 8.1 Measured: tier-2 runtime micro-bench (2026-06-17)

Throwaway spike (`/tmp/tr-spike`, M-series mac, spark's release profile: `opt-level=3`/fat-LTO/
strip/panic=abort). A framing op (`[u16 BE len][bytes ^ key]`) run in each runtime vs a native
baseline. "Control-op" = an 8-byte header (representative — a few per connection); "record" = a
1500-byte buffer pushed *through* the interpreter (the anti-pattern, shown to quantify it).

| runtime | binary-size contribution | control-op latency | record (bytes-through-interp) |
|---|---|---|---|
| native baseline | — | 3 ns | 2823 MB/s |
| **`wasmi`** | **+0.84 MB** | **103 ns** | 99 MB/s |
| `rhai` | +1.55 MB | 1840 ns | 7.3 MB/s |
| `rune` | +2.19 MB | 1367 ns | 9.0 MB/s |

Conclusions: **`wasmi` is both the leanest and the fastest interpreted option** (~13–18× quicker
control-path than the scripting languages, and the smallest by ~0.7–1.4 MB) — and ~1/20th of
`wasmtime`'s 15–20 MB. All three are single-MB-class, so any fits the relaxed budget; `wasmi` simply
wins. The record column makes the design rule **measured, not asserted**: even `wasmi` is 28× slower
than native for bulk bytes (rhai/rune ~300×) → **never run bulk data through the interpreter; keep
crypto/copy native and interpret only control logic.** Caveats: Rune used `with_default_modules` +
int-array marshalling (so its size + perf are upper bounds); these are fast-desktop numbers, but the
ranking and the sub-µs control-path latencies (negligible vs network RTT) hold on any platform. The
delivered `.wasm` for a real transport is ~130–590 KB (research §1) — the over-the-wire payload, fine.

### 8.2 Runtime vs ABI — WATER-compatible, or a new ABI? (a separate axis)

Picking `wasmi` (§8.1) decides the *runtime*, not the *ABI*. They're orthogonal:

- **wasm/WASI level:** any compliant `wasm32-wasi` module runs on `wasmi` + `wasmi_wasi` — independent
  of WATER.
- **"WATER-compatible"** means implementing WATER's **host ABI**: the module imports
  `water_dial`/`water_accept`/`water_dial_fixed` and exports `_water_init`/`_water_dial`/
  `_water_accept`/`_water_associate`/`_water_worker`/`_water_cancel_with`/`_water_v`, over WASI
  preview1. `wasmi` gives the engine, **not** that ABI — and **no wasmi-based WATER host exists**
  (`water-rs`'s host is wasmtime; `getlantern/water` + `refraction-networking/water` are both
  Go/wazero — verified locally). So choosing `wasmi` means *either*:

| | **Path A: WATER ABI on `wasmi`** | **Path B: a new spark ABI on `wasmi`** |
|---|---|---|
| load existing WATMs / use the `watm` guest SDKs | ✅ | ❌ (own SDK) |
| **write a transport once, run it on lantern's WATER *and* spark** | ✅ (the strategic win for a getlantern project) | ❌ |
| WASI dependency / capability surface | inherits WASI (`wasmi_wasi`, **beta**); wider, narrowable via `InsertConn` | none — expose only bytes-in/out + native crypto (tightest sandbox) |
| host work | build/port a **wasmi WATER host** (none exists yet) | a thin bespoke host you fully own |

The pull toward **Path A** isn't loading *existing* modules (spark's transports are spark's) — it's
that spark is a getlantern project and **lantern already runs WATER (Go/wazero)**, so an ABI-compatible
spark lets the org author a transport *once* and run it on both clients instead of maintaining two
transport stacks. That's an ABI decision, fully independent of keeping the runtime lean (`wasmi`, not
`wasmtime`).

**Recommendation: target WATER ABI-compatibility on `wasmi`**, gated on three de-risks before
committing: (1) does `water-rs` abstract its runtime (→ contribute a `wasmi` backend upstream) or is
it wasmtime-wired (→ write a thin fresh wasmi WATER host)? — needs fetching `water-rs` (not local);
(2) `wasmi_wasi` (2.0.0-beta) maturity for the WASI subset WATMs use (`fd_read`/`fd_write`/`fd_close`/
clocks/`random`); (3) scope capabilities via `InsertConn` (host pre-dials the *protected* upstream,
hands the module one fd) rather than module-driven `water_dial(target)`. If any is too costly, fall
back to **Path B**. (Aside: upgrading `water-rs` to wasmtime ≥30 + the Pulley interpreter also yields
a no-JIT/iOS-safe WATER, but Pulley is an *addition* to wasmtime — it keeps the 15–20 MB and still
fails the lean bar; `wasmi` is the only lean path, which is why the ABI must be ported to it.)

## 9. Platform matrix

| platform | tier 1 (config) | tier 2 (`wasmi`, interpreted WASM) |
|---|---|---|
| Linux/macOS desktop | ✅ | ✅ download + run |
| Android | ✅ | ✅ download + run (Play interpreter carve-out + bundled runtime) |
| iOS | ✅ | runs (pure interpreter, **no JIT**), but **bundle modules** — *downloading* a new module that adds a protocol is App-Store 2.5.2-grey |

## 10. Open questions / what to prototype first

1. **Tier-1 schema** against the `Transport` trait: a typed, signed pipeline spec
   (`[fingerprint, framing, padding, prefix, fragmentation, mux]`) composing existing/near-existing
   native blocks. Start from the AnyTLS padding-scheme precedent.
2. **Signing + delivery**: Ed25519 detached sig + pinned key + version counter, over spark's config
   channel (reuse fronted/kindling); decide HTTPS-only vs adding a magnet/fronted fallback like
   lantern-water.
3. **Tier-2 host-function ABI** (runtime decided: `wasmi`, per §8.1). Design the narrow capability
   surface the module imports — `read`/`write` on the single host-chosen upstream fd, native crypto
   (AEAD/hash/`rand`), framing/format helpers, `sleep` — and *nothing* that reaches a second egress
   or the filesystem (mirror WATER's surface). The bytes-through-interpreter penalty (§8.1) makes
   "bulk via native host fns, control-path in wasm" a hard ABI requirement, not a guideline. A
   bespoke bytecode VM is revisited only if `wasmi`'s +0.84 MB ever becomes the binding constraint.
4. **Probe resistance is part of the delivered spec** (Proteus's lesson) — normalized errors /
   fail-open-to-a-real-service must be expressible and tested, not assumed.

## References

- Local: `getlantern/water/{BENCHMARKS.md,core.go,wazero_config.go,transport/v0,transport/v1}`,
  `getlantern/lantern-water/{downloader,version_control}`, `refraction-networking/water[-rs]`.
- Papers (corpus): `2024-chi-just` (FOCI 2024 *Just add WATER*), `2024-wails-precisely` (NDSS 2024),
  `2023-wails-proteus` (FOCI 2023), `2015-dyer-marionette`, `2013-dyer-protocol`,
  `2014-luchaup-libfte`, `2025-pereira-extended`; corpus entries `obfs4`, `snowflake`, `samizdat`.
- spark: `core/src/transport/` (the trait seam + the AnyTLS server-pushed-padding precedent),
  `docs/adr/0001-chrome-mimicry-tls-backend.md`.
