# Design: Dynamically-loaded transports (WATER, and the alternatives)

- **Status:** Accepted — 2026-06-17, recorded in `docs/adr/0003-dynamic-transports.md` (Tier 1 first;
  Tier 2 WATER-on-wasmi prototype next). This doc is the analysis behind that ADR. No code yet.
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
  — a pure-Rust, no-JIT, iOS-safe interpreter, the measured leanest+fastest interpreted option (§8.1).
  Bulk crypto/copy stays **native** via host functions (interpret only the control path — §8.1 shows
  why this is mandatory). The **ABI** is a separate axis from the runtime (§8.2):
  - **Path B — a spark-specific minimal ABI (PRIMARY, 2026-06-17).** The module is a pure
    byte-transform; the **host owns both sockets** and the module imports only native-crypto/entropy
    host fns — no WASI, no network capability (tightest sandbox, leanest: bare `wasmi` ~+0.84 MB,
    11 KB modules). Chosen as primary because WATER-ecosystem compat (its only real advantage) was
    de-prioritized (Go/WATER reuse is "nice-to-have, not widely used atm"). **Proven end-to-end —
    §8.4.**
  - *Path A — WATER-ABI-compatible host on `wasmi`* — **optional / deferred.** Fully de-risked
    (mechanism proven §8.3; both v0+v1 WATMs load on wasmi §8.4) so the door is open cheaply if
    Go-ecosystem reuse ever becomes a driver — but it pulls a WASI stack + the `_water_*`
    choreography for compat we don't currently need.
  - *A purpose-built bytecode VM / transport DSL* (Proteus/Marionette lineage): fallback only if you
    need a sandbox-by-construction parser you fully own; `wasmi` is already small.
  - *Embedded scripting interpreters (Rhai/Rune)* are **dominated** (measured larger + slower, §8.1).
  - `wasmtime` (JIT, ~15–20 MB, iOS-dead) is never linked into the lean Rust core.

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

**Recommendation (updated 2026-06-17): Path B is primary; WATER-ABI-compat (Path A) is optional/
deferred.** The decisive input: Go/WATER-ecosystem reuse — Path A's *only* real advantage — is a
nice-to-have, not a driver ("not used widely atm"). Without it, paying WATER's WASI stack +
`_water_*` choreography buys little, so the lean, tight **Path B** wins. Path A is nonetheless fully
de-risked below, so it can be added cheaply later if Go-ecosystem reuse ever becomes a driver. The
Path A de-risk record (kept for that contingency):

1. **water-rs runtime abstraction — RESOLVED (2026-06-17, inspected the clone).** *No abstraction* —
   `water-rs` is hard-wired to `wasmtime 17` (`wasmtime`/`wasmtime-wasi`/`wasi-common` 17.0.0, no
   runtime feature). Its traits (`WATERStreamTrait`/`Listener`/`Relay`) abstract the *transport
   role*, not the engine. But the `wasmtime::` coupling is localized to **4 files** — `core.rs`
   (Engine/Store/Linker/Module + WASI setup, ~1:1 to wasmi) and `v0/v1/funcs.rs` (host fns via
   `linker.func_wrap(... Caller<Host> ...)`, the same pattern wasmi has). Conclusion: **don't port
   water-rs** (stale: wasmtime 17 / 0.1.0, carries v0+v1+listener+relay+threads spark doesn't need) —
   **write a focused fresh wasmi host for just the v1 dialer/stream ABI**, ABI-compatible (loads the
   same WATMs, preserves write-once-run-on-lantern). Size: bare `wasmi` was +0.84 MB (§8.1), but
   Path A also pulls `wasmi_wasi` + `wasi-common` + `cap-std` + `wiggle` (WATER needs WASI) → several
   MB, still **≪ wasmtime's 15–20 MB** (precise number = a quick build-and-measure). A no-WASI
   spark-specific ABI (Path B) is the one that stays near +0.84 MB.
2. **THE crux — `wasmi_wasi` custom-fd insertion — RESOLVED YES (2026-06-17, inspected the crate).**
   `wasmi_wasi 2.0.0-beta.2` is built on **`wasi-common` v36** (+ `cap-std`) — the *same* WASI crate
   `water-rs` uses (at v17). It re-exports `wasi_common::{WasiCtx, WasiDir, WasiFile}`, and
   `wasi-common` v36 has `WasiCtx::push_file(...)`, the `WasiFile` trait, and
   `TcpStream::from_cap_std(...)` — i.e. **exactly** WATER's `Socket::from(tcp)` → `push_file` → guest
   fd, *plus* a `tokio` variant (async-backed WASI, fits spark). So the wasmtime "lock-in" was really
   a `wasi-common` feature, and `wasmi_wasi`/`wasmtime-wasi` are siblings over the same crate → the
   port is **adaptation, not reinvention**: engine 1:1, host fns via `wasmi::Linker::func_wrap`, data
   path via `wasmi_wasi` `push_file`. Residual frictions: `wasi-common` 17→36 API drift (adapt
   water-rs's host code, don't copy), and `wasmi_wasi` is `2.0.0-beta` (pin carefully). **Path A is
   de-risked.**
3. **Capability scoping** via the host pre-dialing the *protected* upstream and inserting one fd
   (the `InsertConn`/dialer path), rather than module-driven `water_dial(target)` — narrows WATER's
   surface to spark's threat model.

If (2) proves too costly, fall back to **Path B** (a spark-specific minimal ABI — no WASI, host fns
only). (Aside: upgrading `water-rs` to wasmtime ≥30 + the Pulley interpreter also yields
a no-JIT/iOS-safe WATER, but Pulley is an *addition* to wasmtime — it keeps the 15–20 MB and still
fails the lean bar; `wasmi` is the only lean path, which is why the ABI must be ported to it.)

### 8.3 Prototype — PROVEN end-to-end (2026-06-17, `/tmp/wt-proto`)

A minimal `wasmi` + `wasmi_wasi` host inserted a real host TCP socket as a guest WASI **fd 3**; a
`wasm32-wasip1` reactor guest did `fd_write`+`fd_read` on it; the host's echo server received the
bytes and the guest read them back → **PASS**. This makes the de-risked mechanism (WATER's "host owns
the socket, guest does WASI fd I/O on it") *empirical* on the lean runtime — not just inferred.

The working API recipe (pin `wasmi`/`cap-std` to `wasmi_wasi`'s exact versions — shared engine +
cap-std types):
```rust
// host (wasmi = wasmi_wasi = "=2.0.0-beta.2", cap-std = "=3.4.5"):
let mut linker: Linker<WasiCtx> = Linker::new(&engine);
wasmi_wasi::add_to_linker(&mut linker, |ctx: &mut WasiCtx| ctx)?;     // = add_wasi_snapshot_preview1
let wasi = wasmi_wasi::sync::WasiCtxBuilder::new().inherit_stdio().build();
let cap = cap_std::net::TcpStream::from_std(upstream_tcp);            // the protected upstream dial
let fd  = wasi.push_file(Box::new(wasmi_wasi::sync::net::TcpStream::from_cap_std(cap)),
                         wasmi_wasi::wasi_common::file::FileAccessMode::all())?;  // -> guest fd 3
let inst = linker.instantiate_and_start(&mut store, &module)?;        // reactor: no start section
inst.get_typed_func::<(),()>(&store, "_initialize").ok().map(|f| f.call(&mut store, ()));
let code = inst.get_typed_func::<(),i32>(&store, "run")?.call(&mut store, ())?;
```
```rust
// guest (cdylib, wasm32-wasip1): a reactor exporting run() that does fd I/O on the inserted fd.
#[no_mangle] pub extern "C" fn run() -> i32 { /* File::from_raw_fd(3); write/read */ }
```

Scope of the proof + what's next: this validates the **mechanism** (socket-as-guest-fd on
wasmi+wasmi_wasi, sync). It is **not yet** the full WATER v1 ABI (it uses a custom `run` export +
fd-3-by-convention, not WATER's `_water_dial`/`water_dial` host fns), nor async. Next increments:
(1) the WATER v1 ABI host fns → load a real WATM; (2) the `wasi-common` tokio variant for async I/O;
(3) wire into spark's `Transport` (host pre-dials the protected upstream, inserts the fd) + Ed25519
module signing. The PoC lives in `/tmp/wt-proto` (throwaway; the recipe above is the durable artifact).

### 8.4 Path B prototype — PROVEN (2026-06-17, `/tmp/pathb-proto`); WATER ABIs enumerated

**Both real WATMs load on wasmi.** Enumerated the real ecosystem modules from `water-rs/tests`:
`plain.wasm` (v0; exports `_water_init`/`_water_dial`/`_water_worker`/`_water_v0`; imports
`env::host_dial`/`host_defer`/`host_accept` + a WASI subset) and `echo_client.wasm` (v1; exports
`_water_init`/`_water_dial`/`_water_read`/`_water_write`/`_water_set_inbound`/`_water_set_outbound`/
`_water_v1`; imports `env::connect_tcp`/`create_listen` + WASI). wasmi parsed both → Path A's ABI is
characterized and provably loadable.

**Path B (the chosen primary) is proven end-to-end on bare `wasmi`.** An 11 KB no-WASI transform
module: exports `alloc`/`transform_out`/`transform_in`, imports only `env::host_rand` (its entire
capability surface — no WASI, no network). The host owns the sockets and shuttles bytes through the
module; app → `transform_out` → wire (transformed, key-prefixed) → upstream echo → `transform_in` →
recovered == app. **PASS.** This is leaner than WATER on every axis (11 KB vs 130 KB–2 MB modules;
bare `wasmi` vs `wasmi`+`wasmi_wasi`+`wasi-common`+`cap-std`) and sandboxed by construction.

Path B ABI recipe (the durable artifact; PoC is throwaway):
```rust
// guest (cdylib → wasm32-unknown-unknown — NO WASI):
extern "C" { fn host_rand(ptr: *mut u8, len: usize); }   // the only capability it imports
#[no_mangle] pub extern "C" fn alloc(len: usize) -> *mut u8 { /* leak a Vec, return ptr */ }
#[no_mangle] pub extern "C" fn transform_out(ptr: *mut u8, len: usize) -> u64 { /* -> (out_ptr<<32)|out_len */ }
#[no_mangle] pub extern "C" fn transform_in (ptr: *mut u8, len: usize) -> u64 { /* reverse */ }
// host (bare wasmi = "=2.0.0-beta.2", no wasmi_wasi):
let mut linker = Linker::<()>::new(&engine);
linker.func_wrap("env","host_rand", |mut c: Caller<()>, ptr, len| { /* native CSPRNG -> mem.write */ })?;
let inst = linker.instantiate_and_start(&mut store, &module)?;   // host owns both sockets;
// host: alloc(n) -> mem.write(input) -> transform_*(ptr,n) -> read packed (ptr,len) from memory.
```
Real-transport shape: the module's `transform_out`/`in` carry the handshake/framing/padding state
machine (control path); AEAD/hash/rand are native host fns; spark's `Transport::dial` owns the
protected upstream + the netstack flow and pumps both through the module. Next: a richer ABI
(handshake phase, host-fn crypto), Ed25519 module signing + delivery, and wiring into `Transport`.

**Realized (2026-07-20, ADR 0013 §7):** most of that "Next" has since landed — the richer ABI
(`compute_gambit`, `handshake_step`, and the crypto host-fn menu) and Ed25519 signing
(`wasm/signing.rs` `ModuleVerifier`). The build-and-sign half is now a real, reproducible pipeline
rather than the throwaway PoC: `modules/obfs-xor` is the reference Rust→wasm32 guest (a `no_std` cdylib
mirroring the inline `XOR_WAT`), and `scripts/build-module.sh` compiles it and signs it with the
`sign-module` tool (`core/src/bin/sign-module.rs`, `--features module-signer`) into
`core/tests/fixtures/wasm/obfs-xor.spkw` — which a toolchain-free `cargo test` loads through the
production `ModuleVerifier::pinned().verify` → `instantiate` path and round-trips.

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
