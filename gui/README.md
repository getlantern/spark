# spark GUI

A Flutter control GUI for spark — connect / disconnect / live status. The first, deliberately small
cut: one screen with a state-reactive "signal orb", a connect/disconnect toggle, and a fail-open
warning, polling the service every 2s.

## Architecture

The UI talks only to an abstract **`SparkBackend`** (`lib/spark_backend.dart`) — the same small shape
as `spark-ffi`'s `Backend` (`status` / `connect` / `disconnect`). That seam is the point: the UI
never changes as the binding underneath it does.

- **Desktop — `FrbBackend`** (`lib/frb_backend.dart`, **default**): an in-process
  `flutter_rust_bridge` binding over the `spark-bridge` crate → `spark-backend` → `spark-ipc` — **no
  subprocess**, so it isn't blocked by the App Sandbox. The `rust_builder` cargokit plugin compiles
  `spark-bridge` and links it into the app during `flutter build` (no manual dylib step). `main` builds
  this and **falls back to `CliBackend`** if the Rust library can't initialize, so the app always
  launches.
- **Desktop fallback — `CliBackend`**: shells out to the `spark` CLI (`spark connect|disconnect|
  status`), which speaks `spark-ipc` to a running `spark-service`. Zero FFI; the fallback when the
  in-process bridge is unavailable.
- **Mobile** — a platform-channel backend to the native VpnService/NE layer, which runs the tunnel
  via the `platforms/{android,apple}` shims and the UniFFI Kotlin/Swift bindings from `spark-ffi`.
  *Follow-up* (ios/android targets not yet scaffolded here).

### Regenerating the frb bindings

The Dart (`lib/src/rust/`) and Rust (`spark-bridge/src/frb_generated.rs`) bridge code is generated
and checked in (so a build needs no codegen tool). After changing the `spark-bridge` API, regenerate
from the repo root with `flutter_rust_bridge_codegen generate` (config: `flutter_rust_bridge.yaml`).

## Run (macOS dev)

```bash
# 1. Have a spark-service running (privileged):
cargo build --release --bin spark-service
sudo target/release/spark-service --spark-gid "$(id -g)" &      # privileged daemon

# 2. Run the GUI (cargokit compiles + links spark-bridge automatically):
cd gui && flutter run -d macos
```

> **macOS App Sandbox caveat:** `FrbBackend` runs in-process (no subprocess), but it still opens the
> service's unix socket at `/var/run/spark.sock`, which is outside the sandbox container. For local
> dev, disable the App Sandbox in `macos/Runner/DebugProfile.entitlements`
> (`com.apple.security.app-sandbox` → `false`). If the Rust library can't initialize at all, the app
> falls back to `CliBackend` (which needs the `spark` CLI on `PATH` and is itself sandbox-blocked from
> spawning) — so disabling the sandbox is the simplest dev path either way.

Both backends default to socket `/var/run/spark.sock` (a constructor arg if you need to point
elsewhere); `CliBackend` also takes the `spark` binary path.

## Verified

`flutter analyze` clean · `flutter test` (the widget smoke test, against a fake backend) passes ·
`flutter build macos --debug` produces `spark_gui.app` with `spark_bridge.framework` (the Rust bridge)
bundled and its frb symbols force-loaded in · **`flutter test integration_test -d macos`** runtime-
verifies the bridge end-to-end (the real app loads the framework; `FrbBackend.status()` against a dead
socket round-trips a typed error through `RustLib` → Rust → `spark-backend` → back). **Still pending:**
the *successful*-connect path against a running `spark-service` (needs the daemon + sandbox/entitlement
handling for the socket).

## Next

Live-gate `FrbBackend` (launch + connect against a running `spark-service`); ios/android targets + the
platform-channel/native backend; richer screens (capabilities, details, live metrics, the log stream,
profile management) off the ADR-0004 backend contract the service already exposes.
