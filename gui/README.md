# spark GUI

A Flutter control GUI for spark — connect / disconnect / live status. The first, deliberately small
cut: one screen with a state-reactive "signal orb", a connect/disconnect toggle, and a fail-open
warning, polling the service every 2s.

## Architecture

The UI talks only to an abstract **`SparkBackend`** (`lib/spark_backend.dart`) — the same small shape
as `spark-ffi`'s `Backend` (`status` / `connect` / `disconnect`). That seam is the point: the UI
never changes as the binding underneath it does.

- **Desktop v1 — `CliBackend`** (current): shells out to the `spark` CLI (`spark connect|disconnect|
  status`), which already speaks `spark-ipc` to a running `spark-service`. Zero FFI, works today.
- **Desktop (real)** — a `flutter_rust_bridge` backend wrapping `spark_ipc::Client` directly (no
  subprocess). *Follow-up.*
- **Mobile** — a platform-channel backend to the native VpnService/NE layer, which runs the tunnel
  via the `platforms/{android,apple}` shims and the UniFFI Kotlin/Swift bindings from `spark-ffi`.
  *Follow-up* (ios/android targets not yet scaffolded here).

## Run (macOS dev)

```bash
# 1. Have a spark-service running (privileged) and the `spark` CLI on PATH:
cargo build --release --bin spark --bin spark-service
sudo target/release/spark-service --spark-gid "$(id -g)" &      # privileged daemon
sudo install target/release/spark /usr/local/bin/spark          # or symlink; CliBackend runs `spark`

# 2. Run the GUI:
cd gui && flutter run -d macos
```

> **macOS App Sandbox caveat:** the default macOS build is sandboxed, which **blocks spawning the
> external `spark` binary**, so `CliBackend` can't reach the service under the sandbox. For local
> dev, disable the App Sandbox in `macos/Runner/DebugProfile.entitlements`
> (`com.apple.security.app-sandbox` → `false`), or wait for the in-process `flutter_rust_bridge`
> backend (which needs no subprocess and works sandboxed with the network-client entitlement).

`CliBackend` defaults to the `spark` binary on `PATH` and socket `/var/run/spark.sock`; both are
constructor args if you need to point elsewhere.

## Verified

`flutter analyze` clean · `flutter test` (the widget smoke test, against a fake backend) passes ·
`flutter build macos --debug` produces `spark_gui.app`.

## Next

Real `flutter_rust_bridge` desktop backend; ios/android targets + the platform-channel/native
backend; richer screens (capabilities, details, live metrics, the log stream, profile management)
off the ADR-0004 backend contract the service already exposes.
