# spark-ffi — Apple packaging (SparkFFI.xcframework + Swift package)

Packages the `spark-ffi` control-plane binding for iOS/macOS: a Swift package whose `SparkFFI`
target is the UniFFI-generated, type-safe API (`Backend`, `EventListener`, the async
`connect`/`disconnect`/`status`, the `TunnelState`/`TunnelStatus`/`TunnelEvent` mirror types) over a
running `spark-service`'s control socket.

> **Control plane only.** This is the surface a UI uses to drive the service. The data path (the
> tunnel itself) is the separate `SparkCore.xcframework` from `platforms/apple`, which runs the core
> in-process inside the Network Extension. An app embeds *both*.

## Build

```bash
./build-xcframework.sh
```

This builds the Rust staticlib for `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and
`aarch64-apple-darwin`, generates the Swift glue + C header from a host build (UniFFI reads crate
metadata by dlopen, so generation uses a host cdylib — the iOS libs can't load on the host), and
assembles `SparkFFI.xcframework` with the bundled header/modulemap. Output (gitignored, regenerate
with the script):

- `SparkFFI.xcframework` — `ios-arm64`, `ios-arm64-simulator`, `macos-arm64` slices
- `Sources/SparkFFI/spark_ffi.swift` — the generated Swift API

## Verify

```bash
swift build   # type-checks Sources/SparkFFI/spark_ffi.swift against the xcframework (macOS slice)
```

## Use from an app

Add this directory as a local Swift package (Xcode → *Add Package Dependencies…* → local path, or a
`.package(path:)` entry), then:

```swift
import SparkFFI

let backend = try Backend(socketPath: "/var/run/spark/control.sock")
try await backend.connect()
let status = try await backend.status()
backend.subscribe(listener: myListener)   // auto-reconnecting event stream
```

No extra runtime dependencies — the UniFFI scaffolding is statically linked from the xcframework.

## Layout

| Path | Tracked? | What |
|------|----------|------|
| `build-xcframework.sh` | yes | the build/generate/assemble script |
| `Package.swift` | yes | binary target (`spark_ffiFFI`) + Swift target (`SparkFFI`) |
| `Sources/SparkFFI/.gitkeep` | yes | keeps the source dir; the `.swift` lands here at build time |
| `SparkFFI.xcframework`, `Sources/SparkFFI/*.swift`, `.generated/` | no | generated build outputs |
