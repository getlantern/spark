// swift-tools-version:5.9
// Swift package for the spark-ffi control-plane binding. Generate the artifacts first:
//   ./build-xcframework.sh
// then `swift build` type-checks the generated Swift against the Rust FFI, or add this package to
// an app (Xcode → Add Package Dependencies → local path, or a `.package(path:)` entry).
//
// `spark_ffiFFI` is the binary target — the C/UniFFI scaffolding (the Rust staticlibs in the
// xcframework). `SparkFFI` is the generated, type-safe Swift API (Backend, EventListener, the
// mirror types) and imports the `spark_ffiFFI` clang module.
import PackageDescription

let package = Package(
    name: "SparkFFI",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "SparkFFI", targets: ["SparkFFI"]),
    ],
    targets: [
        .binaryTarget(name: "spark_ffiFFI", path: "SparkFFI.xcframework"),
        .target(
            name: "SparkFFI",
            dependencies: ["spark_ffiFFI"],
            path: "Sources/SparkFFI"
        ),
    ]
)
