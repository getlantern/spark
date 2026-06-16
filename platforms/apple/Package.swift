// swift-tools-version:5.9
// Compile-verification harness for the NE provider sources against the Rust core's xcframework.
// Build the xcframework first: ./build-xcframework.sh — then `swift build` type-checks the
// Swift + the C FFI. (The real .app/.appex is an Xcode project; see README.md.)
import PackageDescription

let package = Package(
    name: "SparkNE",
    platforms: [.iOS(.v15), .macOS(.v12)],
    targets: [
        .binaryTarget(name: "SparkCore", path: "SparkCore.xcframework"),
        .target(
            name: "SparkNE",
            dependencies: ["SparkCore"],
            path: "Sources/SparkNE"
        ),
    ]
)
