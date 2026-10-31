// swift-tools-version:6.0
// The protocol core of the Mac app (docs/PROTOCOL.md): keys, envelopes, words and pairing codes,
// item heads and chunks, relay frames and the sync state machine, receive rules, file names,
// the encrypted history and its export. No dependency: CryptoKit and Foundation only.
// Tested against docs/VECTORS.json with `swift test`.
import PackageDescription

let package = Package(
    name: "ClipwayCore",
    platforms: [.macOS(.v14)],
    products: [.library(name: "ClipwayCore", targets: ["ClipwayCore"])],
    targets: [
        .target(name: "ClipwayCore"),
        .testTarget(name: "ClipwayCoreTests", dependencies: ["ClipwayCore"]),
    ]
)
