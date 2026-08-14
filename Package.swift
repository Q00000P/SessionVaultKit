// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SessionVaultKit",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SessionVaultKit", targets: ["SessionVaultKit"])
    ],
    targets: [
        // No external deps by design — only CryptoKit/Security/Foundation (system frameworks).
        .target(name: "SessionVaultKit", dependencies: []),
        .testTarget(name: "SessionVaultKitTests", dependencies: ["SessionVaultKit"])
    ]
)
