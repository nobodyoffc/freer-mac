// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "FCStorage",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "FCStorage", targets: ["FCStorage"])
    ],
    dependencies: [
        .package(path: "../FCCore"),
        // Typed SQLite database layer. Used by EncryptedKVStore to back
        // the row-level AES-GCM encrypted store.
        .package(url: "https://github.com/groue/GRDB.swift", from: "6.0.0")
    ],
    targets: [
        .target(
            name: "FCStorage",
            dependencies: [
                "FCCore",
                .product(name: "GRDB", package: "GRDB.swift")
            ]
        ),
        .testTarget(name: "FCStorageTests", dependencies: ["FCStorage"])
    ]
)
