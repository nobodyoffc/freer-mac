// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "FCStorage",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "FCStorage", targets: ["FCStorage"])
    ],
    dependencies: [
        .package(path: "../FCCore")
    ],
    targets: [
        .target(name: "FCStorage", dependencies: ["FCCore"]),
        .testTarget(name: "FCStorageTests", dependencies: ["FCStorage"])
    ]
)
