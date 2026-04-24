// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "FCCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "FCCore", targets: ["FCCore"])
    ],
    targets: [
        .target(name: "FCCore"),
        .testTarget(name: "FCCoreTests", dependencies: ["FCCore"])
    ]
)
