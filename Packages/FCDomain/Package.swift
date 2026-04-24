// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "FCDomain",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "FCDomain", targets: ["FCDomain"])
    ],
    dependencies: [
        .package(path: "../FCCore"),
        .package(path: "../FCTransport"),
        .package(path: "../FCStorage")
    ],
    targets: [
        .target(
            name: "FCDomain",
            dependencies: ["FCCore", "FCTransport", "FCStorage"]
        ),
        .testTarget(name: "FCDomainTests", dependencies: ["FCDomain"])
    ]
)
