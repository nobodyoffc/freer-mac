// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "FCTransport",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "FCTransport", targets: ["FCTransport"])
    ],
    dependencies: [
        .package(path: "../FCCore")
    ],
    targets: [
        .target(name: "FCTransport", dependencies: ["FCCore"]),
        .testTarget(
            name: "FCTransportTests",
            dependencies: ["FCTransport"],
            resources: [
                .process("Resources/fudpVectors.json")
            ]
        )
    ]
)
