// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "FCUI",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "FCUI", targets: ["FCUI"])
    ],
    dependencies: [
        .package(path: "../FCCore")
    ],
    targets: [
        .target(
            name: "FCUI",
            dependencies: ["FCCore"],
            resources: [
                .copy("Resources/avatar-elements")
            ]
        ),
        .testTarget(name: "FCUITests", dependencies: ["FCUI"])
    ]
)
