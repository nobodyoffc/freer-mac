// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "FCCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "FCCore", targets: ["FCCore"])
    ],
    targets: [
        // Vendored Argon2 reference implementation — see Sources/CArgon2/UPSTREAM.md
        .target(
            name: "CArgon2",
            exclude: [
                "LICENSE",
                "UPSTREAM.md"
            ],
            cSettings: [
                .headerSearchPath(".")
            ]
        ),
        .target(
            name: "FCCore",
            dependencies: ["CArgon2"]
        ),
        .testTarget(
            name: "FCCoreTests",
            dependencies: ["FCCore"],
            resources: [
                .process("Resources/testVectors.json")
            ]
        )
    ]
)
