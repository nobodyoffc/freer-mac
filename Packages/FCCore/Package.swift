// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "FCCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "FCCore", targets: ["FCCore"])
    ],
    dependencies: [
        // Bitcoin Core's libsecp256k1 vendored as a Swift package.
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift", from: "0.18.0")
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
            dependencies: [
                "CArgon2",
                .product(name: "P256K", package: "secp256k1.swift")
            ]
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
