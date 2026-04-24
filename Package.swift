// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "FreerForMac",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "FreerForMac", targets: ["FreerForMac"])
    ],
    dependencies: [
        .package(path: "Packages/FCCore"),
        .package(path: "Packages/FCTransport"),
        .package(path: "Packages/FCStorage"),
        .package(path: "Packages/FCDomain"),
        .package(path: "Packages/FCUI")
    ],
    targets: [
        .executableTarget(
            name: "FreerForMac",
            dependencies: [
                "FCCore",
                "FCTransport",
                "FCStorage",
                "FCDomain",
                "FCUI"
            ]
        )
    ]
)
