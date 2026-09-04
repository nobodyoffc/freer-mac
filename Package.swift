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
        .package(path: "Packages/FCUI"),
        // The terminal emulator behind the Terminal pane. Pinned to a
        // minor range on purpose: SwiftTerm's `main` has already moved
        // to swift-tools 6.2 with `swiftLanguageModes: [.v6]` and picked
        // up a swift-png dependency, so an open-ended `from:` could drag
        // a language-mode change into a package that is still 5.10.
        // Only the executable target links it — keeping it out of FCUI,
        // whose one dependency is FCCore, means the UI package and its
        // tests do not build a terminal emulator.
        .package(url: "https://github.com/migueldeicaza/SwiftTerm", .upToNextMinor(from: "1.20.0"))
    ],
    targets: [
        .executableTarget(
            name: "FreerForMac",
            dependencies: [
                "FCCore",
                "FCTransport",
                "FCStorage",
                "FCDomain",
                "FCUI",
                .product(name: "SwiftTerm", package: "SwiftTerm")
            ],
            // Linked into the binary, not copied as a resource — see the
            // linker settings below.
            exclude: ["Info.plist"],
            linkerSettings: [
                // **The microphone and camera need this.** macOS kills a process
                // that touches a TCC-protected device with no usage
                // description to show the user, and a SwiftPM executable
                // has no bundle to put one in. Writing the plist into
                // the binary's own `__TEXT,__info_plist` section is
                // where TCC looks when there is no bundle, so the voice
                // note recorder and the QR scanner get a prompt rather
                // than a crash. Note SwiftPM does not treat the plist as
                // a linker input: edit it and the binary keeps the old
                // section until something else forces a relink.
                // Phase 10's packaging replaces this with a real `.app`.
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT",
                    "-Xlinker", "__info_plist",
                    "-Xlinker", "Sources/FreerForMac/Info.plist"
                ])
            ]
        )
    ]
)
