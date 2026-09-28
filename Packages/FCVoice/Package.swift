// swift-tools-version: 5.10
import PackageDescription

// The voice engine of calls and meetings (VOICE_SPEC §9): the Opus codec,
// the jitter buffer, and capture and playout on AVAudioEngine.
let package = Package(
    name: "FCVoice",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "FCVoice", targets: ["FCVoice"])
    ],
    targets: [
        // libopus 1.5.2, the same xiph release Android vendors (sha256
        // 65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1):
        // the float build's sources from its *_sources.mk, without dnn/
        // (DRED, OSCE and deep PLC stay off) and without arch-specific code.
        .target(
            name: "COpus",
            path: "Sources/COpus",
            exclude: ["COPYING"],
            publicHeadersPath: "include",
            cSettings: [
                .define("OPUS_BUILD"),
                .define("USE_ALLOCA"),
                .define("HAVE_LRINT"),
                .define("HAVE_LRINTF"),
                .headerSearchPath("celt"),
                .headerSearchPath("silk"),
                .headerSearchPath("silk/float"),
                .headerSearchPath("src"),
                // The codec runs 25-50 times a second per stream: optimise debug builds too.
                .unsafeFlags(["-O2", "-w"])
            ]
        ),
        .target(
            name: "FCVoice",
            dependencies: ["COpus"]
        ),
        .testTarget(
            name: "FCVoiceTests",
            dependencies: ["FCVoice"]
        )
    ]
)
