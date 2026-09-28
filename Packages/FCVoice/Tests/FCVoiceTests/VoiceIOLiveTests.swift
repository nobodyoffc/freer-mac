import XCTest
@testable import FCVoice

/// Starts the real audio devices for two seconds. Runs only with VOICE_IO=1:
/// it needs a microphone and the permission to use it.
final class VoiceIOLiveTests: XCTestCase {
    func testTheDevicesStart() throws {
        guard ProcessInfo.processInfo.environment["VOICE_IO"] != nil else { throw XCTSkip("set VOICE_IO=1") }
        let captured = LockedCount()
        let io = VoiceIO(onCapture: { captured.add($0.count) },
                         render: { _ in [Int16](repeating: 0, count: Mixer.tickSamples) })
        do {
            try io.start()
        } catch {
            XCTFail("start: \(error) \((error as NSError).domain) \((error as NSError).code) \((error as NSError).userInfo)")
            return
        }
        Thread.sleep(forTimeInterval: 2)
        io.stop()
        print("captured \(captured.value) samples in 2 s")
        XCTAssertGreaterThan(captured.value, 48_000, "about 96 000 expected")
    }
}

final class LockedCount: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func add(_ k: Int) { lock.withLock { n += k } }
    var value: Int { lock.withLock { n } }
}
