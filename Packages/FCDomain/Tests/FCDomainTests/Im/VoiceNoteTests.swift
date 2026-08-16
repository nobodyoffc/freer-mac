import XCTest
@testable import FCDomain

/// Voice notes: the metadata the two clients agree on, the reading of it
/// that a transcript depends on, and the size rule that decides whether
/// a note travels inside the message at all.
final class VoiceNoteTests: XCTestCase {

    private let alice = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    private let bob = "F6vqNGkbAqZQ1YkPWLcXfNfwvJXCTGmzUM"

    // MARK: - the metadata both clients read

    /// Byte-for-byte what Android's `VoiceMessageHelper.buildMetaJson`
    /// writes. This string is the whole contract between the clients for
    /// a voice note, so it is asserted literally rather than parsed.
    func testMetaJsonMatchesAndroidsExactly() {
        XCTAssertEqual(
            VoiceNote.metaJson(durationMs: 1985, sampleRate: 16_000),
            #"{"durationMs":1985,"sampleRate":16000,"format":"aac"}"#
        )
    }

    func testAComposedNoteReadsBackItsOwnMetadata() {
        let message = VoiceNote.message(
            type: .p2p, from: alice, to: bob,
            audio: Data(repeating: 0xAB, count: 512), durationMs: 1985
        )
        XCTAssertEqual(message.contentType, .voice)
        XCTAssertEqual(message.data?.count, 512)

        let meta = VoiceNote.meta(in: message)
        XCTAssertEqual(meta?.durationMs, 1985)
        XCTAssertEqual(meta?.sampleRate, 16_000)
        XCTAssertEqual(meta?.format, "aac")
    }

    /// The one thing the reading is strict about. Everything else is a
    /// display detail, but a message that is not a voice note must not
    /// be drawn as one.
    func testAMessageThatIsNotAVoiceNoteHasNoMeta() {
        let text = ImMessage.text(type: .p2p, from: alice, to: bob, "hello")
        XCTAssertNil(VoiceNote.meta(in: text))
    }

    /// Tolerance is deliberate: a note whose metadata we cannot parse is
    /// still a note we can play, so an unreadable field costs a duration
    /// label rather than the audio.
    func testUnreadableMetadataStillYieldsAPlayableNote() {
        var message = VoiceNote.message(
            type: .p2p, from: alice, to: bob, audio: Data([0x01]), durationMs: 1000
        )
        message.content = "not json at all"

        let meta = VoiceNote.meta(in: message)
        XCTAssertNotNil(meta, "the message is still a voice note")
        XCTAssertEqual(meta?.durationMs, 0)
    }

    func testMissingFieldsFallBackRatherThanFailing() throws {
        var message = VoiceNote.message(
            type: .p2p, from: alice, to: bob, audio: Data([0x01]), durationMs: 1000
        )
        message.content = #"{"durationMs":2500}"#

        let meta = try XCTUnwrap(VoiceNote.meta(in: message))
        XCTAssertEqual(meta.durationMs, 2500)
        XCTAssertEqual(meta.sampleRate, VoiceNote.sampleRate)
        XCTAssertEqual(meta.format, "aac")
    }

    // MARK: - the label under the bubble

    func testDurationsAreFormattedForABubble() {
        XCTAssertEqual(VoiceNote.formatDuration(0), "0:00")
        XCTAssertEqual(VoiceNote.formatDuration(999), "0:00")
        XCTAssertEqual(VoiceNote.formatDuration(1985), "0:01")
        XCTAssertEqual(VoiceNote.formatDuration(65_000), "1:05")
        XCTAssertEqual(VoiceNote.formatDuration(VoiceNote.maxDurationMs), "5:00")
        // A clock that has run backwards is not a reason to print "-1:-1".
        XCTAssertEqual(VoiceNote.formatDuration(-4_000), "0:00")
    }

    // MARK: - inline or DISK

    /// The rule that replaced "voice is always inline". The budget comes
    /// from the destination DOCK — 64 KB by default, and an operator may
    /// advertise less — so what fits is a question about the route, not
    /// a constant the app can hold.
    func testWhatFitsIsMeasuredAgainstTheDestinationsBudget() {
        let budget = ImMessage.assumedDockItemLimit
        let ceiling = budget - VoiceNote.wireOverheadAllowance

        XCTAssertTrue(VoiceNote.fitsInline(audioBytes: ceiling, budget: budget))
        XCTAssertFalse(VoiceNote.fitsInline(audioBytes: ceiling + 1, budget: budget))

        // The same recording against a stingier DOCK goes to DISK.
        XCTAssertFalse(VoiceNote.fitsInline(audioBytes: ceiling, budget: 16 * 1024))
    }

    /// What that means in seconds at the bitrate we record: an ordinary
    /// note stays inline, a long one takes the DISK road. Both are
    /// normal — this pins that the bitrate and the default ceiling are
    /// still in a sane relationship to each other.
    func testAnOrdinaryNoteFitsAndALongOneDoesNot() {
        func bytes(seconds: Double) -> Int { Int(seconds * Double(VoiceNote.bitRate) / 8) }
        let budget = ImMessage.assumedDockItemLimit

        XCTAssertTrue(VoiceNote.fitsInline(audioBytes: bytes(seconds: 15), budget: budget))
        XCTAssertFalse(VoiceNote.fitsInline(audioBytes: bytes(seconds: 60), budget: budget))
    }

    // MARK: - across the wire

    /// What the far end's transcript reads is what this end composed.
    func testANoteSurvivesTheWireWithBothHalvesIntact() throws {
        let audio = Data((0 ..< 300).map { UInt8($0 % 256) })
        var message = VoiceNote.message(
            type: .p2p, from: alice, to: bob, audio: audio, durationMs: 7_250
        )
        message.timestamp = 1_700_000_000_000
        message.id = "0000000000000003"

        let back = try ImMessage.fromWireBytes(try message.toWireBytes())
        XCTAssertEqual(back.data, audio)
        XCTAssertEqual(VoiceNote.meta(in: back)?.durationMs, 7_250)
        XCTAssertEqual(Conversation.preview(for: back), "[Voice]")
    }
}
