import XCTest
@testable import FCDomain

/// ``Mentions``. The cases are shared with Android's `MentionsTest`: an
/// `@` must name the same people on every device.
final class MentionsTests: XCTestCase {

    static let me = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"

    private func names(_ text: String) -> [String] {
        Mentions.tokens(in: text).map(\.name)
    }

    func testTokensStopAtSpacesPunctuationAndTheNextAt() {
        XCTAssertEqual(names("@Alice, hi @Bob_1234。 see @Carol@Dave"), ["Alice", "Bob_1234", "Carol"])
        // Only after a space or at the start: "(@Eve" is not a mention.
        XCTAssertEqual(names("(@Eve) and @Frank!"), ["Frank"])
        XCTAssertEqual(names("@Grace，你好\n@Heidi"), ["Grace", "Heidi"])
    }

    func testAnAtInsideAWordIsNotAMention() {
        XCTAssertEqual(names("mail a@b.com"), [])
        XCTAssertEqual(names("@"), [])
        XCTAssertEqual(names("@ alone"), [])
    }

    func testMentionedByFidOrCid() {
        XCTAssertTrue(Mentions.mentions("hey @\(Self.me)!", fid: Self.me, cid: nil))
        XCTAssertTrue(Mentions.mentions("hey @Alice", fid: Self.me, cid: "Alice"))
        XCTAssertFalse(Mentions.mentions("hey @Alicia", fid: Self.me, cid: "Alice"))
        XCTAssertFalse(Mentions.mentions("hey Alice", fid: Self.me, cid: "Alice"))
        XCTAssertFalse(Mentions.mentions("hey @", fid: Self.me, cid: ""))
        XCTAssertFalse(Mentions.mentions(nil, fid: Self.me, cid: "Alice"))
    }

    func testOnlyGroupTextsCount() {
        let text = ImMessage.text(type: .room, from: "Fother", to: "room1", "@Alice look")
        XCTAssertTrue(Mentions.mentions(text, fid: Self.me, cid: "Alice"))
        let p2p = ImMessage.text(type: .p2p, from: "Fother", to: Self.me, "@Alice look")
        XCTAssertFalse(Mentions.mentions(p2p, fid: Self.me, cid: "Alice"))
    }

    func testPendingQueryIsTheNameBeingTypedAtTheEnd() {
        XCTAssertEqual(Mentions.pendingQuery(in: "hi @Al"), "Al")
        XCTAssertEqual(Mentions.pendingQuery(in: "@"), "")
        XCTAssertEqual(Mentions.pendingQuery(in: "hi @"), "")
        XCTAssertNil(Mentions.pendingQuery(in: "a@b"))
        XCTAssertNil(Mentions.pendingQuery(in: "hi @Al x"))
        XCTAssertNil(Mentions.pendingQuery(in: "hi"))
    }

    func testCompleteReplacesWhatIsTypedOrAppends() {
        XCTAssertEqual(Mentions.complete("hi @Al", with: "Alice"), "hi @Alice ")
        XCTAssertEqual(Mentions.complete("hi @", with: "Alice"), "hi @Alice ")
        XCTAssertEqual(Mentions.complete("hi", with: "Bob"), "hi @Bob ")
        XCTAssertEqual(Mentions.complete("hi ", with: "Bob"), "hi @Bob ")
        XCTAssertEqual(Mentions.complete("", with: "Bob"), "@Bob ")
    }
}
