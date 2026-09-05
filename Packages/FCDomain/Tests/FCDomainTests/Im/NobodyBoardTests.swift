import XCTest
import FCCore
@testable import FCDomain

/// ``NobodyBoard``: the published identity behind the first-FCH board, and
/// the template the posts on it use.
final class NobodyBoardTests: XCTestCase {

    // MARK: - the identity

    /// The FID is not an independent constant — it is what the published
    /// private key derives to. If these two ever disagree, every post goes
    /// to an address nobody reads and every read opens nothing.
    func testPublishedKeyDerivesThePublishedFid() throws {
        XCTAssertEqual(NobodyBoard.prikey.count, 32)
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: NobodyBoard.prikey)
        XCTAssertEqual(pubkey, NobodyBoard.pubkey)
        XCTAssertEqual(try FchAddress(publicKey: pubkey).fid, NobodyBoard.defaultNobodyFid)
    }

    // MARK: - the template

    func testBuildAndParseRoundTrip() throws {
        let content = NobodyBoard.buildRequest(from: "FBob", note: "just installed")
        XCTAssertEqual(content, "FIRST_FCH_REQUEST|FBob|just installed")

        let request = try XCTUnwrap(NobodyBoard.parseRequest(content, createTime: 1_700))
        XCTAssertEqual(request.requesterFid, "FBob")
        XCTAssertEqual(request.note, "just installed")
        XCTAssertEqual(request.createTime, 1_700)
    }

    /// A note is flattened and clipped rather than rejected: the person
    /// writing one has no coins and no other way to ask.
    func testNoteIsFlattenedAndClipped() throws {
        let content = NobodyBoard.buildRequest(
            from: "FBob", note: "  two\nlines " + String(repeating: "x", count: 200)
        )
        let request = try XCTUnwrap(NobodyBoard.parseRequest(content, createTime: 0))
        XCTAssertEqual(request.note.count, NobodyBoard.noteMaxCharacters)
        XCTAssertFalse(request.note.contains("\n"))
        XCTAssertTrue(request.note.hasPrefix("two lines"))
    }

    func testEmptyNoteSurvivesTheSeparator() throws {
        let request = try XCTUnwrap(
            NobodyBoard.parseRequest(
                NobodyBoard.buildRequest(from: "FBob", note: nil), createTime: 0
            )
        )
        XCTAssertEqual(request.requesterFid, "FBob")
        XCTAssertEqual(request.note, "")
    }

    /// Everything a public inbox holds that is not a request — chatter,
    /// spam, another protocol's traffic — is simply not a row.
    func testNonTemplateContentIsNotARequest() {
        XCTAssertNil(NobodyBoard.parseRequest(nil, createTime: 0))
        XCTAssertNil(NobodyBoard.parseRequest("hello board", createTime: 0))
        XCTAssertNil(NobodyBoard.parseRequest("FIRST_FCH_REQUEST||no fid", createTime: 0))
        XCTAssertNil(
            NobodyBoard.parseRequest(
                "FIRST_FCH_REQUEST|FBob|" + String(repeating: "x", count: 101), createTime: 0
            )
        )
    }

    // MARK: - reading a post

    /// The whole reason ``NobodyBoard/openPost(wireBytes:)`` exists: a post
    /// arrives sealed like any other P2P message, and a reader that only
    /// decoded the envelope would see a board full of empty content and
    /// call it empty.
    func testPostIsSealedOnTheWireAndOpensWithThePublishedKey() throws {
        let senderPriv = Data(repeating: 0x11, count: 32)
        var message = ImMessage.text(
            type: .p2p, from: "FBob", to: NobodyBoard.defaultNobodyFid,
            NobodyBoard.buildRequest(from: "FBob", note: "please")
        )
        message.setId(fudpId: ImMessage.newFudpId())
        try message.sealBody(privkey: senderPriv, recipientPubkey: NobodyBoard.pubkey)
        let wire = try message.toWireBytes()

        // Decoding alone yields nothing readable.
        let unopened = try ImMessage.fromWireBytes(wire)
        XCTAssertTrue(unopened.isSealed)
        XCTAssertNil(unopened.content)

        // Opening with the published key yields the request.
        let opened = try XCTUnwrap(NobodyBoard.openPost(wireBytes: wire))
        let request = try XCTUnwrap(NobodyBoard.parseRequest(opened.content, createTime: 5))
        XCTAssertEqual(request.requesterFid, "FBob")
        XCTAssertEqual(request.note, "please")
    }

    func testUnreadableBytesAreNotAPost() {
        XCTAssertNil(NobodyBoard.openPost(wireBytes: Data()))
        XCTAssertNil(NobodyBoard.openPost(wireBytes: Data(repeating: 0x00, count: 40)))
    }

    /// A body sealed to somebody else stays shut. The board's key opens
    /// the board's mail and nothing more.
    func testABodySealedToSomeoneElseDoesNotOpen() throws {
        let senderPriv = Data(repeating: 0x11, count: 32)
        let strangerPub = try Secp256k1.publicKey(
            fromPrivateKey: Data(repeating: 0x22, count: 32)
        )
        var message = ImMessage.text(type: .p2p, from: "FBob", to: "FEve", "not for the board")
        message.setId(fudpId: ImMessage.newFudpId())
        try message.sealBody(privkey: senderPriv, recipientPubkey: strangerPub)
        XCTAssertNil(NobodyBoard.openPost(wireBytes: try message.toWireBytes()))
    }
}
