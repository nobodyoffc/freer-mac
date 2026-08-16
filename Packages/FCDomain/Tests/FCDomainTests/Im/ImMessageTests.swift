import XCTest
@testable import FCDomain

/// ``ImMessage`` against vectors from the real FC-AJDK class
/// (`tools/vector-gen/.../ImMessageRef.java`).
///
/// The message has two serializations that carry different sets of
/// fields on purpose, so the suite checks both and — in
/// ``testWireDropsLocalOnlyFields`` — checks that they still disagree.
final class ImMessageTests: XCTestCase {

    private var root: DomainVectors.ImMessageRoot!
    private var vectors: [DomainVectors.ImMessageCase] { root.vectors }

    override func setUpWithError() throws {
        root = try DomainVectors.load().imMessage
        XCTAssertFalse(root.vectors.isEmpty)
    }

    private func vector(_ label: String) throws -> DomainVectors.ImMessageCase {
        try XCTUnwrap(vectors.first { $0.label == label }, "no vector labelled \(label)")
    }

    // MARK: - enum ordinals

    /// The ordinal each enum constant gets on the wire, against the
    /// numbers the Java enums actually produce.
    ///
    /// This is the test that earns the `JavaOrdinalEnum` protocol. Every
    /// other test here would stay green if two cases were transposed —
    /// the JSON only ever names constants — while every message on the
    /// wire quietly changed meaning.
    func testEnumOrdinalsMatchJava() throws {
        func check<E: JavaOrdinalEnum>(_ type: E.Type, _ name: String) throws {
            let names = try XCTUnwrap(root.enumOrdinals[name], "no ordinal table for \(name)")
            XCTAssertEqual(E.allCases.count, names.count, "\(name) case count")
            for (ordinal, javaName) in names.enumerated() {
                let mine = try XCTUnwrap(E(wireOrdinal: UInt8(ordinal)), "\(name) ordinal \(ordinal)")
                XCTAssertEqual(mine.rawValue, javaName, "\(name) ordinal \(ordinal)")
                XCTAssertEqual(mine.wireOrdinal, UInt8(ordinal), "\(name) \(javaName)")
            }
        }
        try check(ImType.self, "ImType")
        try check(ContentType.self, "ContentType")
        try check(RequestType.self, "RequestType")
        try check(MessageStatus.self, "MessageStatus")
        try check(DeliveryMethod.self, "DeliveryMethod")
    }

    /// An ordinal this build has never heard of leaves the field nil
    /// rather than throwing — a message from a newer client still
    /// decodes, minus the part we cannot name.
    func testUnknownOrdinalIsNilNotAnError() {
        XCTAssertNil(ContentType(wireOrdinal: 200))
        XCTAssertNil(ImType(wireOrdinal: 4))
        XCTAssertEqual(ImType(wireOrdinal: 3), .room)
    }

    func testJavaNameLookupIsCaseInsensitive() {
        XCTAssertEqual(ContentType(javaName: "room_info"), .roomInfo)
        XCTAssertEqual(ImType(javaName: "p2p"), .p2p)
        XCTAssertNil(ImType(javaName: "GROUP"))
        XCTAssertNil(ImType(javaName: nil))
    }

    // MARK: - JSON parity

    /// Decode what Android wrote, re-encode it, get the same bytes back.
    /// Field order is what a JSON round trip does not give you for free,
    /// and a history file shared between clients is read as text.
    func testDecodeAndReEncodeIsByteIdentical() throws {
        for v in vectors {
            let message = try ImMessage.fromJson(v.json)
            XCTAssertEqual(message.wireJson(), v.json, "vector \(v.label)")
        }
    }

    /// `JsonUtils.toJson` disables Gson's HTML escaping, so `< > & = '`
    /// stay as themselves. A chat message is where those show up.
    func testHtmlEscapableBodyIsNotEscaped() throws {
        let v = try vector("p2p-text-html-escapable")
        XCTAssertTrue(v.json.contains("a<b & c='d' => e"), "the vector itself should be unescaped")
        let message = try ImMessage.fromJson(v.json)
        XCTAssertEqual(message.wireJson(), v.json)
        XCTAssertFalse(message.wireJson().contains("\\u003c"))
    }

    // MARK: - binary wire format

    func testToWireBytesMatchesJava() throws {
        for v in vectors {
            let message = try ImMessage.fromJson(v.json)
            XCTAssertEqual(try message.toWireBytes().hex, v.wireHex, "vector \(v.label)")
        }
    }

    func testFromWireBytesMatchesJava() throws {
        for v in vectors {
            let decoded = try ImMessage.fromWireBytes(Data(fromHex: v.wireHex))
            XCTAssertEqual(decoded.wireJson(), v.wireDecodedJson, "vector \(v.label)")
        }
    }

    /// Encoding what came off the wire produces the same bytes again —
    /// a relay can forward a message it decoded without reserializing it
    /// into something different.
    func testWireRoundTripIsStable() throws {
        for v in vectors {
            // Encoded here rather than taken from the vector: the vector's
            // bytes are v1. What this asserts is unchanged — that decoding
            // and re-encoding is a no-op — but the fixture is now the
            // message, not the bytes.
            let encoded = try ImMessage.fromJson(v.json).toWireBytes()
            let decoded = try ImMessage.fromWireBytes(encoded)
            XCTAssertEqual(try decoded.toWireBytes().hex, encoded.hex, "vector \(v.label)")
        }
    }

    /// Nothing the sending device knows about *delivery* crosses the
    /// wire: status, roadIds, dockId, deliveredAt, readAt, senderName,
    /// unread, pinned, deleted, sequence. The `full` vector sets every
    /// one of them so their absence here is a real observation.
    func testWireDropsLocalOnlyFields() throws {
        let v = try vector("full")
        let sent = try ImMessage.fromJson(v.json)
        XCTAssertEqual(sent.status, .delivered)
        XCTAssertEqual(sent.roadIds, ["road-a", "road-b"])
        XCTAssertEqual(sent.sequence, 42)

        let received = try ImMessage.fromWireBytes(try sent.toWireBytes())
        XCTAssertNil(received.status)
        XCTAssertNil(received.roadIds)
        XCTAssertNil(received.dockId)
        XCTAssertNil(received.deliveryMethod)
        XCTAssertNil(received.deliveredAt)
        XCTAssertNil(received.readAt)
        XCTAssertNil(received.senderName)
        XCTAssertNil(received.unread)
        XCTAssertNil(received.pinned)
        XCTAssertNil(received.deleted)
        XCTAssertNil(received.sequence)

        // …while everything the recipient needs does cross.
        XCTAssertEqual(received.content, sent.content)
        XCTAssertEqual(received.body, sent.body)
        XCTAssertEqual(received.requestType, .history)
        XCTAssertEqual(received.replyToId, sent.replyToId)
        XCTAssertEqual(received.threadId, sent.threadId)
        XCTAssertEqual(received.id, sent.id)
    }

    /// `symkeyVersion` is a Long that the wire carries in 32 bits, so a
    /// version past 2³¹ arrives sign-extended and negative. Java does
    /// this; we reproduce it rather than widening the field, because a
    /// wider field would just be a different protocol.
    func testSymkeyVersionIsTruncatedToThirtyTwoBits() throws {
        let v = try vector("symkey-version-truncated")
        let sent = try ImMessage.fromJson(v.json)
        XCTAssertEqual(sent.symkeyVersion, 0x1_8000_0001)

        let received = try ImMessage.fromWireBytes(try sent.toWireBytes())
        XCTAssertEqual(received.symkeyVersion, -2_147_483_647)
    }

    /// A nil and an empty string are the same thing to the reader: the
    /// flag says present, the length says zero.
    func testEmptyAndNilStringsAreIndistinguishableOnTheWire() throws {
        // A length-prefixed *string* field still round-trips empty as
        // empty: the flag says present, the length says zero.
        var withEmptyThread = ImMessage(type: .p2p, senderId: "a", targetId: "b", timestamp: 1)
        withEmptyThread.content = "x"
        withEmptyThread.threadId = ""
        let received = try ImMessage.fromWireBytes(try withEmptyThread.toWireBytes())
        XCTAssertEqual(received.threadId, "")

        // The body is different, and deliberately so. Its framing records
        // a length, not a presence, so an empty section cannot come back
        // as `""` — it comes back nil, and the encoder omits the body
        // rather than writing an all-zero framing that would not survive
        // a second encode.
        var withEmptyContent = ImMessage(type: .p2p, senderId: "a", targetId: "b", timestamp: 1)
        withEmptyContent.content = ""
        let encoded = try withEmptyContent.toWireBytes()
        let back = try ImMessage.fromWireBytes(encoded)
        XCTAssertNil(back.content)
        XCTAssertNil(back.data)
        XCTAssertEqual(try back.toWireBytes(), encoded, "empty payload survives a second encode")

        let noContent = ImMessage(type: .p2p, senderId: "a", targetId: "b", timestamp: 1)
        XCTAssertNil(try ImMessage.fromWireBytes(try noContent.toWireBytes()).content)
        XCTAssertEqual(
            try noContent.toWireBytes(), encoded,
            "an empty payload and no payload encode identically"
        )
    }

    /// A message the FUDP layer has not named yet clears the id flag,
    /// and the receiver has to name it from the packet header.
    func testMessageWithoutIdCarriesNoIdFlag() throws {
        let v = try vector("no-id")
        let sent = try ImMessage.fromJson(v.json)
        XCTAssertNil(sent.id)
        XCTAssertNil(try ImMessage.fromWireBytes(try sent.toWireBytes()).id)
    }

    func testTruncatedWireDataThrows() throws {
        let full = try ImMessage.fromJson(try vector("p2p-text").json).toWireBytes()
        XCTAssertThrowsError(try ImMessage.fromWireBytes(full.prefix(10)))
        // Long enough to clear the header check, but the flag word
        // promises a content field that is not there.
        XCTAssertThrowsError(try ImMessage.fromWireBytes(full.prefix(full.count - 4)))
    }

    /// The reader indexes relative to `startIndex`, so a message carved
    /// out of a larger buffer decodes the same as a standalone one.
    func testDecodesFromASlice() throws {
        let encoded = try ImMessage.fromJson(try vector("p2p-text").json).toWireBytes()
        let padded = Data(repeating: 0xAB, count: 7) + encoded
        let slice = padded[7...]
        XCTAssertEqual(try ImMessage.fromWireBytes(slice).wireJson(),
                       try ImMessage.fromWireBytes(encoded).wireJson())
    }

    // MARK: - ids

    /// The FUDP id is 64 bits of *pattern*, not a number: Java formats a
    /// signed long with `%016x` and parses it back unsigned, so half of
    /// all ids are negative and must survive anyway.
    func testFudpIdRoundTripsIncludingNegatives() {
        for id: Int64 in [0, 1, 0xdead_beef, .max, -1, .min, -42] {
            let hex = ImMessage.hexId(fudpId: id)
            XCTAssertEqual(hex.count, 16, "\(id)")
            XCTAssertEqual(ImMessage.fudpId(hexId: hex), id)
        }
        XCTAssertEqual(ImMessage.hexId(fudpId: -1), "ffffffffffffffff")
        XCTAssertEqual(ImMessage.hexId(fudpId: 0xdead_beef), "00000000deadbeef")
    }

    /// `hasFudpId` exists to catch a hash-shaped id, which is what
    /// `FcEntity`'s auto-generation would have produced and what would
    /// have broken delivery without a word.
    func testHasFudpIdRejectsAHashShapedId() {
        var m = ImMessage()
        XCTAssertFalse(m.hasFudpId)
        m.id = String(repeating: "a", count: 64)
        XCTAssertFalse(m.hasFudpId)
        XCTAssertNil(ImMessage.fudpId(hexId: m.id!))
        m.setId(fudpId: 0x1234)
        XCTAssertTrue(m.hasFudpId)
        XCTAssertEqual(m.id, "0000000000001234")
    }

    // MARK: - factories and derived state

    /// The factories reproduce `createBase`: routing, a timestamp, and
    /// PENDING — but no id, because naming is the transport's job.
    func testFactoriesLeaveTheIdToTheTransport() {
        let now = Date(timeIntervalSince1970: 1_755_100_000.123)
        let m = ImMessage.text(type: .p2p, from: "FA", to: "FB", "hi", now: now)
        XCTAssertNil(m.id)
        XCTAssertEqual(m.status, .pending)
        XCTAssertEqual(m.timestamp, 1_755_100_000_123)
        XCTAssertEqual(m.contentType, .text)
        XCTAssertEqual(m.unread, false)
    }

    /// A receipt is P2P whatever the original message was, because it is
    /// addressed to the one sender rather than to the group.
    func testReceiptIsAlwaysP2P() {
        let r = ImMessage.receipt(from: "FB", to: "FA", originalMessageId: "00000000deadbeef", read: true)
        XCTAssertEqual(r.type, .p2p)
        XCTAssertEqual(r.contentType, .receipt)
        XCTAssertEqual(r.requestId, "00000000deadbeef")
        XCTAssertEqual(r.content, "read")
        XCTAssertEqual(
            ImMessage.receipt(from: "FB", to: "FA", originalMessageId: "x", read: false).content,
            "delivered"
        )
    }

    /// For a group message the conversation is the group; only P2P has
    /// to work out which end of it we are.
    func testConversationPartner() throws {
        let outgoing = try ImMessage.fromJson(try vector("p2p-text").json)
        let me = try XCTUnwrap(outgoing.senderId)
        let them = try XCTUnwrap(outgoing.targetId)
        XCTAssertTrue(outgoing.isOutgoing(from: me))
        XCTAssertEqual(outgoing.conversationPartnerId(for: me), them)
        XCTAssertEqual(outgoing.conversationPartnerId(for: them), me)

        let room = try ImMessage.fromJson(try vector("hat-share").json)
        XCTAssertEqual(room.conversationPartnerId(for: me), room.targetId)
        XCTAssertEqual(room.conversationPartnerId(for: "someone-else"), room.targetId)
    }
}
