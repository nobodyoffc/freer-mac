import XCTest
import FCCore
@testable import FCDomain

/// The `Mail` model against vectors from the real FC-AJDK `Mail` class
/// (`tools/vector-gen/.../MailRef.java`), plus the crypto round trip and
/// the FEIP builders.
final class MailTests: XCTestCase {

    private var vectors: [DomainVectors.MailCase]!

    override func setUpWithError() throws {
        vectors = try DomainVectors.load().mail
        XCTAssertFalse(vectors.isEmpty)
    }

    // MARK: - wire parity

    /// Decode what Android wrote, re-encode it, get the same bytes back.
    /// Field order is the part a JSON round trip does not give you for
    /// free, and it is what the id hashes over.
    func testDecodeAndReEncodeIsByteIdentical() throws {
        for v in vectors {
            let mail = try Mail.fromJson(v.json)
            XCTAssertEqual(mail.wireJson(), v.json, "vector \(v.label)")
        }
    }

    /// `checkIdWithCreate()` reproduces Java's derivation, including the
    /// exact bytes it hashes.
    func testDerivedIdMatchesJava() throws {
        for v in vectors {
            var mail = try Mail.fromJson(v.json)
            mail.id = nil
            XCTAssertEqual(mail.wireJson(), v.idSourceJson, "vector \(v.label) id source")
            mail.checkIdWithCreate()
            XCTAssertEqual(mail.id, v.derivedIdWithoutIdField, "vector \(v.label) id")
        }
    }

    /// A mail that already has an id keeps it — an on-chain mail's id is
    /// its carve txid and must never be recomputed from content.
    func testCheckIdLeavesAnExistingIdAlone() throws {
        let onChain = try XCTUnwrap(vectors.first { $0.label == "on-chain-received" })
        var mail = try Mail.fromJson(onChain.json)
        let txid = mail.id
        XCTAssertNotNil(txid)
        mail.checkIdWithCreate()
        XCTAssertEqual(mail.id, txid)
    }

    /// Gson's HTML escaping is *disabled* on this path, unlike
    /// `Hat.toBytes()`. A body full of `< > & ' =` is the case where
    /// reaching for the wrong writer would silently change the id.
    func testHtmlEscapableBodyIsNotEscaped() throws {
        let v = try XCTUnwrap(vectors.first { $0.label == "local-draft-html-escapable" })
        XCTAssertTrue(v.json.contains("a<b & c='d' => e"), "the vector itself should be unescaped")
        let mail = try Mail.fromJson(v.json)
        XCTAssertEqual(mail.wireJson(), v.json)
        XCTAssertFalse(mail.wireJson().contains("\\u003c"))
    }

    /// `Mail.draft` derives the id from `{from, to, content}` alone, which
    /// is the shape Android's compose screen derives from. Stamping any
    /// other field first would give a different id for the same draft.
    func testDraftMatchesAndroidsDerivation() throws {
        let v = try XCTUnwrap(vectors.first { $0.label == "local-draft" })
        let android = try Mail.fromJson(v.json)
        let draft = Mail.draft(
            from: try XCTUnwrap(android.from),
            to: try XCTUnwrap(android.to),
            content: try XCTUnwrap(android.content)
        )
        XCTAssertEqual(draft.id, v.derivedIdWithoutIdField)
    }

    func testFieldsDecodeWithTheRightTypes() throws {
        let v = try XCTUnwrap(vectors.first { $0.label == "full" })
        let mail = try Mail.fromJson(v.json)
        XCTAssertEqual(mail.alg, "EccK1AesCbc256@No1_NrC7")
        XCTAssertEqual(mail.birthTime, 1_755_100_000)
        XCTAssertEqual(mail.birthHeight, 4_100_000)
        XCTAssertEqual(mail.lastHeight, 4_100_000)
        XCTAssertEqual(mail.active, true)
        XCTAssertEqual(mail.onChain, true)
        XCTAssertEqual(mail.decrypted, true)
        XCTAssertEqual(mail.unread, true)
        XCTAssertEqual(mail.noticeFee, 10_000)
        XCTAssertEqual(mail.objName, "Mail")
    }

    /// A field we do not model must not break decoding — the chain index
    /// is free to grow.
    func testUnknownFieldsAreIgnored() throws {
        let mail = try Mail.fromJson(#"{"from":"F1","to":"F2","somethingNew":{"a":1}}"#)
        XCTAssertEqual(mail.from, "F1")
    }

    // MARK: - direction

    func testDirectionAndCounterparty() {
        let me = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
        let them = "F6vqNGkbAqZQ1YkPWLcXfNfwvJXCTGmzUM"

        let incoming = Mail(from: them, to: me)
        XCTAssertTrue(incoming.isIncoming(for: me))
        XCTAssertEqual(incoming.counterparty(for: me), them)

        let outgoing = Mail(from: me, to: them)
        XCTAssertFalse(outgoing.isIncoming(for: me))
        XCTAssertEqual(outgoing.counterparty(for: me), them)

        // A note to self files under Sent, not Inbox.
        let selfMail = Mail(from: me, to: me)
        XCTAssertFalse(selfMail.isIncoming(for: me))
        XCTAssertEqual(selfMail.counterparty(for: me), me)
    }

    func testCounterpartyNameFallsBackToFid() {
        let me = "F-me", them = "F-them"
        XCTAssertEqual(Mail(from: them, to: me).counterpartyName(for: me), them)
        XCTAssertEqual(
            Mail(from: them, to: me, fromName: "alice").counterpartyName(for: me), "alice"
        )
        XCTAssertEqual(
            Mail(from: me, to: them, toName: "bob").counterpartyName(for: me), "bob"
        )
    }

    // MARK: - crypto round trip

    func testEncryptThenParseDetailBothSides() throws {
        let (sendPriv, sendPub) = try keypair(0x11)
        let (recvPriv, recvPub) = try keypair(0x22)
        let sender = try FchAddress(publicKey: sendPub).fid
        let recipient = try FchAddress(publicKey: recvPub).fid

        var mail = Mail.draft(from: sender, to: recipient, content: "老地方见 🚀")
        try mail.encryptContent(privkey: sendPriv, recipientPubkey: recvPub)

        XCTAssertNil(mail.content, "the plaintext must not survive encryption")
        XCTAssertNotNil(mail.cipher)
        XCTAssertEqual(mail.alg, "EccK1AesGcm256@No1_NrC7")

        var asRecipient = mail
        XCTAssertTrue(asRecipient.parseDetail(privkey: recvPriv))
        XCTAssertEqual(asRecipient.content, "老地方见 🚀")
        XCTAssertEqual(asRecipient.decrypted, true)

        // The sender re-reads their own outbox — the reason for AsyTwoWay.
        var asSender = mail
        XCTAssertTrue(asSender.parseDetail(privkey: sendPriv))
        XCTAssertEqual(asSender.content, "老地方见 🚀")
    }

    /// `from == to` is sealed one-way, because Java cannot resolve an
    /// AsyTwoWay envelope whose two pubkeys are equal.
    func testNoteToSelfIsSealedOneWay() throws {
        let (priv, pub) = try keypair(0x33)
        let me = try FchAddress(publicKey: pub).fid

        var mail = Mail.draft(from: me, to: me, content: "renew the domain")
        try mail.encryptContent(privkey: priv, recipientPubkey: pub)

        let envelope = try XCTUnwrap(mail.cipher)
        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(envelope.utf8)) as? [String: Any]
        )
        XCTAssertEqual(json["type"] as? String, "AsyOneWay")
        XCTAssertNil(json["pubkeyB"])

        var copy = mail
        XCTAssertTrue(copy.parseDetail(privkey: priv))
        XCTAssertEqual(copy.content, "renew the domain")
    }

    /// An unopenable mail is reported, not thrown — one bad row must not
    /// abort a mailbox sync, and the row still names its sender.
    func testParseDetailFailsSoftly() throws {
        let (sendPriv, _) = try keypair(0x44)
        let (_, recvPub) = try keypair(0x55)
        let (strangerPriv, _) = try keypair(0x66)

        var mail = Mail.draft(from: "F-a", to: "F-b", content: "secret")
        try mail.encryptContent(privkey: sendPriv, recipientPubkey: recvPub)

        var stranger = mail
        XCTAssertFalse(stranger.parseDetail(privkey: strangerPriv))
        XCTAssertNil(stranger.content)
        XCTAssertEqual(stranger.decrypted, false)

        var empty = Mail(from: "F-a", to: "F-b")
        XCTAssertFalse(empty.parseDetail(privkey: strangerPriv))
        XCTAssertEqual(empty.decrypted, false)
    }

    func testEncryptWithoutContentThrows() throws {
        let (priv, pub) = try keypair(0x77)
        var mail = Mail(from: "F-a", to: "F-b")
        XCTAssertThrowsError(try mail.encryptContent(privkey: priv, recipientPubkey: pub))
    }

    // MARK: - search

    func testMatchesCoversAddressingAndDecryptedBody() throws {
        var mail = Mail(from: "F-alice", to: "F-bob", fromName: "Alice", toName: "Bob", id: "abc123")
        XCTAssertTrue(mail.matches(query: "alice"))
        XCTAssertTrue(mail.matches(query: "BOB"))
        XCTAssertTrue(mail.matches(query: "abc"))
        XCTAssertFalse(mail.matches(query: "carol"))
        XCTAssertFalse(mail.matches(query: "   "))

        // The body joins the search only once it is decrypted in memory.
        XCTAssertFalse(mail.matches(query: "rendezvous"))
        mail.content = "rendezvous at six"
        XCTAssertTrue(mail.matches(query: "rendezvous"))
    }

    // MARK: - FEIP

    func testSendCarveShape() throws {
        let carve = try MailFeip.sendCarve(cipher: #"{"type":"AsyTwoWay","cipher":"abc"}"#)
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(carve.utf8)) as? [String: Any]
        )
        XCTAssertEqual(root["type"] as? String, "FEIP")
        XCTAssertEqual(root["sn"] as? String, "7")
        XCTAssertEqual(root["ver"] as? String, "4")
        XCTAssertEqual(root["name"] as? String, "Mail")
        let data = try XCTUnwrap(root["data"] as? [String: Any])
        XCTAssertEqual(data["op"] as? String, "send")
        XCTAssertEqual(data["cipher"] as? String, #"{"type":"AsyTwoWay","cipher":"abc"}"#)
        // makeSend sets nothing else.
        XCTAssertEqual(Set(data.keys), ["op", "cipher"])
    }

    func testDeleteAndRecoverOps() throws {
        let del = try MailFeip.envelope(opJson: MailFeip.deleteOp(mailIds: ["a", "b"]))
        let delData = try opData(del)
        XCTAssertEqual(delData["op"] as? String, "delete")
        XCTAssertEqual(delData["mailIds"] as? [String], ["a", "b"])

        let rec = try MailFeip.envelope(opJson: MailFeip.recoverOp(mailIds: ["a"]))
        let recData = try opData(rec)
        XCTAssertEqual(recData["op"] as? String, "recover")
        XCTAssertEqual(recData["mailIds"] as? [String], ["a"])
    }

    /// The limit is checked against the whole carve, not the body: the
    /// FEIP envelope plus base64 ciphertext is most of the payload, so a
    /// body that looks safely under 4 KB can still overflow.
    func testOversizeCarveIsRejected() throws {
        let big = String(repeating: "A", count: MailFeip.maxOpReturnSize)
        XCTAssertThrowsError(try MailFeip.sendCarve(cipher: big)) { error in
            guard case MailFeip.Failure.tooLarge = error else {
                return XCTFail("expected tooLarge, got \(error)")
            }
        }
        // Just under, with room for the envelope, is fine.
        XCTAssertNoThrow(try MailFeip.sendCarve(cipher: String(repeating: "A", count: 3900)))
    }

    // MARK: - helpers

    private func keypair(_ byte: UInt8) throws -> (Data, Data) {
        let priv = Data(repeating: byte, count: 32)
        return (priv, try Secp256k1.publicKey(fromPrivateKey: priv))
    }

    private func opData(_ carve: String) throws -> [String: Any] {
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(carve.utf8)) as? [String: Any]
        )
        return try XCTUnwrap(root["data"] as? [String: Any])
    }
}
