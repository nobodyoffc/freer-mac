import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The mail send pipeline through `ActiveSession`: quote → encrypt →
/// FEIP wrap → CD-aware coin-select → build (**pay + change +
/// OP_RETURN**) → Schnorr-sign → broadcast → store.
///
/// The assertions decode the broadcast raw hex, because the recipient
/// output is not a detail of the transaction — it *is* the mail's
/// address, and nothing else on chain records who the mail was for.
final class MailSendTests: XCTestCase {

    private var baseDir: URL!
    private var manager: ConfigureManager!

    /// The recipient's key. Their FID and pubkey are what the staged
    /// `base.freerByIds` returns, and their privkey is what proves the
    /// mail we broadcast is one they can actually open.
    private let recipientPrivkey = Data(repeating: 0xB7, count: 32)

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("MailSendTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        manager = try ConfigureManager(baseDirectory: baseDir)
    }

    override func tearDownWithError() throws {
        manager = nil
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    // MARK: - fixtures

    private func makeSession(fapi: any FapiCalling) throws -> ActiveSession {
        let configure = try manager.createConfigure(
            password: Data("mail-tests".utf8), kdfKind: .legacySha256
        )
        let info = try configure.addMain(
            privkey: Hash.sha256(Data("mailer".utf8)), label: "mailer"
        )
        return try configure.unlockMain(fid: info.fid, fapi: fapi)
    }

    private func recipientPubkey() throws -> Data {
        try Secp256k1.publicKey(fromPrivateKey: recipientPrivkey)
    }

    private func recipientFid() throws -> String {
        try FchAddress(publicKey: recipientPubkey()).fid
    }

    private func cashDict(owner: String, txid: String, value: Int64) throws -> [String: Any] {
        let h160 = try FchAddress(fid: owner).hash160
        return [
            "id": try Cash.makeId(birthTxId: txid, birthIndex: 0),
            "owner": owner,
            "value": value,
            "type": "P2PKH",
            "birthTxId": txid,
            "birthIndex": 0,
            "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
        ]
    }

    /// Stages `base.freerByIds`, `base.cashValid` and `base.broadcastTx`.
    /// `noticeFee` and `pubkey` are what the recipient's on-chain record
    /// says; nil `pubkey` models a FID that has never spent.
    private func stage(
        _ mock: MockFapiClient,
        senderFid: String,
        recipientFid: String,
        noticeFee: String?,
        pubkey: Data?,
        funds: Int64 = 10_000_000,
        onBroadcast: @escaping @Sendable (String) -> Void = { _ in }
    ) throws {
        var freer: [String: Any] = ["id": recipientFid]
        if let noticeFee { freer["noticeFee"] = noticeFee }
        if let pubkey { freer["pubkey"] = pubkey.hex }

        mock.responder = { call in
            switch call.api {
            case "base.freerByIds":
                return try makeResponse(data: [recipientFid: freer])
            case "base.cashValid":
                return try makeResponse(
                    data: [try self.cashDict(
                        owner: senderFid,
                        txid: String(repeating: "ab", count: 32),
                        value: funds
                    )],
                    // Below CDD_CHECK_HEIGHT → no CoinDays requirement.
                    bestHeight: 3_500_000
                )
            case "base.broadcastTx":
                let params = try JSONSerialization.jsonObject(with: call.params!) as? [String: Any]
                onBroadcast((params?["rawTx"] as? String) ?? "")
                return try makeResponse(data: "mail-txid-001")
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }
    }

    /// The serialized bytes of a P2PKH output paying exactly `value` to
    /// `fid`: 8-byte LE value, 0x19 script length, then the script.
    private func payOutputBytes(to fid: String, value: Int64) throws -> Data {
        var out = Data()
        var le = UInt64(value).littleEndian
        withUnsafeBytes(of: &le) { out.append(contentsOf: $0) }
        out.append(0x19)
        out.append(try ScriptBuilder.p2pkhOutput(hash160: FchAddress(fid: fid).hash160).bytes)
        return out
    }

    // MARK: - quote

    func testQuoteUsesTheDefaultFeeWhenNoneIsPublished() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: nil, pubkey: try recipientPubkey())

        let quote = try await session.quoteMail(to: try recipientFid())
        XCTAssertEqual(quote.fee, .pay(NoticeFee.defaultFeeSats))
        XCTAssertEqual(quote.recipientPubkey, try recipientPubkey())
        XCTAssertTrue(quote.canSend)
    }

    func testQuoteHonoursAPublishedFee() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: "0.5", pubkey: try recipientPubkey())

        let quote = try await session.quoteMail(to: try recipientFid())
        XCTAssertEqual(quote.fee, .pay(50_000_000))
        XCTAssertEqual(quote.publishedNoticeFee, "0.5")
    }

    /// A FID that has never published a pubkey cannot be mailed at all —
    /// there is nothing to encrypt to. The quote says so before the user
    /// writes a word.
    func testQuoteReportsAMissingPubkey() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: nil, pubkey: nil)

        let quote = try await session.quoteMail(to: try recipientFid())
        XCTAssertNil(quote.recipientPubkey)
        XCTAssertFalse(quote.canSend)
    }

    func testQuoteRefusesAFeeOverThePreferenceLimit() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        var prefs = try session.preferences.load()
        prefs.maxPayingNoticeFeeSats = 1 * NoticeFee.satsPerCoin
        try session.preferences.save(prefs)

        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: "5", pubkey: try recipientPubkey())

        let quote = try await session.quoteMail(to: try recipientFid())
        XCTAssertEqual(
            quote.fee,
            .refuse(requested: 5 * NoticeFee.satsPerCoin, limit: NoticeFee.satsPerCoin)
        )
        XCTAssertFalse(quote.canSend)
    }

    /// Replying matches a larger fee the correspondent paid us — and the
    /// received fee is in satoshis, the same unit as everything else
    /// here (Android compares it against a coin-denominated double).
    func testQuoteMatchesTheFeeAReplyReceived() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: "0.0001", pubkey: try recipientPubkey())

        let received = Mail(from: try recipientFid(), to: session.mainFid, noticeFee: 5_000_000)
        let quote = try await session.quoteMail(to: try recipientFid(), replyingTo: received)
        XCTAssertEqual(quote.fee, .pay(5_000_000))
    }

    // MARK: - send

    func testSendPaysTheRecipientAndCarvesTheFeip() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let recipient = try recipientFid()

        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, recipientFid: recipient,
                  noticeFee: nil, pubkey: try recipientPubkey(),
                  onBroadcast: { broadcast.value = $0 })

        let quote = try await session.quoteMail(to: recipient)
        let sent = try await session.sendMailOnChain(quote: quote, content: "老地方见 🚀")

        XCTAssertEqual(sent.txid, "mail-txid-001")
        XCTAssertEqual(sent.noticeFeePaidSats, NoticeFee.defaultFeeSats)

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))

        // 1. An output paying exactly the notice fee to the recipient.
        let payOutput = try payOutputBytes(to: recipient, value: NoticeFee.defaultFeeSats)
        let payRange = try XCTUnwrap(
            raw.range(of: payOutput),
            "the transaction must pay the recipient — that payment is the mail's address"
        )

        // 2. The FEIP envelope, in an OP_RETURN after the pay output.
        let feipPrefix = Data(#"{"type":"FEIP","sn":"7","ver":"4","name":"Mail","data":{"#.utf8)
        let feipRange = try XCTUnwrap(raw.range(of: feipPrefix))
        XCTAssertLessThan(payRange.lowerBound, feipRange.lowerBound,
                          "pay output comes before the OP_RETURN, per TxHandler.createTx")
        XCTAssertNotNil(raw.range(of: Data(#""op":"send""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data([0x6A, 0x4D])), "OP_RETURN + PUSHDATA2")

        // 3. Change back to the sender, between the two.
        let changeScript = try ScriptBuilder.p2pkhOutput(
            hash160: FchAddress(fid: session.mainFid).hash160
        ).bytes
        let changeRange = try XCTUnwrap(raw.range(of: changeScript))
        XCTAssertLessThan(payRange.lowerBound, changeRange.lowerBound)
        XCTAssertLessThan(changeRange.lowerBound, feipRange.lowerBound)
    }

    /// The whole point of the exercise: what we broadcast is a mail the
    /// recipient can open with their own key.
    func testTheRecipientCanDecryptWhatWasBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: nil, pubkey: try recipientPubkey())

        let quote = try await session.quoteMail(to: try recipientFid())
        let sent = try await session.sendMailOnChain(quote: quote, content: "meet at six")

        var asRecipient = sent.mail
        XCTAssertTrue(asRecipient.parseDetail(privkey: recipientPrivkey))
        XCTAssertEqual(asRecipient.content, "meet at six")
    }

    /// The stored row: keyed by the carve txid, sealed, and stamped so
    /// it sits at the top of the mailbox until a sync confirms it.
    func testSentMailIsStoredSealedAndUnconfirmed() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: nil, pubkey: try recipientPubkey())

        let quote = try await session.quoteMail(to: try recipientFid())
        _ = try await session.sendMailOnChain(quote: quote, content: "hello")

        let stored = try XCTUnwrap(try session.mails.get(id: "mail-txid-001"))
        XCTAssertEqual(stored.from, session.mainFid)
        XCTAssertEqual(stored.to, try recipientFid())
        XCTAssertNil(stored.content, "the body must never be persisted in the clear")
        XCTAssertNotNil(stored.cipher)
        XCTAssertNil(stored.onChain, "broadcast is not confirmation")
        XCTAssertEqual(stored.lastHeight, MailsStore.unconfirmedHeight)
        XCTAssertEqual(stored.noticeFee, NoticeFee.defaultFeeSats)
        XCTAssertEqual(stored.unread, false)
        XCTAssertEqual(try session.mails.all().first?.id, "mail-txid-001")
    }

    // MARK: - refusals (nothing may be broadcast)

    func testSendingWithARefusedQuoteThrowsAndBroadcastsNothing() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        var prefs = try session.preferences.load()
        prefs.maxPayingNoticeFeeSats = 1 * NoticeFee.satsPerCoin
        try session.preferences.save(prefs)

        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: "5", pubkey: try recipientPubkey(),
                  onBroadcast: { broadcast.value = $0 })

        let quote = try await session.quoteMail(to: try recipientFid())
        do {
            _ = try await session.sendMailOnChain(quote: quote, content: "hello")
            XCTFail("expected a refusal")
        } catch {
            XCTAssertTrue("\(error)".contains("limit"), "\(error)")
        }
        XCTAssertNil(broadcast.value)
        XCTAssertEqual(try session.mails.all().count, 0)
    }

    func testSendingToAFidWithNoPubkeyThrows() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: nil, pubkey: nil, onBroadcast: { broadcast.value = $0 })

        let quote = try await session.quoteMail(to: try recipientFid())
        do {
            _ = try await session.sendMailOnChain(quote: quote, content: "hello")
            XCTFail("expected a missing-pubkey failure")
        } catch {
            XCTAssertTrue("\(error)".contains("public key"), "\(error)")
        }
        XCTAssertNil(broadcast.value)
    }

    /// The 4 KB limit is checked against the assembled carve, before
    /// anything is signed — a body that only overflows once encrypted
    /// and wrapped must not reach the network and fail there.
    func testAnOversizeBodyIsRejectedBeforeBroadcast() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: nil, pubkey: try recipientPubkey(),
                  onBroadcast: { broadcast.value = $0 })

        let quote = try await session.quoteMail(to: try recipientFid())
        do {
            _ = try await session.sendMailOnChain(
                quote: quote, content: String(repeating: "A", count: MailFeip.maxBodyBytes + 1)
            )
            XCTFail("expected a size failure")
        } catch {
            XCTAssertTrue("\(error)".contains("OP_RETURN"), "\(error)")
        }
        XCTAssertNil(broadcast.value)
        XCTAssertEqual(try session.mails.all().count, 0)
    }

    /// A body of exactly `maxBodyBytes` still goes out — the check must
    /// not be so conservative that it refuses mail the chain would take.
    func testABodyAtExactlyTheLimitIsSent() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: nil, pubkey: try recipientPubkey())

        let quote = try await session.quoteMail(to: try recipientFid())
        let sent = try await session.sendMailOnChain(
            quote: quote, content: String(repeating: "A", count: MailFeip.maxBodyBytes)
        )
        XCTAssertEqual(sent.txid, "mail-txid-001")
    }

    // MARK: - delete / recover carves

    /// Deleting pays nobody: only a `send` addresses anyone.
    func testDeleteCarvePaysNoRecipient() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: nil, pubkey: try recipientPubkey(),
                  onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveMailDeleteOnChain(mailIds: ["m1", "m2"])

        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"delete""#.utf8)))
        XCTAssertNotNil(raw.range(of: Data(#""mailIds":["m1","m2"]"#.utf8)))
        XCTAssertNil(
            raw.range(of: try payOutputBytes(to: try recipientFid(), value: NoticeFee.defaultFeeSats)),
            "a delete carve must not pay anyone"
        )
    }

    func testRecoverCarveUsesTheRecoverOp() async throws {
        let mock = MockFapiClient()
        let session = try makeSession(fapi: mock)
        let broadcast = Captured()
        try stage(mock, senderFid: session.mainFid, recipientFid: try recipientFid(),
                  noticeFee: nil, pubkey: try recipientPubkey(),
                  onBroadcast: { broadcast.value = $0 })

        _ = try await session.carveMailDeleteOnChain(mailIds: ["m1"], recover: true)
        let raw = Data(fromHex: try XCTUnwrap(broadcast.value))
        XCTAssertNotNil(raw.range(of: Data(#""op":"recover""#.utf8)))
    }
}

/// A reference box for values written from the mock's `@Sendable`
/// responder and read back on the test's thread.
private final class Captured: @unchecked Sendable {
    var value: String?
}
