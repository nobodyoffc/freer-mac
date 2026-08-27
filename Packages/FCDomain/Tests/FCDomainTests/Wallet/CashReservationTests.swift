import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// Two transactions being built at once must not choose the same
/// cash.
///
/// This is the normal case in this app, not an exotic one: the chat
/// outbox, mail retries and contact syncs all carve in the background
/// while the user is doing something in a pane. Coin selection is
/// largest-first and deterministic, so two builds reading the same
/// snapshot make *identical* choices — and the second broadcast is
/// rejected by the node as a mempool conflict.
final class CashReservationTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("CashReservationTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSessions(passwords pwds: [String], fapi: any FapiCalling) throws -> [ActiveSession] {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("reservation-tests".utf8), kdfKind: .legacySha256
        )
        var sessions: [ActiveSession] = []
        for (i, pwd) in pwds.enumerated() {
            let priv = Hash.sha256(Data(pwd.utf8))
            let info = try configure.addMain(privkey: priv, label: "L\(i)")
            sessions.append(try configure.unlockMain(fid: info.fid, fapi: fapi))
        }
        return sessions
    }

    private func cash(owner: String, txidByte: UInt8, index: Int, value: Int64, cd: Int64 = 10) throws -> Cash {
        let txid = String(repeating: String(format: "%02x", txidByte), count: 32)
        let h160 = try FchAddress(fid: owner).hash160
        return Cash(
            id: try Cash.makeId(birthTxId: txid, birthIndex: index),
            owner: owner, value: value, type: "P2PKH",
            birthTxId: txid, birthIndex: index,
            lockScript: Cash.canonicalP2PKHLockScript(hash160: h160),
            birthHeight: 900, cd: cd
        )
    }

    /// Broadcast-only mock that hands back a distinct txid per call,
    /// so two transactions can be told apart.
    private func broadcastOnly(_ mock: MockFapiClient) {
        let counter = Counter()
        mock.responder = { _ in
            let n = counter.next()
            return try makeResponse(data: String(repeating: String(format: "%02x", UInt8(n)), count: 32))
        }
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0
        func next() -> Int {
            lock.lock(); defer { lock.unlock() }
            value += 1
            return value
        }
    }

    // MARK: - the point

    /// Two sends, back to back, from a wallet holding two cashes
    /// either of which could fund either payment. Without reservation
    /// both pick the larger one; with it, the second picks the other.
    func testASecondTransactionPicksDifferentInputs() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["res-a", "res-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let big = try cash(owner: alice.mainFid, txidByte: 0xA1, index: 0, value: 1_000_000)
        let small = try cash(owner: alice.mainFid, txidByte: 0xB2, index: 0, value: 900_000)
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [big, small],
            bestHeight: 1_000, watermarkHeight: 1_000
        ))

        let first = try await alice.sendFromLive(
            to: bob.mainFid, amount: 400_000, useCache: true
        )
        let second = try await alice.sendFromLive(
            to: bob.mainFid, amount: 400_000, useCache: true
        )

        let firstIds = Set(first.plan.selected.compactMap(\.id))
        let secondIds = Set(second.plan.selected.compactMap(\.id))
        XCTAssertFalse(firstIds.isEmpty)
        XCTAssertTrue(
            firstIds.isDisjoint(with: secondIds),
            "the second transaction reused an input the first one already spent"
        )
    }

    /// The same, with the two builds genuinely interleaved rather than
    /// sequential — a background carve racing a payment.
    func testConcurrentCarveAndSendDoNotCollide() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["race-a", "race-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let cashes = try (0..<4).map {
            try cash(owner: alice.mainFid, txidByte: UInt8(0xC0 + $0), index: $0, value: 500_000)
        }
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: cashes,
            bestHeight: 1_000, watermarkHeight: 1_000
        ))

        async let payment = alice.wallet.send(
            fromAddress: alice.mainFid, privkey: try alice.mainPrikey(),
            to: bob.mainFid, amount: 100_000, useCache: true
        )
        async let carve = alice.wallet.carve(
            fromAddress: alice.mainFid, privkey: try alice.mainPrikey(),
            opReturn: #"{"type":"FEIP","sn":"1","ver":"5"}"#, useCache: true
        )

        let (paid, carved) = try await (payment, carve)
        let paidIds = Set(paid.plan.selected.compactMap(\.id))
        let carvedIds = Set(carved.plan.selected.compactMap(\.id))
        XCTAssertTrue(
            paidIds.isDisjoint(with: carvedIds),
            "a background carve and a payment funded themselves from the same cash"
        )
    }

    /// A claim is a loan, not a forfeiture: a refused transaction has
    /// to give the cash back, or the user quietly loses the use of it.
    func testARefusedTransactionReleasesItsInputs() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["release-a", "release-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let only = try cash(owner: alice.mainFid, txidByte: 0xD3, index: 0, value: 1_000_000)
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [only],
            bestHeight: 1_000, watermarkHeight: 1_000
        ))

        alice.txApprover = { _ in false }
        do {
            _ = try await alice.sendFromLive(to: bob.mainFid, amount: 100_000, useCache: true)
            XCTFail("expected the refusal to throw")
        } catch WalletService.Failure.declinedByUser {
            // expected
        }

        let snap = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.mainFid))
        XCTAssertFalse(
            try XCTUnwrap(snap.cashes.first { $0.id == only.id }).pendingSpend,
            "a declined transaction must not leave its inputs reserved"
        )

        // And the cash really is usable again.
        alice.txApprover = { _ in true }
        _ = try await alice.sendFromLive(to: bob.mainFid, amount: 100_000, useCache: true)
    }

    /// A rejected broadcast releases too — the node never took it, so
    /// nothing is pending.
    func testAFailedBroadcastReleasesItsInputs() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["bcast-a", "bcast-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        mock.responder = { _ in FapiResponse(code: 1, message: "rejected") }

        let only = try cash(owner: alice.mainFid, txidByte: 0xE4, index: 0, value: 1_000_000)
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [only],
            bestHeight: 1_000, watermarkHeight: 1_000
        ))

        do {
            _ = try await alice.sendFromLive(to: bob.mainFid, amount: 100_000, useCache: true)
            XCTFail("expected the broadcast failure to throw")
        } catch {
            // expected
        }

        let snap = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.mainFid))
        XCTAssertFalse(try XCTUnwrap(snap.cashes.first { $0.id == only.id }).pendingSpend)
    }

    /// One cash, two payments: the second is funded by the *change*
    /// the first one minted, not by the original — which is both
    /// features working together, reservation keeping the spent input
    /// out and the unconfirmed-chain rule letting the change straight
    /// back in.
    func testTheSecondTransactionSpendsTheFirstsChange() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["chain-a", "chain-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let only = try cash(owner: alice.mainFid, txidByte: 0xF5, index: 0, value: 1_000_000)
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [only],
            bestHeight: 1_000, watermarkHeight: 1_000
        ))

        let first = try await alice.sendFromLive(to: bob.mainFid, amount: 100_000, useCache: true)
        let second = try await alice.sendFromLive(to: bob.mainFid, amount: 100_000, useCache: true)

        let secondInput = try XCTUnwrap(second.plan.selected.first)
        XCTAssertNotEqual(secondInput.id, only.id, "the spent cash must not fund a second transaction")
        XCTAssertEqual(secondInput.birthTxId, first.remoteTxid, "it should be the first tx's change")
        XCTAssertEqual(secondInput.unconfirmedDepth, 1)

        // And the chain of depths keeps counting.
        let snap = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.mainFid))
        let secondChangeId = try Cash.makeId(birthTxId: second.remoteTxid, birthIndex: 1)
        XCTAssertEqual(
            try XCTUnwrap(snap.cashes.first { $0.id == secondChangeId }).unconfirmedDepth, 2
        )
    }
}
