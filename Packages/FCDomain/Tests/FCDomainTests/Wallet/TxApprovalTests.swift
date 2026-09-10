import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// The approval gate and the unconfirmed-chain bookkeeping — the two
/// halves of "nothing gets signed behind your back, and what you just
/// spent is immediately usable".
final class TxApprovalTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("TxApprovalTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSessions(passwords pwds: [String], fapi: any FapiCalling) throws -> [ActiveSession] {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("approval-tests".utf8), kdfKind: .legacySha256
        )
        var sessions: [ActiveSession] = []
        for (i, pwd) in pwds.enumerated() {
            let priv = Hash.sha256(Data(pwd.utf8))
            let info = try configure.addMain(privkey: priv, label: "L\(i)")
            sessions.append(try configure.unlockMain(fid: info.fid, fapi: fapi))
        }
        return sessions
    }

    private func cash(
        owner: String, txidByte: UInt8, index: Int, value: Int64,
        depth: Int = 0, cd: Int64? = nil
    ) throws -> Cash {
        let txid = String(repeating: String(format: "%02x", txidByte), count: 32)
        let h160 = try FchAddress(fid: owner).hash160
        return Cash(
            id: try Cash.makeId(birthTxId: txid, birthIndex: index),
            owner: owner, value: value, type: "P2PKH",
            birthTxId: txid, birthIndex: index,
            lockScript: Cash.canonicalP2PKHLockScript(hash160: h160),
            cd: cd,
            unconfirmedDepth: depth
        )
    }

    private func broadcastOnly(_ mock: MockFapiClient) {
        mock.responder = { call in
            switch call.api {
            case "base.broadcastTx":
                return try makeResponse(data: String(repeating: "cd", count: 32))
            default:
                XCTFail("unexpected api: \(call.api)")
                return FapiResponse(code: 1, message: "unexpected")
            }
        }
    }

    // MARK: - the gate

    func testApproverSeesTheBuiltTransactionAndCanAllowIt() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["gate-a", "gate-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let seen = PreviewBox()
        alice.txApprover = { preview in
            await seen.set(preview)
            return .approve
        }

        let inputs = [try cash(owner: alice.mainFid, txidByte: 0x11, index: 0, value: 1_000_000, cd: 7)]
        _ = try await alice.sendFromLive(
            to: bob.mainFid, amount: 250_000, using: inputs
        )

        let captured = await seen.value
        let preview = try XCTUnwrap(captured)
        XCTAssertEqual(preview.kind, .payment)
        XCTAssertEqual(preview.from, alice.mainFid)
        XCTAssertEqual(preview.inputs.count, 1)
        XCTAssertEqual(preview.coinDaysDestroyed, 7)

        // Outputs are decoded back out of the built scripts, so the
        // recipient is named and the change is recognised as ours.
        XCTAssertEqual(preview.outputs.count, 2)
        XCTAssertEqual(preview.outputs[0].fid, bob.mainFid)
        XCTAssertEqual(preview.outputs[0].amount, 250_000)
        XCTAssertFalse(preview.outputs[0].isSelf)
        XCTAssertTrue(preview.outputs[1].isSelf)

        // What actually leaves = the payment + the fee, not the change.
        XCTAssertEqual(preview.leaving, 250_000 + preview.fee)
        XCTAssertEqual(preview.payments.count, 1)
    }

    func testDecliningStopsTheSendBeforeAnythingIsBroadcast() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["deny-a", "deny-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        alice.txApprover = { _ in .decline }
        let inputs = [try cash(owner: alice.mainFid, txidByte: 0x22, index: 0, value: 1_000_000)]

        do {
            _ = try await alice.sendFromLive(to: bob.mainFid, amount: 100_000, using: inputs)
            XCTFail("expected throw")
        } catch WalletService.Failure.declinedByUser {
            // Nothing hit the wire, and no cash was flagged.
            XCTAssertTrue(mock.recorded.isEmpty)
            let snap = try alice.cashes.snapshot(forAddress: alice.mainFid)
            XCTAssertNil(snap)
        }
    }

    // MARK: - choosing other cash

    /// Swapping the inputs in the dialog rebuilds the same payment from
    /// the picked cash, shows it again, and moves the reservation with it.
    func testReselectingInputsRebuildsFromTheChosenCashAndAsksAgain() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["swap-a", "swap-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let old = try cash(owner: alice.mainFid, txidByte: 0x81, index: 0, value: 5_000_000, cd: 900)
        let young = try cash(owner: alice.mainFid, txidByte: 0x82, index: 0, value: 1_000_000, cd: 0)
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [old, young],
            bestHeight: 1_000, watermarkHeight: 1_000
        ))

        let asked = PreviewLog()
        alice.txApprover = { preview in
            let count = await asked.append(preview)
            return count == 1 ? .reselect([young]) : .approve
        }

        let result = try await alice.sendFromLive(to: bob.mainFid, amount: 100_000, using: [old])

        let previews = await asked.all
        XCTAssertEqual(previews.count, 2, "the rebuilt transaction is shown again")
        XCTAssertEqual(previews[0].reselection, .payment(amount: 100_000))
        XCTAssertEqual(previews[0].inputs.map(\.id), [old.id])
        XCTAssertEqual(previews[1].inputs.map(\.id), [young.id])
        XCTAssertEqual(previews[1].coinDaysDestroyed, 0)
        XCTAssertEqual(result.plan.selected.map(\.id), [young.id])

        let snap = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.mainFid))
        XCTAssertFalse(
            try XCTUnwrap(snap.cashes.first { $0.id == old.id }).pendingSpend,
            "the cash swapped out is free again"
        )
        XCTAssertTrue(try XCTUnwrap(snap.cashes.first { $0.id == young.id }).pendingSpend)
    }

    /// A carve can be rebuilt too, and the choice may keep the cash the
    /// carve already holds even though the cache marks it as being spent.
    func testCarveReselectionCanKeepTheCashItAlreadyHolds() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["swap-carve"], fapi: mock)[0]
        broadcastOnly(mock)

        let aged = try cash(owner: alice.mainFid, txidByte: 0xA1, index: 0, value: 50_000, cd: 3)
        let fresh = try cash(owner: alice.mainFid, txidByte: 0xA2, index: 0, value: 2_000_000, cd: 0)
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [aged, fresh],
            bestHeight: 1_000, watermarkHeight: 1_000
        ))
        // What the dialog reads while the carve holds `aged`.
        let heldAged: Cash = {
            var row = aged
            row.pendingSpend = true
            return row
        }()

        let asked = PreviewLog()
        alice.txApprover = { preview in
            let count = await asked.append(preview)
            return count == 1 ? .reselect([heldAged, fresh]) : .approve
        }

        _ = try await alice.wallet.carve(
            fromAddress: alice.mainFid,
            privkey: try alice.mainPrikey(),
            opReturn: #"{"type":"FEIP","sn":"1","ver":"5","data":{"op":"add"}}"#,
            minimumCd: 1,
            useCache: true
        )

        let previews = await asked.all
        XCTAssertEqual(previews.count, 2)
        XCTAssertEqual(previews[0].inputs.map(\.id), [aged.id], "the aged cash alone covers the CoinDay")
        XCTAssertEqual(previews[0].requiredCd, 1)
        XCTAssertEqual(Set(previews[1].inputs.map(\.id)), [aged.id, fresh.id])
    }

    /// CoinDays are counted at the cached chain height, not taken from
    /// the server: a cash the index last touched while it was young
    /// still funds a carve once it has aged.
    func testCarveCountsCoinDaysAtTheChainHeightNotTheServerFigure() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["cd-live"], fapi: mock)[0]
        broadcastOnly(mock)

        // The server says 0 CD; two days at 10 coins is 20.
        var aged = try cash(owner: alice.mainFid, txidByte: 0xB1, index: 0, value: 1_000_000_000, cd: 0)
        aged.birthHeight = 1_000
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [aged],
            bestHeight: 1_000 + 2 * Cash.blocksPerCoinDay,
            watermarkHeight: 1_000 + 2 * Cash.blocksPerCoinDay
        ))

        let seen = PreviewBox()
        alice.txApprover = { preview in
            await seen.set(preview)
            return .approve
        }

        _ = try await alice.wallet.carve(
            fromAddress: alice.mainFid,
            privkey: try alice.mainPrikey(),
            opReturn: #"{"type":"FEIP","sn":"1","ver":"5","data":{"op":"add"}}"#,
            minimumCd: 5,
            useCache: true
        )

        let captured = await seen.value
        let preview = try XCTUnwrap(captured)
        XCTAssertEqual(preview.coinDaysDestroyed, 20)
        let cached = try XCTUnwrap(try alice.wallet.cachedSnapshot(forAddress: alice.mainFid))
        XCTAssertEqual(cached.cashes.first { $0.id == aged.id }?.cd, 20)
    }

    /// A reorg's inputs are the instruction itself, so the gate can't be
    /// answered with other cash; trying counts as a refusal.
    func testReselectingWhereItIsNotOfferedDeclines() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["swap-reorg"], fapi: mock)[0]
        broadcastOnly(mock)

        let inputs = try (0..<2).map {
            try cash(owner: alice.mainFid, txidByte: UInt8(0x90 + $0), index: $0, value: 200_000)
        }
        let asked = PreviewLog()
        alice.txApprover = { preview in
            _ = await asked.append(preview)
            return .reselect(inputs)
        }

        do {
            _ = try await alice.reorganizeFromLive(inputs: inputs, shape: .consolidate)
            XCTFail("expected throw")
        } catch WalletService.Failure.declinedByUser {
            XCTAssertTrue(mock.recorded.isEmpty)
        }
        let previews = await asked.all
        XCTAssertNil(previews.first?.reselection)
    }

    /// Every path that signs is gated, not just the pane that has a
    /// Send button — a carve writes to a public ledger and costs
    /// money, so it is exactly the kind of thing the setting exists
    /// for.
    func testCarveIsGatedAndCarriesItsPayload() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["carve-gate"], fapi: mock)[0]
        mock.responder = { call in
            switch call.api {
            case "base.cashValid":
                let h160 = try FchAddress(fid: alice.mainFid).hash160
                return try makeResponse(data: [[
                    "id": try Cash.makeId(birthTxId: String(repeating: "ab", count: 32), birthIndex: 0),
                    "owner": alice.mainFid,
                    "value": 1_000_000,
                    "type": "P2PKH",
                    "birthTxId": String(repeating: "ab", count: 32),
                    "birthIndex": 0,
                    "cd": 5,
                    "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
                ]], bestHeight: 100)
            case "base.broadcastTx":
                return try makeResponse(data: String(repeating: "ef", count: 32))
            default:
                XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
            }
        }

        let seen = PreviewBox()
        alice.txApprover = { preview in
            await seen.set(preview)
            return .approve
        }

        let feip = #"{"type":"FEIP","sn":"1","ver":"5","data":{"op":"add"}}"#
        _ = try await alice.wallet.carve(
            fromAddress: alice.mainFid,
            privkey: try alice.mainPrikey(),
            opReturn: feip
        )

        let captured = await seen.value
        let preview = try XCTUnwrap(captured)
        XCTAssertEqual(preview.kind, .carve)
        XCTAssertEqual(preview.opReturn, feip)
        // sn 1 is Contact — the dialog can say what is being written
        // rather than showing a serial number.
        XCTAssertEqual(preview.feipName, FeipProtocol.displayName(forSn: "1"))
        // The data output pays nobody, and is marked as such.
        XCTAssertTrue(preview.outputs.contains { $0.isOpReturn })
        // A paymentless carve costs only the fee.
        XCTAssertEqual(preview.leaving, preview.fee)
    }

    func testReorgIsGated() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["reorg-gate"], fapi: mock)[0]
        broadcastOnly(mock)

        let seen = PreviewBox()
        alice.txApprover = { preview in
            await seen.set(preview)
            return .approve
        }
        let inputs = try (0..<2).map {
            try cash(owner: alice.mainFid, txidByte: UInt8(0x30 + $0), index: $0, value: 200_000)
        }
        _ = try await alice.reorganizeFromLive(inputs: inputs, shape: .consolidate)

        let captured = await seen.value
        let preview = try XCTUnwrap(captured)
        XCTAssertEqual(preview.kind, .reorg)
        // Every output is ours, so nothing "leaves" except the fee.
        XCTAssertTrue(preview.outputs.allSatisfy(\.isSelf))
        XCTAssertEqual(preview.leaving, preview.fee)
    }

    /// The setting is what decides whether anyone is asked. With it
    /// off, the installed approver is never consulted.
    func testConfirmationSettingOffBypassesTheApprover() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["setting-a", "setting-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let asked = PreviewBox()
        alice.txApprover = { preview in
            await asked.set(preview)
            return .decline                   // would refuse, if asked
        }
        XCTAssertTrue(alice.confirmBeforeSigning, "on by default, as on Android")

        try alice.preferences.update { $0.confirmBeforeSigning = false }
        alice.reloadPreferences()
        XCTAssertFalse(alice.confirmBeforeSigning)

        let inputs = [try cash(owner: alice.mainFid, txidByte: 0x44, index: 0, value: 1_000_000)]
        _ = try await alice.sendFromLive(to: bob.mainFid, amount: 100_000, using: inputs)

        let seen = await asked.value
        XCTAssertNil(seen, "approver must not be consulted when the setting is off")
    }

    // MARK: - unconfirmed chain

    func testChangeFromABroadcastIsSpendableImmediatelyAtDepthOne() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["chain-a", "chain-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let input = try cash(owner: alice.mainFid, txidByte: 0x55, index: 0, value: 1_000_000)
        try alice.cashes.save(CashSnapshot(addr: alice.mainFid, cashes: [input]))

        let first = try await alice.sendFromLive(
            to: bob.mainFid, amount: 100_000, using: [input]
        )

        let snap = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.mainFid))
        // The spent input is out of the spendable set…
        XCTAssertTrue(try XCTUnwrap(snap.cashes.first { $0.id == input.id }).pendingSpend)
        // …and the change is in it, one link deep, ready to spend.
        let changeId = try Cash.makeId(birthTxId: first.remoteTxid, birthIndex: 1)
        let change = try XCTUnwrap(snap.cashes.first { $0.id == changeId })
        XCTAssertEqual(change.unconfirmedDepth, 1)
        XCTAssertEqual(change.localState, .unknown)
        XCTAssertTrue(change.withinUnconfirmedChainLimit)

        // Spending it works and mints depth 2.
        let second = try await alice.sendFromLive(
            to: bob.mainFid, amount: 50_000, using: [change]
        )
        let snap2 = try XCTUnwrap(try alice.cashes.snapshot(forAddress: alice.mainFid))
        let secondChangeId = try Cash.makeId(birthTxId: second.remoteTxid, birthIndex: 1)
        XCTAssertEqual(
            try XCTUnwrap(snap2.cashes.first { $0.id == secondChangeId }).unconfirmedDepth, 2
        )
    }

    func testSpendingRefusesPastTheChainLimit() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["limit-a", "limit-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let deep = try cash(
            owner: alice.mainFid, txidByte: 0x66, index: 0,
            value: 1_000_000, depth: Cash.maxUnconfirmedChain
        )
        do {
            _ = try await alice.sendFromLive(to: bob.mainFid, amount: 10_000, using: [deep])
            XCTFail("expected throw")
        } catch WalletService.Failure.unspendableInput {
            XCTAssertTrue(mock.recorded.isEmpty)
        }

        // The last usable link still works.
        var lastUsable = deep
        lastUsable.unconfirmedDepth = Cash.maxUnconfirmedChain - 1
        _ = try await alice.sendFromLive(to: bob.mainFid, amount: 10_000, using: [lastUsable])
    }

    /// Coin selection has to tell "you have nothing" apart from "you
    /// have plenty, but it is all too deep in the mempool" — the two
    /// have completely different remedies.
    func testSelectionReportsTheChainLimitDistinctly() async throws {
        let mock = MockFapiClient()
        let sessions = try makeSessions(passwords: ["limit-sel-a", "limit-sel-b"], fapi: mock)
        let alice = sessions[0]
        let bob = sessions[1]
        broadcastOnly(mock)

        let deep = try cash(
            owner: alice.mainFid, txidByte: 0x77, index: 0,
            value: 5_000_000, depth: Cash.maxUnconfirmedChain
        )
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [deep], watermarkHeight: 10
        ))

        do {
            _ = try await alice.sendFromLive(
                to: bob.mainFid, amount: 100_000, useCache: true
            )
            XCTFail("expected throw")
        } catch WalletService.Failure.unconfirmedChainLimit(let depth) {
            XCTAssertEqual(depth, Cash.maxUnconfirmedChain)
        }
    }

    /// Confirmation clears the depth: once the chain has the cash, it
    /// is no longer at the end of anything.
    func testSyncResetsDepthOnConfirmation() async throws {
        let mock = MockFapiClient()
        let alice = try makeSessions(passwords: ["depth-reset"], fapi: mock)[0]

        let txid = String(repeating: "9a", count: 32)
        let h160 = try FchAddress(fid: alice.mainFid).hash160
        var pending = try cash(owner: alice.mainFid, txidByte: 0x9a, index: 0, value: 500_000, depth: 3)
        pending.localState = .unknown
        try alice.cashes.save(CashSnapshot(
            addr: alice.mainFid, cashes: [pending],
            bestHeight: 100, watermarkHeight: 100
        ))

        var served = false
        mock.responder = { call in
            guard call.api == "base.search" else {
                XCTFail("unexpected api: \(call.api)"); return FapiResponse(code: 1)
            }
            if served { return try makeResponse(data: [], bestHeight: 130) }
            served = true
            return try makeResponse(data: [[
                "id": pending.id!,
                "owner": alice.mainFid,
                "value": 500_000,
                "type": "P2PKH",
                "birthTxId": txid,
                "birthIndex": 0,
                "valid": true,
                "lastHeight": 130,
                "lockScript": Cash.canonicalP2PKHLockScript(hash160: h160)
            ]], bestHeight: 130)
        }

        let snap = try await alice.wallet.refreshCashes(forFid: alice.mainFid)
        let row = try XCTUnwrap(snap.cashes.first { $0.id == pending.id })
        XCTAssertEqual(row.unconfirmedDepth, 0)
        XCTAssertEqual(row.localState, .onchain)
    }
}

/// Minimal actor box so the approver closure — which is `@Sendable`
/// and runs off whatever executor the send is on — can hand a value
/// back to the test.
private actor PreviewBox {
    private(set) var value: TxPreview?
    func set(_ preview: TxPreview) { value = preview }
}

/// Every preview the approver was shown, in order.
private actor PreviewLog {
    private(set) var all: [TxPreview] = []
    func append(_ preview: TxPreview) -> Int {
        all.append(preview)
        return all.count
    }
}
