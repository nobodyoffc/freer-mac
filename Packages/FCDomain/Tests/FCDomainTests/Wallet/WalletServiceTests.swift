import XCTest
import FCTransport
@testable import FCDomain

final class WalletServiceTests: XCTestCase {

    // MARK: - health

    func testHealthCallShape() async throws {
        let mock = MockFapiClient()
        let svc = WalletService(fapi: mock)

        let ok = try await svc.health(timeoutMs: 1234)
        XCTAssertTrue(ok)

        XCTAssertEqual(mock.recorded.count, 1)
        let r = mock.recorded[0]
        XCTAssertEqual(r.api, "base.health")
        XCTAssertNil(r.params)
        XCTAssertNil(r.fcdsl)
        XCTAssertEqual(r.timeoutMs, 1234)
    }

    func testHealthFailsOnNonZeroCode() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 1, message: "down") }
        let svc = WalletService(fapi: mock)
        let ok = try await svc.health()
        XCTAssertFalse(ok)
    }

    // MARK: - balance

    func testBalanceForFidEncodesFcdslAndDecodesValue() async throws {
        let mock = MockFapiClient()
        // Server returns: {"FAlice": 12345, "FBob": 99}
        mock.responder = { _ in
            try makeResponse(
                data: ["FAlice": 12345, "FBob": 99],
                bestHeight: 800_000
            )
        }
        let svc = WalletService(fapi: mock)
        let balance = try await svc.balance(forFid: "FAlice")

        XCTAssertEqual(balance.fid, "FAlice")
        XCTAssertEqual(balance.satoshis, 12345)
        XCTAssertEqual(balance.bestHeight, 800_000)

        // Verify the request fcdsl was {"ids":["FAlice"]}.
        let r = mock.recorded[0]
        XCTAssertEqual(r.api, "base.balanceByIds")
        let parsed = try JSONSerialization.jsonObject(with: try XCTUnwrap(r.fcdsl)) as? [String: Any]
        XCTAssertEqual(parsed?["ids"] as? [String], ["FAlice"])
    }

    func testBalancesForMultipleFids() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: ["FA": 100, "FB": 200, "FC": 0])
        }
        let svc = WalletService(fapi: mock)
        let bals = try await svc.balances(forFids: ["FA", "FB", "FC"])

        XCTAssertEqual(bals.map { $0.satoshis }, [100, 200, 0])
        XCTAssertEqual(bals.map { $0.fid }, ["FA", "FB", "FC"])
    }

    func testBalanceMissingFidYieldsZero() async throws {
        // Server only knows about FB; we asked about FA too.
        let mock = MockFapiClient()
        mock.responder = { _ in try makeResponse(data: ["FB": 50]) }
        let svc = WalletService(fapi: mock)
        let bals = try await svc.balances(forFids: ["FA", "FB"])
        XCTAssertEqual(bals[0].satoshis, 0)
        XCTAssertEqual(bals[1].satoshis, 50)
    }

    func testBalanceErrorCodePropagates() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in FapiResponse(code: 500, message: "boom") }
        let svc = WalletService(fapi: mock)
        do {
            _ = try await svc.balance(forFid: "FA")
            XCTFail("expected throw")
        } catch let WalletService.Failure.fapiNonZeroCode(api, code, message) {
            XCTAssertEqual(api, "base.balanceByIds")
            XCTAssertEqual(code, 500)
            XCTAssertEqual(message, "boom")
        }
    }

    // MARK: - cash bootstrap (base.cashValid mode-1, FCDSL paginated)

    func testBootstrapCashesDecodesWireShape() async throws {
        let mock = MockFapiClient()
        // Wire shape mirrors Java Cash Gson serialization: value is
        // satoshis (Long), birthTxId/birthIndex name the source output.
        mock.responder = { _ in
            try makeResponse(
                data: [
                    [
                        "owner": "FFromAddr",
                        "value": 10_000,
                        "type": "P2PKH",
                        "birthTxId": "abcd1234",
                        "birthIndex": 0,
                        "issuer": "FIssuer",
                        "birthTime": 1_700_000_000
                    ],
                    [
                        "owner": "FFromAddr",
                        "value": 150_000_000,
                        "type": "P2PKH",
                        "birthTxId": "ef567890",
                        "birthIndex": 2
                    ]
                ],
                bestHeight: 800_001
            )
        }
        let svc = WalletService(fapi: mock)
        let snapshot = try await svc.refreshCashes(forFid: "FFromAddr")

        XCTAssertEqual(snapshot.cashes.count, 2)
        XCTAssertEqual(snapshot.cashes[0].birthTxId, "abcd1234")
        XCTAssertEqual(snapshot.cashes[0].value, 10_000)
        XCTAssertEqual(snapshot.cashes[0].issuer, "FIssuer")
        XCTAssertEqual(snapshot.cashes[0].birthTime, 1_700_000_000)
        XCTAssertEqual(snapshot.cashes[0].localState, .onchain)
        XCTAssertFalse(snapshot.cashes[0].pendingSpend)
        XCTAssertEqual(snapshot.cashes[1].value, 150_000_000)
        XCTAssertEqual(snapshot.totalValue, 150_010_000)
        XCTAssertEqual(snapshot.bestHeight, 800_001)
        XCTAssertEqual(snapshot.watermarkHeight, 800_001)

        // Outgoing wire shape: mode 2 of cashValid — single param
        // `fid`, no FCDSL. The server filters by valid=true and
        // routes by owner internally.
        let r = mock.recorded[0]
        XCTAssertEqual(r.api, "base.cashValid")
        XCTAssertNil(r.fcdsl)
        let params = try JSONSerialization.jsonObject(with: try XCTUnwrap(r.params)) as? [String: Any]
        XCTAssertEqual(params?["fid"] as? String, "FFromAddr")
    }

    func testBootstrapHandlesEmptyWallet() async throws {
        // The server returns NOT_FOUND for an FID with zero cashes.
        // That's a normal empty-wallet outcome and must produce an
        // empty snapshot, not propagate as a failure.
        let mock = MockFapiClient()
        mock.responder = { _ in
            FapiResponse(code: 404, message: "No UTXOs found", bestHeight: 1234)
        }
        let svc = WalletService(fapi: mock)
        let snapshot = try await svc.refreshCashes(forFid: "FEmpty")
        XCTAssertEqual(snapshot.cashes.count, 0)
        XCTAssertEqual(snapshot.bestHeight, 1234)
        XCTAssertEqual(snapshot.watermarkHeight, 1234)
    }

    func testBootstrapWritesCacheWhenStoreProvided() async throws {
        let baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("WalletServiceTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: baseDir) }

        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("wal".utf8), kdfKind: .legacySha256
        )
        let mainInfo = try configure.addMain(
            privkey: Data(repeating: 0x01, count: 32), label: "W"
        )
        let session = try configure.unlockMain(fid: mainInfo.fid, fapi: MockFapiClient())

        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(
                data: [[
                    "owner": session.mainFid,
                    "value": 200_000_000,
                    "type": "P2PKH",
                    "birthTxId": "f00d",
                    "birthIndex": 0
                ]],
                bestHeight: 900_000
            )
        }
        let svc = WalletService(fapi: mock, cashes: session.cashes)
        _ = try await svc.refreshCashes(forFid: session.mainFid)

        // Cache survives via the store.
        let cached = try session.cashes.snapshot(forAddress: session.mainFid)
        XCTAssertEqual(cached?.cashes.count, 1)
        XCTAssertEqual(cached?.cashes[0].value, 200_000_000)
        XCTAssertEqual(cached?.totalValue, 200_000_000)
        XCTAssertEqual(cached?.watermarkHeight, 900_000)

        // Also reachable through the service helper.
        let viaSvc = try svc.cachedSnapshot(forAddress: session.mainFid)
        XCTAssertEqual(viaSvc?.cashes[0].birthTxId, "f00d")
    }

    func testBootstrapSkipsCacheWhenNoStore() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [[
                "owner": "FX",
                "value": 100_000_000,
                "type": "P2PKH",
                "birthTxId": "11",
                "birthIndex": 0
            ]])
        }
        let svc = WalletService(fapi: mock)        // no CashesStore
        let snap = try await svc.refreshCashes(forFid: "FX")
        XCTAssertEqual(snap.cashes.count, 1)
        // No throw, no cache write — just an in-memory result.
        XCTAssertNil(try svc.cachedSnapshot(forAddress: "FX"))
    }

    func testBootstrapRejectsBadResponseShape() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            // data is a JSON array, but elements aren't objects →
            // parser rejects with unexpectedResponseShape.
            try makeResponse(data: [1, 2, 3])
        }
        let svc = WalletService(fapi: mock)
        do {
            _ = try await svc.refreshCashes(forFid: "FX")
            XCTFail("expected throw")
        } catch WalletService.Failure.underlying(Cash.Failure.unexpectedResponseShape) {
            // expected — Cash parser threw, WalletService wrapped it
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    // MARK: - cash incremental refresh (base.search on the cash index)

    func testIncrementalRefreshUsesBaseSearchAndAppliesDelta() async throws {
        let baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("WalletServiceTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: baseDir) }

        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(
            password: Data("inc".utf8), kdfKind: .legacySha256
        )
        let mainInfo = try configure.addMain(
            privkey: Data(repeating: 0x02, count: 32), label: "I"
        )
        let session = try configure.unlockMain(fid: mainInfo.fid, fapi: MockFapiClient())

        // Seed a snapshot directly: two existing cashes (A, B), one
        // .unknown change cash (C) we want to be confirmed by the
        // incremental delta. Watermark = 1000.
        let txid32 = String(repeating: "ab", count: 32)
        let txid32B = String(repeating: "cd", count: 32)
        let txid32C = String(repeating: "ef", count: 32)
        try session.cashes.save(CashSnapshot(
            addr: session.mainFid,
            cashes: [
                Cash(id: "A", owner: session.mainFid, value: 100, type: "P2PKH",
                     birthTxId: txid32, birthIndex: 0,
                     localState: .onchain, pendingSpend: false),
                Cash(id: "B", owner: session.mainFid, value: 200, type: "P2PKH",
                     birthTxId: txid32B, birthIndex: 0,
                     localState: .onchain, pendingSpend: false),
                Cash(id: "C", owner: session.mainFid, value: 300, type: "P2PKH",
                     birthTxId: txid32C, birthIndex: 0,
                     localState: .unknown, pendingSpend: false)
            ],
            bestHeight: 1000,
            watermarkHeight: 1000
        ))

        // Server emits an incremental delta:
        //   - A is now SPENT (valid:false) → must be removed
        //   - C is now CONFIRMED (valid:true, lastHeight set)
        //   - D is brand new, came from somewhere (e.g. an incoming tx)
        //   - B isn't in the delta (no state change since watermark)
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(
                data: [
                    [
                        "id": "A", "owner": session.mainFid, "value": 100,
                        "type": "P2PKH",
                        "birthTxId": txid32, "birthIndex": 0,
                        "valid": false, "lastHeight": 1010
                    ],
                    [
                        "id": "C", "owner": session.mainFid, "value": 300,
                        "type": "P2PKH",
                        "birthTxId": txid32C, "birthIndex": 0,
                        "valid": true, "lastHeight": 1015,
                        "birthHeight": 1014
                    ],
                    [
                        "id": "D", "owner": session.mainFid, "value": 400,
                        "type": "P2PKH",
                        "birthTxId": String(repeating: "12", count: 32),
                        "birthIndex": 1,
                        "valid": true, "lastHeight": 1020
                    ]
                ],
                bestHeight: 1020
            )
        }
        let svc = WalletService(fapi: mock, cashes: session.cashes)
        let result = try await svc.refreshCashes(forFid: session.mainFid)

        XCTAssertEqual(mock.recorded[0].api, "base.search")
        let fcdsl = try JSONSerialization.jsonObject(
            with: try XCTUnwrap(mock.recorded[0].fcdsl)
        ) as? [String: Any]
        XCTAssertEqual(fcdsl?["entity"] as? String, "cash")
        // sinceLastHeightExclusive = max(0, 1000 - 30) = 970.
        // Conditions live under `query`, not `filter` — matching the
        // Android Freer client and what the server expects on
        // base.search.
        let query = fcdsl?["query"] as? [String: Any]
        let range = query?["range"] as? [String: Any]
        XCTAssertEqual(range?["fields"] as? [String], ["lastHeight"])
        XCTAssertEqual(range?["gt"] as? String, "970")
        let terms = query?["terms"] as? [String: Any]
        XCTAssertEqual(terms?["fields"] as? [String], ["owner"])
        XCTAssertEqual(terms?["values"] as? [String], [session.mainFid])

        // Apply outcome: A removed, C confirmed (.onchain), D added, B intact.
        let ids = Set(result.cashes.compactMap { $0.id })
        XCTAssertFalse(ids.contains("A"))
        XCTAssertTrue(ids.contains("B"))
        XCTAssertTrue(ids.contains("C"))
        XCTAssertTrue(ids.contains("D"))
        let c = result.cashes.first { $0.id == "C" }
        XCTAssertEqual(c?.localState, .onchain)
        XCTAssertEqual(c?.lastHeight, 1015)
        // Watermark advanced.
        XCTAssertEqual(result.watermarkHeight, 1020)
    }
}
