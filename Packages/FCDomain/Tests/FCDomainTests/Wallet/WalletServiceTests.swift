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

    // MARK: - utxos

    func testRefreshUtxosDecodesWireShape() async throws {
        let mock = MockFapiClient()
        // Wire shape: amount is a double of BCH (× 1e8 → satoshis).
        mock.responder = { _ in
            try makeResponse(
                data: [
                    [
                        "addr": "FFromAddr",
                        "txId": "abcd1234",
                        "index": 0,
                        "amount": 0.0001,                  // = 10_000 satoshis
                        "issuer": "FIssuer",
                        "birthTime": 1_700_000_000
                    ],
                    [
                        "addr": "FFromAddr",
                        "txId": "ef567890",
                        "index": 2,
                        "amount": 1.5                      // = 150_000_000 satoshis
                    ]
                ],
                bestHeight: 800_001
            )
        }
        let svc = WalletService(fapi: mock)
        let snapshot = try await svc.refreshUtxos(
            forAddress: "FFromAddr",
            minAmountBch: 0.0001
        )

        XCTAssertEqual(snapshot.utxos.count, 2)
        XCTAssertEqual(snapshot.utxos[0].txid, "abcd1234")
        XCTAssertEqual(snapshot.utxos[0].value, 10_000)
        XCTAssertEqual(snapshot.utxos[0].issuer, "FIssuer")
        XCTAssertEqual(snapshot.utxos[0].birthTime, 1_700_000_000)
        XCTAssertEqual(snapshot.utxos[1].value, 150_000_000)
        XCTAssertEqual(snapshot.totalValue, 150_010_000)
        XCTAssertEqual(snapshot.bestHeight, 800_001)

        // Outgoing params shape: {"addr":"FFromAddr","amount":0.0001}
        let r = mock.recorded[0]
        XCTAssertEqual(r.api, "base.getUtxo")
        let params = try JSONSerialization.jsonObject(with: try XCTUnwrap(r.params)) as? [String: Any]
        XCTAssertEqual(params?["addr"] as? String, "FFromAddr")
        XCTAssertEqual((params?["amount"] as? NSNumber)?.doubleValue, 0.0001)
    }

    func testRefreshUtxosWritesCacheWhenStoreProvided() async throws {
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
            try makeResponse(data: [[
                "addr": session.mainFid, "txId": "f00d", "index": 0, "amount": 2.0
            ]])
        }
        let svc = WalletService(fapi: mock, utxos: session.utxos)
        _ = try await svc.refreshUtxos(forAddress: session.mainFid)

        // Cache survives via the store.
        let cached = try session.utxos.snapshot(forAddress: session.mainFid)
        XCTAssertEqual(cached?.utxos.count, 1)
        XCTAssertEqual(cached?.utxos[0].value, 200_000_000)
        XCTAssertEqual(cached?.totalValue, 200_000_000)

        // Also reachable through the service helper.
        let viaSvc = try svc.cachedSnapshot(forAddress: session.mainFid)
        XCTAssertEqual(viaSvc?.utxos[0].txid, "f00d")
    }

    func testRefreshUtxosSkipsCacheWhenNoStore() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            try makeResponse(data: [["addr": "FX", "txId": "11", "index": 0, "amount": 1.0]])
        }
        let svc = WalletService(fapi: mock)        // no UtxosStore
        let snap = try await svc.refreshUtxos(forAddress: "FX")
        XCTAssertEqual(snap.utxos.count, 1)
        // No throw, no cache write — just an in-memory result.
        XCTAssertNil(try svc.cachedSnapshot(forAddress: "FX"))
    }

    func testRefreshUtxosRejectsBadResponseShape() async throws {
        let mock = MockFapiClient()
        mock.responder = { _ in
            // data is a JSON array, but elements aren't objects →
            // parser rejects with unexpectedResponseShape.
            try makeResponse(data: [1, 2, 3])
        }
        let svc = WalletService(fapi: mock)
        do {
            _ = try await svc.refreshUtxos(forAddress: "FX")
            XCTFail("expected throw")
        } catch WalletService.Failure.underlying(Utxo.Failure.unexpectedResponseShape) {
            // expected — Utxo parser threw, WalletService wrapped it
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }
}
