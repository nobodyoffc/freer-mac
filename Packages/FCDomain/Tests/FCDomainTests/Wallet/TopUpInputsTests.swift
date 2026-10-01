import XCTest
import FCCore
import FCTransport
@testable import FCDomain

/// What a DOCK top-up pays with: the cashes the server offered, and
/// local ones only for what those cannot cover.
final class TopUpInputsTests: XCTestCase {

    private var baseDir: URL!

    override func setUpWithError() throws {
        baseDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("TopUpInputsTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        if let baseDir { try? FileManager.default.removeItem(at: baseDir) }
    }

    private func makeSession() throws -> ActiveSession {
        let mgr = try ConfigureManager(baseDirectory: baseDir)
        let configure = try mgr.createConfigure(password: Data("top-up".utf8), kdfKind: .legacySha256)
        let info = try configure.addMain(privkey: Hash.sha256(Data("top-up-main".utf8)), label: "main")
        return try configure.unlockMain(fid: info.fid, fapi: MockFapiClient())
    }

    private func cash(owner: String, txidByte: UInt8, value: Int64) throws -> Cash {
        let txid = String(repeating: String(format: "%02x", txidByte), count: 32)
        return Cash(
            id: try Cash.makeId(birthTxId: txid, birthIndex: 0),
            owner: owner, value: value, type: "P2PKH",
            birthTxId: txid, birthIndex: 0,
            lockScript: Cash.canonicalP2PKHLockScript(hash160: try FchAddress(fid: owner).hash160),
            birthHeight: 900, cd: 10
        )
    }

    func testTheOfferedCashesAloneWhenTheyCover() throws {
        let session = try makeSession()
        let offered = try cash(owner: session.mainFid, txidByte: 0xA1, value: 1_100_000)
        let local = try cash(owner: session.mainFid, txidByte: 0xB2, value: 50_000_000)
        try session.cashes.save(CashSnapshot(
            addr: session.mainFid, cashes: [offered, local], bestHeight: 1_000, watermarkHeight: 1_000
        ))

        let inputs = try session.wallet.topUpInputs(
            offered: [offered], fromAddress: session.mainFid, amount: 1_000_000
        )
        XCTAssertEqual(inputs.map(\.id), [offered.id], "an unchecked local cash is not risked when it is not needed")
    }

    func testLocalCashesMakeUpALargerPaymentLargestFirst() throws {
        let session = try makeSession()
        let offered = try cash(owner: session.mainFid, txidByte: 0xA1, value: 1_100_000)
        let small = try cash(owner: session.mainFid, txidByte: 0xB2, value: 2_000_000)
        let big = try cash(owner: session.mainFid, txidByte: 0xC3, value: 20_000_000)
        try session.cashes.save(CashSnapshot(
            addr: session.mainFid, cashes: [offered, small, big], bestHeight: 1_000, watermarkHeight: 1_000
        ))

        let local = session.wallet.localTopUpCashes(fromAddress: session.mainFid, excluding: [offered])
        XCTAssertEqual(Set(local.map(\.id)), Set([small.id, big.id]), "the offered cash is not counted twice")

        let inputs = try session.wallet.topUpInputs(
            offered: [offered], fromAddress: session.mainFid, amount: 10_000_000
        )
        XCTAssertEqual(inputs.map(\.id), [offered.id, big.id], "offered first, then only the one local cash it takes")
    }

    func testTooLargeAPaymentSaysByHowMuch() throws {
        let session = try makeSession()
        let offered = try cash(owner: session.mainFid, txidByte: 0xA1, value: 1_100_000)
        try session.cashes.save(CashSnapshot(
            addr: session.mainFid, cashes: [offered], bestHeight: 1_000, watermarkHeight: 1_000
        ))
        XCTAssertThrowsError(try session.wallet.topUpInputs(
            offered: [offered], fromAddress: session.mainFid, amount: 5_000_000
        )) { error in
            guard case CoinSelector.Failure.insufficientFunds = error else {
                return XCTFail("expected insufficientFunds, got \(error)")
            }
        }
    }
}
