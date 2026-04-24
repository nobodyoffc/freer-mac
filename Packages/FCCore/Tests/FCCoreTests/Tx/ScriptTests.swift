import XCTest
@testable import FCCore

final class ScriptTests: XCTestCase {

    func testAllScriptVectorsMatch() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.script.isEmpty)
        for vector in vectors.script {
            let script = try buildScriptFromVector(vector)
            XCTAssertEqual(script.bytes.hex, vector.programHex,
                           "'\(vector.label)' (\(vector.kind))")
        }
    }

    /// Data-push encoding must follow the canonical rules exactly —
    /// 1..75 uses a direct length byte, 76..255 uses OP_PUSHDATA1,
    /// 256..65535 uses OP_PUSHDATA2. These boundaries are where
    /// off-by-ones bite.
    func testPushDataBoundaries() {
        let zero = Data()
        let one = Data(repeating: 0xAA, count: 1)
        let max1Byte = Data(repeating: 0xAA, count: 0x4B)      // 75 — last direct
        let min2Byte = Data(repeating: 0xAA, count: 0x4C)      // 76 — first PUSHDATA1
        let maxPushdata1 = Data(repeating: 0xAA, count: 0xFF)  // 255
        let minPushdata2 = Data(repeating: 0xAA, count: 0x100) // 256

        XCTAssertEqual(ScriptBuilder.pushData(zero), Data([0x00]))
        XCTAssertEqual(ScriptBuilder.pushData(one), Data([0x01, 0xAA]))
        XCTAssertEqual(ScriptBuilder.pushData(max1Byte).prefix(1), Data([0x4B]))
        XCTAssertEqual(ScriptBuilder.pushData(min2Byte).prefix(2), Data([0x4C, 0x4C]))
        XCTAssertEqual(ScriptBuilder.pushData(maxPushdata1).prefix(2), Data([0x4C, 0xFF]))
        XCTAssertEqual(ScriptBuilder.pushData(minPushdata2).prefix(3), Data([0x4D, 0x00, 0x01]))
    }

    func testRejectsBadMultisig() {
        // required > total
        XCTAssertThrowsError(try ScriptBuilder.multisigOutput(
            required: 3,
            pubkeys: [Data(repeating: 0x02, count: 33), Data(repeating: 0x02, count: 33)]
        ))
        // required == 0
        XCTAssertThrowsError(try ScriptBuilder.multisigOutput(
            required: 0,
            pubkeys: [Data(repeating: 0x02, count: 33)]
        ))
        // >16 pubkeys
        let many = [Data](repeating: Data(repeating: 0x02, count: 33), count: 17)
        XCTAssertThrowsError(try ScriptBuilder.multisigOutput(required: 1, pubkeys: many))
    }

    func testRejectsWrongHashLength() {
        XCTAssertThrowsError(try ScriptBuilder.p2pkhOutput(hash160: Data(repeating: 0, count: 19)))
        XCTAssertThrowsError(try ScriptBuilder.p2shOutput(scriptHash: Data(repeating: 0, count: 21)))
    }

    // MARK: - helper

    private func buildScriptFromVector(_ vector: TestVectors.ScriptCase) throws -> Script {
        switch vector.kind {
        case "p2pkh":
            let hash = try XCTUnwrap(vector.hash160Hex).hexData
            return try ScriptBuilder.p2pkhOutput(hash160: hash)
        case "p2sh":
            let hash = try XCTUnwrap(vector.scriptHashHex).hexData
            return try ScriptBuilder.p2shOutput(scriptHash: hash)
        case "multisig":
            let required = try XCTUnwrap(vector.required)
            let keys = try XCTUnwrap(vector.pubkeysHex).map { $0.hexData }
            return try ScriptBuilder.multisigOutput(required: required, pubkeys: keys)
        case "p2pkh_input":
            let sig = try XCTUnwrap(vector.derSigHex).hexData
            let flag = try XCTUnwrap(vector.sighashFlag)
            let pub = try XCTUnwrap(vector.pubkeyHex).hexData
            return try ScriptBuilder.p2pkhInput(signatureDER: sig, sighashFlag: flag, pubkey: pub)
        default:
            XCTFail("unknown script kind '\(vector.kind)'")
            return Script(Data())
        }
    }
}

private extension String {
    var hexData: Data { Data(fromHex: self) }
}
