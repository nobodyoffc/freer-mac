import XCTest
@testable import FCCore

/// Checked against `tools/vector-gen`, which runs the **real** FC-AJDK
/// `P2SH` class. Every one of these values ends up hashed into an
/// address, so a mismatch is not a rounding difference — it is coins
/// sent somewhere the other client would not look for them.
final class P2shTests: XCTestCase {

    // MARK: - build

    func testCltvRedeemScriptMatchesAndroid() throws {
        let v = try TestVectors.load().p2sh.cltv
        let p2sh = try P2sh(fid: v.inputFid!, lockTime: v.inputLockTime!)

        XCTAssertEqual(p2sh.redeemScriptHex, v.redeemScriptHex)
        XCTAssertEqual(Hex.encode(p2sh.scriptHash), v.scriptHashHex)
        XCTAssertEqual(p2sh.address, v.address)
        XCTAssertEqual(p2sh.fid, v.fid)
        XCTAssertEqual(p2sh.kind, .cltv)
    }

    func testMultisigRedeemScriptMatchesAndroid() throws {
        let v = try TestVectors.load().p2sh.multisig
        let p2sh = try P2sh(
            pubkeys: v.inputPubkeys!, m: v.inputM!, n: v.inputN!, lockTime: nil
        )

        XCTAssertEqual(p2sh.redeemScriptHex, v.redeemScriptHex)
        XCTAssertEqual(Hex.encode(p2sh.scriptHash), v.scriptHashHex)
        XCTAssertEqual(p2sh.address, v.address)
        XCTAssertEqual(p2sh.fid, v.fid)
        XCTAssertEqual(p2sh.kind, .multisig)
    }

    func testMultisigCltvRedeemScriptMatchesAndroid() throws {
        let v = try TestVectors.load().p2sh.multisigCltv
        let p2sh = try P2sh(
            pubkeys: v.inputPubkeys!, m: v.inputM!, n: v.inputN!,
            lockTime: v.inputLockTime!
        )

        XCTAssertEqual(p2sh.redeemScriptHex, v.redeemScriptHex)
        XCTAssertEqual(Hex.encode(p2sh.scriptHash), v.scriptHashHex)
        XCTAssertEqual(p2sh.kind, .multisigCltv)
    }

    /// The two addresses a multisig-CLTV script carries are different
    /// on purpose: `fid` names the group (the multisig script *without*
    /// the lock), `address` is where these particular coins go. Getting
    /// them the wrong way round pays an unlocked address.
    func testMultisigCltvNamesTheGroupButPaysTheLockedScript() throws {
        let vectors = try TestVectors.load().p2sh
        let locked = try P2sh(
            pubkeys: vectors.multisigCltv.inputPubkeys!,
            m: 2, n: 3, lockTime: vectors.multisigCltv.inputLockTime!
        )
        XCTAssertEqual(locked.fid, vectors.multisig.address,
                       "fid must be the plain group address")
        XCTAssertEqual(locked.address, vectors.multisigCltv.address)
        XCTAssertNotEqual(locked.fid, locked.address)
    }

    // MARK: - parse

    func testReparsingRecoversEveryField() throws {
        let vectors = try TestVectors.load().p2sh
        for v in [vectors.cltv, vectors.multisig, vectors.multisigCltv] {
            let reparsed = try P2sh(redeemScriptHex: v.redeemScriptHex)
            let expected = v.reparsed!

            XCTAssertEqual(reparsed.redeemScriptHex, expected.redeemScriptHex)
            XCTAssertEqual(Hex.encode(reparsed.scriptHash), expected.scriptHashHex)
            XCTAssertEqual(reparsed.address, expected.address, expected.type)
            XCTAssertEqual(reparsed.fid, expected.fid, expected.type)
            XCTAssertEqual(reparsed.lockTime, expected.lockTime, expected.type)
            XCTAssertEqual(reparsed.m, expected.m, expected.type)
            XCTAssertEqual(reparsed.n, expected.n, expected.type)
        }
    }

    func testKindMatchesAndroidsTypeName() throws {
        let vectors = try TestVectors.load().p2sh
        let mapping: [(TestVectors.P2shCase, P2sh.Kind)] = [
            (vectors.cltv, .cltv),
            (vectors.multisig, .multisig),
            (vectors.multisigCltv, .multisigCltv),
        ]
        for (v, kind) in mapping {
            XCTAssertEqual(try P2sh(redeemScriptHex: v.redeemScriptHex).kind, kind)
            // Our raw values are the Android `Cash.CashType` names, which
            // prefix the `P2SH.P2shType` name the vector carries.
            XCTAssertEqual(kind.rawValue, "P2SH_" + v.type)
        }
    }

    func testMalformedScriptsAreRejected() {
        // A leading push with no CLTV/DROP behind it.
        XCTAssertThrowsError(try P2sh(redeemScriptHex: "03a0bb0d76a914"))
        XCTAssertThrowsError(try P2sh(redeemScriptHex: ""))
        XCTAssertThrowsError(try P2sh(redeemScriptHex: "zz"))
        // Single-sig body with a truncated tail.
        XCTAssertThrowsError(try P2sh(redeemScriptHex: "76a914"))
    }

    func testValidationRejectsScriptsThatWouldBeUnspendable() throws {
        let v = try TestVectors.load().p2sh
        XCTAssertTrue(P2sh.isValidRedeemScript(v.cltv.redeemScriptHex))
        XCTAssertTrue(P2sh.isValidRedeemScript(v.multisig.redeemScriptHex))
        XCTAssertTrue(P2sh.isValidRedeemScript(v.multisigCltv.redeemScriptHex))
        XCTAssertFalse(P2sh.isValidRedeemScript("76a914"))
        XCTAssertFalse(P2sh.isValidRedeemScript(""))
    }

    // MARK: - OP_RETURN manifest

    func testOpReturnManifestMatchesAndroidIncludingDeDuplication() throws {
        let v = try TestVectors.load().p2sh.opReturnManifest
        let scripts = try v.inputRedeemScripts.map { try P2sh(redeemScriptHex: $0) }

        let payload = try P2sh.opReturnPayload(for: scripts)
        XCTAssertEqual(payload, v.json)
        XCTAssertEqual(payload.utf8.count, v.byteLength)
        // Three scripts in, two out — the duplicate is dropped.
        XCTAssertEqual(v.inputRedeemScripts.count, 3)
    }

    func testManifestRoundTripsBackToScriptsKeyedByHash() throws {
        let v = try TestVectors.load().p2sh.opReturnManifest
        let map = P2sh.redeemScripts(fromOpReturn: v.json)
        XCTAssertEqual(map?.count, 2)
        for hex in Set(v.inputRedeemScripts) {
            let hash = Hex.encode(Hash.hash160(try Hex.decode(hex)))
            XCTAssertEqual(map?[hash], hex)
        }
        XCTAssertNil(P2sh.redeemScripts(fromOpReturn: "not a manifest"))
    }

    // MARK: - script number encoding

    /// `ScriptBuilder.number` is where a CLTV script most easily goes
    /// wrong: a non-minimal push changes the script hash, and so the
    /// address, without changing what the script *does*.
    func testScriptNumberEncoding() {
        XCTAssertEqual(Hex.encode(ScriptBuilder.number(0)), "00")
        XCTAssertEqual(Hex.encode(ScriptBuilder.number(1)), "51")
        XCTAssertEqual(Hex.encode(ScriptBuilder.number(16)), "60")
        XCTAssertEqual(Hex.encode(ScriptBuilder.number(-1)), "4f")
        // 17 no longer fits an opcode: push one byte.
        XCTAssertEqual(Hex.encode(ScriptBuilder.number(17)), "0111")
        // 900 000 = 0x0DBBA0 → little-endian, sign bit clear.
        XCTAssertEqual(Hex.encode(ScriptBuilder.number(900_000)), "03a0bb0d")
        // 128 would set the sign bit, so it carries a zero byte.
        XCTAssertEqual(Hex.encode(ScriptBuilder.number(128)), "028000")
    }

    // MARK: - chunk parsing

    func testChunksSeparatePushesFromOpcodes() throws {
        let v = try TestVectors.load().p2sh.cltv
        let chunks = try ScriptParser.chunks(try Hex.decode(v.redeemScriptHex))
        // <lockTime> CLTV DROP DUP HASH160 <hash160> EQUALVERIFY CHECKSIG
        XCTAssertEqual(chunks.count, 8)
        XCTAssertEqual(chunks[0].pushedNumber, v.lockTime)
        XCTAssertEqual(chunks[1].opcode, 0xB1)
        XCTAssertEqual(chunks[2].opcode, 0x75)
        XCTAssertEqual(chunks[3].opcode, 0x76)
        XCTAssertEqual(chunks[5].data?.count, 20)
        XCTAssertEqual(chunks[7].opcode, 0xAC)
    }

    func testChunksRejectATruncatedPush() {
        // Declares a 32-byte push with nothing behind it.
        XCTAssertThrowsError(try ScriptParser.chunks(Data([0x20, 0x01, 0x02])))
    }

    // MARK: - address

    func testP2shAddressesAreDistinctFromP2pkhOnes() throws {
        let v = try TestVectors.load().p2sh.cltv
        XCTAssertTrue(FchAddress.isP2sh(fid: v.address))
        XCTAssertFalse(FchAddress.isP2sh(fid: v.fid!))
        XCTAssertTrue(v.address.hasPrefix("3"))
        XCTAssertTrue(v.fid!.hasPrefix("F"))
    }
}
