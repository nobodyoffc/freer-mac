import XCTest
@testable import FCCore

final class BchSchnorrTests: XCTestCase {

    /// Byte-exact sign parity: BCH Schnorr signing is deterministic (nonce is
    /// `SHA-256(d || m)`), so our Swift output must equal the Java output
    /// hex-for-hex. Unlike ECDSA where libsecp256k1 and BouncyCastle diverge
    /// on RFC 6979 details, BCH Schnorr has a single specified nonce and
    /// either implementation must produce the same signature.
    func testSignMatchesFreecashjVectorsExactly() throws {
        let vectors = try TestVectors.load()
        let privkey = Data(fromHex: vectors.sampleKey.privkeyHex)
        XCTAssertFalse(vectors.schnorrBch.isEmpty)
        for vector in vectors.schnorrBch {
            let msgHash = Data(fromHex: vector.messageHashHex)
            let sig = try BchSchnorr.sign(message: msgHash, privateKey: privkey)
            XCTAssertEqual(sig.hex, vector.signatureHex,
                           "schnorr sign '\(vector.label)'")
        }
    }

    func testVerifyAcceptsFreecashjVectors() throws {
        let vectors = try TestVectors.load()
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)
        for vector in vectors.schnorrBch {
            let msgHash = Data(fromHex: vector.messageHashHex)
            let sig = Data(fromHex: vector.signatureHex)
            let valid = try BchSchnorr.verify(message: msgHash, publicKey: pubkey, signature: sig)
            XCTAssertTrue(valid, "java sig must verify '\(vector.label)'")
        }
    }

    func testVerifyRejectsTamperedSignature() throws {
        let vectors = try TestVectors.load()
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)
        let first = vectors.schnorrBch[0]
        let msgHash = Data(fromHex: first.messageHashHex)
        var sigBytes = Array(Data(fromHex: first.signatureHex))
        sigBytes[0] ^= 0x01  // flip one bit of R.x
        let valid = try BchSchnorr.verify(
            message: msgHash, publicKey: pubkey, signature: Data(sigBytes)
        )
        XCTAssertFalse(valid)
    }

    func testVerifyRejectsTamperedMessage() throws {
        let vectors = try TestVectors.load()
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)
        let first = vectors.schnorrBch[0]
        var msgBytes = Array(Data(fromHex: first.messageHashHex))
        msgBytes[0] ^= 0x01
        let valid = try BchSchnorr.verify(
            message: Data(msgBytes),
            publicKey: pubkey,
            signature: Data(fromHex: first.signatureHex)
        )
        XCTAssertFalse(valid)
    }

    func testSignRejectsNon32ByteMessage() {
        XCTAssertThrowsError(
            try BchSchnorr.sign(message: Data(repeating: 0, count: 31),
                                privateKey: Data(repeating: 1, count: 32))
        )
    }

    func testSignRejectsZeroPrivateKey() {
        XCTAssertThrowsError(
            try BchSchnorr.sign(message: Data(repeating: 0, count: 32),
                                privateKey: Data(repeating: 0, count: 32))
        )
    }
}
