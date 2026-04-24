import XCTest
@testable import FCCore

final class Secp256k1Tests: XCTestCase {

    func testPublicKeyDerivationMatchesSampleKey() throws {
        let vectors = try TestVectors.load()
        let privkey = Data(fromHex: vectors.sampleKey.privkeyHex)
        let derivedPubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        XCTAssertEqual(derivedPubkey.hex, vectors.sampleKey.pubkeyHex)
    }

    /// Verify-parity: every signature the Java generator produced with
    /// freecashj (BouncyCastle + bitcoinj) must verify under our Swift
    /// (libsecp256k1) implementation. This is the only direction that
    /// matters for cross-platform interop.
    ///
    /// Note: byte-exact **sign** parity is *not* tested here — libsecp256k1
    /// and BouncyCastle/bitcoinj both implement RFC 6979 but produce
    /// different deterministic nonces (they disagree on an internal HMAC
    /// input shape). Every signature from either side is a valid RFC 6979
    /// signature, so either verifies the other. Byte-exact parity would
    /// require a specific Swift-side nonce override, which gains nothing
    /// for correctness and locks us to one library.
    func testEcdsaVerifyAcceptsFreecashjVectors() throws {
        let vectors = try TestVectors.load()
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)
        XCTAssertFalse(vectors.ecdsa.isEmpty)
        for vector in vectors.ecdsa {
            let message = Data(fromHex: vector.messageHex)
            let sigDer = Data(fromHex: vector.signatureDerHex)
            let valid = try Secp256k1.verifyMessage(
                publicKey: pubkey, message: message, signatureDER: sigDer
            )
            XCTAssertTrue(valid, "Java-produced sig must verify in Swift: '\(vector.label)'")
        }
    }

    /// Round-trip: Swift-produced signatures must verify in Swift.
    func testEcdsaSignRoundTrips() throws {
        let vectors = try TestVectors.load()
        let privkey = Data(fromHex: vectors.sampleKey.privkeyHex)
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)
        for vector in vectors.ecdsa {
            let message = Data(fromHex: vector.messageHex)
            let sig = try Secp256k1.signMessage(privateKey: privkey, message: message)
            let valid = try Secp256k1.verifyMessage(
                publicKey: pubkey, message: message, signatureDER: sig
            )
            XCTAssertTrue(valid, "Swift-signed sig must verify: '\(vector.label)'")
        }
    }

    /// Same key + message must produce the same signature across calls
    /// (RFC 6979 determinism) — catches accidental randomisation.
    func testEcdsaSignIsDeterministic() throws {
        let vectors = try TestVectors.load()
        let privkey = Data(fromHex: vectors.sampleKey.privkeyHex)
        let message = Data("test".utf8)
        let first = try Secp256k1.signMessage(privateKey: privkey, message: message)
        let second = try Secp256k1.signMessage(privateKey: privkey, message: message)
        XCTAssertEqual(first, second)
    }

    func testEcdsaVerifyRejectsTamperedMessage() throws {
        let vectors = try TestVectors.load()
        let pubkey = Data(fromHex: vectors.sampleKey.pubkeyHex)
        let first = vectors.ecdsa[0]
        let sigDer = Data(fromHex: first.signatureDerHex)
        var tampered = Array(Data(fromHex: first.messageHex))
        tampered.append(0x01)
        let valid = try Secp256k1.verifyMessage(
            publicKey: pubkey, message: Data(tampered), signatureDER: sigDer
        )
        XCTAssertFalse(valid)
    }

    func testEcdhMatchesFreecashjVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.ecdh.isEmpty)
        for vector in vectors.ecdh {
            let alicePriv = Data(fromHex: vector.alicePrivkeyHex)
            let bobPriv = Data(fromHex: vector.bobPrivkeyHex)
            let alicePub = Data(fromHex: vector.alicePubkeyHex)
            let bobPub = Data(fromHex: vector.bobPubkeyHex)

            let fromAlice = try Secp256k1.sharedSecretX(privateKey: alicePriv, publicKey: bobPub)
            let fromBob = try Secp256k1.sharedSecretX(privateKey: bobPriv, publicKey: alicePub)

            XCTAssertEqual(fromAlice.hex, vector.sharedXHex, "alice×bob '\(vector.label)'")
            XCTAssertEqual(fromBob.hex, vector.sharedXHex, "bob×alice (symmetry) '\(vector.label)'")
            XCTAssertEqual(fromAlice, fromBob, "ECDH must be symmetric")
        }
    }

    func testRejectsBadPrivateKey() {
        XCTAssertThrowsError(
            try Secp256k1.publicKey(fromPrivateKey: Data(repeating: 0, count: 32))
        )
    }

    func testRejectsBadPublicKey() {
        XCTAssertThrowsError(
            try Secp256k1.verifyMessage(
                publicKey: Data(repeating: 0xff, count: 33),
                message: Data("hi".utf8),
                signatureDER: Data(repeating: 0, count: 70)
            )
        )
    }
}
