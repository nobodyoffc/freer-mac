import XCTest
@testable import FCCore

final class AeadTests: XCTestCase {

    func testAesGcm256MatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.aesGcm256.isEmpty)
        for vector in vectors.aesGcm256 {
            try runVector(vector, algorithm: .aesGcm)
        }
    }

    func testChaCha20Poly1305MatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.chacha20Poly1305.isEmpty)
        for vector in vectors.chacha20Poly1305 {
            try runVector(vector, algorithm: .chaChaPoly)
        }
    }

    func testAesGcmRejectsWrongKeyLength() {
        XCTAssertThrowsError(
            try AesGcm256.seal(
                key: Data(repeating: 0, count: 16),
                nonce: Data(repeating: 0, count: 12),
                plaintext: Data("x".utf8)
            )
        ) { error in
            guard case Aead.Failure.invalidKeyLength = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testAesGcmRejectsWrongNonceLength() {
        XCTAssertThrowsError(
            try AesGcm256.seal(
                key: Data(repeating: 0, count: 32),
                nonce: Data(repeating: 0, count: 8),
                plaintext: Data("x".utf8)
            )
        ) { error in
            guard case Aead.Failure.invalidNonceLength = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testAesGcmAuthFailsOnTamperedTag() throws {
        let key = Data(repeating: 0x11, count: 32)
        let nonce = Data(repeating: 0x22, count: 12)
        let sealed = try AesGcm256.seal(key: key, nonce: nonce, plaintext: Data("hello".utf8))
        var tagBytes = Array(sealed.tag)
        tagBytes[0] ^= 0x01
        let badTag = Data(tagBytes)
        XCTAssertThrowsError(
            try AesGcm256.open(key: key, nonce: nonce, ciphertext: sealed.ciphertext, tag: badTag)
        ) { error in
            guard case Aead.Failure.authenticationFailed = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testChaChaPolyAuthFailsOnTamperedCiphertext() throws {
        let key = Data(repeating: 0x33, count: 32)
        let nonce = Data(repeating: 0x44, count: 12)
        let sealed = try ChaChaPoly.seal(key: key, nonce: nonce, plaintext: Data("goodbye".utf8))
        var ctBytes = Array(sealed.ciphertext)
        ctBytes[0] ^= 0x01
        let badCt = Data(ctBytes)
        XCTAssertThrowsError(
            try ChaChaPoly.open(key: key, nonce: nonce, ciphertext: badCt, tag: sealed.tag)
        ) { error in
            guard case Aead.Failure.authenticationFailed = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    // MARK: -

    private enum Algorithm { case aesGcm, chaChaPoly }

    private func runVector(_ vector: TestVectors.AeadCase, algorithm: Algorithm) throws {
        let key = Data(fromHex: vector.keyHex)
        let nonce = Data(fromHex: vector.ivHex)
        let plaintext = Data(fromHex: vector.plaintextHex)
        let aad = Data(fromHex: vector.aadHex)

        let sealed: Aead.SealedBox
        let roundTripped: Data
        switch algorithm {
        case .aesGcm:
            sealed = try AesGcm256.seal(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
            roundTripped = try AesGcm256.open(
                key: key, nonce: nonce,
                ciphertext: sealed.ciphertext, tag: sealed.tag, aad: aad
            )
        case .chaChaPoly:
            sealed = try ChaChaPoly.seal(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
            roundTripped = try ChaChaPoly.open(
                key: key, nonce: nonce,
                ciphertext: sealed.ciphertext, tag: sealed.tag, aad: aad
            )
        }

        XCTAssertEqual(sealed.ciphertext.hex, vector.ciphertextHex,
                       "\(algorithm) ciphertext '\(vector.label)'")
        XCTAssertEqual(sealed.tag.hex, vector.tagHex,
                       "\(algorithm) tag '\(vector.label)'")
        XCTAssertEqual(roundTripped, plaintext,
                       "\(algorithm) round-trip '\(vector.label)'")
    }
}
