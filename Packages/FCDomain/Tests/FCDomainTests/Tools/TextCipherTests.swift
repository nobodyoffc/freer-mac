import XCTest
@testable import FCDomain
import FCCore

final class TextCipherTests: XCTestCase {

    // MARK: - Envelope shape

    func testPasswordEnvelopeShape() throws {
        let json = try TextCipher.encryptWithPassword(Data("hi".utf8), password: Data("pw".utf8))
        let envelope = try TextCipher.parse(json)
        XCTAssertEqual(envelope.type, "Password")
        XCTAssertEqual(envelope.alg, "AesGcm256@No1_NrC7")
        XCTAssertEqual(envelope.kdf, "Argon2id@No1_NrC7")
        XCTAssertEqual(Data(fcHex: envelope.iv ?? "")?.count, 12)
        XCTAssertNotNil(envelope.keyName)
        XCTAssertNil(envelope.sum) // GCM carries its own tag
    }

    func testSymkeyEnvelopeShape() throws {
        let key = Data(repeating: 3, count: 32)
        let json = try TextCipher.encryptWithSymkey(Data("hi".utf8), symkey: key)
        let envelope = try TextCipher.parse(json)
        XCTAssertEqual(envelope.type, "Symkey")
        XCTAssertNil(envelope.kdf)
        // keyName = first 6 bytes of sha256(symkey), hex.
        XCTAssertEqual(envelope.keyName, Hash.sha256(key).prefix(6).fcToolHex)
    }

    // MARK: - Round trips

    func testPasswordRoundTrip() throws {
        let plaintext = Data("秘密 secret bytes".utf8)
        let password = Data("correct horse".utf8)
        let json = try TextCipher.encryptWithPassword(plaintext, password: password)
        let envelope = try TextCipher.parse(json)
        XCTAssertEqual(try TextCipher.decrypt(envelope: envelope, password: password), plaintext)
        XCTAssertThrowsError(
            try TextCipher.decrypt(envelope: envelope, password: Data("wrong".utf8))
        )
    }

    func testSymkeyRoundTrip() throws {
        let key = Data((0..<32).map { UInt8($0) })
        let plaintext = Data((0..<100).map { UInt8($0 % 251) })
        let json = try TextCipher.encryptWithSymkey(plaintext, symkey: key)
        let envelope = try TextCipher.parse(json)
        XCTAssertEqual(try TextCipher.decrypt(envelope: envelope, symkey: key), plaintext)
        XCTAssertThrowsError(
            try TextCipher.decrypt(envelope: envelope, symkey: Data(repeating: 1, count: 32))
        )
    }

    func testPubkeyModeRoundTripsThroughAsyOneWay() throws {
        let privkey = Data(fcHex: "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725")!
        let pubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        let plaintext = Data("to a pubkey".utf8)
        let json = try TextCipher.encryptWithPubkey(plaintext, pubkey: pubkey)
        XCTAssertEqual(try AsyOneWayCipher.decrypt(cipherString: json, privkey: privkey), plaintext)
    }

    // MARK: - Legacy / Android-shaped decrypt paths

    func testDecryptsLegacySha256IvPasswordCipher() throws {
        // Hand-built the way the Java legacy path
        // (`Kdf.Sha256Iv_No1_NrC7` + AES-GCM) would emit it.
        let password = Data("legacy pw".utf8)
        let iv = Data(fcHex: "000102030405060708090a0b")!
        let key = Hash.sha256(Hash.sha256(password) + iv)
        let plaintext = Data("legacy plaintext".utf8)
        let box = try AesGcm256.seal(key: key, nonce: iv, plaintext: plaintext)
        let json = """
        {"type":"Password","alg":"AesGcm256@No1_NrC7","kdf":"Sha256Iv@No1_NrC7",\
        "cipher":"\((box.ciphertext + box.tag).base64EncodedString())","iv":"\(iv.fcToolHex)"}
        """
        let envelope = try TextCipher.parse(json)
        XCTAssertEqual(try TextCipher.decrypt(envelope: envelope, password: password), plaintext)
    }

    func testDecryptsUnstampedLegacyPasswordCipherViaFallback() throws {
        // No kdf field at all — Decryptor tries Argon2id, then legacy.
        let password = Data("pw2".utf8)
        let iv = Data(fcHex: "0f0e0d0c0b0a090807060504")!
        let key = Hash.sha256(Hash.sha256(password) + iv)
        let plaintext = Data("old cipher".utf8)
        let box = try AesGcm256.seal(key: key, nonce: iv, plaintext: plaintext)
        let json = """
        {"type":"Password","alg":"AesGcm256@No1_NrC7",\
        "cipher":"\((box.ciphertext + box.tag).base64EncodedString())","iv":"\(iv.fcToolHex)"}
        """
        let envelope = try TextCipher.parse(json)
        XCTAssertEqual(try TextCipher.decrypt(envelope: envelope, password: password), plaintext)
    }

    func testParseRejectsNonJson() {
        XCTAssertThrowsError(try TextCipher.parse("Zm9vYmFy"))
        XCTAssertThrowsError(try TextCipher.parse(""))
    }

    func testUnsupportedAlgIsReported() throws {
        let envelope = try TextCipher.parse(
            #"{"type":"Symkey","alg":"ChaCha20@No1_NrC7","cipher":"AAAA","iv":"00010203"}"#
        )
        XCTAssertThrowsError(try TextCipher.decrypt(envelope: envelope, symkey: Data(repeating: 0, count: 32))) { error in
            guard case TextCipher.Failure.unsupportedAlgorithm = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }
}
