import XCTest
import FCCore
@testable import FCTransport

final class AsyTwoWayTests: XCTestCase {

    // MARK: - byte parity

    func testSealMatchesFreecashjVectors() throws {
        let vectors = try FudpVectors.load()
        XCTAssertFalse(vectors.asyTwoWay.isEmpty)
        for vector in vectors.asyTwoWay {
            let bundle = try AsyTwoWay.seal(
                plaintext: Data(fromHex: vector.plaintextHex),
                aad: Data(fromHex: vector.aadHex),
                peerPubkey: Data(fromHex: vector.peerPubkeyHex),
                localPrivkey: Data(fromHex: vector.localPrivkeyHex),
                localPubkey: Data(fromHex: vector.localPubkeyHex),
                iv: Data(fromHex: vector.ivHex)
            )
            XCTAssertEqual(bundle.hex, vector.bundleHex,
                           "seal '\(vector.label)'")
        }
    }

    func testOpenRecoversPlaintextAndSenderPubkey() throws {
        let vectors = try FudpVectors.load()
        for vector in vectors.asyTwoWay {
            // The recipient's privkey is *not* in the vector. Identify it by
            // direction: if local is alice (sample), recipient is bob; if
            // local is bob (0x42), recipient is alice. In either case,
            // peerPubkeyHex == recipient's pubkey, so we can pick the
            // matching privkey from the two known identities.
            let recipientPriv = recipientPrivkey(for: vector)
            let (sender, plaintext) = try AsyTwoWay.open(
                bundle: Data(fromHex: vector.bundleHex),
                aad: Data(fromHex: vector.aadHex),
                localPrivkey: recipientPriv
            )
            XCTAssertEqual(sender.hex, vector.localPubkeyHex,
                           "sender pubkey '\(vector.label)'")
            XCTAssertEqual(plaintext.hex, vector.plaintextHex,
                           "plaintext '\(vector.label)'")
        }
    }

    // MARK: - tamper detection (F1: header AAD must matter)

    func testWrongAadFailsAuthentication() throws {
        let vectors = try FudpVectors.load()
        // Pick a vector that has non-empty AAD so the test means something.
        guard let vector = vectors.asyTwoWay.first(where: { !$0.aadHex.isEmpty }) else {
            XCTFail("expected a vector with AAD"); return
        }
        var tamperedAad = Data(fromHex: vector.aadHex)
        tamperedAad[0] ^= 0x01
        let recipientPriv = recipientPrivkey(for: vector)
        XCTAssertThrowsError(
            try AsyTwoWay.open(
                bundle: Data(fromHex: vector.bundleHex),
                aad: tamperedAad,
                localPrivkey: recipientPriv
            )
        ) { error in
            guard case AsyTwoWay.Failure.decryptionFailed = error else {
                XCTFail("expected decryptionFailed, got \(error)"); return
            }
        }
    }

    func testTamperedCiphertextFailsAuthentication() throws {
        let vectors = try FudpVectors.load()
        let vector = vectors.asyTwoWay[0]
        var bundleBytes = Array(Data(fromHex: vector.bundleHex))
        // Flip a bit in the last byte (inside the GCM tag).
        bundleBytes[bundleBytes.count - 1] ^= 0x01
        XCTAssertThrowsError(
            try AsyTwoWay.open(
                bundle: Data(bundleBytes),
                aad: Data(fromHex: vector.aadHex),
                localPrivkey: recipientPrivkey(for: vector)
            )
        )
    }

    func testWrongRecipientPrivkeyFails() throws {
        let vectors = try FudpVectors.load()
        let vector = vectors.asyTwoWay[0]
        // Use an unrelated 0x33-pattern privkey rather than the real
        // recipient's. ECDH yields a different shared secret → wrong
        // symKey → AEAD tag fails.
        let unrelatedPriv = Data(repeating: 0x33, count: 32)
        XCTAssertThrowsError(
            try AsyTwoWay.open(
                bundle: Data(fromHex: vector.bundleHex),
                aad: Data(fromHex: vector.aadHex),
                localPrivkey: unrelatedPriv
            )
        ) { error in
            guard case AsyTwoWay.Failure.decryptionFailed = error else {
                XCTFail("expected decryptionFailed, got \(error)"); return
            }
        }
    }

    // MARK: - shape validation

    func testRejectsBadIvLength() {
        XCTAssertThrowsError(
            try AsyTwoWay.seal(
                plaintext: Data("x".utf8),
                aad: Data(),
                peerPubkey: Data(repeating: 0x02, count: 33),
                localPrivkey: Data(repeating: 0x11, count: 32),
                localPubkey: Data(repeating: 0x02, count: 33),
                iv: Data(repeating: 0, count: 11)
            )
        ) { error in
            guard case AsyTwoWay.Failure.invalidIvLength = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testOpenRejectsTruncatedBundle() {
        XCTAssertThrowsError(
            try AsyTwoWay.open(
                bundle: Data(repeating: 0, count: 10),
                aad: Data(),
                localPrivkey: Data(repeating: 0x11, count: 32)
            )
        ) { error in
            guard case AsyTwoWay.Failure.bundleTooShort = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    func testOpenRejectsUnknownAlgorithmId() {
        var badBundle = Data(repeating: 0xff, count: 6)  // bogus algId
        badBundle.append(0x02)                            // type
        badBundle.append(Data(repeating: 0x02, count: 33))
        badBundle.append(Data(repeating: 0x00, count: 12))
        badBundle.append(Data(repeating: 0x00, count: 16))
        XCTAssertThrowsError(
            try AsyTwoWay.open(bundle: badBundle, aad: Data(),
                               localPrivkey: Data(repeating: 0x11, count: 32))
        ) { error in
            guard case AsyTwoWay.Failure.unknownAlgorithmId = error else {
                XCTFail("wrong error: \(error)"); return
            }
        }
    }

    // MARK: - shared secret + symkey parity (sanity)

    /// We trust Secp256k1.sharedSecretX (Phase 1) and Hkdf.sha512 (Phase 1)
    /// independently. This test confirms our composition feeds them the
    /// arguments FC-JDK feeds: ECDH → 32B X-coord, then HKDF-SHA512 with
    /// salt = iv, info = "hkdf".
    func testSharedSecretAndSymKeyMatchVectors() throws {
        let vectors = try FudpVectors.load()
        for vector in vectors.asyTwoWay {
            let shared = try Secp256k1.sharedSecretX(
                privateKey: Data(fromHex: vector.localPrivkeyHex),
                publicKey: Data(fromHex: vector.peerPubkeyHex)
            )
            XCTAssertEqual(shared.hex, vector.sharedSecretHex,
                           "shared secret '\(vector.label)'")

            let symKey = Hkdf.sha512(
                ikm: shared,
                salt: Data(fromHex: vector.ivHex),
                info: AsyTwoWay.hkdfInfo,
                outputLength: 32
            )
            XCTAssertEqual(symKey.hex, vector.symKeyHex,
                           "symkey '\(vector.label)'")
        }
    }

    // MARK: - helper

    /// Recover the recipient's privkey from the well-known sample / 0x42
    /// pair used in the vectors. Returns sample if the sender was 0x42,
    /// 0x42 if the sender was sample.
    private func recipientPrivkey(for vector: FudpVectors.AsyTwoWayCase) -> Data {
        let samplePrivHex = "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575"
        let sampleHex = vector.localPrivkeyHex.lowercased()
        if sampleHex == samplePrivHex {
            // sender was sample → recipient is 0x42
            return Data(repeating: 0x42, count: 32)
        }
        return Data(fromHex: samplePrivHex)
    }
}
