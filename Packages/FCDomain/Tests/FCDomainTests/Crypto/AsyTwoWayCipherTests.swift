import XCTest
import FCCore
@testable import FCDomain

/// `AsyTwoWayCipher` against envelopes sealed by the real FC-AJDK
/// `Encryptor` (`tools/vector-gen/.../AsyTwoWayRef.java`).
///
/// The property that earns this whole type its existence is
/// ``testSenderOpensTheirOwnMail``: with the AsyOneWay cipher we already
/// had, a sent mail would be write-only.
final class AsyTwoWayCipherTests: XCTestCase {

    private var root: DomainVectors.AsyTwoWayRoot!

    override func setUpWithError() throws {
        root = try DomainVectors.load().asyTwoWayEnvelope
    }

    private var privkeyA: Data { Data(fromHex: root.prikeyA) }
    private var privkeyB: Data { Data(fromHex: root.prikeyB) }
    private var stranger: Data { Data(fromHex: root.strangerPrikey) }

    // MARK: - Java-sealed envelopes

    /// Every vector opens on the recipient's side, GCM and CBC alike.
    /// The CBC cases are not academic: `Mail.encryptContent` — the path a
    /// carved mail actually takes — asks for CBC, so a GCM-only port would
    /// fail on every mail Android has put on chain.
    func testRecipientOpensEveryJavaVector() throws {
        for v in root.vectors {
            let key = v.isTwoWay ? privkeyB : privkeyA
            let plaintext = try AsyCipher.decrypt(cipherString: v.envelope, privkey: key)
            XCTAssertEqual(plaintext.hex, v.plaintextHex, "vector \(v.name)")
            XCTAssertEqual(String(data: plaintext, encoding: .utf8), v.plaintext, "vector \(v.name)")
        }
        XCTAssertFalse(root.vectors.isEmpty)
    }

    /// The sender opens what they sealed — the reason AsyTwoWay exists.
    func testSenderOpensTheirOwnMail() throws {
        let twoWay = root.vectors.filter(\.isTwoWay)
        XCTAssertFalse(twoWay.isEmpty)
        for v in twoWay {
            let plaintext = try AsyTwoWayCipher.decrypt(cipherString: v.envelope, privkey: privkeyA)
            XCTAssertEqual(plaintext.hex, v.plaintextHex, "vector \(v.name)")
        }
    }

    func testStrangerOpensNothing() throws {
        XCTAssertFalse(root.strangerCanDecrypt, "the generator expects the stranger to be locked out")
        for v in root.vectors {
            XCTAssertThrowsError(
                try AsyCipher.decrypt(cipherString: v.envelope, privkey: stranger),
                "vector \(v.name) opened for an unrelated key"
            )
        }
    }

    /// Both algorithms are actually exercised above — a vector file that
    /// silently lost its CBC cases would otherwise still pass.
    func testVectorsCoverBothAlgorithms() {
        let algs = Set(root.vectors.map(\.alg))
        XCTAssertTrue(algs.contains("FC_EccK1AesGcm256_No1_NrC7"))
        XCTAssertTrue(algs.contains("FC_EccK1AesCbc256_No1_NrC7"))
        XCTAssertTrue(root.vectors.contains { !$0.isTwoWay }, "self-addressed AsyOneWay case missing")
    }

    // MARK: - our own envelopes

    func testRoundTripBothDirections() throws {
        let pubkeyB = try Secp256k1.publicKey(fromPrivateKey: privkeyB)
        let message = Data("Meet me at the usual place. 老地方见 🚀".utf8)
        let envelope = try AsyTwoWayCipher.encrypt(
            plaintext: message, privkeyA: privkeyA, toPubkey: pubkeyB
        )

        XCTAssertEqual(try AsyTwoWayCipher.decrypt(cipherString: envelope, privkey: privkeyB), message)
        XCTAssertEqual(try AsyTwoWayCipher.decrypt(cipherString: envelope, privkey: privkeyA), message)
        XCTAssertEqual(try AsyCipher.decrypt(cipherString: envelope, privkey: privkeyB), message)
        XCTAssertThrowsError(try AsyTwoWayCipher.decrypt(cipherString: envelope, privkey: stranger))
    }

    /// Field names, order, and the two recorded pubkeys — what an Android
    /// peer parses. `sum` must be absent: GCM authenticates itself and the
    /// Java encryptor skips the checksum for AEAD algorithms.
    func testEnvelopeShapeMatchesJava() throws {
        let pubkeyA = try Secp256k1.publicKey(fromPrivateKey: privkeyA)
        let pubkeyB = try Secp256k1.publicKey(fromPrivateKey: privkeyB)
        let envelope = try AsyTwoWayCipher.encrypt(
            plaintext: Data("hi".utf8), privkeyA: privkeyA, toPubkey: pubkeyB
        )

        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(envelope.utf8)) as? [String: Any]
        )
        XCTAssertEqual(json["type"] as? String, "AsyTwoWay")
        XCTAssertEqual(json["alg"] as? String, "EccK1AesGcm256@No1_NrC7")
        XCTAssertEqual(json["pubkeyA"] as? String, pubkeyA.hex)
        XCTAssertEqual(json["pubkeyB"] as? String, pubkeyB.hex)
        XCTAssertEqual((json["iv"] as? String)?.count, 24)
        XCTAssertNil(json["sum"])
        XCTAssertEqual(Set(json.keys), ["type", "alg", "cipher", "pubkeyA", "pubkeyB", "iv"])

        // Declaration order, as Gson emits it.
        let order = ["type", "alg", "cipher", "pubkeyA", "pubkeyB", "iv"]
        let positions = order.compactMap { envelope.range(of: "\"\($0)\":")?.lowerBound }
        XCTAssertEqual(positions.count, order.count)
        XCTAssertEqual(positions, positions.sorted())
    }

    func testEachEnvelopeUsesAFreshIv() throws {
        let pubkeyB = try Secp256k1.publicKey(fromPrivateKey: privkeyB)
        var ivs = Set<String>()
        for _ in 0..<16 {
            let envelope = try AsyTwoWayCipher.encrypt(
                plaintext: Data("same body every time".utf8),
                privkeyA: privkeyA, toPubkey: pubkeyB
            )
            let json = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(envelope.utf8)) as? [String: Any]
            )
            ivs.insert(try XCTUnwrap(json["iv"] as? String))
        }
        XCTAssertEqual(ivs.count, 16)
    }

    // MARK: - tampering

    func testTamperedGcmCiphertextIsRejected() throws {
        let v = try XCTUnwrap(root.vectors.first { $0.alg.contains("Gcm") && $0.isTwoWay })
        XCTAssertThrowsError(try AsyCipher.decrypt(cipherString: flipCipherBit(v.envelope), privkey: privkeyB))
    }

    /// CBC has no AEAD tag, so a flipped bit often decrypts to garbage
    /// instead of failing. The 4-byte `sum` is the only thing standing
    /// between that garbage and a mail body rendered to the user — this
    /// pins that we check it.
    func testTamperedCbcCiphertextIsCaughtBySum() throws {
        let v = try XCTUnwrap(root.vectors.first { $0.alg.contains("Cbc") && $0.isTwoWay })
        var caught = 0
        // Several offsets: some corruptions break the padding (a decrypt
        // failure), the rest must be caught by the checksum. Neither
        // outcome may be "returns a plaintext".
        for byteIndex in 0..<8 {
            let tampered = flipCipherBit(v.envelope, atByte: byteIndex)
            XCTAssertThrowsError(
                try AsyCipher.decrypt(cipherString: tampered, privkey: privkeyB),
                "CBC vector \(v.name) accepted a corrupted ciphertext at byte \(byteIndex)"
            ) { _ in caught += 1 }
        }
        XCTAssertEqual(caught, 8)
    }

    func testWrongSumIsRejected() throws {
        let v = try XCTUnwrap(root.vectors.first { $0.alg.contains("Cbc") && $0.isTwoWay })
        // Sanity: it opens untouched.
        XCTAssertNoThrow(try AsyCipher.decrypt(cipherString: v.envelope, privkey: privkeyB))

        var json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(v.envelope.utf8)) as? [String: Any]
        )
        XCTAssertNotNil(json["sum"], "CBC envelopes are expected to carry a sum")
        json["sum"] = "deadbeef"
        let rewritten = try JSONSerialization.data(withJSONObject: json)
        XCTAssertThrowsError(
            try AsyCipher.decrypt(cipherString: String(decoding: rewritten, as: UTF8.self), privkey: privkeyB)
        ) { error in
            guard case AsyOneWayCipher.Failure.badSum = error else {
                return XCTFail("expected badSum, got \(error)")
            }
        }
    }

    // MARK: - dispatch

    /// `AsyCipher` picks the path from the envelope, which is what a
    /// mailbox holding both kinds needs.
    func testDispatcherRoutesByType() throws {
        let oneWay = try XCTUnwrap(root.vectors.first { !$0.isTwoWay })
        let twoWay = try XCTUnwrap(root.vectors.first(where: \.isTwoWay))

        XCTAssertNoThrow(try AsyCipher.decrypt(cipherString: oneWay.envelope, privkey: privkeyA))
        XCTAssertNoThrow(try AsyCipher.decrypt(cipherString: twoWay.envelope, privkey: privkeyB))
        // ...and the wrong concrete cipher does not silently succeed:
        // AsyOneWayCipher would ECDH against pubkeyA, which for the sender
        // is their own key.
        XCTAssertThrowsError(
            try AsyOneWayCipher.decrypt(cipherString: twoWay.envelope, privkey: privkeyA)
        )
    }

    /// A self-addressed envelope sealed two-way (both pubkeys ours) is
    /// readable here even though Java's side-selection gives up on it. We
    /// never write one — `Mail.encryptContent` uses AsyOneWay when
    /// `from == to` — but reading one costs nothing and losing a mail to it
    /// would be silent.
    func testSelfAddressedTwoWayEnvelopeOpens() throws {
        let pubkeyA = try Secp256k1.publicKey(fromPrivateKey: privkeyA)
        let message = Data("a note to myself".utf8)
        let envelope = try AsyTwoWayCipher.encrypt(
            plaintext: message, privkeyA: privkeyA, toPubkey: pubkeyA
        )
        XCTAssertEqual(try AsyTwoWayCipher.decrypt(cipherString: envelope, privkey: privkeyA), message)
        XCTAssertThrowsError(try AsyTwoWayCipher.decrypt(cipherString: envelope, privkey: privkeyB))
    }

    func testMalformedEnvelopesThrowRatherThanCrash() {
        for bad in ["", "{", "{}", "not json", #"{"type":"AsyTwoWay"}"#,
                    #"{"type":"AsyTwoWay","cipher":"!!!","iv":"zz","pubkeyA":"00"}"#] {
            XCTAssertThrowsError(try AsyCipher.decrypt(cipherString: bad, privkey: privkeyB), bad)
        }
    }

    // MARK: - helpers

    /// Flips one bit of the base64 `cipher` field, leaving everything else
    /// byte-identical.
    private func flipCipherBit(_ envelope: String, atByte index: Int = 0) -> String {
        guard
            let json = try? JSONSerialization.jsonObject(with: Data(envelope.utf8)) as? [String: Any],
            let b64 = json["cipher"] as? String,
            var bytes = Data(base64Encoded: b64), index < bytes.count
        else { return envelope }
        bytes[bytes.startIndex + index] ^= 0x01
        var mutated = json
        mutated["cipher"] = bytes.base64EncodedString()
        guard let data = try? JSONSerialization.data(withJSONObject: mutated) else { return envelope }
        return String(decoding: data, as: UTF8.self)
    }
}
