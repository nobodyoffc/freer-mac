import XCTest
@testable import FCCore

final class PhraseKeyTests: XCTestCase {

    func testLegacySha256MatchesVectors() throws {
        let vectors = try TestVectors.load()
        XCTAssertFalse(vectors.phraseToPrivkey.isEmpty)
        for vector in vectors.phraseToPrivkey {
            let priv = try PhraseKey.privateKey(
                fromPhrase: vector.phraseUtf8, scheme: .legacySha256
            )
            XCTAssertEqual(priv.hex, vector.legacy.privkeyHex,
                           "legacy privkey '\(vector.phraseUtf8)'")

            // Cross-check: the derived privkey must produce the same
            // pubkey freecashj produced — ties the whole chain together.
            let pub = try Secp256k1.publicKey(fromPrivateKey: priv)
            XCTAssertEqual(pub.hex, vector.legacy.pubkeyHex,
                           "legacy pubkey '\(vector.phraseUtf8)'")
        }
    }

    func testArgon2idMatchesVectors() throws {
        let vectors = try TestVectors.load()
        for vector in vectors.phraseToPrivkey {
            let priv = try PhraseKey.privateKey(
                fromPhrase: vector.phraseUtf8, scheme: .argon2id
            )
            XCTAssertEqual(priv.hex, vector.argon2id.privkeyHex,
                           "argon2id privkey '\(vector.phraseUtf8)'")

            let pub = try Secp256k1.publicKey(fromPrivateKey: priv)
            XCTAssertEqual(pub.hex, vector.argon2id.pubkeyHex,
                           "argon2id pubkey '\(vector.phraseUtf8)'")
        }
    }

    /// The two schemes must produce different keys for the same phrase —
    /// otherwise upgrading users would be silently broken.
    func testSchemesProduceDifferentKeysForSamePhrase() throws {
        let phrase = "correct horse battery staple"
        let legacy = try PhraseKey.privateKey(fromPhrase: phrase, scheme: .legacySha256)
        let argon = try PhraseKey.privateKey(fromPhrase: phrase, scheme: .argon2id)
        XCTAssertNotEqual(legacy, argon)
    }

    func testRejectsEmptyPhrase() {
        for scheme in PhraseKey.Scheme.allCases {
            XCTAssertThrowsError(
                try PhraseKey.privateKey(fromPhrase: "", scheme: scheme)
            ) { error in
                guard case PhraseKey.Failure.emptyPhrase = error else {
                    XCTFail("expected emptyPhrase, got \(error)"); return
                }
            }
        }
    }

    /// The safety metadata must clearly mark legacy as not-recommended
    /// and must carry a non-nil advisory string. UI layers rely on this.
    func testLegacySchemeIsMarkedUnsafe() {
        XCTAssertFalse(PhraseKey.Scheme.legacySha256.isRecommendedForNewKeys)
        XCTAssertNotNil(PhraseKey.Scheme.legacySha256.advisory)

        XCTAssertTrue(PhraseKey.Scheme.argon2id.isRecommendedForNewKeys)
        XCTAssertNil(PhraseKey.Scheme.argon2id.advisory)
    }

    /// The protocol salt must match the Java generator's byte-for-byte,
    /// otherwise cross-platform phrase import would silently fail.
    func testArgon2idSaltMatchesJavaConstant() {
        XCTAssertEqual(
            String(data: PhraseKey.argon2idProtocolSalt, encoding: .utf8),
            "fc.freer.phrase.v1"
        )
    }
}
