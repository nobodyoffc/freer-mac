import XCTest
import FCCore
@testable import FCDomain

/// `Secret.matches(query:)` — the in-memory filter behind the Secrets
/// pane's search box. The load-bearing case is the last one: the
/// plaintext must never be searchable, because at rest it exists only
/// as an encrypted envelope.
final class SecretMatchTests: XCTestCase {

    private func secret(
        id: String = "abc123",
        type: String? = "password",
        title: String? = "GitHub login",
        memo: String? = "work account, 2FA on",
        carveId: String? = nil
    ) -> Secret {
        Secret(id: id, type: type, title: title, memo: memo, carveId: carveId)
    }

    func testMatchesEachSearchableField() {
        let s = secret(carveId: "carve-deadbeef")
        XCTAssertTrue(s.matches(query: "github"))      // title
        XCTAssertTrue(s.matches(query: "password"))    // type
        XCTAssertTrue(s.matches(query: "2FA"))         // memo
        XCTAssertTrue(s.matches(query: "abc123"))      // id
        XCTAssertTrue(s.matches(query: "deadbeef"))    // carve id
        XCTAssertFalse(s.matches(query: "gitlab"))
    }

    func testMatchingIsCaseInsensitiveAndTrimmed() {
        let s = secret()
        XCTAssertTrue(s.matches(query: "GITHUB"))
        XCTAssertTrue(s.matches(query: "  github  "))
    }

    /// Empty query matches nothing rather than everything — callers
    /// short-circuit to the unfiltered list, same as `Hat`.
    func testEmptyQueryMatchesNothing() {
        let s = secret()
        XCTAssertFalse(s.matches(query: ""))
        XCTAssertFalse(s.matches(query: "   "))
    }

    func testNilFieldsDoNotMatch() {
        let s = secret(type: nil, title: nil, memo: nil)
        XCTAssertFalse(s.matches(query: "github"))
        XCTAssertTrue(s.matches(query: "abc123"))
    }

    /// Pattern B: the content lives only in `contentCipher`, so a
    /// search for the plaintext must miss — otherwise the result count
    /// alone would leak what a hidden secret contains.
    func testDoesNotMatchEncryptedContent() throws {
        let priv = Hash.sha256(Data("match-tests-owner".utf8))
        let pub = try Secp256k1.publicKey(fromPrivateKey: priv)
        let s = try Secret.createLocal(
            type: .password,
            title: "GitHub login",
            content: "hunter2-plaintext",
            memo: nil,
            ownPubkey: pub
        )
        XCTAssertNotNil(s.contentCipher)
        XCTAssertFalse(s.matches(query: "hunter2"))
        XCTAssertTrue(s.matches(query: "github"))
        // Sanity: the content really is recoverable, just not searchable.
        XCTAssertEqual(try s.decryptContent(privkey: priv), "hunter2-plaintext")
    }
}
