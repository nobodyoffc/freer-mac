import XCTest
import CryptoKit
@testable import FCCore

final class SshEd25519KeyTests: XCTestCase {

    // MARK: - The frozen vector
    //
    // Provenance: derived from the inputs below, then confirmed against
    // OpenSSH itself. Writing `line` to a file and running
    //
    //     ssh-keygen -l -f v.pub
    //
    // under OpenSSH_10.2p1 prints
    //
    //     256 SHA256:53g09uESDsKX5mh1XrI0KBGflNV4KkenvAq7k49dwIM
    //         freer:FEk41Kqjar45fLDriztUDTUkdki7mmcjWK (ED25519)
    //
    // — i.e. ssh-keygen parses our line as a valid ed25519 key and
    // computes the same fingerprint. If this test ever fails, every
    // `authorized_keys` line this app has ever printed is invalidated,
    // so treat a change here as a breaking change and bump
    // `derivationSalt` deliberately rather than editing the vector.

    private static let privkey = Data(repeating: 0x42, count: 32)
    private static let fid = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    private static let expectedLine =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK8bXrQ7XOKCAgfPTC+RqDZFgD+AMRVmBLSir6bq9imh"
        + " freer:FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"
    private static let expectedFingerprint = "SHA256:53g09uESDsKX5mh1XrI0KBGflNV4KkenvAq7k49dwIM"

    func testKnownAnswerVector() throws {
        let key = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: Self.fid)
        XCTAssertEqual(key.authorizedKeysLine(), Self.expectedLine)
        XCTAssertEqual(key.fingerprint, Self.expectedFingerprint)
    }

    func testPublicKeyFileHasExactlyOneTrailingNewline() throws {
        let key = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: Self.fid)
        XCTAssertEqual(key.publicKeyFileContents(), Self.expectedLine + "\n")
    }

    // MARK: - Blob shapes

    /// 4 + 11 + 4 + 32. `ssh` compares this blob byte-for-byte against
    /// what the agent advertises, so its length is not cosmetic.
    func testPublicKeyBlobIs51BytesAndStartsWithTheAlgorithmName() throws {
        let key = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: Self.fid)
        let blob = key.publicKeyBlob
        XCTAssertEqual(blob.count, 51)

        var reader = SshWire.Reader(blob)
        XCTAssertEqual(String(data: try reader.readString(), encoding: .utf8), "ssh-ed25519")
        XCTAssertEqual(try reader.readString(), key.publicKeyBytes)
        XCTAssertTrue(reader.isAtEnd)
    }

    /// 4 + 11 + 4 + 64.
    func testSignatureBlobIs83BytesAndVerifies() throws {
        let key = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: Self.fid)
        let message = Data("freer ssh test vector".utf8)
        let blob = try key.signatureBlob(message)
        XCTAssertEqual(blob.count, 83)

        var reader = SshWire.Reader(blob)
        XCTAssertEqual(String(data: try reader.readString(), encoding: .utf8), "ssh-ed25519")
        let signature = try reader.readString()
        XCTAssertEqual(signature.count, 64)
        XCTAssertTrue(reader.isAtEnd)

        let pub = try Curve25519.Signing.PublicKey(rawRepresentation: key.publicKeyBytes)
        XCTAssertTrue(pub.isValidSignature(signature, for: message))
        XCTAssertFalse(pub.isValidSignature(signature, for: Data("other".utf8)))
    }

    // MARK: - Determinism and separation

    /// The whole premise: nothing is stored, so the same vault must
    /// re-derive the same key every time, on any machine.
    func testDerivationIsDeterministic() throws {
        let a = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: Self.fid)
        let b = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: Self.fid)
        XCTAssertEqual(a.publicKeyBlob, b.publicKeyBlob)
        XCTAssertEqual(a.authorizedKeysLine(), b.authorizedKeysLine())
    }

    /// The FID is HKDF `info`, so two identities in one vault get two
    /// SSH keys — and rotating the main FID invalidates the old one.
    /// That cost is deliberate; this test pins it.
    func testDifferentFidGivesADifferentKey() throws {
        let a = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: Self.fid)
        let b = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: "FTqiQAWCVsUKWzjyHxTvmwzxKQ2y7Xxxxx")
        XCTAssertNotEqual(a.publicKeyBlob, b.publicKeyBlob)
    }

    func testDifferentPrivkeyGivesADifferentKey() throws {
        let a = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: Self.fid)
        let b = try SshEd25519Key(mainPrikey: Data(repeating: 0x43, count: 32), mainFid: Self.fid)
        XCTAssertNotEqual(a.publicKeyBlob, b.publicKeyBlob)
    }

    /// The derived key must not be the FCH key wearing a hat: the
    /// ed25519 public point must not equal the input scalar, and no
    /// output byte range may echo the input.
    func testDerivedKeyDoesNotLeakTheInputScalar() throws {
        let key = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: Self.fid)
        XCTAssertNotEqual(key.publicKeyBytes, Self.privkey)
        XCTAssertFalse(key.publicKeyBlob.range(of: Self.privkey) != nil)
    }

    // MARK: - Rejections

    func testShortPrivkeyIsRejected() {
        XCTAssertThrowsError(try SshEd25519Key(mainPrikey: Data(repeating: 1, count: 31), mainFid: Self.fid)) {
            guard case SshEd25519Key.Failure.badPrivkeyLength(31) = $0 else {
                return XCTFail("expected .badPrivkeyLength(31), got \($0)")
            }
        }
    }

    func testEmptyFidIsRejected() {
        XCTAssertThrowsError(try SshEd25519Key(mainPrikey: Self.privkey, mainFid: "")) {
            guard case SshEd25519Key.Failure.emptyFid = $0 else {
                return XCTFail("expected .emptyFid, got \($0)")
            }
        }
    }

    func testCustomCommentReplacesTheDefault() throws {
        let key = try SshEd25519Key(mainPrikey: Self.privkey, mainFid: Self.fid)
        XCTAssertTrue(key.authorizedKeysLine(comment: "laptop").hasSuffix(" laptop"))
        XCTAssertFalse(key.authorizedKeysLine(comment: "").hasSuffix(" "))
    }
}
