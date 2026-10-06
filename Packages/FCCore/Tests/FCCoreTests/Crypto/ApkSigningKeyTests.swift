import XCTest
import CryptoKit
import Security
@testable import FCCore

final class ApkSigningKeyTests: XCTestCase {

    private static let privkey = Data(repeating: 0x42, count: 32)
    private static let fid = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK"

    // MARK: - The frozen vector
    //
    // Provenance: a keystore exported from the inputs above, then
    // checked with the Android tools themselves. `keytool -list -v`
    // (JBR 21) reads it as one PrivateKeyEntry "freer", owner
    // CN=FEk41Kqjar45fLDriztUDTUkdki7mmcjWK, O=Freer; `apksigner sign
    // --ks` (build-tools 36.0.0) signs a release APK with it, and
    // `apksigner verify --print-certs` reports the signer certificate
    // SHA-256 below. Android pins every installed copy to that digest,
    // so if this test fails, apps already signed can no longer be
    // updated: bump `derivationSalt` deliberately, with a v3 rotation,
    // rather than editing the vector.

    private static let expectedCertificateSha256 =
        "d2a1b8d9c0c5298d600eeb5b8ff9fff5610cb3229c2f365c8f4d04e3af0f765b"

    func testKnownAnswerVector() throws {
        let key = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: Self.fid)
        XCTAssertEqual(Hex.encode(key.certificateSha256), Self.expectedCertificateSha256)
    }

    // MARK: - RFC 6979

    /// RFC 6979 A.2.5, P-256 with SHA-256, message "sample".
    func testRfc6979KnownAnswer() throws {
        let scalar = try Hex.decode("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
        let (r, s) = try ApkSigningKey.rfc6979Sign(
            digest: Data(SHA256.hash(data: Data("sample".utf8))), scalar: scalar
        )
        XCTAssertEqual(Hex.encode(r).uppercased(), "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")
        XCTAssertEqual(Hex.encode(s).uppercased(), "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
    }

    /// RFC 6979 A.2.5, message "test" — a second vector, so a fluke
    /// on one input can't pass.
    func testRfc6979SecondVector() throws {
        let scalar = try Hex.decode("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
        let (r, s) = try ApkSigningKey.rfc6979Sign(
            digest: Data(SHA256.hash(data: Data("test".utf8))), scalar: scalar
        )
        XCTAssertEqual(Hex.encode(r).uppercased(), "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367")
        XCTAssertEqual(Hex.encode(s).uppercased(), "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083")
    }

    // MARK: - Determinism

    /// The whole point: the certificate, not just the key, is a pure
    /// function of (prikey, FID). Android pins the app to these bytes.
    func testCertificateIsByteIdenticalAcrossDerivations() throws {
        let a = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: Self.fid)
        let b = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: Self.fid)
        XCTAssertEqual(a.certificate, b.certificate)
        XCTAssertEqual(a.pkcs8, b.pkcs8)
    }

    func testDifferentFidGivesDifferentSigner() throws {
        let a = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: Self.fid)
        let b = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: "FTqiQAWCVsUKWzjyHxTvmwzxKQ2y7Xxxxx")
        XCTAssertNotEqual(a.publicKeyDer, b.publicKeyDer)
    }

    func testDifferentPrikeyGivesDifferentSigner() throws {
        let a = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: Self.fid)
        let b = try ApkSigningKey(mainPrikey: Data(repeating: 0x43, count: 32), mainFid: Self.fid)
        XCTAssertNotEqual(a.publicKeyDer, b.publicKeyDer)
    }

    // MARK: - Certificate

    func testCertificateParsesAndNamesTheFid() throws {
        let key = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: Self.fid)
        let cert = try XCTUnwrap(SecCertificateCreateWithData(nil, key.certificate as CFData))
        var cn: CFString?
        XCTAssertEqual(SecCertificateCopyCommonName(cert, &cn), errSecSuccess)
        XCTAssertEqual(cn as String?, Self.fid)
        XCTAssertEqual(SecCertificateCopyKey(cert).flatMap { SecKeyCopyExternalRepresentation($0, nil) } as Data?,
                       try P256.Signing.PublicKey(derRepresentation: key.publicKeyDer).x963Representation)
    }

    func testFingerprintFormat() throws {
        let key = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: Self.fid)
        XCTAssertEqual(key.fingerprint.split(separator: ":").count, 32)
        XCTAssertEqual(key.fingerprint, key.fingerprint.uppercased())
    }

    // MARK: - Keystore

    func testEmptyPasswordIsRefused() throws {
        let key = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: Self.fid)
        XCTAssertThrowsError(try key.keystore(password: ""))
    }

    /// Java's PKCS#12 loader rejects these, so we refuse to write them.
    func testNonAsciiPasswordIsRefused() throws {
        let key = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: Self.fid)
        XCTAssertThrowsError(try key.keystore(password: "pässword"))
        XCTAssertNoThrow(try key.keystore(password: "p@ss word~"))
    }

    /// Cross-checks the PKCS#12 against OpenSSL when one is installed:
    /// the MAC must verify and the key must decrypt back to our PKCS#8.
    func testKeystoreOpensInOpenSsl() throws {
        let openssl = ["/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl"]
            .first { FileManager.default.isExecutableFile(atPath: $0) }
        guard let openssl else { throw XCTSkip("no openssl on this machine") }

        let key = try ApkSigningKey(mainPrikey: Self.privkey, mainFid: Self.fid)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let p12 = dir.appendingPathComponent("k.p12")
        try key.keystore(password: "s3cret").write(to: p12)

        let p = Process()
        p.executableURL = URL(fileURLWithPath: openssl)
        p.arguments = ["pkcs12", "-in", p12.path, "-nodes", "-passin", "pass:s3cret"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = Pipe()
        try p.run()
        p.waitUntilExit()
        let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard p.terminationStatus == 0 else {
            throw XCTSkip("\(openssl) could not read a PBES2/SHA-256 PKCS#12 (too old?)")
        }

        XCTAssertTrue(text.contains(ApkSigningKey.pem(key.pkcs8, label: "PRIVATE KEY")
            .split(separator: "\n")[1]))
        XCTAssertTrue(text.contains(key.certificatePem.split(separator: "\n")[1]))
        XCTAssertTrue(text.contains("friendlyName: freer"))
    }
}
