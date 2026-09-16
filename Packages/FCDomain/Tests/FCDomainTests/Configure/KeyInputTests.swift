import XCTest
@testable import FCDomain
import FCCore

/// One import field takes every kind of key text, so these pin that each form is
/// told apart, that near-miss typos are reported rather than guessed, and that a
/// cipher in either form opens back to the same private key. Ported case-for-case
/// from Android's `KeyInputDetectorTest`, which the Mac box has to agree with —
/// the two apps back up to each other's formats.
final class KeyInputTests: XCTestCase {

    private static let password = Data("correct horse".utf8)

    private var prikey: Data { Data((1 ... 32).map { UInt8($0) }) }
    private var prikeyHex: String { prikey.map { String(format: "%02x", $0) }.joined() }
    private var wif: String { WifPrivkey.encode(privkey: prikey) }
    private var pubkeyHex: String {
        let pubkey = try! Secp256k1.publicKey(fromPrivateKey: prikey)
        return pubkey.map { String(format: "%02x", $0) }.joined()
    }
    private var fid: String {
        try! FchAddress(publicKey: Secp256k1.publicKey(fromPrivateKey: prikey)).fid
    }

    /// Changes the last character to another Base58 character, so the checksum breaks.
    private func typo(_ text: String) -> String {
        let last = text.last!
        return String(text.dropLast()) + (last == "2" ? "3" : "2")
    }

    private func decrypt(_ input: String) throws -> Data {
        try KeyInput.openCipher(input, password: Self.password)
    }

    // MARK: - plain forms

    func testEmptyInput() {
        XCTAssertEqual(KeyInput.detect(nil), .empty)
        XCTAssertEqual(KeyInput.detect("  \n "), .empty)
    }

    func testPrivateKeyForms() {
        XCTAssertEqual(KeyInput.detect(prikeyHex), .prikey)
        XCTAssertEqual(KeyInput.detect("0x" + prikeyHex), .prikey)
        XCTAssertEqual(KeyInput.detect(wif), .prikey)
        XCTAssertEqual(KeyInput.detect("  " + wif + "\n"), .prikey)
        XCTAssertEqual(KeyInput.prikey32(from: wif), prikey)
        XCTAssertEqual(KeyInput.prikey32(from: "0x" + prikeyHex.uppercased()), prikey)
    }

    func testWatchOnlyForms() {
        XCTAssertEqual(KeyInput.detect(pubkeyHex), .pubkey)
        XCTAssertEqual(KeyInput.detect(fid), .fid)
    }

    /// A multisig group address is a key text the box has to recognize too — it is
    /// what someone pastes to watch a group they are in.
    func testP2shAddressIsAnFid() throws {
        let p2sh = try FchAddress(
            versionByte: FchAddress.p2shVersionByte,
            hash160: Data(repeating: 7, count: 20)
        ).fid
        XCTAssertEqual(KeyInput.detect(p2sh), .fid)
    }

    func testNearMissesAreReportedNotGuessed() {
        XCTAssertEqual(KeyInput.detect(typo(wif)), .badPrikey)
        XCTAssertEqual(KeyInput.detect(String(prikeyHex.dropLast()) + "g"), .badPrikey)
        XCTAssertEqual(KeyInput.detect(typo(fid)), .badFid)
        XCTAssertEqual(KeyInput.detect("05" + pubkeyHex.dropFirst(2)), .badPubkey)
    }

    func testSomethingElseIsUnknownOrMultiple() {
        XCTAssertEqual(KeyInput.detect("hello"), .unknown)
        XCTAssertEqual(KeyInput.detect("{\"unterminated\""), .unknown)
        XCTAssertEqual(KeyInput.detect(wif + " " + wif), .multiple)
    }

    // MARK: - ciphers

    func testJsonCipherOpensToThePrivateKey() throws {
        let json = try TextCipher.encryptWithPassword(prikey, password: Self.password)
        XCTAssertEqual(KeyInput.detect(json), .cipher)
        XCTAssertEqual(KeyInput.prikey(fromPlaintext: try decrypt(json)), prikey)
    }

    func testBase64CipherOpensToThePrivateKey() throws {
        let bundle = try CryptoBundle.sealPassword(plaintext: prikey, password: Self.password)
        let base64 = bundle.base64EncodedString()
        XCTAssertEqual(KeyInput.detect(base64), .cipher)
        XCTAssertEqual(KeyInput.prikey(fromPlaintext: try decrypt(base64)), prikey)
    }

    /// The backup sheet encrypts the *text it is showing*, so a WIF backup opens to
    /// WIF characters rather than to 32 bytes. Both have to land on the same key.
    func testEncryptedWifTextOpensToThePrivateKey() throws {
        let json = try TextCipher.encryptWithPassword(Data(wif.utf8), password: Self.password)
        XCTAssertEqual(KeyInput.prikey(fromPlaintext: try decrypt(json)), prikey)
    }

    func testEncryptedKeyJsonIsNotMistakenForAKey() throws {
        let plaintext = Data("{\"id\":\"F\"}".utf8)
        let json = try TextCipher.encryptWithPassword(plaintext, password: Self.password)
        XCTAssertEqual(KeyInput.detect(json), .cipher)

        let opened = try decrypt(json)
        XCTAssertNil(KeyInput.prikey(fromPlaintext: opened))
        XCTAssertTrue(KeyInput.isJson(opened))
        XCTAssertFalse(KeyInput.isJson(prikey))
    }

    func testKeyJsonIsABackup() throws {
        XCTAssertEqual(KeyInput.detect("{\"id\":\"\(fid)\"}"), .backup)

        let cipher = try TextCipher.encryptWithPassword(prikey, password: Self.password)
        XCTAssertEqual(KeyInput.detect(cipher + "\n" + cipher), .backup)
    }

    func testSymkeyCipherIsNotOpenedWithAPassword() throws {
        let json = try TextCipher.encryptWithSymkey(prikey, symkey: Data(repeating: 0, count: 32))
        XCTAssertEqual(KeyInput.detect(json), .nonPasswordCipher)
        XCTAssertThrowsError(try decrypt(json)) { error in
            guard case KeyInput.Failure.notPasswordEncrypted = error else {
                return XCTFail("expected notPasswordEncrypted, got \(error)")
            }
        }
    }

    func testWrongPasswordFailsRatherThanReturningGarbage() throws {
        let json = try TextCipher.encryptWithPassword(prikey, password: Self.password)
        XCTAssertThrowsError(try KeyInput.openCipher(json, password: Data("wrong".utf8)))
    }
}
