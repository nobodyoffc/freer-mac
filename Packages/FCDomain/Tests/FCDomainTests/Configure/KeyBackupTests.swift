import XCTest
@testable import FCDomain
import FCCore

/// Pins that the three shapes Android Safe's Export Keys writes — random
/// password, app password, no encryption — read back to the keys they hold.
final class KeyBackupTests: XCTestCase {

    private static let password = "ABCDEFGHIJKLMNOP"

    private let prikeyA = Data((1 ... 32).map { UInt8($0) })
    private let prikeyB = Data((33 ... 64).map { UInt8($0) })

    private func fid(_ prikey: Data) -> String {
        try! FchAddress(publicKey: Secp256k1.publicKey(fromPrivateKey: prikey)).fid
    }

    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    private var keyName: String { Hash.sha256(Data(Self.password.utf8)).prefix(6).fcToolHex }

    private func cipher(_ prikey: Data) throws -> String {
        try CryptoBundle.sealPassword(plaintext: prikey, password: Data(Self.password.utf8)).base64EncodedString()
    }

    private func export(backupKey: String?) throws -> String {
        var lines: [String] = []
        if let backupKey { lines.append(backupKey) }
        lines.append("""
        {
          "time": "2026-09-21 10:00:00",
          "items": 3,
          "keyName": "\(keyName)",
          "alg": "FC_AesGcm256_No1_NrC7",
          "tClass": "KeyInfo"
        }
        """)
        lines.append("""
        {"prikeyCipher": "\(try cipher(prikeyA))", "label": "alice", "saveTime": "2026-01-01", "id": "\(fid(prikeyA))"}
        """)
        lines.append("""
        {"prikeyCipher": "\(try cipher(prikeyB))", "id": "\(fid(prikeyB))"}
        """)
        let pubkey = hex(try Secp256k1.publicKey(fromPrivateKey: Data(repeating: 7, count: 32)))
        lines.append("{\"id\": \"\(fid(Data(repeating: 7, count: 32)))\", \"pubkey\": \"\(pubkey)\"}")
        return lines.joined(separator: "\n\n")
    }

    func testRandomPasswordExportOpensWithItsOwnPassword() throws {
        let text = try export(backupKey: """
        {"password": "\(Self.password)", "time": "2026-09-21 10:00:00", "keyName": "\(keyName)"}
        """)
        XCTAssertEqual(KeyInput.detect(text), .backup)
        let backup = try XCTUnwrap(KeyBackup.parse(text))

        XCTAssertEqual(backup.password, Self.password)
        XCTAssertEqual(backup.itemClass, "KeyInfo")
        XCTAssertEqual(backup.entries.count, 3)
        XCTAssertEqual(backup.entries.map(\.canSign), [true, true, false])
        XCTAssertEqual(backup.entries[0].label, "alice")

        let password = Data(Self.password.utf8)
        XCTAssertEqual(try backup.open(backup.entries[0], password: password), prikeyA)
        XCTAssertEqual(try backup.open(backup.entries[1], password: password), prikeyB)
        XCTAssertThrowsError(try backup.open(backup.entries[2], password: password))
    }

    func testAppPasswordExportRejectsAWrongPasswordBeforeTheKdf() throws {
        let text = try export(backupKey: """
        {"hint": "The app password can't be shown.", "keyName": "\(keyName)"}
        """)
        let backup = try XCTUnwrap(KeyBackup.parse(text))
        XCTAssertNil(backup.password)
        XCTAssertNotNil(backup.hint)
        XCTAssertTrue(backup.needsPassword)
        XCTAssertFalse(backup.accepts(password: Data("nope".utf8)))
        XCTAssertThrowsError(try backup.open(backup.entries[0], password: Data("nope".utf8))) {
            XCTAssertEqual($0 as? KeyBackup.Failure, .wrongPassword)
        }
        XCTAssertEqual(try backup.open(backup.entries[0], password: Data(Self.password.utf8)), prikeyA)
    }

    func testUnencryptedExport() throws {
        let text = """
        {"prikey": "\(hex(prikeyA))", "label": "a", "id": "\(fid(prikeyA))"}

        {"prikey": "\(hex(prikeyB))", "id": "\(fid(prikeyB))"}
        """
        let backup = try XCTUnwrap(KeyBackup.parse(text))
        XCTAssertFalse(backup.needsPassword)
        XCTAssertEqual(try backup.open(backup.entries[1], password: nil), prikeyB)
    }

    func testAnFidThatDoesNotMatchItsPrikeyIsRefused() throws {
        let text = "{\"prikey\": \"\(hex(prikeyA))\", \"id\": \"\(fid(prikeyB))\"}"
        let backup = try XCTUnwrap(KeyBackup.parse(text))
        XCTAssertThrowsError(try backup.open(backup.entries[0], password: nil)) {
            guard case .fidMismatch = $0 as? KeyBackup.Failure else { return XCTFail("\($0)") }
        }
    }

    func testTextWithoutKeysIsNotABackup() {
        XCTAssertNil(KeyBackup.parse("{\"time\": \"x\", \"items\": 0}"))
        XCTAssertNil(KeyBackup.parse("hello"))
    }
}
