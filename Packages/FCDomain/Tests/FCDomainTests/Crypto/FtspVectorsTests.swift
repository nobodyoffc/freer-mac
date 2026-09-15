import XCTest
import FCCore
@testable import FCDomain

/// The shared FTSP vectors (Freeverse `Protocols/FTSP/vectors`), which FC-JDK
/// generates and every implementation must pass. Copied in by
/// `Freeverse/tools/sync-ftsp-vectors.sh`; rerun it after regenerating them.
final class FtspVectorsTests: XCTestCase {

    private static let encryptTypes: [String: CryptoBundle.EncryptType] = [
        "Symkey": .symkey, "AsyOneWay": .asyOneWay, "AsyTwoWay": .asyTwoWay, "Password": .password,
    ]

    private func vectors(_ name: String) throws -> [[String: Any]] {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "ftsp-vectors") else {
            XCTFail("ftsp-vectors/\(name).json missing; run Freeverse/tools/sync-ftsp-vectors.sh")
            throw CocoaError(.fileReadNoSuchFile)
        }
        let root = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        let list = try XCTUnwrap(root?["vectors"] as? [[String: Any]])
        XCTAssertFalse(list.isEmpty, name)
        return list
    }

    func testKdfVectors() throws {
        for v in try vectors("kdf") {
            let id = v["id"] as? String ?? "?"
            let kdf = try XCTUnwrap(KdfKind(wireName: v["kdf"] as? String ?? ""), id)
            let kdfId = Data(fromHex: try XCTUnwrap(v["kdfId"] as? String, id))
            XCTAssertEqual(KdfKind(bundleId: kdfId[kdfId.startIndex]), kdf, id)
            let password = Data(try XCTUnwrap(v["password"] as? String, id).utf8)
            let salt = Data(fromHex: try XCTUnwrap(v["salt"] as? String, id))
            XCTAssertEqual(try kdf.deriveSymkey(password: password, salt: salt).hex, v["symkey"] as? String, id)
        }
    }

    func testCipherJsonVectors() throws {
        for v in try vectors("cipher-json") {
            let id = v["id"] as? String ?? "?"
            let json = try XCTUnwrap(v["cipherJson"] as? String, id)
            let secret = try XCTUnwrap(v["secret"] as? [String: String], id)
            let plain: Data
            switch v["type"] as? String {
            case "Symkey":
                plain = try TextCipher.decrypt(envelope: TextCipher.parse(json), symkey: Data(fromHex: secret["symkey"] ?? ""))
            case "Password":
                plain = try TextCipher.decrypt(envelope: TextCipher.parse(json), password: Data((secret["password"] ?? "").utf8))
            case "AsyOneWay", "AsyTwoWay":
                plain = try AsyCipher.decrypt(cipherString: json, privkey: Data(fromHex: secret["prikey"] ?? ""))
            default:
                XCTFail("unknown type in \(id)")
                continue
            }
            XCTAssertEqual(plain.hex, v["plaintextHex"] as? String, id)
        }
    }

    func testBundleVectors() throws {
        for v in try vectors("bundle") {
            let id = v["id"] as? String ?? "?"
            let bundle = Data(fromHex: try XCTUnwrap(v["bundleHex"] as? String, id))
            XCTAssertEqual(Data(base64Encoded: v["bundleBase64"] as? String ?? ""), bundle, id)
            if v["expect"] as? String == "reject" {
                XCTAssertThrowsError(try CryptoBundle.parse(bundle), "\(id) must be rejected")
                continue
            }
            let parsed = try CryptoBundle.parse(bundle)
            XCTAssertEqual(parsed.algorithm.name, v["alg"] as? String, id)
            XCTAssertEqual(parsed.type, Self.encryptTypes[v["type"] as? String ?? ""], id)
            XCTAssertEqual(parsed.kdf?.wireName, v["kdfRecorded"] as? String, id)
            if v["canonical"] as? Bool == true {
                XCTAssertEqual(CryptoBundle.serialize(parsed), bundle, "\(id): serialize does not reproduce the bundle")
            }
            let secret = try XCTUnwrap(v["secret"] as? [String: String], id)
            let plain: Data
            switch parsed.type {
            case .symkey:
                plain = try CryptoBundle.open(bundle: bundle, symkey: Data(fromHex: secret["symkey"] ?? ""))
            case .password:
                plain = try CryptoBundle.open(bundle: bundle, password: Data((secret["password"] ?? "").utf8))
            case .asyOneWay, .asyTwoWay:
                plain = try CryptoBundle.open(bundle: bundle, privkey: Data(fromHex: secret["prikey"] ?? ""))
            }
            XCTAssertEqual(plain.hex, v["plaintextHex"] as? String, id)
        }
    }

    /// The other FTSP profiles. FreerForMac opens none of them, but its parser must still
    /// read the framing of their bundles, tampered ones included.
    func testAlgorithmBundlesParse() throws {
        for v in try vectors("algorithms") where v["form"] as? String == "bundle" {
            let id = v["id"] as? String ?? "?"
            let bundle = Data(fromHex: try XCTUnwrap(v["bundleHex"] as? String, id))
            let parsed = try CryptoBundle.parse(bundle)
            XCTAssertEqual(parsed.algorithm.name, v["alg"] as? String, id)
            XCTAssertEqual(parsed.type, Self.encryptTypes[v["type"] as? String ?? ""], id)
        }
    }

    func testSealPasswordRoundTrip() throws {
        let plaintext = Data("Hello world!".utf8)
        let bundle = try CryptoBundle.sealPassword(plaintext: plaintext, password: Data("MyPassword".utf8))
        XCTAssertEqual(bundle[bundle.startIndex + 6], CryptoBundle.writePasswordBundleWithKdf ? 4 : 3)
        XCTAssertEqual(try CryptoBundle.parse(bundle).type, .password)
        XCTAssertEqual(try CryptoBundle.open(bundle: bundle, password: Data("MyPassword".utf8)), plaintext)
        XCTAssertThrowsError(try CryptoBundle.open(bundle: bundle, password: Data("not the password".utf8)))
    }
}
