import XCTest
import FCCore
@testable import FCDomain

final class ContactFeipTests: XCTestCase {

    private func realFid(byte: UInt8) throws -> String {
        let priv = Data(repeating: byte, count: 32)
        let pub = try Secp256k1.publicKey(fromPrivateKey: priv)
        return try FchAddress(publicKey: pub).fid
    }

    // MARK: - op / envelope JSON shapes

    func testDetailJsonCarriesExactlyTheEditableBlock() throws {
        let fid = try realFid(byte: 0xE1)
        var contact = Contact(id: fid)
        contact.titles = ["Friend", "Engineer"]
        contact.memo = "quote \" and slash \\ survive"
        contact.seeStatement = true
        // seeWritings deliberately nil → key absent, like Gson.

        let json = try ContactFeip.detailJson(for: contact)
        let obj = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        XCTAssertEqual(obj["fid"] as? String, fid)
        XCTAssertEqual(obj["titles"] as? [String], ["Friend", "Engineer"])
        XCTAssertEqual(obj["memo"] as? String, "quote \" and slash \\ survive")
        XCTAssertEqual(obj["seeStatement"] as? Bool, true)
        XCTAssertNil(obj["seeWritings"])
        XCTAssertEqual(obj.count, 4)
    }

    func testOpPayloadShapes() throws {
        let add = try JSONSerialization.jsonObject(
            with: Data(try ContactFeip.addOp(cipher: "CIPHER").utf8)
        ) as? [String: Any]
        XCTAssertEqual(add?["op"] as? String, "add")
        XCTAssertEqual(add?["cipher"] as? String, "CIPHER")
        XCTAssertNil(add?["alg"])   // makeAdd(null, cipher) omits alg

        let update = try JSONSerialization.jsonObject(
            with: Data(try ContactFeip.updateOp(contactId: "abc123", cipher: "C2").utf8)
        ) as? [String: Any]
        XCTAssertEqual(update?["op"] as? String, "update")
        XCTAssertEqual(update?["contactId"] as? String, "abc123")

        let del = try JSONSerialization.jsonObject(
            with: Data(try ContactFeip.deleteOp(contactIds: ["id1", "id2"]).utf8)
        ) as? [String: Any]
        XCTAssertEqual(del?["op"] as? String, "delete")
        XCTAssertEqual(del?["contactIds"] as? [String], ["id1", "id2"])
    }

    func testEnvelopeWrapsFeipHeader() throws {
        let feip = ContactFeip.envelope(opJson: #"{"op":"add","cipher":"C"}"#)
        let obj = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(feip.utf8)) as? [String: Any]
        )
        XCTAssertEqual(obj["type"] as? String, "FEIP")
        XCTAssertEqual(obj["sn"] as? String, "12")
        XCTAssertEqual(obj["ver"] as? String, "3")
        XCTAssertEqual(obj["name"] as? String, "Contact")
        let data = try XCTUnwrap(obj["data"] as? [String: Any])
        XCTAssertEqual(data["op"] as? String, "add")
    }

    // MARK: - AsyOneWay encrypt

    func testEncryptRoundTripsThroughDecrypt() throws {
        let recipientPriv = Data(repeating: 0x5C, count: 32)
        let recipientPub = try Secp256k1.publicKey(fromPrivateKey: recipientPriv)
        let plaintext = Data(#"{"fid":"F123","memo":"round trip"}"#.utf8)

        let envelope = try AsyOneWayCipher.encrypt(
            plaintext: plaintext, toPubkey: recipientPub
        )
        // The envelope is exactly the CryptoDataStr field set the
        // Java Encryptor emits for GCM (no sum, no data, no did).
        let obj = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(envelope.utf8)) as? [String: Any]
        )
        XCTAssertEqual(obj["type"] as? String, "AsyOneWay")
        XCTAssertEqual(obj["alg"] as? String, "EccK1AesGcm256@No1_NrC7")
        XCTAssertEqual((obj["pubkeyA"] as? String)?.count, 66)
        XCTAssertEqual((obj["iv"] as? String)?.count, 24)
        XCTAssertNotNil(obj["cipher"] as? String)
        XCTAssertEqual(obj.count, 5)

        let decrypted = try AsyOneWayCipher.decrypt(
            cipherString: envelope, privkey: recipientPriv
        )
        XCTAssertEqual(decrypted, plaintext)
    }

    func testEncryptUsesFreshEphemeralKeyAndIvPerCall() throws {
        let recipientPub = try Secp256k1.publicKey(fromPrivateKey: Data(repeating: 0x5C, count: 32))
        let a = try AsyOneWayCipher.encrypt(plaintext: Data("x".utf8), toPubkey: recipientPub)
        let b = try AsyOneWayCipher.encrypt(plaintext: Data("x".utf8), toPubkey: recipientPub)
        let objA = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(a.utf8)) as? [String: String])
        let objB = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(b.utf8)) as? [String: String])
        XCTAssertNotEqual(objA["pubkeyA"], objB["pubkeyA"])
        XCTAssertNotEqual(objA["iv"], objB["iv"])
        XCTAssertNotEqual(objA["cipher"], objB["cipher"])
    }

    func testDecryptWithWrongKeyFails() throws {
        let recipientPub = try Secp256k1.publicKey(fromPrivateKey: Data(repeating: 0x5C, count: 32))
        let envelope = try AsyOneWayCipher.encrypt(
            plaintext: Data("secret".utf8), toPubkey: recipientPub
        )
        XCTAssertThrowsError(try AsyOneWayCipher.decrypt(
            cipherString: envelope, privkey: Data(repeating: 0x11, count: 32)
        ))
    }
}
