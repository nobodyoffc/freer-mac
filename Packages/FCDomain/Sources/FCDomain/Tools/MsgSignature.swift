import Foundation
import FCCore

/// FC message signature — the Swift mirror of the Java
/// `fcData.Signature` in its `ShortSign` JSON form:
/// `{"fid":…,"keyName":…,"msg":…,"sign":…,"alg":…}` where `alg` is the
/// AlgorithmId *display name* and null fields are omitted.
///
/// Three algorithms, as offered by Android's Sign/Verify tools:
/// - **ECDSA** (`BTC-EcdsaSignMsg@No1_NrC7`): Bitcoin signed-message
///   compact signature (Base64, recoverable). Carries `fid`.
/// - **Schnorr** (`SchnorrSignMsg@No1_NrC7`): BCH-2019 Schnorr over
///   `sha256x2(msg)`; `sign` = Base64(pubkey₃₃ ‖ sig₆₄). Carries `fid`.
/// - **Symkey** (`Sha256SymSignMsg@No1_NrC7`): HMAC-SHA256 hex.
///   Carries `keyName` = first 6 bytes of `sha256(key)` in hex.
///   Verification also accepts the legacy `sha256x2(msg ‖ key)` form.
public struct MsgSignature: Codable, Equatable, Sendable {

    public enum Alg: String, Codable, Sendable, CaseIterable {
        case ecdsa = "BTC-EcdsaSignMsg@No1_NrC7"
        case schnorr = "SchnorrSignMsg@No1_NrC7"
        case symkey = "Sha256SymSignMsg@No1_NrC7"
    }

    public enum Failure: Error, CustomStringConvertible {
        case notJson
        case missingField(String)
        case signFailed(underlying: Error)

        public var description: String {
            switch self {
            case .notJson:
                return "not a signature JSON"
            case .missingField(let f):
                return "signature JSON lacks '\(f)'"
            case .signFailed(let e):
                return "signing failed — \(e)"
            }
        }
    }

    public var fid: String?
    public var keyName: String?
    public var msg: String
    public var sign: String
    public var alg: Alg

    // MARK: - Signing

    /// ECDSA or Schnorr signature with a 32-byte private key.
    public static func sign(message: String, privkey: Data, alg: Alg) throws -> MsgSignature {
        precondition(alg != .symkey, "use sign(message:symkey:) for the symmetric algorithm")
        do {
            let pubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
            let fid = try FchAddress(publicKey: pubkey).fid
            let sign: String
            switch alg {
            case .ecdsa:
                sign = try SignedMessage.sign(message: message, privateKey: privkey)
            case .schnorr:
                let digest = Hash.doubleSha256(Data(message.utf8))
                let sig = try BchSchnorr.sign(message: digest, privateKey: privkey)
                sign = (pubkey + sig).base64EncodedString()
            case .symkey:
                fatalError("unreachable")
            }
            return MsgSignature(fid: fid, keyName: nil, msg: message, sign: sign, alg: alg)
        } catch {
            throw Failure.signFailed(underlying: error)
        }
    }

    /// HMAC-SHA256 symmetric signature.
    public static func sign(message: String, symkey: Data) -> MsgSignature {
        let sign = Hash.hmacSha256(Data(message.utf8), key: symkey).fcToolHex
        let keyName = Hash.sha256(symkey).prefix(6).fcToolHex
        return MsgSignature(fid: nil, keyName: keyName, msg: message, sign: sign, alg: .symkey)
    }

    // MARK: - Verification

    /// Verify an asymmetric (ECDSA / Schnorr) signature. Returns false
    /// for `.symkey` — that needs `verify(symkey:)`.
    public func verify() -> Bool {
        guard let fid else { return false }
        switch alg {
        case .ecdsa:
            return SignedMessage.verify(message: msg, signatureBase64: sign, fid: fid)
        case .schnorr:
            guard let bundle = Data(base64Encoded: sign), bundle.count > 33 else { return false }
            let pubkey = bundle.prefix(33)
            let sig = bundle.dropFirst(33)
            guard let address = try? FchAddress(publicKey: pubkey), address.fid == fid else {
                return false
            }
            let digest = Hash.doubleSha256(Data(msg.utf8))
            return (try? BchSchnorr.verify(message: digest, publicKey: pubkey, signature: sig)) == true
        case .symkey:
            return false
        }
    }

    /// Verify a symmetric signature against the key. Accepts the modern
    /// HMAC-SHA256 form and falls back to the legacy
    /// `sha256x2(msg ‖ key)` form, like the Java verifier.
    public func verify(symkey: Data) -> Bool {
        guard alg == .symkey else { return verify() }
        let msgBytes = Data(msg.utf8)
        if Hash.hmacSha256(msgBytes, key: symkey).fcToolHex == sign { return true }
        return Hash.doubleSha256(msgBytes + symkey).fcToolHex == sign
    }

    // MARK: - JSON

    /// Parse a signature JSON. Tolerates the Java long-form aliases
    /// (`address`/`message`/`signature`/`algorithm`), which
    /// `Signature.makeSignature()` merges into the short fields.
    public static func fromJson(_ json: String) throws -> MsgSignature {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Failure.notJson
        }
        let fid = (object["fid"] ?? object["address"]) as? String
        let keyName = object["keyName"] as? String
        guard let msg = (object["msg"] ?? object["message"]) as? String else {
            throw Failure.missingField("msg")
        }
        guard let sign = (object["sign"] ?? object["signature"]) as? String else {
            throw Failure.missingField("sign")
        }
        // Missing alg defaults to ECDSA, like `Signature.verify()`.
        let algName = (object["alg"] ?? object["algorithm"]) as? String
        let alg = algName.flatMap(Alg.init(rawValue:)) ?? .ecdsa
        return MsgSignature(fid: fid, keyName: keyName, msg: msg, sign: sign, alg: alg)
    }

    /// Serialize in the Java `ShortSign` field order with null fields
    /// omitted — what Android's Sign tool puts on the clipboard/QR.
    public func toJson() -> String {
        var parts: [String] = []
        switch alg {
        case .ecdsa, .schnorr:
            if let fid { parts.append("\"fid\":\(Self.jsonString(fid))") }
        case .symkey:
            if let keyName { parts.append("\"keyName\":\(Self.jsonString(keyName))") }
        }
        parts.append("\"msg\":\(Self.jsonString(msg))")
        parts.append("\"sign\":\(Self.jsonString(sign))")
        parts.append("\"alg\":\(Self.jsonString(alg.rawValue))")
        return "{\(parts.joined(separator: ","))}"
    }

    static func jsonString(_ s: String) -> String {
        // JSONEncoder-grade escaping for a bare string.
        let data = try? JSONSerialization.data(
            withJSONObject: [s], options: [.withoutEscapingSlashes]
        )
        guard let data, let wrapped = String(data: data, encoding: .utf8) else {
            return "\"\(s)\""
        }
        return String(wrapped.dropFirst().dropLast())
    }
}

extension Data {
    /// Lowercase hex, tool-layer spelling (Foundation-only).
    var fcToolHex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
