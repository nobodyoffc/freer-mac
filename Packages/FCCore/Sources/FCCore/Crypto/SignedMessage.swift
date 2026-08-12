import Foundation
import P256K

/// Bitcoin-style signed messages — the `ECKey.signMessage` /
/// `ECKey.signedMessageToKey` pair from bitcoinj (and its freecashj
/// fork), which the FC ecosystem uses for
/// `BTC-EcdsaSignMsg@No1_NrC7` signatures.
///
/// Format: the message is framed as
/// `varint(len(magic)) ‖ magic ‖ varint(len(msg)) ‖ msg` with
/// magic `"Bitcoin Signed Message:\n"`, double-SHA-256 hashed, and
/// signed with deterministic (RFC 6979, low-S) ECDSA. The signature
/// travels as Base64 of 65 bytes:
/// `header(1) ‖ R(32) ‖ S(32)` where
/// `header = 27 + recoveryId + (compressed ? 4 : 0)`.
///
/// Verification does not need the signer's public key — it *recovers*
/// the key from the signature and lets the caller compare the derived
/// address/FID.
public enum SignedMessage {

    public enum Failure: Error, CustomStringConvertible {
        case invalidPrivateKey
        case invalidSignature
        case recoveryFailed

        public var description: String {
            switch self {
            case .invalidPrivateKey: return "SignedMessage: invalid private key"
            case .invalidSignature:  return "SignedMessage: signature is not 65 Base64 bytes with a valid header"
            case .recoveryFailed:    return "SignedMessage: public key recovery failed"
            }
        }
    }

    static let magic = Data("Bitcoin Signed Message:\n".utf8)

    /// The double-SHA-256 of the magic-framed message — the digest that
    /// actually gets signed.
    static func messageHash(_ message: String) -> Data {
        var framed = Data()
        let messageBytes = Data(message.utf8)
        framed.append(VarInt.encode(UInt64(magic.count)))
        framed.append(magic)
        framed.append(VarInt.encode(UInt64(messageBytes.count)))
        framed.append(messageBytes)
        return Hash.doubleSha256(framed)
    }

    /// Sign `message` with a 32-byte private key. Returns the Base64
    /// compact signature (compressed-key header), byte-identical to
    /// `ECKey.fromPrivate(key).signMessage(message)`.
    public static func sign(message: String, privateKey: Data) throws -> String {
        let key: P256K.Recovery.PrivateKey
        do {
            key = try P256K.Recovery.PrivateKey(dataRepresentation: privateKey)
        } catch {
            throw Failure.invalidPrivateKey
        }
        let digest = RawSighashDigest(messageHash(message))
        let compact = key.signature(for: digest).compactRepresentation

        // bitcoinj always derives from a compressed pubkey here (FC keys
        // are compressed), so the header adds 4.
        var out = Data(capacity: 65)
        out.append(UInt8(27 + compact.recoveryId + 4))
        out.append(compact.signature) // r ‖ s, already 64 bytes
        return out.base64EncodedString()
    }

    /// Recover the signer's 33-byte compressed public key from a
    /// Base64 signature, mirroring `ECKey.signedMessageToKey`.
    public static func recoverPublicKey(message: String, signatureBase64: String) throws -> Data {
        guard let sigBytes = Data(base64Encoded: signatureBase64), sigBytes.count == 65 else {
            throw Failure.invalidSignature
        }
        var header = Int32(sigBytes[sigBytes.startIndex])
        guard header >= 27, header <= 34 else { throw Failure.invalidSignature }
        if header >= 31 { header -= 4 } // compressed-key flag
        let recoveryId = header - 27

        let signature: P256K.Recovery.ECDSASignature
        do {
            signature = try P256K.Recovery.ECDSASignature(
                compactRepresentation: sigBytes.dropFirst(),
                recoveryId: recoveryId
            )
        } catch {
            throw Failure.invalidSignature
        }

        let digest = RawSighashDigest(messageHash(message))
        let recovered = P256K.Recovery.PublicKey(digest, signature: signature)
        let pubkey = recovered.dataRepresentation
        guard pubkey.count == 33 else { throw Failure.recoveryFailed }
        return pubkey
    }

    /// Verify that `signatureBase64` over `message` was made by the key
    /// behind `fid` (an FCH P2PKH address).
    public static func verify(message: String, signatureBase64: String, fid: String) -> Bool {
        guard let pubkey = try? recoverPublicKey(message: message, signatureBase64: signatureBase64),
              let address = try? FchAddress(publicKey: pubkey) else {
            return false
        }
        return address.fid == fid
    }
}
