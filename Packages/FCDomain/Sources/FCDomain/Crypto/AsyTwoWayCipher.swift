import Foundation
import FCCore

/// The **AsyTwoWay** CryptoDataStr envelope — the format every mail body
/// travels in (`Encryptor.encryptByAsyTwoWay`).
///
/// ``AsyOneWayCipher`` seals to a recipient with a throwaway sender key:
/// `pubkeyA` is ephemeral, its private half is discarded on the spot, and
/// only the recipient can ever reopen the result. That is the right shape
/// for a contact or a secret, which you encrypt to yourself.
///
/// A mail has two readers. So AsyTwoWay does the ECDH between the sender's
/// **real** private key and the recipient's public key, and records both
/// halves in the envelope:
///
/// ```json
/// {"type":"AsyTwoWay","alg":"EccK1AesGcm256@No1_NrC7","cipher":"<base64>",
///  "pubkeyA":"<sender 33 B hex>","pubkeyB":"<recipient 33 B hex>",
///  "iv":"<hex>"}
/// ```
///
/// Either party recovers the same shared secret by pairing their own
/// private key with *the other* pubkey — which is exactly how you open a
/// mail you sent, and why an outbox works at all. The cost is that the
/// sender's key is now a long-lived party to the ciphertext: compromising
/// it exposes every mail they ever sent, where AsyOneWay would only expose
/// what was addressed to them. That is the protocol's trade, not ours.
///
/// **Both algorithms occur in the wild** and both are read here. Android's
/// `Mail.encryptContent` — the path a *carved* mail takes — asks for
/// `EccK1AesCbc256@No1_NrC7`, while `CreateMailActivity.encryptMailContent`
/// (local save) asks for `EccK1AesGcm256@No1_NrC7`. We always *write* GCM:
/// it is authenticated, Android's decryptor accepts it, and CBC's only
/// integrity check is the 4-byte `sum` that ``AsyOneWayCipher/verifySum(_:alg:symkey:iv:plaintext:)``
/// now verifies.
public enum AsyTwoWayCipher {

    public typealias Failure = AsyOneWayCipher.Failure

    public static let type = "AsyTwoWay"

    /// Seal `plaintext` from `privkeyA` to `pubkeyB`, returning the JSON
    /// envelope. AES-256-GCM with a fresh 12-byte iv and
    /// `symkey = HKDF-SHA512(ECDH.x, salt: iv, info: "hkdf")` — the same
    /// derivation ``AsyOneWayCipher/encrypt(plaintext:toPubkey:)`` uses,
    /// differing only in whose private key enters the ECDH.
    ///
    /// Sealing to your *own* pubkey is legal and produces a self-readable
    /// envelope, but ``AsyOneWayCipher`` is the right tool for that: Java's
    /// side-selection can't resolve an envelope whose two pubkeys are equal
    /// (see ``decrypt(cipherString:privkey:)``), so an Android peer would
    /// fail to open it.
    public static func encrypt(
        plaintext: Data, privkeyA: Data, toPubkey pubkeyB: Data
    ) throws -> String {
        guard pubkeyB.count == 33 else { throw Failure.badField("pubkeyB") }
        let pubkeyA: Data
        do {
            pubkeyA = try Secp256k1.publicKey(fromPrivateKey: privkeyA)
        } catch {
            throw Failure.badField("privkeyA")
        }

        let iv = Data((0..<AesGcm256.nonceLength).map { _ in UInt8.random(in: .min ... .max) })
        let x = try Secp256k1.sharedSecretX(privateKey: privkeyA, publicKey: pubkeyB)
        let symkey = Hkdf.sha512(
            ikm: x, salt: iv,
            info: Data("hkdf".utf8),
            outputLength: AesGcm256.keyLength
        )
        let box = try AesGcm256.seal(key: symkey, nonce: iv, plaintext: plaintext)

        // base64 and hex never need JSON escaping, so the envelope is
        // assembled literally, in the Java field-declaration order.
        let cipherB64 = (box.ciphertext + box.tag).base64EncodedString()
        return #"{"type":"\#(type)","alg":"\#(AsyOneWayCipher.algGcm)","cipher":"\#(cipherB64)","pubkeyA":"\#(hex(pubkeyA))","pubkeyB":"\#(hex(pubkeyB))","iv":"\#(hex(iv))"}"#
    }

    /// Open an AsyTwoWay envelope with `privkey`, whichever side of it we
    /// are. Ports the side-selection in Java's `Decryptor.decryptTry`: the
    /// pubkey in the envelope that **isn't ours** is the one we ECDH
    /// against.
    ///
    /// An envelope where both pubkeys are ours (a self-addressed mail
    /// mistakenly sealed two-way) is opened here by pairing our key with
    /// itself — unambiguous, since there is only one counterparty it could
    /// mean. Java refuses that case unless the caller passes the peer
    /// pubkey separately, so such an envelope is readable on the Mac and
    /// not on Android; we never produce one.
    public static func decrypt(cipherString: String, privkey: Data) throws -> Data {
        let trimmed = cipherString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("{") else {
            // A bundle records only pubkeyA even for AsyTwoWay
            // (`CryptoDataByte.toBundle`), so the recipient-side path in
            // AsyOneWayCipher is already the whole story for that encoding.
            return try AsyOneWayCipher.decrypt(cipherString: trimmed, privkey: privkey)
        }

        let env: AsyOneWayCipher.Envelope
        do {
            env = try JSONDecoder().decode(
                AsyOneWayCipher.Envelope.self, from: Data(trimmed.utf8)
            )
        } catch {
            throw Failure.badEnvelope(underlying: error)
        }

        guard let ivHex = env.iv, let iv = Data(fcHex: ivHex) else {
            throw Failure.badField("iv")
        }
        guard let cipherB64 = env.cipher, let cipher = Data(base64Encoded: cipherB64) else {
            throw Failure.badField("cipher")
        }

        let myPubkey: Data
        do {
            myPubkey = try Secp256k1.publicKey(fromPrivateKey: privkey)
        } catch {
            throw Failure.badField("privkey")
        }
        let peer = try counterparty(env: env, myPubkey: myPubkey)

        return try AsyOneWayCipher.decryptParts(
            alg: env.alg ?? AsyOneWayCipher.algP7,
            pubkeyA: peer, iv: iv, cipher: cipher,
            privkey: privkey,
            sum: env.sum.flatMap { Data(fcHex: $0) }
        )
    }

    /// Which recorded pubkey to ECDH against, given ours.
    static func counterparty(env: AsyOneWayCipher.Envelope, myPubkey: Data) throws -> Data {
        let a = env.pubkeyA.flatMap { Data(fcHex: $0) }
        let b = env.pubkeyB.flatMap { Data(fcHex: $0) }
        guard a != nil || b != nil else { throw Failure.badField("pubkeyA") }

        if let a, a != myPubkey { return a }
        if let b, b != myPubkey { return b }
        // Both sides are us: a self-addressed envelope.
        if let a, a == myPubkey, b == nil || b == myPubkey { return a }
        throw Failure.badField("pubkeyB")
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

/// Opens either flavour of asymmetric CryptoDataStr envelope, picking the
/// path from the envelope's own `type`.
///
/// Callers that read on-chain payloads want this rather than one of the two
/// concrete ciphers: a mailbox holds AsyTwoWay envelopes for real
/// correspondence *and* AsyOneWay envelopes for notes to self, and which is
/// which is a property of the record, not of the call site.
public enum AsyCipher {

    public static func decrypt(cipherString: String, privkey: Data) throws -> Data {
        let trimmed = cipherString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("{") else {
            return try AsyOneWayCipher.decrypt(cipherString: trimmed, privkey: privkey)
        }
        let env = try? JSONDecoder().decode(
            AsyOneWayCipher.Envelope.self, from: Data(trimmed.utf8)
        )
        // A missing `type` with a pubkeyB present can only be two-way —
        // AsyOneWay drops pubkeyB precisely because nobody needs it.
        if env?.type == AsyTwoWayCipher.type || (env?.type == nil && env?.pubkeyB != nil) {
            return try AsyTwoWayCipher.decrypt(cipherString: trimmed, privkey: privkey)
        }
        return try AsyOneWayCipher.decrypt(cipherString: trimmed, privkey: privkey)
    }
}
