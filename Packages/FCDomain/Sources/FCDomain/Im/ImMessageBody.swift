import Foundation
import FCCore

/// Sealing and opening a message body — the ``ImMessage`` counterpart of
/// ``Mail/encryptContent(privkey:recipientPubkey:)`` and
/// ``Mail/parseDetail(privkey:)``, and deliberately the same shape: seal
/// throws, open returns a Bool.
///
/// The asymmetry is the point. Failing to seal must stop a send — the
/// alternative is putting the plaintext on the wire. Failing to open
/// must not stop anything: a batch of messages arriving after a key
/// rotation will contain some we cannot read yet, and each of those is a
/// row to show as locked and a key to go and ask for, not an error to
/// abort the batch with.
///
/// **Which envelope depends on the conversation**, and the two are not
/// interchangeable:
///
/// - Team and Room bodies use a **symkey** envelope, because every
///   member reads the same ciphertext. That is what makes group chat
///   affordable and what makes a rotation necessary when someone leaves.
/// - P2P bodies use the **AsyTwoWay** envelope from 9.1.1, which carries
///   both pubkeys so either end can open it — without that, we could not
///   reread what we ourselves sent.
/// - Square bodies are not sealed at all. A square's membership is open
///   and on-chain, so there is nobody to keep out.
public extension ImMessage {

    // MARK: - symkey (team, room)

    /// Seal ``content`` into ``cipher`` under a group key, stamping the
    /// version so the far end knows which key to reach for.
    mutating func sealBody(symkey: Data, version: Int64) throws {
        guard let content else { throw BodyFailure.noContent }
        cipher = try TextCipher.encryptWithSymkey(Data(content.utf8), symkey: symkey)
        symkeyVersion = version
        self.content = nil
    }

    /// Recover ``content`` from a symkey-sealed ``cipher``.
    ///
    /// ``cipher`` is left in place; ``MessagesStore`` drops it on the way
    /// in, once the plaintext beside it makes it redundant.
    @discardableResult
    mutating func openBody(symkey: Data) -> Bool {
        guard let cipher, !cipher.isEmpty else { return false }
        guard let envelope = try? TextCipher.parse(cipher),
              let plaintext = try? TextCipher.decrypt(envelope: envelope, symkey: symkey),
              let text = String(data: plaintext, encoding: .utf8)
        else { return false }
        content = text
        return true
    }

    // MARK: - AsyTwoWay (p2p)

    /// Seal ``content`` for a single recipient, so that **both** ends can
    /// reopen it.
    ///
    /// A message to ourselves goes AsyOneWay instead, for the reason
    /// ``Mail/encryptContent(privkey:recipientPubkey:)`` gives: an
    /// AsyTwoWay envelope whose two pubkeys are the same is one the
    /// side-selection cannot resolve.
    mutating func sealBody(privkey: Data, recipientPubkey: Data) throws {
        guard let content else { throw BodyFailure.noContent }
        let plaintext = Data(content.utf8)
        if senderId != nil, senderId == targetId {
            cipher = try AsyOneWayCipher.encrypt(plaintext: plaintext, toPubkey: recipientPubkey)
        } else {
            cipher = try AsyTwoWayCipher.encrypt(
                plaintext: plaintext, privkeyA: privkey, toPubkey: recipientPubkey
            )
        }
        self.content = nil
    }

    /// Recover ``content`` from an AsyOneWay or AsyTwoWay ``cipher``.
    /// ``AsyCipher`` picks the side for us — whichever pubkey in the
    /// envelope is not ours is the one to agree against.
    @discardableResult
    mutating func openBody(privkey: Data) -> Bool {
        guard let cipher, !cipher.isEmpty else { return false }
        guard let plaintext = try? AsyCipher.decrypt(cipherString: cipher, privkey: privkey),
              let text = String(data: plaintext, encoding: .utf8)
        else { return false }
        content = text
        return true
    }

    /// Whether this message is still sealed to us — a body we hold but
    /// have not opened. The cue for a locked row in the transcript, and
    /// for asking the group for the key version it names.
    var isSealed: Bool {
        content == nil && !(cipher ?? "").isEmpty
    }

    enum BodyFailure: Error, Equatable, CustomStringConvertible {
        case noContent

        public var description: String {
            switch self {
            case .noContent: return "ImMessage: no content to seal"
            }
        }
    }
}
