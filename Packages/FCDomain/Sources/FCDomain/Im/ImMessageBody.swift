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
/// **What gets sealed is the whole body**, both ``ImMessage/content`` and
/// ``ImMessage/data``, framed together by
/// ``ImMessage/bodyFraming()``. v1 sealed `content` alone and left the
/// binary payload beside it in the clear, so a voice note travelled with
/// its metadata encrypted and its audio readable, and a file share
/// travelled with the key next to the ciphertext it unlocked. Sealing the
/// framing instead makes that state unrepresentable rather than merely
/// discouraged.
///
/// **Which envelope depends on the conversation**, and the two are not
/// interchangeable:
///
/// - Team and Room bodies use a **symkey** bundle, because every member
///   reads the same ciphertext. That is what makes group chat affordable
///   and what makes a rotation necessary when someone leaves.
/// - P2P bodies use the **AsyTwoWay** bundle, sealed from our real key to
///   theirs — on the DOCK and ROAD channels, where an intermediary would
///   otherwise hold the plaintext.
/// - Square bodies are not sealed at all. A square's membership is open
///   and on-chain, so there is nobody to keep out.
public extension ImMessage {

    // MARK: - symkey (team, room)

    /// Seal the body under a group key, stamping the version so the far
    /// end knows which key to reach for.
    mutating func sealBody(symkey: Data, version: Int64) throws {
        guard content != nil || data != nil else { throw BodyFailure.noContent }
        body = try CryptoBundle.sealSymkey(plaintext: bodyFraming(), symkey: symkey)
        symkeyVersion = version
        content = nil
        data = nil
    }

    /// Recover the body from a symkey-sealed ``body``.
    ///
    /// ``body`` is left in place; ``MessagesStore`` drops it on the way
    /// in, once the plaintext beside it makes it redundant.
    @discardableResult
    mutating func openBody(symkey: Data) -> Bool {
        guard let body, !body.isEmpty else { return false }
        guard let framing = try? CryptoBundle.open(bundle: body, symkey: symkey) else { return false }
        return (try? applyBodyFraming(framing)) != nil
    }

    // MARK: - asymmetric (p2p)

    /// Seal the body for a single recipient.
    ///
    /// A message to ourselves goes AsyOneWay instead, for the reason
    /// ``Mail/encryptContent(privkey:recipientPubkey:)`` gives: an
    /// AsyTwoWay envelope whose two pubkeys are the same is one the
    /// side-selection cannot resolve.
    ///
    /// Note that an AsyTwoWay *bundle* records only `pubkeyA`, so unlike
    /// the JSON envelope it cannot be reopened by its sender. Nothing
    /// needs that: ``MessagesStore`` keeps our own messages in plaintext
    /// and never re-reads them off the wire.
    mutating func sealBody(privkey: Data, recipientPubkey: Data) throws {
        guard content != nil || data != nil else { throw BodyFailure.noContent }
        let framing = bodyFraming()
        if senderId != nil, senderId == targetId {
            body = try CryptoBundle.sealAsyOneWay(plaintext: framing, toPubkey: recipientPubkey)
        } else {
            body = try CryptoBundle.sealAsyTwoWay(
                plaintext: framing, privkeyA: privkey, toPubkey: recipientPubkey
            )
        }
        content = nil
        data = nil
    }

    /// Recover the body from an AsyOneWay or AsyTwoWay ``body``. The
    /// bundle records the one pubkey to agree against, so there is no side
    /// to select.
    @discardableResult
    mutating func openBody(privkey: Data) -> Bool {
        guard let body, !body.isEmpty else { return false }
        guard let framing = try? CryptoBundle.open(bundle: body, privkey: privkey) else { return false }
        return (try? applyBodyFraming(framing)) != nil
    }

    /// Whether this message is still sealed to us — a body we hold but
    /// have not opened. The cue for a locked row in the transcript, and
    /// for asking the group for the key version it names.
    var isSealed: Bool {
        content == nil && data == nil && !(body ?? Data()).isEmpty
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
