import Foundation
import FCCore

/// One mail, mirroring `FC-AJDK/.../data/feipData/Mail.java` field for
/// field. Both a wire model (this is what `base.search` returns for the
/// `mail` entity, and what Android stores locally) and the row type of
/// ``MailsStore``.
///
/// **The body is never stored in the clear.** Like ``Secret`` (Pattern B),
/// a stored mail carries ``cipher`` and a nil ``content``; the plaintext
/// exists only in memory, for as long as a pane is showing it. Android
/// does the same — `parseDetail` fills `content` on a fetched object and
/// `encryptMailContent` clears it again before saving.
///
/// **Sender and recipient are public.** Unlike a contact or a secret,
/// which are carved to yourself, a mail is a carve that *pays the
/// recipient*, so ``from`` and ``to`` are ordinary indexed fields on the
/// chain. Only the body is sealed. This is worth being blunt about in the
/// UI: the fact that you mailed someone is not private, and never was.
public struct Mail: Codable, Equatable, Sendable, Identifiable {

    // MARK: - wire fields, in Java declaration order

    /// The `AlgorithmId` display name of ``cipher``'s envelope. Android
    /// writes CBC on the carve path and GCM on the local-save path
    /// (Android issue C7); ``AsyCipher`` reads the envelope's own `alg`
    /// and ignores this, so it is informational.
    public var alg: String?
    /// The AsyTwoWay (or, for `from == to`, AsyOneWay) CryptoDataStr
    /// envelope holding the body. See ``AsyTwoWayCipher``.
    public var cipher: String?
    public var from: String?
    public var to: String?
    /// Seconds since the epoch — note the chain's other timestamps are
    /// milliseconds; this one is not.
    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastHeight: Int64?
    /// `false` once the newest carve for this mail was a `delete` op.
    public var active: Bool?
    /// Plaintext body. Present only in memory — see the type's note.
    public var content: String?
    public var onChain: Bool?
    /// Whether ``content`` was successfully recovered from ``cipher``.
    /// A mail we cannot open is still shown: unlike a contact, whose FID
    /// lives *inside* the cipher, a mail's correspondent is on the
    /// outside, so an undecryptable row still says something true.
    public var decrypted: Bool?
    public var fromName: String?
    public var toName: String?
    public var unread: Bool?
    /// Satoshis paid to the recipient by the carve that delivered this
    /// mail — the "notice fee".
    public var noticeFee: Int64?
    public var objName: String?
    /// The carve txid for an on-chain mail; for a local draft, the
    /// derivation in ``checkIdWithCreate()``.
    public var id: String?

    public init(
        alg: String? = nil,
        cipher: String? = nil,
        from: String? = nil,
        to: String? = nil,
        birthTime: Int64? = nil,
        birthHeight: Int64? = nil,
        lastHeight: Int64? = nil,
        active: Bool? = nil,
        content: String? = nil,
        onChain: Bool? = nil,
        decrypted: Bool? = nil,
        fromName: String? = nil,
        toName: String? = nil,
        unread: Bool? = nil,
        noticeFee: Int64? = nil,
        objName: String? = nil,
        id: String? = nil
    ) {
        self.alg = alg
        self.cipher = cipher
        self.from = from
        self.to = to
        self.birthTime = birthTime
        self.birthHeight = birthHeight
        self.lastHeight = lastHeight
        self.active = active
        self.content = content
        self.onChain = onChain
        self.decrypted = decrypted
        self.fromName = fromName
        self.toName = toName
        self.unread = unread
        self.noticeFee = noticeFee
        self.objName = objName
        self.id = id
    }

    // MARK: - derived

    /// `true` when this mail was addressed *to* `fid` by someone else.
    /// A note to self is neither incoming nor outgoing; it is both, and
    /// this reports `false` so it files under Sent.
    public func isIncoming(for fid: String) -> Bool {
        to == fid && from != fid
    }

    /// The FID at the other end, from `fid`'s point of view. For a note
    /// to self that is `fid` itself.
    public func counterparty(for fid: String) -> String? {
        from == fid ? to : from
    }

    /// The counterparty's display name, falling back to their FID.
    public func counterpartyName(for fid: String) -> String? {
        (from == fid ? toName : fromName) ?? counterparty(for: fid)
    }

    /// A deleted mail — the newest carve for it was a `delete` op.
    public var isDeleted: Bool { active == false }

    /// Case-insensitive substring match across the fields a mailbox
    /// search can honestly cover.
    ///
    /// ``content`` participates **only when it is already decrypted in
    /// memory**. A stored row holds ciphertext, so a search over the
    /// store would silently match nothing in the body; a search over a
    /// pane that has decrypted its rows matches everything the reader can
    /// see. That difference is deliberate and is why this takes the value
    /// as it stands rather than reaching for a key.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        return hit(from) || hit(to) || hit(fromName) || hit(toName)
            || hit(content) || hit(id)
    }

    // MARK: - JSON

    /// The JSON Android's `JsonUtils.toJson(mail)` produces: Java
    /// declaration order, nulls omitted, HTML escaping **disabled**.
    ///
    /// Unlike ``Hat``, which needs two encoders because its DID is hashed
    /// over the *escaped* form, `Mail.toBytes()` and its JSON are the same
    /// bytes — both go through `JsonUtils.toJson`. So a body containing
    /// `< > & ' =` is stored and hashed identically.
    public func wireJson() -> String {
        GsonCompatibleWriter.object(orderedFields(), htmlSafe: false)
    }

    public static func fromJson(_ json: String) throws -> Mail {
        try JSONDecoder().decode(Mail.self, from: Data(json.utf8))
    }

    /// Port of `Mail.checkIdWithCreate()`: when the mail has no id, set it
    /// to `hex(sha256x2(toBytes()))` over this object *as it currently
    /// stands*, minus the id.
    ///
    /// The "as it currently stands" is the sharp edge. The id covers every
    /// field that happens to be set, so deriving it before versus after
    /// stamping `birthTime` gives two different ids for the same draft.
    /// Android derives it from `{from, to, content}` alone, at the top of
    /// `CreateMailActivity`'s local-save branch, and ``draft(from:to:content:)``
    /// keeps to that so the two clients agree.
    ///
    /// An on-chain mail never reaches here: its id is the carve txid,
    /// assigned by the server or by our own broadcast.
    public mutating func checkIdWithCreate() {
        guard id == nil else { return }
        var copy = self
        copy.id = nil
        let bytes = Data(copy.wireJson().utf8)
        id = Hash.doubleSha256(bytes).map { String(format: "%02x", $0) }.joined()
    }

    /// A local draft with the id Android would derive for it: sender,
    /// recipient, and body, and nothing else set yet. Encrypt and stamp
    /// **after** calling this — see ``checkIdWithCreate()``.
    public static func draft(from: String, to: String, content: String) -> Mail {
        var m = Mail(from: from, to: to, content: content)
        m.checkIdWithCreate()
        return m
    }

    /// Fields in Java declaration order, nils dropped. Mail's own fields
    /// come first, then `objName` (FcObject) and `id` (FcEntity) — Gson's
    /// declaring-class-first ordering.
    private func orderedFields() -> [(String, GsonCompatibleWriter.Value)] {
        var out: [(String, GsonCompatibleWriter.Value)] = []
        func put(_ k: String, _ v: String?) { if let v { out.append((k, .string(v))) } }
        func put(_ k: String, _ v: Int64?)  { if let v { out.append((k, .int(v))) } }
        func put(_ k: String, _ v: Bool?)   { if let v { out.append((k, .bool(v))) } }

        put("alg", alg)
        put("cipher", cipher)
        put("from", from)
        put("to", to)
        put("birthTime", birthTime)
        put("birthHeight", birthHeight)
        put("lastHeight", lastHeight)
        put("active", active)
        put("content", content)
        put("onChain", onChain)
        put("decrypted", decrypted)
        put("fromName", fromName)
        put("toName", toName)
        put("unread", unread)
        put("noticeFee", noticeFee)
        put("objName", objName)
        put("id", id)
        return out
    }

    // MARK: - crypto

    /// Seal ``content`` into ``cipher`` and clear the plaintext — the port
    /// of `Mail.encryptContent`.
    ///
    /// `from == to` (a note to self) goes AsyOneWay, because an AsyTwoWay
    /// envelope whose two pubkeys are equal is one Android's side-selection
    /// cannot resolve. Everything else goes AsyTwoWay so the sender can
    /// reopen their own mail.
    ///
    /// We always write GCM. Android's carve path writes CBC (Android issue
    /// C7); both are readable by both clients, and GCM is the authenticated
    /// one.
    public mutating func encryptContent(privkey: Data, recipientPubkey: Data) throws {
        guard let content else { throw Failure.noContent }
        let plaintext = Data(content.utf8)
        if from != nil, from == to {
            cipher = try AsyOneWayCipher.encrypt(plaintext: plaintext, toPubkey: recipientPubkey)
        } else {
            cipher = try AsyTwoWayCipher.encrypt(
                plaintext: plaintext, privkeyA: privkey, toPubkey: recipientPubkey
            )
        }
        alg = AsyOneWayCipher.algGcm
        self.content = nil
        decrypted = nil
    }

    /// Recover ``content`` from ``cipher`` — the port of
    /// `Mail.parseDetail`. Returns `false` and marks the mail
    /// `decrypted = false` when the body cannot be opened, rather than
    /// throwing: one unreadable mail must not abort a mailbox sync, and
    /// the row is still worth showing.
    @discardableResult
    public mutating func parseDetail(privkey: Data) -> Bool {
        guard let cipher, !cipher.isEmpty else {
            decrypted = false
            return false
        }
        guard let plaintext = try? AsyCipher.decrypt(cipherString: cipher, privkey: privkey),
              let text = String(data: plaintext, encoding: .utf8) else {
            decrypted = false
            return false
        }
        content = text
        decrypted = true
        return true
    }

    public enum Failure: Error, CustomStringConvertible {
        case noContent

        public var description: String {
            switch self {
            case .noContent: return "Mail: no content to encrypt"
            }
        }
    }
}
