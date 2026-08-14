import Foundation
import FCCore

/// A saved secret — the Swift mirror of the Java `feipData.Secret`,
/// stored per Pattern B: the plaintext `content` is **never persisted**.
/// It lives only in memory after an explicit decrypt; at rest the store
/// holds `contentCipher`, an AsyOneWay CryptoDataStr envelope encrypted
/// to the owner's own pubkey (so the live privkey can always recover it).
///
/// `id` is the merge key with the chain: a carved secret's id is the
/// carve txid (the FEIP record id); a local-only secret gets
/// `sha256x2` of its detail JSON, which can never collide with a txid
/// of different preimage.
public struct Secret: Codable, Equatable, Sendable, Identifiable {

    public enum SecretType: String, Codable, Sendable, CaseIterable {
        case prikey
        case symkey
        case password
        case totp = "TOTP"
        case secret
        case text

        public var displayName: String { rawValue }
    }

    public var id: String
    /// One of ``SecretType``'s raw values. Kept as a string on the wire
    /// (Android tolerates arbitrary strings here).
    public var type: String?
    public var title: String?
    public var memo: String?
    /// AsyOneWay CryptoDataStr JSON — `content` encrypted to the
    /// owner's own pubkey. Nil only for rows synced before the cipher
    /// could be built (shouldn't happen in practice).
    public var contentCipher: String?

    // On-chain block (populated by sync).
    public var birthTime: Int64?
    public var lastHeight: Int64?
    public var active: Bool?
    public var onChain: Bool
    /// The carve record id backing this row, when known. For secrets
    /// this equals ``id`` once carved; kept separate so a local row
    /// that later carves keeps its local id until the sync merges.
    public var carveId: String?

    // Local bookkeeping.
    public var addedAt: Date
    public var updatedAt: Date

    public init(
        id: String,
        type: String? = nil,
        title: String? = nil,
        memo: String? = nil,
        contentCipher: String? = nil,
        birthTime: Int64? = nil,
        lastHeight: Int64? = nil,
        active: Bool? = nil,
        onChain: Bool = false,
        carveId: String? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.type = type
        self.title = title
        self.memo = memo
        self.contentCipher = contentCipher
        self.birthTime = birthTime
        self.lastHeight = lastHeight
        self.active = active
        self.onChain = onChain
        self.carveId = carveId
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }

    /// List label: title, else memo, else the elided id.
    public var name: String {
        if let title, !title.isEmpty { return title }
        if let memo, !memo.isEmpty { return memo }
        return id
    }

    public var isTotp: Bool {
        type?.caseInsensitiveCompare(SecretType.totp.rawValue) == .orderedSame
    }

    /// Case-insensitive substring match across the *searchable* fields.
    ///
    /// Deliberately excludes the content: at rest it exists only as
    /// ``contentCipher`` (Pattern B), so matching it would mean
    /// decrypting every row on every keystroke — and a filtered count
    /// would leak what hidden values contain. Title, type, memo, and
    /// id are enough to find a row you saved yourself.
    ///
    /// Lives here rather than on the store, like ``Hat/matches(query:)``,
    /// so a list already in memory filters as the user types.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        return hit(title) || hit(type) || hit(memo) || hit(id) || hit(carveId)
    }

    /// Decrypt ``contentCipher`` with the owner's 32-byte privkey.
    public func decryptContent(privkey: Data) throws -> String {
        guard let contentCipher, !contentCipher.isEmpty else {
            throw SecretService.Failure.noContentCipher
        }
        let plain = try AsyOneWayCipher.decrypt(cipherString: contentCipher, privkey: privkey)
        guard let text = String(data: plain, encoding: .utf8) else {
            throw SecretService.Failure.contentNotUtf8
        }
        return text
    }

    /// Build a brand-new local secret: encrypts `content` to
    /// `ownPubkey` and derives the local id the way Android's
    /// `checkIdWithCreate` does — `sha256x2` of the detail JSON.
    public static func createLocal(
        type: SecretType,
        title: String?,
        content: String,
        memo: String?,
        ownPubkey: Data
    ) throws -> Secret {
        let contentCipher = try AsyOneWayCipher.encrypt(
            plaintext: Data(content.utf8), toPubkey: ownPubkey
        )
        let detail = try SecretFeip.detailJson(
            type: type.rawValue, title: title, content: content, memo: memo
        )
        let id = Hash.doubleSha256(Data(detail.utf8)).fcToolHex
        return Secret(
            id: id,
            type: type.rawValue,
            title: title,
            memo: memo,
            contentCipher: contentCipher
        )
    }
}
