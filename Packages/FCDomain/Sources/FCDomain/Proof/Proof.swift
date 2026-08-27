import Foundation
import FCCore

/// An on-chain proof — the Swift mirror of the Java `feipData.Proof`,
/// and the record type of the `proof` index that `base.search` reads.
///
/// A proof is a signed statement that lives on the chain: a title, a
/// body, and a list of people the issuer invited to countersign it.
/// Unlike a ``Secret`` there is **no cipher on this path** — every
/// field below is public. That is the point: a proof you cannot show
/// to a third party proves nothing.
///
/// **Three parties, not one.** ``issuer`` carved it and can never be
/// changed. ``owner`` holds it now, and moves when a `transfer` carve
/// confirms. ``cosignersInvited`` is the issuer's ask;
/// ``cosignersSigned`` is what the chain has actually seen. The gap
/// between those two lists is the whole state machine — see
/// ``isFullySigned``.
///
/// **``onChain`` is three-valued, and deliberately so.** `true` means a
/// block confirms it, `false` means this row has never left the device,
/// and **`nil` means a carve was broadcast and no block has confirmed
/// it yet** — the state Android writes right after a successful
/// broadcast. Collapsing nil into false would tell the user to carve
/// again something they already paid for.
public struct Proof: Codable, Equatable, Sendable, Identifiable {

    // MARK: - wire fields, in Java declaration order

    public var title: String?
    public var content: String?
    /// Who the issuer asked to countersign. Empty or nil means the
    /// proof stands on the issuer's signature alone.
    public var cosignersInvited: [String]?
    /// Who actually has, per the chain. Never contains a FID absent
    /// from ``cosignersInvited`` — the indexer drops uninvited signs.
    public var cosignersSigned: [String]?
    /// Whether ownership can be moved. Fixed at issue; there is no op
    /// to change it afterwards.
    public var transferable: Bool?
    /// The indexer's verdict on whether the proof is in force. For a
    /// proof issued with `allSignsRequired` this stays false until the
    /// last invited cosigner signs.
    public var active: Bool?
    public var destroyed: Bool?

    public var issuer: String?
    public var owner: String?

    /// Whether every invited cosigner must sign before the proof takes
    /// force. **Draft-only, and not on the wire.** The op carries it
    /// (see ``ProofFeip/issueOp(title:content:cosigners:transferable:allSignsRequired:)``)
    /// but the `proof` index does not store it — what a chain record
    /// exposes is the *result*, ``active``. It is kept here so a draft
    /// can remember the choice between being saved and being carved;
    /// Android drops it, and carves `false` for every draft whatever the
    /// issuer ticked.
    public var allSignsRequired: Bool?

    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    /// Seconds since the epoch, like ``News/time`` and unlike the
    /// millisecond fields on the IM path.
    public var lastTime: Int64?
    public var lastHeight: Int64?
    /// Confirmed / broadcast-unconfirmed / local-only — see the type's
    /// note. Decoded from the wire, where it is absent for a record the
    /// indexer has not made up its mind about.
    public var onChain: Bool?

    /// The carve txid once carved; a locally derived digest before
    /// that. See ``localId(title:content:cosigners:transferable:)``.
    public var id: String

    // MARK: - local bookkeeping
    //
    // Not on the wire — see the CodingKeys note.

    public var addedAt: Date
    public var updatedAt: Date

    /// The wire fields only. `addedAt`/`updatedAt` are ours: a server
    /// reply never carries them, and decoding a record must not fail
    /// for their absence, which is why they are defaulted in
    /// ``init(from:)`` rather than made optional.
    private enum CodingKeys: String, CodingKey {
        case title, content, cosignersInvited, cosignersSigned
        case transferable, active, destroyed
        case issuer, owner, allSignsRequired
        case birthTime, birthHeight, lastTxId, lastTime, lastHeight
        case onChain, id
        case addedAt, updatedAt
    }

    public init(
        id: String,
        title: String? = nil,
        content: String? = nil,
        cosignersInvited: [String]? = nil,
        cosignersSigned: [String]? = nil,
        transferable: Bool? = nil,
        active: Bool? = nil,
        destroyed: Bool? = nil,
        issuer: String? = nil,
        owner: String? = nil,
        allSignsRequired: Bool? = nil,
        birthTime: Int64? = nil,
        birthHeight: Int64? = nil,
        lastTxId: String? = nil,
        lastTime: Int64? = nil,
        lastHeight: Int64? = nil,
        onChain: Bool? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.title = title
        self.content = content
        self.cosignersInvited = cosignersInvited
        self.cosignersSigned = cosignersSigned
        self.transferable = transferable
        self.active = active
        self.destroyed = destroyed
        self.issuer = issuer
        self.owner = owner
        self.allSignsRequired = allSignsRequired
        self.birthTime = birthTime
        self.birthHeight = birthHeight
        self.lastTxId = lastTxId
        self.lastTime = lastTime
        self.lastHeight = lastHeight
        self.onChain = onChain
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // A server row without an id is unusable, but throwing would
        // fail the whole page; the service drops those rows instead, so
        // decode tolerates it and leaves the id empty.
        id = (try c.decodeIfPresent(String.self, forKey: .id)) ?? ""
        title = try c.decodeIfPresent(String.self, forKey: .title)
        content = try c.decodeIfPresent(String.self, forKey: .content)
        cosignersInvited = try c.decodeIfPresent([String].self, forKey: .cosignersInvited)
        cosignersSigned = try c.decodeIfPresent([String].self, forKey: .cosignersSigned)
        transferable = try c.decodeIfPresent(Bool.self, forKey: .transferable)
        active = try c.decodeIfPresent(Bool.self, forKey: .active)
        destroyed = try c.decodeIfPresent(Bool.self, forKey: .destroyed)
        issuer = try c.decodeIfPresent(String.self, forKey: .issuer)
        owner = try c.decodeIfPresent(String.self, forKey: .owner)
        allSignsRequired = try c.decodeIfPresent(Bool.self, forKey: .allSignsRequired)
        birthTime = try c.decodeIfPresent(Int64.self, forKey: .birthTime)
        birthHeight = try c.decodeIfPresent(Int64.self, forKey: .birthHeight)
        lastTxId = try c.decodeIfPresent(String.self, forKey: .lastTxId)
        lastTime = try c.decodeIfPresent(Int64.self, forKey: .lastTime)
        lastHeight = try c.decodeIfPresent(Int64.self, forKey: .lastHeight)
        onChain = try c.decodeIfPresent(Bool.self, forKey: .onChain)
        addedAt = (try c.decodeIfPresent(Date.self, forKey: .addedAt)) ?? Date()
        updatedAt = (try c.decodeIfPresent(Date.self, forKey: .updatedAt)) ?? Date()
    }

    // MARK: - derived state

    /// List label: the title, else the elided id. A proof with no title
    /// is legal on the wire and should still be identifiable in a list.
    public var name: String {
        if let title, !title.isEmpty { return title }
        return id
    }

    /// Whether the chain has retired this proof.
    ///
    /// **A missing flag means not destroyed**, which is the whole point
    /// of spelling this out: `destroyed` is absent from plenty of rows,
    /// and `destroyed != true` and `destroyed == false` disagree exactly
    /// there. A list that decides membership with the wrong one of those
    /// shows every proof whose flag the indexer omitted.
    public var isDestroyed: Bool { destroyed == true }

    /// Every invited cosigner has signed (vacuously true when nobody
    /// was invited). The gate on transferring: moving a half-signed
    /// proof would hand over a document whose signatures were collected
    /// for a different holder.
    public var isFullySigned: Bool {
        guard let invited = cosignersInvited, !invited.isEmpty else { return true }
        let signed = Set(cosignersSigned ?? [])
        return invited.allSatisfy(signed.contains)
    }

    /// Invited but not yet signed, in the issuer's order.
    public var cosignersPending: [String] {
        guard let invited = cosignersInvited else { return [] }
        let signed = Set(cosignersSigned ?? [])
        return invited.filter { !signed.contains($0) }
    }

    /// `fid` was invited to countersign and has not yet done so — the
    /// condition behind the Sign action.
    public func awaitsSignature(from fid: String) -> Bool {
        guard onChain != false else { return false }
        guard let invited = cosignersInvited, invited.contains(fid) else { return false }
        return !(cosignersSigned ?? []).contains(fid)
    }

    /// `fid` may transfer this proof: it is confirmed on chain, they
    /// own it, it is transferable, in force, and fully signed. Mirrors
    /// the five conditions Android's `setupPayIcon` checks.
    public func canTransfer(as fid: String) -> Bool {
        onChain == true
            && owner == fid
            && transferable == true
            && active == true
            && destroyed != true
            && isFullySigned
    }

    /// `fid` may destroy this proof — only the current owner can, and
    /// only what the chain already knows about.
    public func canDestroy(as fid: String) -> Bool {
        onChain != false && owner == fid && destroyed != true
    }

    /// Case-insensitive substring match across the searchable fields —
    /// the same set the chain index exposes (`issuer`, `owner`,
    /// `title`, `content`, `cosignersInvited`, `id`), so that filtering
    /// the loaded rows and searching the chain agree about what a query
    /// means.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        if hit(title) || hit(content) || hit(issuer) || hit(owner) || hit(id) { return true }
        return (cosignersInvited ?? []).contains { hit($0) }
    }

    // MARK: - local id

    /// The id a proof carries before it has a txid — `sha256x2` of the
    /// issue detail, hex.
    ///
    /// Android hashes `Gson.toJson(proof)` over the whole object
    /// (`checkIdWithCreate`), which folds in fields a draft has no
    /// business committing to, like `owner` and `active`. This hashes
    /// exactly the five values the `issue` op will carve, so re-deriving
    /// the id of an unchanged draft is stable across a save/reload — the
    /// property the id exists for. It is 32 bytes of hex either way, so
    /// it can never collide with a txid of a different preimage, and the
    /// value never leaves the device: once carved, the txid replaces it.
    public static func localId(
        title: String?,
        content: String?,
        cosigners: [String]?,
        transferable: Bool?
    ) -> String {
        let detail = (try? ProofFeip.issueOp(
            title: title, content: content, cosigners: cosigners,
            transferable: transferable, allSignsRequired: nil
        )) ?? "\(title ?? "")\u{1F}\(content ?? "")"
        return Hex.encode(Hash.doubleSha256(Data(detail.utf8)))
    }

    /// A brand-new local-only proof, issued by `issuer` and not yet
    /// carved. `owner` starts as the issuer, matching what the chain
    /// will say once the carve confirms.
    ///
    /// ``active`` stays nil rather than true: it is the *indexer's*
    /// verdict on whether the proof is in force, and a draft that has
    /// never been carved has no indexer behind it. Android writes true
    /// here, which claims a proof with unsigned cosigners is already
    /// binding.
    public static func createLocal(
        title: String,
        content: String,
        cosigners: [String],
        transferable: Bool,
        allSignsRequired: Bool = false,
        issuer: String
    ) -> Proof {
        let invited = cosigners.isEmpty ? nil : cosigners
        return Proof(
            id: localId(
                title: title, content: content,
                cosigners: invited, transferable: transferable
            ),
            title: title,
            content: content,
            cosignersInvited: invited,
            transferable: transferable,
            destroyed: false,
            issuer: issuer,
            owner: issuer,
            allSignsRequired: cosigners.isEmpty ? nil : allSignsRequired,
            onChain: false
        )
    }
}
