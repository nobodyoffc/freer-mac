import Foundation

/// One entry in the live FID's address book. Mirrors the Java
/// `com.fc.fc_ajdk.data.feipData.Contact` so an Android-saved contact
/// (or an on-chain `freer.byIds` lookup result) can be reflected here
/// without lossy field renaming.
///
/// `id` is the FID (the FCH Base58Check address). On-chain identity
/// facts (`cid`, `pubkey`, `balance`, …) are populated lazily — when
/// the wallet syncs them or a FAPI `freer.byIds` lookup runs — and
/// are all optional. Locally editable detail lives in `titles`,
/// `memo`, `seeStatement`, `seeWritings`.
///
/// `pinnedAt` / `addedAt` / `updatedAt` are Mac-local UX additions —
/// Android doesn't pin contacts. They're never serialized on-chain.
public struct Contact: Codable, Equatable, Hashable, Sendable, Identifiable {

    // MARK: - identity

    /// FCH address. Primary key in ``ContactsStore`` and in the
    /// Android `feip` index.
    public var id: String

    /// On-chain protocol envelope `{p, v, n}` if this contact came
    /// from a FEIP record. Carried opaquely; the wallet doesn't read
    /// individual fields.
    public var meta: ContactMeta?

    /// Current Coin ID — the user's chosen on-chain handle. The
    /// preferred display name when set; otherwise we fall back to the
    /// FID. See ``name``.
    public var cid: String?

    /// Historic CIDs the same FID used in the past.
    public var usedCids: [String]?

    /// 33-byte SEC1-compressed pubkey. Populated by `freer.byIds` or
    /// after the first successful encrypted message exchange.
    public var pubkey: Data?

    /// True if the on-chain index has flagged this FID as "nobody"
    /// (no activity / decoy).
    public var isNobody: Bool?

    // MARK: - on-chain stats

    public var balance: Int64?      // satoshis
    public var cash: Int64?         // count of UTXOs
    public var income: Int64?       // total received satoshis
    public var expend: Int64?       // total spent satoshis

    public var cd: Int64?           // CoinDays
    public var cdd: Int64?          // CoinDays destroyed
    public var reputation: Int64?
    public var hot: Int64?
    public var weight: Int64?

    public var master: String?
    public var guide: String?       // FID that funded the first cash
    public var noticeFee: String?
    public var home: [String: String]?

    // MARK: - cross-chain addresses

    public var btcAddr: String?
    public var ethAddr: String?
    public var ltcAddr: String?
    public var dogeAddr: String?
    public var trxAddr: String?
    public var bchAddr: String?

    // MARK: - lifecycle

    public var birthHeight: Int64?  // first cash received height
    public var nameTime: Int64?     // when CID was set
    public var lastHeight: Int64?   // latest on-chain change
    public var birthTime: Int64?

    public var multisig: Multisig?

    // MARK: - editable detail (the on-chain "cipher" payload, decrypted)

    public var titles: [String]?
    public var memo: String?
    public var seeStatement: Bool?
    public var seeWritings: Bool?

    // MARK: - status

    /// True once the contact's on-chain FEIP record is confirmed.
    /// `nil` means pending; `false` means off-chain only.
    public var onChain: Bool?
    public var active: Bool?

    /// The id of the newest on-chain CONTACT carve for this FID
    /// (sha256x2 of the carve op — NOT the FID). Set by the chain
    /// sync; needed to target the record in `update` / `delete` /
    /// `recover` FEIP ops.
    public var carveId: String?

    // MARK: - Mac-local extras

    public var pinnedAt: Date?
    public var addedAt: Date
    public var updatedAt: Date

    // MARK: - computed

    /// What the UI shows as the contact's name. Mirrors the Android
    /// rule `name = cid == null ? id : cid`. Always non-nil.
    public var name: String { cid ?? id }

    public init(
        id: String,
        cid: String? = nil,
        pubkey: Data? = nil,
        titles: [String]? = nil,
        memo: String? = nil,
        seeStatement: Bool? = nil,
        seeWritings: Bool? = nil,
        onChain: Bool? = nil,
        pinnedAt: Date? = nil,
        addedAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.cid = cid
        self.pubkey = pubkey
        self.titles = titles
        self.memo = memo
        self.seeStatement = seeStatement
        self.seeWritings = seeWritings
        self.onChain = onChain
        self.pinnedAt = pinnedAt
        self.addedAt = addedAt
        self.updatedAt = updatedAt
    }
}

/// FEIP envelope sub-struct: `{ p: protocolId, v: version, n: name }`.
public struct ContactMeta: Codable, Equatable, Hashable, Sendable {
    public var p: String?
    public var v: String?
    public var n: String?

    public init(p: String? = nil, v: String? = nil, n: String? = nil) {
        self.p = p; self.v = v; self.n = n
    }
}

/// The redeem-script details of a multisig contact. Set when the
/// contact's FID resolves to a P2SH multisig address rather than a
/// P2PKH one. Mirrors the Java `Contact.Multisig` shape.
public struct Multisig: Codable, Equatable, Hashable, Sendable {
    public var redeemScript: String?
    public var m: Int?
    public var n: Int?
    public var pubkeys: [String]?
    public var fids: [String]?
    public var birthHeight: Int64?
    public var birthTime: Int64?
    public var birthTxId: String?
    public var saveTime: String?
    public var label: String?

    public init() {}
}
