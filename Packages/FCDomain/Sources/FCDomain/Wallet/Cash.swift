import Foundation
import FCCore

/// Local-only annotation describing how confident we are that a cash
/// reflects current chain state. Distinct from the server's ``Cash/onChain``
/// or ``Cash/valid`` flags — those mean "the indexer's view"; this means
/// "our view of the indexer's view". The third value `.offchain` is
/// reserved for future entities that can exist purely client-side
/// (contact, mail, secret); cash is always either `.onchain` (server
/// confirmed it) or `.unknown` (we created or modified locally and
/// haven't seen the server's confirmation yet).
public enum LocalState: String, Codable, Sendable {
    case offchain
    case unknown
    case onchain
}

/// One FCH cash — a UTXO in the abstract, but with the extra metadata
/// the FAPI `base.cashValid` endpoint emits: script type, lockTime,
/// redeemScript, coin-days, etc. P2PKH sends only need
/// (`birthTxId`, `birthIndex`, `value`) but P2SH-CLTV and multisig
/// (Phase 8) need the redeemScript/lockTime fields too — we keep the
/// full shape end-to-end so adding those signing paths later doesn't
/// require a second round-trip.
///
/// Wire shape mirrors the Java `data.fchData.Cash` Gson serialization
/// (`birthTxId` not `txId`, satoshis as a long not BCH-as-double).
public struct Cash: Codable, Equatable, Hashable, Sendable {

    public static let satoshisPerBch: Int64 = 100_000_000

    /// `sha256d(reverse(birthTxId) || birthIndex)` — server-computed,
    /// stable identifier across snapshots.
    public var id: String?

    /// Address that owns this cash. For P2PKH it's the recipient FID;
    /// for P2SH it's the script-hash address.
    public var owner: String

    /// Value in satoshis.
    public var value: Int64

    /// Cash type — `"P2PKH"`, `"P2SH_CLTV"`, `"P2SH_MULTISIG"`,
    /// `"P2SH_MULTISIG_CLTV"`, etc. Nil-tolerant: the server may omit
    /// it for plain P2PKH; treat `nil` as `"P2PKH"` at the call site.
    public var type: String?

    /// Birth = the tx that created this output.
    public var birthTxId: String
    public var birthIndex: Int

    /// Output's locking script, hex. Always present from the server.
    public var lockScript: String?

    /// P2SH redeem script (hex). Required to spend a P2SH output —
    /// without it, the spend can't be assembled.
    public var redeemScript: String?

    /// CLTV lock-time. Unix timestamp if > ~5e8, else block height.
    public var lockTime: Int64?

    public var birthBlockId: String?
    public var birthHeight: Int64?
    public var birthTime: Int64?
    public var birthTxIndex: Int?

    public var cd: Int64?
    public var cdd: Int64?

    public var valid: Bool?
    public var issuer: String?

    public var lastTime: Int64?
    public var lastHeight: Int64?

    // ---- spend coordinates (populated when this cash has been spent) ----

    /// Txid of the transaction that spent this cash. Mirror of the
    /// Java `spendTxId` field. Nil for unspent (`valid == true`)
    /// cashes; populated by `base.search` results when the cash is
    /// returned with `valid: false`.
    public var spendTxId: String?
    public var spendHeight: Int64?
    public var spendTime: Int64?
    public var spendIndex: Int?

    // ---- local-only annotations (see ``LocalState``) ----

    /// Whether the chain has confirmed this cash. Defaults to
    /// ``LocalState/onchain`` because almost every cash we see comes
    /// from a server response; the optimistic post-Send write path is
    /// the one place that creates `.unknown` rows.
    public var localState: LocalState

    /// `true` iff this cash was used as an input in a locally-broadcast
    /// transaction whose confirmation we haven't observed yet. The
    /// row stays in the cache (so manual recovery can restore it) but
    /// the wallet excludes it from spendable selection. When the
    /// server's next sync emits a `valid: false` delta for the same
    /// id we drop it for good. Independent of ``localState``: a
    /// freshly-confirmed `.onchain` cash can also be `pendingSpend`
    /// if we just used it.
    public var pendingSpend: Bool

    public init(
        id: String? = nil,
        owner: String,
        value: Int64,
        type: String? = nil,
        birthTxId: String,
        birthIndex: Int,
        lockScript: String? = nil,
        redeemScript: String? = nil,
        lockTime: Int64? = nil,
        birthBlockId: String? = nil,
        birthHeight: Int64? = nil,
        birthTime: Int64? = nil,
        birthTxIndex: Int? = nil,
        cd: Int64? = nil,
        cdd: Int64? = nil,
        valid: Bool? = nil,
        issuer: String? = nil,
        lastTime: Int64? = nil,
        lastHeight: Int64? = nil,
        spendTxId: String? = nil,
        spendHeight: Int64? = nil,
        spendTime: Int64? = nil,
        spendIndex: Int? = nil,
        localState: LocalState = .onchain,
        pendingSpend: Bool = false
    ) {
        self.id = id
        self.owner = owner
        self.value = value
        self.type = type
        self.birthTxId = birthTxId
        self.birthIndex = birthIndex
        self.lockScript = lockScript
        self.redeemScript = redeemScript
        self.lockTime = lockTime
        self.birthBlockId = birthBlockId
        self.birthHeight = birthHeight
        self.birthTime = birthTime
        self.birthTxIndex = birthTxIndex
        self.cd = cd
        self.cdd = cdd
        self.valid = valid
        self.issuer = issuer
        self.lastTime = lastTime
        self.lastHeight = lastHeight
        self.spendTxId = spendTxId
        self.spendHeight = spendHeight
        self.spendTime = spendTime
        self.spendIndex = spendIndex
        self.localState = localState
        self.pendingSpend = pendingSpend
    }

    // MARK: - Codable

    private enum CodingKeys: String, CodingKey {
        case id, owner, value, type, birthTxId, birthIndex, lockScript
        case redeemScript, lockTime, birthBlockId, birthHeight, birthTime, birthTxIndex
        case cd, cdd, valid, issuer, lastTime, lastHeight
        case spendTxId, spendHeight, spendTime, spendIndex
        case localState, pendingSpend
    }

    /// Decoder is hand-rolled so that older on-disk blobs (which
    /// predate `localState` / `pendingSpend`) decode cleanly with
    /// sensible defaults. The encoder uses Swift's synthesized impl —
    /// freshly-written rows always carry the new fields.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id           = try c.decodeIfPresent(String.self,  forKey: .id)
        self.owner        = try c.decode         (String.self,  forKey: .owner)
        self.value        = try c.decode         (Int64.self,   forKey: .value)
        self.type         = try c.decodeIfPresent(String.self,  forKey: .type)
        self.birthTxId    = try c.decode         (String.self,  forKey: .birthTxId)
        self.birthIndex   = try c.decode         (Int.self,     forKey: .birthIndex)
        self.lockScript   = try c.decodeIfPresent(String.self,  forKey: .lockScript)
        self.redeemScript = try c.decodeIfPresent(String.self,  forKey: .redeemScript)
        self.lockTime     = try c.decodeIfPresent(Int64.self,   forKey: .lockTime)
        self.birthBlockId = try c.decodeIfPresent(String.self,  forKey: .birthBlockId)
        self.birthHeight  = try c.decodeIfPresent(Int64.self,   forKey: .birthHeight)
        self.birthTime    = try c.decodeIfPresent(Int64.self,   forKey: .birthTime)
        self.birthTxIndex = try c.decodeIfPresent(Int.self,     forKey: .birthTxIndex)
        self.cd           = try c.decodeIfPresent(Int64.self,   forKey: .cd)
        self.cdd          = try c.decodeIfPresent(Int64.self,   forKey: .cdd)
        self.valid        = try c.decodeIfPresent(Bool.self,    forKey: .valid)
        self.issuer       = try c.decodeIfPresent(String.self,  forKey: .issuer)
        self.lastTime     = try c.decodeIfPresent(Int64.self,   forKey: .lastTime)
        self.lastHeight   = try c.decodeIfPresent(Int64.self,   forKey: .lastHeight)
        self.spendTxId    = try c.decodeIfPresent(String.self,  forKey: .spendTxId)
        self.spendHeight  = try c.decodeIfPresent(Int64.self,   forKey: .spendHeight)
        self.spendTime    = try c.decodeIfPresent(Int64.self,   forKey: .spendTime)
        self.spendIndex   = try c.decodeIfPresent(Int.self,     forKey: .spendIndex)
        self.localState   = try c.decodeIfPresent(LocalState.self, forKey: .localState) ?? .onchain
        self.pendingSpend = try c.decodeIfPresent(Bool.self,    forKey: .pendingSpend) ?? false
    }

    /// Compute the canonical cash id from `(birthTxId, birthIndex)` —
    /// the same value the server's indexer assigns. Mirrors
    /// `data.fchData.Cash.makeCashId(txId, j)` in FC-AJDK:
    /// `displayHex(sha256d(naturalTxIdBytes || leVoutBytes))`. We use
    /// this to pre-compute ids for optimistically-inserted change
    /// cashes after a Send, so the id matches when the server's
    /// next sync delta arrives.
    public static func makeId(birthTxId: String, birthIndex: Int) throws -> String {
        let natural = try TxBuilder.decodeTxid(birthTxId)
        var le = UInt32(truncatingIfNeeded: birthIndex).littleEndian
        let voutBytes = withUnsafeBytes(of: &le) { Data($0) }
        var merged = Data()
        merged.append(natural)
        merged.append(voutBytes)
        let digest = Hash.sha256(Hash.sha256(merged))
        // bytesToHexStringLE: reverse the digest, then hex-encode.
        return Data(digest.reversed()).map { String(format: "%02x", $0) }.joined()
    }

    /// Canonical P2PKH lockScript that pays to `hash160`:
    /// `76a914 <20-byte hash160> 88ac` = 25 bytes, 50 hex chars,
    /// lowercase. Independent of any cash instance — exposed so
    /// callers can compare directly.
    public static func canonicalP2PKHLockScript(hash160: Data) -> String {
        let hex = hash160.map { String(format: "%02x", $0) }.joined()
        return "76a914" + hex + "88ac"
    }

    /// True iff this cash's `lockScript` is the canonical P2PKH
    /// pattern paying to `hash160` — the only spend path
    /// ``FCCore.TxHandler/signP2pkhInput`` supports today.
    ///
    /// This is the source of truth for "is this spendable?", not
    /// the optional ``type`` string. The Java server populates
    /// ``type`` opportunistically (e.g. `Cash.fromUtxo` leaves it
    /// nil), so trusting it can let multisig / CLTV outputs slip
    /// through and produce a tx the node rejects with
    /// `mandatory-script-verify-flag-failed`.
    public func locksToP2PKH(hash160: Data) -> Bool {
        guard let s = lockScript?.lowercased() else { return false }
        return s == Cash.canonicalP2PKHLockScript(hash160: hash160)
    }

    public enum Failure: Error, CustomStringConvertible {
        case unexpectedResponseShape
        case missingRequiredField(String)

        public var description: String {
            switch self {
            case .unexpectedResponseShape:
                return "Cash: FAPI response data was not a JSON array of objects"
            case .missingRequiredField(let f):
                return "Cash: required field '\(f)' missing or wrong type"
            }
        }
    }

    /// Parse the `data` array from a `base.cashValid` FAPI response.
    public static func parseFapiList(_ rawJson: Data) throws -> [Cash] {
        let parsed = try JSONSerialization.jsonObject(with: rawJson, options: [])
        guard let array = parsed as? [[String: Any]] else {
            throw Failure.unexpectedResponseShape
        }
        return try array.map(Cash.init(dict:))
    }

    init(dict: [String: Any]) throws {
        guard let owner = dict["owner"] as? String else {
            throw Failure.missingRequiredField("owner")
        }
        guard let value = (dict["value"] as? NSNumber)?.int64Value else {
            throw Failure.missingRequiredField("value")
        }
        guard let birthTxId = dict["birthTxId"] as? String else {
            throw Failure.missingRequiredField("birthTxId")
        }
        guard let birthIndex = (dict["birthIndex"] as? NSNumber)?.intValue else {
            throw Failure.missingRequiredField("birthIndex")
        }
        self.init(
            id: dict["id"] as? String,
            owner: owner,
            value: value,
            type: dict["type"] as? String,
            birthTxId: birthTxId,
            birthIndex: birthIndex,
            lockScript: dict["lockScript"] as? String,
            redeemScript: dict["redeemScript"] as? String,
            lockTime: (dict["lockTime"] as? NSNumber)?.int64Value,
            birthBlockId: dict["birthBlockId"] as? String,
            birthHeight: (dict["birthHeight"] as? NSNumber)?.int64Value,
            birthTime: (dict["birthTime"] as? NSNumber)?.int64Value,
            birthTxIndex: (dict["birthTxIndex"] as? NSNumber)?.intValue,
            cd: (dict["cd"] as? NSNumber)?.int64Value,
            cdd: (dict["cdd"] as? NSNumber)?.int64Value,
            valid: (dict["valid"] as? NSNumber)?.boolValue,
            issuer: dict["issuer"] as? String,
            lastTime: (dict["lastTime"] as? NSNumber)?.int64Value,
            lastHeight: (dict["lastHeight"] as? NSNumber)?.int64Value,
            spendTxId: dict["spendTxId"] as? String,
            spendHeight: (dict["spendHeight"] as? NSNumber)?.int64Value,
            spendTime: (dict["spendTime"] as? NSNumber)?.int64Value,
            spendIndex: (dict["spendIndex"] as? NSNumber)?.intValue
        )
    }
}
