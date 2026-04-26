import Foundation

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
        lastHeight: Int64? = nil
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
    }

    /// True iff this cash can be spent with a single P2PKH signature
    /// against the standard scriptPubKey. Other script types need
    /// dedicated builders (Phase 8).
    public var isStandardP2PKH: Bool {
        let t = type ?? "P2PKH"
        return t == "P2PKH"
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
            lastHeight: (dict["lastHeight"] as? NSNumber)?.int64Value
        )
    }
}
