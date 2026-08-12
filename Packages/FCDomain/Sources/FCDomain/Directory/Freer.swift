import Foundation

/// Wire-level decode of one entry in a `base.freerByIds` response.
/// Mirrors the Java `com.fc.fc_ajdk.data.fchData.Freer` (extends
/// `FcSubject` → `FcEntity`) — the on-chain identity record for one
/// FID. Every field is optional because the server omits keys when
/// it has no value (Jackson with `@JsonIgnoreProperties(ignoreUnknown=true)`).
///
/// The struct is a strict subset of ``Contact`` (Contact = Freer +
/// editable detail + Mac-local extras), so domain code merges a freshly
/// fetched `Freer` into a `Contact` via ``Contact/merging(_:)``.
public struct Freer: Codable, Hashable, Sendable {

    public var id: String?
    public var meta: ContactMeta?

    public var cid: String?
    public var usedCids: [String]?

    /// Hex-encoded SEC1-compressed pubkey (66 chars). Decoded into the
    /// 33-byte ``Contact/pubkey`` at merge time.
    public var pubkey: String?
    public var isNobody: Bool?

    public var balance: Int64?
    public var cash: Int64?
    public var income: Int64?
    public var expend: Int64?

    public var cd: Int64?
    public var cdd: Int64?
    public var reputation: Int64?
    public var hot: Int64?
    public var weight: Int64?

    public var master: String?
    public var guide: String?
    public var noticeFee: String?
    public var home: [String: String]?

    public var btcAddr: String?
    public var ethAddr: String?
    public var ltcAddr: String?
    public var dogeAddr: String?
    public var trxAddr: String?
    public var bchAddr: String?

    public var birthHeight: Int64?
    public var nameTime: Int64?
    public var lastHeight: Int64?

    public var multisig: Multisig?

    public init() {}
}

public extension Contact {

    /// Return a new ``Contact`` with on-chain fields overwritten from
    /// `freer`. Preserves locally-edited detail (``titles``, ``memo``,
    /// ``seeStatement``, ``seeWritings``, ``pinnedAt``, ``addedAt``).
    /// `updatedAt` is bumped so the store sees a change.
    ///
    /// ``Contact/onChain`` is deliberately left alone: it means "my
    /// CONTACT carve for this FID exists on-chain", not "this FID has
    /// a Freer record". Only the carve/sync paths may set it
    /// (Android's save button likewise writes `setOnChain(false)`).
    func merging(_ freer: Freer) -> Contact {
        var c = self

        if let v = freer.meta { c.meta = v }
        if let v = freer.cid { c.cid = v }
        if let v = freer.usedCids { c.usedCids = v }
        if let v = freer.isNobody { c.isNobody = v }
        if let hex = freer.pubkey, let data = Self.decodePubkeyHex(hex) {
            c.pubkey = data
        }

        if let v = freer.balance { c.balance = v }
        if let v = freer.cash { c.cash = v }
        if let v = freer.income { c.income = v }
        if let v = freer.expend { c.expend = v }
        if let v = freer.cd { c.cd = v }
        if let v = freer.cdd { c.cdd = v }
        if let v = freer.reputation { c.reputation = v }
        if let v = freer.hot { c.hot = v }
        if let v = freer.weight { c.weight = v }

        if let v = freer.master { c.master = v }
        if let v = freer.guide { c.guide = v }
        if let v = freer.noticeFee { c.noticeFee = v }
        if let v = freer.home { c.home = v }

        if let v = freer.btcAddr { c.btcAddr = v }
        if let v = freer.ethAddr { c.ethAddr = v }
        if let v = freer.ltcAddr { c.ltcAddr = v }
        if let v = freer.dogeAddr { c.dogeAddr = v }
        if let v = freer.trxAddr { c.trxAddr = v }
        if let v = freer.bchAddr { c.bchAddr = v }

        if let v = freer.birthHeight { c.birthHeight = v }
        if let v = freer.nameTime { c.nameTime = v }
        if let v = freer.lastHeight { c.lastHeight = v }
        if let v = freer.multisig { c.multisig = v }

        c.updatedAt = Date()
        return c
    }

    /// Parse a 66-char hex string as a 33-byte SEC1-compressed pubkey.
    /// Returns nil for any other length — uncompressed (65 B) and
    /// malformed encodings are ignored rather than silently coerced
    /// so a wrong pubkey never lands in the contact record.
    internal static func decodePubkeyHex(_ s: String) -> Data? {
        guard s.count == 66, s.count % 2 == 0 else { return nil }
        var data = Data(capacity: 33)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let b = UInt8(s[idx..<next], radix: 16) else { return nil }
            data.append(b)
            idx = next
        }
        guard data.count == 33 else { return nil }
        let prefix = data[0]
        guard prefix == 0x02 || prefix == 0x03 else { return nil }
        return data
    }
}

public extension KeyInfo {

    /// Build a privkey-less ``KeyInfo`` from an on-chain ``Freer``
    /// record — the Android `KeyInfo.fromCid`. Used when registering
    /// a sub-identity discovered through the directory (a master, a
    /// watched FID). Label defaults to the CID so lists show the
    /// human name when one exists. Returns nil when the record has
    /// no `id` (nothing to key it by).
    static func from(freer: Freer, kind: KeyKind = .watched) -> KeyInfo? {
        guard let fid = freer.id else { return nil }
        return KeyInfo(
            fid: fid,
            pubkey: freer.pubkey.flatMap(Contact.decodePubkeyHex),
            prikeyCipher: nil,
            label: freer.cid ?? "",
            kind: kind,
            master: freer.master
        )
    }
}
