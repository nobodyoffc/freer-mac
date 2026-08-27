import Foundation

/// The FEIP protocol registry — a port of FC-AJDK's
/// `Feip.FeipProtocol` enum: serial number, current version, and
/// protocol name for each of the twenty-five FEIP protocols.
///
/// **This is a lookup table, not an authority.** The carve builders in
/// this package (``ContactFeip``, ``MailFeip``, ``SecretFeip``,
/// ``GroupFeip``, ``NoticeFee``) each spell their own `sn`/`ver` into
/// the JSON they emit, and they keep doing so: a protocol's version is
/// pinned by the payload shape that builder writes, and reading it from
/// a shared table would let a bump here silently change what those
/// carve. What this table is for is the other direction — turning an
/// `sn` that arrives *from* the chain into something a reader can
/// understand, which is what the ``News`` feed needs on every row.
public enum FeipProtocol: String, CaseIterable, Sendable {
    case protocolMeta
    case code
    case cid
    case nobody
    case service
    case master
    case mail
    case statement
    case home
    case noticeFee
    case nid
    case contact
    case box
    case proof
    case app
    case reputation
    case secret
    case team
    case square
    case token
    case text
    case remark
    case sound
    case image
    case video

    /// Serial number, as it appears in a carve's `sn` and in
    /// ``News/objectType``.
    public var sn: String {
        switch self {
        case .protocolMeta: return "1"
        case .code:         return "2"
        case .cid:          return "3"
        case .nobody:       return "4"
        case .service:      return "5"
        case .master:       return "6"
        case .mail:         return "7"
        case .statement:    return "8"
        case .home:         return "9"
        case .noticeFee:    return "10"
        case .nid:          return "11"
        case .contact:      return "12"
        case .box:          return "13"
        case .proof:        return "14"
        case .app:          return "15"
        case .reputation:   return "16"
        case .secret:       return "17"
        case .team:         return "18"
        case .square:       return "19"
        case .token:        return "20"
        case .text:         return "21"
        case .remark:       return "22"
        case .sound:        return "23"
        case .image:        return "24"
        case .video:        return "25"
        }
    }

    /// Current protocol version per the Android table.
    public var ver: String {
        switch self {
        case .protocolMeta: return "7"
        case .cid:          return "4"
        case .service:      return "3"
        case .mail:         return "4"
        case .contact:      return "3"
        case .secret:       return "3"
        case .square:       return "4"
        default:            return "1"
        }
    }

    /// Protocol name as the wire spells it. Protocol text, not display
    /// text — never localised, never reworded.
    public var protocolName: String {
        switch self {
        case .protocolMeta: return "FeipProtocol"
        case .code:         return "Code"
        case .cid:          return "CID"
        case .nobody:       return "Nobody"
        case .service:      return "Service"
        case .master:       return "Master"
        case .mail:         return "Mail"
        case .statement:    return "Statement"
        case .home:         return "Home"
        case .noticeFee:    return "NoticeFee"
        case .nid:          return "NID"
        case .contact:      return "Contact"
        case .box:          return "Box"
        case .proof:        return "Proof"
        case .app:          return "APP"
        case .reputation:   return "Reputation"
        case .secret:       return "Secret"
        case .team:         return "Team"
        case .square:       return "Square"
        case .token:        return "Token"
        case .text:         return "Text"
        case .remark:       return "Remark"
        case .sound:        return "Sound"
        case .image:        return "Image"
        case .video:        return "Video"
        }
    }

    public static func bySn(_ sn: String?) -> FeipProtocol? {
        guard let sn else { return nil }
        let trimmed = sn.trimmingCharacters(in: .whitespaces)
        return allCases.first { $0.sn == trimmed }
    }

    /// Protocol name for an `sn`, falling back to whatever arrived.
    ///
    /// The indexer is not guaranteed to write serial numbers — an
    /// unrecognised value is shown as-is rather than blanked, because a
    /// feed row that says something we don't have a name for is still
    /// more use than one that says nothing.
    public static func displayName(forSn sn: String?) -> String? {
        guard let sn, !sn.isEmpty else { return nil }
        return bySn(sn)?.protocolName ?? sn
    }
}
