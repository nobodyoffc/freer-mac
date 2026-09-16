import Foundation

/// Builders for FEIP3 `CID` (ver 4): a human-readable name for a FID.
///
/// ```json
/// {"type":"FEIP","sn":"3","ver":"4","name":"CID",
///  "data":{"op":"register","name":"Alice"}}
/// ```
///
/// **The carve names a name, not a CID.** The parser appends the suffix —
/// the FID's last four characters, one more for every collision with a
/// different FID — so what the user will be called is decided on the
/// indexer, from the chain as it stands when the carve confirms.
/// ``preview(name:fid:ownUsedCids:ownerOf:)`` runs the same rule against
/// the chain now, which is the best a client can say before paying.
public enum CidFeip {

    public static let sn = "3"
    public static let ver = "4"
    public static let protocolName = "CID"

    /// The spec's limit on `usedCids`; a fifth distinct CID is ignored.
    public static let maxUsedCids = 4
    public static let baseSuffixLength = 4

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case badName(String)

        public var description: String {
            switch self {
            case .badName(let name):
                return "“\(name)” can't be a CID name: it must not be empty or contain spaces, @, # or /."
            }
        }
    }

    /// FEIP3's parsing rule 1. A name that fails it is carved, paid for,
    /// and ignored, so nothing that fails it is ever built.
    public static func isGoodName(_ name: String) -> Bool {
        !name.isEmpty && !name.contains { $0.isWhitespace || $0 == "@" || $0 == "#" || $0 == "/" }
    }

    public static func register(name: String) throws -> String {
        guard isGoodName(name) else { throw Failure.badName(name) }
        return try FeipEnvelope.json(
            sn: sn, ver: ver, name: protocolName,
            data: ["op": "register", "name": name]
        )
    }

    /// What registering `name` would do, decided the way the parser
    /// decides it.
    public enum Preview: Equatable, Sendable {
        /// A new CID for this FID.
        case new(cid: String)
        /// One of this FID's own earlier CIDs, made current again. Never
        /// counts against the limit.
        case reactivate(cid: String)
        /// Would be a fifth used CID, which the parser ignores.
        case limitReached(cid: String)
        /// Every suffix up to the whole FID is taken by somebody else.
        case unavailable
    }

    /// Run FEIP3's rules 2–5 for `name`. `ownerOf` answers which FID has
    /// ever used a CID, or nil.
    public static func preview(
        name: String,
        fid: String,
        ownUsedCids: [String],
        ownerOf: (String) async throws -> String?
    ) async throws -> Preview {
        guard isGoodName(name) else { throw Failure.badName(name) }
        var length = min(baseSuffixLength, fid.count)
        while length <= fid.count {
            let cid = "\(name)_\(fid.suffix(length))"
            if ownUsedCids.contains(cid) { return .reactivate(cid: cid) }
            if let owner = try await ownerOf(cid), owner != fid {
                length += 1
                continue
            }
            return ownUsedCids.count >= maxUsedCids ? .limitReached(cid: cid) : .new(cid: cid)
        }
        return .unavailable
    }
}

/// Builders for FEIP9 `Home` (ver 1): the map of services a FID can be
/// reached through.
///
/// **`register` replaces the whole map**, so a carve that only meant to
/// set the DOCK would erase every other entry. ``HomeFeip`` therefore
/// never takes a map from a screen: ``merged(over:dock:disk:)`` lays the
/// changes over what the chain holds, the same discipline ``GroupHome``
/// keeps for groups.
public enum HomeFeip {

    public static let sn = "9"
    public static let ver = "1"
    public static let protocolName = "Home"

    public static func register(home: [String: String]) throws -> String {
        try FeipEnvelope.json(
            sn: sn, ver: ver, name: protocolName,
            data: ["op": "register", "home": home]
        )
    }

    /// The home map with a new DOCK and/or DISK, under the keys every
    /// resolver in this app looks up (``ServiceName``). Nil when nothing
    /// would change — a carve for that would cost a fee to say nothing.
    public static func merged(
        over stored: [String: String]?,
        dock: String?,
        disk: String?
    ) -> [String: String]? {
        GroupHome.merged(over: stored, changing: [ServiceName.dock: dock, ServiceName.disk: disk])
    }

    /// Whether `home` names a service of `kind` (`"DOCK"`, `"DISK"`).
    ///
    /// By prefix, as Android and ``ChatGate/declaresDock(home:)`` read it: a
    /// map written by another client may use a bare `DOCK` key, and that FID
    /// is still reachable.
    public static func declares(_ kind: String, in home: [String: String]?) -> Bool {
        guard let home else { return false }
        return home.contains { key, value in
            key.uppercased().hasPrefix(kind.uppercased())
                && !value.trimmingCharacters(in: .whitespaces).isEmpty
        }
    }
}

/// The FEIP envelope with sorted keys, for builders whose data is a
/// plain dictionary.
enum FeipEnvelope {
    static func json(sn: String, ver: String, name: String, data: [String: Any]) throws -> String {
        let object: [String: Any] = ["type": "FEIP", "sn": sn, "ver": ver, "name": name, "data": data]
        let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        return String(decoding: bytes, as: UTF8.self)
    }
}
