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

    /// The home map with a new BASE, DOCK, DISK and/or CALL, under the keys every
    /// resolver in this app looks up (``ServiceName``). `removeCall` takes
    /// the CALL entry out, which stops calls (FIMP5 §6.1). Nil when nothing
    /// would change — a carve for that would cost a fee to say nothing.
    public static func merged(
        over stored: [String: String]?,
        base: String? = nil,
        dock: String?,
        disk: String?,
        call: String? = nil,
        removeCall: Bool = false
    ) -> [String: String]? {
        GroupHome.merged(
            over: stored,
            changing: [ServiceName.base: base, ServiceName.dock: dock, ServiceName.disk: disk, ServiceName.call: removeCall ? nil : call],
            removing: removeCall ? ["CALL"] : []
        )
    }

    /// The home carved when BASE and DISK may each be kept private: the
    /// sealed entries are sealed to `pubkey` here, and only when they
    /// change. Nil when nothing would. See ``HomePrivacy``.
    public static func planned(
        over stored: [String: String]?,
        base: HomeEntry?,
        dock: String?,
        disk: HomeEntry?,
        call: String? = nil,
        removeCall: Bool = false,
        prikey: Data?,
        pubkey: Data
    ) throws -> [String: String]? {
        try plan(over: stored, base: base, dock: dock, disk: disk, call: call, removeCall: removeCall, prikey: prikey) {
            try HomePrivacy.seal($0, toPubkey: pubkey)
        }
    }

    /// Whether ``planned(over:base:dock:disk:call:removeCall:prikey:pubkey:)``
    /// would carve anything — without sealing, so a form can ask on every
    /// keystroke. An entry that cannot be sealed counts as no carve.
    public static func wouldChange(
        over stored: [String: String]?,
        base: HomeEntry?,
        dock: String?,
        disk: HomeEntry?,
        call: String? = nil,
        removeCall: Bool = false,
        prikey: Data?
    ) -> Bool {
        let planned = try? plan(over: stored, base: base, dock: dock, disk: disk, call: call, removeCall: removeCall, prikey: prikey) {
            "{sealed:\($0)}"
        }
        return (planned ?? nil) != nil
    }

    private static func plan(
        over stored: [String: String]?,
        base: HomeEntry?, dock: String?, disk: HomeEntry?,
        call: String?, removeCall: Bool, prikey: Data?,
        seal: (String) throws -> String
    ) throws -> [String: String]? {
        let baseValue = try HomePrivacy.pending(base, over: value(of: "BASE", in: stored), prikey: prikey, seal: seal)
        let diskValue = try HomePrivacy.pending(disk, over: value(of: "DISK", in: stored), prikey: prikey, seal: seal)
        return merged(over: stored, base: baseValue, dock: dock, disk: diskValue, call: call, removeCall: removeCall)
    }

    /// The value `home` holds for `kind`, under the key this app writes or
    /// any key another client wrote for it. Nil when blank or absent.
    public static func value(of kind: String, in home: [String: String]?) -> String? {
        guard let home else { return nil }
        let exact = "\(kind.uppercased())@No1_NrC7"
        let raw = home[exact] ?? home.first { GroupHome.isKey($0.key, ofKind: kind) }?.value
        let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Whether `home` names a service of `kind` (`"BASE"`, `"DOCK"`, `"DISK"`).
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
