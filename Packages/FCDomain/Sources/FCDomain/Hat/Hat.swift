import Foundation
import FCCore

/// A HAT — the local metadata record describing one piece of data
/// (a file, a slice of one, or an encrypted copy of one). Mirror of
/// `FC-AJDK/.../data/fcData/Hat.java` field for field.
///
/// HATs are **local only**: no blockchain sync, no FEIP carve. They
/// travel between devices two ways — an explicit HAT export/import, and
/// IM file messages, whose body is literally `hat.toJson()` with the
/// plaintext `key` and DISK locations filled in. Both paths mean the
/// JSON here must match Android's byte for byte, which drives three
/// details that look like mistakes and are not:
///
/// - **`Leaked` is capitalized.** Java's field is `Leaked`, and Gson
///   serializes field names verbatim.
/// - **Field order is Hat's own fields, then `objName`, then `id`.**
///   Gson emits the declaring class before its superclasses
///   (`FcObject` contributes `objName`, `FcEntity` contributes `id`).
/// - **Two encoders, differing only in escaping.** Java's `toJson()`
///   disables HTML escaping, but `toBytes()` — whose output
///   ``checkIdWithCreate()`` hashes into the DID — uses a bare
///   `new Gson()`, which escapes `< > & = '`. A HAT named `a&b.txt`
///   therefore hashes over `a&b.txt` while its stored JSON keeps
///   the literal `&`. See ``wireJson()`` and ``idSourceJson()``.
///
/// `id` is the DID: for file data, the hex `sha256x2` of the content;
/// for a HAT with no content id of its own, whatever
/// ``checkIdWithCreate()`` derives.
public struct Hat: Codable, Equatable, Sendable, Identifiable {

    /// Lifecycle state. Serialized by name (`"ACTIVE"`), matching
    /// Gson's default enum handling; the byte numbers are kept for
    /// parity with the Java enum's `number` field.
    public enum DataState: String, Codable, Sendable, CaseIterable {
        case active = "ACTIVE"
        case deleted = "DELETED"
        case outdated = "OUTDATED"
        case archived = "ARCHIVED"

        /// The Java enum's byte value.
        public var number: UInt8 {
            switch self {
            case .deleted:  return 0
            case .active:   return 1
            case .outdated: return 2
            case .archived: return 3
            }
        }
    }

    // MARK: basic
    /// Hash algorithm. Java spells the field `hAlg`.
    public var hAlg: String?
    /// Size in bytes.
    public var size: Int64?
    /// Creation time (epoch ms).
    public var born: Int64?
    /// Last-used time (epoch ms) — the Files pane's sort key.
    public var last: Int64?

    // MARK: extend
    public var name: String?
    public var desc: String?
    public var types: [String]?
    /// App ids.
    public var aids: [String]?
    /// Protocol ids.
    public var pids: [String]?

    // MARK: version
    /// DID of the first version.
    public var srcDid: String?
    /// DID of the previous version.
    public var preDid: String?

    // MARK: slice
    /// DID of the whole data this is a slice of.
    public var tDid: String?
    /// Size of that whole data.
    public var tSize: Int64?
    /// This slice's offset within it.
    public var offset: Int64?

    // MARK: crypto
    /// Set on a **cipher** HAT: the DID of the raw data it encrypts.
    /// Cipher HATs are hidden from the file list.
    public var rawDid: String?
    /// Plaintext symmetric key, hex. Present on HATs shared through IM
    /// so the receiver can decrypt without any private key.
    public var key: String?
    /// The symkey encrypted to the owner's pubkey (a CryptoDataStr
    /// envelope, JSON).
    public var kCipher: String?
    /// Java spells this field `Leaked`, capital L.
    public var leaked: Bool?
    /// DIDs of cipher HATs derived from this raw HAT.
    public var cipherIds: [String]?

    // MARK: manage
    public var rank: Int?
    public var state: DataState?
    /// Where the bytes live: `local://<path>`, `fudp://host:port`,
    /// `(sid)<serviceId>`.
    public var locas: [String]?

    // MARK: FcObject / FcEntity
    public var objName: String?
    /// The DID.
    public var id: String?

    public init(
        hAlg: String? = nil,
        size: Int64? = nil,
        born: Int64? = nil,
        last: Int64? = nil,
        name: String? = nil,
        desc: String? = nil,
        types: [String]? = nil,
        aids: [String]? = nil,
        pids: [String]? = nil,
        srcDid: String? = nil,
        preDid: String? = nil,
        tDid: String? = nil,
        tSize: Int64? = nil,
        offset: Int64? = nil,
        rawDid: String? = nil,
        key: String? = nil,
        kCipher: String? = nil,
        leaked: Bool? = nil,
        cipherIds: [String]? = nil,
        rank: Int? = nil,
        state: DataState? = nil,
        locas: [String]? = nil,
        objName: String? = nil,
        id: String? = nil
    ) {
        self.hAlg = hAlg
        self.size = size
        self.born = born
        self.last = last
        self.name = name
        self.desc = desc
        self.types = types
        self.aids = aids
        self.pids = pids
        self.srcDid = srcDid
        self.preDid = preDid
        self.tDid = tDid
        self.tSize = tSize
        self.offset = offset
        self.rawDid = rawDid
        self.key = key
        self.kCipher = kCipher
        self.leaked = leaked
        self.cipherIds = cipherIds
        self.rank = rank
        self.state = state
        self.locas = locas
        self.objName = objName
        self.id = id
    }

    /// JSON keys exactly as Java spells the fields.
    public enum CodingKeys: String, CodingKey {
        case hAlg, size, born, last
        case name, desc, types, aids, pids
        case srcDid, preDid
        case tDid, tSize, offset
        case rawDid, key, kCipher
        case leaked = "Leaked"
        case cipherIds
        case rank, state, locas
        case objName, id
    }

    // MARK: - derived properties

    /// True for the cipher half of the two-HAT model. These are hidden
    /// from the Files list (Android's `filterOutCipherHats`).
    public var isCipherHat: Bool { rawDid != nil }

    /// Display name, falling back to the DID like Android's
    /// `resolveFileName`.
    public var displayName: String {
        if let name, !name.trimmingCharacters(in: .whitespaces).isEmpty {
            return name.trimmingCharacters(in: .whitespaces)
        }
        return id ?? ""
    }

    /// First declared MIME type, if any.
    public var mimeType: String? { types?.first }

    /// Case-insensitive substring match across every field Android's
    /// `HatManager.searchFromList` indexes. Lives here rather than on
    /// the store so a list already in memory can filter as the user
    /// types, without a round trip per keystroke.
    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        func hitList(_ list: [String]?) -> Bool {
            guard let list else { return false }
            return list.contains { $0.lowercased().contains(needle) }
        }
        return hit(id) || hit(name) || hit(desc)
            || hitList(types) || hitList(aids) || hitList(pids)
            || hit(srcDid) || hit(preDid) || hit(tDid) || hit(rawDid)
            || hitList(locas)
    }

    /// Locations that are remote DISK services (`fudp://` or `(sid)`).
    public var remoteLocas: [String] {
        (locas ?? []).filter {
            $0.hasPrefix(Hat.fudpLocationPrefix) || $0.hasPrefix(Hat.sidLocationPrefix)
        }
    }

    /// Local filesystem paths recorded on this HAT (the `local://`
    /// entries, prefix stripped).
    public var localPaths: [String] {
        (locas ?? []).compactMap {
            $0.hasPrefix(Hat.localLocationPrefix)
                ? String($0.dropFirst(Hat.localLocationPrefix.count))
                : nil
        }
    }

    /// Whether the data can be fetched from a DISK service — either a
    /// remote location on this HAT or a cipher HAT to go through.
    public var hasDiskSource: Bool {
        !remoteLocas.isEmpty || !(cipherIds ?? []).isEmpty
    }

    public static let localLocationPrefix = "local://"
    public static let fudpLocationPrefix = "fudp://"
    public static let sidLocationPrefix = "(sid)"

    // MARK: - mutation helpers

    /// Add a location if not already present. Mirrors
    /// `HatManager.addHatLocation`, including its `last` bump.
    public mutating func addLoca(_ loca: String, nowMs: Int64 = Hat.currentTimeMillis()) {
        var list = locas ?? []
        guard !list.contains(loca) else { return }
        list.append(loca)
        locas = list
        last = nowMs
    }

    /// Remove every `local://` location (the file itself is deleted by
    /// the caller). Mirrors DataActivity's "remove local data".
    public mutating func removeLocalLocas(nowMs: Int64 = Hat.currentTimeMillis()) {
        let remaining = (locas ?? []).filter { !$0.hasPrefix(Hat.localLocationPrefix) }
        locas = remaining
        last = nowMs
    }

    /// Add a cipher HAT's DID. Mirrors `HatManager.addCipherId`.
    public mutating func addCipherId(_ cipherId: String, nowMs: Int64 = Hat.currentTimeMillis()) {
        var list = cipherIds ?? []
        guard !list.contains(cipherId) else { return }
        list.append(cipherId)
        cipherIds = list
        last = nowMs
    }

    // MARK: - JSON

    /// The JSON Android's `Hat.toJson()` produces: declaration order,
    /// nulls omitted, HTML escaping **disabled**. This is what goes
    /// into IM file messages and HAT exports.
    public func wireJson() -> String {
        GsonCompatibleWriter.object(orderedFields(), htmlSafe: false)
    }

    /// The JSON Android's `toBytes()` produces — identical except that
    /// `< > & = '` are escaped as `\uXXXX`. Only ``checkIdWithCreate()``
    /// consumes this; it exists because the DID is hashed over these
    /// bytes, not over ``wireJson()``.
    public func idSourceJson() -> String {
        GsonCompatibleWriter.object(orderedFields(), htmlSafe: true)
    }

    /// Decode an Android-produced `Hat.toJson()` string.
    public static func fromJson(_ json: String) throws -> Hat {
        try JSONDecoder().decode(Hat.self, from: Data(json.utf8))
    }

    /// Assign the DID if absent: `hex(sha256x2(toBytes()))` over this
    /// HAT with no `id` — the port of `Hat.checkIdWithCreate()`.
    /// A HAT that already has an id (the normal case: the id *is* the
    /// content hash) is untouched.
    public mutating func checkIdWithCreate() {
        guard id == nil else { return }
        var copy = self
        copy.id = nil
        let bytes = Data(copy.idSourceJson().utf8)
        id = Hash.doubleSha256(bytes).map { String(format: "%02x", $0) }.joined()
    }

    /// Fields in Java declaration order, nils dropped. Hat's own fields
    /// come first, then `objName` (FcObject) and `id` (FcEntity) —
    /// Gson's declaring-class-first ordering.
    private func orderedFields() -> [(String, GsonCompatibleWriter.Value)] {
        var out: [(String, GsonCompatibleWriter.Value)] = []
        func put(_ k: String, _ v: String?)   { if let v { out.append((k, .string(v))) } }
        func put(_ k: String, _ v: Int64?)    { if let v { out.append((k, .int(v))) } }
        func put(_ k: String, _ v: Int?)      { if let v { out.append((k, .int(Int64(v)))) } }
        func put(_ k: String, _ v: Bool?)     { if let v { out.append((k, .bool(v))) } }
        func put(_ k: String, _ v: [String]?) { if let v { out.append((k, .stringArray(v))) } }

        put("hAlg", hAlg)
        put("size", size)
        put("born", born)
        put("last", last)
        put("name", name)
        put("desc", desc)
        put("types", types)
        put("aids", aids)
        put("pids", pids)
        put("srcDid", srcDid)
        put("preDid", preDid)
        put("tDid", tDid)
        put("tSize", tSize)
        put("offset", offset)
        put("rawDid", rawDid)
        put("key", key)
        put("kCipher", kCipher)
        put("Leaked", leaked)
        put("cipherIds", cipherIds)
        put("rank", rank)
        if let state { out.append(("state", .string(state.rawValue))) }
        put("locas", locas)
        put("objName", objName)
        put("id", id)
        return out
    }

    public static func currentTimeMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }
}

/// Minimal JSON object writer matching Gson's output for the value
/// shapes a ``Hat`` uses (string, integer, bool, string array).
///
/// Needed because neither `JSONEncoder` nor `JSONSerialization` can
/// promise **field order** or reproduce **Gson's escaping**, and a HAT
/// crossing to Android must be byte-identical: its DID is a hash of
/// these bytes.
enum GsonCompatibleWriter {

    enum Value {
        case string(String)
        case int(Int64)
        case bool(Bool)
        case stringArray([String])
    }

    static func object(_ fields: [(String, Value)], htmlSafe: Bool) -> String {
        var out = "{"
        for (index, field) in fields.enumerated() {
            if index > 0 { out += "," }
            out += "\"" + escape(field.0, htmlSafe: htmlSafe) + "\":"
            out += render(field.1, htmlSafe: htmlSafe)
        }
        out += "}"
        return out
    }

    private static func render(_ value: Value, htmlSafe: Bool) -> String {
        switch value {
        case .string(let s):
            return "\"" + escape(s, htmlSafe: htmlSafe) + "\""
        case .int(let i):
            return String(i)
        case .bool(let b):
            return b ? "true" : "false"
        case .stringArray(let list):
            let items = list.map { "\"" + escape($0, htmlSafe: htmlSafe) + "\"" }
            return "[" + items.joined(separator: ",") + "]"
        }
    }

    /// Port of Gson's `JsonWriter.string()` escaping tables.
    ///
    /// Base table: control characters below 0x20 become `\u00xx`, with
    /// short forms for `\b \t \n \f \r`, plus `"` and `\`. U+2028 and
    /// U+2029 are escaped because they are line terminators in
    /// JavaScript. The HTML-safe table adds `< > & = '` — that table is
    /// Gson's default, and `disableHtmlEscaping()` selects the base one.
    static func escape(_ s: String, htmlSafe: Bool) -> String {
        var out = ""
        out.reserveCapacity(s.count + 2)
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"":  out += "\\\""
            case "\\":  out += "\\\\"
            case "\t":  out += "\\t"
            case "\u{08}": out += "\\b"
            case "\n":  out += "\\n"
            case "\r":  out += "\\r"
            case "\u{0C}": out += "\\f"
            case "\u{2028}": out += "\\u2028"
            case "\u{2029}": out += "\\u2029"
            case "<", ">", "&", "=", "'":
                if htmlSafe {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }
}
