import Foundation

/// HAT from a published work — FEIP21 Text, FEIP23 Sound, FEIP24 Image,
/// FEIP25 Video.
///
/// A reader who downloads a work by its `did` gets bytes with no
/// description. These build the HAT that describes them from the work's
/// on-chain fields. Mirror of `Hat.fromWork` / `Hat.mergeWork` in FC-JDK
/// and FC-AJDK `Hat.java`, rule for rule: HATs travel between devices as
/// JSON, so a work HAT built on any device must serialize identically.
/// The shared vector in `HatFromWorkTests` pins that.
///
/// Dropped on purpose: the work's id (the did finds the work again),
/// authors, cover, ver and lang — a HAT describes bytes, not the
/// publication.
extension Hat {

    /// The work protocols whose entities carry a content did.
    public enum WorkKind: String, CaseIterable, Sendable {
        case text, sound, image, video

        /// PID of the protocol document on chain.
        public var pid: String {
            switch self {
            case .text:  return "9fe31de9ef0e5af4637738af41f68ccaf93ff2f1b0c4264133cee9254772b144"
            case .sound: return "983ffb819e2793ba85b9171dc8d879abac352199f7e982ebecefc962245e6a72"
            case .image: return "34f8e6637506ea309c413b99296360101b12467f0b5e7db32051acddb4b6410f"
            case .video: return "89c23e636e93e6feb6776720688f02a138a036db338ed72df5510d5129b9ac00"
            }
        }

        /// MIME type used when the work's format names none.
        public var defaultMime: String {
            switch self {
            case .text:  return "text/plain"
            case .sound: return "audio/*"
            case .image: return "image/*"
            case .video: return "video/*"
            }
        }

        public init(_ media: MediaKind) {
            switch media {
            case .image: self = .image
            case .sound: self = .sound
            case .video: self = .video
            }
        }
    }

    public enum WorkError: Error, Equatable, CustomStringConvertible {
        case badDid(String?)
        case didMismatch
        /// A cipher HAT names encrypted bytes nobody else can read.
        case cipherHat

        public var description: String {
            switch self {
            case .badDid(let did): return "Not a content DID (64 hex characters): \(did ?? "nil")"
            case .didMismatch:     return "The two HATs describe different data"
            case .cipherHat:       return "This record is an encrypted copy; publish the original file instead"
            }
        }
    }

    public static let sha256x2 = "sha256x2"

    /// MIME ↔ extension. Order matters for the reverse lookup: the first
    /// MIME listed for an extension wins. Same table as Java.
    static let mimeExtensions: [(mime: String, ext: String)] = [
        ("text/plain", "txt"), ("text/markdown", "md"), ("text/html", "html"),
        ("application/pdf", "pdf"), ("application/epub+zip", "epub"),
        ("application/rtf", "rtf"), ("application/msword", "doc"),
        ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
        ("application/vnd.oasis.opendocument.text", "odt"),
        ("image/jpeg", "jpg"), ("image/png", "png"), ("image/gif", "gif"),
        ("image/webp", "webp"), ("image/svg+xml", "svg"),
        ("audio/mpeg", "mp3"), ("audio/mp4", "m4a"), ("audio/aac", "aac"),
        ("audio/wav", "wav"), ("audio/ogg", "ogg"), ("audio/flac", "flac"),
        ("video/mp4", "mp4"), ("video/webm", "webm"), ("video/quicktime", "mov"),
        ("video/x-matroska", "mkv"),
    ]
    static let extensionAliases: [(alias: String, ext: String)] = [("jpeg", "jpg"), ("markdown", "md")]

    public static func fromText(_ w: TextRecord, nowMs: Int64 = Hat.currentTimeMillis()) throws -> Hat {
        try fromWork(kind: .text, did: w.did, title: w.title, format: w.format,
                     summary: w.summary, locas: w.locas, nowMs: nowMs)
    }

    public static func fromMedia(_ w: MediaRecord, nowMs: Int64 = Hat.currentTimeMillis()) throws -> Hat {
        try fromWork(kind: WorkKind(w.kind), did: w.did, title: w.title, format: w.format,
                     summary: w.summary, locas: w.locas, nowMs: nowMs)
    }

    /// Build the HAT describing a work's content. Pure: touches no store,
    /// no network. `size` is left nil — works do not carry it; set it from
    /// the downloaded file. Add the local location after download too.
    public static func fromWork(
        kind: WorkKind, did: String?, title: String?, format: String?,
        summary: String?, locas: [String]?, nowMs: Int64 = Hat.currentTimeMillis()
    ) throws -> Hat {
        let id = did?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard let id, id.count == 64, id.allSatisfy({ $0.isHexDigit && $0.isASCII }) else {
            throw WorkError.badDid(did)
        }
        let mime = workMime(kind: kind, format: format)
        return Hat(
            hAlg: sha256x2,
            born: nowMs,
            last: nowMs,
            name: workFileName(did: id, title: title, mime: mime, format: format),
            desc: blankToNil(summary),
            types: [mime],
            pids: [kind.pid],
            state: .active,
            locas: union(nil, locas),
            id: id
        )
    }

    /// Fold a work's HAT into one the user already holds for the same did.
    /// What the user set stays: name (unless it is still the did-prefix
    /// placeholder), desc and types are only filled when empty; pids and
    /// locas are unioned, existing entries first; `last` moves forward.
    /// Size, born, crypto, version and slice fields are never touched.
    public static func mergeWork(_ existing: Hat?, _ work: Hat) throws -> Hat {
        guard var out = existing else { return work }
        guard let id = out.id, id.lowercased() == work.id?.lowercased() else {
            throw WorkError.didMismatch
        }
        let placeholder = String(id.prefix(8))
        if blankToNil(out.name) == nil || out.name == placeholder { out.name = work.name }
        if blankToNil(out.desc) == nil { out.desc = work.desc }
        if out.types?.isEmpty ?? true { out.types = work.types }
        if out.hAlg == nil { out.hAlg = work.hAlg }
        if out.state == nil { out.state = work.state }
        out.pids = union(out.pids, work.pids)
        out.locas = union(out.locas, work.locas)
        if let wl = work.last, (out.last ?? Int64.min) < wl { out.last = wl }
        if out.born == nil { out.born = work.born }
        return out
    }

    /// The format if it is a MIME type, else the MIME its extension maps
    /// to, else the kind's default.
    static func workMime(kind: WorkKind, format: String?) -> String {
        guard var f = blankToNil(format)?.lowercased() else { return kind.defaultMime }
        if let semi = f.firstIndex(of: ";") {
            f = String(f[..<semi]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if isMime(f) { return f }
        let ext = canonicalExtension(f.hasPrefix(".") ? String(f.dropFirst()) : f)
        return mimeExtensions.first { $0.ext == ext }?.mime ?? kind.defaultMime
    }

    /// Title made safe as a file name, with an extension from the MIME (or
    /// the bare format) appended unless the title already ends with it.
    /// The did's first 8 characters stand in for a missing title.
    static func workFileName(did: String, title: String?, mime: String, format: String?) -> String {
        var base = String(did.prefix(8))
        if let t = blankToNil(title) {
            base = t.replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "\\", with: "_")
                .replacingOccurrences(of: ":", with: "_")
        }
        var ext = mimeExtensions.first { $0.mime == mime }?.ext
        if ext == nil, var f = blankToNil(format)?.lowercased() {
            if f.hasPrefix(".") { f.removeFirst() }
            if (1...5).contains(f.count), f.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) {
                ext = canonicalExtension(f)
            }
        }
        guard let ext else { return base }
        let lower = base.lowercased()
        if lower.hasSuffix("." + ext) { return base }
        if extensionAliases.contains(where: { $0.ext == ext && lower.hasSuffix("." + $0.alias) }) { return base }
        return base + "." + ext
    }

    private static let mimeTopTypes: Set<String> = ["text", "image", "audio", "video", "application", "font", "model"]

    private static func isMime(_ s: String) -> Bool {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, mimeTopTypes.contains(String(parts[0])), !parts[1].isEmpty else { return false }
        return parts[1].allSatisfy { c in
            c.isASCII && (c.isLowercase || c.isNumber || ".+*-".contains(c))
        }
    }

    private static func canonicalExtension(_ ext: String) -> String {
        extensionAliases.first { $0.alias == ext }?.ext ?? ext
    }

    /// Ordered union of non-blank, trimmed entries; nil when empty.
    private static func union(_ first: [String]?, _ second: [String]?) -> [String]? {
        var seen = Set<String>()
        var out: [String] = []
        for s in (first ?? []) + (second ?? []) {
            guard let t = blankToNil(s), seen.insert(t).inserted else { continue }
            out.append(t)
        }
        return out.isEmpty ? nil : out
    }

    private static func blankToNil(_ s: String?) -> String? {
        guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else { return nil }
        return t
    }

    // MARK: - the reverse: a work draft from a HAT

    /// The fields of a work prefilled from a HAT the user holds — what a
    /// "Publish…" action opens the composer with. A draft, not a carve:
    /// the user reviews it, and authors, lang, cover and type are theirs
    /// to add. Mirror of `Hat.toWorkDraft()` in FC-JDK and FC-AJDK.
    public struct WorkDraft: Equatable, Sendable {
        /// Which protocol fits the data; nil when its type fits none.
        public var kind: WorkKind?
        public var did: String
        public var title: String?
        public var format: String?
        public var summary: String?
        /// Where a reader can fetch the plaintext. Never `local://`.
        public var locas: [String]?
    }

    /// The most locations a carve lists (FEIP21–25).
    public static let maxWorkLocas = 3

    /// Prefill a work from this HAT.
    ///
    /// - `title`: the name without its extension.
    /// - `format`: the first type if it is a concrete MIME type (not
    ///   `application/octet-stream`), else the MIME of the name's
    ///   extension.
    /// - `kind`: from the format, else from the first type even if it is
    ///   a wildcard such as `image/*`.
    /// - `locas`: DISK (`(sid)`, `fudp://`) and `https://` entries, at
    ///   most three. None at all when the HAT carries a plaintext `key`:
    ///   it came over IM, and its DISK entries hold the *encrypted* copy.
    ///
    /// - throws: ``WorkError/cipherHat`` for a cipher HAT,
    ///   ``WorkError/badDid(_:)`` when the id is not a content DID.
    public func toWorkDraft() throws -> WorkDraft {
        if rawDid != nil { throw WorkError.cipherHat }
        let did = (id ?? "").lowercased()
        guard did.count == 64, did.allSatisfy({ $0.isHexDigit && $0.isASCII }) else {
            throw WorkError.badDid(id)
        }
        let name = Self.blankToNil(self.name)
        let format = Self.draftFormat(types: types, name: name)
        return WorkDraft(
            kind: Self.workKind(mime: format ?? Self.blankToNil(types?.first)),
            did: did,
            title: name.map(Self.stripExtension),
            format: format,
            summary: Self.blankToNil(desc),
            locas: key == nil ? Self.publishableLocas(locas) : nil
        )
    }

    /// The protocol a MIME type belongs to.
    public static func workKind(mime: String?) -> WorkKind? {
        guard let m = mime?.lowercased() else { return nil }
        if m.hasPrefix("text/") || textDocumentMimes.contains(m) { return .text }
        if m.hasPrefix("image/") { return .image }
        if m.hasPrefix("audio/") { return .sound }
        if m.hasPrefix("video/") { return .video }
        return nil
    }

    static let textDocumentMimes: Set<String> = [
        "application/pdf", "application/epub+zip", "application/rtf", "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.oasis.opendocument.text",
    ]

    static func draftFormat(types: [String]?, name: String?) -> String? {
        if let t = blankToNil(types?.first)?.lowercased(), isMime(t), !t.contains("*"),
           t != "application/octet-stream" {
            return t
        }
        guard let name, let dot = name.lastIndex(of: "."), dot != name.startIndex else { return nil }
        let ext = canonicalExtension(String(name[name.index(after: dot)...]).lowercased())
        return mimeExtensions.first { $0.ext == ext }?.mime
    }

    /// `name.ext` → `name`, for an extension of 1–5 letters or digits.
    static func stripExtension(_ name: String) -> String {
        guard let dot = name.lastIndex(of: "."), dot != name.startIndex else { return name }
        let ext = name[name.index(after: dot)...]
        guard (1...5).contains(ext.count), ext.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else {
            return name
        }
        return String(name[..<dot])
    }

    /// The entries of `locas` a reader elsewhere can use, in order, at
    /// most ``maxWorkLocas``: DISK by SID or FUDP address (not the
    /// `fudp://unknown` placeholder) and `https://` mirrors.
    public static func publishableLocas(_ locas: [String]?) -> [String]? {
        let kept = (union(nil, locas) ?? []).filter { loca in
            let l = loca.lowercased()
            if l == fudpLocationPrefix + "unknown" { return false }
            return loca.hasPrefix(sidLocationPrefix) || l.hasPrefix(fudpLocationPrefix) || l.hasPrefix("https://")
        }
        let capped = Array(kept.prefix(maxWorkLocas))
        return capped.isEmpty ? nil : capped
    }
}
