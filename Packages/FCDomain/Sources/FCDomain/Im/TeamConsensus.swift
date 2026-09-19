import Foundation
import FCCore

/// A team's **consensus document** — the bytes behind ``Team/consensusId``
/// — and the four things a client has to be able to do with them: write
/// one, put it where members can read it, read it back, and prove that
/// an id names something real before paying to carve it.
///
/// **The id is a content address, and that is this client family's
/// choice rather than the protocol's.** FEIP18 treats `consensusId` as
/// an opaque string compared for equality; nothing on the chain says
/// what it points at. So the convention has to be enforced here or not
/// at all: `consensusId = sha256x2(documentBytes)`, hex, which doubles
/// as the raw HAT id — the same convention ``PublishBody`` uses for a
/// published work's `did`. A hash cannot lie about what it names, which
/// is what lets a member fetch a document from a server nobody trusts
/// and still know they are reading what the owner carved.
///
/// **Where the bytes live is published in plaintext.** The document goes
/// to the team's own DISK, unencrypted and permanent (`disk.carve`, not
/// `put` — a team outlives a data-life window), and the team's `home`
/// map carries `DISK@No1_NrC7 = "(sid)<sid>"` so *any* peer can resolve
/// the server and fetch it without holding a key or being told anything
/// out of band. That is the whole distribution mechanism, and it is why
/// erasing that one `home` entry strands every member at once.
///
/// **Carving is a payment, and this type is arranged around that.**
/// Every method that could lead to an upload checks whether the work is
/// already done first: ``place(consensusId:onDiskSid:fallbackDiskSid:)``
/// asks the target DISK before it asks anything else, because
/// re-uploading a document that is already there charges the owner for
/// nothing. And ``fetch(consensusId:diskSids:)`` reads this device
/// before it opens a socket, for the same reason in reverse.
public struct TeamConsensus {

    /// Opens a client onto the DISK service named by a SID. Supplied by
    /// the app shell — the only layer that can open connections — so
    /// this type stays testable with nothing under it. Nil in headless
    /// callers, where every DISK step simply reports that it had no
    /// server to ask.
    public typealias DiskResolver = @Sendable (_ sid: String) async -> DiskService?

    public enum Failure: Error, CustomStringConvertible {
        case noId
        case emptyDocument
        /// No DISK was available to ask — distinct from having asked and
        /// come back empty. C4's whole point: an error that names a step
        /// which never ran is worse than no error at all.
        case notHere(consensusId: String)
        case unreachable(consensusId: String, diagnostics: String)
        case noServer(sid: String)
        case notUtf8(consensusId: String)
        case underlying(Error)

        public var description: String {
            switch self {
            case .noId:
                return "TeamConsensus: no consensus id given"
            case .emptyDocument:
                return "TeamConsensus: a consensus document cannot be empty"
            case .notHere(let id):
                return "TeamConsensus: the document \(id.middleElided()) is not on this Mac, and the team publishes no DISK to read it from. Set the team's DISK, or open the file from this device."
            case let .unreachable(id, diagnostics):
                return "TeamConsensus: could not fetch the document \(id.middleElided()) — \(diagnostics)"
            case .noServer(let sid):
                return "TeamConsensus: could not reach the DISK service \(sid.middleElided())"
            case .notUtf8(let id):
                return "TeamConsensus: the bytes at \(id.middleElided()) hash correctly but are not UTF-8 text"
            case .underlying(let e):
                return "TeamConsensus: \(e)"
            }
        }
    }

    /// What ``place(consensusId:onDiskSid:fallbackDiskSid:)`` did.
    ///
    /// Four outcomes rather than a bool, because the owner is owed a
    /// different sentence for each — and because ``unavailable`` is
    /// only worth mentioning at all when there *was* somewhere it could
    /// have come from.
    public enum Placement: Equatable, Sendable {
        /// Already on the target DISK. Nothing was uploaded, nothing paid.
        case alreadyThere
        /// Uploaded from bytes held on this Mac.
        case uploadedFromHere
        /// Pulled from another DISK and pushed to the target — the
        /// team-is-moving case.
        case copiedFrom(diskSid: String)
        /// Not on the target, not on this Mac, and not obtainable.
        /// `hadOtherDisk` is false when the team published no other DISK
        /// to pull from, which is not a loss: there was never a document
        /// there to move.
        case unavailable(hadOtherDisk: Bool)
    }

    public let files: FileVault
    public let hats: HatsStore
    public let diskBySid: DiskResolver?

    public init(files: FileVault, hats: HatsStore, diskBySid: DiskResolver? = nil) {
        self.files = files
        self.hats = hats
        self.diskBySid = diskBySid
    }

    // MARK: - the team's DISK

    /// The DISK service id a team publishes, or nil when it publishes
    /// none. Accepts the bare and `(sid)`-prefixed forms alike, because
    /// both are legal home values and only one of them is what this
    /// client writes.
    public static func diskSid(of team: Team?) -> String? {
        guard let value = team?.home?[ServiceName.disk] else { return nil }
        return HomeServiceResolver.extractSid(value)
    }

    // MARK: - writing a document

    /// The id a document *would* have, without storing anything — so a
    /// form can show what it is about to carve, and so a caller can
    /// notice that re-saving unchanged text needs no upload at all.
    public static func id(for text: String) -> String {
        Hex.encode(Hash.doubleSha256(Data(text.utf8)))
    }

    /// Write text into this Mac's data store as a content-addressed
    /// document and return its id. **Local only** — nothing is uploaded
    /// and nothing is paid, which is what lets an owner draft, reread
    /// and rewrite before deciding to publish.
    @discardableResult
    public func storeText(_ text: String, name: String? = nil) throws -> String {
        guard !text.isEmpty else { throw Failure.emptyDocument }
        let data = Data(text.utf8)
        let id = Hex.encode(Hash.doubleSha256(data))
        let url = files.defaultLocalURL(did: id)
        do {
            try FileManager.default.createDirectory(
                at: files.dataDirectory, withIntermediateDirectories: true
            )
            if !FileManager.default.fileExists(atPath: url.path) {
                try data.write(to: url, options: .atomic)
            }
            _ = try files.registerFile(
                at: url,
                name: name ?? "consensus-\(String(id.prefix(8))).txt",
                desc: "Team consensus document",
                types: ["text/plain"]
            )
        } catch {
            throw Failure.underlying(error)
        }
        return id
    }

    /// Register a document the user picked from disk. **The original is
    /// referenced, not copied** — the Phase 8.4 decision ``FileVault``
    /// already makes for every other import.
    @discardableResult
    public func importFile(at url: URL) throws -> String {
        let hat: Hat
        do {
            hat = try files.registerFile(
                at: url, desc: "Team consensus document", types: ["text/plain"]
            )
        } catch {
            throw Failure.underlying(error)
        }
        guard let id = hat.id, !id.isEmpty else { throw Failure.emptyDocument }
        return id
    }

    /// Usable local bytes for a document, or nil. Never writes, never
    /// deletes — a caller asking "do I already have this" must not be
    /// able to lose it by asking.
    public func localURL(consensusId: String) -> URL? {
        guard !consensusId.isEmpty,
              (try? hats.exists(id: consensusId)) == true,
              let resolution = try? files.resolve(hatId: consensusId),
              case .available(let url) = resolution
        else { return nil }
        return url
    }

    // MARK: - placing it on a DISK

    /// Whether a document is on **this particular** DISK.
    ///
    /// Asks that one server and no other. A copy sitting on some DISK
    /// this Mac happens to know about is no use to a member, who can
    /// only resolve the SID published in the team's `home` — so a check
    /// that accepted any location would report a document reachable
    /// that nobody else can reach.
    public func isOn(consensusId: String, diskSid: String) async -> Bool {
        guard !consensusId.isEmpty, !diskSid.isEmpty else { return false }
        guard let diskBySid, let disk = await diskBySid(diskSid) else { return false }
        return await Self.holds(consensusId, disk)
    }

    /// Does this DISK hold these bytes?
    ///
    /// **Not there and could not ask are deliberately the same answer**,
    /// and it is the cautious one. Both mean this client cannot show
    /// that a member would be able to fetch the document, and the only
    /// safe reading of that is "no" — a presence check that guessed
    /// "yes" from a timeout would wave through an id with nothing behind
    /// it, which is precisely what carving one is not allowed to do.
    ///
    /// `try?` flattens here (SE-0230), so the failed call and the
    /// server's own "not here" arrive as the same nil. That is why this
    /// is one function rather than two branches at each call site.
    private static func holds(_ did: String, _ disk: DiskService) async -> Bool {
        (try? await disk.check(did: did)) != nil
    }

    /// Make sure the document is on `onDiskSid`, wherever it lives now.
    ///
    /// **The order is the point, and it is cheapest-first for a reason
    /// that is not performance.** Carving is a payment:
    ///
    /// 1. **Already on the target** — ask before doing anything. This is
    ///    the ordinary case on an update that does not move the DISK,
    ///    and skipping the check would re-upload, and re-charge, every
    ///    single time the owner edited the team's name.
    /// 2. **Local bytes** — the owner just wrote or picked the document,
    ///    so it is right here.
    /// 3. **Pulled from `fallbackDiskSid`** — the team is moving, and
    ///    members who have not re-signed still need to read what they
    ///    originally agreed to. Downloaded, verified against the id, and
    ///    pushed across.
    ///
    /// **A blank or identical fallback is a plain "not found".** A team
    /// whose `home` carries no DISK — the state a partial-`home` update
    /// leaves it in — has nowhere to be pulled from, and telling its
    /// owner the old document could not be moved would be describing a
    /// loss that never happened. ``Placement/unavailable(hadOtherDisk:)``
    /// carries that distinction so the caller can stay quiet about it.
    public func place(
        consensusId: String,
        onDiskSid: String,
        fallbackDiskSid: String?,
        progress: (@Sendable (Int64, Int64) -> Void)? = nil
    ) async throws -> Placement {
        guard !consensusId.isEmpty else { throw Failure.noId }
        guard !onDiskSid.isEmpty else { throw Failure.noServer(sid: onDiskSid) }
        guard let diskBySid else { return .unavailable(hadOtherDisk: false) }
        guard let target = await diskBySid(onDiskSid) else { throw Failure.noServer(sid: onDiskSid) }

        // 1. Already there. Never short-circuit on "the source and the
        //    target are the same server" instead of this — that is an
        //    assumption about a document nobody has looked for, and it
        //    is exactly how an id with no bytes behind it gets carved.
        if await Self.holds(consensusId, target) { return .alreadyThere }

        // 2. Bytes on this Mac.
        if let local = localURL(consensusId: consensusId) {
            do {
                try await target.carve(fileURL: local, progress: progress)
            } catch {
                throw Failure.underlying(error)
            }
            note(location: onDiskSid, on: consensusId)
            return .uploadedFromHere
        }

        // 3. Pull from the DISK the team is leaving.
        let fallback = fallbackDiskSid?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !fallback.isEmpty, fallback != onDiskSid else {
            return .unavailable(hadOtherDisk: false)
        }
        guard let source = await diskBySid(fallback) else {
            return .unavailable(hadOtherDisk: true)
        }

        let staging = Self.temporaryURL()
        defer { try? FileManager.default.removeItem(at: staging) }
        do {
            try await source.get(did: consensusId, to: staging)
        } catch {
            return .unavailable(hadOtherDisk: true)
        }
        guard (try? Hex.encode(Hash.doubleSha256(fileAt: staging))) == consensusId else {
            return .unavailable(hadOtherDisk: true)
        }
        do {
            try await target.carve(fileURL: staging, progress: progress)
        } catch {
            throw Failure.underlying(error)
        }
        // Keep what we just paid to move, so the next read is free.
        adopt(consensusId: consensusId, from: staging)
        note(location: onDiskSid, on: consensusId)
        return .copiedFrom(diskSid: fallback)
    }

    // MARK: - reading it back

    /// Fetch a document's bytes: **this Mac first, then each candidate
    /// DISK in turn.**
    ///
    /// The candidate list is plural because a team mid-move has its
    /// document on one side or the other, and the reader has no way of
    /// knowing which. On an update form that means both the team's
    /// current DISK *and* whatever is typed into the box; elsewhere it
    /// is just the team's.
    ///
    /// Every download is hashed and refused unless it matches the id, so
    /// a DISK serving the wrong bytes is caught rather than believed —
    /// and a temp file that failed that check is deleted. **The local
    /// store's own file is never deleted**: it is the copy the user
    /// keeps, not a download this call owns.
    public func fetch(
        consensusId: String,
        diskSids: [String],
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws -> URL {
        guard !consensusId.isEmpty else { throw Failure.noId }

        if let local = localURL(consensusId: consensusId) { return local }

        // Deduplicated in order: the team's DISK and the one typed into
        // a form are usually the same, and asking twice is a round trip
        // spent to learn nothing.
        var seen: Set<String> = []
        let candidates = diskSids
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .compactMap { HomeServiceResolver.extractSid($0) ?? ($0.isEmpty ? nil : $0) }
            .filter { seen.insert($0).inserted }

        guard !candidates.isEmpty, diskBySid != nil else {
            throw Failure.notHere(consensusId: consensusId)
        }

        var diagnostics: [String] = []
        for sid in candidates {
            guard let disk = await diskBySid?(sid) else {
                diagnostics.append("\(sid.middleElided())=unreachable")
                continue
            }
            let staging = Self.temporaryURL()
            do {
                try await disk.get(did: consensusId, to: staging, progress: progress)
            } catch {
                try? FileManager.default.removeItem(at: staging)
                diagnostics.append("\(sid.middleElided())=\(Self.short(error))")
                continue
            }
            let got = try? Hex.encode(Hash.doubleSha256(fileAt: staging))
            guard got == consensusId else {
                try? FileManager.default.removeItem(at: staging)
                diagnostics.append("\(sid.middleElided())=served \(String(got?.prefix(12) ?? "nothing"))…")
                continue
            }
            if let adopted = adopt(consensusId: consensusId, from: staging) { return adopted }
            return staging
        }
        throw Failure.unreachable(
            consensusId: consensusId, diagnostics: diagnostics.joined(separator: "; ")
        )
    }

    /// A consensus document as it came back: the verified bytes, and
    /// the prose if prose is what they are.
    ///
    /// **``text`` being nil is an answer, not a failure.** FEIP18 says
    /// nothing at all about what a `consensusId` points at; that it is
    /// the hash of the document is this client family's convention, and
    /// even that convention says nothing about the document being
    /// written rather than typeset. Owners on other clients carve PDFs
    /// and word-processor files. A reader that could only report an
    /// encoding error would be withholding a document it has already
    /// fetched, verified against the id, and stored — which is every
    /// part of the job except the last one.
    public struct Document: Sendable {
        /// This device's copy of the verified bytes. Named by the id,
        /// so it carries no file extension.
        public let url: URL
        public let byteCount: Int64
        /// The document as prose, or nil when the bytes are not text.
        public let text: String?
        /// What the bytes look like, from the first few of them. Nil
        /// when nothing recognises them — also an answer.
        public let kind: FileKind?
    }

    /// A guess at what a document that is not prose actually is.
    ///
    /// Enough to name it on screen and to propose a filename the Finder
    /// will hand to the right app. It is never used to decide whether
    /// bytes are acceptable: the hash already did that, and a document
    /// this client cannot name is still the document the team carved.
    public struct FileKind: Sendable, Equatable {
        /// A noun phrase with its article — "a PDF" — because every
        /// sentence this appears in is of the form "the document is …".
        public let label: String
        public let fileExtension: String

        public init(label: String, fileExtension: String) {
            self.label = label
            self.fileExtension = fileExtension
        }
    }

    /// Fetch the document and say what it is —
    /// ``fetch(consensusId:diskSids:progress:)`` plus a decode that is
    /// allowed to come back empty-handed.
    ///
    /// The decode is deliberately outside the retry: bytes that arrived
    /// and hashed correctly are a final answer, and asking a second
    /// server for the same id can only return the same bytes.
    public func read(
        consensusId: String,
        diskSids: [String],
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws -> Document {
        let url = try await fetch(consensusId: consensusId, diskSids: diskSids, progress: progress)
        guard let data = try? Data(contentsOf: url) else {
            throw Failure.unreachable(consensusId: consensusId, diagnostics: "local read failed")
        }
        return Document(
            url: url,
            byteCount: Int64(data.count),
            text: Self.decodeText(data),
            kind: Self.sniff(data)
        )
    }

    /// The document as text, or ``Failure/notUtf8(consensusId:)``.
    ///
    /// For callers that have nothing to offer but prose. Anything with
    /// a user in front of it should call ``read(consensusId:diskSids:progress:)``
    /// instead and hand over the file.
    public func readText(
        consensusId: String,
        diskSids: [String],
        progress: (@Sendable (Int64) -> Void)? = nil
    ) async throws -> String {
        let document = try await read(
            consensusId: consensusId, diskSids: diskSids, progress: progress
        )
        guard let text = document.text else {
            throw Failure.notUtf8(consensusId: consensusId)
        }
        return text
    }

    /// The bytes as prose, or nil when they are not prose.
    ///
    /// UTF-8, or UTF-16 when a byte-order mark says so outright. **No
    /// further guessing**, and that restraint is the point: the legacy
    /// encodings decode almost any byte sequence into *something*, so a
    /// decoder that kept trying would turn a PDF into a page of
    /// mojibake and present it as the team's consensus. Better to say
    /// the document is not text and hand over the file.
    public static func decodeText(_ data: Data) -> String? {
        if data.starts(with: [0xFF, 0xFE]) || data.starts(with: [0xFE, 0xFF]) {
            return String(data: data, encoding: .utf16)
        }
        return String(data: data, encoding: .utf8)
    }

    /// What a document looks like, from its leading bytes.
    public static func sniff(_ data: Data) -> FileKind? {
        if data.starts(with: Array("%PDF".utf8)) {
            return FileKind(label: "a PDF", fileExtension: "pdf")
        }
        // The OLE2 compound-file header, which is every pre-2007 Office
        // document. Which one it is lives inside the container, and
        // .doc is the only one anybody carves as a consensus.
        if data.starts(with: [0xD0, 0xCF, 0x11, 0xE0]) {
            return FileKind(label: "an older Word document", fileExtension: "doc")
        }
        if data.starts(with: Array("{\\rtf".utf8)) {
            return FileKind(label: "an RTF document", fileExtension: "rtf")
        }
        if data.starts(with: [0x89, 0x50, 0x4E, 0x47]) {
            return FileKind(label: "a PNG image", fileExtension: "png")
        }
        if data.starts(with: [0xFF, 0xD8, 0xFF]) {
            return FileKind(label: "a JPEG image", fileExtension: "jpg")
        }
        if data.starts(with: Array("GIF8".utf8)) {
            return FileKind(label: "a GIF image", fileExtension: "gif")
        }
        if data.starts(with: [0x50, 0x4B, 0x03, 0x04]) {
            return zipKind(data)
        }
        return nil
    }

    /// Which flavour of zip. The modern office formats are all zips,
    /// and they are told apart by the directory names inside — read out
    /// of the first few kilobytes rather than by unpacking, because
    /// this is a label on a screen and not a parse.
    private static func zipKind(_ data: Data) -> FileKind {
        let head = data.prefix(4096)
        func names(_ needle: String) -> Bool {
            head.range(of: Data(needle.utf8)) != nil
        }
        if names("word/") { return FileKind(label: "a Word document", fileExtension: "docx") }
        if names("xl/") { return FileKind(label: "an Excel workbook", fileExtension: "xlsx") }
        if names("ppt/") { return FileKind(label: "a PowerPoint deck", fileExtension: "pptx") }
        if names("opendocument.text") {
            return FileKind(label: "an OpenDocument text document", fileExtension: "odt")
        }
        return FileKind(label: "a zip archive", fileExtension: "zip")
    }

    // MARK: - internals

    private static func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("consensus-\(UUID().uuidString)")
    }

    /// Move verified bytes into the data store and register them, so the
    /// next read costs a `stat` rather than a round trip. Best effort:
    /// failing to keep a copy is not a reason to fail a fetch that
    /// already succeeded.
    @discardableResult
    private func adopt(consensusId: String, from staging: URL) -> URL? {
        let destination = files.defaultLocalURL(did: consensusId)
        do {
            try FileManager.default.createDirectory(
                at: files.dataDirectory, withIntermediateDirectories: true
            )
            // Content-addressed storage: a file named by its own hash
            // that does not hash to it is corrupt, not a version of
            // anything, so it is replaced rather than preserved.
            if FileManager.default.fileExists(atPath: destination.path),
               (try? Hex.encode(Hash.doubleSha256(fileAt: destination))) != consensusId {
                try FileManager.default.removeItem(at: destination)
            }
            if !FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.copyItem(at: staging, to: destination)
            }
            if try hats.hat(id: consensusId) == nil {
                let now = Hat.currentTimeMillis()
                _ = try hats.upsert(Hat(
                    born: now, last: now,
                    name: "consensus-\(String(consensusId.prefix(8))).txt",
                    desc: "Team consensus document",
                    types: ["text/plain"],
                    state: .active,
                    id: consensusId
                ))
            }
            _ = try files.adoptAppCopy(hatId: consensusId, at: destination)
            return destination
        } catch {
            return nil
        }
    }

    /// Remember that a DISK holds this document, so a later read tries
    /// it. Best effort, for the same reason as ``adopt(consensusId:from:)``.
    private func note(location diskSid: String, on consensusId: String) {
        guard (try? hats.exists(id: consensusId)) == true else { return }
        _ = try? hats.addLoca(HatSyncService.sidLocationPrefix + diskSid, toId: consensusId)
    }

    private static func short(_ error: Error) -> String {
        let text = "\(error)"
        return text.count > 100 ? String(text.prefix(100)) + "…" : text
    }

    // MARK: - the template

    /// A starting point for a team's consensus, offered when one is
    /// created.
    ///
    /// **Most of a consensus asks the same questions every time** — who
    /// decides, who may join, what ends a membership — and an owner
    /// handed a blank box writes nothing, or writes one sentence. A
    /// template is not the document; it is the set of questions, and the
    /// owner is expected to answer them and delete what does not apply.
    ///
    /// Kept as a Swift multi-line literal, where the newlines are the
    /// bytes: nothing in this toolchain rewrites string literals, so
    /// what is written here is what gets hashed. (Android's build did
    /// collapse them, which flattened the same template into one
    /// paragraph without anybody noticing until it was carved.)
    public static let template = """
        # Consensus of <team name>

        This document is what every member of this team agrees to by
        joining. It is stored by its own hash, so the id carved on chain
        can only ever name this exact text — change a word and it becomes
        a different document, which every member is then asked to sign
        again.

        ## What this team is for

        <One or two sentences. What is this team, and what is it not?>

        ## Who may join

        <Anyone invited? Only people who meet some condition? Say who
        decides, and on what.>

        ## How decisions are made

        <Who decides what, and how disagreements end. If the owner simply
        decides, say so — an honest short answer is worth more than a
        procedure nobody follows.>

        ## What is expected of members

        <What members do, contribute, or refrain from.>

        ## How a membership ends

        <Leaving, dismissal, and what happens to anything held in common.
        Note that leaving and dismissal are both transactions on chain,
        and that neither takes back what a former member could already
        read.>

        ## Changing this document

        <The owner can carve a new consensus at any time. Every member is
        then listed as not having agreed to it until they sign it
        themselves, and may leave instead. Say here whether you will
        consult members first.>
        """
}
