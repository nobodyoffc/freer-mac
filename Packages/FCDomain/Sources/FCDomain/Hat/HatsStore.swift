import Foundation
import FCStorage

/// Per-identity HAT database — the Mac port of Android's `HatManager`
/// (a `LocalEntityManager`: local only, no chain sync, no encryption
/// beyond the store's own row-level AES-GCM).
///
/// Rows are ``HatRecord`` (portable ``Hat`` + local-only ``HatLocal``)
/// keyed by DID. Android's manager keeps every HAT in memory and sorts
/// or filters the whole set per query; the Files pane needs the same
/// query surface (sort by `last`, search across many fields, paginate),
/// so this store loads the namespace once per call rather than per row.
/// That is fine at the scale HATs reach for one identity — a few
/// thousand rows — and keeps the API honest about being a scan.
/// Message history, which is unbounded, will not use this shape.
public struct HatsStore {

    public static let namespace = "hats.v1"

    private let inner: TypedStore<HatRecord>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    // MARK: - single-row access

    /// Insert or replace. Mirrors `HatManager.preprocessEntity`:
    /// derives the id when absent, stamps `born` on first write, and
    /// bumps `last`.
    ///
    /// - parameter touch: pass false to keep the `last` the caller
    ///   supplied — sync and merge paths use it so a row doesn't look
    ///   freshly used. A row that arrives with no `last` at all still
    ///   gets one stamped either way: Android always sets it, and the
    ///   list ordering depends on it.
    @discardableResult
    public func upsert(_ hat: Hat, local: HatLocal? = nil, touch: Bool = true) throws -> HatRecord {
        var wire = hat
        wire.checkIdWithCreate()
        guard let id = wire.id else { return HatRecord(wire: wire) }

        let existing = try inner.get(id)
        let now = Hat.currentTimeMillis()
        if wire.born == nil { wire.born = existing?.wire.born ?? now }
        if touch { wire.last = now } else if wire.last == nil { wire.last = existing?.wire.last ?? now }

        var sidecar = local ?? existing?.local ?? HatLocal()
        sidecar.updatedAt = Date()

        let record = HatRecord(wire: wire, local: sidecar)
        try inner.put(record, key: id)
        return record
    }

    public func record(id: String) throws -> HatRecord? {
        try inner.get(id)
    }

    public func hat(id: String) throws -> Hat? {
        try inner.get(id)?.wire
    }

    public func exists(id: String) throws -> Bool {
        try inner.exists(id)
    }

    @discardableResult
    public func remove(id: String) throws -> Bool {
        guard try inner.exists(id) else { return false }
        try inner.delete(id)
        return true
    }

    public func removeAll(ids: [String]) throws -> Int {
        var removed = 0
        for id in ids where try remove(id: id) { removed += 1 }
        return removed
    }

    public func count() throws -> Int {
        try inner.keys().count
    }

    // MARK: - collections

    /// Every row, cipher HATs included.
    public func allRecords() throws -> [HatRecord] {
        try inner.all().map(\.value)
    }

    /// Every HAT, cipher HATs included.
    public func all() throws -> [Hat] {
        try allRecords().map(\.wire)
    }

    /// The Files pane's data source: raw HATs only (cipher HATs are an
    /// implementation detail of the upload path), newest use first.
    /// Mirrors `getHatsSortedByLastDesc` + `filterOutCipherHats`.
    ///
    /// - parameters:
    ///   - pageSize: rows to return; nil for all.
    ///   - afterId: resume after this id in the sorted order — the
    ///     cursor Android uses for paging.
    public func sortedByLastDesc(pageSize: Int? = nil, afterId: String? = nil) throws -> [Hat] {
        var rows = try all().filter { !$0.isCipherHat }
        rows.sort(by: Self.byLastDescending)
        return Self.page(rows, pageSize: pageSize, afterId: afterId)
    }

    /// Cipher HATs only — the rows `sortedByLastDesc` hides.
    public func cipherHats() throws -> [Hat] {
        try all().filter(\.isCipherHat)
    }

    /// Search across id, name, desc, types, aids, pids, the DID fields
    /// and locas — the field set `HatManager.searchFromList` covers.
    /// Case-insensitive substring match; cipher HATs excluded, as in
    /// `HatManager.searchHats`.
    public func search(_ query: String) throws -> [Hat] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return [] }
        var rows = try all().filter { !$0.isCipherHat && Self.matches($0, needle: needle) }
        rows.sort(by: Self.byLastDescending)
        return rows
    }

    /// HATs in a given state.
    public func byState(_ state: Hat.DataState) throws -> [Hat] {
        try all().filter { $0.state == state }
    }

    /// HATs carrying a location with this prefix — used to find
    /// everything stored on one DISK service (`"(sid)abc"`).
    public func byLocationPrefix(_ prefix: String) throws -> [Hat] {
        guard !prefix.isEmpty else { return [] }
        return try all().filter { hat in
            (hat.locas ?? []).contains { $0.hasPrefix(prefix) }
        }
    }

    /// HATs whose `last` is newer than `timestampMs` — the incremental
    /// backup query.
    public func modifiedSince(_ timestampMs: Int64) throws -> [Hat] {
        try all().filter { ($0.last ?? 0) > timestampMs }
    }

    /// All versions of one lineage, by first-version DID.
    public func bySrcDid(_ srcDid: String) throws -> [Hat] {
        try all().filter { $0.srcDid == srcDid }
    }

    // MARK: - mutation helpers (HatManager parity)

    /// Add a location to a stored HAT. No-op when the id is unknown.
    @discardableResult
    public func addLoca(_ loca: String, toId id: String) throws -> Hat? {
        guard var record = try inner.get(id) else { return nil }
        record.wire.addLoca(loca)
        record.local.updatedAt = Date()
        try inner.put(record, key: id)
        return record.wire
    }

    /// Replace a HAT's locations wholesale.
    @discardableResult
    public func setLocas(_ locas: [String], forId id: String) throws -> Hat? {
        guard var record = try inner.get(id) else { return nil }
        record.wire.locas = locas
        record.wire.last = Hat.currentTimeMillis()
        record.local.updatedAt = Date()
        try inner.put(record, key: id)
        return record.wire
    }

    /// Attach a cipher HAT's DID to its raw HAT. Mirrors
    /// `HatManager.addCipherId`.
    @discardableResult
    public func addCipherId(_ cipherId: String, toRawId rawId: String) throws -> Hat? {
        guard var record = try inner.get(rawId) else { return nil }
        record.wire.addCipherId(cipherId)
        record.local.updatedAt = Date()
        try inner.put(record, key: rawId)
        return record.wire
    }

    /// Create and store the cipher half of the two-HAT model. Mirrors
    /// `HatManager.createCipherHat`.
    @discardableResult
    public func createCipherHat(
        cipherId: String,
        rawDid: String,
        kCipher: String,
        size: Int64,
        locas: [String] = []
    ) throws -> Hat {
        let now = Hat.currentTimeMillis()
        let hat = Hat(
            size: size,
            born: now,
            last: now,
            rawDid: rawDid,
            kCipher: kCipher,
            state: .active,
            locas: locas.isEmpty ? nil : locas,
            id: cipherId
        )
        return try upsert(hat).wire
    }

    /// Merge credentials from a HAT received over IM into the stored
    /// copy: the local row may predate the sender's key/locations, and
    /// its own `local://` paths must survive. Mirrors
    /// `ChatActivity.mergeImHatCredentials`.
    @discardableResult
    public func mergeIncoming(_ incoming: Hat) throws -> Hat? {
        guard let id = incoming.id else { return nil }
        guard var record = try inner.get(id) else {
            return try upsert(incoming).wire
        }
        if record.wire.key == nil, let key = incoming.key { record.wire.key = key }
        if (record.wire.cipherIds ?? []).isEmpty, let ids = incoming.cipherIds {
            record.wire.cipherIds = ids
        }
        for loca in incoming.locas ?? [] {
            record.wire.addLoca(loca)
        }
        record.local.updatedAt = Date()
        try inner.put(record, key: id)
        return record.wire
    }

    // MARK: - sorting / paging / matching

    /// Newest `last` first; rows without a `last` sink to the bottom,
    /// ties broken by id so paging is stable.
    static func byLastDescending(_ a: Hat, _ b: Hat) -> Bool {
        switch (a.last, b.last) {
        case let (x?, y?) where x != y: return x > y
        case (nil, .some): return false
        case (.some, nil): return true
        default: return (a.id ?? "") > (b.id ?? "")
        }
    }

    /// Cursor paging over an already-sorted array. An `afterId` past the
    /// end yields an empty page; an unknown one starts from the top,
    /// matching Android's behaviour when the cursor row was deleted.
    static func page(_ rows: [Hat], pageSize: Int?, afterId: String?) -> [Hat] {
        var slice = rows
        if let afterId, let index = rows.firstIndex(where: { $0.id == afterId }) {
            let start = rows.index(after: index)
            slice = start < rows.endIndex ? Array(rows[start...]) : []
        }
        if let pageSize, slice.count > pageSize {
            slice = Array(slice.prefix(pageSize))
        }
        return slice
    }

    static func matches(_ hat: Hat, needle: String) -> Bool {
        func hit(_ s: String?) -> Bool {
            guard let s else { return false }
            return s.lowercased().contains(needle)
        }
        func hitList(_ list: [String]?) -> Bool {
            guard let list else { return false }
            return list.contains { $0.lowercased().contains(needle) }
        }
        return hit(hat.id) || hit(hat.name) || hit(hat.desc)
            || hitList(hat.types) || hitList(hat.aids) || hitList(hat.pids)
            || hit(hat.srcDid) || hit(hat.preDid) || hit(hat.tDid) || hit(hat.rawDid)
            || hitList(hat.locas)
    }
}
