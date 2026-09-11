import Foundation
import Observation

/// Where ``NobodyRegistry`` keeps what must survive a relaunch.
public protocol NobodyStore: Sendable {
    func loadNobodies() -> Set<String>
    func saveNobodies(_ fids: Set<String>)
    func loadAlerted() -> Set<String>
    func saveAlerted(_ fids: Set<String>)
}

/// The one place the app remembers which FIDs are **nobodies**.
///
/// A nobody is a FID whose private key has been published on chain
/// (FEIP4). Anyone can sign as it, open what is sealed to it, spend its
/// cash and rewrite its on-chain record — its CID included. Every avatar,
/// name and confirmation that involves another identity asks this type,
/// so the answer is the same in every pane. See `NOBODY_SPEC.md`.
///
/// **Why it lives in FCCore.** `FCUI` draws the mark and depends on
/// `FCCore` alone; `FCDomain` feeds it from every freer and nobody-index
/// lookup. A fact about keys is the one thing both can reach.
///
/// **A positive is forever, a negative is not.** Publishing a key cannot
/// be undone, so a nobody is persisted and never expires. "Not a nobody"
/// is only true until someone publishes the key, so it lives in memory
/// for ``negativeTtl``. And only a check against the nobody index says
/// "not a nobody": a freer lookup may carry a subset of fields, so a
/// missing flag there proves nothing.
///
/// **Reading never waits.** ``isNobody(_:)`` is a set lookup, safe inside
/// a view body; when read on the main thread it also registers the view
/// for the next change, so a mark appears the moment a lookup lands.
@Observable
public final class NobodyRegistry: @unchecked Sendable {

    /// The well-known board freer. Its key is public by design.
    public static let defaultNobodyFid = "FHG8DW2eHQ5wNAJQnLNKzYUSo2YKt7ffff"

    public static let negativeTtl: TimeInterval = 10 * 60
    public static let failureBackoff: TimeInterval = 60

    public static let shared = NobodyRegistry()

    /// Bumped on the main thread whenever a nobody is newly learned.
    /// Nothing reads the number; reading it is how a view subscribes.
    public private(set) var revision = 0

    @ObservationIgnored private let lock = NSLock()
    @ObservationIgnored private let now: @Sendable () -> Date
    @ObservationIgnored private var store: NobodyStore?
    @ObservationIgnored private var known: Set<String> = [defaultNobodyFid]
    @ObservationIgnored private var notNobodyUntil: [String: Date] = [:]
    @ObservationIgnored private var failedUntil: [String: Date] = [:]
    @ObservationIgnored private var inFlight: Set<String> = []
    @ObservationIgnored private var alerted: Set<String> = []

    public init(store: NobodyStore? = nil, now: @escaping @Sendable () -> Date = { Date() }) {
        self.now = now
        if let store { adopt(store) }
    }

    /// Attach persistence. What was learned before is kept and written out.
    public func install(store: NobodyStore) {
        adopt(store)
    }

    private func adopt(_ store: NobodyStore) {
        let saved = store.loadNobodies()
        let savedAlerts = store.loadAlerted()
        let snapshot: Set<String> = lock.withLock {
            self.store = store
            known.formUnion(saved)
            alerted.formUnion(savedAlerts)
            return known
        }
        if snapshot != saved { store.saveNobodies(snapshot) }
        bumpRevision()
    }

    // MARK: - reading

    public func isNobody(_ fid: String?) -> Bool {
        if Thread.isMainThread { _ = revision }
        guard let fid, !fid.isEmpty else { return false }
        return lock.withLock { known.contains(fid) }
    }

    /// Whether the FID of a hex pubkey is a known nobody.
    public func isNobody(pubkeyHex: String) -> Bool {
        isNobody(Self.fid(ofPubkeyHex: pubkeyHex))
    }

    /// Whether a recent nobody-index check found this FID absent.
    public func isKnownNotNobody(_ fid: String) -> Bool {
        lock.withLock {
            guard !known.contains(fid), let until = notNobodyUntil[fid] else { return false }
            return until > now()
        }
    }

    /// The known nobodies among `fids`, deduplicated, in order.
    public func nobodies(among fids: [String]) -> [String] {
        if Thread.isMainThread { _ = revision }
        return lock.withLock {
            var seen = Set<String>()
            return fids.filter { !$0.isEmpty && seen.insert($0).inserted && known.contains($0) }
        }
    }

    /// FIDs, deduplicated and in order, whose status is neither known nor freshly checked.
    public func unknown(among fids: [String]) -> [String] {
        lock.withLock { unknownLocked(fids) }
    }

    private func unknownLocked(_ fids: [String]) -> [String] {
        let t = now()
        var seen = Set<String>()
        return fids.filter { fid in
            guard !fid.isEmpty, seen.insert(fid).inserted, !known.contains(fid) else { return false }
            if let until = notNobodyUntil[fid], until > t { return false }
            return true
        }
    }

    // MARK: - learning

    public func markNobodies<S: Sequence>(_ fids: S) where S.Element == String {
        var learned = false
        let snapshot: Set<String>? = lock.withLock {
            for fid in fids where !fid.isEmpty {
                notNobodyUntil[fid] = nil
                if known.insert(fid).inserted { learned = true }
            }
            return learned ? known : nil
        }
        guard let snapshot else { return }
        store?.saveNobodies(snapshot)
        bumpRevision()
    }

    public func markNotNobodies<S: Sequence>(_ fids: S) where S.Element == String {
        let until = now().addingTimeInterval(Self.negativeTtl)
        lock.withLock {
            for fid in fids where !fid.isEmpty && !known.contains(fid) {
                notNobodyUntil[fid] = until
                failedUntil[fid] = nil
            }
        }
    }

    /// Check the unknown FIDs against the nobody index.
    ///
    /// - Parameters:
    ///   - retryFailed: also retry FIDs whose last check failed moments
    ///     ago. A confirmation before a risky action wants that; a list
    ///     row does not.
    ///   - check: returns the FIDs the index holds, or nil when the check
    ///     itself failed — a failure is never read as "not a nobody".
    /// - Returns: false only when a needed check failed.
    @discardableResult
    public func resolve(
        _ fids: [String],
        retryFailed: Bool,
        using check: ([String]) async throws -> Set<String>?
    ) async -> Bool {
        let toCheck: [String] = lock.withLock {
            let t = now()
            var picked: [String] = []
            for fid in unknownLocked(fids) {
                if !retryFailed {
                    if let until = failedUntil[fid], until > t { continue }
                    if inFlight.contains(fid) { continue }
                }
                inFlight.insert(fid)
                picked.append(fid)
            }
            return picked
        }
        guard !toCheck.isEmpty else { return true }
        defer { lock.withLock { inFlight.subtract(toCheck) } }

        let found: Set<String>?
        do {
            found = try await check(toCheck)
        } catch {
            found = nil
        }
        guard let found else {
            let until = now().addingTimeInterval(Self.failureBackoff)
            lock.withLock { for fid in toCheck { failedUntil[fid] = until } }
            return false
        }
        markNobodies(toCheck.filter { found.contains($0) })
        markNotNobodies(toCheck.filter { !found.contains($0) })
        return true
    }

    /// Claim the one-time alert that one of the user's own keys is a nobody.
    /// True the first time for a nobody FID, false ever after.
    public func claimOwnKeyAlert(_ fid: String) -> Bool {
        let snapshot: Set<String>? = lock.withLock {
            guard known.contains(fid), alerted.insert(fid).inserted else { return nil }
            return alerted
        }
        guard let snapshot else { return false }
        store?.saveAlerted(snapshot)
        return true
    }

    // MARK: -

    /// The FID a 33-byte compressed pubkey in hex derives to, or nil.
    public static func fid(ofPubkeyHex hex: String) -> String? {
        guard let data = Hex.decodeOrNil(hex), data.count == 33,
              let address = try? FchAddress(publicKey: data)
        else { return nil }
        return address.fid
    }

    private func bumpRevision() {
        if Thread.isMainThread {
            revision &+= 1
        } else {
            DispatchQueue.main.async { self.revision &+= 1 }
        }
    }
}

/// A JSON file beside the configures. Global rather than per vault:
/// whether a key was published is a fact of the chain, not of the user,
/// and it holds only nobodies — identities that are public by definition.
public final class FileNobodyStore: NobodyStore, @unchecked Sendable {

    private struct Contents: Codable {
        var nobodies: [String] = []
        var alerted: [String] = []
    }

    private let url: URL
    private let lock = NSLock()
    private var contents: Contents

    public init(url: URL) {
        self.url = url
        if let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode(Contents.self, from: data) {
            contents = decoded
        } else {
            contents = Contents()
        }
    }

    public func loadNobodies() -> Set<String> { lock.withLock { Set(contents.nobodies) } }
    public func loadAlerted() -> Set<String> { lock.withLock { Set(contents.alerted) } }

    public func saveNobodies(_ fids: Set<String>) {
        write { $0.nobodies = fids.sorted() }
    }

    public func saveAlerted(_ fids: Set<String>) {
        write { $0.alerted = fids.sorted() }
    }

    private func write(_ change: (inout Contents) -> Void) {
        let data: Data? = lock.withLock {
            change(&contents)
            return try? JSONEncoder().encode(contents)
        }
        guard let data else { return }
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: url, options: .atomic)
    }
}

/// An unpersisted store, for tests and previews.
public final class MemoryNobodyStore: NobodyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var nobodies: Set<String> = []
    private var alerted: Set<String> = []

    public init() {}

    public func loadNobodies() -> Set<String> { lock.withLock { nobodies } }
    public func saveNobodies(_ fids: Set<String>) { lock.withLock { nobodies = fids } }
    public func loadAlerted() -> Set<String> { lock.withLock { alerted } }
    public func saveAlerted(_ fids: Set<String>) { lock.withLock { alerted = fids } }
}
