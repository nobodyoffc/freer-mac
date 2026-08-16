import Foundation
import FCTransport

/// Turns a `home` map entry into a URL you can actually call — the port
/// of `FC-AJDK/.../fapi/client/HomeServiceResolver.java`.
///
/// Every entity that can be reached publishes a `home` map: a FID's
/// ``Freer``, a team's, a square's, a room's. The values in it come in
/// **three shapes**, and only one of them is a URL:
///
/// | shape | example | what it takes to use |
/// |---|---|---|
/// | direct URL | `https://dock.example` | nothing |
/// | bare SID | 64 hex chars | a `base.getByIds` lookup |
/// | prefixed SID | `(sid)` + 64 hex | the same lookup |
///
/// The indirection is the point: a SID names a service *record on the
/// chain*, so an operator can move their server and everyone who ever
/// wrote down the SID follows them. A client that only understood
/// direct URLs would work right up until the day a server moved.
///
/// **This is the piece Phase 8.4.5 deferred.** Its note said the
/// `(sid)` bootstrap "stays deferred to the IM phase that first needs a
/// *foreign* DISK" — and IM needs it for every route, because a
/// recipient's DOCK and ROAD are addressed exactly this way.
///
/// A resolved SID is cached, because a service record changes about as
/// often as a server moves and a message send is not the moment to
/// re-litigate it. The cache is per-instance and in memory: it is an
/// optimisation, never a source of truth.
public actor HomeServiceResolver {

    public static let sidPrefix = "(sid)"
    public static let sidHexLength = 64

    /// Mutable, and that is the whole point.
    ///
    /// This resolver is long-lived — it has to be, or its SID cache
    /// would not survive a send — while the client underneath it is
    /// replaced whenever the FAPI server changes, and once at startup
    /// when the stub gives way to the real one. A resolver that captured
    /// the client it was built with would keep asking a connection
    /// nobody else uses, and since a `(sid)` home value is *only*
    /// reachable through a `base.getByIds` lookup, the visible
    /// symptom is oddly specific: peers whose DOCK is written as a URL
    /// work, and peers whose DOCK is written as a SID are unreachable.
    ///
    /// Android sidesteps this by taking the client as a parameter on
    /// every call. Keeping it here instead is what makes the two-line
    /// call sites possible, so the swap has to be explicit.
    private let directoryBox: DirectoryBox
    private var directory: DirectoryService { directoryBox.current }
    private var urlBySid: [String: String] = [:]
    private var serviceBySid: [String: Service] = [:]

    public init(directory: DirectoryService) {
        self.directoryBox = DirectoryBox(directory)
    }

    public init(fapi: any FapiCalling) {
        self.directoryBox = DirectoryBox(DirectoryService(fapi: fapi))
    }

    /// Point future lookups at a new client.
    ///
    /// **Synchronous on purpose.** The obvious spelling — an isolated
    /// method the caller hops onto with a `Task` — makes two swaps
    /// racy: a tear-down to the stub and a bring-up of the real client
    /// are separate tasks with no ordering between them, so the stub
    /// can land last and leave every SID unresolvable again. Taking a
    /// lock instead means the swap has happened by the time the caller's
    /// next line runs.
    ///
    /// The cache is **kept**: a SID resolves to whatever the chain says,
    /// so the answer does not depend on which server was asked, and
    /// throwing it away would cost a round trip per peer to relearn
    /// facts that have not changed.
    public nonisolated func setFapi(_ fapi: any FapiCalling) {
        directoryBox.set(DirectoryService(fapi: fapi))
    }

    // MARK: - shape

    /// Whether a home value is already a URL. `fudp://` counts: a FUDP
    /// endpoint is as much an address as an HTTP one.
    public static func isUrl(_ value: String) -> Bool {
        value.hasPrefix("http://") || value.hasPrefix("https://") || value.hasPrefix("fudp://")
    }

    /// The SID a home value names, or nil if it does not name one.
    /// Accepts the bare and `(sid)`-prefixed forms alike.
    public static func extractSid(_ value: String?) -> String? {
        guard let value else { return nil }
        let candidate = value.hasPrefix(sidPrefix)
            ? String(value.dropFirst(sidPrefix.count))
            : value
        guard candidate.count == sidHexLength,
              candidate.allSatisfy({ $0.isHexDigit })
        else { return nil }
        return candidate
    }

    // MARK: - resolving

    /// Resolve one home value. Returns nil when it is neither a URL nor
    /// a SID we can look up — which is an ordinary outcome, not an
    /// error: a peer may simply not run the service being asked about.
    public func resolve(_ homeValue: String?, timeoutMs: Int = 5_000) async -> String? {
        guard let homeValue, !homeValue.isEmpty else { return nil }
        if Self.isUrl(homeValue) { return homeValue }
        guard let sid = Self.extractSid(homeValue) else {
            SystemLog.shared.warning(
                SystemSource.directory,
                "Home value is neither an address nor a service id",
                detail: homeValue
            )
            return nil
        }
        if let cached = urlBySid[sid] { return cached }

        // Each failure below is a *silent* nil to the caller — "this
        // peer does not run that service" is an ordinary answer, so it
        // must not throw. That makes the log the only place a genuinely
        // broken lookup can be noticed.
        let service: Service?
        do {
            service = try await directory.serviceById(sid, timeoutMs: timeoutMs)
        } catch {
            SystemLog.shared.error(
                SystemSource.directory,
                "Could not look up service \(sid.middleElided())",
                detail: String(describing: error)
            )
            return nil
        }
        guard let service else {
            SystemLog.shared.warning(
                SystemSource.directory,
                "No service record on chain for \(sid.middleElided())"
            )
            return nil
        }
        guard let url = service.apiUrl else {
            SystemLog.shared.warning(
                SystemSource.directory,
                "Service \(sid.middleElided()) publishes no API address",
                detail: service.home.map { "home: \($0)" }
            )
            return nil
        }

        serviceBySid[sid] = service
        urlBySid[sid] = url
        return url
    }

    /// Resolve the service under `key` in an entity's home map.
    public func resolve(
        home: [String: String]?, key: String, timeoutMs: Int = 5_000
    ) async -> String? {
        guard let home, let value = home[key] else { return nil }
        return await resolve(value, timeoutMs: timeoutMs)
    }

    /// The recipient's DOCK — the store-and-forward server their
    /// messages wait at while they are offline.
    public func dockUrl(home: [String: String]?, timeoutMs: Int = 5_000) async -> String? {
        await resolve(home: home, key: ServiceName.dock, timeoutMs: timeoutMs)
    }

    /// The recipient's ROAD — the live relay.
    public func roadUrl(home: [String: String]?, timeoutMs: Int = 5_000) async -> String? {
        await resolve(home: home, key: ServiceName.road, timeoutMs: timeoutMs)
    }

    /// Resolve several home entries at once, collapsing the SID lookups
    /// into **one** `base.getByIds` round trip.
    ///
    /// That collapse is the reason this exists alongside
    /// ``resolve(_:timeoutMs:)``. A send resolves a DOCK and a ROAD
    /// together, and doing them one at a time would double the latency
    /// of every first message to a peer.
    ///
    /// Keys whose value resolves to nothing are omitted rather than
    /// mapped to nil, so a caller can read the result as "what is
    /// reachable".
    public func resolveBatch(
        _ homeValues: [String: String], timeoutMs: Int = 5_000
    ) async -> [String: String] {
        var resolved: [String: String] = [:]
        var sidByKey: [String: String] = [:]
        var toFetch: Set<String> = []

        for (key, value) in homeValues where !value.isEmpty {
            if Self.isUrl(value) {
                resolved[key] = value
                continue
            }
            guard let sid = Self.extractSid(value) else { continue }
            sidByKey[key] = sid
            if let cached = urlBySid[sid] {
                resolved[key] = cached
            } else {
                toFetch.insert(sid)
            }
        }

        if !toFetch.isEmpty,
           let services = try? await directory.serviceByIds(Array(toFetch), timeoutMs: timeoutMs) {
            for (sid, service) in services {
                serviceBySid[sid] = service
                if let url = service.apiUrl { urlBySid[sid] = url }
            }
        }

        for (key, sid) in sidByKey where resolved[key] == nil {
            if let url = urlBySid[sid] { resolved[key] = url }
        }
        return resolved
    }

    // MARK: - cache

    /// A service record we have already fetched, if any.
    public func cachedService(sid: String) -> Service? {
        serviceBySid[sid]
    }

    /// The service record behind a URL we resolved earlier.
    ///
    /// The cache is keyed by SID because that is what a lookup starts
    /// from, but a caller downstream — the courier, say — holds only the
    /// URL it was told to talk to. Comparison is by normalised endpoint
    /// rather than string, so the same server spelled two ways is one
    /// server; see ``FudpUrl``.
    ///
    /// Returns nil for a home value that was a **direct URL**. Such a peer
    /// published an address instead of a service id, so there is no record
    /// to read and no advertised limit to honour — an ordinary answer, not
    /// a failure.
    public func cachedService(url: String) -> Service? {
        let wanted = FudpUrl.normalize(url) ?? url
        for (sid, resolved) in urlBySid where (FudpUrl.normalize(resolved) ?? resolved) == wanted {
            if let service = serviceBySid[sid] { return service }
        }
        return nil
    }

    /// How large an item `url` will accept, in bytes.
    ///
    /// This is the number the FIMP v2 size rule is measured against, and
    /// it is deliberately *resolved* rather than constant. FAPI13's
    /// default is 64 KB, every operator may publish their own, and the
    /// previous port asserted 1 MB in a comment and enforced 900 KB —
    /// fourteen times what the server actually took.
    ///
    /// Falls back to ``ImMessage/assumedDockItemLimit`` when the record is
    /// silent, absent, or was never a record at all. That is the server's
    /// own default, so the fallback errs the same way the server does.
    public func dockItemLimit(url: String) -> Int {
        cachedService(url: url)?.itemSizeLimit ?? ImMessage.assumedDockItemLimit
    }

    /// Forget everything. The cache is an optimisation, so dropping it
    /// costs a round trip and nothing else — which is what makes it
    /// safe to call when a server is misbehaving.
    public func clearCache() {
        urlBySid.removeAll()
        serviceBySid.removeAll()
    }
}

/// Holds the current ``DirectoryService`` so it can be swapped without
/// awaiting the actor — see ``HomeServiceResolver/setFapi(_:)``.
private final class DirectoryBox: @unchecked Sendable {
    private let lock = NSLock()
    private var directory: DirectoryService

    init(_ directory: DirectoryService) {
        self.directory = directory
    }

    var current: DirectoryService {
        lock.lock(); defer { lock.unlock() }
        return directory
    }

    func set(_ directory: DirectoryService) {
        lock.lock(); self.directory = directory; lock.unlock()
    }
}
