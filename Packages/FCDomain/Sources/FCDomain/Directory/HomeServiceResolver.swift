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
/// | bare SID | 64 hex chars | a `base.serviceByIds` lookup |
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

    private let directory: DirectoryService
    private var urlBySid: [String: String] = [:]
    private var serviceBySid: [String: Service] = [:]

    public init(directory: DirectoryService) {
        self.directory = directory
    }

    public init(fapi: any FapiCalling) {
        self.directory = DirectoryService(fapi: fapi)
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
        guard let sid = Self.extractSid(homeValue) else { return nil }
        if let cached = urlBySid[sid] { return cached }

        guard let service = try? await directory.serviceById(sid, timeoutMs: timeoutMs),
              let url = service.apiUrl
        else { return nil }

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
    /// into **one** `base.serviceByIds` round trip.
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

    /// Forget everything. The cache is an optimisation, so dropping it
    /// costs a round trip and nothing else — which is what makes it
    /// safe to call when a server is misbehaving.
    public func clearCache() {
        urlBySid.removeAll()
        serviceBySid.removeAll()
    }
}
