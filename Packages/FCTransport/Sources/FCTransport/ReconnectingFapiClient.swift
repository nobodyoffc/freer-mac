import Foundation

/// A ``FapiCalling`` that owns its transport and rebuilds it when the
/// old one dies.
///
/// **Why this exists.** A ``FudpClient`` is bound to one UDP socket, one
/// connection id, one session epoch and — invisibly — one NAT mapping on
/// the path to the server. Every one of those is invalidated when the
/// machine sleeps, joins a different network, or simply sits idle long
/// enough for the NAT mapping to be reaped. The socket rarely reports
/// this: sends still "succeed", replies just never come back, and every
/// call fails with a timeout until the app is relaunched.
///
/// The fix is not to keep a connection alive across those events — it
/// cannot be kept alive — but to notice and build a new one. This class
/// is the single seam where that happens, so every service holding an
/// `any FapiCalling` (they all cache one) heals without knowing the
/// transport was ever replaced.
///
/// **Rebuild policy.** Lazily, at the moment of use: a call checks the
/// transport first and reconnects if it is dead or has been marked
/// stale. Reconnecting when the user actually does something is more
/// reliable than reconnecting on the wake notification itself, which
/// fires *before* Wi-Fi has reassociated.
///
/// A call that fails mid-flight is **not** retried. By then the request
/// may already be on the wire, and re-sending a `dock.put` or a carve
/// would double-execute it. Such a call surfaces its error, marks the
/// transport for rebuild, and the next call comes up on a fresh socket.
public final class ReconnectingFapiClient: FapiCalling, @unchecked Sendable {

    /// Builds a fresh, connected transport. Called on every reconnect,
    /// so it must be safe to invoke repeatedly.
    public typealias Factory = @Sendable () async throws -> FudpClient

    public enum Failure: Error, CustomStringConvertible {
        case closed

        public var description: String {
            switch self {
            case .closed: return "ReconnectingFapiClient: client is closed"
            }
        }
    }

    private let shared = SharedFlags()
    private let box: TransportBox

    /// - parameters:
    ///   - initial: an already-connected client to use until it dies.
    ///     Pass the one built during setup so the first call doesn't
    ///     pay for a second connect.
    public init(factory: @escaping Factory, initial: FudpClient? = nil) {
        self.box = TransportBox(factory: factory, initial: initial, shared: shared)
    }

    /// Force the next call to reconnect, even if the socket still looks
    /// healthy. Wake-from-sleep and network changes go through here:
    /// the OS often keeps a UDP socket nominally "ready" across them
    /// while the flow it belongs to is already dead on the far side.
    ///
    /// Takes effect synchronously: a wake notification must not lose a
    /// race with the call it is meant to affect.
    public func markStale() {
        shared.markStale()
    }

    /// Close the current transport and refuse further calls. The
    /// refusal is immediate; releasing the socket hops through the
    /// actor.
    public func close() {
        shared.close()
        Task { await box.close() }
    }

    /// The live transport, if one is currently up. For diagnostics —
    /// callers should not hold onto it.
    public var currentTransport: FudpClient? {
        get async { await box.currentIfAny() }
    }

    // MARK: - FapiCalling

    public func call(
        api: String,
        params: Data?,
        fcdsl: Data?,
        binary: Data?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        timeoutMs: Int
    ) async throws -> FapiClient.Reply {
        try await withClient {
            try await $0.call(
                api: api, params: params, fcdsl: fcdsl, binary: binary,
                sid: sid, via: via, maxCost: maxCost, timeoutMs: timeoutMs
            )
        }
    }

    public func callWithHashedBinary(
        api: String,
        params: Data?,
        binary: Data,
        dataHash: String?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        timeoutMs: Int
    ) async throws -> FapiClient.Reply {
        try await withClient {
            try await $0.callWithHashedBinary(
                api: api, params: params, binary: binary, dataHash: dataHash,
                sid: sid, via: via, maxCost: maxCost, timeoutMs: timeoutMs
            )
        }
    }

    public func callUploadingFile(
        api: String,
        params: Data?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        fileURL: URL,
        idleTimeoutMs: Int64,
        progress: (@Sendable (Int64, Int64) -> Void)?
    ) async throws -> FapiClient.Reply {
        try await withClient {
            try await $0.callUploadingFile(
                api: api, params: params, sid: sid, via: via, maxCost: maxCost,
                fileURL: fileURL, idleTimeoutMs: idleTimeoutMs, progress: progress
            )
        }
    }

    public func callDownloadingToFile(
        api: String,
        params: Data?,
        fcdsl: Data?,
        sid: String?,
        via: String?,
        maxCost: Int64?,
        outputURL: URL,
        idleTimeoutMs: Int64,
        progress: (@Sendable (Int64) -> Void)?
    ) async throws -> FapiClient.Reply {
        try await withClient {
            try await $0.callDownloadingToFile(
                api: api, params: params, fcdsl: fcdsl, sid: sid, via: via,
                maxCost: maxCost, outputURL: outputURL,
                idleTimeoutMs: idleTimeoutMs, progress: progress
            )
        }
    }

    // MARK: - private

    /// Resolve a live transport, run `body` on a `FapiClient` wrapping
    /// it, and mark the transport for rebuild if it died in the attempt.
    /// `FapiClient` holds no state beyond its `fudp`, so making one per
    /// call is free.
    private func withClient<T>(
        _ body: (FapiClient) async throws -> T
    ) async throws -> T {
        let fudp = try await box.client()
        do {
            return try await body(FapiClient(fudp: fudp))
        } catch {
            if !fudp.isAlive {
                shared.markStale()
            }
            throw error
        }
    }
}

/// State that has to be readable and writable *without* awaiting the
/// actor: `markStale()` and `close()` are called from notification
/// handlers and UI paths that cannot suspend, and both must be
/// observed by the very next call.
private final class SharedFlags: @unchecked Sendable {
    private let lock = NSLock()
    private var _generation: UInt64 = 0
    private var _closed = false

    /// Bumped on every stale mark. A transport built at an older
    /// generation is by definition out of date.
    var generation: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return _generation
    }

    var isClosed: Bool {
        lock.lock(); defer { lock.unlock() }
        return _closed
    }

    func markStale() {
        lock.lock(); _generation &+= 1; lock.unlock()
    }

    func close() {
        lock.lock(); _closed = true; lock.unlock()
    }
}

/// Serializes reconnects so that N concurrent callers finding a dead
/// transport produce one new socket, not N.
private actor TransportBox {

    private let factory: ReconnectingFapiClient.Factory
    private let shared: SharedFlags
    private var current: FudpClient?
    /// Stale-generation the `current` transport was built at.
    private var builtAtGeneration: UInt64
    private var building: Task<FudpClient, Error>?

    init(
        factory: @escaping ReconnectingFapiClient.Factory,
        initial: FudpClient?,
        shared: SharedFlags
    ) {
        self.factory = factory
        self.shared = shared
        self.current = initial
        self.builtAtGeneration = shared.generation
    }

    func currentIfAny() -> FudpClient? {
        guard let current, current.isAlive, builtAtGeneration == shared.generation else {
            return nil
        }
        return current
    }

    func close() {
        building?.cancel()
        building = nil
        current?.close()
        current = nil
    }

    /// The live transport, building a new one if the old one is dead,
    /// stale, or absent.
    func client() async throws -> FudpClient {
        if shared.isClosed { throw ReconnectingFapiClient.Failure.closed }
        if let current = currentIfAny() { return current }

        // A rebuild is already under way — join it rather than opening
        // a second socket.
        if let building { return try await building.value }

        let doomed = current
        current = nil
        // Read the generation *before* building: a stale mark that
        // lands while the socket is being opened has to invalidate it
        // too — the network changed underneath the new one as well.
        let generation = shared.generation
        let task = Task { [factory] in try await factory() }
        building = task
        defer { building = nil }

        do {
            let fresh = try await task.value
            doomed?.close()
            guard !shared.isClosed else {
                fresh.close()
                throw ReconnectingFapiClient.Failure.closed
            }
            current = fresh
            builtAtGeneration = generation
            return fresh
        } catch {
            doomed?.close()
            throw error
        }
    }
}
