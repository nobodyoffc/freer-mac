import Foundation
import Darwin
import FCCore

/// An ssh-agent that lives inside this process, holds exactly one
/// derived key, and never writes it anywhere.
///
/// **Why an agent at all.** `ssh` will take a private key from a file
/// or from an agent socket. A file would mean writing the derived key
/// to disk, where it outlives the vault lock and is readable by
/// anything running as the user — which throws away the main reason to
/// derive the key rather than store one. An agent keeps the key in
/// memory for as long as this object is alive and not one moment
/// longer, so ``stop`` is the whole security boundary.
///
/// **What an attacker who reaches the socket gets.** Everything. An
/// agent is a signing oracle by construction: connect to it and it
/// will sign whatever you hand it, which is a login to every server
/// carrying this key in `authorized_keys`. That is true of every
/// ssh-agent ever shipped, and the mitigations are layered
/// accordingly:
///
///   - the socket lives in a 0700 directory under the per-user
///     `$TMPDIR`, so another user cannot reach the path at all;
///   - the socket is 0600 and every accepted connection must pass a
///     `LOCAL_PEERCRED` check for our own uid;
///   - and the one that actually matters — **the agent runs only while
///     a terminal session is open**, not for the app's lifetime. The
///     caller starts it on connect and stops it when the last session
///     ends, and vault lock stops it unconditionally.
///
/// Three details are load-bearing rather than tidy, and each is
/// commented at its call site: `FD_CLOEXEC` (the terminal forks and
/// execs without closing inherited descriptors), `SO_NOSIGPIPE` (the
/// default disposition would take the whole app down when a client
/// hangs up mid-write), and unlinking a stale socket before `bind`.
public final class SshAgentServer: @unchecked Sendable {

    public enum Failure: Error, CustomStringConvertible {
        case pathTooLong(String, limit: Int)
        case directory(String, errno: Int32)
        case socketCall(String, errno: Int32)
        case alreadyStopped

        public var description: String {
            switch self {
            case let .pathTooLong(p, limit):
                return "SshAgentServer: socket path is \(p.utf8.count) bytes, over the \(limit)-byte sun_path limit — \(p)"
            case let .directory(what, e):
                return "SshAgentServer: \(what) failed — \(String(cString: strerror(e))) (\(e))"
            case let .socketCall(what, e):
                return "SshAgentServer: \(what) failed — \(String(cString: strerror(e))) (\(e))"
            case .alreadyStopped:
                return "SshAgentServer: this agent has been stopped and cannot be restarted"
            }
        }
    }

    /// A backstop against a local process opening sockets until we run
    /// out of file descriptors — not a throughput limit. It has to sit
    /// well above any real workload, because `ssh` holds its agent
    /// connection open for the life of the session rather than closing
    /// it after authenticating, so the count tracks *live sessions*,
    /// not requests. A client refused here gets a closed socket and
    /// reports "communication with agent failed", so the number must be
    /// one nobody reaches by using the app normally.
    private static let maxConnections = 64
    /// One authentication is a handful of messages; anything slower is
    /// not a real `ssh`.
    private static let ioTimeoutSeconds = 30

    private let key: SshEd25519Key
    private let comment: String

    /// The 0700 directory holding the socket and the `.pub`. Named
    /// with our pid so two Freer instances cannot collide.
    public let runtimeDirectory: String
    public let socketPath: String
    public let publicKeyPath: String

    private let lock = NSLock()
    private var listenFd: Int32 = -1
    private var acceptSource: DispatchSourceRead?
    private var started = false
    private var stopped = false
    private var liveConnections = 0

    private let acceptQueue = DispatchQueue(label: "fc.freer.ssh.agent.accept")
    private let ioQueue = DispatchQueue(label: "fc.freer.ssh.agent.io", attributes: .concurrent)

    /// - Parameters:
    ///   - key: the identity to serve. Held for this object's lifetime.
    ///   - comment: the `authorized_keys` comment advertised alongside
    ///     the key, conventionally `freer:<mainFid>`.
    public init(key: SshEd25519Key, comment: String) throws {
        self.key = key
        self.comment = comment

        // **Not Application Support.** `sun_path` is 104 bytes on
        // Darwin, and the app's support directory both eats most of
        // that budget and contains a space — which `-o IdentityAgent=`
        // would then have to quote through ssh's config tokenizer.
        // `NSTemporaryDirectory()` is `$TMPDIR`: already per-user,
        // already 0700, already reaped by the OS, and space-free.
        let base = (NSTemporaryDirectory() as NSString).appendingPathComponent("fc.freer.ssh.\(getpid())")
        self.runtimeDirectory = base
        self.socketPath = (base as NSString).appendingPathComponent("agent.sock")
        self.publicKeyPath = (base as NSString).appendingPathComponent("id_ed25519.pub")

        let limit = MemoryLayout.size(ofValue: sockaddr_un().sun_path)
        guard socketPath.utf8.count < limit else {
            throw Failure.pathTooLong(socketPath, limit: limit)
        }
    }

    deinit { stop() }

    public var isRunning: Bool {
        lock.lock(); defer { lock.unlock() }
        return started && !stopped
    }

    // MARK: - Lifecycle

    public func start() throws {
        lock.lock()
        if stopped { lock.unlock(); throw Failure.alreadyStopped }
        if started { lock.unlock(); return }
        lock.unlock()

        try makeRuntimeDirectory()
        try writePublicKeyFile()
        let fd = try makeListeningSocket()

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: acceptQueue)
        source.setEventHandler { [weak self] in self?.acceptOne(on: fd) }
        // Captures the fd and the path by value, never `self`. A strong
        // capture here would be a retain cycle through `acceptSource`,
        // which would make `deinit` unreachable — and `deinit` is the
        // net that cleans up when `start()` throws half-way, or when a
        // caller drops the agent without calling `stop()`.
        let path = socketPath
        source.setCancelHandler {
            close(fd)
            unlink(path)
        }

        lock.lock()
        listenFd = fd
        acceptSource = source
        started = true
        lock.unlock()

        source.resume()
    }

    /// Idempotent, and safe to call from `deinit`.
    public func stop() {
        lock.lock()
        if stopped { lock.unlock(); return }
        stopped = true
        let source = acceptSource
        acceptSource = nil
        listenFd = -1
        lock.unlock()

        // The cancel handler closes the fd and unlinks the socket.
        source?.cancel()

        unlink(publicKeyPath)
        unlink(socketPath)
        rmdir(runtimeDirectory)
    }

    // MARK: - Setup

    private func makeRuntimeDirectory() throws {
        // 0700 is the real boundary: it is what stops another user
        // reaching the socket path, whatever the socket's own mode.
        if mkdir(runtimeDirectory, 0o700) != 0 {
            let e = errno
            guard e == EEXIST else { throw Failure.directory("mkdir(\(runtimeDirectory))", errno: e) }
            // Ours from a previous run in this same pid slot. Force the
            // mode back down and refuse anything we do not own.
            if chmod(runtimeDirectory, 0o700) != 0 {
                throw Failure.directory("chmod(\(runtimeDirectory))", errno: errno)
            }
        }

        var st = stat()
        guard stat(runtimeDirectory, &st) == 0 else {
            throw Failure.directory("stat(\(runtimeDirectory))", errno: errno)
        }
        guard st.st_uid == getuid(), (st.st_mode & 0o077) == 0 else {
            throw Failure.directory("\(runtimeDirectory) is not a private directory owned by this user", errno: EPERM)
        }
    }

    private func writePublicKeyFile() throws {
        let contents = key.publicKeyFileContents(comment: comment)
        try? FileManager.default.removeItem(atPath: publicKeyPath)
        guard FileManager.default.createFile(
            atPath: publicKeyPath,
            contents: Data(contents.utf8),
            attributes: [.posixPermissions: 0o644]
        ) else {
            // `createFile` reports only a Bool, so there is no errno to
            // quote — EIO is a placeholder that keeps the one error
            // shape rather than a claim about the cause.
            throw Failure.directory("write(\(publicKeyPath))", errno: EIO)
        }
    }

    private func makeListeningSocket() throws -> Int32 {
        // A stale entry from a crash would make bind fail with EADDRINUSE
        // even though nothing is listening.
        unlink(socketPath)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.socketCall("socket", errno: errno) }

        // **Required.** SwiftTerm's local process spawn forks and execs
        // without closing inherited descriptors, so without this the
        // `ssh` child would inherit the listening socket itself.
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else {
            let e = errno; close(fd)
            throw Failure.socketCall("fcntl(FD_CLOEXEC)", errno: e)
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let pathBytes = Array(socketPath.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
            raw[pathBytes.count] = 0
        }

        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, size) }
        }
        guard bound == 0 else {
            let e = errno; close(fd)
            throw Failure.socketCall("bind(\(socketPath))", errno: e)
        }

        // After bind, because bind creates the node. The window before
        // this chmod is not exploitable: the parent directory is 0700.
        guard chmod(socketPath, 0o600) == 0 else {
            let e = errno; close(fd); unlink(socketPath)
            throw Failure.socketCall("chmod(\(socketPath))", errno: e)
        }

        guard listen(fd, Int32(Self.maxConnections)) == 0 else {
            let e = errno; close(fd); unlink(socketPath)
            throw Failure.socketCall("listen", errno: e)
        }

        return fd
    }

    // MARK: - Serving

    private func acceptOne(on fd: Int32) {
        let cfd = accept(fd, nil, nil)
        guard cfd >= 0 else { return }

        guard configure(connection: cfd), Self.peerIsSelf(cfd) else {
            close(cfd)
            return
        }

        lock.lock()
        let overloaded = liveConnections >= Self.maxConnections || stopped
        if !overloaded { liveConnections += 1 }
        lock.unlock()

        guard !overloaded else { close(cfd); return }

        ioQueue.async { [weak self] in
            defer {
                close(cfd)
                if let self {
                    self.lock.lock()
                    self.liveConnections -= 1
                    self.lock.unlock()
                }
            }
            self?.serve(cfd)
        }
    }

    private func configure(connection cfd: Int32) -> Bool {
        guard fcntl(cfd, F_SETFD, FD_CLOEXEC) == 0 else { return false }

        // **Without this a client that hangs up mid-write kills the
        // app.** The default SIGPIPE disposition terminates the
        // process; with SO_NOSIGPIPE `send` returns EPIPE instead.
        var on: Int32 = 1
        guard setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            return false
        }

        var tv = timeval(tv_sec: Self.ioTimeoutSeconds, tv_usec: 0)
        let len = socklen_t(MemoryLayout<timeval>.size)
        _ = setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, len)
        _ = setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, len)
        return true
    }

    /// Require the peer to be running as us. Cheap, and it narrows "any
    /// local process" to "any process running as this user" — which is
    /// the same boundary the 0700 directory draws, enforced twice.
    private static func peerIsSelf(_ cfd: Int32) -> Bool {
        var cred = xucred()
        var len = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(cfd, SOL_LOCAL, LOCAL_PEERCRED, &cred, &len) == 0 else { return false }
        guard cred.cr_version == XUCRED_VERSION else { return false }
        return cred.cr_uid == getuid()
    }

    /// One connection: `ssh` sends `REQUEST_IDENTITIES`, then one or
    /// more `SIGN_REQUEST`s, then closes.
    private func serve(_ cfd: Int32) {
        while true {
            guard let header = Self.readExactly(cfd, 4) else { return }
            var reader = SshWire.Reader(header)
            guard let declared = try? reader.readUInt32() else { return }

            let length = Int(declared)
            guard length >= 1, length <= SshAgentProtocol.maxMessageLength else { return }
            guard let body = Self.readExactly(cfd, length) else { return }

            let (response, _) = SshAgentProtocol.respond(to: body, key: key, comment: comment)
            guard Self.writeAll(cfd, response) else { return }
        }
    }

    // MARK: - Blocking I/O helpers
    //
    // Deliberately blocking, on a concurrent queue. One authentication
    // moves a few hundred bytes; DispatchIO would buy nothing and cost
    // a state machine.

    private static func readExactly(_ fd: Int32, _ count: Int) -> Data? {
        var buffer = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = buffer.withUnsafeMutableBytes { raw -> Int in
                recv(fd, raw.baseAddress!.advanced(by: got), count - got, 0)
            }
            if n <= 0 { return nil }
            got += n
        }
        return Data(buffer)
    }

    private static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        let bytes = [UInt8](data)
        var sent = 0
        while sent < bytes.count {
            let n = bytes.withUnsafeBytes { raw -> Int in
                send(fd, raw.baseAddress!.advanced(by: sent), bytes.count - sent, 0)
            }
            if n <= 0 { return false }
            sent += n
        }
        return true
    }
}
