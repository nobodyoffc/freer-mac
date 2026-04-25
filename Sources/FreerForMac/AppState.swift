import Foundation
import Observation
import FCCore
import FCDomain
import FCTransport

/// Top-level UI route. Mutually exclusive screens; navigation happens
/// by reassigning ``AppState/route``. There is intentionally **no
/// "first-launch" state** — showing a different screen when the
/// vault index is empty would leak whether the device has any
/// vaults at all to a shoulder-surfer.
enum AppRoute: Equatable {
    /// Single password field with explicit `Check` and
    /// `Create new` actions. Default entry point at every launch.
    case password

    /// Configure is unlocked; pick which main FID to operate as
    /// (or add a new one).
    case chooseMain

    /// Form to mint a new main FID inside the unlocked Configure
    /// (random / hex / WIF / passphrase).
    case addMain

    /// Fully active session. Show the wallet, contacts, etc.
    case home
}

/// Single source of truth for the app shell. Holds:
///   - the ``ConfigureManager`` (talks to disk)
///   - an optional ``ConfigureSession`` (post-password; symkey in mem)
///   - an optional ``ActiveSession`` (post-main-pick; per-main store +
///     wallet services)
///   - the ``AppRoute`` driving which view is visible
///
/// Children read it via `@Environment(AppState.self)`.
///
/// **Live FAPI lifecycle.** When the user saves an FAPI server in
/// Settings, ``applyFapiSettings(_:)`` builds a real `FudpClient` +
/// `FapiClient` and swaps it into the active session via
/// `setFapi(_:)`. The previous `FudpClient` (if any) is closed so
/// its UDP socket is released. Lock-vault / switch-identity tear it
/// down too.
@Observable
final class AppState {

    let manager: ConfigureManager
    private(set) var configureSession: ConfigureSession?
    private(set) var activeSession: ActiveSession?
    private(set) var configures: [ConfigureRecord]

    var route: AppRoute
    var lastError: String?

    /// Owned UDP transport behind the live `FapiClient`, kept here
    /// so the lock-vault / switch-identity / save-new-settings paths
    /// can close it. nil when the session is using the stub client.
    private var liveFudpClient: FudpClient?

    /// Closure that produces the *initial* (pre-settings-applied)
    /// FAPI client for a freshly-unlocked main. Default = stub. The
    /// real client gets swapped in by ``applyFapiSettings(_:)`` once
    /// the unlocked session can read its preferences.
    private let fapiFactory: @Sendable (String) -> any FapiCalling

    init(
        manager: ConfigureManager? = nil,
        fapiFactory: @escaping @Sendable (String) -> any FapiCalling = { _ in StubFapiClient() }
    ) {
        let resolved: ConfigureManager
        do {
            resolved = try manager ?? ConfigureManager()
        } catch {
            // Last-resort fallback: use temp dir so the UI still draws
            // and we surface the error rather than crashing on launch.
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent("fc.freer.mac.fallback-\(UUID().uuidString)")
            resolved = (try? ConfigureManager(baseDirectory: tmp))
                ?? (try! ConfigureManager(baseDirectory: FileManager.default.temporaryDirectory))
            self.manager = resolved
            self.fapiFactory = fapiFactory
            self.configures = []
            self.route = .password
            self.lastError = "Couldn't open vault storage: \(error). Data won't persist."
            return
        }
        self.manager = resolved
        self.fapiFactory = fapiFactory
        // Always start at the password view — never reveal whether
        // the vault index is empty.
        self.configures = (try? resolved.listConfigures()) ?? []
        self.route = .password
    }

    // MARK: - password flow

    /// Try to open the Configure whose `passwordName` matches this
    /// password. Falls through to creating a new Configure when none
    /// exists yet (`createIfMissing == true`).
    ///
    /// Errors are deliberately generic — "Couldn't open vault" /
    /// "Couldn't create vault" — so a wrong password vs. an unknown
    /// password are indistinguishable on screen.
    func openOrCreate(
        password: Data,
        createIfMissing: Bool,
        kdfKind: KdfKind = .argon2id
    ) async {
        lastError = nil
        let passwordName = ConfigureCrypto.passwordName(from: password)
        let manager = self.manager

        if let _ = configures.first(where: { $0.passwordName == passwordName }) {
            // Existing Configure — try to open.
            do {
                let cs = try await Task.detached(priority: .userInitiated) {
                    try manager.openConfigure(passwordName: passwordName, password: password)
                }.value
                self.configureSession = cs
                self.route = .chooseMain
            } catch {
                lastError = "Couldn't open vault."
            }
            return
        }

        // No Configure with this passwordName.
        guard createIfMissing else {
            lastError = "Couldn't open vault."
            return
        }

        do {
            let cs = try await Task.detached(priority: .userInitiated) {
                try manager.createConfigure(password: password, label: "", kdfKind: kdfKind)
            }.value
            self.configureSession = cs
            self.configures = (try? manager.listConfigures()) ?? configures
            self.route = .chooseMain
        } catch {
            lastError = "Couldn't create vault."
        }
    }

    // MARK: - configure-level lock

    /// Lock both the active session and the configure session. Send
    /// the user back to the password screen. Closes the live FUDP
    /// transport (if any) so its UDP socket is released.
    func lockAll() {
        tearDownLiveFapi()
        activeSession = nil
        configureSession?.lock()
        configureSession = nil
        configures = (try? manager.listConfigures()) ?? configures
        route = .password
    }

    // MARK: - main FID flow

    /// Add a main FID inside the unlocked Configure. The privkey is
    /// validated by deriving its FID; on success the new KeyInfo is
    /// persisted to the Configure body.
    func addMain(privkey: Data, label: String) async {
        guard let cs = configureSession else {
            lastError = "No unlocked Configure."
            return
        }
        lastError = nil
        do {
            _ = try await Task.detached(priority: .userInitiated) {
                try cs.addMain(privkey: privkey, label: label)
            }.value
            // Refresh views — list of mains comes from cs.listMains().
            self.route = .chooseMain
        } catch {
            lastError = String(describing: error)
        }
    }

    /// Unlock one of the main FIDs and open an ActiveSession. The
    /// session starts with the stub `FapiClient`; if the per-main
    /// preferences have an FAPI server configured the real client is
    /// built and swapped in immediately afterward.
    func unlockMain(fid: String) async {
        guard let cs = configureSession else {
            lastError = "No unlocked Configure."
            return
        }
        lastError = nil
        let factory = self.fapiFactory
        do {
            let session = try await Task.detached(priority: .userInitiated) {
                try cs.unlockMain(fid: fid, fapi: factory(fid))
            }.value
            self.activeSession = session
            self.route = .home
            // Best-effort attempt to bring up the live FAPI client.
            // Failure is non-fatal — Overview will show the stub
            // error and the Settings pane lets the user fix things.
            await applyFapiSettings(for: session)
        } catch {
            lastError = String(describing: error)
        }
    }

    /// Drop the active session but keep the Configure unlocked.
    /// Returns the user to the main chooser so they can pick a
    /// different main FID without re-entering the password. The
    /// live FUDP transport is torn down (different main → different
    /// keypair → different AsyTwoWay session anyway).
    func returnToChooseMain() {
        tearDownLiveFapi()
        activeSession = nil
        route = .chooseMain
    }

    // MARK: - live FAPI

    /// Tear down the FUDP transport behind the live FAPI client and
    /// reset the session's `fapi` to the stub. Idempotent.
    private func tearDownLiveFapi() {
        liveFudpClient?.close()
        liveFudpClient = nil
        activeSession?.setFapi(StubFapiClient())
    }

    /// Read the per-main preferences and bring up a real
    /// ``FapiClient`` if FAPI is configured. Closes any previous
    /// live transport. Failure leaves the session on the stub
    /// client and surfaces the error via `lastError`.
    func applyFapiSettings(for session: ActiveSession) async {
        let prefs: Preferences
        do {
            prefs = try session.preferences.load()
        } catch {
            lastError = "Couldn't read preferences: \(error)"
            return
        }

        // No FAPI configured → stub.
        guard
            let serviceStr = prefs.preferredFapiService,
            let pubkeyHex = prefs.preferredFapiServicePubkeyHex,
            let (host, port) = parseHostPort(serviceStr),
            let pubkey = decodeHex(pubkeyHex), pubkey.count == 33
        else {
            tearDownLiveFapi()
            return
        }

        let priv: Data
        do {
            priv = try session.mainPrikey()
        } catch {
            lastError = "Couldn't read main privkey: \(error)"
            return
        }

        do {
            let fudp = try await FudpClient(
                host: host,
                port: port,
                peerPubkey: pubkey,
                localPrivkey: priv
            )
            // Swap atomically: close old → assign new → publish.
            liveFudpClient?.close()
            liveFudpClient = fudp
            session.setFapi(FapiClient(fudp: fudp))
        } catch {
            lastError = "FAPI connect failed: \(error)"
            tearDownLiveFapi()
        }
    }

    // MARK: - helpers

    /// Parse "host:port" → (host, port). Tolerant of IPv6-style
    /// `[::1]:8500` not yet — colon-split with `lastIndex(of:)` is
    /// good enough for the localhost / hostname / IPv4 cases.
    private func parseHostPort(_ s: String) -> (String, UInt16)? {
        guard let colon = s.lastIndex(of: ":") else { return nil }
        let host = String(s[s.startIndex..<colon])
        let portStr = String(s[s.index(after: colon)..<s.endIndex])
        guard let port = UInt16(portStr) else { return nil }
        return (host, port)
    }

    /// Tiny inline hex parser. Returns nil on any malformed input.
    /// Pulled inline because adding a public Data(hex:) extension
    /// in FCCore would conflict with the test-only one — keeping
    /// the API surface clean for now.
    private func decodeHex(_ s: String) -> Data? {
        guard s.count % 2 == 0 else { return nil }
        var data = Data(capacity: s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let b = UInt8(s[idx..<next], radix: 16) else { return nil }
            data.append(b)
            idx = next
        }
        return data
    }

    // MARK: - live-FID switching

    func switchLive(fid: String) {
        guard let session = activeSession else { return }
        do {
            try session.switchLive(fid: fid)
        } catch {
            lastError = String(describing: error)
        }
    }
}

/// Stub ``FapiCalling`` used until the real FAPI server pubkey is wired.
/// Every call throws so a buggy view can't accidentally pretend it
/// got valid network data.
struct StubFapiClient: FapiCalling, Sendable {
    func call(
        api: String, params: Data?, fcdsl: Data?, binary: Data?,
        sid: String?, via: String?, maxCost: Int64?, timeoutMs: Int
    ) async throws -> FapiClient.Reply {
        throw StubError.notConfigured(api: api)
    }
    enum StubError: Error, CustomStringConvertible {
        case notConfigured(api: String)
        var description: String {
            switch self {
            case .notConfigured(let api):
                return "FAPI not yet configured (call: \(api)). Wire a real FapiClient in Phase 6."
            }
        }
    }
}
