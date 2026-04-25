import Foundation
import Observation
import FCCore
import FCDomain
import FCTransport

/// Top-level UI route. Mutually exclusive screens; navigation happens
/// by reassigning ``AppState/route``.
enum AppRoute: Equatable {
    /// First launch — no Configures exist yet. Shown to nudge the
    /// user toward setting a password.
    case welcome

    /// Single password field. The submit action either opens an
    /// existing Configure (matched by `passwordName`) or — if no
    /// Configure has that `passwordName` — offers to create one.
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
/// **No real network in 5.7d.** ``fapiFactory`` defaults to a
/// `StubFapiClient` whose calls all throw "not configured". Phase 6
/// plugs in a real `FapiClient` once the FAPI server pubkey is in
/// hand.
@Observable
final class AppState {

    let manager: ConfigureManager
    private(set) var configureSession: ConfigureSession?
    private(set) var activeSession: ActiveSession?
    private(set) var configures: [ConfigureRecord]

    var route: AppRoute
    var lastError: String?

    /// Closure that produces a network client for an unlocked main.
    /// `mainFid` is passed for future use (e.g. authenticated FAPI).
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
            self.route = .welcome
            self.lastError = "Couldn't open Configure storage: \(error). Data won't persist."
            return
        }
        self.manager = resolved
        self.fapiFactory = fapiFactory
        let loaded = (try? resolved.listConfigures()) ?? []
        self.configures = loaded
        self.route = loaded.isEmpty ? .welcome : .password
    }

    // MARK: - password flow

    /// Try to open the Configure whose `passwordName` matches this
    /// password. Falls through to creating a new Configure when none
    /// exists yet (`createIfMissing == true`).
    func openOrCreate(
        password: Data,
        createIfMissing: Bool,
        newLabel: String = "",
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
                lastError = String(describing: error)
            }
            return
        }

        // No Configure with this passwordName.
        guard createIfMissing else {
            lastError = "No vault matched that password. Tap 'Create new vault' to make one."
            return
        }

        do {
            let cs = try await Task.detached(priority: .userInitiated) {
                try manager.createConfigure(password: password, label: newLabel, kdfKind: kdfKind)
            }.value
            self.configureSession = cs
            self.configures = (try? manager.listConfigures()) ?? configures
            self.route = .chooseMain
        } catch {
            lastError = String(describing: error)
        }
    }

    // MARK: - configure-level lock

    /// Lock both the active session and the configure session. Send
    /// the user back to the password screen.
    func lockAll() {
        activeSession = nil
        configureSession?.lock()
        configureSession = nil
        configures = (try? manager.listConfigures()) ?? configures
        route = configures.isEmpty ? .welcome : .password
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

    /// Unlock one of the main FIDs and open an ActiveSession.
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
        } catch {
            lastError = String(describing: error)
        }
    }

    /// Drop the active session but keep the Configure unlocked.
    /// Returns the user to the main chooser so they can pick a
    /// different main FID without re-entering the password.
    func returnToChooseMain() {
        activeSession = nil
        route = .chooseMain
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
