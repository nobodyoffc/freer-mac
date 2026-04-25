import Foundation
import Observation
import FCCore
import FCDomain
import FCTransport

/// Top-level UI route. Mutually exclusive screens; navigation happens
/// by reassigning ``AppState/route``.
enum AppRoute: Equatable {
    case welcome
    case chooseIdentity
    case createIdentity
    case unlock(IdentityRecord)
    case home
}

/// Single source of truth for the app shell. Owns the
/// ``IdentityVault`` and the currently-unlocked ``IdentitySession``
/// (if any), plus the navigation route.
///
/// **One AppState per app.** Children read it from
/// `@Environment(AppState.self)`.
///
/// **No network in 6.1.** ``fapiFactory`` defaults to a stub client
/// that throws "not configured" on every call. Phase 6.2 plugs in the
/// real `FapiClient` once we have the FAPI server's pubkey.
@Observable
final class AppState {

    let vault: IdentityVault
    private(set) var session: IdentitySession?

    /// What screen to show. Children mutate this to navigate.
    var route: AppRoute

    /// Inline error surface. Set by async actions; cleared by views
    /// when the user dismisses or retries.
    var lastError: String?

    /// Reactive list of registered identities. Refreshed on register/
    /// delete so the chooser updates without an extra `listIdentities`
    /// call.
    private(set) var identities: [IdentityRecord]

    /// Closure that produces a network client for a freshly-unlocked
    /// identity. Pulling this out as a closure lets tests inject a
    /// mock and lets Phase 6.2 swap to a real FudpClient/FapiClient
    /// without touching the call sites.
    private let fapiFactory: @Sendable (Identity) -> any FapiCalling

    init(
        vault: IdentityVault? = nil,
        fapiFactory: @escaping @Sendable (Identity) -> any FapiCalling = { _ in StubFapiClient() }
    ) {
        // The default IdentityVault may throw if the Application
        // Support directory is unwritable — extremely rare on macOS
        // outside of failed sandbox setup. Surface the error rather
        // than crashing.
        let resolvedVault: IdentityVault
        do {
            resolvedVault = try vault ?? IdentityVault()
        } catch {
            // Fall back to a temp-dir vault and surface the error so
            // the welcome screen can show "your data won't persist".
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent("fc.freer.mac.fallback-\(UUID().uuidString)")
            resolvedVault = (try? IdentityVault(baseDirectory: tmp))
                ?? (try! IdentityVault(baseDirectory: FileManager.default.temporaryDirectory))
            self.vault = resolvedVault
            self.fapiFactory = fapiFactory
            self.identities = []
            self.route = .welcome
            self.lastError = "Couldn't open identity vault: \(error). Data won't persist."
            return
        }
        self.vault = resolvedVault
        self.fapiFactory = fapiFactory
        let loaded = (try? resolvedVault.listIdentities()) ?? []
        self.identities = loaded
        self.route = loaded.isEmpty ? .welcome : .chooseIdentity
    }

    // MARK: - register

    /// Create a new identity. Runs Argon2id on a background priority
    /// task so the UI stays responsive (~300 ms per derivation).
    /// On success, transitions straight into the home screen with an
    /// unlocked session.
    func createIdentity(
        passphrase: String,
        displayName: String,
        scheme: PhraseKey.Scheme = .argon2id
    ) async {
        lastError = nil
        let trimmedName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let useName = trimmedName.isEmpty ? "Me" : trimmedName

        let vault = self.vault
        let factory = self.fapiFactory
        do {
            let session: IdentitySession = try await Task.detached(priority: .userInitiated) {
                let id = try vault.register(
                    passphrase: passphrase, displayName: useName, scheme: scheme
                )
                return IdentitySession(identity: id, fapi: factory(id))
            }.value
            self.session = session
            self.identities = (try? vault.listIdentities()) ?? identities
            self.route = .home
        } catch {
            lastError = String(describing: error)
        }
    }

    // MARK: - login

    func login(fid: String, passphrase: String) async {
        lastError = nil
        let vault = self.vault
        let factory = self.fapiFactory
        do {
            let session: IdentitySession = try await Task.detached(priority: .userInitiated) {
                let id = try vault.login(fid: fid, passphrase: passphrase)
                return IdentitySession(identity: id, fapi: factory(id))
            }.value
            self.session = session
            self.route = .home
        } catch {
            lastError = String(describing: error)
        }
    }

    // MARK: - lock

    func lock() {
        session?.lock()
        session = nil
        route = identities.isEmpty ? .welcome : .chooseIdentity
    }

    // MARK: - identities mgmt

    func goToCreateIdentity() {
        lastError = nil
        route = .createIdentity
    }

    func goToChooseIdentity() {
        lastError = nil
        // Refresh — register or delete may have happened.
        identities = (try? vault.listIdentities()) ?? identities
        route = identities.isEmpty ? .welcome : .chooseIdentity
    }

    func selectIdentity(_ record: IdentityRecord) {
        lastError = nil
        route = .unlock(record)
    }

    @discardableResult
    func deleteIdentity(_ record: IdentityRecord) -> Bool {
        do {
            let removed = try vault.delete(fid: record.fid)
            identities = (try? vault.listIdentities()) ?? []
            if identities.isEmpty { route = .welcome }
            return removed
        } catch {
            lastError = String(describing: error)
            return false
        }
    }
}

/// Stub ``FapiCalling`` used until Phase 6.2 wires a real client.
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
                return "FAPI not yet configured (call: \(api)). Phase 6.2 wires a real client."
            }
        }
    }
}
