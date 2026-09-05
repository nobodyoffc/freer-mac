import Foundation
import Observation
import AppKit
import Network
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
/// Settings, ``applyFapiSettings(_:)`` builds a real `FudpClient`
/// wrapped in a `ReconnectingFapiClient` and swaps it into the active
/// session via `setFapi(_:)`. The previous client (if any) is closed
/// so its UDP socket is released. Lock-vault / switch-identity tear it
/// down too.
///
/// **Surviving sleep/wake.** A UDP flow does not survive the machine
/// sleeping, changing network, or idling past its NAT mapping's
/// lifetime — the socket looks fine and every reply silently vanishes.
/// So the session holds the reconnecting wrapper, not a bare client,
/// and ``AppState`` nudges it with `markStale()` on wake and on path
/// changes; the wrapper reconnects at the next call, by which time the
/// network is actually back.
@Observable
final class AppState {

    let manager: ConfigureManager
    private(set) var configureSession: ConfigureSession?
    private(set) var activeSession: ActiveSession?
    private(set) var configures: [ConfigureRecord]

    /// Observable mirror of `activeSession?.liveFid`. `ActiveSession`
    /// is a plain class SwiftUI can't track, so every live-FID switch
    /// goes through ``switchLive(fid:)`` which updates this — views
    /// key off it (`.id(appState.liveFid)`) to rebuild after a switch.
    private(set) var liveFid: String?

    /// On-chain stats for the live FID — what the FID bar shows beyond
    /// the locally-stored KeyInfo. Cache-first: the stored row renders
    /// immediately on switch, then a `base.freerByIds` refresh replaces
    /// it. Lives here rather than in `PaneHeader` because the bar is on
    /// every pane, and per-view state would re-fetch on every pane
    /// switch.
    /// Bumped whenever something edits the live identity's `KeyInfo` —
    /// today only its label. The `Setting` is a plain struct behind a
    /// plain class, so SwiftUI cannot see a write to it; views that
    /// render `liveKeyInfo` read this counter to pick the change up.
    private(set) var identityRevision = 0

    private(set) var liveFidInfo: LiveFidInfo?
    private(set) var liveFidInfoLoading = false
    private(set) var liveFidInfoError: String?

    /// Which detail pane is on screen. Hoisted out of `HomeView` so
    /// anything can navigate — the FID bar's numbers jump to Cash, and
    /// the Overview tiles jump to whatever they are counting. A
    /// `@State` in `HomeView` would have meant threading a binding
    /// through all twenty-odd panes to achieve the same thing.
    var selectedPane: WalletPane = .overview

    /// A chat flavour the Chat pane should open on, set by whoever
    /// navigated there. One-shot: the pane reads it and clears it, so
    /// coming back to Chat later lands on whatever tab the user last
    /// used rather than re-running an old deep link.
    private(set) var pendingChatMode: ImType?

    /// Open the Chat pane on `mode`. The two writes belong together —
    /// setting the tab without switching panes does nothing visible.
    func openChat(mode: ImType) {
        pendingChatMode = mode
        selectedPane = .chat
    }

    func consumePendingChatMode() -> ImType? {
        defer { pendingChatMode = nil }
        return pendingChatMode
    }

    var route: AppRoute
    var lastError: String?

    /// Owned FAPI client (and, inside it, the UDP transport) kept here
    /// so the lock-vault / switch-identity / save-new-settings paths
    /// can close it, and so the wake / network-change observers can
    /// mark it stale. nil when the session is using the stub client.
    @ObservationIgnored
    private var liveFapi: ReconnectingFapiClient?

    /// Wake-from-sleep and network-path observers. Held for their
    /// lifetime — they live as long as the app does. Not observable:
    /// a Wi-Fi flap is no reason to redraw the UI.
    @ObservationIgnored private var wakeObserver: (any NSObjectProtocol)?
    @ObservationIgnored private var pathMonitor: NWPathMonitor?
    @ObservationIgnored private var lastPathSummary: String?
    @ObservationIgnored private var activationObservers: [any NSObjectProtocol] = []

    /// Polls the DOCKs so messages arrive on their own. Lives exactly as
    /// long as a live FAPI client does: with no server configured there
    /// is nothing to poll.
    @ObservationIgnored private var fetchScheduler: DockFetchScheduler?

    /// The two inputs to the polling layer, kept apart because they
    /// change independently: the OS tells us about one, the chat pane
    /// about the other.
    @ObservationIgnored private var appIsActive = true
    /// The ssh-agent behind the Terminal pane. Nil until a session
    /// asks for it, and dropped on lock — see ``sshAgent(for:)``.
    @ObservationIgnored private var sshAgentServer: SshAgentServer?
    @ObservationIgnored private var chatIsOpen = false

    /// Raises the "approve this transaction?" modal for every signing
    /// path, when the identity has that setting on. Lives on AppState
    /// because the dialog has to be presentable from the root view no
    /// matter which pane started the transaction — and because a
    /// background carve (the chat outbox, a retry) has no pane at all.
    let txApprovals = TxApprovalCenter()

    /// Bumped whenever a background collect filed something. Views watch
    /// it to reload — an observable counter is the smallest thing that
    /// can carry "the transcript changed underneath you" from a
    /// non-UI task into SwiftUI.
    private(set) var inboxRevision = 0

    /// How many newcomers are waiting on the first-FCH board, for the
    /// identity that opted into looking. Zero when nobody is waiting,
    /// when the setting is off, or when the board could not be read —
    /// a login is the wrong moment to report a server problem the user
    /// did not ask about.
    private(set) var newcomersWaiting = 0

    /// FIDs already checked this app run, so returning to Overview does
    /// not re-ask the board on every appearance.
    @ObservationIgnored private var boardCheckedFids: Set<String> = []

    /// Look at the board once, for an identity that asked to.
    ///
    /// **Read-only, and it does not move the cursor.** The count is a
    /// nudge towards the pane; advancing the watermark here would hide
    /// from the board the very requests this just counted.
    func checkFirstFchBoardIfOptedIn() {
        guard let session = activeSession else { return }
        let fid = session.liveFid
        guard session.firstFchBoardState.get(fid: fid).checkAtLogin else { return }
        guard boardCheckedFids.insert(fid).inserted else { return }
        let board = session.firstFchBoard
        let cursor = session.firstFchBoardState.get(fid: fid).cursor
        Task { @MainActor in
            let result = await board.fetch(newerThan: cursor)
            guard result.error == nil, session.liveFid == fid else { return }
            newcomersWaiting = result.requests.count
        }
    }

    func clearNewcomersWaiting() { newcomersWaiting = 0 }

    /// The live FID holds nothing, and we actually know that.
    ///
    /// Three states collapse to "no coins" and only one of them is worth
    /// acting on: a balance of zero, a FID with no on-chain record at all
    /// (``ActiveSession/refreshLiveFidInfo()`` leaves `balance` nil for
    /// one the index has never seen — which is precisely the newcomer
    /// this is for), and *not knowing yet*. The first two are broke; the
    /// third must not be, or every helper with a full wallet sees the
    /// newcomer banner flash on a slow connection. An index we could not
    /// reach says nothing either way.
    var liveFidIsBroke: Bool {
        guard activeSession != nil, !liveFidInfoLoading, liveFidInfoError == nil else {
            return false
        }
        return (liveFidInfo?.balance ?? 0) == 0
    }

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
            self.installConnectivityObservers()
            return
        }
        self.manager = resolved
        self.fapiFactory = fapiFactory
        // Always start at the password view — never reveal whether
        // the vault index is empty.
        self.configures = (try? resolved.listConfigures()) ?? []
        self.route = .password
        self.installConnectivityObservers()
    }

    deinit {
        if let wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(wakeObserver)
        }
        for observer in activationObservers {
            NotificationCenter.default.removeObserver(observer)
        }
        pathMonitor?.cancel()
    }

    // MARK: - connectivity observers

    /// Watch the two events that silently kill a live UDP flow, and
    /// mark the FAPI client stale so the next call comes up on a fresh
    /// socket. Marking (rather than reconnecting here and now) is
    /// deliberate: at wake time Wi-Fi has usually not reassociated
    /// yet, so an immediate reconnect would just build a second dead
    /// socket.
    private func installConnectivityObservers() {
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.markTransportsStale()
        }

        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            // Interfaces flap during a wake; only a real change of
            // status or interface set means the old flow is finished.
            let summary = "\(path.status)|"
                + path.availableInterfaces.map(\.name).joined(separator: ",")
            DispatchQueue.main.async { [weak self] in
                guard let self, self.lastPathSummary != summary else { return }
                let hadPath = self.lastPathSummary != nil
                self.lastPathSummary = summary
                // The first update just records the baseline — there is
                // no connection to invalidate at startup.
                if hadPath { self.markTransportsStale() }
            }
        }
        monitor.start(queue: DispatchQueue(label: "fc.path-monitor", qos: .utility))
        pathMonitor = monitor

        // How hard to poll depends on whether anyone is looking. An app
        // in the background still collects — a message that arrived
        // while it was hidden should be there when it comes back — just
        // at a third of the rate.
        let center = NotificationCenter.default
        for (name, active) in [
            (NSApplication.didBecomeActiveNotification, true),
            (NSApplication.didResignActiveNotification, false),
        ] {
            activationObservers.append(
                center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                    guard let self else { return }
                    self.appIsActive = active
                    self.applyFetchLayer()
                }
            )
        }
    }

    // MARK: - background collection

    /// Whether a chat pane is on screen. Drives the polling rate: an
    /// open conversation wants an answer in seconds, a wallet screen
    /// does not.
    func setChatOpen(_ open: Bool) {
        guard chatIsOpen != open else { return }
        chatIsOpen = open
        applyFetchLayer()
    }

    /// Put one conversation's DOCK on the fast lane. Pass nil when the
    /// conversation closes.
    func setPriorityDock(_ dockUrl: String?) {
        guard let fetchScheduler else { return }
        Task { await fetchScheduler.setPriorityDock(dockUrl) }
    }

    /// Collect from every DOCK right now, off the schedule.
    func fetchInboxNow() {
        guard let fetchScheduler else { return }
        Task { await fetchScheduler.fetchNow() }
    }

    private func applyFetchLayer() {
        guard let fetchScheduler else { return }
        let layer: DockFetchScheduler.Layer =
            !appIsActive ? .background : (chatIsOpen ? .active : .normal)
        Task { await fetchScheduler.setLayer(layer) }
    }

    /// Build and start the poller for `session`.
    ///
    /// The collect closure is the only thing that reaches back into the
    /// session, and it deliberately re-reads `activeSession` each pass
    /// rather than capturing it: a scheduler holding a session the user
    /// has since locked would keep decrypting into a store nobody is
    /// looking at.
    private func startFetchScheduler(for session: ActiveSession) {
        stopFetchScheduler()
        let scheduler = DockFetchScheduler(
            collect: { [weak self] selection in
                guard let session = self?.activeSession else { return .none }
                do {
                    return try await session.courier.collect(
                        as: session.liveFid,
                        docks: selection,
                        privkey: try? session.livePrikey()
                    )
                } catch {
                    return .none
                }
            },
            drain: { [weak self] in
                guard let session = self?.activeSession else { return }
                _ = try? await session.courier.drainOutbox(as: session.liveFid)
            },
            report: { [weak self] _ in
                Task { @MainActor in self?.inboxRevision += 1 }
            }
        )
        fetchScheduler = scheduler
        applyFetchLayer()
        Task { await scheduler.start() }
    }

    private func stopFetchScheduler() {
        guard let fetchScheduler else { return }
        self.fetchScheduler = nil
        Task { await fetchScheduler.stop() }
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
        // Anything parked on a confirmation dialog is answered "no"
        // first: the session is about to disappear, and a question
        // nobody can answer must not turn into a signature.
        txApprovals.cancelAll()
        tearDownLiveFapi()
        tearDownTerminalSessions()
        tearDownSshAgent()
        activeSession = nil
        liveFid = nil
        clearLiveFidInfo()
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

    /// Delete a main FID from the unlocked Configure. The vault holds
    /// the only copy of its encrypted privkey, so this cannot be undone.
    ///
    /// `deletingSetting` also removes the FID's on-disk Setting
    /// directory — contacts, caches, chat state. Leaving it behind is
    /// the kinder default: re-importing the same privkey later picks the
    /// directory straight back up, so only the key is actually lost.
    func deleteMain(fid: String, deletingSetting: Bool) async {
        guard let cs = configureSession else {
            lastError = "No unlocked Configure."
            return
        }
        lastError = nil
        do {
            let removed = try await Task.detached(priority: .userInitiated) {
                deletingSetting
                    ? try cs.deleteMainAndSetting(fid: fid)
                    : try cs.removeMain(fid: fid)
            }.value
            if !removed {
                lastError = "That identity is no longer in this vault."
            }
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
            session.txApprover = self.txApprovals.approver()
            self.activeSession = session
            self.liveFid = session.liveFid
            self.route = .home
            // Show whatever the last session cached before the network
            // is even up — the bar should never start blank.
            self.loadCachedLiveFidInfo()
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
        txApprovals.cancelAll()
        tearDownLiveFapi()
        // A different main FID derives a different SSH key, so the
        // running agent is not merely stale — it holds the wrong one.
        tearDownTerminalSessions()
        tearDownSshAgent()
        activeSession = nil
        liveFid = nil
        clearLiveFidInfo()
        route = .chooseMain
    }

    // MARK: - ssh agent

    /// The running ssh-agent, starting it if this is the first session.
    ///
    /// **Lives on `AppState` rather than in the pane** because it
    /// outlives any one terminal view — several sessions share one
    /// agent — and because the two moments that must kill it,
    /// ``lockAll()`` and ``returnToChooseMain()``, are here. A key that
    /// survives the vault lock in a process the user believes is locked
    /// is the bug this whole design exists to avoid.
    ///
    /// The key is derived here and handed over; nothing caches it.
    func sshAgent(for session: ActiveSession) throws -> SshAgentServer {
        if let existing = sshAgentServer, existing.isRunning { return existing }

        let identity = try session.sshIdentity()
        let agent = try SshAgentServer(key: identity, comment: "freer:\(session.mainFid)")
        try agent.start()
        sshAgentServer = agent
        return agent
    }

    /// Stop the agent, unlink its socket, and drop the object holding
    /// the key. Idempotent.
    ///
    /// Dropping the object is the part that matters: ``SshAgentServer``
    /// cannot wipe CryptoKit's internal copy of the private key, so
    /// "the key is gone" means "nothing references it any more".
    func tearDownSshAgent() {
        sshAgentServer?.stop()
        sshAgentServer = nil
    }

    /// Whether an agent is currently up — the pane shows this, because
    /// "a process on this Mac can sign as you right now" should not be
    /// invisible.
    var sshAgentIsRunning: Bool {
        sshAgentServer?.isRunning ?? false
    }

    // MARK: - terminal sessions

    /// Live SSH sessions, keyed by ``SshServer/id``.
    ///
    /// **Here rather than in the pane's `@State`** because the detail
    /// column is rebuilt when the sidebar selection changes: a session
    /// owned by the view would be torn down the moment the user
    /// glanced at their wallet, which is not what a terminal is for.
    private(set) var terminalSessions: [String: TerminalSessionModel] = [:]

    /// The live session for this server, or a fresh one.
    ///
    /// A *finished* session is replaced rather than restarted: its
    /// `LocalProcessTerminalView` still holds the last session's
    /// scrollback and a spent pty, and reusing it would splice two
    /// logins into one transcript.
    func terminalSession(for server: SshServer) -> TerminalSessionModel {
        if let existing = terminalSessions[server.id], existing.isRunning { return existing }
        let session = TerminalSessionModel(server: server)
        session.onEnded = { [weak self] in self?.stopSshAgentIfIdle() }
        terminalSessions[server.id] = session
        return session
    }

    /// End one session but keep its transcript on screen.
    func stopTerminalSession(id: String) {
        terminalSessions[id]?.stop()
        stopSshAgentIfIdle()
    }

    /// End one session and forget it — for when the server itself is
    /// being removed and there is nothing left to show.
    func closeTerminalSession(id: String) {
        terminalSessions[id]?.stop()
        terminalSessions.removeValue(forKey: id)
        stopSshAgentIfIdle()
    }

    /// Put the agent away once nothing is using it.
    ///
    /// The agent's entire risk is the window it is up for, so that
    /// window is "at least one live session" and not "the app is
    /// running". Note the test is `isRunning`, not "the dictionary is
    /// empty": a finished session stays in the dictionary so its
    /// scrollback survives, and it must not keep the key alive.
    private func stopSshAgentIfIdle() {
        guard !terminalSessions.values.contains(where: { $0.isRunning }) else { return }
        tearDownSshAgent()
    }

    /// Kill every session. Called on lock: a channel authenticated
    /// before the lock would otherwise stay open on a vault the user
    /// believes is closed.
    func tearDownTerminalSessions() {
        for session in terminalSessions.values { session.stop() }
        terminalSessions.removeAll()
    }

    // MARK: - live FAPI

    /// Tear down the FUDP transport behind the live FAPI client and
    /// reset the session's `fapi` to the stub. Idempotent.
    private func tearDownLiveFapi() {
        stopFetchScheduler()
        liveFapi?.close()
        liveFapi = nil
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

        // No usable FAPI config → stub. `PreferencesStore.load()`
        // backfills the project server when the row has no service at
        // all, so landing here means the stored values are malformed —
        // say so, because the alternative is every pane loading empty
        // with nothing on screen to explain why.
        guard
            let serviceStr = prefs.preferredFapiService,
            let pubkeyHex = prefs.preferredFapiServicePubkeyHex,
            let (host, port) = parseHostPort(serviceStr),
            let pubkey = decodeHex(pubkeyHex), pubkey.count == 33
        else {
            tearDownLiveFapi()
            lastError = """
                No FAPI server configured — nothing will load. \
                Open Settings and set the host, port and server pubkey \
                (Discover fills the pubkey in), then Save.
                """
            return
        }

        let priv: Data
        do {
            priv = try session.mainPrikey()
        } catch {
            lastError = "Couldn't read main privkey: \(error)"
            return
        }

        // Everything the transport needs, captured once so the wrapper
        // can rebuild it later without re-reading preferences (which
        // would need the session — and its unlocked privkey — on a
        // background reconnect).
        let factory: @Sendable () async throws -> FudpClient = {
            try await FudpClient(
                host: host,
                port: port,
                peerPubkey: pubkey,
                localPrivkey: priv
            )
        }

        // Opens a client to *any other* DOCK, given only its URL.
        //
        // The peer's pubkey is not configured anywhere — it cannot be,
        // since the URL comes off the chain at send time — so it is
        // discovered with a plaintext HELLO first, exactly as the
        // Settings pane's "fetch pubkey" button does and as Android's
        // `bootstrapFromUrl` does before building its client. The
        // discovery is repeated on every reconnect because a server
        // that moved may also have re-keyed.
        let connect: @Sendable (String) async throws -> any FapiCalling = { url in
            guard let endpoint = FudpUrl.hostPort(url) else {
                throw DockConnectFailure.unusableUrl(url)
            }
            let build: @Sendable () async throws -> FudpClient = {
                let peerPubkey = try await FudpDiscovery.discoverPubkey(
                    host: endpoint.host, port: endpoint.port
                )
                return try await FudpClient(
                    host: endpoint.host,
                    port: endpoint.port,
                    peerPubkey: peerPubkey,
                    localPrivkey: priv
                )
            }
            return ReconnectingFapiClient(factory: build, initial: try await build())
        }

        do {
            // Connect eagerly so a bad host/port/pubkey is reported
            // now, in Settings, rather than at the next chain sync.
            let fudp = try await factory()
            // Swap atomically: close old → assign new → publish.
            liveFapi?.close()
            let client = ReconnectingFapiClient(factory: factory, initial: fudp)
            liveFapi = client
            session.setFapi(client)
            // Our own DOCK is whatever server we just connected to; the
            // registry needs it by URL so a put aimed there is a plain
            // store rather than a forward to ourselves.
            await session.dockRegistry.configure(
                ownDockUrl: "\(host):\(port)", ownClient: client, connect: connect
            )
            await session.refreshDockRegistry()
            // Only now: a poller started before the registry knows where
            // anything lives would spend its first passes fetching from
            // nowhere.
            startFetchScheduler(for: session)
            // First moment the bar can actually get real numbers: the
            // cached row went up at unlock, this replaces it.
            Task { await refreshLiveFidInfo() }
            // …and the first moment the board is reachable, for an
            // identity that asked to be told when somebody is waiting.
            checkFirstFchBoardIfOptedIn()
            SystemLog.shared.info(
                SystemSource.fapi, "Connected to \(host):\(port)"
            )
        } catch {
            lastError = "FAPI connect failed: \(error)"
            SystemLog.shared.error(
                SystemSource.fapi,
                "Could not connect to \(host):\(port)",
                detail: "\(error)\nWallet, chat and sync all run over this connection."
            )
            tearDownLiveFapi()
        }
    }

    /// Retire the live transport: the next FAPI call opens a fresh
    /// socket. For callers that learn the old one can't be trusted —
    /// a wake, a network change, a successful connection test.
    func markFapiStale() {
        liveFapi?.markStale()
    }

    /// Retire **every** socket, not just the one to our own server.
    ///
    /// A wake or a network change kills each per-DOCK connection the
    /// registry is holding exactly as it kills the main one, and a dead
    /// one that is never dropped means a group whose messages stop
    /// arriving until the app is relaunched.
    private func markTransportsStale() {
        liveFapi?.markStale()
        guard let session = activeSession else { return }
        Task { await session.dockRegistry.invalidateAllClients() }
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
            liveFid = session.liveFid
            // Sitting on Mail and switching to a watch-only identity
            // would otherwise leave the selection on a pane the sidebar
            // has just greyed out — a detail view with no way back to
            // it, since the row that owns the selection is no longer
            // clickable. Overview is always open, to every kind.
            if selectedPane.needsKey && !session.canSign {
                selectedPane = .overview
            }
            // The new identity's numbers are a different set entirely,
            // so show its cached row at once and go get a fresh one.
            loadCachedLiveFidInfo()
            Task { await refreshLiveFidInfo() }
            // A different identity opted in, or did not, and has its own
            // cursor — so the previous one's count means nothing here.
            newcomersWaiting = 0
            checkFirstFchBoardIfOptedIn()
        } catch {
            lastError = String(describing: error)
        }
    }

    /// Re-read `liveFid` from the session after something *else*
    /// changed it — removing the sub-identity you were living as, which
    /// drops the session back to the main from inside ``ActiveSession``.
    /// Without this the toolbar and every `.id(liveFid)` keep the FID
    /// the Setting no longer holds.
    func syncLiveFid() {
        guard let session = activeSession else { return }
        guard liveFid != session.liveFid else { return }
        liveFid = session.liveFid
        if selectedPane.needsKey && !session.canSign {
            selectedPane = .overview
        }
        loadCachedLiveFidInfo()
        Task { await refreshLiveFidInfo() }
    }

    // MARK: - live FID on-chain stats

    /// Render the stored row for the live FID immediately, without
    /// touching the network.
    private func loadCachedLiveFidInfo() {
        guard let session = activeSession else { return }
        liveFidInfoError = nil
        liveFidInfo = session.cachedLiveFidInfo()
    }

    /// Tell every view rendering the live `KeyInfo` to re-read it.
    func bumpIdentityRevision() { identityRevision += 1 }

    private func clearLiveFidInfo() {
        liveFidInfo = nil
        liveFidInfoLoading = false
        liveFidInfoError = nil
    }

    /// Re-fetch the live FID's on-chain record. Safe to call from
    /// anywhere that just changed the identity's money — a send, a
    /// carve, the bar's refresh button.
    ///
    /// Overlapping calls are dropped rather than queued: the second
    /// answer would overwrite the first with the same chain state.
    func refreshLiveFidInfo() async {
        guard let session = activeSession, !liveFidInfoLoading else { return }
        let fidAtStart = session.liveFid
        liveFidInfoLoading = true
        liveFidInfoError = nil
        defer { liveFidInfoLoading = false }
        do {
            let info = try await session.refreshLiveFidInfo()
            // The user can switch identity while the call is in flight;
            // dropping a late answer for the previous FID keeps the bar
            // from briefly showing the wrong identity's balance.
            guard session.liveFid == fidAtStart else { return }
            liveFidInfo = info
        } catch {
            guard session.liveFid == fidAtStart else { return }
            liveFidInfoError = String(describing: error)
        }
    }
}

/// Why a DOCK we were asked to reach could not be connected to.
enum DockConnectFailure: Error, CustomStringConvertible {
    case unusableUrl(String)

    var description: String {
        switch self {
        case .unusableUrl(let url):
            return "DOCK address '\(url)' does not name a host we can reach"
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
