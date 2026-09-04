import Foundation
import FCCore
import FCStorage
import FCTransport

/// One unlocked main FID inside one unlocked Configure. The runtime
/// container that the SwiftUI app shell holds while the user is
/// "logged in." Owns:
///
///   - a back-reference to its parent ``ConfigureSession``
///   - the per-main ``Setting`` (decrypted, in-memory, mutated and
///     re-persisted on every change)
///   - a per-main ``EncryptedKVStore`` for fast-changing cached state
///     (UTXO snapshots, contacts, message logs)
///   - the `liveFid` — what FID the user is *currently operating as*,
///     which may be the main itself or any of its sub-identities
///     (watch-only / multisig / servant) registered in
///     ``Setting/keyInfoMap``.
///
/// **Switching live FID.** Calling ``switchLive(fid:)`` changes which
/// FID the wallet/contact/etc. services act as — without re-auth, no
/// network round-trip. Operations that need a privkey check
/// ``canSign`` first; for watch-only entries the wallet exposes a
/// `buildUnsignedTxInfo` path instead (Phase 8).
public final class ActiveSession {

    public enum Failure: Error, CustomStringConvertible {
        case unknownLive(fid: String)
        case watchOnlyCannotSign(fid: String)
        case cannotReplaceMain(fid: String)
        case masterNeedsMain(live: String)
        case masterIsSelf(fid: String)
        case masterPubkeyMismatch(fid: String, derived: String)
        case masterPubkeyUnknown(fid: String)
        case multisigIncomplete
        case notAMultisigMember(fid: String, group: String)
        case underlying(Error)

        public var description: String {
            switch self {
            case .unknownLive(let fid):
                return "ActiveSession: \(fid) is not registered in this Setting"
            case .watchOnlyCannotSign(let fid):
                return "ActiveSession: \(fid) is watch-only — cannot sign or decrypt"
            case .cannotReplaceMain(let fid):
                return "ActiveSession: \(fid) is the main FID — it cannot be replaced by a sub-identity"
            case .masterNeedsMain(let live):
                return "ActiveSession: a master is set for the main FID, but \(live) is live — switch to the main first"
            case .masterIsSelf(let fid):
                return "ActiveSession: \(fid) cannot be its own master"
            case .masterPubkeyMismatch(let fid, let derived):
                return "ActiveSession: that pubkey belongs to \(derived), not \(fid) — refusing to seal a private key to the wrong party"
            case .masterPubkeyUnknown(let fid):
                return "ActiveSession: \(fid) has never published a pubkey, so there is nothing to encrypt the private key to"
            case .multisigIncomplete:
                return "ActiveSession: that multisig group has no address — it is missing its members or its m-of-n"
            case let .notAMultisigMember(fid, group):
                return "ActiveSession: \(fid) is not a member of \(group), so this Setting could never sign for it"
            case .underlying(let err):
                return "ActiveSession: \(err)"
            }
        }
    }

    public let configureSession: ConfigureSession
    public let mainFid: String
    public private(set) var setting: Setting
    public private(set) var liveFid: String

    public let storage: EncryptedKVStore
    /// Where this main's app-managed file copies live (downloads and
    /// materialized copies). Sits beside the per-main store, so file
    /// bytes inherit the same identity isolation the database has.
    public let dataDirectory: URL
    /// The FAPI client used by ``wallet`` and any other domain
    /// service that talks to a server. Mutable so the app shell can
    /// swap a stub for a real `FapiClient` after the user configures
    /// the FAPI server in Settings, without rebuilding the whole
    /// session.
    public private(set) var fapi: any FapiCalling

    private let settingUrl: URL

    init(
        configureSession: ConfigureSession,
        mainFid: String,
        setting: Setting,
        settingUrl: URL,
        storage: EncryptedKVStore,
        dataDirectory: URL,
        fapi: any FapiCalling
    ) {
        self.configureSession = configureSession
        self.mainFid = mainFid
        self.setting = setting
        self.liveFid = mainFid
        self.settingUrl = settingUrl
        self.storage = storage
        self.dataDirectory = dataDirectory
        self.fapi = fapi
    }

    // MARK: - identity views

    /// The KeyInfo for whatever FID the user is currently operating
    /// as (defaults to the main FID).
    public var liveKeyInfo: KeyInfo {
        // Setting.keyInfoMap is guaranteed to contain at least the
        // main entry (added at session-creation time). If liveFid is
        // ever set to something not in the map, switchLive(fid:)
        // refuses — so this force-unwrap is sound.
        setting.keyInfoMap[liveFid] ?? setting.keyInfoMap[mainFid]!
    }

    public var mainKeyInfo: KeyInfo { setting.keyInfoMap[mainFid]! }

    /// Whether the live FID can sign/decrypt. Watch-only entries
    /// return false; the UI should show "cold-sign export" affordances
    /// instead of the normal send button.
    public var canSign: Bool { liveKeyInfo.hasPrivkey && liveKeyInfo.kind.canSign }

    public func switchLive(fid: String) throws {
        guard setting.keyInfoMap[fid] != nil else {
            throw Failure.unknownLive(fid: fid)
        }
        liveFid = fid
    }

    // MARK: - prikey

    /// The 32-byte privkey for the **main** FID. Always available
    /// while the session is unlocked (the main always has a privkey).
    public func mainPrikey() throws -> Data {
        try configureSession.privkeyForMain(fid: mainFid)
    }

    /// The 32-byte privkey for the **live** FID. Throws for watch-only
    /// entries — callers handle that as the cold-sign path.
    public func livePrikey() throws -> Data {
        let info = liveKeyInfo
        guard info.hasPrivkey else { throw Failure.watchOnlyCannotSign(fid: info.fid) }
        do {
            let symkey = try configureSession.symkey()
            return try info.decryptPrikey(symkey: symkey)
        } catch let e as ConfigureSession.Failure {
            throw Failure.underlying(e)
        } catch {
            throw Failure.underlying(error)
        }
    }

    // MARK: - ssh

    /// The SSH identity for this vault: an ed25519 key derived one-way
    /// from ``mainPrikey()``.
    ///
    /// **Bound to the main FID, not the live one.** Switching to a
    /// watch-only sub-identity does not change which key opens your
    /// servers, so the Terminal pane stays open for every identity in
    /// the vault — see the note on ``SshEd25519Key`` for what that
    /// binding costs when the main FID changes.
    ///
    /// **A method, not a `lazy var`.** Caching it would keep the key
    /// alive for as long as anything held this session, which is
    /// exactly what vault lock is supposed to end. Deriving is one
    /// HKDF read, so there is nothing to save by caching.
    public func sshIdentity() throws -> SshEd25519Key {
        var priv = try mainPrikey()
        defer { priv.resetBytes(in: 0 ..< priv.count) }
        return try SshEd25519Key(mainPrikey: priv, mainFid: mainFid)
    }

    // MARK: - sub-identities

    /// Add a watch-only sub-identity (just an FID we want to track,
    /// no privkey). Phase 5.7 handles `.watched`; the other kinds
    /// (multisig / servant) follow the same shape but need their own
    /// signing UI and are deferred.
    @discardableResult
    public func addWatchedFid(
        _ fid: String,
        label: String = "",
        pubkey: Data? = nil,
        master: String? = nil
    ) throws -> KeyInfo {
        let info = KeyInfo(
            fid: fid,
            pubkey: pubkey,
            prikeyCipher: nil,
            label: label,
            kind: .watched,
            master: master
        )
        try addSubIdentity(info)
        return info
    }

    /// Register a **multisig group** this FID is a member of.
    ///
    /// Local, like every other sub-identity: a multisig address is
    /// derived from its members' public keys, so it needs no carve to
    /// come into being and no permission to record. What this stores
    /// that the other kinds do not is the group itself — members,
    /// order and m-of-n — because without the redeem script a 3…
    /// address is unspendable.
    ///
    /// Refuses a group the main FID does not belong to. Registering
    /// one would list an identity that can never be lived as, and the
    /// failure would only surface later, at signing time, as "not a
    /// member".
    @discardableResult
    public func addMultisigFid(
        _ multisig: Multisig,
        label: String = ""
    ) throws -> KeyInfo {
        guard let fid = multisig.id, !fid.isEmpty else {
            throw Failure.multisigIncomplete
        }
        guard multisig.contains(mainFid) else {
            throw Failure.notAMultisigMember(fid: mainFid, group: fid)
        }
        let info = KeyInfo(
            fid: fid,
            pubkey: nil,
            prikeyCipher: nil,
            label: label,
            kind: .multisig,
            multisig: multisig
        )
        try addSubIdentity(info)
        return info
    }

    /// The registered group behind a multisig FID, or nil if that FID
    /// is not a multisig entry of this Setting.
    public func multisigGroup(for fid: String) -> Multisig? {
        guard let info = setting.keyInfoMap[fid], info.kind == .multisig else { return nil }
        return info.multisig
    }

    /// Register a **servant** — a FID that has named this one as its
    /// master on chain.
    ///
    /// Purely local, and deliberately so: the relationship was created
    /// by the servant's own carve (see
    /// ``DirectoryService/myServants(of:after:size:timeoutMs:)``), so
    /// there is nothing for the master to publish. This only records
    /// which of them we want listed in the person menu.
    ///
    /// The entry carries no privkey *cipher*, so ``canSign`` is false
    /// for it until the servant's key is actually imported — even
    /// though ``KeyKind/canSign`` is true for the kind. That is the
    /// right way round: the kind says "a servant may act", the missing
    /// cipher says "we do not hold this one's key yet".
    @discardableResult
    public func addServantFid(
        _ fid: String,
        label: String = "",
        pubkey: Data? = nil
    ) throws -> KeyInfo {
        let info = KeyInfo(
            fid: fid,
            pubkey: pubkey,
            prikeyCipher: nil,
            label: label,
            kind: .servant,
            master: mainFid
        )
        try addSubIdentity(info)
        return info
    }

    /// Register any non-main ``KeyInfo`` (watched / multisig /
    /// servant — e.g. a master record fetched from the directory) in
    /// this Setting and persist. Refuses to overwrite the main entry.
    public func addSubIdentity(_ info: KeyInfo) throws {
        guard info.fid != mainFid else {
            throw Failure.cannotReplaceMain(fid: info.fid)
        }
        setting.keyInfoMap[info.fid] = info
        try saveSetting()
    }

    /// Rename a registered key. Whitespace-only input clears the label
    /// rather than storing a blank-looking one, so the FID bar falls
    /// back to its "add a label" affordance instead of showing an
    /// invisible name.
    ///
    /// For the main FID the label lives in two places — this Setting's
    /// `keyInfoMap` and the parent Configure's `mainCidInfoMap`, which
    /// is what the identity chooser reads before any Setting is
    /// decrypted — so both are written.
    public func setLabel(_ label: String, forFid fid: String) throws {
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var info = setting.keyInfoMap[fid] else {
            throw Failure.unknownLive(fid: fid)
        }
        if info.label != trimmed {
            info.label = trimmed
            setting.keyInfoMap[fid] = info
            try saveSetting()
        }
        if fid == mainFid {
            do {
                try configureSession.setMainLabel(trimmed, fid: fid)
            } catch {
                throw Failure.underlying(error)
            }
        }
    }

    @discardableResult
    public func removeSubIdentity(fid: String) throws -> Bool {
        guard fid != mainFid else { return false }   // never remove the main
        guard setting.keyInfoMap.removeValue(forKey: fid) != nil else {
            return false
        }
        if liveFid == fid { liveFid = mainFid }
        try saveSetting()
        return true
    }

    // MARK: - persistence

    /// Re-encrypt and write the Setting body file. Called automatically
    /// after any mutation; exposed for callers who batch changes.
    public func saveSetting() throws {
        let symkey: Data
        do {
            symkey = try configureSession.symkey()
        } catch {
            throw Failure.underlying(error)
        }
        do {
            try EncryptedFile.write(setting, to: settingUrl, key: symkey)
        } catch {
            throw Failure.underlying(error)
        }
    }

    // MARK: - lazy domain services

    public lazy var preferences: PreferencesStore = PreferencesStore(kv: storage)
    /// Saved SSH destinations. See ``SshServersStore`` for why the
    /// rows being encrypted matters more here than elsewhere.
    public lazy var sshServers: SshServersStore = SshServersStore(kv: storage)
    public lazy var contacts: ContactsStore = ContactsStore(kv: storage)
    public lazy var secrets: SecretsStore  = SecretsStore(kv: storage)
    public lazy var proofs: ProofsStore    = ProofsStore(kv: storage)
    /// Protocol drafts, the cached registry window and the hidden list —
    /// the first of the four Construct records. See ``ProtocolsStore``
    /// for why drafts and cache live in separate namespaces.
    public lazy var protocols: ProtocolsStore = ProtocolsStore(kv: storage)
    /// Code drafts, the cached registry window and the hidden list —
    /// the second of the four Construct records. Same shape as
    /// ``ProtocolsStore``, over the `code` index.
    public lazy var codes: CodesStore = CodesStore(kv: storage)

    /// Service drafts, the cached registry window and the hidden list —
    /// the third of the four Construct records. Same shape as
    /// ``CodesStore``, over the `service` index.
    ///
    /// **Not ``homeServices``.** That resolver caches SID→URL answers
    /// for the message path; this caches registry rows for the pane.
    /// Same index, different jobs — see ``ServicesStore``.
    public lazy var services: ServicesStore = ServicesStore(kv: storage)

    /// App drafts, the cached registry window and the hidden list — the
    /// last of the four Construct records. Same shape as ``CodesStore``,
    /// over the `app` index.
    public lazy var apps: AppsStore = AppsStore(kv: storage)
    /// Cached token ledgers, holdings, history and the two hidden
    /// lists. See ``TokensStore`` — everything in it is a cache except
    /// what the user chose to hide.
    /// Published text works — cached chain rows and local drafts. The
    /// first of the Publish family (Phase 8.8); see ``TextsStore``.
    public lazy var texts: TextsStore      = TextsStore(kv: storage)
    /// Annotations on published works, cached and drafted the same way.
    /// Keyed by remark id; the thread under a work is ``RemarksStore/all(on:)``.
    public lazy var remarks: RemarksStore  = RemarksStore(kv: storage)
    /// Formal statements — carved in full, and never touched again.
    /// The one Publish store with no update path; see ``StatementsStore``.
    public lazy var statements: StatementsStore = StatementsStore(kv: storage)

    /// Published images, sounds and videos — one store per kind, over
    /// the `image` / `sound` / `video` indices. Cheap to build (a
    /// namespace over ``storage``), so this is a function rather than
    /// three lazy properties.
    public func media(_ kind: MediaKind) -> MediaStore {
        MediaStore(kv: storage, kind: kind)
    }
    public lazy var tokens: TokensStore    = TokensStore(kv: storage)
    public lazy var mails: MailsStore      = MailsStore(kv: storage)
    public lazy var hats: HatsStore        = HatsStore(kv: storage)
    /// The cached on-chain activity window and its seen-watermark.
    /// The feed is public and identity-independent; what counts as
    /// *new* is not, which is why it lives on this identity's DB.
    public lazy var newsCache: NewsStore   = NewsStore(kv: storage)
    /// Chat threads (the index) and their transcripts (one namespace
    /// each) — see ``MessagesStore`` for why those are separate.
    public lazy var conversations: ConversationsStore = ConversationsStore(kv: storage)
    public lazy var messages: MessagesStore = MessagesStore(kv: storage)
    /// Versioned team/room keys. P2P is not in here — it seals
    /// AsyTwoWay and stores nothing.
    public lazy var symkeys: SymkeyStore = SymkeyStore(kv: storage)
    /// The durable outbox, and what we last observed about each peer.
    public lazy var outbox: MessageQueue = MessageQueue(kv: storage)
    public lazy var peers: PeerBook = PeerBook(kv: storage)
    public lazy var rooms: RoomsStore = RoomsStore(kv: storage)
    /// The two on-chain group flavours. Caches of what `base.search`
    /// says — unlike ``rooms``, losing them costs only a sync.
    public lazy var teams: TeamsStore = TeamsStore(kv: storage)
    public lazy var squares: SquaresStore = SquaresStore(kv: storage)

    /// On-chain group sync. Computed so a ``setFapi(_:)`` swap is
    /// picked up.
    public var groups: GroupService { GroupService(fapi: fapi) }

    /// What ``groups`` is for a team, for a room: the thing that carries
    /// a room record across into the row the chat list draws. A room has
    /// no chain to sync from, so every place that changes a room has to
    /// call this — there is no later pass that would notice.
    public var roomConversations: RoomConversations {
        RoomConversations(rooms: rooms, symkeys: symkeys, conversations: conversations)
    }

    /// Who each group row's avatar badges. A repair pass rather than a
    /// sync — it reads only local stores — so it is cheap enough to run
    /// whenever the chat list is drawn.
    public var groupOwners: GroupOwners {
        GroupOwners(rooms: rooms, teams: teams, squares: squares, conversations: conversations)
    }

    /// Turns the `home` map of a FID, team, square or room into URLs —
    /// what every delivery route needs before it can go anywhere.
    /// Lazy, so its SID→URL cache survives across sends.
    public lazy var homeServices: HomeServiceResolver = HomeServiceResolver(fapi: fapi)

    /// Sharing a file in a chat, over the Phase 8.4 two-HAT flow.
    public var fileShare: FileShareService {
        FileShareService(files: files, hats: hats, sync: hatSync)
    }

    /// Store-and-forward against our own DOCK — whatever server ``fapi``
    /// is pointed at. A put aimed at *someone else's* DOCK goes through
    /// this one's forwarding, which is what `targetDockUrl` is for.
    public var dockService: DockService { DockService(fapi: fapi) }

    /// Reads over the `text` and `remark` indices. Computed so a
    /// ``setFapi(_:)`` swap is picked up.
    public var publish: PublishService { PublishService(fapi: fapi) }

    /// The bytes behind a published work's `did` — store on publish,
    /// fetch on read. See ``PublishBody``.
    ///
    /// **The third read attempt is wired here and nowhere else.** A
    /// body we do not hold and our own DISK does not have is asked of
    /// the *publisher's* DISK, which means resolving their home map and
    /// opening a connection to a server we do not otherwise talk to.
    /// The client cache that can do that is ``dockRegistry`` — it is
    /// named for the first thing that needed it, but what it holds is
    /// one FAPI client per server, which is exactly what a foreign DISK
    /// needs too. Opening a second cache beside it would mean two
    /// sockets to the same host whenever a publisher's DOCK and DISK
    /// are the same machine, which is the normal case.
    public var publishBody: PublishBody {
        let directory = self.directory
        let resolver = self.homeServices
        let registry = self.dockRegistry
        return PublishBody(
            files: files, hats: hats, sync: hatSync, disk: disk,
            foreignDisk: { publisherFid in
                guard let freer = try? await directory.freerByIds([publisherFid])[publisherFid],
                      let url = await resolver.resolve(home: freer.home, key: ServiceName.disk),
                      let client = await registry.client(for: url)
                else { return nil }
                return DiskService(fapi: client)
            }
        )
    }

    /// Which DOCK each conversation lives on, and a connected client per
    /// server. Lazy and long-lived: it caches one connection per DOCK,
    /// and rebuilding it per send would open a new socket for every
    /// message. The app shell configures it (see
    /// ``DockRegistry/configure(ownDockUrl:ownClient:connect:)``)
    /// whenever the FAPI settings change.
    public lazy var dockRegistry: DockRegistry = DockRegistry(
        resolver: homeServices, kv: storage
    )

    /// Re-derive which DOCK each group we belong to lives on.
    ///
    /// Call after a group sync, after joining or leaving one, and at
    /// startup: the registry is what a collect polls, so a group missing
    /// from it is a conversation that silently receives nothing.
    ///
    /// **Keyed on the main FID, not the live one — deliberately.** Your
    /// mailbox does not follow an identity switch. The transport under
    /// this registry is a FUDP connection handshaked with
    /// ``mainPrikey()`` (the app shell has no other key to offer), so
    /// `ownDockUrl` is the *main's* server whoever you are living as.
    /// Passing `liveFid` here therefore did two wrong things at once
    /// while a sub-identity was live: it asked the main's DOCK for items
    /// addressed to a FID that server holds nothing for, and — because
    /// the group queries below are membership tests — it found no teams,
    /// squares or rooms and rebuilt the map with **every group entry
    /// dropped**, so group messages stopped arriving until something
    /// refreshed it again from the main.
    ///
    /// Pinning to `mainFid` also keeps the cursor rows
    /// (``DockRegistry/cursorNamespace``) on one key instead of
    /// churning a fresh set per identity.
    public func refreshDockRegistry() async {
        var groups: [DockRegistry.GroupRef] = []
        for team in (try? teams.joined(by: mainFid)) ?? [] {
            guard let id = team.id else { continue }
            groups.append(.init(id: id, type: .team, home: team.home))
        }
        for square in (try? squares.joined(by: mainFid)) ?? [] {
            guard let id = square.id else { continue }
            groups.append(.init(id: id, type: .square, home: square.home))
        }
        for room in (try? rooms.active()) ?? [] {
            guard let id = room.id, room.isMember(mainFid) else { continue }
            groups.append(.init(id: id, type: .room, home: room.home))
        }
        await dockRegistry.refresh(ownFid: mainFid, groups: groups)
    }

    /// The loop that moves messages: drains the outbox onto a DOCK and
    /// collects what one is holding for us.
    public var courier: MessageCourier {
        let teams = self.teams
        let squares = self.squares
        let rooms = self.rooms
        return MessageCourier(
            outbox: outbox,
            messages: messages,
            chat: chat,
            peers: peers,
            dock: dockService,
            resolver: homeServices,
            directory: DirectoryService(fapi: fapi),
            registry: dockRegistry,
            groupHome: { targetId in
                if let team = try? teams.get(id: targetId)?.home { return team }
                if let square = try? squares.get(id: targetId)?.home { return square }
                return try? rooms.get(id: targetId)?.home
            },
            routeSignal: signalRoute
        )
    }

    /// Room notifications, key shares and key requests.
    ///
    /// Built here and handed to the courier as a closure, because the
    /// router needs this identity's private key and four stores, and the
    /// courier should keep knowing about none of them.
    ///
    /// **Nil when the session cannot sign.** Every branch of the router
    /// either opens a key sealed to us or seals one to somebody else,
    /// and a watch-only session can do neither; a router without a key
    /// would answer "no" to everything, which is harder to read than not
    /// being there.
    private var signalRoute: (@Sendable (ImMessage, String, Date) throws -> SignalRouter.Outcome)? {
        guard let privkey = try? livePrikey(), let service = try? roomService else { return nil }
        let rooms = self.rooms
        let teams = self.teams
        let symkeys = self.symkeys
        let invites = self.roomInvites
        let contacts = self.contacts
        let roomConversations = self.roomConversations
        return { message, liveFid, now in
            let router = SignalRouter(
                rooms: rooms,
                teams: teams,
                symkeys: symkeys,
                invites: invites,
                roomService: service,
                roomConversations: roomConversations,
                privkey: privkey,
                pubkeys: { fid in try contacts.get(fid: fid)?.pubkey }
            )
            return try router.route(message, as: liveFid, now: now)
        }
    }

    /// Room invitations waiting for an answer.
    public lazy var roomInvites: RoomInvitesStore = RoomInvitesStore(kv: storage)

    /// Everything a DOCK fetch should ask for: this identity, plus every
    /// group it belongs to — a team's messages are addressed to the
    /// team, so asking only for our FID would collect none of them.
    public func dockRecipientIds() throws -> [String] {
        var ids = [liveFid]
        ids += try teams.joined(by: liveFid).compactMap(\.id)
        ids += try squares.joined(by: liveFid).compactMap(\.id)
        ids += try rooms.active().filter { $0.isMember(liveFid) }.compactMap(\.id)
        return ids
    }

    /// The send/receive path the chat pane and the transport share.
    ///
    /// The stranger gate is wired in here rather than at the call sites,
    /// so there is no way to receive a message on a path that skips it.
    public var chat: ChatService {
        let contacts = self.contacts
        return ChatService(
            messages: messages, conversations: conversations,
            symkeys: symkeys, outbox: outbox,
            policy: contactPolicy, requests: messageRequests,
            isContact: { fid in ((try? contacts.get(fid: fid)) ?? nil) != nil }
        )
    }

    /// Who may start a conversation with this identity.
    public lazy var contactPolicy: ContactPolicyStore = ContactPolicyStore(kv: storage)
    private lazy var requestsStore: MessageRequestsStore = MessageRequestsStore(kv: storage)

    /// Messages held from senders this identity has not agreed to hear
    /// from.
    public var messageRequests: MessageRequests {
        MessageRequests(
            requests: requestsStore, messages: messages, conversations: conversations
        )
    }

    /// Everything ``ChatGate`` needs to answer whether this identity may
    /// send into this conversation.
    ///
    /// Gathering the facts is this session's job because it owns the
    /// four stores they come from; deciding on them is ``ChatGate``'s,
    /// so the rule stays testable without any of this.
    ///
    /// A conversation whose backing record is *missing* reads as "not a
    /// member", which is the safe reading: a team we have never synced
    /// and a team we were thrown out of look identical from here, and of
    /// the two possible mistakes, refusing to send is the recoverable
    /// one.
    public func chatGateFacts(for conversation: Conversation) -> ChatGate.Facts {
        var facts = ChatGate.Facts(type: conversation.type, canSign: canSign)
        facts.leftGroup = conversation.leftGroup == true

        switch conversation.type {
        case .p2p:
            return facts

        case .room:
            let room = try? rooms.get(id: conversation.targetId)
            facts.isOwner = room?.isOwner(liveFid) ?? false
            facts.isMember = facts.isOwner || (room?.isMember(liveFid) ?? false)
            facts.hasDock = ChatGate.declaresDock(home: room?.home)
            // A closed room is one nobody may write in again, owner
            // included — the same shape as having been removed.
            if room?.isInactive == true { facts.leftGroup = true }

        case .team:
            let team = try? teams.get(id: conversation.targetId)
            facts.isOwner = team?.isOwner(liveFid) ?? false
            facts.isMember = facts.isOwner || (team?.isMember(liveFid) ?? false)
            facts.hasDock = ChatGate.declaresDock(home: team?.home)
            if team?.isActive == false { facts.leftGroup = true }

        case .square:
            let square = try? squares.get(id: conversation.targetId)
            facts.isMember = square?.isMember(liveFid) ?? false
            facts.hasDock = ChatGate.declaresDock(home: square?.home)
        }

        facts.hasSymkey = ChatGate.requiresSymkey(conversation.type)
            ? ((try? symkeys.has(entityId: conversation.targetId)) ?? false)
            : true
        return facts
    }

    /// The room protocol. Computed so it always carries the *live*
    /// identity's privkey — a sub-identity joins rooms as itself, and a
    /// service holding the main's key would open its shared keys with
    /// the wrong one.
    public var roomService: RoomService {
        get throws {
            RoomService(rooms: rooms, symkeys: symkeys).withPrivkey(try livePrikey())
        }
    }

    /// Who may make a team's key. No privkey needed: a team's keys are
    /// minted and sealed *outward*, and opening one that arrives is
    /// ``SignalRouter``'s job.
    public var teamKeys: TeamKeyService {
        TeamKeyService(teams: teams, symkeys: symkeys)
    }

    /// A member's public key, as fresh as this device can answer without
    /// a round-trip — what a key share is sealed to.
    public func knownPubkey(of fid: String) throws -> Data? {
        try contacts.get(fid: fid)?.pubkey
    }

    /// A member's `home` map, which is how we know whether there is
    /// anywhere to leave a message for them.
    ///
    /// **A contact we have never fetched reads as "no home", and that is
    /// the honest answer rather than a pessimistic one**: the check it
    /// feeds only ever decides whether to *queue* an invitation now, and
    /// queueing one for somebody with nowhere to receive it means a
    /// message the outbox retries forever. The owner can share again
    /// once the directory knows them.
    public func knownHome(of fid: String) throws -> [String: String]? {
        try contacts.get(fid: fid)?.home
    }

    /// Reference-mode file layer over ``hats``.
    public lazy var files: FileVault       = FileVault(hats: hats, dataDirectory: dataDirectory)
    public lazy var keys: KeysStore        = KeysStore(kv: storage)
    public lazy var cashes: CashesStore    = CashesStore(kv: storage)
    public lazy var recentActivity: RecentActivityStore = RecentActivityStore(kv: storage)
    public lazy var liveFidInfoCache: LiveFidInfoStore = LiveFidInfoStore(kv: storage)

    /// Asked to approve every transaction before it is signed, when
    /// the identity has that setting on. The app installs a closure
    /// here that raises a modal; leave it nil (tests, headless
    /// callers) and nothing is asked.
    ///
    /// **Held on the session, not passed per call**, because the
    /// signing paths are twenty-odd carve helpers spread across this
    /// file and every pane in the app — a parameter would be one more
    /// thing each of them could forget, and forgetting it silently
    /// disables the confirmation for exactly the operations the user
    /// understands least.
    public var txApprover: TxApprover?

    /// Cached answer for ``confirmBeforeSigning``. ``wallet`` is a
    /// computed property that half the app touches, and decrypting the
    /// preferences row on every touch to re-read one boolean is a
    /// silly amount of work. Cleared by ``reloadPreferences()``, which
    /// the Settings pane calls when it saves.
    private var confirmBeforeSigningCache: Bool?

    /// True when this identity wants to see transactions before they
    /// are signed. Defaults on, and a preferences read that fails
    /// counts as on: the failure mode of asking too often is a click,
    /// the failure mode of not asking is a spend nobody saw.
    public var confirmBeforeSigning: Bool {
        if let confirmBeforeSigningCache { return confirmBeforeSigningCache }
        let value = ((try? preferences.load())?.confirmBeforeSigning) ?? true
        confirmBeforeSigningCache = value
        return value
    }

    /// Drop anything cached from the preferences row. Call after
    /// writing preferences through ``preferences`` directly.
    public func reloadPreferences() {
        confirmBeforeSigningCache = nil
    }

    /// The approver the wallet actually gets: nil when the identity
    /// has turned confirmation off, so the gate costs nothing.
    private var effectiveApprover: TxApprover? {
        guard let txApprover, confirmBeforeSigning else { return nil }
        return txApprover
    }

    /// Computed (not lazy) so ``setFapi(_:)`` is picked up the next
    /// time something asks for the wallet. WalletService is a struct;
    /// constructing it is essentially a Foundation pointer copy.
    public var wallet: WalletService {
        WalletService(
            fapi: fapi, cashes: cashes, recentActivity: recentActivity,
            approve: effectiveApprover
        )
    }

    /// Identity-directory lookups (`base.freerByIds`). Computed so a
    /// `setFapi(_:)` swap is picked up immediately.
    public var directory: DirectoryService {
        DirectoryService(fapi: fapi)
    }

    // MARK: - live FID on-chain stats

    /// The cached on-chain record for the live FID, or an empty one if
    /// this identity has never been fetched. Never throws upward: a
    /// missing or undecodable cache row is a blank bar, not an error
    /// screen.
    public func cachedLiveFidInfo() -> LiveFidInfo {
        (try? liveFidInfoCache.get(fid: liveFid)) ?? LiveFidInfo(fid: liveFid)
    }

    /// Fetch the live FID's on-chain record and fold it into the cache.
    ///
    /// One `base.freerByIds` call covers everything the FID bar shows —
    /// balance, cash count, CD, weight, reputation, hot, CID and the
    /// nobody flag — which is why the bar does not also call
    /// `base.balanceByIds`. Both read the same chain index, so a second
    /// call would buy nothing but latency.
    ///
    /// A FID with no on-chain record yet is not an error: `freerByIds`
    /// simply omits it, and the cached row is stamped as fetched so the
    /// bar stops showing a spinner.
    @discardableResult
    public func refreshLiveFidInfo(timeoutMs: Int = 5_000) async throws -> LiveFidInfo {
        let fid = liveFid
        let found = try await directory.freerByIds([fid], timeoutMs: timeoutMs)
        let base = (try? liveFidInfoCache.get(fid: fid)) ?? LiveFidInfo(fid: fid)
        let updated: LiveFidInfo
        if let freer = found[fid] {
            updated = base.merging(freer)
        } else {
            var stamped = base
            stamped.fetchedAt = Date()
            updated = stamped
        }
        try liveFidInfoCache.upsert(updated)
        // A CID is the one value from that reply worth writing back into
        // the KeyInfo. Everything else ticks; this is a name someone
        // registered, and the identity chooser needs it before any
        // Setting is decrypted. The write is guarded, so the ordinary
        // case — a CID that has not changed, or was never there — costs
        // nothing.
        try? persistCid(updated.cid, forFid: fid)
        return updated
    }

    /// Fold a freshly-seen CID into the stored ``KeyInfo``, in both
    /// places a main FID's identity lives. No-ops unless it changed.
    private func persistCid(_ cid: String?, forFid fid: String) throws {
        let trimmed = cid?.trimmingCharacters(in: .whitespacesAndNewlines)
        let value = (trimmed?.isEmpty ?? true) ? nil : trimmed
        guard var info = setting.keyInfoMap[fid], info.cid != value else { return }
        info.cid = value
        setting.keyInfoMap[fid] = info
        try saveSetting()
        if fid == mainFid {
            do {
                try configureSession.setMainCid(value, fid: fid)
            } catch {
                throw Failure.underlying(error)
            }
        }
    }

    /// On-chain secret sync (`base.search` over entity `secret`).
    /// Computed so a `setFapi(_:)` swap is picked up immediately.
    public var secretService: SecretService {
        SecretService(fapi: fapi)
    }

    /// On-chain mail sync (`base.search` over entity `mail`).
    public var mailService: MailService {
        MailService(fapi: fapi)
    }

    /// The chain-wide activity feed (`base.search` over entity `news`).
    /// Needs no key — see ``NewsService``.
    public var newsService: NewsService {
        NewsService(fapi: fapi)
    }

    /// On-chain proof reads (`base.search` over entity `proof`).
    /// Needs no key either — a proof is public by construction.
    public var proofService: ProofService {
        ProofService(fapi: fapi)
    }

    /// On-chain protocol-registry reads (`base.search` over entity
    /// `protocol`). Needs no key, and unlike ``proofService`` the index
    /// is chain-wide: the point of a registry is looking up what other
    /// people published.
    public var protocolService: ProtocolService {
        ProtocolService(fapi: fapi)
    }

    /// On-chain code-registry reads (`base.search` over entity `code`).
    /// Chain-wide and key-free for the same reasons as
    /// ``protocolService``: a published implementation is public, and
    /// the point of the index is looking up other people's.
    public var codeService: CodeService {
        CodeService(fapi: fapi)
    }

    /// Chain reads over the `service` index for the Service pane.
    /// Named `serviceRegistry` rather than `serviceService`; see the
    /// type's note on why it is separate from ``directory``.
    public var serviceRegistry: ServiceRegistry {
        ServiceRegistry(fapi: fapi)
    }

    /// Chain reads over the `app` index for the Apps pane.
    public var appService: AppService {
        AppService(fapi: fapi)
    }

    /// On-chain token reads (`base.search` over entities `token`,
    /// `token_holder` and `token_history`). Needs no key — a token
    /// ledger is public, so a watch-only identity can watch a balance
    /// it cannot move.
    public var tokenService: TokenService {
        TokenService(fapi: fapi)
    }

    /// DISK endpoints of the configured FAPI service.
    public var disk: DiskService {
        DiskService(fapi: fapi)
    }

    /// The two-HAT upload/download flows over ``disk``, ``hats`` and
    /// ``files``. Computed so a `setFapi(_:)` swap is picked up.
    ///
    /// `serviceSid` tags new uploads with a `(sid)` location, which
    /// survives the server changing address; it comes from the saved
    /// preferences when the user has pinned a DISK provider.
    public var hatSync: HatSyncService {
        HatSyncService(
            disk: disk,
            hats: hats,
            files: files,
            serviceSid: try? preferences.load().preferredDiskServiceSid,
            serviceUrl: try? preferences.load().preferredFapiService
        )
    }

    // MARK: - mutating fapi

    /// Replace the active FAPI client. Used by the app shell after
    /// the user saves new server settings — the previous client (and
    /// its underlying transport) is released and the next call to
    /// `wallet`/`fapi` uses the new one. The caller is responsible
    /// for closing the *previous* transport if it owns one (the
    /// `ActiveSession` is type-erased to `FapiCalling` and can't
    /// know how to tear it down).
    /// **Every long-lived holder has to be told.** Most services here
    /// are computed properties that read `fapi` afresh, so they pick the
    /// new client up for free. ``homeServices`` is the exception: it is
    /// lazy, because its SID→URL cache has to outlive a send, which
    /// means it captured whatever client existed the first time anyone
    /// touched it — the stub, if a view rendered before the real client
    /// was built. See ``HomeServiceResolver/setFapi(_:)``.
    public func setFapi(_ client: any FapiCalling) {
        self.fapi = client
        homeServices.setFapi(client)
    }

    // MARK: - send convenience

    /// Send from the **live** FID. Throws for watch-only —
    /// callers should fall back to a cold-sign builder (Phase 8).
    /// `using` names the exact cashes to spend — the Cash pane's
    /// Send, where the user ticked them. Leave it nil for the Send
    /// pane, which lets coin selection decide.
    @discardableResult
    public func sendFromLive(
        to toFid: String,
        amount: Int64,
        feePerByte: Int64 = 1,
        useCache: Bool = false,
        using chosenInputs: [Cash]? = nil,
        timeoutMs: Int = 10_000
    ) async throws -> WalletService.SendResult {
        let priv = try livePrikey()
        return try await wallet.send(
            fromAddress: liveFid, privkey: priv,
            to: toFid, amount: amount,
            feePerByte: feePerByte,
            useCache: useCache,
            using: chosenInputs,
            timeoutMs: timeoutMs
        )
    }

    /// Build (but don't sign or broadcast) a send from the **live**
    /// FID — the cold-sign path for watch-only identities. Works for
    /// any live FID; ``canSign`` tells the UI which button to show.
    public func buildUnsignedSendFromLive(
        to toFid: String,
        amount: Int64,
        feePerByte: Int64 = 1,
        useCache: Bool = false,
        using chosenInputs: [Cash]? = nil,
        timeoutMs: Int = 10_000
    ) async throws -> WalletService.UnsignedSendResult {
        try await wallet.buildUnsignedSend(
            fromAddress: liveFid,
            to: toFid, amount: amount,
            feePerByte: feePerByte,
            useCache: useCache,
            using: chosenInputs,
            timeoutMs: timeoutMs
        )
    }

    // MARK: - advanced (composed) transaction convenience

    /// Sign and broadcast a composed transaction from the **live**
    /// FID. Throws for watch-only — use
    /// ``buildUnsignedAdvancedFromLive`` there.
    ///
    /// The document's `sender` is forced to the live FID rather than
    /// trusted: an imported one names whoever composed it, and signing
    /// with this key on that document's behalf would build a
    /// transaction whose change goes to a stranger.
    @discardableResult
    public func sendAdvancedFromLive(
        info: RawTxInfo,
        inputCashes: [Cash],
        bestHeight: Int64 = 0,
        timeoutMs: Int = 10_000
    ) async throws -> WalletService.SendResult {
        let priv = try livePrikey()
        var info = info
        info.sender = liveFid
        if info.changeTo == nil { info.changeTo = liveFid }
        return try await wallet.sendAdvanced(
            info: info,
            inputCashes: inputCashes,
            privkey: priv,
            fromAddress: liveFid,
            bestHeight: bestHeight,
            timeoutMs: timeoutMs
        )
    }

    /// The cold-sign half of ``sendAdvancedFromLive``. Needs no key.
    public func buildUnsignedAdvancedFromLive(
        info: RawTxInfo,
        bestHeight: Int64 = 0
    ) throws -> WalletService.UnsignedSendResult {
        var info = info
        info.sender = liveFid
        if info.changeTo == nil { info.changeTo = liveFid }
        return try wallet.buildUnsignedAdvanced(info: info, bestHeight: bestHeight)
    }

    // MARK: - reorg convenience

    /// Split or consolidate the live FID's own cashes. Throws for
    /// watch-only — use ``buildUnsignedReorgFromLive`` there.
    @discardableResult
    public func reorganizeFromLive(
        inputs: [Cash],
        shape: CashReorg.Shape,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> WalletService.ReorgResult {
        let priv = try livePrikey()
        return try await wallet.reorganize(
            fromAddress: liveFid, privkey: priv,
            inputs: inputs, shape: shape,
            feePerByte: feePerByte,
            timeoutMs: timeoutMs
        )
    }

    /// The cold-sign half of ``reorganizeFromLive``. Needs no key, so
    /// it works for any live FID.
    public func buildUnsignedReorgFromLive(
        inputs: [Cash],
        shape: CashReorg.Shape,
        feePerByte: Int64 = 1
    ) throws -> WalletService.UnsignedReorgResult {
        try wallet.buildUnsignedReorg(
            fromAddress: liveFid,
            inputs: inputs, shape: shape,
            feePerByte: feePerByte
        )
    }

    // MARK: - contact carving (FEIP CONTACT)

    /// Write `contact`'s editable detail onto the chain, encrypted to
    /// the live FID's own pubkey. Mirrors Android's
    /// `ContactActivity.sendContactOnChain` → `makeAddContactFeip` →
    /// `TxSender.carveSimpleFeip`. When the contact already has a
    /// known carve (``Contact/carveId``), an `update` op targeting it
    /// is carved instead of a duplicate `add`.
    ///
    /// Returns the broadcast txid. The local row is *not* flipped to
    /// on-chain here — the next chain sync picks the carve up once a
    /// block confirms it.
    @discardableResult
    public func carveContactOnChain(
        _ contact: Contact,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let ownPubkey: Data
        do {
            ownPubkey = try Secp256k1.publicKey(fromPrivateKey: priv)
        } catch {
            throw Failure.underlying(error)
        }
        let detail = try ContactFeip.detailJson(for: contact)
        let cipher = try AsyOneWayCipher.encrypt(
            plaintext: Data(detail.utf8), toPubkey: ownPubkey
        )
        let opJson: String
        if let carveId = contact.carveId, !carveId.isEmpty {
            opJson = try ContactFeip.updateOp(contactId: carveId, cipher: cipher)
        } else {
            opJson = try ContactFeip.addOp(cipher: cipher)
        }
        let feipJson = ContactFeip.envelope(opJson: opJson)
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Carve a `delete` op deactivating the given carve records.
    /// Returns the broadcast txid. Callers usually also remove the
    /// local row; the next sync would do it anyway once the delete
    /// confirms.
    @discardableResult
    public func carveContactDeleteOnChain(
        carveIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let feipJson = ContactFeip.envelope(
            opJson: try ContactFeip.deleteOp(contactIds: carveIds)
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    // MARK: - multisig co-signing

    /// Propose a spend from a multisig group: pick its coins, price the
    /// transaction, and produce the document its members will sign.
    ///
    /// Nothing is signed here and nothing is reserved — a proposal is
    /// just a description until m members have agreed to it. The
    /// proposer need not be one of them.
    ///
    /// The group's coins are watch-only from this wallet's point of
    /// view (nobody holds a key to a 3… address), so this reuses the
    /// same cold-sign document the watch-only Send path builds, then
    /// repairs anything the chain left off the inputs.
    public func proposeMultisigSpend(
        groupFid: String,
        to recipient: String,
        amount: Int64,
        feePerByte: Int64 = 1,
        useCache: Bool = false,
        timeoutMs: Int = 10_000
    ) async throws -> RawTxInfo {
        guard let group = multisigGroup(for: groupFid) else {
            throw Failure.unknownLive(fid: groupFid)
        }
        let unsigned = try await wallet.buildUnsignedSend(
            fromAddress: groupFid,
            to: recipient,
            amount: amount,
            feePerByte: feePerByte,
            useCache: useCache,
            timeoutMs: timeoutMs
        )
        var info = unsigned.info
        info.inputs = try Self.repairMultisigRedeemScripts(info.inputs ?? [], group: group)
        info.senderMultisig = group
        return info
    }

    /// Fill in the redeem script on any input that arrived without one.
    ///
    /// A multisig input is unsignable without it, and the index does
    /// not always carry it. It is reconstructible because the script is
    /// a function of the group and the input's own lock time — the same
    /// repair ``AdvancedTxBuilder/fillMissingRedeemScripts(_:)`` does
    /// for single-sig CLTV.
    static func repairMultisigRedeemScripts(
        _ slots: [RawTxInfo.Slot], group: Multisig
    ) throws -> [RawTxInfo.Slot] {
        try slots.map { slot in
            guard slot.redeemScript == nil || slot.redeemScript?.isEmpty == true
            else { return slot }
            var repaired = slot
            let lock = (slot.lockTime ?? 0) > 0 ? slot.lockTime : nil
            repaired.redeemScript = try group.redeemScript(lockTime: lock)
            return repaired
        }
    }

    /// Add this Setting's main FID to a co-sign document.
    ///
    /// Signing is deliberately keyed on the **main** FID rather than
    /// the live one: the multisig entry itself holds no key, so living
    /// as the group and asking it to sign is a contradiction — the
    /// signature that satisfies the group comes from a member, and the
    /// member this Setting can act as is its main.
    public func signMultisigDocument(_ info: RawTxInfo) throws -> RawTxInfo {
        var priv = try mainPrikey()
        defer { priv.resetBytes(in: 0..<priv.count) }
        return try MultisigCosign.sign(info, privkey: priv)
    }

    /// Assemble a document that has reached its threshold and broadcast
    /// it. Returns the txid.
    @discardableResult
    public func broadcastMultisigDocument(
        _ info: RawTxInfo, timeoutMs: Int = 10_000
    ) async throws -> String {
        let serialized = try MultisigCosign.assemble(info)
        return try await wallet.broadcastRaw(serialized, timeoutMs: timeoutMs)
    }

    // MARK: - master carving (FEIP Master)

    /// Name `masterFid` as this main FID's master, on chain.
    ///
    /// **This publishes the main FID's private key.** Sealed to the
    /// master's pubkey, but published: the cipher goes into a permanent
    /// OP_RETURN that anyone can read, and whoever holds the master's
    /// private key can open it. From the moment it confirms, the master
    /// can spend this FID's coins, sign as it, and read everything ever
    /// encrypted to it. See ``MasterFeip`` for the protocol's own words
    /// on that.
    ///
    /// **It cannot be undone.** A later carve can name a different
    /// master, but the first record stays on chain, so the first master
    /// keeps what it was given. Callers must put that in front of the
    /// user in those terms before calling — the tx-approval dialog
    /// shows a fee and a payload, which is not the same warning.
    ///
    /// Mirrors Android's `SetMasterActivity.confirmSetMaster` →
    /// `FeipHandler.masterSet` → `TxSender.carveSimpleFeip`, with two
    /// checks Android leaves to its UI: the pubkey must actually be
    /// `masterFid`'s, and the master may not be the FID itself.
    ///
    /// On a successful broadcast the local `master` field is written so
    /// the person menu reflects it at once; the chain record is what
    /// counts, and the next sync re-reads it.
    @discardableResult
    public func carveMasterOnChain(
        masterFid: String,
        masterPubkey: Data,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        // A master belongs to the main FID: the key being sealed is the
        // main's, and the carve is paid and signed by it. Living as a
        // sub-identity while doing this would carve from the wrong FID.
        guard liveFid == mainFid else {
            throw Failure.masterNeedsMain(live: liveFid)
        }
        guard masterFid != mainFid else {
            throw Failure.masterIsSelf(fid: masterFid)
        }
        // The FID must be the one this pubkey hashes to. Without this a
        // mixed-up pair would seal the private key to a stranger, and
        // the carve would look correct on chain while having handed the
        // identity to whoever holds *that* key.
        let derived: String
        do {
            derived = try FchAddress(publicKey: masterPubkey).fid
        } catch {
            throw Failure.underlying(error)
        }
        guard derived == masterFid else {
            throw Failure.masterPubkeyMismatch(fid: masterFid, derived: derived)
        }

        var priv = try mainPrikey()
        defer { priv.resetBytes(in: 0..<priv.count) }

        let cipher = try AsyOneWayCipher.encrypt(plaintext: priv, toPubkey: masterPubkey)
        let opJson = try MasterFeip.setOp(master: masterFid, cipherPriKey: cipher)
        let feipJson = MasterFeip.envelope(opJson: opJson)
        let result = try await wallet.carve(
            fromAddress: mainFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )

        // Broadcast succeeded — record it locally so the menu stops
        // saying "not set" before the next sync runs.
        if var info = setting.keyInfoMap[mainFid] {
            info.master = masterFid
            setting.keyInfoMap[mainFid] = info
            try saveSetting()
        }
        return result.remoteTxid
    }

    // MARK: - secret carving (FEIP Secret)

    /// Write a secret's detail onto the chain, encrypted to the live
    /// FID's own pubkey. Mirrors Android's `CreateSecretActivity.
    /// carveSecret` → `makeAddSecretFeip` → `TxSender.carveSimpleFeip`.
    /// `content` is passed explicitly because the stored row holds only
    /// the cipher — callers decrypt (or still have the fresh input)
    /// before carving. Carves an `update` op when the secret already
    /// has a known carve id.
    ///
    /// Returns the broadcast txid; the caller re-keys/refreshes the
    /// local row (the next sync merges by that txid).
    @discardableResult
    public func carveSecretOnChain(
        _ secret: Secret,
        content: String,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let ownPubkey: Data
        do {
            ownPubkey = try Secp256k1.publicKey(fromPrivateKey: priv)
        } catch {
            throw Failure.underlying(error)
        }
        let detail = try SecretFeip.detailJson(
            type: secret.type, title: secret.title,
            content: content, memo: secret.memo
        )
        let cipher = try AsyOneWayCipher.encrypt(
            plaintext: Data(detail.utf8), toPubkey: ownPubkey
        )
        let opJson: String
        if let carveId = secret.carveId, !carveId.isEmpty {
            opJson = try SecretFeip.updateOp(secretId: carveId, cipher: cipher)
        } else {
            opJson = try SecretFeip.addOp(cipher: cipher)
        }
        let feipJson = SecretFeip.envelope(opJson: opJson)
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    // MARK: - mail (Phase 9.1.3)

    /// What it will cost to mail someone, and whether we can at all.
    ///
    /// Produced before the user writes anything, because both of its
    /// answers change the shape of the compose screen: an unknown
    /// pubkey means the mail cannot be encrypted *at all*, and a fee
    /// over the limit means it will not be sent. Finding either out
    /// after the user has typed a page is the wrong order.
    public struct MailQuote: Sendable {
        public let recipientFid: String
        /// Nil when the FID has never published a pubkey — nothing has
        /// ever been signed from it — so there is nothing to encrypt to.
        public let recipientPubkey: Data?
        public let fee: NoticeFee.Decision
        /// The fee as the recipient published it (coins), for display.
        public let publishedNoticeFee: String?

        public var canSend: Bool { recipientPubkey != nil && fee.satoshis != nil }
    }

    /// Look up a recipient's on-chain record and decide the notice fee.
    ///
    /// `replyingTo` is the mail being answered, if any: its
    /// ``Mail/noticeFee`` is what that correspondent paid us, which the
    /// pay-back rule may match. Pass nil for a fresh mail.
    public func quoteMail(
        to recipientFid: String,
        replyingTo: Mail? = nil,
        timeoutMs: Int = 10_000
    ) async throws -> MailQuote {
        let freer = try? await directory.freerByIds([recipientFid], timeoutMs: timeoutMs)[recipientFid]
        let prefs = (try? preferences.load()) ?? .defaults

        let fee = NoticeFee.decide(
            recipientNoticeFee: freer?.noticeFee,
            maxPayingSats: prefs.maxPayingNoticeFeeSats ?? NoticeFee.defaultMaxPayingSats,
            payBack: prefs.payBackNoticeFee ?? true,
            receivedNoticeFeeSats: replyingTo?.noticeFee
        )
        return MailQuote(
            recipientFid: recipientFid,
            recipientPubkey: freer?.pubkey.flatMap { Data(fcHex: $0) },
            fee: fee,
            publishedNoticeFee: freer?.noticeFee
        )
    }

    /// A mail that has been broadcast.
    public struct SentMail: Sendable {
        public let txid: String
        /// The stored row: sealed, id = the carve txid.
        public let mail: Mail
        public let noticeFeePaidSats: Int64
    }

    /// Encrypt, carve, and store a mail. The carve pays the recipient —
    /// that payment is how the mail is addressed, not a courtesy — so
    /// this goes through ``WalletService/carve(fromAddress:privkey:opReturn:payTo:payAmount:feePerByte:useCache:timeoutMs:)``
    /// rather than the paymentless path contacts and secrets use.
    ///
    /// Takes a ``MailQuote`` rather than a raw amount so a fee the user
    /// declined cannot be paid by a caller that forgot to check: a
    /// `.refuse` decision has no satoshi value to spend.
    public func sendMailOnChain(
        quote: MailQuote,
        content: String,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> SentMail {
        guard let feeSats = quote.fee.satoshis else {
            guard case let .refuse(requested, limit) = quote.fee else {
                throw Failure.underlying(MailFailure.noFee)
            }
            throw Failure.underlying(MailFailure.feeOverLimit(requested: requested, limit: limit))
        }
        guard let recipientPubkey = quote.recipientPubkey else {
            throw Failure.underlying(MailFailure.recipientHasNoPubkey(quote.recipientFid))
        }
        let priv = try livePrikey()

        var mail = Mail(from: liveFid, to: quote.recipientFid, content: content)
        try mail.encryptContent(privkey: priv, recipientPubkey: recipientPubkey)
        guard let cipher = mail.cipher else {
            throw Failure.underlying(MailFailure.noFee)
        }
        // Throws before anything is broadcast when the body is too big
        // for an OP_RETURN.
        let feipJson = try MailFeip.sendCarve(cipher: cipher)

        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            payTo: quote.recipientFid, payAmount: feeSats,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )

        // Android's post-broadcast stamping: the id becomes the txid,
        // `onChain` stays nil (broadcast ≠ confirmed), and lastHeight
        // takes the sentinel so the mail sits at the top of the list
        // until a sync replaces it with a real height.
        mail.id = result.remoteTxid
        mail.onChain = nil
        mail.birthTime = Int64(Date().timeIntervalSince1970)
        mail.lastHeight = MailsStore.unconfirmedHeight
        mail.noticeFee = feeSats
        mail.unread = false
        mail.active = true
        try mails.upsert(mail)

        return SentMail(txid: result.remoteTxid, mail: mail, noticeFeePaidSats: feeSats)
    }

    /// Publish what this FID charges to receive mail (FEIP `NoticeFee`,
    /// sn 10). Pays nobody — it is a statement about us, not a message.
    ///
    /// There is no delete op: republishing overwrites, and `0` is how
    /// you stop charging. Note that a fee only takes effect for senders
    /// once the carve confirms *and* their client re-reads your record,
    /// so raising it is not retroactive against mail already in flight.
    @discardableResult
    public func carveNoticeFeeOnChain(
        satoshis: Int64,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try NoticeFeeFeip.carve(satoshis: satoshis),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// What this FID currently publishes as its notice fee, in satoshis,
    /// or nil if it publishes none. Read from the chain rather than
    /// remembered locally: the carve may have been made from another
    /// device, and a stale local copy would mislead about what senders
    /// are actually being charged.
    public func publishedNoticeFee(timeoutMs: Int = 10_000) async throws -> Int64? {
        let freer = try await directory.freerByIds([liveFid], timeoutMs: timeoutMs)[liveFid]
        return NoticeFee.satoshis(coinString: freer?.noticeFee)
    }

    /// Carve a `delete` (or `recover`) op over the given mail carve ids.
    /// Pays nobody — only a `send` addresses anyone.
    @discardableResult
    public func carveMailDeleteOnChain(
        mailIds: [String],
        recover: Bool = false,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let opJson = recover
            ? try MailFeip.recoverOp(mailIds: mailIds)
            : try MailFeip.deleteOp(mailIds: mailIds)
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: MailFeip.envelope(opJson: opJson),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    public enum MailFailure: Error, CustomStringConvertible {
        case recipientHasNoPubkey(String)
        case feeOverLimit(requested: Int64, limit: Int64)
        case noFee

        public var description: String {
            switch self {
            case .recipientHasNoPubkey(let fid):
                return "\(fid) has never published a public key, so there is nothing to encrypt a mail to. They need to spend from that FID at least once."
            case let .feeOverLimit(requested, limit):
                return "This FID charges \(NoticeFee.coinString(satoshis: requested)) F to receive mail, over your \(NoticeFee.coinString(satoshis: limit)) F limit."
            case .noFee:
                return "the mail could not be prepared for sending"
            }
        }
    }

    // MARK: - group carves

    /// Join a team, agreeing to `consensusId`.
    ///
    /// The consensus id is quoted back in the carve alongside a fixed
    /// sentence, so joining is a signed statement about *which* document
    /// was agreed to. Passing a stale one would sign agreement to
    /// something the team has since replaced, which is why callers
    /// should read it from the team record they just synced rather than
    /// from a cached copy.
    @discardableResult
    public func carveTeamJoinOnChain(
        teamId: String,
        consensusId: String?,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveGroupOp(
            TeamFeip.envelope(opJson: try TeamFeip.joinOp(tid: teamId, consensusId: consensusId)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    /// Leave one or more teams in a single carve — the protocol takes a
    /// list, and for a paid operation that is the difference between one
    /// fee and several.
    @discardableResult
    public func carveTeamLeaveOnChain(
        teamIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveGroupOp(
            TeamFeip.envelope(opJson: try TeamFeip.leaveOp(tids: teamIds)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    /// Create a team.
    ///
    /// **The team's id is the carve's txid**, which is why nothing is
    /// returned but that: there is no local record to make, and the team
    /// only exists once the transaction confirms and the indexer has
    /// seen it. A row appears here on the next sync, not now.
    ///
    /// `consensusId` names the document members agree to when they join
    /// — the `join` op quotes it, and that quotation in a signed
    /// transaction is what makes agreement a public act rather than a
    /// checkbox. A team created without one has nothing for its members
    /// to agree *to*.
    @discardableResult
    public func carveTeamCreateOnChain(
        stdName: String,
        desc: String? = nil,
        consensusId: String? = nil,
        home: [String: String]? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveGroupOp(
            TeamFeip.envelope(
                opJson: try TeamFeip.createOp(
                    stdName: stdName, consensusId: consensusId, desc: desc, home: home
                )
            ),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    /// Create a square. Same shape as a team's create, and the same
    /// caveat about the id — but no consensus document, because a square
    /// has no membership to agree to anything: anyone may join.
    @discardableResult
    public func carveSquareCreateOnChain(
        name: String,
        desc: String? = nil,
        home: [String: String]? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveGroupOp(
            SquareFeip.envelope(
                opJson: try SquareFeip.createOp(name: name, desc: desc, home: home)
            ),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    /// Change a team's name, consensus document, description or home —
    /// the port of Android's `UpdateTeamActivity`.
    ///
    /// **Only the fields you pass travel.** A `nil` is *absent* from the
    /// carve, and an absent field is one the update does not speak
    /// about; there is no way to say "clear this" in the op, which is
    /// why an empty description box must be sent as an empty string
    /// rather than as nothing. `home` is the exception: an empty map is
    /// omitted, so a team's DOCK can be moved but not withdrawn.
    ///
    /// **The consensus document is the team's constitution, and swapping
    /// it is not a cosmetic edit.** Members joined by signing agreement
    /// to the one that was quoted at the time; naming a different one
    /// here leaves every existing member holding an agreement to a
    /// document the team no longer runs on, which the chain records as
    /// `notAgreeMembers` until each of them carves an `agree consensus`.
    @discardableResult
    public func carveTeamUpdateOnChain(
        teamId: String,
        stdName: String? = nil,
        consensusId: String? = nil,
        desc: String? = nil,
        home: [String: String]? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveGroupOp(
            TeamFeip.envelope(
                opJson: try TeamFeip.updateOp(
                    tid: teamId, stdName: stdName, consensusId: consensusId,
                    desc: desc, home: home
                )
            ),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    /// Change a square's name, description or home — the port of
    /// Android's `UpdateSquareActivity`.
    ///
    /// **The CoinDays are the permission.** A square has no owner, no
    /// manager, and no list of who may rename it: *anyone* may update
    /// one, provided the transaction destroys **more** coin-days than
    /// the last update destroyed. ``Square/cddToUpdate`` is that last
    /// figure, so the price rises every time somebody pays it — which is
    /// the whole of a square's governance, and why nothing here checks
    /// who is asking.
    ///
    /// The requirement is read from the square's own record, so a caller
    /// cannot forget to pay it; passing it in is for tests and for a
    /// record this device has not synced. The carve must beat it rather
    /// than match it, exactly as Android refuses on
    /// `totalCd <= cddToUpdate`.
    ///
    /// A square nobody has updated yet states no figure, and then the
    /// floor is 1 CD — what any FEIP carve costs — so it never drops
    /// below the rule everything else already obeys.
    @discardableResult
    public func carveSquareUpdateOnChain(
        squareId: String,
        name: String? = nil,
        desc: String? = nil,
        home: [String: String]? = nil,
        cddToUpdate: Int64? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let onRecord = (try? squares.get(id: squareId))??.cddToUpdate
        let required = max(0, cddToUpdate ?? onRecord ?? 0)
        return try await carveGroupOp(
            SquareFeip.envelope(
                opJson: try SquareFeip.updateOp(
                    squareId: squareId, name: name, desc: desc, home: home
                )
            ),
            feePerByte: feePerByte,
            minimumCd: required + 1,
            timeoutMs: timeoutMs
        )
    }

    /// Invite FIDs to a team we own.
    ///
    /// **An invitation is not a membership.** The invitee still has to
    /// carve their own `join`, quoting the consensus document — which is
    /// what makes belonging to a team a signed act by the member rather
    /// than something an owner can do to somebody.
    @discardableResult
    public func carveTeamInviteOnChain(
        teamId: String,
        fids: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveGroupOp(
            TeamFeip.envelope(opJson: try TeamFeip.inviteOp(tid: teamId, fids: fids)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    /// Dismiss members from a team we own.
    ///
    /// This ends their membership on the chain; it does **not** take
    /// back what they can read. Every key they hold still opens what it
    /// always did, so the key has to be rotated as well — the same
    /// bargain ``RoomService/removeMember(_:from:as:pubkeys:now:)``
    /// makes, except that here the two halves are separate acts.
    @discardableResult
    public func carveTeamDismissOnChain(
        teamId: String,
        fids: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveGroupOp(
            TeamFeip.envelope(opJson: try TeamFeip.dismissOp(tid: teamId, fids: fids)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    @discardableResult
    public func carveSquareJoinOnChain(
        squareId: String,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveGroupOp(
            SquareFeip.envelope(opJson: try SquareFeip.joinOp(squareId: squareId)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    @discardableResult
    public func carveSquareLeaveOnChain(
        squareIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveGroupOp(
            SquareFeip.envelope(opJson: try SquareFeip.leaveOp(squareIds: squareIds)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    /// The paymentless carve every group op uses. Joining a group pays
    /// nobody — it is a statement about us, like publishing a notice fee
    /// — which is what separates it from a mail.
    private func carveGroupOp(
        _ feipJson: String,
        feePerByte: Int64,
        minimumCd: Int64 = 0,
        timeoutMs: Int
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, minimumCd: minimumCd, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Carve a `delete` op deactivating the given secret carves.
    @discardableResult
    public func carveSecretDeleteOnChain(
        carveIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let feipJson = SecretFeip.envelope(
            opJson: try SecretFeip.deleteOp(secretIds: carveIds)
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    // MARK: - proof carving (FEIP Proof, sn 14)

    /// What a `transfer` pays the new owner.
    ///
    /// The transfer op names no recipient — the protocol reads it off
    /// the transaction's output, so the payment *is* the addressing,
    /// exactly as it is for mail. Android sends `Cash.MIN_AMOUNT`
    /// (0.0001 F) and this matches it, because the two clients have to
    /// agree on what an ownership change looks like on chain. It is far
    /// above the 546-sat dust floor, so the output always relays.
    public static let proofTransferSats: Int64 = NoticeFee.satsPerCoin / 10_000

    /// Issue a proof — mint a signed public statement.
    ///
    /// **The proof's id is the carve's txid**, so nothing can know the
    /// id until the broadcast returns; a caller holding a draft passes
    /// its id as `draftId` and gets the promoted row back under the new
    /// key. Pays nobody: issuing is a statement, not a message.
    ///
    /// Title and content go on chain **in the clear** — this is the one
    /// carve in the app with no cipher anywhere in it, and the reason
    /// the size guard in ``ProofFeip/issueCarve(title:content:cosigners:transferable:allSignsRequired:)``
    /// runs before a single satoshi is committed.
    @discardableResult
    public func carveProofIssueOnChain(
        title: String,
        content: String,
        cosigners: [String] = [],
        transferable: Bool = false,
        allSignsRequired: Bool = false,
        draftId: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> Proof {
        let priv = try livePrikey()
        let invited = cosigners.isEmpty ? nil : cosigners
        // Throws before anything is broadcast when the text is too big
        // for an OP_RETURN.
        let feipJson = try ProofFeip.issueCarve(
            title: title, content: content,
            cosigners: invited,
            transferable: transferable,
            allSignsRequired: invited == nil ? nil : allSignsRequired
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        if let draftId, let promoted = try? proofs.promoteDraft(id: draftId, toTxid: txid) {
            return promoted
        }
        let now = Int64(Date().timeIntervalSince1970)
        var proof = Proof(
            id: txid,
            title: title,
            content: content,
            cosignersInvited: invited,
            transferable: transferable,
            destroyed: false,
            issuer: liveFid,
            owner: liveFid,
            birthTime: now,
            lastTxId: txid,
            lastTime: now,
            // Sentinel height so a just-broadcast carve sorts above
            // every confirmed row until a block gives it a real one.
            lastHeight: ProofsStore.unconfirmedHeight,
            // Broadcast, not confirmed — see ``Proof/onChain``.
            onChain: nil
        )
        proof.updatedAt = Date()
        try? proofs.upsert(proof)
        return proof
    }

    /// Countersign a proof you were invited to.
    ///
    /// The signature is the carve itself: the transaction is signed by
    /// the live FID's key, so the chain records *who* signed without the
    /// payload having to say. Which is also why this cannot be done from
    /// a watch-only identity — there is no key to sign the transaction
    /// with, and a countersignature nobody signed is not one.
    @discardableResult
    public func carveProofSignOnChain(
        proofId: String,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: ProofFeip.envelope(opJson: try ProofFeip.signOp(proofId: proofId)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Hand a proof to `recipient`.
    ///
    /// Goes through the *paying* carve path — see ``proofTransferSats``
    /// for why the payment is the addressing rather than a courtesy.
    @discardableResult
    public func carveProofTransferOnChain(
        proofId: String,
        to recipient: String,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: ProofFeip.envelope(opJson: try ProofFeip.transferOp(proofId: proofId)),
            payTo: recipient, payAmount: Self.proofTransferSats,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Retire proofs you own, in one carve. Pays nobody.
    ///
    /// Destruction is not deletion: the record stays on the chain and
    /// stays readable, flagged `destroyed`. What ends is its force —
    /// which is the only thing a proof ever had.
    @discardableResult
    public func carveProofDestroyOnChain(
        proofIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: ProofFeip.envelope(opJson: try ProofFeip.destroyOp(proofIds: proofIds)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    // MARK: - publish carving (FEIP Text sn 21, Remark sn 22)

    /// Catalogue a text work on chain.
    ///
    /// **The body is not in this carve.** `did` points at it — see
    /// ``PublishBody``, which stores the bytes and hands back that
    /// pointer. Doing the upload first is deliberate: a publish that
    /// cannot reach a DISK should fail while it is still free, because
    /// a carve naming bytes nobody can fetch is a permanent dead link
    /// that cost a fee.
    ///
    /// **The record's id is this carve's txid** (rule 1 of FEIP21), so
    /// nothing can know the id until the broadcast returns; the
    /// ``TextRecord`` handed back carries it. Pays nobody.
    @discardableResult
    public func carveTextPublishOnChain(
        title: String,
        type: String? = nil,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil,
        draftId: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> TextRecord {
        let priv = try livePrikey()
        let list = (authors?.isEmpty ?? true) ? nil : authors
        // Throws before anything is broadcast when the metadata is too
        // big for an OP_RETURN.
        let feipJson = try TextFeip.publishCarve(
            title: title, type: type, did: did, lang: lang,
            authors: list, format: format, summary: summary
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        if let draftId, let promoted = try? texts.promoteDraft(id: draftId, toTxid: txid) {
            return promoted
        }
        let now = Int64(Date().timeIntervalSince1970)
        var record = TextRecord(
            id: txid,
            title: title,
            // The indexer assigns "1" to a first edition; this is what
            // it is about to say, not a claim of our own.
            ver: "1",
            did: did,
            authors: list,
            lang: lang,
            type: type,
            format: format,
            summary: summary,
            publisher: liveFid,
            birthTime: now,
            lastTxId: txid,
            lastTime: now,
            // Sentinel height so a just-broadcast carve sorts above
            // every confirmed row until a block gives it a real one.
            lastHeight: TextsStore.unconfirmedHeight,
            deleted: false,
            // Broadcast, not confirmed — see ``TextRecord/onChain``.
            onChain: nil
        )
        record.updatedAt = Date()
        try? texts.upsert(record)
        return record
    }

    /// Publish a new edition of a text work you published.
    ///
    /// **Every mutable field goes on the wire, whether or not it
    /// changed.** The reference parser assigns the op's fields onto the
    /// entity including the ones it did not carry, so an update that
    /// mentions only the title clears the summary, the language, the
    /// authors, the format and the `did`. Callers pass the record's
    /// current values for anything they are not changing; the pane's
    /// editor is pre-filled from the record for exactly this reason.
    ///
    /// The signer must be the publisher — the parser does **not** allow
    /// the FEIP6 master bypass on update, only on delete and recover.
    @discardableResult
    public func carveTextUpdateOnChain(
        textId: String,
        title: String,
        type: String? = nil,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let list = (authors?.isEmpty ?? true) ? nil : authors
        let feipJson = try TextFeip.updateCarve(
            textId: textId, title: title, type: type, did: did, lang: lang,
            authors: list, format: format, summary: summary
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        // Apply the edit to the cached row so the pane shows what was
        // just paid for. `onChain` is left alone: the *record* is still
        // as confirmed as it was, it is this edition that is pending.
        if var record = try? texts.get(id: textId) {
            record.title = title
            record.type = type
            record.did = did
            record.lang = lang
            record.authors = list
            record.format = format
            record.summary = summary
            record.ver = String(record.edition + 1)
            record.lastTxId = txid
            record.lastHeight = TextsStore.unconfirmedHeight
            record.lastTime = Int64(Date().timeIntervalSince1970)
            try? texts.upsert(record)
        }
        return txid
    }

    /// Retire text records, in one carve. Pays nobody.
    ///
    /// The deletion is soft: the row stays on the chain and stays
    /// readable, flagged `deleted`, and ``carveTextRecoverOnChain(textIds:feePerByte:timeoutMs:)``
    /// puts it back. What ends is its place in a listing.
    @discardableResult
    public func carveTextDeleteOnChain(
        textIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveTextFlag(textIds: textIds, deleted: true, feePerByte: feePerByte, timeoutMs: timeoutMs)
    }

    /// Clear the deleted flag on text records.
    @discardableResult
    public func carveTextRecoverOnChain(
        textIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveTextFlag(textIds: textIds, deleted: false, feePerByte: feePerByte, timeoutMs: timeoutMs)
    }

    /// Delete and recover differ by one boolean at both ends — the op
    /// name and the flag it sets — so they share everything else.
    private func carveTextFlag(
        textIds: [String],
        deleted: Bool,
        feePerByte: Int64,
        timeoutMs: Int
    ) async throws -> String {
        let priv = try livePrikey()
        let opJson = deleted
            ? try TextFeip.deleteOp(textIds: textIds)
            : try TextFeip.recoverOp(textIds: textIds)
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try TextFeip.sized(TextFeip.envelope(opJson: opJson)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid
        for id in textIds {
            guard var record = try? texts.get(id: id) else { continue }
            record.deleted = deleted
            record.lastTxId = txid
            record.lastHeight = TextsStore.unconfirmedHeight
            record.lastTime = Int64(Date().timeIntervalSince1970)
            try? texts.upsert(record)
        }
        return txid
    }

    /// Anchor a remark to something already published.
    ///
    /// `onDid` is the **target's record id** — its publish txid — which
    /// is this app's convention for the field; see ``Remark``. The
    /// remark's own body, if it has one, is at `did`, stored the same
    /// way a text's body is.
    @discardableResult
    public func carveRemarkPublishOnChain(
        title: String,
        onDid: String,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil,
        draftId: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> Remark {
        let priv = try livePrikey()
        let list = (authors?.isEmpty ?? true) ? nil : authors
        let feipJson = try RemarkFeip.publishCarve(
            title: title, onDid: onDid, did: did, lang: lang,
            authors: list, format: format, summary: summary
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        if let draftId, let promoted = try? remarks.promoteDraft(id: draftId, toTxid: txid) {
            return promoted
        }
        let now = Int64(Date().timeIntervalSince1970)
        var record = Remark(
            id: txid,
            title: title,
            ver: "1",
            did: did,
            onDid: onDid,
            authors: list,
            lang: lang,
            format: format,
            summary: summary,
            publisher: liveFid,
            birthTime: now,
            lastTxId: txid,
            lastTime: now,
            lastHeight: RemarksStore.unconfirmedHeight,
            deleted: false,
            onChain: nil
        )
        record.updatedAt = Date()
        try? remarks.upsert(record)
        return record
    }

    /// Publish a new edition of a remark. Sends every mutable field,
    /// for the reason ``carveTextUpdateOnChain(textId:title:type:did:lang:authors:format:summary:feePerByte:timeoutMs:)``
    /// documents.
    @discardableResult
    public func carveRemarkUpdateOnChain(
        remarkId: String,
        title: String,
        onDid: String,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let list = (authors?.isEmpty ?? true) ? nil : authors
        let feipJson = try RemarkFeip.updateCarve(
            remarkId: remarkId, title: title, onDid: onDid, did: did,
            lang: lang, authors: list, format: format, summary: summary
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        if var record = try? remarks.get(id: remarkId) {
            record.title = title
            record.onDid = onDid
            record.did = did
            record.lang = lang
            record.authors = list
            record.format = format
            record.summary = summary
            record.ver = String(record.edition + 1)
            record.lastTxId = txid
            record.lastHeight = RemarksStore.unconfirmedHeight
            record.lastTime = Int64(Date().timeIntervalSince1970)
            try? remarks.upsert(record)
        }
        return txid
    }

    @discardableResult
    public func carveRemarkDeleteOnChain(
        remarkIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveRemarkFlag(remarkIds: remarkIds, deleted: true, feePerByte: feePerByte, timeoutMs: timeoutMs)
    }

    @discardableResult
    public func carveRemarkRecoverOnChain(
        remarkIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveRemarkFlag(remarkIds: remarkIds, deleted: false, feePerByte: feePerByte, timeoutMs: timeoutMs)
    }

    private func carveRemarkFlag(
        remarkIds: [String],
        deleted: Bool,
        feePerByte: Int64,
        timeoutMs: Int
    ) async throws -> String {
        let priv = try livePrikey()
        let opJson = deleted
            ? try RemarkFeip.deleteOp(remarkIds: remarkIds)
            : try RemarkFeip.recoverOp(remarkIds: remarkIds)
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try RemarkFeip.sized(RemarkFeip.envelope(opJson: opJson)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid
        for id in remarkIds {
            guard var record = try? remarks.get(id: id) else { continue }
            record.deleted = deleted
            record.lastTxId = txid
            record.lastHeight = RemarksStore.unconfirmedHeight
            record.lastTime = Int64(Date().timeIntervalSince1970)
            try? remarks.upsert(record)
        }
        return txid
    }

    /// Catalogue an image, sound or video on chain.
    ///
    /// Identical to ``carveTextPublishOnChain(title:type:did:lang:authors:format:summary:draftId:feePerByte:timeoutMs:)``
    /// but for the media protocols' two differences: no `type`, and the
    /// subject field is named by ``MediaKind/subjectKey``. The bytes are
    /// not in the carve — `did` points at them, and
    /// ``PublishBody/storeFile(at:name:types:progress:)`` is what puts
    /// them on DISK and hands back that pointer.
    ///
    /// **One function for three protocols.** Image, Sound and Video
    /// differ in a serial number and a field spelling and nothing else;
    /// three copies of this would be three chances to carve the wrong
    /// `sn` — see ``MediaKind``.
    @discardableResult
    public func carveMediaPublishOnChain(
        kind: MediaKind,
        title: String,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil,
        draftId: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> MediaRecord {
        let priv = try livePrikey()
        let list = (authors?.isEmpty ?? true) ? nil : authors
        let feipJson = try MediaFeip.publishCarve(
            kind: kind, title: title, did: did, lang: lang,
            authors: list, format: format, summary: summary
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid
        let store = media(kind)

        if let draftId, let promoted = try? store.promoteDraft(id: draftId, toTxid: txid) {
            return promoted
        }
        let now = Int64(Date().timeIntervalSince1970)
        var record = MediaRecord(
            id: txid,
            kind: kind,
            title: title,
            ver: "1",
            did: did,
            authors: list,
            lang: lang,
            format: format,
            summary: summary,
            publisher: liveFid,
            birthTime: now,
            lastTxId: txid,
            lastTime: now,
            lastHeight: MediaStore.unconfirmedHeight,
            deleted: false,
            onChain: nil
        )
        record.updatedAt = Date()
        try? store.upsert(record)
        return record
    }

    /// Publish a new edition of a media record. Sends every mutable
    /// field, for the reason ``carveTextUpdateOnChain(textId:title:type:did:lang:authors:format:summary:feePerByte:timeoutMs:)``
    /// documents.
    @discardableResult
    public func carveMediaUpdateOnChain(
        kind: MediaKind,
        mediaId: String,
        title: String,
        did: String? = nil,
        lang: String? = nil,
        authors: [String]? = nil,
        format: String? = nil,
        summary: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let list = (authors?.isEmpty ?? true) ? nil : authors
        let feipJson = try MediaFeip.updateCarve(
            kind: kind, imageId: mediaId, title: title, did: did, lang: lang,
            authors: list, format: format, summary: summary
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        let store = media(kind)
        if var record = try? store.get(id: mediaId) {
            record.title = title
            record.did = did
            record.lang = lang
            record.authors = list
            record.format = format
            record.summary = summary
            record.ver = String(record.edition + 1)
            record.lastTxId = txid
            record.lastHeight = MediaStore.unconfirmedHeight
            record.lastTime = Int64(Date().timeIntervalSince1970)
            try? store.upsert(record)
        }
        return txid
    }

    @discardableResult
    public func carveMediaDeleteOnChain(
        kind: MediaKind,
        mediaIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveMediaFlag(
            kind: kind, mediaIds: mediaIds, deleted: true,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    @discardableResult
    public func carveMediaRecoverOnChain(
        kind: MediaKind,
        mediaIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        try await carveMediaFlag(
            kind: kind, mediaIds: mediaIds, deleted: false,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
    }

    private func carveMediaFlag(
        kind: MediaKind,
        mediaIds: [String],
        deleted: Bool,
        feePerByte: Int64,
        timeoutMs: Int
    ) async throws -> String {
        let priv = try livePrikey()
        let opJson = deleted
            ? try MediaFeip.deleteOp(kind: kind, imageIds: mediaIds)
            : try MediaFeip.recoverOp(kind: kind, imageIds: mediaIds)
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try MediaFeip.sized(MediaFeip.envelope(kind: kind, opJson: opJson)),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid
        let store = media(kind)
        for id in mediaIds {
            guard var record = try? store.get(id: id) else { continue }
            record.deleted = deleted
            record.lastTxId = txid
            record.lastHeight = MediaStore.unconfirmedHeight
            record.lastTime = Int64(Date().timeIntervalSince1970)
            try? store.upsert(record)
        }
        return txid
    }

    /// Carve a formal statement — FEIP8, and the one Publish protocol
    /// whose content goes **on the chain** rather than to DISK.
    ///
    /// **There is nothing to undo.** No update, no delete, no recover:
    /// the protocol has one operation and the record it writes is
    /// permanent. That is what the `confirm` phrase in the payload is
    /// for, and why the composer makes a person tick it by hand rather
    /// than filling it in for them —
    /// ``StatementFeip/confirmPhrase`` is compared byte for byte by the
    /// parser, so it is spelled once in the builder and never assembled
    /// at a call site.
    ///
    /// The size guard in ``StatementFeip/carve(title:content:)`` runs
    /// before a satoshi is committed, and it bites: an ordinary three
    /// paragraphs is over the OP_RETURN limit, because this text is
    /// carved in full and is neither compressed nor stored elsewhere.
    /// Pays nobody.
    @discardableResult
    public func carveStatementOnChain(
        title: String?,
        content: String?,
        draftId: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> Statement {
        let priv = try livePrikey()
        let feipJson = try StatementFeip.carve(title: title, content: content)
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        if let draftId, let promoted = try? statements.promoteDraft(id: draftId, toTxid: txid) {
            return promoted
        }
        var statement = Statement(
            id: txid,
            title: title,
            content: content,
            publisher: liveFid,
            birthTime: Int64(Date().timeIntervalSince1970),
            // Sentinel height so a just-broadcast carve sorts above
            // every confirmed row until a block gives it a real one.
            birthHeight: StatementsStore.unconfirmedHeight,
            // Broadcast, not confirmed — see ``Statement/onChain``.
            onChain: nil
        )
        statement.updatedAt = Date()
        try? statements.upsert(statement)
        return statement
    }

    // MARK: - token carving (FEIP Token, sn 20)

    /// Deploy a token — fix its rules and mint it into existence.
    ///
    /// **The token's id is this carve's txid**, so nothing can know the
    /// id until the broadcast returns; the ``Token`` handed back
    /// carries it. Pays nobody.
    ///
    /// **There is no draft.** Every other carve in the app can be
    /// composed and saved locally first, and a token cannot: a token
    /// with no id is not a token, and the id only exists once the carve
    /// is broadcast. Android says the same thing by way of a Save button
    /// that answers "tokens must be published on-chain" — this simply
    /// has no such button.
    ///
    /// The rules go on chain **in the clear** and can never be changed.
    /// The size guard in ``TokenFeip/deployCarve(name:desc:consensusId:capacity:decimal:transferable:closable:openIssue:maxAmtPerIssue:minCddPerIssue:maxIssuesPerAddr:)``
    /// runs before a single satoshi is committed.
    @discardableResult
    public func carveTokenDeployOnChain(
        name: String,
        desc: String? = nil,
        consensusId: String? = nil,
        capacity: String? = nil,
        decimal: String? = nil,
        transferable: Bool = true,
        closable: Bool = true,
        openIssue: Bool = false,
        maxAmtPerIssue: String? = nil,
        minCddPerIssue: String? = nil,
        maxIssuesPerAddr: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> Token {
        let priv = try livePrikey()
        // Throws before anything is broadcast when the rules do not fit
        // an OP_RETURN.
        let feipJson = try TokenFeip.deployCarve(
            name: name, desc: desc, consensusId: consensusId,
            capacity: capacity, decimal: decimal,
            transferable: transferable, closable: closable, openIssue: openIssue,
            maxAmtPerIssue: maxAmtPerIssue, minCddPerIssue: minCddPerIssue,
            maxIssuesPerAddr: maxIssuesPerAddr
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid
        let now = Int64(Date().timeIntervalSince1970)
        func clean(_ s: String?) -> String? {
            guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else {
                return nil
            }
            return t
        }
        // Mirrors what the deploy carve actually said, including
        // dropping the three issue limits when openIssue is false —
        // otherwise the local row would claim rules the carve omitted
        // and the chain will never report.
        return Token(
            id: txid,
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            desc: clean(desc),
            consensusId: clean(consensusId),
            capacity: clean(capacity),
            decimal: clean(decimal),
            transferable: transferable,
            closable: closable,
            openIssue: openIssue,
            maxAmtPerIssue: openIssue ? clean(maxAmtPerIssue) : nil,
            minCddPerIssue: openIssue ? clean(minCddPerIssue) : nil,
            maxIssuesPerAddr: openIssue ? clean(maxIssuesPerAddr) : nil,
            closed: false,
            deployer: liveFid,
            circulating: 0,
            birthTime: now,
            lastTxId: txid,
            lastTime: now
        )
    }

    /// Issue supply of `tokenId` into the named FIDs' balances.
    ///
    /// `scale` is the token's ``Token/decimalPlaces``, and it is a
    /// parameter rather than something looked up here because the
    /// caller already holds the token — and because issuing against a
    /// scale guessed wrong is a carve the parser silently rejects after
    /// the fee is paid.
    ///
    /// Whether the live FID is *allowed* to issue is
    /// ``Token/canIssue(as:)``, checked by the form. The chain checks
    /// it too, but only after the miner fee is spent.
    @discardableResult
    public func carveTokenIssueOnChain(
        tokenId: String,
        issueTo: [TokenTransfer],
        scale: Int,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let feipJson = try TokenFeip.issueCarve(
            tokenId: tokenId, issueTo: issueTo, scale: scale
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Move balance of `tokenId` from the live FID to the named FIDs.
    ///
    /// **The recipients are in the payload, not in a payment output.**
    /// A proof transfer addresses its recipient by paying them; a token
    /// transfer names them in the carve, so this pays nobody and costs
    /// only the miner fee. The corollary is that the chain will happily
    /// carve a transfer to a FID that has never existed — nothing
    /// bounces, the balance simply lands somewhere nobody holds a key
    /// for. That check belongs to the form.
    @discardableResult
    public func carveTokenTransferOnChain(
        tokenId: String,
        transferTo: [TokenTransfer],
        scale: Int,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let feipJson = try TokenFeip.transferCarve(
            tokenId: tokenId, transferTo: transferTo, scale: scale
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Burn **the live FID's entire balance** of `tokenId`.
    ///
    /// There is no partial destroy: the op takes an id, not an amount.
    /// A holder wanting to burn part of a holding sends the rest
    /// somewhere first — which is why the confirmation for this needs
    /// to say the whole balance out loud.
    @discardableResult
    public func carveTokenDestroyOnChain(
        tokenId: String,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try TokenFeip.destroyCarve(tokenId: tokenId),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Close tokens the live FID deployed, in one carve. Pays nobody.
    ///
    /// **Closing is not destroying, and it is not local hiding.** It
    /// retires the token for everybody and for good: no further issue,
    /// no further transfer, existing balances frozen where they sit.
    /// Only the deployer of a token deployed `closable` can do it, and
    /// nothing undoes it.
    @discardableResult
    public func carveTokenCloseOnChain(
        tokenIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try TokenFeip.closeCarve(tokenIds: tokenIds),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    // MARK: - protocol carving (FEIP FeipProtocol, sn 1)

    /// Publish a protocol — register a specification on chain.
    ///
    /// **The record's id is the carve's txid**, so nothing can know the
    /// id until the broadcast returns; a caller holding a draft passes
    /// its id as `draftId` and gets the promoted row back under the new
    /// key. Pays nobody: publishing is a registration, not a message.
    ///
    /// Everything goes on chain **in the clear**, which is why the size
    /// guard in ``ProtocolFeip/publishCarve(sn:name:type:ver:did:desc:lang:home:preDid:waiters:)``
    /// runs before a single satoshi is committed.
    ///
    /// The returned row is also written to the cached window
    /// (``ProtocolsStore/rememberBroadcast(_:)``) so the carve the user
    /// just paid for is visible before a block confirms it; the next
    /// refresh replaces it with the chain's copy.
    @discardableResult
    public func carveProtocolPublishOnChain(
        name: String,
        type: String? = nil,
        sn: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        lang: String? = nil,
        home: [String: String]? = nil,
        preDid: String? = nil,
        waiters: [String]? = nil,
        draftId: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> ProtocolSpec {
        let priv = try livePrikey()
        // Throws before anything is broadcast when the registration is
        // too big for an OP_RETURN.
        let feipJson = try ProtocolFeip.publishCarve(
            sn: sn, name: name, type: type, ver: ver, did: did,
            desc: desc, lang: lang, home: home, preDid: preDid, waiters: waiters
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        if let draftId, let promoted = try? protocols.promoteDraft(id: draftId, toTxid: txid) {
            try? protocols.rememberBroadcast(promoted)
            return promoted
        }
        let now = Int64(Date().timeIntervalSince1970)
        func clean(_ s: String?) -> String? {
            guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else {
                return nil
            }
            return t
        }
        let servers = waiters?.filter { !$0.isEmpty }
        let invited = (servers?.isEmpty == false) ? servers : nil
        var spec = ProtocolSpec(
            id: txid,
            type: clean(type),
            sn: clean(sn),
            ver: clean(ver),
            did: clean(did),
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            lang: clean(lang),
            desc: clean(desc),
            prePid: clean(preDid),
            home: (home?.isEmpty == false) ? home : nil,
            owner: liveFid,
            waiters: invited,
            birthTxId: txid,
            birthTime: now,
            lastTxId: txid,
            lastTime: now,
            // Sentinel height so a just-broadcast carve sorts above
            // every confirmed row until a block gives it a real one.
            lastHeight: ProtocolsStore.unconfirmedHeight,
            closed: false,
            // Broadcast, not confirmed — see ``ProtocolSpec/onChain``.
            onChain: nil
        )
        spec.updatedAt = Date()
        try? protocols.rememberBroadcast(spec)
        return spec
    }

    /// Amend a registration you own.
    ///
    /// **Every field is resent, not just the changed ones.** The op
    /// replaces the record's mutable half, so a field left out here is a
    /// field cleared on chain — which is why the edit form loads the
    /// current record and submits all of it.
    ///
    /// The id does not change: `update` names the record by `pid` and
    /// the chain keeps the original publish txid as its id. Only
    /// ``ProtocolSpec/lastTxId`` moves.
    @discardableResult
    public func carveProtocolUpdateOnChain(
        pid: String,
        name: String,
        type: String? = nil,
        sn: String? = nil,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        lang: String? = nil,
        home: [String: String]? = nil,
        preDid: String? = nil,
        waiters: [String]? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let feipJson = try ProtocolFeip.updateCarve(
            pid: pid, sn: sn, name: name, type: type, ver: ver, did: did,
            desc: desc, lang: lang, home: home, preDid: preDid, waiters: waiters
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Take protocols you own out of force, in one carve. Pays nobody.
    ///
    /// Reversible — ``carveProtocolRecoverOnChain(pids:feePerByte:timeoutMs:)``
    /// puts them back. That is the whole difference between this and
    /// closing.
    @discardableResult
    public func carveProtocolStopOnChain(
        pids: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try ProtocolFeip.stopCarve(pids: pids),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? protocols.markLocally(ids: pids, active: false)
        return result.remoteTxid
    }

    /// Put stopped protocols back in force, in one carve. Pays nobody.
    ///
    /// **Does not undo a close.** A closed protocol is finished; the
    /// chain will accept this carve and change nothing, which is a miner
    /// fee for nothing — ``ProtocolSpec/canRecover(as:)`` is what keeps
    /// the button off.
    @discardableResult
    public func carveProtocolRecoverOnChain(
        pids: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try ProtocolFeip.recoverCarve(pids: pids),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? protocols.markLocally(ids: pids, active: true)
        return result.remoteTxid
    }

    /// Retire protocols you own, permanently, in one carve. Pays nobody.
    ///
    /// **Closing is not stopping and it is not hiding.** The record
    /// stays on the chain and stays readable, flagged closed, and
    /// nothing puts it back — there is no op that reopens a closed
    /// protocol. `closeStatement` is the reason, and it is the last
    /// thing the owner will ever be able to say about it.
    @discardableResult
    public func carveProtocolCloseOnChain(
        pids: [String],
        closeStatement: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try ProtocolFeip.closeCarve(pids: pids, closeStatement: closeStatement),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? protocols.markLocally(ids: pids, closed: true, closeStatement: closeStatement)
        return result.remoteTxid
    }

    // MARK: - code carving (FEIP Code, sn 2)

    /// Publish a code record — register an implementation on chain.
    ///
    /// **The record's id is the carve's txid**, so nothing can know the
    /// id until the broadcast returns; a caller holding a draft passes
    /// its id as `draftId` and gets the promoted row back under the new
    /// key. Pays nobody: publishing is a registration, not a message.
    ///
    /// Everything goes on chain **in the clear**, which is why the size
    /// guard in ``CodeFeip/publishCarve(name:ver:did:desc:langs:home:protocols:waiters:)``
    /// runs before a single satoshi is committed — and it bites sooner
    /// here than it does for a protocol, because every entry in
    /// `protocols` is a 64-character record id.
    ///
    /// The returned row is also written to the cached window
    /// (``CodesStore/rememberBroadcast(_:)``) so the carve the user just
    /// paid for is visible before a block confirms it; the next refresh
    /// replaces it with the chain's copy.
    @discardableResult
    public func carveCodePublishOnChain(
        name: String,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        langs: [String]? = nil,
        home: [String: String]? = nil,
        protocols: [String]? = nil,
        waiters: [String]? = nil,
        draftId: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> Code {
        let priv = try livePrikey()
        // Throws before anything is broadcast when the registration is
        // too big for an OP_RETURN.
        let feipJson = try CodeFeip.publishCarve(
            name: name, ver: ver, did: did, desc: desc,
            langs: langs, home: home, protocols: protocols, waiters: waiters
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        if let draftId, let promoted = try? codes.promoteDraft(id: draftId, toTxid: txid) {
            try? codes.rememberBroadcast(promoted)
            return promoted
        }
        let now = Int64(Date().timeIntervalSince1970)
        func clean(_ s: String?) -> String? {
            guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else {
                return nil
            }
            return t
        }
        func cleanList(_ list: [String]?) -> [String]? {
            let kept = (list ?? [])
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            return kept.isEmpty ? nil : kept
        }
        var code = Code(
            id: txid,
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            ver: clean(ver),
            did: clean(did),
            desc: clean(desc),
            langs: cleanList(langs),
            home: (home?.isEmpty == false) ? home : nil,
            protocols: cleanList(protocols),
            waiters: cleanList(waiters),
            owner: liveFid,
            birthTime: now,
            lastTxId: txid,
            lastTime: now,
            // Sentinel height so a just-broadcast carve sorts above
            // every confirmed row until a block gives it a real one.
            lastHeight: CodesStore.unconfirmedHeight,
            closed: false,
            // Broadcast, not confirmed — see ``Code/onChain``.
            onChain: nil
        )
        code.updatedAt = Date()
        try? codes.rememberBroadcast(code)
        return code
    }

    /// Amend a code registration you own.
    ///
    /// **Every field is resent, not just the changed ones.** The op
    /// replaces the record's mutable half, so a field left out here is a
    /// field cleared on chain — which is why the edit form loads the
    /// current record and submits all of it.
    ///
    /// The id does not change: `update` names the record by `codeId` and
    /// the chain keeps the original publish txid as its id. Only
    /// ``Code/lastTxId`` moves.
    @discardableResult
    public func carveCodeUpdateOnChain(
        codeId: String,
        name: String,
        ver: String? = nil,
        did: String? = nil,
        desc: String? = nil,
        langs: [String]? = nil,
        home: [String: String]? = nil,
        protocols: [String]? = nil,
        waiters: [String]? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let feipJson = try CodeFeip.updateCarve(
            codeId: codeId, name: name, ver: ver, did: did, desc: desc,
            langs: langs, home: home, protocols: protocols, waiters: waiters
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Take code records you own out of force, in one carve. Pays
    /// nobody.
    ///
    /// Reversible — ``carveCodeRecoverOnChain(codeIds:feePerByte:timeoutMs:)``
    /// puts them back. That is the whole difference between this and
    /// closing.
    @discardableResult
    public func carveCodeStopOnChain(
        codeIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try CodeFeip.stopCarve(codeIds: codeIds),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? codes.markLocally(ids: codeIds, active: false)
        return result.remoteTxid
    }

    /// Put stopped code records back in force, in one carve. Pays
    /// nobody.
    ///
    /// **Does not undo a close.** A closed record is finished; the chain
    /// will accept this carve and change nothing, which is a miner fee
    /// for nothing — ``Code/canRecover(as:)`` is what keeps the button
    /// off.
    @discardableResult
    public func carveCodeRecoverOnChain(
        codeIds: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try CodeFeip.recoverCarve(codeIds: codeIds),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? codes.markLocally(ids: codeIds, active: true)
        return result.remoteTxid
    }

    /// Retire code records you own, permanently, in one carve. Pays
    /// nobody.
    ///
    /// **Closing is not stopping and it is not hiding.** The record
    /// stays on the chain and stays readable, flagged closed, and
    /// nothing puts it back — there is no op that reopens a closed
    /// record. `closeStatement` is the reason, and it is the last thing
    /// the owner will ever be able to say about it.
    @discardableResult
    public func carveCodeCloseOnChain(
        codeIds: [String],
        closeStatement: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try CodeFeip.closeCarve(codeIds: codeIds, closeStatement: closeStatement),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? codes.markLocally(ids: codeIds, closed: true, closeStatement: closeStatement)
        return result.remoteTxid
    }

    // MARK: - service carving (FEIP Service, sn 5)

    /// Publish a service record — register a running instance on chain.
    ///
    /// **The record's SID is the carve's txid**, so nothing can know it
    /// until the broadcast returns; a caller holding a draft passes its
    /// id as `draftId` and gets the promoted row back under the new key.
    /// Pays nobody: publishing is a registration, not a message.
    ///
    /// Everything goes on chain **in the clear**, which is why the size
    /// guard in ``ServiceFeip/publishCarve(stdName:localNames:desc:type:components:ver:home:waiters:protocols:codes:services:pricing:)``
    /// runs before a single satoshi is committed. It bites soonest on
    /// this record of the four: a service can name five id lists, two
    /// maps and thirteen prices, and protocol and code ids are 64
    /// characters each.
    ///
    /// The returned row is also written to the cached window
    /// (``ServicesStore/rememberBroadcast(_:)``) so the carve the user
    /// just paid for is visible before a block confirms it; the next
    /// refresh replaces it with the chain's copy.
    @discardableResult
    public func carveServicePublishOnChain(
        stdName: String,
        localNames: [String: String]? = nil,
        desc: String? = nil,
        type: String? = nil,
        components: [String]? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services serviceIds: [String]? = nil,
        pricing: ServiceFeip.Pricing = .init(),
        draftId: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> Service {
        let priv = try livePrikey()
        // Throws before anything is broadcast when the registration is
        // too big for an OP_RETURN.
        let feipJson = try ServiceFeip.publishCarve(
            stdName: stdName, localNames: localNames, desc: desc, type: type,
            components: components, ver: ver, home: home, waiters: waiters,
            protocols: protocols, codes: codes, services: serviceIds, pricing: pricing
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        if let draftId, let promoted = try? services.promoteDraft(id: draftId, toTxid: txid) {
            try? services.rememberBroadcast(promoted)
            return promoted
        }
        let now = Int64(Date().timeIntervalSince1970)
        func clean(_ s: String?) -> String? {
            guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else {
                return nil
            }
            return t
        }
        func cleanList(_ list: [String]?) -> [String]? {
            let kept = (list ?? [])
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            return kept.isEmpty ? nil : kept
        }
        var service = Service(
            stdName: stdName.trimmingCharacters(in: .whitespacesAndNewlines),
            localNames: (localNames?.isEmpty == false) ? localNames : nil,
            desc: clean(desc),
            type: clean(type),
            components: cleanList(components),
            ver: clean(ver),
            home: (home?.isEmpty == false) ? home : nil,
            waiters: cleanList(waiters),
            protocols: cleanList(protocols),
            codes: cleanList(codes),
            services: cleanList(serviceIds),
            owner: liveFid,
            birthTime: now,
            lastTxId: txid,
            lastTime: now,
            // Sentinel height so a just-broadcast carve sorts above
            // every confirmed row until a block gives it a real one.
            lastHeight: ServicesStore.unconfirmedHeight,
            closed: false,
            // Broadcast, not confirmed — see ``Service/onChain``.
            onChain: nil,
            id: txid
        )
        service.applyPricing(pricing.pruned)
        service.updatedAt = Date()
        try? services.rememberBroadcast(service)
        return service
    }

    /// Amend a service registration you own.
    ///
    /// **Every field is resent, not just the changed ones.** The op
    /// replaces the record's mutable half, so a field left out here is a
    /// field cleared on chain — which on a service means the endpoint
    /// under `home` can be deleted by omission, and every client
    /// resolving that SID stops finding it. The edit form loads the
    /// current record and submits all of it.
    ///
    /// The SID does not change: `update` names the record by `sid` and
    /// the chain keeps the original publish txid as its id. Only
    /// ``Service/lastTxId`` moves.
    @discardableResult
    public func carveServiceUpdateOnChain(
        sid: String,
        stdName: String,
        localNames: [String: String]? = nil,
        desc: String? = nil,
        type: String? = nil,
        components: [String]? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services serviceIds: [String]? = nil,
        pricing: ServiceFeip.Pricing = .init(),
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let feipJson = try ServiceFeip.updateCarve(
            sid: sid, stdName: stdName, localNames: localNames, desc: desc,
            type: type, components: components, ver: ver, home: home,
            waiters: waiters, protocols: protocols, codes: codes,
            services: serviceIds, pricing: pricing
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Take services you own out of force, in one carve. Pays nobody.
    ///
    /// Reversible — ``carveServiceRecoverOnChain(sids:feePerByte:timeoutMs:)``
    /// puts them back. That is the whole difference between this and
    /// closing.
    ///
    /// **A stopped service is still reachable.** `active` is what the
    /// registry says, not what the server does: stopping tells clients
    /// to stop routing here, and the daemon at the other end carries on
    /// answering until its operator turns it off.
    @discardableResult
    public func carveServiceStopOnChain(
        sids: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try ServiceFeip.stopCarve(sids: sids),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? services.markLocally(ids: sids, active: false)
        return result.remoteTxid
    }

    /// Put stopped services back in force, in one carve. Pays nobody.
    ///
    /// **Does not undo a close.** A closed record is finished; the chain
    /// will accept this carve and change nothing, which is a miner fee
    /// for nothing — ``Service/canRecover(as:)`` is what keeps the
    /// button off.
    @discardableResult
    public func carveServiceRecoverOnChain(
        sids: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try ServiceFeip.recoverCarve(sids: sids),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? services.markLocally(ids: sids, active: true)
        return result.remoteTxid
    }

    /// Retire services you own, permanently, in one carve. Pays nobody.
    ///
    /// **Closing is not stopping and it is not hiding.** The record
    /// stays on the chain and stays readable, flagged closed, and
    /// nothing puts it back. `closeStatement` is the reason, and it is
    /// the last thing the owner will ever be able to say about it —
    /// which on a service is where you point people at the replacement.
    @discardableResult
    public func carveServiceCloseOnChain(
        sids: [String],
        closeStatement: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try ServiceFeip.closeCarve(sids: sids, closeStatement: closeStatement),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? services.markLocally(ids: sids, closed: true, closeStatement: closeStatement)
        return result.remoteTxid
    }


    // MARK: - app carving (FEIP APP, sn 15)

    /// Publish an app record — register something a person can install.
    ///
    /// **The record's AID is the carve's txid**, so nothing can know it
    /// until the broadcast returns; a caller holding a draft passes its
    /// id as `draftId` and gets the promoted row back under the new key.
    /// Pays nobody: publishing is a registration, not a message.
    ///
    /// Everything goes on chain **in the clear**, which is why the size
    /// guard in ``AppFeip/publishCarve(stdName:localNames:types:desc:ver:home:downloads:waiters:protocols:codes:services:)``
    /// runs before a single satoshi is committed — and on this record
    /// the `downloads` list is what spends the budget, a URL and a
    /// 64-character digest per platform.
    ///
    /// The returned row is also written to the cached window
    /// (``AppsStore/rememberBroadcast(_:)``) so the carve the user just
    /// paid for is visible before a block confirms it; the next refresh
    /// replaces it with the chain's copy.
    @discardableResult
    public func carveAppPublishOnChain(
        stdName: String,
        localNames: [String: String]? = nil,
        types: [String]? = nil,
        desc: String? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        downloads: [AppRecord.Download]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        draftId: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> AppRecord {
        let priv = try livePrikey()
        // Throws before anything is broadcast when the registration is
        // too big for an OP_RETURN.
        let feipJson = try AppFeip.publishCarve(
            stdName: stdName, localNames: localNames, types: types, desc: desc,
            ver: ver, home: home, downloads: downloads, waiters: waiters,
            protocols: protocols, codes: codes, services: services
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        let txid = result.remoteTxid

        if let draftId, let promoted = try? apps.promoteDraft(id: draftId, toTxid: txid) {
            try? apps.rememberBroadcast(promoted)
            return promoted
        }
        let now = Int64(Date().timeIntervalSince1970)
        func clean(_ s: String?) -> String? {
            guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else {
                return nil
            }
            return t
        }
        func cleanList(_ list: [String]?) -> [String]? {
            let kept = (list ?? [])
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            return kept.isEmpty ? nil : kept
        }
        let cleanDownloads: [AppRecord.Download]? = {
            let kept = (downloads ?? []).compactMap(\.pruned)
            return kept.isEmpty ? nil : kept
        }()
        var app = AppRecord(
            id: txid,
            stdName: stdName.trimmingCharacters(in: .whitespacesAndNewlines),
            localNames: (localNames?.isEmpty == false) ? localNames : nil,
            types: cleanList(types),
            desc: clean(desc),
            ver: clean(ver),
            home: (home?.isEmpty == false) ? home : nil,
            downloads: cleanDownloads,
            waiters: cleanList(waiters),
            protocols: cleanList(protocols),
            codes: cleanList(codes),
            services: cleanList(services),
            owner: liveFid,
            birthTime: now,
            lastTxId: txid,
            lastTime: now,
            // Sentinel height so a just-broadcast carve sorts above
            // every confirmed row until a block gives it a real one.
            lastHeight: AppsStore.unconfirmedHeight,
            closed: false,
            // Broadcast, not confirmed — see ``AppRecord/onChain``.
            onChain: nil
        )
        app.updatedAt = Date()
        try? apps.rememberBroadcast(app)
        return app
    }

    /// Amend an app registration you own.
    ///
    /// **Every field is resent, not just the changed ones.** The op
    /// replaces the record's mutable half, so a field left out here is a
    /// field cleared on chain — which is why the edit form loads the
    /// current record and submits all of it, `downloads` included.
    /// Android omits that list because it never had it, and so erases
    /// it on every update (**Android issue C23**).
    ///
    /// The AID does not change: `update` names the record by `aid` and
    /// the chain keeps the original publish txid as its id. Only
    /// ``AppRecord/lastTxId`` moves.
    @discardableResult
    public func carveAppUpdateOnChain(
        aid: String,
        stdName: String,
        localNames: [String: String]? = nil,
        types: [String]? = nil,
        desc: String? = nil,
        ver: String? = nil,
        home: [String: String]? = nil,
        downloads: [AppRecord.Download]? = nil,
        waiters: [String]? = nil,
        protocols: [String]? = nil,
        codes: [String]? = nil,
        services: [String]? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let feipJson = try AppFeip.updateCarve(
            aid: aid, stdName: stdName, localNames: localNames, types: types,
            desc: desc, ver: ver, home: home, downloads: downloads,
            waiters: waiters, protocols: protocols, codes: codes, services: services
        )
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: feipJson,
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        return result.remoteTxid
    }

    /// Take app records you own out of force, in one carve. Pays nobody.
    ///
    /// Reversible — ``carveAppRecoverOnChain(aids:feePerByte:timeoutMs:)``
    /// puts them back. That is the whole difference between this and
    /// closing.
    ///
    /// **It does not unpublish anything already installed.** Stopping
    /// takes the registration out of force; copies people downloaded
    /// keep working, and the links under `downloads` keep resolving
    /// until whoever hosts them takes them down.
    @discardableResult
    public func carveAppStopOnChain(
        aids: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try AppFeip.stopCarve(aids: aids),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? apps.markLocally(ids: aids, active: false)
        return result.remoteTxid
    }

    /// Put stopped app records back in force, in one carve. Pays nobody.
    ///
    /// **Does not undo a close.** A closed record is finished; the chain
    /// will accept this carve and change nothing, which is a miner fee
    /// for nothing — ``AppRecord/canRecover(as:)`` is what keeps the
    /// button off.
    @discardableResult
    public func carveAppRecoverOnChain(
        aids: [String],
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try AppFeip.recoverCarve(aids: aids),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? apps.markLocally(ids: aids, active: true)
        return result.remoteTxid
    }

    /// Retire app records you own, permanently, in one carve. Pays
    /// nobody.
    ///
    /// **Closing is not stopping and it is not hiding.** The record
    /// stays on the chain and stays readable, flagged closed, and
    /// nothing puts it back. `closeStatement` is the reason, and it is
    /// the last thing the owner will ever be able to say about it —
    /// on an app, that is where you name the successor people should
    /// install instead.
    @discardableResult
    public func carveAppCloseOnChain(
        aids: [String],
        closeStatement: String? = nil,
        feePerByte: Int64 = 1,
        timeoutMs: Int = 10_000
    ) async throws -> String {
        let priv = try livePrikey()
        let result = try await wallet.carve(
            fromAddress: liveFid, privkey: priv,
            opReturn: try AppFeip.closeCarve(aids: aids, closeStatement: closeStatement),
            feePerByte: feePerByte, timeoutMs: timeoutMs
        )
        try? apps.markLocally(ids: aids, closed: true, closeStatement: closeStatement)
        return result.remoteTxid
    }

}
