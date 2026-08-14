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
        case underlying(Error)

        public var description: String {
            switch self {
            case .unknownLive(let fid):
                return "ActiveSession: \(fid) is not registered in this Setting"
            case .watchOnlyCannotSign(let fid):
                return "ActiveSession: \(fid) is watch-only — cannot sign or decrypt"
            case .cannotReplaceMain(let fid):
                return "ActiveSession: \(fid) is the main FID — it cannot be replaced by a sub-identity"
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
    public lazy var contacts: ContactsStore = ContactsStore(kv: storage)
    public lazy var secrets: SecretsStore  = SecretsStore(kv: storage)
    public lazy var mails: MailsStore      = MailsStore(kv: storage)
    public lazy var hats: HatsStore        = HatsStore(kv: storage)
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

    /// The room protocol. Computed so it always carries the *live*
    /// identity's privkey — a sub-identity joins rooms as itself, and a
    /// service holding the main's key would open its shared keys with
    /// the wrong one.
    public var roomService: RoomService {
        get throws {
            RoomService(rooms: rooms, symkeys: symkeys).withPrivkey(try livePrikey())
        }
    }
    /// Reference-mode file layer over ``hats``.
    public lazy var files: FileVault       = FileVault(hats: hats, dataDirectory: dataDirectory)
    public lazy var keys: KeysStore        = KeysStore(kv: storage)
    public lazy var cashes: CashesStore    = CashesStore(kv: storage)
    public lazy var recentActivity: RecentActivityStore = RecentActivityStore(kv: storage)

    /// Computed (not lazy) so ``setFapi(_:)`` is picked up the next
    /// time something asks for the wallet. WalletService is a struct;
    /// constructing it is essentially a Foundation pointer copy.
    public var wallet: WalletService {
        WalletService(fapi: fapi, cashes: cashes, recentActivity: recentActivity)
    }

    /// Identity-directory lookups (`base.freerByIds`). Computed so a
    /// `setFapi(_:)` swap is picked up immediately.
    public var directory: DirectoryService {
        DirectoryService(fapi: fapi)
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
    public func setFapi(_ client: any FapiCalling) {
        self.fapi = client
    }

    // MARK: - send convenience

    /// Send from the **live** FID. Throws for watch-only —
    /// callers should fall back to a cold-sign builder (Phase 8).
    @discardableResult
    public func sendFromLive(
        to toFid: String,
        amount: Int64,
        feePerByte: Int64 = 1,
        useCache: Bool = false,
        timeoutMs: Int = 10_000
    ) async throws -> WalletService.SendResult {
        let priv = try livePrikey()
        return try await wallet.send(
            fromAddress: liveFid, privkey: priv,
            to: toFid, amount: amount,
            feePerByte: feePerByte,
            useCache: useCache,
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
        timeoutMs: Int = 10_000
    ) async throws -> WalletService.UnsignedSendResult {
        try await wallet.buildUnsignedSend(
            fromAddress: liveFid,
            to: toFid, amount: amount,
            feePerByte: feePerByte,
            useCache: useCache,
            timeoutMs: timeoutMs
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
}
