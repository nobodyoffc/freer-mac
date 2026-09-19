import Foundation
import FCCore
import FCStorage

/// One symmetric key, at one version, for one team or room — the port of
/// Android's `SymkeyStore.SymkeyEntry`.
///
/// **We store the key itself; Android stores it sealed.** Android wraps
/// each key AsyOneWay under the user's own pubkey before it goes into
/// MMKV, because on that platform the row is protected only by the app
/// sandbox. Here the row is already AES-GCM under the per-main vault key,
/// and that key is `HKDF(configure symkey, …)` — derived from the very
/// password that also releases the identity privkey. The two gates are
/// the same gate, so a second self-ECDH would buy no security and would
/// cost one elliptic-curve operation per message decrypted. What it
/// *does* buy, by not being there, is that reading a key is a plain KV
/// read — which is why this store needs no in-memory key cache and
/// Android's does.
public struct SymkeyEntry: Codable, Equatable, Sendable {

    /// The team or room this key belongs to.
    public var entityId: String
    /// Seconds since the epoch at the moment the key was minted. See
    /// ``SymkeyStore/nextVersion(for:now:)``.
    public var version: Int64
    /// The raw 32-byte AES key.
    public var key: Data
    /// Milliseconds since the epoch.
    public var createdAt: Int64?
    /// Kept for parity with Android's row. Nothing retires a key today:
    /// a rotation supersedes a version rather than revoking it, because
    /// the old messages sealed under it still have to open.
    public var active: Bool?

    /// This key's local identity — `SHA256(key)`, first 16 hex characters.
    ///
    /// **Derived, never stored.** A stored copy could disagree with the
    /// key beside it after any bug that rewrote one and not the other,
    /// and the whole point of the id is to be the one thing that cannot
    /// lie about which key this is. It is also never transmitted: both
    /// ends compute it from the key they hold, so it costs no wire byte
    /// (SYMKEY_IDENTITY_SPEC.md §2).
    public var keyId: String { SymkeyStore.keyId(of: key) }

    public init(
        entityId: String,
        version: Int64,
        key: Data,
        createdAt: Int64? = nil,
        active: Bool? = true
    ) {
        self.entityId = entityId
        self.version = version
        self.key = key
        self.createdAt = createdAt
        self.active = active
    }
}

/// The versioned symmetric keys that Team and Room traffic is sealed
/// with. (P2P does not appear here — it uses the AsyTwoWay envelope from
/// 9.1.1, which needs no stored key at all.)
///
/// **A version is a mint time, not a counter** — seconds since the epoch,
/// floored above every version already known for the entity
/// (``nextVersion(for:now:)``). A counter cannot survive this app's own
/// identity model: one FID is signed in on several devices by design, so
/// two of the owner's devices can be partitioned and both mint "the next
/// version". A device holding nothing mints version 1 for a key that is
/// not the version 1 the group already uses, and two distinct keys then
/// answer to one name. See FIMP0V2 §Symkey id and
/// SYMKEY_IDENTITY_SPEC.md §1.
///
/// **Every version is kept forever.** A rotation does not replace a key,
/// it adds one: messages already sealed under an older version still
/// have to open after the group moves on, and the only copy of that key
/// is this store. So "the key for this room" always means "the newest
/// version", and decryption always asks for the version the message
/// names.
///
/// **Nothing is ever overwritten.** Not by a member, not by the owner. A
/// key arriving for a version we already hold is either the same key —
/// two members answering one request, which is ordinary — or a different
/// one, and then *both are kept* and opening tries each. The rule this
/// replaces (`allowOverwrite`, granted when the sender owned the entity)
/// existed to stop a member poisoning a version everyone used, and a
/// poisoned key is now simply a candidate that fails its AES-GCM tag.
/// The rule that protected history was also the only thing that could
/// destroy it: an owner's key at an existing version used to overwrite
/// the row, and every message sealed under the displaced key became
/// unreadable with no other copy anywhere.
public struct SymkeyStore {

    public static let namespace = "im.symkeys.v1"

    /// Versions start at 1, and 0 means "no key" (Android's
    /// `getCurrentVersion` returns 0 for an entity it has never seen).
    ///
    /// Non-positive versions are refused outright, and that is a real
    /// guard rather than a formality: ``ImMessage/symkeyVersion`` is a
    /// 64-bit field that the wire carries in 32 bits, so a peer *can*
    /// name a version this side of zero. Storing one would put a key
    /// where no honest mint could ever reach it.
    public static let minimumVersion: Int64 = 1

    /// Below this, a version is a pre-spec counter (1, 2, 3, …) minted
    /// before versions were mint times; at or above it, a timestamp.
    ///
    /// The two cannot collide, which is why no migration of version
    /// *numbers* is needed and old and new keys sit in one store: no
    /// group is rotated a billion times, and no timestamp since 2001 is
    /// this small. `max()` still selects the newest key, because every
    /// timestamp exceeds every counter.
    public static let legacyVersionCeiling: Int64 = 1_000_000_000

    /// AES-256.
    public static let keyLength = 32

    /// Characters of hex in a ``SymkeyEntry/keyId`` — 8 bytes of SHA-256.
    ///
    /// A deliberate collision costs 2⁶⁴ work and still yields a key that
    /// fails its AES-GCM tag, so the id never decides anything on its
    /// own; it only tells two keys apart in the store and in the
    /// distribution ledger.
    public static let keyIdLength = 16

    /// The most keys one entity may accumulate.
    ///
    /// A bound on a misbehaving peer, not on honest use — no group is
    /// rotated this often. What keeps it out of a peer's reach is the
    /// acceptance rule in FIMP §4.2 (owner, or an answer to a request we
    /// made): once nothing is overwritten, "only what I asked for" is
    /// what stops someone else filling this store.
    public static let maxKeysPerEntity = 256

    private let inner: TypedStore<SymkeyEntry>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    // MARK: - identity

    /// `SHA256(key)`, first ``keyIdLength`` hex characters.
    public static func keyId(of key: Data) -> String {
        Hash.sha256(key)
            .prefix(keyIdLength / 2)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    /// Whether `version` is a mint time rather than a pre-spec counter.
    public static func isTimestamp(_ version: Int64) -> Bool {
        version >= legacyVersionCeiling
    }

    // MARK: - keys

    /// `<entityId>_<19-digit version>_<16-hex keyId>`.
    ///
    /// Two properties are load-bearing. The zero-padded version makes the
    /// key's text order the version order, so ``versions(for:)`` and
    /// ``currentVersion(for:)`` are answered from the key list alone —
    /// no ciphertext is touched to find out which version is current.
    /// And the keyId suffix is what lets two different keys share a
    /// version instead of one displacing the other. The key is local, so
    /// it owes Android no parity.
    static func storageKey(entityId: String, version: Int64, keyId: String) -> String {
        entityId + "_" + String(format: "%019lld", version) + "_" + keyId
    }

    /// Slices from the **end**: 16 hex, `_`, 19 digits, `_`, and whatever
    /// precedes that is the entity id.
    ///
    /// Fixed widths read backwards, rather than splitting on separators,
    /// so an entity id containing an underscore still parses. It also
    /// tells the new row shape from the pre-spec one (`<entityId>_<19
    /// digits>`) without a version marker: the old shape has no
    /// underscore where this one requires one, so it parses to nil here
    /// and is picked up by ``migrateLegacyRowKeys(now:)`` instead.
    static func parse(storageKey: String) -> (entityId: String, version: Int64, keyId: String)? {
        // 1 entity char + "_" + 19 version + "_" + 16 keyId
        guard storageKey.count >= 1 + 1 + 19 + 1 + Self.keyIdLength else { return nil }

        let keyIdStart = storageKey.index(storageKey.endIndex, offsetBy: -Self.keyIdLength)
        let keyId = String(storageKey[keyIdStart...])
        guard keyId.allSatisfy({ $0.isHexDigit }) else { return nil }

        let secondSeparator = storageKey.index(before: keyIdStart)
        guard storageKey[secondSeparator] == "_" else { return nil }

        let versionStart = storageKey.index(secondSeparator, offsetBy: -19)
        guard let version = Int64(storageKey[versionStart ..< secondSeparator]) else { return nil }

        let firstSeparator = storageKey.index(before: versionStart)
        guard storageKey[firstSeparator] == "_" else { return nil }

        let entityId = String(storageKey[storageKey.startIndex ..< firstSeparator])
        guard !entityId.isEmpty else { return nil }
        return (entityId, version, keyId)
    }

    /// The pre-spec row shape, `<entityId>_<19-digit version>`. Only
    /// ``migrateLegacyRowKeys(now:)`` reads it.
    static func parseLegacy(storageKey: String) -> (entityId: String, version: Int64)? {
        guard parse(storageKey: storageKey) == nil else { return nil }
        guard let separator = storageKey.lastIndex(of: "_") else { return nil }
        let entityId = String(storageKey[storageKey.startIndex ..< separator])
        let versionText = storageKey[storageKey.index(after: separator)...]
        guard !entityId.isEmpty, let version = Int64(versionText) else { return nil }
        return (entityId, version)
    }

    // MARK: - minting

    /// The version a key minted now would carry:
    /// `max(nowSeconds, highestKnown + 1)`.
    ///
    /// **The floor is not decoration.** Two cases stop being improbable
    /// and become impossible. A device minting twice inside one second —
    /// a double-tapped "Reset the key", a test loop — is forced onto the
    /// next value instead of colliding with itself. And a clock that
    /// steps backwards (an NTP correction, a restored snapshot, a fresh
    /// install with the wrong time) cannot mint a key that sorts *below*
    /// one already held. That case is worse than a tie: "current" would
    /// select the retired key, so an owner who rotates after removing a
    /// member keeps sealing under the key that member still holds, and
    /// nothing says so.
    ///
    /// What is left is a timestamp where the clock is sane and a counter
    /// where it is not.
    public func nextVersion(for entityId: String, now: Date = Date()) throws -> Int64 {
        let clock = Int64(now.timeIntervalSince1970)
        let floor = try currentVersion(for: entityId) + 1
        return max(max(clock, floor), Self.minimumVersion)
    }

    /// A fresh 32-byte key for `entityId`, stored and returned — the one
    /// way a key is created.
    ///
    /// First key or rotation, it is the same operation: the floor in
    /// ``nextVersion(for:now:)`` makes "the next version" and "the first
    /// version" the same question, so there is nothing for a caller to
    /// special-case and no way for one to name a version by hand. Naming
    /// one by hand was how a reinstalled owner minted a second version 1.
    @discardableResult
    public func mint(for entityId: String, now: Date = Date()) throws -> SymkeyEntry {
        let entry = SymkeyEntry(
            entityId: entityId,
            version: try nextVersion(for: entityId, now: now),
            key: FileCipher.randomSymkey(),
            createdAt: Int64(now.timeIntervalSince1970 * 1000)
        )
        try validate(entityId: entityId, version: entry.version, key: entry.key)
        try guardCapacity(for: entityId)
        try inner.put(
            entry,
            key: Self.storageKey(entityId: entityId, version: entry.version, keyId: entry.keyId)
        )
        return entry
    }

    // MARK: - storing

    /// Store a key we were given. Returns false when we already hold
    /// **this same key** at this version — which is not an error, it is
    /// the normal result of two members answering one request.
    ///
    /// A *different* key at a version we already hold is added beside the
    /// one there, not over it. See the type's note for why no caller is
    /// trusted to authorise a replacement, the owner included.
    @discardableResult
    public func store(
        _ key: Data,
        for entityId: String,
        version: Int64,
        now: Date = Date()
    ) throws -> Bool {
        try validate(entityId: entityId, version: version, key: key)
        let storageKey = Self.storageKey(
            entityId: entityId, version: version, keyId: Self.keyId(of: key)
        )
        if try inner.exists(storageKey) { return false }
        try guardCapacity(for: entityId)

        let entry = SymkeyEntry(
            entityId: entityId,
            version: version,
            key: key,
            createdAt: Int64(now.timeIntervalSince1970 * 1000)
        )
        try inner.put(entry, key: storageKey)
        return true
    }

    private func validate(entityId: String, version: Int64, key: Data) throws {
        guard !entityId.isEmpty else { throw Failure.noEntityId }
        guard version >= Self.minimumVersion else { throw Failure.badVersion(version) }
        guard key.count == Self.keyLength else { throw Failure.badKeyLength(key.count) }
    }

    /// Checked before a row is added, never before a no-op: re-storing a
    /// key we already hold must not be able to fail on a full store.
    private func guardCapacity(for entityId: String) throws {
        let held = try rowKeys(for: entityId).count
        guard held < Self.maxKeysPerEntity else {
            throw Failure.tooManyKeys(entityId: entityId, limit: Self.maxKeysPerEntity)
        }
    }

    // MARK: - reading

    /// Every key we hold at one version, newest first.
    ///
    /// **A list, not one key.** Two devices of one owner minting in the
    /// same second is the only way this returns more than one element,
    /// and it is rare enough that no caller will see it in practice —
    /// but a caller that assumes a single key is a caller that silently
    /// picks the wrong one when it happens, which is the failure this
    /// whole design exists to remove.
    public func keys(for entityId: String, version: Int64) throws -> [Data] {
        try entries(for: entityId, version: version).map(\.key)
    }

    /// The entries we hold at one version, newest minted first, ties
    /// broken by key id.
    ///
    /// **The tie-break is not tidiness.** Where two keys share a version
    /// *and* a mint millisecond, every device must choose the same one as
    /// current, or two members seal new messages under different keys and
    /// each other's traffic stops opening. Ordering on the key's own hash
    /// decides it identically everywhere, with nothing exchanged.
    public func entries(for entityId: String, version: Int64) throws -> [SymkeyEntry] {
        try rowKeys(for: entityId, version: version)
            .compactMap { try inner.get($0) }
            .sorted {
                ($0.createdAt ?? 0) != ($1.createdAt ?? 0)
                    ? ($0.createdAt ?? 0) > ($1.createdAt ?? 0)
                    : $0.keyId < $1.keyId
            }
    }

    /// The key new messages are sealed with: the newest-minted key at the
    /// newest version we hold, or nil if we hold none.
    public func currentKey(for entityId: String) throws -> Data? {
        let version = try currentVersion(for: entityId)
        guard version >= Self.minimumVersion else { return nil }
        return try keys(for: entityId, version: version).first
    }

    /// The newest version we hold, or 0 for an entity we have no key for
    /// — matching Android's `getCurrentVersion`.
    public func currentVersion(for entityId: String) throws -> Int64 {
        try versions(for: entityId).last ?? 0
    }

    /// Every version we hold for an entity, ascending and distinct. Read
    /// from the key list, so nothing is decrypted.
    public func versions(for entityId: String) throws -> [Int64] {
        var seen: Set<Int64> = []
        return try inner.keys()
            .compactMap { rowKey in
                guard let parsed = Self.parse(storageKey: rowKey),
                      parsed.entityId == entityId,
                      seen.insert(parsed.version).inserted
                else { return nil }
                return parsed.version
            }
            .sorted()
    }

    public func entry(for entityId: String, version: Int64, keyId: String) throws -> SymkeyEntry? {
        try inner.get(Self.storageKey(entityId: entityId, version: version, keyId: keyId))
    }

    public func has(entityId: String) throws -> Bool {
        try currentVersion(for: entityId) >= Self.minimumVersion
    }

    public func has(entityId: String, version: Int64) throws -> Bool {
        try !rowKeys(for: entityId, version: version).isEmpty
    }

    /// How many keys we hold for an entity, counting every version.
    public func count(for entityId: String) throws -> Int {
        try rowKeys(for: entityId).count
    }

    /// Every entity we hold a key for. From the key list, undecrypted.
    public func entityIds() throws -> [String] {
        var seen: Set<String> = []
        return try inner.keys().compactMap { rowKey in
            guard let parsed = Self.parse(storageKey: rowKey),
                  seen.insert(parsed.entityId).inserted
            else { return nil }
            return parsed.entityId
        }
    }

    /// Row names for one entity, optionally at one version. Names only —
    /// no ciphertext is read.
    private func rowKeys(for entityId: String, version: Int64? = nil) throws -> [String] {
        try inner.keys().filter { rowKey in
            guard let parsed = Self.parse(storageKey: rowKey),
                  parsed.entityId == entityId
            else { return false }
            return version == nil || parsed.version == version
        }
    }

    // MARK: - migrating

    /// Rewrite pre-spec rows (`<entityId>_<version>`) under the current
    /// row shape, and report how many moved.
    ///
    /// Local, lossless and idempotent: the key id is computed from the
    /// key already in the row, so nothing is fetched and nothing is
    /// decided. Rows already in the current shape are left alone, and a
    /// row whose new name is somehow taken is dropped rather than
    /// duplicated — the key under that name is the same key, since the
    /// name contains its hash.
    @discardableResult
    public func migrateLegacyRowKeys(now: Date = Date()) throws -> Int {
        var moved = 0
        for rowKey in try inner.keys() {
            guard let legacy = Self.parseLegacy(storageKey: rowKey),
                  let entry = try inner.get(rowKey)
            else { continue }
            let moving = SymkeyEntry(
                entityId: legacy.entityId,
                version: legacy.version,
                key: entry.key,
                createdAt: entry.createdAt ?? Int64(now.timeIntervalSince1970 * 1000),
                active: entry.active
            )
            let target = Self.storageKey(
                entityId: moving.entityId, version: moving.version, keyId: moving.keyId
            )
            if try !inner.exists(target) { try inner.put(moving, key: target) }
            try inner.delete(rowKey)
            moved += 1
        }
        return moved
    }

    // MARK: - deleting

    /// Forget one key. `keyId` nil removes every key at that version.
    @discardableResult
    public func remove(entityId: String, version: Int64, keyId: String? = nil) throws -> Int {
        var removed = 0
        for rowKey in try rowKeys(for: entityId, version: version) {
            if let keyId, Self.parse(storageKey: rowKey)?.keyId != keyId { continue }
            try inner.delete(rowKey)
            removed += 1
        }
        return removed
    }

    /// Forget every key for an entity — leaving a room for good. This
    /// makes that room's history permanently unreadable, which is the
    /// point, and is why nothing calls it as part of an ordinary
    /// rotation.
    @discardableResult
    public func removeAll(for entityId: String) throws -> Int {
        var removed = 0
        for rowKey in try rowKeys(for: entityId) {
            try inner.delete(rowKey)
            removed += 1
        }
        return removed
    }

    // MARK: - sharing

    /// Seal our keys at one version to `recipientPubkey`, for the SYMKEY
    /// messages that carry them — Android's `createShareCipher`.
    /// AsyOneWay, so only the recipient can open them; we already have
    /// the keys.
    ///
    /// **Every key at that version, not one of them.** In the one case
    /// where there are two, we cannot know which of them seals the
    /// messages the asker cannot read — so sending our favourite would
    /// leave them exactly where they started, with a key stored and
    /// nothing opened and no way to ask for the other one. Sending both
    /// costs one extra message in a case that essentially never happens.
    ///
    /// Empty when we hold that version not at all, rather than throwing:
    /// not having a key is an ordinary answer to "share this".
    public func shareCiphers(
        for entityId: String, version: Int64, to recipientPubkey: Data
    ) throws -> [String] {
        try keys(for: entityId, version: version).map {
            try AsyOneWayCipher.encrypt(plaintext: $0, toPubkey: recipientPubkey)
        }
    }

    /// Open a shared key and store it — Android's
    /// `receiveSharedSymkey`. Returns false when the cipher will not
    /// open with our key, or when we already hold that same key.
    @discardableResult
    public func receiveShared(
        cipher: String,
        for entityId: String,
        version: Int64,
        privkey: Data,
        now: Date = Date()
    ) throws -> Bool {
        guard let key = try? AsyCipher.decrypt(cipherString: cipher, privkey: privkey) else {
            return false
        }
        return try store(key, for: entityId, version: version, now: now)
    }

    // MARK: - message bodies

    /// Seal `message`'s body with the entity's current key, stamping the
    /// version used. Throws when we hold no key for the entity — a
    /// message that cannot be sealed must not be sent in the clear.
    @discardableResult
    public func seal(_ message: inout ImMessage, for entityId: String) throws -> Int64 {
        let version = try currentVersion(for: entityId)
        guard version >= Self.minimumVersion,
              let key = try keys(for: entityId, version: version).first
        else { throw Failure.noKey(entityId: entityId) }
        try message.sealBody(symkey: key, version: version)
        return version
    }

    /// Open `message`'s body with **the version it names**, not with the
    /// current one — that is the whole reason old versions are kept.
    ///
    /// Tries every key held at that version and lets AES-GCM's tag
    /// decide, which is exact: a wrong key cannot authenticate. In
    /// practice there is one key and one attempt.
    ///
    /// Returns false when we hold no such version (the caller's cue to
    /// ask for it with a ``RequestType/symkey`` request) or when no key
    /// there opens the body. It does not throw: one unreadable message
    /// must not abort a batch.
    @discardableResult
    public func open(_ message: inout ImMessage, for entityId: String) throws -> Bool {
        let version = message.symkeyVersion ?? Self.minimumVersion
        guard version >= Self.minimumVersion else { return false }
        for key in try keys(for: entityId, version: version) {
            if message.openBody(symkey: key) { return true }
        }
        return false
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case noEntityId
        case badVersion(Int64)
        case badKeyLength(Int)
        case noKey(entityId: String)
        case tooManyKeys(entityId: String, limit: Int)

        public var description: String {
            switch self {
            case .noEntityId:
                return "SymkeyStore: no entity id"
            case .badVersion(let v):
                return "SymkeyStore: version \(v) is below the minimum of \(SymkeyStore.minimumVersion)"
            case .badKeyLength(let n):
                return "SymkeyStore: key is \(n) bytes, expected \(SymkeyStore.keyLength)"
            case .noKey(let entityId):
                return "SymkeyStore: no key held for \(entityId)"
            case .tooManyKeys(let entityId, let limit):
                return "SymkeyStore: \(entityId) already holds the maximum of \(limit) keys"
            }
        }
    }
}

/// The `SYMKEY` message payload: `"<entityId>:<AsyOneWay cipher>"`, with
/// the version in ``ImMessage/symkeyVersion``.
///
/// Split on the **first** colon, always. The cipher is a JSON envelope
/// and is full of colons of its own, so splitting on the last one — or
/// on all of them — would hand back a mangled key. Android's
/// `content.indexOf(':')` says the same thing more quietly.
public enum SymkeyShare {

    public static func payload(entityId: String, cipher: String) -> String {
        entityId + ":" + cipher
    }

    public static func parse(_ payload: String) -> (entityId: String, cipher: String)? {
        guard let sep = payload.firstIndex(of: ":") else { return nil }
        let entityId = String(payload[payload.startIndex ..< sep])
        let cipher = String(payload[payload.index(after: sep)...])
        guard !entityId.isEmpty, !cipher.isEmpty else { return nil }
        return (entityId, cipher)
    }

    /// The entity a ``RequestType/symkey`` request is asking about.
    /// Android accepts both a bare id and an `id:…` form, so this does
    /// too.
    public static func requestedEntityId(_ content: String?) -> String? {
        requested(content)?.entityId
    }

    /// What a `SYMKEY` request is asking for: the entity, and the
    /// version when one is named.
    ///
    /// FIMP4V3 §5.1 and FIMP2V3 §5.2 define the content as
    /// `"<entityId>"` for the current version or `"<entityId>:<version>"`
    /// for a specific one. **Both clients used to parse the id out of
    /// the second form and then answer with their current version
    /// anyway**, which made the whole point of naming a version — asking
    /// for an *old* key, so messages sealed before a rotation can be
    /// read — impossible to express. A member who had every version but
    /// the one they needed could ask forever and be handed the one they
    /// already held.
    ///
    /// A version that is not a positive integer is treated as **absent**
    /// rather than as a failed request: the sender may be a client that
    /// puts something else after the colon, and answering with the
    /// current key is what this protocol did before versions could be
    /// named, so it is the compatible reading.
    public static func requested(_ content: String?) -> (entityId: String, version: Int64?)? {
        guard let content, !content.isEmpty else { return nil }
        guard let sep = content.firstIndex(of: ":") else { return (content, nil) }
        let entityId = String(content[content.startIndex ..< sep])
        guard !entityId.isEmpty else { return nil }
        let tail = String(content[content.index(after: sep)...])
        guard let version = Int64(tail), version >= SymkeyStore.minimumVersion else {
            return (entityId, nil)
        }
        return (entityId, version)
    }

    /// The content of a request for one entity, naming a version when
    /// one is wanted. See ``requested(_:)``.
    public static func request(entityId: String, version: Int64? = nil) -> String {
        guard let version, version >= SymkeyStore.minimumVersion else { return entityId }
        return entityId + ":" + String(version)
    }

    // MARK: - SYMKEY_HISTORY

    /// The most versions one ``RequestType/symkeyHistory`` request may
    /// ask for.
    ///
    /// **A bound is a security property, not tidiness.** Every version
    /// named costs the responder one asymmetric seal and one message on
    /// somebody's DOCK, paid for by the responder. An unbounded list is
    /// therefore an amplifier: a single small request naming ten
    /// thousand versions would have a member's device seal and pay to
    /// send ten thousand replies. No real entity has been rotated this
    /// many times, so the cap costs nothing legitimate.
    public static let maxHistoryVersions = 64

    /// The content of a batch request — FIMP4V3 §5.2, FIMP2V3 §5.3:
    /// `"<entityId>:<v1>,<v2>,…"`.
    ///
    /// Versions are de-duplicated and sorted, so the same set always
    /// produces the same request, and capped at
    /// ``maxHistoryVersions``. Returns nil when no version is worth
    /// asking for, since a batch request naming none has no meaning —
    /// the caller wants ``request(entityId:version:)`` for that.
    public static func historyRequest(entityId: String, versions: [Int64]) -> String? {
        guard !entityId.isEmpty else { return nil }
        let wanted = Set(versions.filter { $0 >= SymkeyStore.minimumVersion })
            .sorted()
            .prefix(maxHistoryVersions)
        guard !wanted.isEmpty else { return nil }
        return entityId + ":" + wanted.map(String.init).joined(separator: ",")
    }

    /// What a batch request is asking for.
    ///
    /// Unreadable entries are **skipped rather than failing the
    /// request**: a list of eight versions with one piece of nonsense in
    /// it is still seven keys somebody needs, and refusing the whole
    /// thing helps nobody. A request whose every entry is unreadable
    /// yields nil, because there is then nothing to answer.
    public static func requestedHistory(_ content: String?) -> (entityId: String, versions: [Int64])? {
        guard let content, !content.isEmpty else { return nil }
        guard let sep = content.firstIndex(of: ":") else { return nil }
        let entityId = String(content[content.startIndex ..< sep])
        guard !entityId.isEmpty else { return nil }
        let versions = Set(
            content[content.index(after: sep)...]
                .split(separator: ",")
                .compactMap { Int64($0.trimmingCharacters(in: .whitespaces)) }
                .filter { $0 >= SymkeyStore.minimumVersion }
        )
        .sorted()
        .prefix(maxHistoryVersions)
        guard !versions.isEmpty else { return nil }
        return (entityId, Array(versions))
    }
}
