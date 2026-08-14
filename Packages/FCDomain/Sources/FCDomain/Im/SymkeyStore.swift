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
    /// Monotonic from 1. See ``SymkeyStore/minimumVersion``.
    public var version: Int64
    /// The raw 32-byte AES key.
    public var key: Data
    /// Milliseconds since the epoch.
    public var createdAt: Int64?
    /// Kept for parity with Android's row. Nothing retires a key today:
    /// a rotation supersedes a version rather than revoking it, because
    /// the old messages sealed under it still have to open.
    public var active: Bool?

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
/// **Every version is kept forever.** A rotation does not replace a key,
/// it adds one: messages already sealed under v3 still have to open
/// after the room moves to v4, and the only copy of v3 is this store. So
/// "the key for this room" always means "the newest version", and
/// decryption always asks for the version the message names.
///
/// **A received key never overwrites one we already hold** unless the
/// caller says the sender is the entity's owner. That check is the
/// difference between a rotation and an attack: without it any member
/// could push a bogus key for an existing version and make everyone
/// else's history unreadable. This store cannot tell who the owner is —
/// that lives with `Room` and `Team` in 9.2.5/9.2.6 — so it takes the
/// answer as an argument and makes the caller state it.
public struct SymkeyStore {

    public static let namespace = "im.symkeys.v1"

    /// Versions start at 1, and 0 means "no key" (Android's
    /// `getCurrentVersion` returns 0 for an entity it has never seen).
    ///
    /// Non-positive versions are refused outright, and that is a real
    /// guard rather than a formality: ``ImMessage/symkeyVersion`` is a
    /// 64-bit field that the wire carries in 32 bits and sign-extends on
    /// the way back, so a peer *can* name a negative version. Storing
    /// one would put a key where no honest rotation could ever reach it.
    public static let minimumVersion: Int64 = 1

    /// AES-256.
    public static let keyLength = 32

    private let inner: TypedStore<SymkeyEntry>

    public init(kv: EncryptedKVStore) {
        self.inner = TypedStore(kv: kv, namespace: Self.namespace)
    }

    // MARK: - keys

    /// `<entityId>_<19-digit version>`.
    ///
    /// Android's key is `entityId + "_" + version` unpadded, and it then
    /// loads every row to find the highest version. Padding here makes
    /// the key's text order the version order, so ``versions(for:)`` and
    /// ``currentVersion(for:)`` are answered from the key list alone —
    /// no ciphertext is touched to find out which key is current. The
    /// key is local, so it owes Android no parity.
    static func storageKey(entityId: String, version: Int64) -> String {
        entityId + "_" + String(format: "%019lld", version)
    }

    /// Splits on the **last** underscore, so an entity id containing one
    /// still parses. Returns nil for anything that is not our key shape.
    static func parse(storageKey: String) -> (entityId: String, version: Int64)? {
        guard let sep = storageKey.lastIndex(of: "_") else { return nil }
        let entityId = String(storageKey[storageKey.startIndex ..< sep])
        let versionText = storageKey[storageKey.index(after: sep)...]
        guard !entityId.isEmpty, let version = Int64(versionText) else { return nil }
        return (entityId, version)
    }

    // MARK: - generating

    /// A fresh 32-byte key for `entityId` at `version`, stored and
    /// returned. Overwrites any key already held at that version —
    /// generating is something only we do, for an entity we own, and a
    /// caller that asks for a key at a version they already have has
    /// asked for a new key.
    @discardableResult
    public func generate(
        for entityId: String, version: Int64, now: Date = Date()
    ) throws -> SymkeyEntry {
        let entry = SymkeyEntry(
            entityId: entityId,
            version: version,
            key: FileCipher.randomSymkey(),
            createdAt: Int64(now.timeIntervalSince1970 * 1000)
        )
        try validate(entityId: entityId, version: version, key: entry.key)
        try inner.put(entry, key: Self.storageKey(entityId: entityId, version: version))
        return entry
    }

    /// The next version up, generated and stored — what an owner does
    /// when the membership changes.
    ///
    /// The old version stays: it is the only thing that can still open
    /// what was said before the rotation.
    @discardableResult
    public func rotate(for entityId: String, now: Date = Date()) throws -> SymkeyEntry {
        let next = max(try currentVersion(for: entityId) + 1, Self.minimumVersion)
        return try generate(for: entityId, version: next, now: now)
    }

    // MARK: - storing

    /// Store a key we were given. Returns false when a key is already
    /// held at that version and `allowOverwrite` is false — which is
    /// **not** an error: re-sharing a key we already have is the normal
    /// result of two members answering the same request.
    ///
    /// `allowOverwrite` should be true only when the sender is the
    /// entity's owner. See the type's note.
    @discardableResult
    public func store(
        _ key: Data,
        for entityId: String,
        version: Int64,
        allowOverwrite: Bool,
        now: Date = Date()
    ) throws -> Bool {
        try validate(entityId: entityId, version: version, key: key)
        let storageKey = Self.storageKey(entityId: entityId, version: version)
        if !allowOverwrite, try inner.exists(storageKey) { return false }

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

    // MARK: - reading

    /// The key for one version, or nil if we do not hold it.
    public func key(for entityId: String, version: Int64) throws -> Data? {
        try inner.get(Self.storageKey(entityId: entityId, version: version))?.key
    }

    /// The newest key for an entity, or nil if we hold none.
    public func currentKey(for entityId: String) throws -> Data? {
        let version = try currentVersion(for: entityId)
        guard version >= Self.minimumVersion else { return nil }
        return try key(for: entityId, version: version)
    }

    /// The newest version we hold, or 0 for an entity we have no key for
    /// — matching Android's `getCurrentVersion`.
    public func currentVersion(for entityId: String) throws -> Int64 {
        try versions(for: entityId).last ?? 0
    }

    /// Every version we hold for an entity, ascending. Read from the key
    /// list, so nothing is decrypted.
    public func versions(for entityId: String) throws -> [Int64] {
        try inner.keys().compactMap { storageKey in
            guard let parsed = Self.parse(storageKey: storageKey),
                  parsed.entityId == entityId
            else { return nil }
            return parsed.version
        }
        .sorted()
    }

    public func entry(for entityId: String, version: Int64) throws -> SymkeyEntry? {
        try inner.get(Self.storageKey(entityId: entityId, version: version))
    }

    public func has(entityId: String) throws -> Bool {
        try currentVersion(for: entityId) >= Self.minimumVersion
    }

    public func has(entityId: String, version: Int64) throws -> Bool {
        try inner.exists(Self.storageKey(entityId: entityId, version: version))
    }

    /// Every entity we hold a key for. From the key list, undecrypted.
    public func entityIds() throws -> [String] {
        var seen: Set<String> = []
        return try inner.keys().compactMap { storageKey in
            guard let parsed = Self.parse(storageKey: storageKey),
                  seen.insert(parsed.entityId).inserted
            else { return nil }
            return parsed.entityId
        }
    }

    // MARK: - deleting

    @discardableResult
    public func remove(entityId: String, version: Int64) throws -> Bool {
        let storageKey = Self.storageKey(entityId: entityId, version: version)
        guard try inner.exists(storageKey) else { return false }
        try inner.delete(storageKey)
        return true
    }

    /// Forget every key for an entity — leaving a room for good. This
    /// makes that room's history permanently unreadable, which is the
    /// point, and is why nothing calls it as part of an ordinary
    /// rotation.
    @discardableResult
    public func removeAll(for entityId: String) throws -> Int {
        var removed = 0
        for version in try versions(for: entityId) where try remove(entityId: entityId, version: version) {
            removed += 1
        }
        return removed
    }

    // MARK: - sharing

    /// Seal one of our keys to `recipientPubkey` for the SYMKEY message
    /// that carries it — Android's `createShareCipher`. AsyOneWay, so
    /// only the recipient can open it; we already have the key.
    ///
    /// Returns nil when we do not hold that version, rather than
    /// throwing: not having a key is an ordinary answer to "share this".
    public func shareCipher(
        for entityId: String, version: Int64, to recipientPubkey: Data
    ) throws -> String? {
        guard let key = try key(for: entityId, version: version) else { return nil }
        return try AsyOneWayCipher.encrypt(plaintext: key, toPubkey: recipientPubkey)
    }

    /// Open a shared key and store it — Android's
    /// `receiveSharedSymkey`. Returns false when the cipher will not
    /// open with our key, or when we already hold that version and
    /// `allowOverwrite` is false.
    @discardableResult
    public func receiveShared(
        cipher: String,
        for entityId: String,
        version: Int64,
        privkey: Data,
        allowOverwrite: Bool,
        now: Date = Date()
    ) throws -> Bool {
        guard let key = try? AsyCipher.decrypt(cipherString: cipher, privkey: privkey) else {
            return false
        }
        return try store(
            key, for: entityId, version: version, allowOverwrite: allowOverwrite, now: now
        )
    }

    // MARK: - message bodies

    /// Seal `message`'s body with the entity's current key, stamping the
    /// version used. Throws when we hold no key for the entity — a
    /// message that cannot be sealed must not be sent in the clear.
    @discardableResult
    public func seal(_ message: inout ImMessage, for entityId: String) throws -> Int64 {
        let version = try currentVersion(for: entityId)
        guard version >= Self.minimumVersion, let key = try key(for: entityId, version: version)
        else { throw Failure.noKey(entityId: entityId) }
        try message.sealBody(symkey: key, version: version)
        return version
    }

    /// Open `message`'s body with **the version it names**, not with the
    /// current one — that is the whole reason old versions are kept.
    ///
    /// Returns false when we hold no such version (the caller's cue to
    /// ask for it with a ``RequestType/symkey`` request) or when the
    /// body will not open. It does not throw: one unreadable message
    /// must not abort a batch.
    @discardableResult
    public func open(_ message: inout ImMessage, for entityId: String) throws -> Bool {
        let version = message.symkeyVersion ?? Self.minimumVersion
        guard version >= Self.minimumVersion, let key = try key(for: entityId, version: version)
        else { return false }
        return message.openBody(symkey: key)
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case noEntityId
        case badVersion(Int64)
        case badKeyLength(Int)
        case noKey(entityId: String)

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
        guard let content, !content.isEmpty else { return nil }
        guard let sep = content.firstIndex(of: ":") else { return content }
        let entityId = String(content[content.startIndex ..< sep])
        return entityId.isEmpty ? nil : entityId
    }
}
