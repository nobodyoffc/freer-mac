import Foundation
import FCCore

/// A room: private group messaging whose membership is defined
/// **locally**, mirroring `FC-AJDK/.../data/fcData/Room.java`.
///
/// Nothing about a room is on the chain. There is no carve to look up,
/// no indexed member list, no way for a stranger to enumerate one — and
/// equally no arbiter. The owner's copy *is* the membership, and every
/// other member holds a cache of what the owner last told them. That is
/// the whole difference from a Team (9.2.6), and it is why every
/// membership-changing notification has to be checked against the owner
/// before it is believed: there is nothing else to check against.
public struct Room: Codable, Equatable, Sendable, Identifiable {

    /// FID of the owner. Always also a member.
    public var owner: String?
    public var name: String?
    public var desc: String?
    public var members: [String]?
    /// Invited but not yet confirmed by a `ROOM_ACCEPT`. **Owner-side
    /// bookkeeping only** — it is never sent, and `RoomInfo` has no
    /// field for it, so a member's copy of a room never has one.
    public var pendingMembers: [String]?

    /// The key version the **owner last announced**.
    ///
    /// Not the same fact as "the newest key we hold" — that is
    /// ``SymkeyStore/currentVersion(for:)``, and the two differ exactly
    /// when a rotation has been announced but its key has not reached us
    /// yet. That gap is the cue to ask for the key, so collapsing the
    /// two into one number would erase the thing we need to notice.
    ///
    /// Android's `Room` also carries `symkeyCipher` and `symkeyHistory`;
    /// here the keys live in ``SymkeyStore`` alone, so there is one
    /// place that can answer what we can decrypt.
    public var symkeyVersion: Int64?

    public var created: Int64?
    public var lastActive: Int64?
    /// Last membership or key change.
    public var lastUpdated: Int64?

    /// `false` once the room has been disbanded, or we were removed
    /// from it. The row is kept either way — the transcript outlives the
    /// room.
    public var active: Bool?
    public var avatarDid: String?
    /// Service URLs the owner set, e.g. the DOCK the room's traffic goes
    /// through.
    public var home: [String: String]?

    // Local preferences
    public var muted: Bool?
    public var pinned: Bool?

    public var id: String?

    public init(
        owner: String? = nil,
        name: String? = nil,
        desc: String? = nil,
        members: [String]? = nil,
        pendingMembers: [String]? = nil,
        symkeyVersion: Int64? = nil,
        created: Int64? = nil,
        lastActive: Int64? = nil,
        lastUpdated: Int64? = nil,
        active: Bool? = nil,
        avatarDid: String? = nil,
        home: [String: String]? = nil,
        muted: Bool? = nil,
        pinned: Bool? = nil,
        id: String? = nil
    ) {
        self.owner = owner
        self.name = name
        self.desc = desc
        self.members = members
        self.pendingMembers = pendingMembers
        self.symkeyVersion = symkeyVersion
        self.created = created
        self.lastActive = lastActive
        self.lastUpdated = lastUpdated
        self.active = active
        self.avatarDid = avatarDid
        self.home = home
        self.muted = muted
        self.pinned = pinned
        self.id = id
    }

    // MARK: - identity

    /// Port of `generateRoomId`: `room_` + the first 24 hex chars of
    /// `sha256(owner ‖ millis ‖ random)`.
    ///
    /// **The id contains an underscore**, which is not incidental: a
    /// room id turns up as the entity id in ``SymkeyStore``'s storage
    /// keys and as the target in a ``Conversation`` id, and both of
    /// those join with `_`. That is why the symkey key parses on the
    /// *last* underscore rather than the first.
    public static func generateId(owner: String, now: Date = Date(), random: UInt64? = nil) -> String {
        let nonce = random ?? UInt64.random(in: UInt64.min ... UInt64.max)
        let seed = owner + String(Int64(now.timeIntervalSince1970 * 1000)) + String(Int64(bitPattern: nonce))
        let hash = Hash.sha256(Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
        return "room_" + String(hash.prefix(24))
    }

    public mutating func checkIdWithCreate(now: Date = Date()) {
        guard id == nil, let owner else { return }
        id = Self.generateId(owner: owner, now: now)
    }

    /// A brand-new room, owned by `owner`, who is its first member.
    public static func create(owner: String, name: String?, desc: String? = nil, now: Date = Date()) -> Room {
        let stamp = Int64(now.timeIntervalSince1970 * 1000)
        var room = Room(
            owner: owner,
            name: name,
            desc: desc,
            members: [owner],
            symkeyVersion: 1,
            created: stamp,
            lastActive: stamp,
            lastUpdated: stamp,
            active: true
        )
        room.checkIdWithCreate(now: now)
        return room
    }

    // MARK: - membership

    public func isMember(_ fid: String?) -> Bool {
        guard let fid else { return false }
        return members?.contains(fid) ?? false
    }

    public func isOwner(_ fid: String?) -> Bool {
        guard let fid, let owner else { return false }
        return fid == owner
    }

    public func isPendingMember(_ fid: String) -> Bool {
        pendingMembers?.contains(fid) ?? false
    }

    public var memberCount: Int { members?.count ?? 0 }

    /// Everyone but `fid` — who a broadcast actually goes to.
    public func others(than fid: String) -> [String] {
        (members ?? []).filter { $0 != fid }
    }

    @discardableResult
    public mutating func addMember(_ fid: String, now: Date = Date()) -> Bool {
        var current = members ?? []
        guard !current.contains(fid) else { return false }
        current.append(fid)
        members = current
        lastUpdated = Int64(now.timeIntervalSince1970 * 1000)
        return true
    }

    /// Remove a member. **The owner cannot be removed** — a room with no
    /// owner has nobody who can speak for its membership, so this
    /// refuses rather than leaving one behind.
    @discardableResult
    public mutating func removeMember(_ fid: String, now: Date = Date()) -> Bool {
        guard !isOwner(fid) else { return false }
        var current = members ?? []
        guard let index = current.firstIndex(of: fid) else { return false }
        current.remove(at: index)
        members = current
        pendingMembers?.removeAll { $0 == fid }
        lastUpdated = Int64(now.timeIntervalSince1970 * 1000)
        return true
    }

    @discardableResult
    public mutating func addPendingMember(_ fid: String) -> Bool {
        guard !isOwner(fid) else { return false }
        var current = pendingMembers ?? []
        guard !current.contains(fid) else { return false }
        current.append(fid)
        pendingMembers = current
        return true
    }

    /// Clear a member's pending flag, on their `ROOM_ACCEPT`.
    @discardableResult
    public mutating func confirmMember(_ fid: String) -> Bool {
        guard var current = pendingMembers, let index = current.firstIndex(of: fid) else { return false }
        current.remove(at: index)
        pendingMembers = current.isEmpty ? nil : current
        return true
    }

    /// A room that has been disbanded, or that we were removed from.
    public var isInactive: Bool { active == false }

    public func matches(query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return false }
        func hit(_ s: String?) -> Bool { s?.lowercased().contains(needle) ?? false }
        return hit(name) || hit(desc) || hit(id) || (members ?? []).contains { hit($0) }
    }

    // MARK: - JSON

    /// Local storage only — a `Room` is never sent. What crosses is
    /// ``RoomInfo``.
    public func wireJson() -> String {
        GsonCompatibleWriter.object(orderedFields(), htmlSafe: false)
    }

    public static func fromJson(_ json: String) throws -> Room {
        try JSONDecoder().decode(Room.self, from: Data(json.utf8))
    }

    private func orderedFields() -> [(String, GsonCompatibleWriter.Value)] {
        var out: [(String, GsonCompatibleWriter.Value)] = []
        func put(_ k: String, _ v: String?) { if let v { out.append((k, .string(v))) } }
        func put(_ k: String, _ v: Int64?)  { if let v { out.append((k, .int(v))) } }
        func put(_ k: String, _ v: Bool?)   { if let v { out.append((k, .bool(v))) } }
        func put(_ k: String, _ v: [String]?) { if let v { out.append((k, .stringArray(v))) } }
        func put(_ k: String, _ v: [String: String]?) { if let v { out.append((k, .stringMap(v))) } }

        put("owner", owner)
        put("name", name)
        put("desc", desc)
        put("members", members)
        put("pendingMembers", pendingMembers)
        put("symkeyVersion", symkeyVersion)
        put("created", created)
        put("lastActive", lastActive)
        put("lastUpdated", lastUpdated)
        put("active", active)
        put("avatarDid", avatarDid)
        put("home", home)
        put("muted", muted)
        put("pinned", pinned)
        put("id", id)
        return out
    }
}

/// What one member tells another about a room — the payload of a
/// ``ContentType/roomInfo`` message, mirroring
/// `FC-AJDK/.../data/fcData/RoomInfo.java`.
///
/// This is the only shape of a room that crosses the wire, and it does
/// two jobs at once: it is the **invitation** to a room you are not in,
/// and the **update** for one you are. Which one it is depends entirely
/// on whether the receiver already has the room, and that ambiguity is
/// where the sharp edges are — see ``RoomService/acceptInvite(roomInfoJson:as:now:)``.
///
/// ``symkey`` is the room key sealed to *one* recipient's pubkey, so a
/// `RoomInfo` is built per recipient rather than broadcast verbatim.
public struct RoomInfo: Codable, Equatable, Sendable {

    public var name: String?
    public var desc: String?
    public var owner: String?
    /// The room key, AsyOneWay-sealed to the recipient. Nil for an
    /// update to someone who already has it.
    public var symkey: String?
    public var symkeyVersion: Int64?
    public var members: [String]?
    public var home: [String: String]?
    public var id: String?

    public init(
        name: String? = nil,
        desc: String? = nil,
        owner: String? = nil,
        symkey: String? = nil,
        symkeyVersion: Int64? = nil,
        members: [String]? = nil,
        home: [String: String]? = nil,
        id: String? = nil
    ) {
        self.name = name
        self.desc = desc
        self.owner = owner
        self.symkey = symkey
        self.symkeyVersion = symkeyVersion
        self.members = members
        self.home = home
        self.id = id
    }

    /// Describe `room`. The key is added separately, per recipient.
    public static func from(_ room: Room) -> RoomInfo {
        RoomInfo(
            name: room.name,
            desc: room.desc,
            owner: room.owner,
            symkeyVersion: room.symkeyVersion,
            members: room.members,
            home: room.home,
            id: room.id
        )
    }

    /// Fold this into a room we already have. **Local preferences are
    /// not touched** — muted, pinned and `active` are ours, and an
    /// update from the owner has no business overwriting whether we
    /// muted their room.
    public func apply(to room: inout Room, now: Date = Date()) {
        if let name { room.name = name }
        if let desc { room.desc = desc }
        if let owner { room.owner = owner }
        if let members { room.members = members }
        if let symkeyVersion { room.symkeyVersion = symkeyVersion }
        if let home { room.home = home }
        room.lastUpdated = Int64(now.timeIntervalSince1970 * 1000)
    }

    /// Build a fresh room from this description — accepting an invite.
    public func toRoom(now: Date = Date()) -> Room {
        let stamp = Int64(now.timeIntervalSince1970 * 1000)
        return Room(
            owner: owner,
            name: name,
            desc: desc,
            members: members ?? [],
            symkeyVersion: symkeyVersion ?? 1,
            created: stamp,
            lastActive: stamp,
            lastUpdated: stamp,
            active: true,
            home: home,
            id: id
        )
    }

    public func wireJson() -> String {
        GsonCompatibleWriter.object(orderedFields(), htmlSafe: false)
    }

    public static func fromJson(_ json: String) throws -> RoomInfo {
        try JSONDecoder().decode(RoomInfo.self, from: Data(json.utf8))
    }

    private func orderedFields() -> [(String, GsonCompatibleWriter.Value)] {
        var out: [(String, GsonCompatibleWriter.Value)] = []
        func put(_ k: String, _ v: String?) { if let v { out.append((k, .string(v))) } }
        func put(_ k: String, _ v: Int64?)  { if let v { out.append((k, .int(v))) } }
        func put(_ k: String, _ v: [String]?) { if let v { out.append((k, .stringArray(v))) } }
        func put(_ k: String, _ v: [String: String]?) { if let v { out.append((k, .stringMap(v))) } }

        put("name", name)
        put("desc", desc)
        put("owner", owner)
        put("symkey", symkey)
        put("symkeyVersion", symkeyVersion)
        put("members", members)
        put("home", home)
        put("id", id)
        return out
    }
}
