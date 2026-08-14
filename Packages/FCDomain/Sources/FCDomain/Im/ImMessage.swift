import Foundation

/// One instant message, mirroring `FC-AJDK/.../data/fcData/ImMessage.java`
/// field for field.
///
/// **Two serializations that deliberately disagree.**
///
/// ``wireJson()`` is the local-storage form and carries everything,
/// including the delivery bookkeeping this device has accumulated. It
/// also crosses devices: a HISTORY share writes one line of it per
/// message into a file the other client reads back, so Gson's rules bind
/// — declaration order, nulls omitted, HTML escaping disabled, enums by
/// name.
///
/// ``toWireBytes()`` is what actually travels, and it carries only what
/// the recipient could possibly know: no status, no `roadIds`, no
/// `dockId`, no `readAt`, no `unread`. Those describe *this* device's
/// relationship to the message. A port that helpfully preserved them
/// across the wire would be telling the receiver facts about itself that
/// the sender invented.
///
/// **The id is not derived.** Unlike ``Mail`` and ``Hat``, whose ids are
/// hashes of their own content, an `ImMessage` id is a 16-char hex
/// rendering of the FUDP layer's 64-bit message id — assigned by the
/// transport, not by the model. `ImMessage.getId()` in Java exists purely
/// to *suppress* `FcEntity`'s hash-based auto-generation, because a
/// 64-char hash would not survive ``fudpId`` and would break delivery
/// quietly. There is no `checkIdWithCreate` here on purpose.
public struct ImMessage: Codable, Equatable, Sendable, Identifiable {

    // MARK: - fields, in Java declaration order

    public var type: ImType?
    public var senderId: String?
    /// The FID for a P2P message; the square, team or room id otherwise.
    public var targetId: String?
    /// Milliseconds since the epoch.
    public var timestamp: Int64?
    /// Tiebreaker for two messages in the same millisecond. Local-only —
    /// it is not on the wire, so it orders our own copy, not the world's.
    public var sequence: Int64?

    public var contentType: ContentType?
    /// Text, or the metadata/JSON payload for the structured kinds.
    public var content: String?
    /// Small binary payloads, Base64. Anything over
    /// ``maxInlineDataSize`` goes to a DISK instead and travels as a HAT.
    public var dataBase64: String?

    public var requestType: RequestType?
    /// The id of the request a `RESPONSE` (or `RECEIPT`) answers.
    public var requestId: String?

    /// ROAD servers that relayed this, in order. Local-only.
    public var roadIds: [String]?
    /// The DOCK that held it while we were offline. Local-only.
    public var dockId: String?
    /// Local-only.
    public var deliveryMethod: DeliveryMethod?
    /// Local-only.
    public var status: MessageStatus?
    /// Local-only.
    public var deliveredAt: Int64?
    /// Local-only.
    public var readAt: Int64?

    /// The sealed body, for the flavours that seal one. Which envelope it
    /// is depends on ``type``: AsyTwoWay for P2P, a versioned symkey for
    /// team and room, nothing at all for a square.
    public var cipher: String?
    /// Which symkey version ``cipher`` was sealed with. **Long here, but
    /// only 32 bits of it survive the wire** — see ``toWireBytes()``.
    public var symkeyVersion: Int64?

    public var replyToId: String?
    public var threadId: String?

    /// Cached display name for the sender. Local-only.
    public var senderName: String?
    /// Local-only.
    public var unread: Bool?
    /// Local-only.
    public var pinned: Bool?
    /// Soft delete. Local-only.
    public var deleted: Bool?

    /// 16 lowercase hex chars — see the type's note. `nil` until the FUDP
    /// layer names it.
    public var id: String?

    public init(
        type: ImType? = nil,
        senderId: String? = nil,
        targetId: String? = nil,
        timestamp: Int64? = nil,
        sequence: Int64? = nil,
        contentType: ContentType? = nil,
        content: String? = nil,
        dataBase64: String? = nil,
        requestType: RequestType? = nil,
        requestId: String? = nil,
        roadIds: [String]? = nil,
        dockId: String? = nil,
        deliveryMethod: DeliveryMethod? = nil,
        status: MessageStatus? = nil,
        deliveredAt: Int64? = nil,
        readAt: Int64? = nil,
        cipher: String? = nil,
        symkeyVersion: Int64? = nil,
        replyToId: String? = nil,
        threadId: String? = nil,
        senderName: String? = nil,
        unread: Bool? = nil,
        pinned: Bool? = nil,
        deleted: Bool? = nil,
        id: String? = nil
    ) {
        self.type = type
        self.senderId = senderId
        self.targetId = targetId
        self.timestamp = timestamp
        self.sequence = sequence
        self.contentType = contentType
        self.content = content
        self.dataBase64 = dataBase64
        self.requestType = requestType
        self.requestId = requestId
        self.roadIds = roadIds
        self.dockId = dockId
        self.deliveryMethod = deliveryMethod
        self.status = status
        self.deliveredAt = deliveredAt
        self.readAt = readAt
        self.cipher = cipher
        self.symkeyVersion = symkeyVersion
        self.replyToId = replyToId
        self.threadId = threadId
        self.senderName = senderName
        self.unread = unread
        self.pinned = pinned
        self.deleted = deleted
        self.id = id
    }

    /// The largest payload that may travel inline in ``dataBase64``
    /// (900 KB — 100 KB of headroom under a DOCK server's 1 MB limit).
    /// Anything larger goes to a DISK and is shared as a HAT reference.
    public static let maxInlineDataSize = 900 * 1024

    // MARK: - id

    /// Java's `longIdToHex`: the FUDP id as 16 lowercase hex chars.
    ///
    /// Java formats a *signed* `long` with `%016x`, which prints the
    /// two's-complement bit pattern, and reads it back with
    /// `parseUnsignedLong`. So the round trip is over the bits, not the
    /// value, and a negative id is perfectly ordinary — half of them are.
    public static func hexId(fudpId: Int64) -> String {
        String(format: "%016llx", UInt64(bitPattern: fudpId))
    }

    /// Java's `hexIdToLong`. `nil` when the string is not 16 hex chars.
    public static func fudpId(hexId: String) -> Int64? {
        guard hexId.count == 16, let bits = UInt64(hexId, radix: 16) else { return nil }
        return Int64(bitPattern: bits)
    }

    /// The transport naming this message.
    public mutating func setId(fudpId: Int64) {
        id = Self.hexId(fudpId: fudpId)
    }

    /// Whether a FUDP-shaped id has been assigned. A 64-char hash would
    /// answer `false` here, which is exactly the accident this guards.
    public var hasFudpId: Bool { id?.count == 16 }

    // MARK: - derived

    public func isOutgoing(from fid: String) -> Bool { senderId == fid }

    /// Who the conversation is *with*, from `fid`'s point of view. For
    /// anything but P2P that is the group, so it is just ``targetId``.
    public func conversationPartnerId(for fid: String) -> String? {
        guard type == .p2p else { return targetId }
        return senderId == fid ? targetId : senderId
    }

    // MARK: - factories

    /// Port of the private `createBase`: type, routing, content type, a
    /// timestamp of now, and `PENDING`. The id is *not* set — the FUDP
    /// layer assigns it on the way out.
    public static func make(
        type: ImType,
        from senderId: String,
        to targetId: String,
        contentType: ContentType,
        now: Date = Date()
    ) -> ImMessage {
        ImMessage(
            type: type,
            senderId: senderId,
            targetId: targetId,
            timestamp: Int64(now.timeIntervalSince1970 * 1000),
            contentType: contentType,
            status: .pending
        )
    }

    public static func text(
        type: ImType, from: String, to: String, _ text: String, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .text, now: now)
        m.content = text
        m.unread = false
        return m
    }

    /// Inline binary: `metaJson` describes it (name, size, type), the
    /// payload rides Base64 in `dataBase64`.
    public static func stream(
        type: ImType, from: String, to: String,
        metaJson: String, dataBase64: String, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .stream, now: now)
        m.content = metaJson
        m.dataBase64 = dataBase64
        m.unread = false
        return m
    }

    /// A file share. `hatJson` is the raw HAT — plaintext key and DISK
    /// locas — which is what makes it openable by the receiver.
    public static func hat(
        type: ImType, from: String, to: String, hatJson: String, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .hat, now: now)
        m.content = hatJson
        m.unread = false
        return m
    }

    /// Inline audio. `metaJson` is
    /// `{"durationMs":…,"sampleRate":…,"format":"aac"}`.
    public static func voice(
        type: ImType, from: String, to: String,
        metaJson: String, dataBase64: String, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .voice, now: now)
        m.content = metaJson
        m.dataBase64 = dataBase64
        m.unread = false
        return m
    }

    public static func request(
        type: ImType, from: String, to: String,
        requestType: RequestType, data: String? = nil, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .request, now: now)
        m.requestType = requestType
        m.content = data
        return m
    }

    public static func response(
        type: ImType, from: String, to: String,
        requestId: String, data: String? = nil, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .response, now: now)
        m.requestId = requestId
        m.content = data
        return m
    }

    /// A delivery or read receipt for `originalMessageId`. Always P2P —
    /// a receipt is addressed to the one sender, whatever kind of
    /// conversation the original was in.
    public static func receipt(
        from: String, to: String, originalMessageId: String, read: Bool, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: .p2p, from: from, to: to, contentType: .receipt, now: now)
        m.requestId = originalMessageId
        m.content = read ? "read" : "delivered"
        return m
    }

    /// Pushing a symmetric key at a member, unasked — the other half of
    /// ``RequestType/symkey``.
    public static func symkey(
        type: ImType, from: String, to: String,
        symkeyData: String, version: Int64, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .symkey, now: now)
        m.content = symkeyData
        m.symkeyVersion = version
        return m
    }

    public static func members(
        type: ImType, from: String, to: String, membersJson: String, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .members, now: now)
        m.content = membersJson
        return m
    }

    /// A history share: `hatJson` points at the exported history file,
    /// `kCipherBase64` is the file's symkey sealed to the receiver.
    public static func history(
        type: ImType, from: String, to: String,
        hatJson: String, kCipherBase64: String?, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .history, now: now)
        m.content = hatJson
        m.dataBase64 = kCipherBase64
        return m
    }

    /// The room lifecycle notifications, which differ only in their
    /// content type and all carry the room id as their content:
    /// ``ContentType/roomInfo`` (whose content is the RoomInfo JSON
    /// instead), `roomLeave`, `roomAccept`, `roomDisband`, `roomRemoved`.
    ///
    /// Three of those — disband, removed, and any info that changes
    /// membership — are only meaningful from the room's owner, and this
    /// factory does not and cannot check that. The verification belongs
    /// where the room is known; see Phase 9.2.5.
    public static func roomNotice(
        _ contentType: ContentType, from: String, to: String,
        content: String, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: .room, from: from, to: to, contentType: contentType, now: now)
        m.content = content
        return m
    }

    // MARK: - JSON

    /// The JSON Android's `JsonUtils.toJson(message)` produces: Java
    /// declaration order, nulls omitted, HTML escaping **disabled**,
    /// enums by name.
    ///
    /// Written by hand rather than by `JSONEncoder` because key order is
    /// the point — a history file is read by the other client, and both
    /// have to agree on the bytes.
    public func wireJson() -> String {
        GsonCompatibleWriter.object(orderedFields(), htmlSafe: false)
    }

    public static func fromJson(_ json: String) throws -> ImMessage {
        try JSONDecoder().decode(ImMessage.self, from: Data(json.utf8))
    }

    /// Declaration order: `ImMessage`'s own fields, then `FcEntity`'s
    /// `id`. `FcEntity` also declares `meta`, which this app never sets
    /// and Gson therefore never writes, so it is not modelled.
    private func orderedFields() -> [(String, GsonCompatibleWriter.Value)] {
        var out: [(String, GsonCompatibleWriter.Value)] = []
        func put(_ k: String, _ v: String?) { if let v { out.append((k, .string(v))) } }
        func put(_ k: String, _ v: Int64?)  { if let v { out.append((k, .int(v))) } }
        func put(_ k: String, _ v: Bool?)   { if let v { out.append((k, .bool(v))) } }
        func put(_ k: String, _ v: [String]?) { if let v { out.append((k, .stringArray(v))) } }

        put("type", type?.rawValue)
        put("senderId", senderId)
        put("targetId", targetId)
        put("timestamp", timestamp)
        put("sequence", sequence)
        put("contentType", contentType?.rawValue)
        put("content", content)
        put("dataBase64", dataBase64)
        put("requestType", requestType?.rawValue)
        put("requestId", requestId)
        put("roadIds", roadIds)
        put("dockId", dockId)
        put("deliveryMethod", deliveryMethod?.rawValue)
        put("status", status?.rawValue)
        put("deliveredAt", deliveredAt)
        put("readAt", readAt)
        put("cipher", cipher)
        put("symkeyVersion", symkeyVersion)
        put("replyToId", replyToId)
        put("threadId", threadId)
        put("senderName", senderName)
        put("unread", unread)
        put("pinned", pinned)
        put("deleted", deleted)
        put("id", id)
        return out
    }

    // MARK: - binary wire format

    /// Bit positions in the 2-byte flag word. Bits 9–15 are reserved.
    private enum WireFlag {
        static let content: UInt16        = 0x0001
        static let dataBase64: UInt16     = 0x0002
        static let cipher: UInt16         = 0x0004
        static let symkeyVersion: UInt16  = 0x0008
        static let requestType: UInt16    = 0x0010
        static let requestId: UInt16      = 0x0020
        static let replyToId: UInt16      = 0x0040
        static let threadId: UInt16       = 0x0080
        static let messageId: UInt16      = 0x0100
    }

    /// The shortest legal encoding: the fixed header alone, with both
    /// ids empty and no optional fields.
    static let wireHeaderSize = 14

    /// Port of `toWireBytes()`:
    ///
    /// ```
    ///   type(1) contentType(1)
    ///   senderId(u8-prefixed) targetId(u8-prefixed)
    ///   timestamp(8, big-endian)
    ///   flags(2, big-endian)
    ///   [content] [dataBase64] [cipher]   — each u16-prefixed
    ///   [symkeyVersion(4)] [requestType(1)]
    ///   [requestId] [replyToId] [threadId] [id]  — each u16-prefixed
    /// ```
    ///
    /// Three things here are lossy, and all three are reproduced rather
    /// than repaired, because the other end is the Android client and it
    /// is the format that has to match:
    ///
    /// 1. **``symkeyVersion`` is truncated to 32 bits** (Java writes
    ///    `putInt(intValue())` and reads back `(long) getInt()`), so a
    ///    version past 2³¹ comes out the far side sign-extended and
    ///    negative. Rotations would have to run for a very long time to
    ///    reach that, but a port that widened the field would simply
    ///    desynchronise from Android at the first message.
    /// 2. **A nil ``type`` or ``contentType`` writes ordinal 0**, so it
    ///    arrives as `P2P`/`TEXT` rather than as nothing.
    /// 3. **Empty and nil are the same on the far side** for the
    ///    length-prefixed strings: the flag says the field is present,
    ///    the length says zero, and the reader produces `""`.
    ///
    /// A sender id longer than 255 UTF-8 bytes cannot be length-prefixed
    /// with one byte; FIDs are 34, so this throws rather than silently
    /// truncating.
    public func toWireBytes() throws -> Data {
        let sender = Data((senderId ?? "").utf8)
        let target = Data((targetId ?? "").utf8)
        guard sender.count <= 0xFF, target.count <= 0xFF else {
            throw WireFailure.idTooLong
        }

        var flags: UInt16 = 0
        if content != nil       { flags |= WireFlag.content }
        if dataBase64 != nil    { flags |= WireFlag.dataBase64 }
        if cipher != nil        { flags |= WireFlag.cipher }
        if symkeyVersion != nil { flags |= WireFlag.symkeyVersion }
        if requestType != nil   { flags |= WireFlag.requestType }
        if requestId != nil     { flags |= WireFlag.requestId }
        if replyToId != nil     { flags |= WireFlag.replyToId }
        if threadId != nil      { flags |= WireFlag.threadId }
        if id != nil            { flags |= WireFlag.messageId }

        var out = Data()
        out.append(type?.wireOrdinal ?? 0)
        out.append(contentType?.wireOrdinal ?? 0)
        try Self.appendLen8(&out, sender)
        try Self.appendLen8(&out, target)
        Self.appendBE(&out, UInt64(bitPattern: timestamp ?? 0))
        Self.appendBE(&out, flags)

        try Self.appendLen16(&out, content)
        try Self.appendLen16(&out, dataBase64)
        try Self.appendLen16(&out, cipher)
        if let symkeyVersion {
            Self.appendBE(&out, UInt32(truncatingIfNeeded: symkeyVersion))
        }
        if let requestType { out.append(requestType.wireOrdinal) }
        try Self.appendLen16(&out, requestId)
        try Self.appendLen16(&out, replyToId)
        try Self.appendLen16(&out, threadId)
        try Self.appendLen16(&out, id)
        return out
    }

    /// Port of `fromWireBytes(byte[])`. Everything local-only comes back
    /// nil — see the type's note.
    ///
    /// When the flag word has no ``WireFlag/messageId`` bit the message
    /// arrives nameless and the caller must name it, from the FUDP
    /// message id or the ROAD/DOCK header.
    public static func fromWireBytes(_ data: Data) throws -> ImMessage {
        guard data.count >= wireHeaderSize else { throw WireFailure.truncated }
        var cursor = Cursor(data)
        var m = ImMessage()

        m.type = ImType(wireOrdinal: try cursor.byte())
        m.contentType = ContentType(wireOrdinal: try cursor.byte())
        m.senderId = try cursor.len8String()
        m.targetId = try cursor.len8String()
        m.timestamp = Int64(bitPattern: try cursor.u64())

        let flags = try cursor.u16()
        if flags & WireFlag.content != 0       { m.content = try cursor.len16String() }
        if flags & WireFlag.dataBase64 != 0    { m.dataBase64 = try cursor.len16String() }
        if flags & WireFlag.cipher != 0        { m.cipher = try cursor.len16String() }
        if flags & WireFlag.symkeyVersion != 0 {
            // Sign-extend, as Java's `(long) buf.getInt()` does.
            m.symkeyVersion = Int64(Int32(bitPattern: try cursor.u32()))
        }
        if flags & WireFlag.requestType != 0   { m.requestType = RequestType(wireOrdinal: try cursor.byte()) }
        if flags & WireFlag.requestId != 0     { m.requestId = try cursor.len16String() }
        if flags & WireFlag.replyToId != 0     { m.replyToId = try cursor.len16String() }
        if flags & WireFlag.threadId != 0      { m.threadId = try cursor.len16String() }
        if flags & WireFlag.messageId != 0     { m.id = try cursor.len16String() }
        return m
    }

    public enum WireFailure: Error, CustomStringConvertible {
        case truncated
        case idTooLong
        case fieldTooLong(String)

        public var description: String {
            switch self {
            case .truncated:
                return "ImMessage: wire data ended mid-field"
            case .idTooLong:
                return "ImMessage: senderId/targetId exceeds the 255-byte length prefix"
            case .fieldTooLong(let name):
                return "ImMessage: \(name) exceeds the 65535-byte length prefix"
            }
        }
    }

    // MARK: - wire helpers

    private static func appendBE(_ out: inout Data, _ value: UInt16) {
        out.append(UInt8(truncatingIfNeeded: value >> 8))
        out.append(UInt8(truncatingIfNeeded: value))
    }

    private static func appendBE(_ out: inout Data, _ value: UInt32) {
        for shift in stride(from: 24, through: 0, by: -8) {
            out.append(UInt8(truncatingIfNeeded: value >> UInt32(shift)))
        }
    }

    private static func appendBE(_ out: inout Data, _ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            out.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    private static func appendLen8(_ out: inout Data, _ bytes: Data) throws {
        guard bytes.count <= 0xFF else { throw WireFailure.idTooLong }
        out.append(UInt8(bytes.count))
        out.append(bytes)
    }

    /// Writes nothing when `value` is nil — the flag word already said so.
    private static func appendLen16(_ out: inout Data, _ value: String?) throws {
        guard let value else { return }
        let bytes = Data(value.utf8)
        guard bytes.count <= 0xFFFF else { throw WireFailure.fieldTooLong(String(value.prefix(16)) + "…") }
        appendBE(&out, UInt16(bytes.count))
        out.append(bytes)
    }

    /// A forward-only reader over a `Data` that may be a slice, so every
    /// read is relative to `startIndex` rather than to zero.
    private struct Cursor {
        private let data: Data
        private var offset: Int

        init(_ data: Data) {
            self.data = data
            self.offset = data.startIndex
        }

        mutating func byte() throws -> UInt8 {
            guard offset < data.endIndex else { throw WireFailure.truncated }
            defer { offset += 1 }
            return data[offset]
        }

        mutating func bytes(_ count: Int) throws -> Data {
            guard count >= 0, data.endIndex - offset >= count else { throw WireFailure.truncated }
            defer { offset += count }
            return data[offset ..< offset + count]
        }

        mutating func u16() throws -> UInt16 {
            let hi = UInt16(try byte()), lo = UInt16(try byte())
            return hi << 8 | lo
        }

        mutating func u32() throws -> UInt32 {
            var v: UInt32 = 0
            for _ in 0 ..< 4 { v = v << 8 | UInt32(try byte()) }
            return v
        }

        mutating func u64() throws -> UInt64 {
            var v: UInt64 = 0
            for _ in 0 ..< 8 { v = v << 8 | UInt64(try byte()) }
            return v
        }

        /// Invalid UTF-8 decodes lossily rather than throwing: Java's
        /// `new String(bytes, UTF_8)` substitutes U+FFFD too, and a
        /// mangled byte in one field should not discard a whole message.
        mutating func len8String() throws -> String {
            let len = Int(try byte())
            return String(decoding: try bytes(len), as: UTF8.self)
        }

        mutating func len16String() throws -> String {
            let len = Int(try u16())
            return String(decoding: try bytes(len), as: UTF8.self)
        }
    }
}
