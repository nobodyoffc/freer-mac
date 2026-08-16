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
    /// On the wire this is the **first section of the body**, not a field
    /// of its own — see ``toWireBytes()``.
    public var content: String?
    /// Inline binary payload — audio, an attachment, a wrapped key.
    ///
    /// **Raw bytes, not Base64.** v1 carried this as a Base64 *string*
    /// because the wire had no way to express bytes; v2's body framing
    /// does, so the +33% is gone. Local storage still writes it as
    /// `dataBase64` (see ``wireJson()``), because a history file is read
    /// by Android's Gson and that key is part of the file format.
    ///
    /// Whether a payload may travel inline at all is a property of the
    /// destination, not a constant — see ``DockRegistry/inlineBudget(for:)``.
    public var data: Data?

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

    /// The sealed body, for the flavours that seal one — a binary
    /// ``CryptoBundle``. Which envelope it holds depends on ``type``:
    /// AsyTwoWay for P2P (AsyOneWay for self-chat), a versioned symkey for
    /// team and room, nothing at all for a square.
    ///
    /// This replaces v1's `cipher`, and the replacement is the point of
    /// the version break: v1 sealed `content` and left `dataBase64` beside
    /// it in the clear, so a voice note travelled with its metadata
    /// encrypted and its audio readable. Here the seal covers
    /// ``content`` *and* ``data`` together, so that state cannot be built.
    public var body: Data?
    /// Which symkey version ``body`` was sealed with. **Long here, but
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
        data: Data? = nil,
        requestType: RequestType? = nil,
        requestId: String? = nil,
        roadIds: [String]? = nil,
        dockId: String? = nil,
        deliveryMethod: DeliveryMethod? = nil,
        status: MessageStatus? = nil,
        deliveredAt: Int64? = nil,
        readAt: Int64? = nil,
        body: Data? = nil,
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
        self.data = data
        self.requestType = requestType
        self.requestId = requestId
        self.roadIds = roadIds
        self.dockId = dockId
        self.deliveryMethod = deliveryMethod
        self.status = status
        self.deliveredAt = deliveredAt
        self.readAt = readAt
        self.body = body
        self.symkeyVersion = symkeyVersion
        self.replyToId = replyToId
        self.threadId = threadId
        self.senderName = senderName
        self.unread = unread
        self.pinned = pinned
        self.deleted = deleted
        self.id = id
    }

    /// What to assume a DOCK will accept per item when its service record
    /// does not say — FAPI13's own `DEFAULT_MAX_DATA_SIZE`.
    ///
    /// This is a **floor to fall back on, not a limit to enforce**. The
    /// real ceiling is whatever the destination DOCK advertises in its
    /// on-chain service record, and it varies by operator; resolve it with
    /// ``DockRegistry/inlineBudget(for:)`` and measure the encoded
    /// envelope against that.
    ///
    /// v1 had a fixed `maxInlineDataSize` of 900 KB here, justified by an
    /// assumed 1 MB server limit that does not exist. The server's default
    /// is this value — 14× smaller — so inline binary failed long before
    /// the documented limit and the failure looked like a wire bug.
    public static let assumedDockItemLimit = 64 * 1024

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
    /// payload rides raw in ``data``.
    public static func stream(
        type: ImType, from: String, to: String,
        metaJson: String, data: Data, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .stream, now: now)
        m.content = metaJson
        m.data = data
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
        metaJson: String, data: Data, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .voice, now: now)
        m.content = metaJson
        m.data = data
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
        hatJson: String, kCipher: Data?, now: Date = Date()
    ) -> ImMessage {
        var m = make(type: type, from: from, to: to, contentType: .history, now: now)
        m.content = hatJson
        m.data = kCipher
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

    /// Local storage renames v1's `dataBase64` and `cipher` to match the
    /// model, and FIMP0V2 §7 fixes both as **Base64 strings** — which is
    /// what Swift's `Data` Codable already produces.
    ///
    /// Keeping the old names would have been friendlier to read and worse
    /// to debug: the *encoding* of both values changed (a JSON envelope
    /// became a binary bundle), so a v1 record under a v1 name would look
    /// decodable and fail deep inside the crypto instead of at the field.
    /// A hard break should break loudly.
    enum CodingKeys: String, CodingKey {
        case type, senderId, targetId, timestamp, sequence
        case contentType, content, data
        case requestType, requestId
        case roadIds, dockId, deliveryMethod, status, deliveredAt, readAt
        case body
        case symkeyVersion, replyToId, threadId
        case senderName, unread, pinned, deleted, id
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
        // Local storage keeps the *opened* body. A history file is read by
        // the other client, so this is file format, not wire format, and
        // FIMP0V2 §7 pins it: binary fields are Base64 strings, because
        // JSON has no way to hold bytes and Gson's default for `byte[]` (a
        // JSON array of signed numbers) is neither compact nor obvious.
        put("data", data?.base64EncodedString())
        put("requestType", requestType?.rawValue)
        put("requestId", requestId)
        put("roadIds", roadIds)
        put("dockId", dockId)
        put("deliveryMethod", deliveryMethod?.rawValue)
        put("status", status?.rawValue)
        put("deliveredAt", deliveredAt)
        put("readAt", readAt)
        put("body", body?.base64EncodedString())
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

    /// Bit positions in the 2-byte flag word. Bits 8–15 are reserved.
    enum WireFlag {
        static let body: UInt16           = 0x0001
        static let bodySealed: UInt16     = 0x0002
        static let symkeyVersion: UInt16  = 0x0004
        static let requestType: UInt16    = 0x0008
        static let requestId: UInt16      = 0x0010
        static let replyToId: UInt16      = 0x0020
        static let threadId: UInt16       = 0x0040
        static let messageId: UInt16      = 0x0080
    }

    /// `0xF1 0x02` — FIMP magic, then the wire version.
    ///
    /// The magic byte is load-bearing, not decoration. A v1 envelope opens
    /// with the `ImType` ordinal, a value in 0…3, so a bare version byte
    /// of 2 is indistinguishable from a v1 **TEAM** message: a v2 reader
    /// would parse legacy team traffic as v2 and misparse it silently
    /// instead of rejecting it. `0xF1` cannot occur as a v1 first byte, so
    /// the rejection is deterministic in both directions.
    public static let wireMagic: UInt8 = 0xF1
    public static let wireVersion: UInt8 = 0x02

    /// The shortest legal encoding: magic, version, the fixed header,
    /// both ids empty, no optional fields.
    static let wireHeaderSize = 16

    /// The FIMP v2 envelope:
    ///
    /// ```
    ///   magic(1)=0xF1 version(1)=0x02
    ///   type(1) contentType(1)
    ///   senderId(u8-prefixed) targetId(u8-prefixed)
    ///   timestamp(8, big-endian)
    ///   flags(2, big-endian)
    ///   [body(u32-prefixed)]
    ///   [symkeyVersion(4)] [requestType(1)]
    ///   [requestId] [replyToId] [threadId] [id]  — each u16-prefixed
    /// ```
    ///
    /// **One private field.** ``content`` and ``data`` are not fields here
    /// at all: they are framed together into the body (``bodyFraming()``),
    /// and it is that framing the mode's cipher seals. v1 had three
    /// payload fields and sealed one of them, which is how a voice note
    /// shipped with encrypted metadata and cleartext audio. With a single
    /// field the rule is "seal the body", and the half-sealed state has no
    /// encoding.
    ///
    /// Two v1 behaviours are kept deliberately, because Android reproduces
    /// them and the format is what has to match:
    ///
    /// 1. **``symkeyVersion`` is truncated to 32 bits** (Java writes
    ///    `putInt(intValue())` and reads back `(long) getInt()`), so a
    ///    version past 2³¹ comes out sign-extended and negative.
    /// 2. **A nil ``type`` or ``contentType`` writes ordinal 0**, so it
    ///    arrives as `P2P`/`TEXT` rather than as nothing.
    ///
    /// One is fixed: a length that does not fit its prefix now throws.
    /// v1's 16-bit prefix silently wrapped on Android, corrupting every
    /// field after it, which is the failure this version exists to end.
    public func toWireBytes() throws -> Data {
        let sender = Data((senderId ?? "").utf8)
        let target = Data((targetId ?? "").utf8)
        guard sender.count <= 0xFF, target.count <= 0xFF else {
            throw WireFailure.idTooLong
        }

        // A sealed body is carried as-is; an unsealed one is framed here.
        //
        // **Empty counts as absent.** The framing records a length, not a
        // presence, so a zero-length section reads back as nil and cannot
        // read back as `""`. Encoding an empty payload as an 8-byte
        // all-zero framing would therefore make the round trip unstable:
        // decode would yield nil, and re-encoding would emit no body at
        // all. Treating empty as absent on the way out keeps
        // encode→decode→encode byte-identical, which is what lets a relay
        // forward a message it decoded. v1 said the same thing about its
        // length-prefixed strings ("empty and nil are the same on the far
        // side"); v2 just has to apply it one level up.
        let wireBody: Data?
        if let body {
            wireBody = body
        } else if !(content ?? "").isEmpty || !(data ?? Data()).isEmpty {
            wireBody = bodyFraming()
        } else {
            wireBody = nil
        }

        var flags: UInt16 = 0
        if wireBody != nil      { flags |= WireFlag.body }
        if body != nil          { flags |= WireFlag.bodySealed }
        if symkeyVersion != nil { flags |= WireFlag.symkeyVersion }
        if requestType != nil   { flags |= WireFlag.requestType }
        if requestId != nil     { flags |= WireFlag.requestId }
        if replyToId != nil     { flags |= WireFlag.replyToId }
        if threadId != nil      { flags |= WireFlag.threadId }
        if id != nil            { flags |= WireFlag.messageId }

        var out = Data()
        out.append(Self.wireMagic)
        out.append(Self.wireVersion)
        out.append(type?.wireOrdinal ?? 0)
        out.append(contentType?.wireOrdinal ?? 0)
        try Self.appendLen8(&out, sender)
        try Self.appendLen8(&out, target)
        Self.appendBE(&out, UInt64(bitPattern: timestamp ?? 0))
        Self.appendBE(&out, flags)

        if let wireBody {
            guard wireBody.count <= Int(UInt32.max) else { throw WireFailure.fieldTooLong("body") }
            Self.appendBE(&out, UInt32(wireBody.count))
            out.append(wireBody)
        }
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

    /// Read a v2 envelope. Everything local-only comes back nil — see the
    /// type's note.
    ///
    /// A sealed body lands in ``body`` and stays sealed; ``content`` and
    /// ``data`` are populated only once something opens it (see
    /// `ImMessageBody`). An unsealed body is unframed here and there is
    /// nothing left to open.
    ///
    /// When the flag word has no ``WireFlag/messageId`` bit the message
    /// arrives nameless and the caller must name it, from the FUDP
    /// message id or the ROAD/DOCK header.
    public static func fromWireBytes(_ bytes: Data) throws -> ImMessage {
        guard bytes.count >= wireHeaderSize else { throw WireFailure.truncated }
        var cursor = Cursor(bytes)
        var m = ImMessage()

        let magic = try cursor.byte()
        let version = try cursor.byte()
        guard magic == wireMagic else { throw WireFailure.notFimp(magic: magic) }
        guard version == wireVersion else { throw WireFailure.wrongVersion(version) }

        m.type = ImType(wireOrdinal: try cursor.byte())
        m.contentType = ContentType(wireOrdinal: try cursor.byte())
        m.senderId = try cursor.len8String()
        m.targetId = try cursor.len8String()
        m.timestamp = Int64(bitPattern: try cursor.u64())

        let flags = try cursor.u16()
        if flags & WireFlag.body != 0 {
            let length = Int(try cursor.u32())
            let raw = Data(try cursor.bytes(length))
            if flags & WireFlag.bodySealed != 0 {
                m.body = raw
            } else {
                try m.applyBodyFraming(raw)
            }
        } else if flags & WireFlag.bodySealed != 0 {
            // Sealed-but-absent is not a shape any encoder produces.
            throw WireFailure.sealedWithoutBody
        }
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

    // MARK: - body framing

    /// The plaintext layout inside the body:
    /// `contentLen(4) ‖ content ‖ dataLen(4) ‖ data`.
    ///
    /// Both sections are always framed; an absent one is a zero length.
    /// This is what a cipher seals, and what it returns on opening — so
    /// the two payloads are inside or outside the seal *together*, never
    /// one without the other.
    public func bodyFraming() -> Data {
        let contentBytes = Data((content ?? "").utf8)
        let dataBytes = data ?? Data()
        var out = Data()
        Self.appendBE(&out, UInt32(contentBytes.count))
        out.append(contentBytes)
        Self.appendBE(&out, UInt32(dataBytes.count))
        out.append(dataBytes)
        return out
    }

    /// Unframe a body into ``content`` and ``data``.
    ///
    /// A zero-length section reads back as `nil`, not as `""`/empty: the
    /// framing cannot tell absent from empty, and every producer of an
    /// empty section means absent.
    public mutating func applyBodyFraming(_ framing: Data) throws {
        var cursor = Cursor(framing)
        let contentLength = Int(try cursor.u32())
        let contentBytes = try cursor.bytes(contentLength)
        let dataLength = Int(try cursor.u32())
        let dataBytes = try cursor.bytes(dataLength)

        content = contentLength == 0 ? nil : String(decoding: contentBytes, as: UTF8.self)
        data = dataLength == 0 ? nil : Data(dataBytes)
    }

    public enum WireFailure: Error, Equatable, CustomStringConvertible {
        case truncated
        case idTooLong
        case fieldTooLong(String)
        case notFimp(magic: UInt8)
        case wrongVersion(UInt8)
        case sealedWithoutBody

        public var description: String {
            switch self {
            case .truncated:
                return "ImMessage: wire data ended mid-field"
            case .idTooLong:
                return "ImMessage: senderId/targetId exceeds the 255-byte length prefix"
            case .fieldTooLong(let name):
                return "ImMessage: \(name) exceeds its length prefix"
            case .notFimp(let magic):
                // A v1 envelope opens with the ImType ordinal, so a first
                // byte in 0…3 is almost certainly one — worth saying,
                // because "not a FIMP envelope" would be misleading for
                // the one case that really is a FIMP envelope.
                return magic <= 3
                    ? "ImMessage: looks like a FIMP v1 envelope — v2 does not read v1, and there is no negotiation"
                    : String(format: "ImMessage: not a FIMP envelope (first byte 0x%02x, expected 0xf1)", magic)
            case .wrongVersion(let version):
                return "ImMessage: unsupported FIMP wire version \(version)"
            case .sealedWithoutBody:
                return "ImMessage: bodySealed flag with no body"
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
