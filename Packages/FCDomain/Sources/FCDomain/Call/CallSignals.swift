import Foundation
import FCCore

/// The content of a 1:1 `CALL` message (VOICE_SPEC §3.2): JSON with an `op`.
/// Field names are the reference's (`CallSignal` in FC-AJDK); absent fields
/// are left out, as Gson leaves out nulls.
public struct CallSignal: Codable, Sendable, Equatable {
    public enum Op: String, Codable, Sendable { case INVITE, ACCEPT, REJECT, CANCEL, HANGUP }

    public static let rejectDeclined = "declined"
    public static let rejectBusy = "busy"
    public static let rejectUnsupported = "unsupported"
    public static let rejectRelay = "relay"
    public static let cancelCancelled = "cancelled"
    public static let cancelTimeout = "timeout"
    public static let cancelAnsweredElsewhere = "answered_elsewhere"
    /// An INVITE rings for this long (§3.2).
    public static let ringMs: Int64 = 45_000

    /// The relay to meet on; `pubkey` and `sid` spare the callee discovery (§6.2).
    public struct Relay: Codable, Sendable, Equatable {
        public var url: String
        public var pubkey: String?
        public var sid: String?

        public init(url: String, pubkey: String? = nil, sid: String? = nil) {
            self.url = url
            self.pubkey = pubkey
            self.sid = sid
        }
    }

    /// A direct-path address (§6.1): `t` is map, lan or home; `a` is ip:port.
    public struct Candidate: Codable, Sendable, Equatable {
        public var t: String
        public var a: String
    }

    public var op: Op
    public var callId: String
    public var transportPub: String?
    public var delegation: Delegation?
    public var relay: Relay?
    public var candidates: [Candidate]?
    public var expires: Int64?
    public var codecs: [String]?
    public var reason: String?
    public var duration: Int64?

    public static func invite(callId: String, tPub: Data, delegation: Delegation, relay: Relay?, nowMs: Int64) -> CallSignal {
        CallSignal(op: .INVITE, callId: callId, transportPub: Hex.encode(tPub), delegation: delegation, relay: relay,
                   expires: nowMs + ringMs, codecs: ["opus"])
    }

    public static func accept(callId: String, tPub: Data, delegation: Delegation) -> CallSignal {
        CallSignal(op: .ACCEPT, callId: callId, transportPub: Hex.encode(tPub), delegation: delegation)
    }

    public static func reject(callId: String, reason: String) -> CallSignal {
        CallSignal(op: .REJECT, callId: callId, reason: reason)
    }

    public static func cancel(callId: String, reason: String) -> CallSignal {
        CallSignal(op: .CANCEL, callId: callId, reason: reason)
    }

    public static func hangup(callId: String, durationMs: Int64) -> CallSignal {
        CallSignal(op: .HANGUP, callId: callId, duration: durationMs)
    }

    public init(op: Op, callId: String, transportPub: String? = nil, delegation: Delegation? = nil, relay: Relay? = nil,
                candidates: [Candidate]? = nil, expires: Int64? = nil, codecs: [String]? = nil, reason: String? = nil,
                duration: Int64? = nil) {
        self.op = op
        self.callId = callId
        self.transportPub = transportPub
        self.delegation = delegation
        self.relay = relay
        self.candidates = candidates
        self.expires = expires
        self.codecs = codecs
        self.reason = reason
        self.duration = duration
    }

    public func toJson() -> String {
        String(decoding: (try? JSONEncoder().encode(self)) ?? Data(), as: UTF8.self)
    }

    /// The signal, or nil if unreadable or lacking what its op needs.
    /// Delegations are only checked for presence; the receiver verifies them.
    public static func fromJson(_ json: String) -> CallSignal? {
        guard let s = try? JSONDecoder().decode(CallSignal.self, from: Data(json.utf8)), s.wellFormed else { return nil }
        return s
    }

    private var wellFormed: Bool {
        guard CallSignal.isCallId(callId) else { return false }
        switch op {
        case .INVITE:
            return CallSignal.isPub(transportPub) && delegation != nil && expires != nil
                && (codecs == nil || codecs!.contains("opus"))
        case .ACCEPT: return CallSignal.isPub(transportPub) && delegation != nil
        case .REJECT, .CANCEL: return reason != nil
        case .HANGUP: return true
        }
    }

    public var transportPubBytes: Data? { transportPub.flatMap(Hex.decodeOrNil) }

    /// 16 random bytes, hex (§3.2).
    public static func isCallId(_ id: String) -> Bool {
        id.count == 32 && Hex.decodeOrNil(id)?.count == 16
    }

    static func isPub(_ hex: String?) -> Bool {
        hex.flatMap(Hex.decodeOrNil)?.count == 33
    }
}

/// The content of a `CALL` message about a meeting (VOICE_SPEC §3.3): in a
/// Room or Team chat, sealed under its symkey; or 1:1, for a meeting of
/// chosen people (Decision 20). Field names are the reference's
/// (`MeetingSignal` in FC-AJDK).
public struct MeetingSignal: Codable, Sendable, Equatable {
    public enum Op: String, Codable, Sendable { case MEETING_START, MEETING_END, MEETING_INVITE }

    public static let idPrefix = "mtg_"
    /// A chosen-people meeting's key is version 1 of an entity named by its meetingId.
    public static let invitedVersion: UInt64 = 1

    public var op: Op
    public var meetingId: String
    public var relay: CallSignal.Relay?
    public var nonce: String?
    public var symkeyVersion: UInt64?
    public var authPub: String?
    /// 0 at the start; each rekey adds one (§4.5).
    public var keyEpoch: Int64?
    public var title: String?
    public var started: Int64?
    public var duration: Int64?
    /// MEETING_INVITE, and a 1:1 MEETING_END: the Room or Team.
    public var entityId: String?
    /// TEAM or ROOM.
    public var entityType: String?
    /// MEETING_INVITE: the meeting's key, hex. Only ever inside a message sealed to one invitee.
    public var key: String?

    public static func start(meetingId: String, relay: CallSignal.Relay, nonce: Data, symkeyVersion: UInt64, authPub: Data,
                             keyEpoch: Int64, title: String?, startedMs: Int64) -> MeetingSignal {
        MeetingSignal(op: .MEETING_START, meetingId: meetingId, relay: relay, nonce: Hex.encode(nonce),
                      symkeyVersion: symkeyVersion, authPub: Hex.encode(authPub), keyEpoch: keyEpoch,
                      title: (title?.isEmpty ?? true) ? nil : title, started: startedMs)
    }

    public static func invite(meetingId: String, entityId: String, entityType: String, relay: CallSignal.Relay,
                              nonce: Data, authPub: Data, key: Data, title: String?, startedMs: Int64) -> MeetingSignal {
        var s = start(meetingId: meetingId, relay: relay, nonce: nonce, symkeyVersion: invitedVersion, authPub: authPub,
                      keyEpoch: 0, title: title, startedMs: startedMs)
        s.op = .MEETING_INVITE
        s.entityId = entityId
        s.entityType = entityType
        s.key = Hex.encode(key)
        return s
    }

    public static func end(meetingId: String, durationMs: Int64) -> MeetingSignal {
        MeetingSignal(op: .MEETING_END, meetingId: meetingId, duration: durationMs)
    }

    public init(op: Op, meetingId: String, relay: CallSignal.Relay? = nil, nonce: String? = nil, symkeyVersion: UInt64? = nil,
                authPub: String? = nil, keyEpoch: Int64? = nil, title: String? = nil, started: Int64? = nil,
                duration: Int64? = nil, entityId: String? = nil, entityType: String? = nil, key: String? = nil) {
        self.op = op
        self.meetingId = meetingId
        self.relay = relay
        self.nonce = nonce
        self.symkeyVersion = symkeyVersion
        self.authPub = authPub
        self.keyEpoch = keyEpoch
        self.title = title
        self.started = started
        self.duration = duration
        self.entityId = entityId
        self.entityType = entityType
        self.key = key
    }

    /// The card for a chat: an invitation without its key.
    public var withoutKey: MeetingSignal {
        var s = self
        s.op = .MEETING_START
        s.key = nil
        return s
    }

    public var keyEpochOrZero: Int64 { keyEpoch ?? 0 }
    public var nonceBytes: Data? { nonce.flatMap(Hex.decodeOrNil) }
    public var authPubBytes: Data? { authPub.flatMap(Hex.decodeOrNil) }
    public var keyBytes: Data? { key.flatMap(Hex.decodeOrNil) }

    public func toJson() -> String {
        String(decoding: (try? JSONEncoder().encode(self)) ?? Data(), as: UTF8.self)
    }

    public static func fromJson(_ json: String) -> MeetingSignal? {
        guard let s = try? JSONDecoder().decode(MeetingSignal.self, from: Data(json.utf8)), s.wellFormed else { return nil }
        return s
    }

    private var wellFormed: Bool {
        guard MeetingSignal.isMeetingId(meetingId) else { return false }
        func len(_ hex: String?) -> Int { hex.flatMap(Hex.decodeOrNil)?.count ?? -1 }
        let hasRelay = !(relay?.url.isEmpty ?? true)
        switch op {
        case .MEETING_START:
            return hasRelay && len(nonce) == 32 && len(authPub) == 33 && symkeyVersion != nil && started != nil
                && (keyEpoch ?? 0) >= 0
        case .MEETING_END:
            return true
        case .MEETING_INVITE:
            return hasRelay && len(nonce) == 32 && len(authPub) == 33 && len(key) == 32
                && !(entityId?.isEmpty ?? true) && (entityType == "TEAM" || entityType == "ROOM") && started != nil
        }
    }

    /// `"mtg_"` and 24 hex digits (§8).
    public static func isMeetingId(_ id: String) -> Bool {
        id.hasPrefix(idPrefix) && id.count == idPrefix.count + 24
            && Hex.decodeOrNil(String(id.dropFirst(idPrefix.count)))?.count == 12
    }
}
