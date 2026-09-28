import Foundation

/// What a CALL row says in a chat (VOICE_SPEC §10): "Outgoing call, 4:12",
/// "Missed call", "Declined". The row is a local record, or a stranger's
/// INVITE that was held; its content is the record JSON Android writes too.
public enum CallText {

    public static func describe(_ content: String?) -> String {
        guard let data = content?.data(using: .utf8),
              let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return "Call" }
        if let op = o["op"] as? String {
            return op == CallSignal.Op.INVITE.rawValue ? "Missed call" : "Call"
        }
        let outgoing = o["outgoing"] as? Bool ?? false
        let duration = (o["duration"] as? NSNumber)?.int64Value ?? 0
        switch o["record"] as? String {
        case "ENDED": return (outgoing ? "Outgoing call, " : "Incoming call, ") + formatDuration(duration)
        case "MISSED": return "Missed call"
        case "DECLINED": return "Declined"
        case "NO_ANSWER": return "No answer"
        case "BUSY": return "Busy"
        case "CANCELLED": return "Cancelled call"
        case "ANSWERED_ELSEWHERE": return "Answered on another device"
        default: return "Call"
        }
    }

    /// 4:12, or 1:02:03 past an hour.
    public static func formatDuration(_ ms: Int64) -> String {
        let s = max(0, ms / 1000)
        return s >= 3600 ? String(format: "%d:%02d:%02d", s / 3600, s / 60 % 60, s % 60)
            : String(format: "%d:%02d", s / 60, s % 60)
    }
}
