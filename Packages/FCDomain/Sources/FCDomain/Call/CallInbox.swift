import Foundation

/// Where the session hands `CALL` messages (VOICE_SPEC §3): the call code
/// sets `handler`, and the courier's signal routing gives each one to it
/// instead of the room and key router, which would drop it. Until a
/// handler is set, calls are dropped quietly, as before calls came to the Mac.
public final class CallInbox: @unchecked Sendable {
    private let lock = NSLock()
    private var _handler: (@Sendable (_ message: ImMessage, _ liveFid: String) -> Void)?

    public init() {}

    public var handler: (@Sendable (ImMessage, String) -> Void)? {
        get { lock.withLock { _handler } }
        set { lock.withLock { _handler = newValue } }
    }

    func deliver(_ message: ImMessage, liveFid: String) {
        handler?(message, liveFid)
    }
}
