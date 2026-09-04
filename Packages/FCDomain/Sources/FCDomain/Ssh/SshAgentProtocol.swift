import Foundation
import FCCore

/// The ssh-agent protocol (RFC 9987), reduced to the four messages a
/// single-key, read-only agent needs — and one answer for everything
/// else.
///
/// **The reduction is the security model.** A stock `ssh-agent` can be
/// asked to add keys, remove keys, lock itself, and run vendor
/// extensions. This agent holds exactly one key that it derived
/// itself, so every request that would change what it holds —
/// `ADD_IDENTITY` (17), `REMOVE_IDENTITY` (18), `REMOVE_ALL` (19),
/// `LOCK`/`UNLOCK` (22/23), `EXTENSION` (27) — is answered
/// `SSH_AGENT_FAILURE`. There is no code path that mutates state, so
/// there is nothing for a hostile client to mutate.
///
/// Pure codec: no sockets, no I/O, no key storage decisions. That is
/// what makes the whole wire format testable byte-for-byte, which
/// matters because a subtly wrong length prefix does not fail loudly —
/// it makes `ssh` fall back to password auth and look like the feature
/// simply does not work.
public enum SshAgentProtocol {

    /// OpenSSH's own client-side cap. Every message we actually answer
    /// is a few hundred bytes.
    public static let maxMessageLength = 256 * 1024

    public enum MessageType {
        public static let failure: UInt8 = 5
        public static let success: UInt8 = 6
        public static let requestIdentities: UInt8 = 11
        public static let identitiesAnswer: UInt8 = 12
        public static let signRequest: UInt8 = 13
        public static let signResponse: UInt8 = 14
    }

    /// What a client asked for. `unsupported` and `malformed` are
    /// separate cases only so the caller can log them differently —
    /// both answer `SSH_AGENT_FAILURE`.
    public enum Request: Equatable {
        case requestIdentities
        case sign(keyBlob: Data, data: Data, flags: UInt32)
        /// A message type this agent deliberately does not implement.
        case unsupported(UInt8)
        /// A message of a known type whose body did not parse.
        case malformed(UInt8)
    }

    // MARK: - Framing

    /// `uint32 length ‖ body`, where `length` counts the type byte.
    public static func frame(_ body: Data) -> Data {
        SshWire.uint32(UInt32(body.count)) + body
    }

    // MARK: - Parsing

    /// Parse one message body — the type byte and everything after it,
    /// with the length prefix already stripped by the transport.
    public static func parse(body: Data) -> Request {
        var reader = SshWire.Reader(body)
        guard let type = try? reader.readByte() else { return .malformed(0) }

        switch type {
        case MessageType.requestIdentities:
            // No payload. Trailing bytes would mean a confused client;
            // OpenSSH ignores them, and so do we.
            return .requestIdentities

        case MessageType.signRequest:
            guard let keyBlob = try? reader.readString(),
                  let data = try? reader.readString(),
                  let flags = try? reader.readUInt32() else {
                return .malformed(type)
            }
            return .sign(keyBlob: keyBlob, data: data, flags: flags)

        default:
            return .unsupported(type)
        }
    }

    // MARK: - Responses

    public static func failure() -> Data {
        frame(Data([MessageType.failure]))
    }

    /// The one-key answer: `byte 12 ‖ uint32 1 ‖ string blob ‖ string comment`.
    public static func identitiesAnswer(keyBlob: Data, comment: String) -> Data {
        var body = Data([MessageType.identitiesAnswer])
        body += SshWire.uint32(1)
        body += SshWire.string(keyBlob)
        body += SshWire.string(comment)
        return frame(body)
    }

    public static func signResponse(signatureBlob: Data) -> Data {
        frame(Data([MessageType.signResponse]) + SshWire.string(signatureBlob))
    }

    // MARK: - Policy

    /// The whole agent, as a function. Everything the socket layer does
    /// is read a message, call this, and write the answer back.
    ///
    /// Three ways to get `SSH_AGENT_FAILURE`, all deliberate:
    ///
    ///   - **A key blob that is not ours.** `ssh` names the key it wants
    ///     signed; a mismatch means the request was meant for a
    ///     different agent, not for us.
    ///   - **Non-zero flags.** The only defined flags,
    ///     `SSH_AGENT_RSA_SHA2_256` (2) and `SSH_AGENT_RSA_SHA2_512`
    ///     (4), select an RSA hash and are meaningless for ed25519.
    ///     RFC 9987 is explicit that an agent which does not support
    ///     the requested flags MUST fail rather than sign something
    ///     else, so `ssh` sends 0 here and anything else is a bug or a
    ///     probe.
    ///   - **Any other message type**, per the note on this enum.
    ///
    /// One of those failures is routine and must not be logged as an
    /// error: OpenSSH sends `SSH_AGENTC_EXTENSION` (27) carrying
    /// `session-bind@openssh.com` before it uses an agent key. Failing
    /// it is fine — `ssh` logs the refusal at debug level and
    /// authenticates anyway — but treating it as a fault would make
    /// every successful connection look broken.
    public static func respond(
        to body: Data,
        key: SshEd25519Key,
        comment: String
    ) -> (response: Data, request: Request) {
        let request = parse(body: body)
        switch request {
        case .requestIdentities:
            return (identitiesAnswer(keyBlob: key.publicKeyBlob, comment: comment), request)

        case let .sign(keyBlob, data, flags):
            guard keyBlob == key.publicKeyBlob, flags == 0 else {
                return (failure(), request)
            }
            guard let blob = try? key.signatureBlob(data) else {
                return (failure(), request)
            }
            return (signResponse(signatureBlob: blob), request)

        case .unsupported, .malformed:
            return (failure(), request)
        }
    }
}
