import Foundation
import FCCore

/// One home entry as its owner means it: which service, and whether to
/// keep that to themselves.
public struct HomeEntry: Equatable, Sendable {
    /// A service id (bare or `(sid)`-prefixed) or, public only, an address.
    public var value: String
    public var sealed: Bool

    public init(_ value: String, sealed: Bool) {
        self.value = value
        self.sealed = sealed
    }
}

/// Home entries only their owner can read.
///
/// **Only BASE and DISK.** A DOCK and a CALL service exist to be found —
/// a sender has to reach the DOCK, a caller the relay — so sealing either
/// would just make the FID unreachable. Where you read the chain and where
/// your files live are nobody else's business, and some people would
/// rather say so publicly anyway, so for those two it is a choice.
///
/// **Android's format, byte for byte in meaning.** `DiskHomeManager` seals
/// the 32 raw bytes of the service id to the FID's own pubkey, AsyOneWay
/// with EccK1AesGcm256, and stores the CryptoDataStr JSON envelope. Each
/// app has to open what the other wrote, so this does exactly that; only
/// a service id can be sealed, because an address is not 32 bytes and
/// Android's reader would reject anything else.
public enum HomePrivacy {

    /// The kinds a home may seal.
    public static let sealableKinds: Set<String> = ["BASE", "DISK"]

    public enum Failure: Error, CustomStringConvertible, Equatable {
        case notAServiceId(String)
        var descriptionText: String {
            switch self {
            case .notAServiceId(let value):
                return "Only a service id can be kept private, not '\(value)'."
            }
        }
        public var description: String { descriptionText }
    }

    /// Whether a stored value is sealed. Every sealed value is a JSON
    /// envelope, and no service id or address starts with a brace.
    public static func isSealed(_ value: String?) -> Bool {
        value?.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{") ?? false
    }

    /// Seal a service id to `pubkey`. Fresh randomness each time, so the
    /// same id never seals to the same string twice.
    public static func seal(_ value: String, toPubkey pubkey: Data) throws -> String {
        guard let sid = HomeServiceResolver.extractSid(value),
              let bytes = Hex.decodeOrNil(sid)
        else { throw Failure.notAServiceId(value) }
        return try AsyOneWayCipher.encrypt(plaintext: bytes, toPubkey: pubkey)
    }

    /// A stored value as a plain home value: unchanged when public, the
    /// `(sid)` it holds when sealed. Nil when there is nothing there, or
    /// it is sealed and `prikey` does not open it.
    public static func open(_ value: String?, prikey: Data?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty
        else { return nil }
        guard isSealed(trimmed) else { return trimmed }
        guard let prikey,
              let bytes = try? AsyOneWayCipher.decrypt(cipherString: trimmed, privkey: prikey),
              let sid = HomeServiceResolver.extractSid(Hex.encode(bytes).lowercased())
        else { return nil }
        return HomeServiceResolver.sidPrefix + sid
    }

    /// What to carve for `entry` over `stored`, or nil when the chain
    /// already says it — the same service, kept the same way.
    ///
    /// **Compared opened, never as bytes.** A sealed value is different
    /// every time it is sealed, so comparing strings would make every
    /// carve of an unchanged private entry look like a change, at a fee.
    static func pending(
        _ entry: HomeEntry?, over stored: String?, prikey: Data?,
        seal: (String) throws -> String
    ) throws -> String? {
        guard let entry else { return nil }
        let wanted = HomeServiceResolver.homeValue(entry.value)
        guard !wanted.isEmpty else { return nil }
        let storedPlain = open(stored, prikey: prikey).map(HomeServiceResolver.homeValue)
        if storedPlain == wanted, isSealed(stored) == entry.sealed { return nil }
        guard entry.sealed else { return wanted }
        guard HomeServiceResolver.extractSid(wanted) != nil else { throw Failure.notAServiceId(entry.value) }
        return try seal(wanted)
    }
}
