import Foundation
import FCCore

/// The BASE in a FID's home: the FAPI server (the FAPI11 BASE component)
/// its owner reads the chain through, on every device they use.
///
/// **Following it starts from a server that is not it.** A device has to
/// read the chain to learn the home, so it connects somewhere first — the
/// project server, or the last home BASE it reached — and only then knows
/// where to go. That first server also answers the home lookup and the
/// service record, so it is trusted for those; what is checked here is
/// the step after, where a HELLO over plain UDP hands back whatever key
/// the machine at that address chose. That key must be the one the
/// service record names, or a hijacked address could carry the session.
public enum HomeBase {

    /// What the main FID's home says about its BASE.
    public enum Entry: Equatable, Sendable {
        case none
        /// A service id — the only form whose key can be checked.
        case serviceId(String)
        /// A bare address: public, and no record to check a key against.
        case address(String)
        /// Sealed, and this prikey does not open it.
        case unreadable
    }

    /// The BASE in `home`, opened with `prikey` when it is sealed.
    public static func entry(in home: [String: String]?, prikey: Data?) -> Entry {
        guard let stored = HomeFeip.value(of: "BASE", in: home) else { return .none }
        guard let value = HomePrivacy.open(stored, prikey: prikey) else { return .unreadable }
        if let sid = HomeServiceResolver.extractSid(value) { return .serviceId(sid) }
        return .address(value)
    }

    public enum Verdict: Equatable, Sendable {
        case matches
        /// The record names a different key or dealer: `expected`.
        case mismatch(expected: String)
        /// No record, or one that names neither a dealer pubkey nor a
        /// dealer — nothing to check the key against.
        case unverifiable
    }

    /// Whether the key a server answered HELLO with is the one its service
    /// record names. A FAPI server's FUDP key is its dealer's — FC-JDK's
    /// `ClientGroup` records the discovered key as the dealer pubkey — so
    /// the record's `dealerPubkey` is compared, or failing that, the FID
    /// the key derives to against its `dealer`.
    public static func verify(helloPubkey: Data, against service: Service?) -> Verdict {
        guard let service else { return .unverifiable }
        let hello = Hex.encode(helloPubkey).lowercased()
        if let expected = service.dealerPubkey?.trimmingCharacters(in: .whitespaces).lowercased(),
           !expected.isEmpty {
            return expected == hello ? .matches : .mismatch(expected: expected)
        }
        if let dealer = service.dealer?.trimmingCharacters(in: .whitespaces), !dealer.isEmpty {
            let fid = try? FchAddress(publicKey: helloPubkey).fid
            return fid == dealer ? .matches : .mismatch(expected: dealer)
        }
        return .unverifiable
    }
}
