import Foundation

/// An on-chain service record, mirroring
/// `FC-AJDK/.../data/feipData/Service.java`.
///
/// Only the fields this port has a use for are modelled. `Service` on
/// the Java side also carries a dozen pricing strings and a free-form
/// `params` object; none of them are read on any path we have ported, so
/// modelling them would be inventing an interface to code that does not
/// exist yet. `Codable` ignores what it is not asked for, so a record
/// carrying them decodes fine.
///
/// The field that matters here is ``home``: it is where a service
/// publishes the URL clients should talk to, under the key `API`.
public struct Service: Codable, Equatable, Sendable, Identifiable {

    /// The service's canonical name, e.g. `DOCK@No1_NrC7`.
    public var stdName: String?
    public var localNames: [String: String]?
    public var desc: String?
    public var type: String?
    public var ver: String?
    /// The FID that runs it.
    public var dealer: String?
    public var dealerPubkey: String?
    /// Where to reach it. The `API` key is the endpoint; see
    /// ``apiUrl``.
    public var home: [String: String]?
    public var protocols: [String]?
    public var owner: String?

    public var birthTime: Int64?
    public var birthHeight: Int64?
    public var lastTxId: String?
    public var lastHeight: Int64?
    public var active: Bool?

    /// The SID — 64 hex characters, and the id a `(sid)` home value
    /// points at.
    public var id: String?

    public init(
        stdName: String? = nil,
        localNames: [String: String]? = nil,
        desc: String? = nil,
        type: String? = nil,
        ver: String? = nil,
        dealer: String? = nil,
        dealerPubkey: String? = nil,
        home: [String: String]? = nil,
        protocols: [String]? = nil,
        owner: String? = nil,
        birthTime: Int64? = nil,
        birthHeight: Int64? = nil,
        lastTxId: String? = nil,
        lastHeight: Int64? = nil,
        active: Bool? = nil,
        id: String? = nil
    ) {
        self.stdName = stdName
        self.localNames = localNames
        self.desc = desc
        self.type = type
        self.ver = ver
        self.dealer = dealer
        self.dealerPubkey = dealerPubkey
        self.home = home
        self.protocols = protocols
        self.owner = owner
        self.birthTime = birthTime
        self.birthHeight = birthHeight
        self.lastTxId = lastTxId
        self.lastHeight = lastHeight
        self.active = active
        self.id = id
    }

    /// The endpoint clients should call.
    ///
    /// **Case-insensitive on the key.** Services register the URL under
    /// `API` or `api` depending on who published them, and a resolver
    /// that only looked for one spelling would silently fail to reach
    /// half the network. Java tolerates both and so does this.
    public var apiUrl: String? {
        guard let home, !home.isEmpty else { return nil }
        if let exact = home["API"] { return exact }
        for (key, value) in home where key.lowercased() == "api" {
            return value
        }
        return nil
    }

    /// A service is live unless the chain says otherwise — a missing
    /// flag is not a retirement.
    public var isActive: Bool { active ?? true }
}

/// Well-known service names, as they appear as keys in an entity's
/// `home` map.
public enum ServiceName {
    /// Store-and-forward for messages whose recipient is offline.
    public static let dock = "DOCK@No1_NrC7"
    /// Live relay for messages whose recipient is online but
    /// unreachable directly.
    public static let road = "ROAD@No1_NrC7"
    /// Content-addressed file storage (Phase 8.4).
    public static let disk = "DISK@No1_NrC7"
    /// The chain-index API.
    public static let fapi = "FAPI@No1_NrC7"
}
