import Foundation

/// One entry of the chain's **nobody index**: a FID whose private key was
/// published with a FEIP4 carve. Mirrors Java's
/// `com.fc.fc_ajdk.data.fchData.Nobody`; the key is the FID.
///
/// The index is the authority for "is this a nobody". A ``Freer`` record
/// carries `isNobody` too, but a freer fetched for a subset of fields
/// omits it, so only this index can also say "not a nobody".
public struct NobodyRecord: Codable, Hashable, Sendable {
    public var id: String?
    /// The published private key, hex. Public by definition.
    public var priKey: String?
    public var deathTime: Int64?
    public var deathHeight: Int64?
    public var deathTxId: String?
    public var deathTxIndex: Int?

    public init() {}
}
