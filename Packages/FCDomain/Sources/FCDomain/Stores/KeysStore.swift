import Foundation
import FCCore
import FCStorage

/// A public key we've learned for some FID. Cached so the wallet
/// doesn't have to round-trip to FAPI on every send to a previously
/// contacted peer.
///
/// Pubkey is the 33-byte SEC1 compressed encoding (`0x02`/`0x03` ‖
/// X). We always store it as `Data` rather than hex for compactness;
/// the helper accessors produce hex on demand.
public struct PubkeyRecord: Codable, Equatable, Hashable, Sendable {
    public var fid: String
    public var pubkey: Data
    public var nickname: String?
    public var addedAt: Date

    public init(fid: String, pubkey: Data, nickname: String? = nil, addedAt: Date = Date()) {
        self.fid = fid
        self.pubkey = pubkey
        self.nickname = nickname
        self.addedAt = addedAt
    }

    public var pubkeyHex: String {
        pubkey.map { String(format: "%02x", $0) }.joined()
    }
}

/// Per-identity address book of pubkeys-for-FIDs. Separate from
/// ``ContactsStore`` because not every contact has a known pubkey
/// (we may have a friend's FID but never have messaged them) and not
/// every cached pubkey is a contact (we cache pubkeys for tx
/// destinations the user might never befriend).
///
/// On insert, the supplied (fid, pubkey) pair is **validated** against
/// the FCH address derivation: `Hash160(pubkey) + version → fid`. A
/// mismatch throws — silently storing a wrong pubkey would be a
/// foot-gun, since later operations would build txs spending to the
/// wrong recipient.
public struct KeysStore {

    public static let namespace = "pubkeys"

    public enum Failure: Error, CustomStringConvertible {
        case fidPubkeyMismatch(claimedFid: String, derivedFid: String)
        case invalidPubkeyLength(Int)

        public var description: String {
            switch self {
            case let .fidPubkeyMismatch(claimed, derived):
                return "KeysStore: pubkey derives FID \(derived), not the claimed \(claimed)"
            case let .invalidPubkeyLength(n):
                return "KeysStore: pubkey must be 33 bytes (SEC1 compressed), got \(n)"
            }
        }
    }

    private let inner: TypedStore<PubkeyRecord>

    public init(_ identity: Identity) throws {
        self.inner = TypedStore(kv: try identity.storage(), namespace: Self.namespace)
    }

    /// Validate the (fid, pubkey) pair and store. Throws if the pubkey
    /// doesn't actually derive that FID — callers should never see
    /// `Failure.fidPubkeyMismatch` in practice; if they do, somebody
    /// upstream is feeding us garbage.
    public func upsert(_ record: PubkeyRecord) throws {
        guard record.pubkey.count == 33 else {
            throw Failure.invalidPubkeyLength(record.pubkey.count)
        }
        let derivedFid = try FchAddress(publicKey: record.pubkey).fid
        guard derivedFid == record.fid else {
            throw Failure.fidPubkeyMismatch(claimedFid: record.fid, derivedFid: derivedFid)
        }
        try inner.put(record, key: record.fid)
    }

    public func pubkey(forFid fid: String) throws -> Data? {
        try inner.get(fid)?.pubkey
    }

    public func record(forFid fid: String) throws -> PubkeyRecord? {
        try inner.get(fid)
    }

    @discardableResult
    public func remove(fid: String) throws -> Bool {
        guard try inner.exists(fid) else { return false }
        try inner.delete(fid)
        return true
    }

    public func all() throws -> [PubkeyRecord] {
        try inner.all().map(\.value).sorted { $0.fid < $1.fid }
    }
}
