import Foundation
import FCCore

// VOICE_SPEC §4–§5: the byte encodings, keys, delegations, sealed media frames,
// attestations and the replay window of calls and meetings. The reference is
// `com.fc.fc_ajdk.call` in FC-AJDK; `callVectors.json` pins every value.

/// The byte encodings of §4. A quoted literal such as `"FreerCall v1 p2p"`
/// is its UTF-8 bytes with no prefix; `str(x)` is a 2-byte big-endian
/// length, then UTF-8; integers are big-endian and unsigned.
struct CallBytes {
    private(set) var data = Data()

    static func of(_ literal: String) -> CallBytes {
        var b = CallBytes()
        b.data.append(Data(literal.utf8))
        return b
    }

    func str(_ s: String) -> CallBytes {
        let bytes = Data(s.utf8)
        precondition(bytes.count <= 0xFFFF, "string too long for str()")
        var b = self
        b.data.append(UInt8(bytes.count >> 8))
        b.data.append(UInt8(bytes.count & 0xFF))
        b.data.append(bytes)
        return b
    }

    func bytes(_ d: Data) -> CallBytes {
        var b = self
        b.data.append(d)
        return b
    }

    func u8(_ v: Int) -> CallBytes {
        var b = self
        b.data.append(UInt8(truncatingIfNeeded: v))
        return b
    }

    func u32(_ v: UInt32) -> CallBytes {
        var b = self
        withUnsafeBytes(of: v.bigEndian) { b.data.append(contentsOf: $0) }
        return b
    }

    func u64(_ v: UInt64) -> CallBytes {
        var b = self
        withUnsafeBytes(of: v.bigEndian) { b.data.append(contentsOf: $0) }
        return b
    }
}

/// `Schnorr(key, m)` of §4: the BCH Schnorr signature FIMP0V3 uses, over
/// SHA-256d of the preimage. Every preimage starts with its own tag.
public enum CallSig {
    public static func sign(privateKey: Data, preimage: Data) throws -> Data {
        try BchSchnorr.sign(message: Hash.doubleSha256(preimage), privateKey: privateKey)
    }

    public static func verify(publicKey: Data, preimage: Data, signature: Data) -> Bool {
        guard publicKey.count == 33, signature.count == 64 else { return false }
        return (try? BchSchnorr.verify(message: Hash.doubleSha256(preimage), publicKey: publicKey,
                                       signature: signature)) ?? false
    }
}

/// Key material for calls and meetings (§4.2–§4.4). All HKDF is
/// HKDF-SHA512, as the reference's `HKDF` class is (§4); an empty salt is
/// RFC 5869's all-zero salt.
public enum CallKeys {
    public static let keyLength = 32

    public enum Failure: Error {
        case badCallId, badNonce
    }

    /// 1:1, forward secret (§4.2).
    public static func p2pSecret(tPrivSelf: Data, tPubPeer: Data, callIdHex: String,
                                 fidA: String, fidB: String) throws -> Data {
        guard let callId = Hex.decodeOrNil(callIdHex), callId.count == 16 else { throw Failure.badCallId }
        let shared = try Secp256k1.sharedSecretX(privateKey: tPrivSelf, publicKey: tPubPeer)
        let lo = fidA <= fidB ? fidA : fidB
        let hi = lo == fidA ? fidB : fidA
        let info = CallBytes.of("FreerCall v1 p2p").str(lo).str(hi).data
        return hkdf(ikm: shared, salt: callId, info: info)
    }

    /// A meeting, no stronger than the entity's symkey (§4.2).
    public static func meetingSecret(symkey: Data, nonce: Data, entityId: String, symkeyVersion: UInt64,
                                     meetingId: String) throws -> Data {
        guard nonce.count == 32 else { throw Failure.badNonce }
        let info = CallBytes.of("FreerCall v1 meeting").str(entityId).u64(symkeyVersion).str(meetingId).data
        return hkdf(ikm: symkey, salt: nonce, info: info)
    }

    /// One sender's frame key (§4.3).
    public static func senderKey(callSecret: Data, fid: String, ssrc: UInt32, keyEpoch: Int) -> Data {
        let info = CallBytes.of("FreerCall v1 sender").str(fid).u32(ssrc).u8(keyEpoch).data
        return hkdf(ikm: callSecret, salt: Data(), info: info)
    }

    /// The admission key (§4.4): `authSeed mod n`, retried with `info ‖ 0x01` while zero.
    public static func authPriv(callSecret: Data) -> Data {
        var info = CallBytes.of("FreerCall v1 admit").data
        var attempt = 0
        while true {
            let k = modN(hkdf(ikm: callSecret, salt: Data(), info: info))
            if k.contains(where: { $0 != 0 }) { return k }
            attempt += 1
            info = CallBytes.of("FreerCall v1 admit").bytes(Data(repeating: 1, count: attempt)).data
        }
    }

    public static func authPub(authPriv: Data) throws -> Data {
        try Secp256k1.publicKey(fromPrivateKey: authPriv)
    }

    /// `Schnorr(authPriv, "FreerCall-admit-v1" ‖ str(meetingId) ‖ tPub ‖ u32(ssrc) ‖ u64(ts))`, `ts` in ms.
    public static func admitSig(authPriv: Data, meetingId: String, tPub: Data, ssrc: UInt32, tsMs: UInt64) throws -> Data {
        try CallSig.sign(privateKey: authPriv, preimage: admitPreimage(meetingId, tPub, ssrc, tsMs))
    }

    public static func verifyAdmit(authPub: Data, meetingId: String, tPub: Data, ssrc: UInt32, tsMs: UInt64,
                                   signature: Data) -> Bool {
        CallSig.verify(publicKey: authPub, preimage: admitPreimage(meetingId, tPub, ssrc, tsMs), signature: signature)
    }

    static func admitPreimage(_ meetingId: String, _ tPub: Data, _ ssrc: UInt32, _ tsMs: UInt64) -> Data {
        CallBytes.of("FreerCall-admit-v1").str(meetingId).bytes(tPub).u32(ssrc).u64(tsMs).data
    }

    /// The 12-byte AES-GCM nonce of a media frame: `u32(ssrc) ‖ u64(seq)` (§4.3).
    public static func frameNonce(ssrc: UInt32, seq: UInt64) -> Data {
        CallBytes().u32(ssrc).u64(seq).data
    }

    static func hkdf(ikm: Data, salt: Data, info: Data) -> Data {
        Hkdf.sha512(ikm: ikm, salt: salt, info: info, outputLength: keyLength)
    }

    /// secp256k1's group order.
    private static let n: [UInt8] = Array(Hex.decodeOrNil("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")!)

    /// A 32-byte big-endian value mod n. It is below 2^256 < 2n, so one subtraction does.
    static func modN(_ value: Data) -> Data {
        var v = Array(value)
        if v.lexicographicallyPrecedes(n) { return Data(v) }
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            let d = Int(v[i]) - Int(n[i]) - borrow
            v[i] = UInt8((d + 256) & 0xFF)
            borrow = d < 0 ? 1 : 0
        }
        return Data(v)
    }
}

/// A FID's statement that a throwaway transport key speaks for it in one
/// call or meeting (§4.1). Published as `{fid, fidPub, tPub, expiresSec, sig}`.
public struct Delegation: Codable, Equatable, Sendable {
    public static let tag = "FreerCall-delegate-v1"
    public static let maxLifetimeSec: Int64 = 24 * 3600

    public var fid: String
    public var fidPub: String
    public var tPub: String
    public var expiresSec: Int64
    public var sig: String

    public enum Check: Equatable {
        case ok, malformed, fidMismatch, badSignature, expired, tooLong
    }

    public static func sign(fidPriv: Data, callOrMeetingId: String, tPub: Data, expiresSec: Int64) throws -> Delegation {
        let fidPubBytes = try Secp256k1.publicKey(fromPrivateKey: fidPriv)
        guard let fid = NobodyRegistry.fid(ofPubkeyHex: Hex.encode(fidPubBytes)) else { throw CallKeys.Failure.badCallId }
        let sig = try CallSig.sign(privateKey: fidPriv, preimage: preimage(callOrMeetingId, tPub, expiresSec))
        return Delegation(fid: fid, fidPub: Hex.encode(fidPubBytes), tPub: Hex.encode(tPub), expiresSec: expiresSec,
                          sig: Hex.encode(sig))
    }

    static func preimage(_ id: String, _ tPub: Data, _ expiresSec: Int64) -> Data {
        CallBytes.of(tag).str(id).bytes(tPub).u64(UInt64(bitPattern: expiresSec)).data
    }

    /// Everything a verifier must check: the key hashes to the FID, the
    /// signature holds for this id, it has not expired, and it claims no more than 24 h.
    public func verify(callOrMeetingId: String, nowSec: Int64) -> Check {
        guard let fidPubBytes = Hex.decodeOrNil(fidPub), fidPubBytes.count == 33,
              let tPubBytes = Hex.decodeOrNil(tPub), tPubBytes.count == 33,
              let sigBytes = Hex.decodeOrNil(sig), sigBytes.count == 64 else { return .malformed }
        guard NobodyRegistry.fid(ofPubkeyHex: fidPub) == fid else { return .fidMismatch }
        guard CallSig.verify(publicKey: fidPubBytes, preimage: Delegation.preimage(callOrMeetingId, tPubBytes, expiresSec),
                             signature: sigBytes) else { return .badSignature }
        if expiresSec <= nowSec { return .expired }
        if expiresSec - nowSec > Delegation.maxLifetimeSec { return .tooLong }
        return .ok
    }

    public var tPubBytes: Data? { Hex.decodeOrNil(tPub) }

    /// The reference's field order (Gson's declaration order), as the vectors pin it.
    /// Every value is hex or base58, so nothing needs escaping.
    public func toJson() -> String {
        "{\"fid\":\"\(fid)\",\"fidPub\":\"\(fidPub)\",\"tPub\":\"\(tPub)\",\"expiresSec\":\(expiresSec),\"sig\":\"\(sig)\"}"
    }

    public static func fromJson(_ json: String) -> Delegation? {
        try? JSONDecoder().decode(Delegation.self, from: Data(json.utf8))
    }
}

/// One end-to-end sealed audio frame, the data of a DATAGRAM frame (§5):
/// `kind(1)=0x01 flags(1) routeId(4) ssrc(4) seq(8) timestamp(4) level(1) keyEpoch(1)`,
/// then AES-256-GCM of the Opus payload with the 24 header bytes as AAD.
public enum MediaFrame {
    public static let kind: UInt8 = 0x01
    public static let headerLength = 24
    public static let tagLength = 16
    public static let flagVad = 0x01
    public static let flagDtx = 0x02
    public static let flagControl = 0x80

    public struct Header: Equatable, Sendable {
        public var flags: Int
        public var routeId: UInt32
        public var ssrc: UInt32
        public var seq: UInt64
        public var timestamp: UInt32
        public var level: Int
        public var keyEpoch: Int

        public init(flags: Int, routeId: UInt32, ssrc: UInt32, seq: UInt64, timestamp: UInt32, level: Int, keyEpoch: Int) {
            self.flags = flags
            self.routeId = routeId
            self.ssrc = ssrc
            self.seq = seq
            self.timestamp = timestamp
            self.level = level
            self.keyEpoch = keyEpoch
        }

        public var bytes: Data {
            CallBytes().u8(Int(MediaFrame.kind)).u8(flags).u32(routeId).u32(ssrc).u64(seq).u32(timestamp)
                .u8(level).u8(keyEpoch).data
        }

        /// Nil unless `frame` is a v1 media frame.
        public static func parse(_ frame: Data) -> Header? {
            let f = Array(frame)
            guard f.count >= MediaFrame.headerLength + MediaFrame.tagLength, f[0] == MediaFrame.kind else { return nil }
            let flags = Int(f[1])
            guard flags & 0x7C == 0 else { return nil } // bits 2-6 are reserved
            func be(_ at: Int, _ n: Int) -> UInt64 { f[at..<at + n].reduce(0) { $0 << 8 | UInt64($1) } }
            return Header(flags: flags, routeId: UInt32(be(2, 4)), ssrc: UInt32(be(6, 4)), seq: be(10, 8),
                          timestamp: UInt32(be(18, 4)), level: Int(f[22]), keyEpoch: Int(f[23]))
        }
    }

    public static func seal(senderKey: Data, header: Header, payload: Data) throws -> Data {
        let h = header.bytes
        let box = try AesGcm256.seal(key: senderKey, nonce: CallKeys.frameNonce(ssrc: header.ssrc, seq: header.seq),
                                     plaintext: payload, aad: h)
        return h + box.ciphertext + box.tag
    }

    /// The payload, or nil if the frame fails under `senderKey`.
    public static func open(senderKey: Data, frame: Data) -> Data? {
        guard let h = Header.parse(frame) else { return nil }
        let bytes = Data(frame)
        let body = bytes.subdata(in: headerLength..<(bytes.count - tagLength))
        let tag = bytes.subdata(in: (bytes.count - tagLength)..<bytes.count)
        return try? AesGcm256.open(key: senderKey, nonce: CallKeys.frameNonce(ssrc: h.ssrc, seq: h.seq),
                                   ciphertext: body, tag: tag, aad: bytes.prefix(headerLength))
    }
}

/// A sender's signed list of the frames it just sent (§5.1):
/// `kind(1)=0x02 routeId(4) ssrc(4) firstSeq(8) count(1) digests(8 × count) sig(64)`.
public struct Attestation: Equatable, Sendable {
    public static let kind: UInt8 = 0x02
    public static let digestLength = 8
    public static let maxCount = 64
    public static let tag = "FreerCall-attest-v1"

    public let routeId: UInt32
    public let ssrc: UInt32
    public let firstSeq: UInt64
    public let digests: [Data]
    public let sig: Data

    /// First 8 bytes of SHA-256 of a complete, sealed media frame.
    public static func digest(_ mediaFrame: Data) -> Data {
        Hash.sha256(mediaFrame).prefix(digestLength)
    }

    /// `frames`: one per seq from `firstSeq`, nil where not sent (DTX).
    public static func sign(tPriv: Data, callOrMeetingId: String, routeId: UInt32, ssrc: UInt32, firstSeq: UInt64,
                            frames: [Data?]) throws -> Attestation {
        precondition(!frames.isEmpty && frames.count <= maxCount, "an attestation covers 1..64 frames")
        let digests = frames.map { $0.map(digest) ?? Data(repeating: 0, count: digestLength) }
        let body = Attestation.body(routeId, ssrc, firstSeq, digests)
        let sig = try CallSig.sign(privateKey: tPriv, preimage: CallBytes.of(tag).str(callOrMeetingId).bytes(body).data)
        return Attestation(routeId: routeId, ssrc: ssrc, firstSeq: firstSeq, digests: digests, sig: sig)
    }

    public func verify(tPub: Data, callOrMeetingId: String) -> Bool {
        let body = Attestation.body(routeId, ssrc, firstSeq, digests)
        return CallSig.verify(publicKey: tPub, preimage: CallBytes.of(Attestation.tag).str(callOrMeetingId).bytes(body).data,
                              signature: sig)
    }

    public var lastSeq: UInt64 { firstSeq + UInt64(digests.count) - 1 }

    public var bytes: Data { Attestation.body(routeId, ssrc, firstSeq, digests) + sig }

    public static func parse(_ data: Data) -> Attestation? {
        let b = Array(data)
        guard b.count >= 18 + digestLength + 64, b[0] == kind else { return nil }
        func be(_ at: Int, _ n: Int) -> UInt64 { b[at..<at + n].reduce(0) { $0 << 8 | UInt64($1) } }
        let count = Int(b[17])
        guard count >= 1, count <= maxCount, b.count == 18 + count * digestLength + 64 else { return nil }
        var digests: [Data] = []
        for i in 0..<count { digests.append(Data(b[(18 + i * digestLength)..<(18 + (i + 1) * digestLength)])) }
        return Attestation(routeId: UInt32(be(1, 4)), ssrc: UInt32(be(5, 4)), firstSeq: be(9, 8), digests: digests,
                           sig: Data(b[(b.count - 64)...]))
    }

    static func body(_ routeId: UInt32, _ ssrc: UInt32, _ firstSeq: UInt64, _ digests: [Data]) -> Data {
        var b = CallBytes().u8(Int(kind)).u32(routeId).u32(ssrc).u64(firstSeq).u8(digests.count)
        for d in digests { b = b.bytes(d) }
        return b.data
    }
}

/// The per-ssrc sliding window of §5: a seq seen within the last 1024, or
/// older than that, is refused. Check it only after the frame authenticates.
public struct ReplayWindow: Sendable {
    public static let size: UInt64 = 1024
    private var bits = [UInt64](repeating: 0, count: Int(size / 64))
    private var highest: Int64 = -1

    public init() {}

    public mutating func accept(_ seq: UInt64) -> Bool {
        let s = Int64(bitPattern: seq)
        guard s >= 0 else { return false }
        if s > highest {
            if highest < 0 || UInt64(s - highest) >= ReplayWindow.size {
                bits = [UInt64](repeating: 0, count: bits.count)
            } else {
                var t = highest + 1
                while t <= s { clear(UInt64(t)); t += 1 }
            }
            highest = s
            set(seq)
            return true
        }
        if UInt64(highest - s) >= ReplayWindow.size || isSet(seq) { return false }
        set(seq)
        return true
    }

    private func isSet(_ seq: UInt64) -> Bool {
        let i = Int(seq % ReplayWindow.size)
        return bits[i >> 6] & (1 << UInt64(i & 63)) != 0
    }

    private mutating func set(_ seq: UInt64) {
        let i = Int(seq % ReplayWindow.size)
        bits[i >> 6] |= 1 << UInt64(i & 63)
    }

    private mutating func clear(_ seq: UInt64) {
        let i = Int(seq % ReplayWindow.size)
        bits[i >> 6] &= ~(1 << UInt64(i & 63))
    }
}
