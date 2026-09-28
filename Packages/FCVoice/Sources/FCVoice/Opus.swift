import Foundation
import COpus

/// libopus for calls (VOICE_SPEC §9.1): mono, 48 kHz, VOIP mode. One encoder
/// per outgoing stream and one decoder per incoming one; neither is thread-safe.
public enum Opus {
    public static let sampleRate = 48_000
    /// Largest packet asked for; a 60 ms frame at 32 kbps is about 240 bytes.
    public static let maxPacket = 1000

    public enum Failure: Error {
        case create(Int32), encode(Int32), decode(Int32), ctl(Int32, Int32)
    }

    public final class Encoder {
        private let enc: OpaquePointer

        /// The spec's settings: VBR, voice signal, complexity 9, in-band FEC.
        public init(bitrate: Int, dtx: Bool, expectedLossPercent: Int) throws {
            var err: Int32 = 0
            guard let e = opus_encoder_create(Int32(Opus.sampleRate), 1, OPUS_APPLICATION_VOIP, &err), err == OPUS_OK else {
                throw Failure.create(err)
            }
            enc = e
            try set(OPUS_SET_SIGNAL_REQUEST, OPUS_SIGNAL_VOICE)
            try set(OPUS_SET_VBR_REQUEST, 1)
            try set(OPUS_SET_COMPLEXITY_REQUEST, 9)
            try set(OPUS_SET_INBAND_FEC_REQUEST, 1)
            try setBitrate(bitrate)
            try set(OPUS_SET_DTX_REQUEST, dtx ? 1 : 0)
            try setPacketLossPercent(expectedLossPercent)
        }

        deinit { opus_encoder_destroy(enc) }

        public func setBitrate(_ bps: Int) throws {
            try set(OPUS_SET_BITRATE_REQUEST, Int32(bps))
        }

        /// How much loss FEC is sized for.
        public func setPacketLossPercent(_ percent: Int) throws {
            try set(OPUS_SET_PACKET_LOSS_PERC_REQUEST, Int32(max(0, min(100, percent))))
        }

        /// One frame of `pcm` (its whole length) to a packet. 1-2 bytes is a DTX frame not worth sending.
        public func encode(_ pcm: [Int16]) throws -> Data {
            var out = [UInt8](repeating: 0, count: Opus.maxPacket)
            let n = pcm.withUnsafeBufferPointer { p in
                opus_encode(enc, p.baseAddress!, Int32(pcm.count), &out, Int32(out.count))
            }
            guard n >= 0 else { throw Failure.encode(n) }
            return Data(out[0..<Int(n)])
        }

        private func set(_ request: Int32, _ value: Int32) throws {
            let r = copus_encoder_set(enc, request, value)
            guard r == OPUS_OK else { throw Failure.ctl(request, r) }
        }
    }

    public final class Decoder {
        private let dec: OpaquePointer

        public init() throws {
            var err: Int32 = 0
            guard let d = opus_decoder_create(Int32(Opus.sampleRate), 1, &err), err == OPUS_OK else {
                throw Failure.create(err)
            }
            dec = d
        }

        deinit { opus_decoder_destroy(dec) }

        /// One frame of `frameSize` samples.
        public func decode(_ packet: Data, frameSize: Int) throws -> [Int16] {
            try run(packet, frameSize: frameSize, fec: false)
        }

        /// The frame before `nextPacket`, from the FEC data that one carries.
        public func decodeFec(_ nextPacket: Data, frameSize: Int) throws -> [Int16] {
            try run(nextPacket, frameSize: frameSize, fec: true)
        }

        /// Packet-loss concealment for one missing frame.
        public func conceal(frameSize: Int) throws -> [Int16] {
            try run(nil, frameSize: frameSize, fec: false)
        }

        private func run(_ packet: Data?, frameSize: Int, fec: Bool) throws -> [Int16] {
            var pcm = [Int16](repeating: 0, count: frameSize)
            let n: Int32
            if let packet {
                n = packet.withUnsafeBytes { raw in
                    opus_decode(dec, raw.bindMemory(to: UInt8.self).baseAddress, Int32(packet.count), &pcm,
                                Int32(frameSize), fec ? 1 : 0)
                }
            } else {
                n = opus_decode(dec, nil, 0, &pcm, Int32(frameSize), 0)
            }
            guard n >= 0 else { throw Failure.decode(n) }
            return Array(pcm[0..<Int(n)])
        }
    }
}

/// How much audio an Opus packet holds, from its TOC byte (RFC 6716 §3.1),
/// without decoding it: a receiver learns each sender's frame length this
/// way, and senders may change it mid-call (VOICE_SPEC §9.1).
public enum OpusToc {
    private static func frameSamples(config: Int) -> Int {
        if config < 12 { return [480, 960, 1920, 2880][config & 3] }
        if config < 16 { return config & 1 == 0 ? 480 : 960 }
        return [120, 240, 480, 960][config & 3]
    }

    /// The packet's audio in 48 kHz samples, or nil if malformed or over 60 ms.
    public static func samples(_ packet: Data) -> Int? {
        let p = Array(packet)
        guard let toc = p.first.map(Int.init) else { return nil }
        let frames: Int
        switch toc & 3 {
        case 0: frames = 1
        case 1, 2: frames = 2
        default: frames = p.count < 2 ? 0 : Int(p[1]) & 0x3F
        }
        let total = frames * frameSamples(config: toc >> 3)
        return frames == 0 || total > 2880 ? nil : total
    }
}
