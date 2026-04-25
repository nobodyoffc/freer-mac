package cash.freer.mac.vectorgen;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal copy of the FUDP wire-format encoding logic from
 * {@code Freeverse/FC-JDK/src/main/java/fudp/}. Lives here so the Mac
 * vector generator can emit byte-identical reference bytes without
 * pulling FC-JDK in as a Maven dependency.
 *
 * <p>If FC-JDK ever changes the wire format, mirror the change here and
 * regenerate {@code fudpVectors.json}.
 */
public final class FudpRef {

    // ---------------------------------------------------------------
    // QUIC-style variable-length integer
    //
    // 2-bit prefix selects total length:
    //   00 → 1 byte  (6 bits data, max 63)
    //   01 → 2 bytes (14 bits data, max 16,383)
    //   10 → 4 bytes (30 bits data, max 1,073,741,823)
    //   11 → 8 bytes (62 bits data, max 4,611,686,018,427,387,903)
    // ---------------------------------------------------------------

    public static final long VARINT_MAX_1 = 63L;
    public static final long VARINT_MAX_2 = 16383L;
    public static final long VARINT_MAX_4 = 1073741823L;
    public static final long VARINT_MAX_8 = 4611686018427387903L;

    public static byte[] varintEncode(long value) {
        if (value < 0) {
            throw new IllegalArgumentException("Varint must be non-negative: " + value);
        }
        if (value <= VARINT_MAX_1) {
            return new byte[]{ (byte) value };
        }
        if (value <= VARINT_MAX_2) {
            return new byte[]{
                    (byte) ((value >> 8) | 0x40),
                    (byte) value
            };
        }
        if (value <= VARINT_MAX_4) {
            return new byte[]{
                    (byte) ((value >> 24) | 0x80),
                    (byte) (value >> 16),
                    (byte) (value >> 8),
                    (byte) value
            };
        }
        if (value <= VARINT_MAX_8) {
            return new byte[]{
                    (byte) ((value >> 56) | 0xC0),
                    (byte) (value >> 48),
                    (byte) (value >> 40),
                    (byte) (value >> 32),
                    (byte) (value >> 24),
                    (byte) (value >> 16),
                    (byte) (value >> 8),
                    (byte) value
            };
        }
        throw new IllegalArgumentException("Varint too large: " + value);
    }

    // ---------------------------------------------------------------
    // PacketHeader (21 bytes, big-endian)
    //
    //   offset 0   1B   flags
    //          1   4B   version (BE int32, currently 1)
    //          5   8B   connectionId (BE int64)
    //          13  8B   packetNumber (BE int64)
    // ---------------------------------------------------------------

    public static final int HEADER_SIZE = 21;
    public static final int CURRENT_VERSION = 1;

    public static final int FLAG_TYPE_MASK = 0x03;
    public static final int FLAG_FIN = 0x10;
    public static final int FLAG_HAS_TIMESTAMP = 0x20;
    public static final int FLAG_HAS_EPOCH = 0x40;

    public static final int PACKET_TYPE_DATA = 0x00;
    public static final int PACKET_TYPE_ACK = 0x01;
    public static final int PACKET_TYPE_CONTROL = 0x02;
    public static final int PACKET_TYPE_ERROR = 0x03;

    public static byte[] headerToBytes(byte flags, int version, long connectionId, long packetNumber) {
        ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE);  // BE by default
        buf.put(flags);
        buf.putInt(version);
        buf.putLong(connectionId);
        buf.putLong(packetNumber);
        return buf.array();
    }

    public static byte makeFlags(int packetType, boolean fin, boolean hasTimestamp, boolean hasEpoch) {
        int f = packetType & FLAG_TYPE_MASK;
        if (fin) f |= FLAG_FIN;
        if (hasTimestamp) f |= FLAG_HAS_TIMESTAMP;
        if (hasEpoch) f |= FLAG_HAS_EPOCH;
        return (byte) f;
    }

    // ---------------------------------------------------------------
    // Frames
    //
    //   FrameType.PADDING          = 0x00
    //   FrameType.ACK              = 0x01
    //   FrameType.CONNECTION_CLOSE = 0x02
    //   FrameType.MAX_DATA         = 0x03
    //   FrameType.MAX_STREAM_DATA  = 0x04
    //   FrameType.MAX_STREAMS      = 0x05
    //   FrameType.STREAM           = 0x08 base; lower 3 bits carry flags:
    //                                  bit 0 FIN, bit 1 LEN, bit 2 OFF.
    // ---------------------------------------------------------------

    public static final int FRAME_PADDING = 0x00;
    public static final int FRAME_ACK = 0x01;
    public static final int FRAME_STREAM_BASE = 0x08;

    public static final int STREAM_FIN = 0x01;
    public static final int STREAM_LEN = 0x02;  // always set in the released wire format
    public static final int STREAM_OFF = 0x04;

    public static byte[] paddingFrame() {
        return varintEncode(FRAME_PADDING);
    }

    public static byte[] streamFrame(long streamId, long offset, byte[] data, boolean fin) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int typeByte = FRAME_STREAM_BASE | STREAM_LEN;
            if (fin) typeByte |= STREAM_FIN;
            if (offset > 0) typeByte |= STREAM_OFF;
            out.write(varintEncode(typeByte));
            out.write(varintEncode(streamId));
            if (offset > 0) {
                out.write(varintEncode(offset));
            }
            out.write(varintEncode(data.length));
            out.write(data);
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] ackFrame(long largestAcked, long ackDelay, List<long[]> ranges) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(varintEncode(FRAME_ACK));
            out.write(varintEncode(largestAcked));
            out.write(varintEncode(ackDelay));
            out.write(varintEncode(ranges.size()));
            if (!ranges.isEmpty()) {
                out.write(varintEncode(ranges.get(0)[1]));  // first range length
                for (int i = 1; i < ranges.size(); i++) {
                    out.write(varintEncode(ranges.get(i)[0]));  // gap
                    out.write(varintEncode(ranges.get(i)[1]));  // length
                }
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // ---------------------------------------------------------------
    // Plaintext packet payload (the bytes that get fed into AES-GCM
    // alongside the 21-byte header as AAD).
    //
    //   [optional 8B timestamp BE int64] (if FLAG_HAS_TIMESTAMP)
    //   [optional 8B sessionEpoch BE int64] (if FLAG_HAS_EPOCH)
    //   [frames, concatenated, each varint-typed]
    // ---------------------------------------------------------------

    public static byte[] payload(boolean includeTimestamp, long timestamp,
                                 boolean includeEpoch, long sessionEpoch,
                                 List<byte[]> frames) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            if (includeTimestamp) out.write(longToBytes(timestamp));
            if (includeEpoch) out.write(longToBytes(sessionEpoch));
            for (byte[] f : frames) out.write(f);
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] longToBytes(long v) {
        ByteBuffer buf = ByteBuffer.allocate(8);  // BE
        buf.putLong(v);
        return buf.array();
    }

    private FudpRef() {}

    // No-op accessor to silence "unused import" warnings if Hex isn't
    // referenced elsewhere in the file.
    static String hexOf(byte[] bytes) { return Hex.toHexString(bytes); }
}
