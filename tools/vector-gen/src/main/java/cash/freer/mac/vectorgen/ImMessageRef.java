package cash.freer.mac.vectorgen;

import com.fc.fc_ajdk.data.fcData.ContentType;
import com.fc.fc_ajdk.data.fcData.DeliveryMethod;
import com.fc.fc_ajdk.data.fcData.ImMessage;
import com.fc.fc_ajdk.data.fcData.ImType;
import com.fc.fc_ajdk.data.fcData.MessageStatus;
import com.fc.fc_ajdk.data.fcData.RequestType;
import com.fc.fc_ajdk.utils.JsonUtils;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.bouncycastle.util.encoders.Hex;

import java.util.List;

/**
 * Golden vectors for {@code ImMessage}, produced by the REAL FC-AJDK class.
 *
 * <p>An IM message has two serializations and they disagree on purpose:
 *
 * <ol>
 *   <li><b>JSON</b> ({@code toJson}) is the local-storage form — every field,
 *       including the delivery bookkeeping. It also crosses devices: a HISTORY
 *       share writes one {@code toJson()} per line into a file that the other
 *       client reads back with {@code fromJson}. So Gson's rules bind here too:
 *       declaration order (subclass before superclass, hence {@code id} last),
 *       nulls omitted, HTML escaping <i>disabled</i>, and enums by
 *       <b>name</b>.</li>
 *   <li><b>Wire bytes</b> ({@code toWireBytes}) is what actually travels. It is
 *       a flag-word format that carries only what the recipient needs, and it
 *       identifies enums by <b>ordinal</b>. Two encodings of the same enum,
 *       which is why {@code enum_ordinals} below is pinned separately: a
 *       reordered enum constant would keep every JSON test green and silently
 *       reroute every message on the wire.</li>
 * </ol>
 *
 * <p>The {@code wire_decoded_json} field on each vector is the round trip —
 * {@code fromWireBytes(toWireBytes(m))} re-serialized — and it is the honest
 * statement of what survives transmission. Everything a sender knows about
 * delivery (status, roadIds, dockId, readAt, unread, …) is local-only and
 * drops out; a port that helpfully preserved it would be inventing facts about
 * the receiving device.
 */
final class ImMessageRef {

    private ImMessageRef() {}

    private static final String FID_A = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK";
    private static final String FID_B = "F6vqNGkbAqZQ1YkPWLcXfNfwvJXCTGmzUM";
    private static final String ROOM_ID = "b4c9a1f2e8d73065b4c9a1f2e8d73065b4c9a1f2e8d73065b4c9a1f2e8d73065";

    static JsonObject generate() {
        JsonObject root = new JsonObject();
        root.add("enum_ordinals", enumOrdinals());
        root.add("vectors", vectors());
        return root;
    }

    // ------------------------------------------------------------------
    // Enum ordinal tables
    // ------------------------------------------------------------------

    /**
     * Every enum constant that reaches the wire, in declaration order, with the
     * ordinal the wire format writes for it. These are the numbers, not a
     * description of them: the Swift side asserts against this table rather
     * than against its own case order.
     */
    private static JsonObject enumOrdinals() {
        JsonObject out = new JsonObject();
        out.add("ImType", names(ImType.values()));
        out.add("ContentType", names(ContentType.values()));
        out.add("RequestType", names(RequestType.values()));
        out.add("MessageStatus", names(MessageStatus.values()));
        out.add("DeliveryMethod", names(DeliveryMethod.values()));
        return out;
    }

    private static JsonArray names(Enum<?>[] values) {
        JsonArray a = new JsonArray();
        for (Enum<?> v : values) a.add(v.name());
        return a;
    }

    // ------------------------------------------------------------------
    // Message vectors
    // ------------------------------------------------------------------

    private static JsonArray vectors() {
        JsonArray out = new JsonArray();
        out.add(vector("p2p-text", p2pText()));
        out.add(vector("p2p-text-unicode", p2pTextUnicode()));
        // '<' '>' '&' '=' '\'' are escaped by Gson's default writer but NOT by
        // JsonUtils.toJson. A chat message is the likeliest place in the app
        // for those characters to show up in anger.
        out.add(vector("p2p-text-html-escapable", p2pTextHtmlEscapable()));
        out.add(vector("no-id", noId()));
        out.add(vector("hat-share", hatShare()));
        out.add(vector("voice", voice()));
        out.add(vector("request-symkey", requestSymkey()));
        out.add(vector("response", response()));
        out.add(vector("receipt", receipt()));
        out.add(vector("room-info", roomInfo()));
        out.add(vector("team-cipher", teamCipher()));
        out.add(vector("symkey-version-truncated", symkeyVersionTruncated()));
        out.add(vector("empty-strings", emptyStrings()));
        out.add(vector("full", full()));
        return out;
    }

    private static JsonObject vector(String label, ImMessage msg) {
        JsonObject v = new JsonObject();
        v.addProperty("label", label);
        v.addProperty("json", JsonUtils.toJson(msg));

        byte[] wire = msg.toWireBytes();
        v.addProperty("wire_hex", Hex.toHexString(wire));
        v.addProperty("wire_decoded_json", JsonUtils.toJson(ImMessage.fromWireBytes(wire)));
        return v;
    }

    // ------------------------------------------------------------------
    // The cases
    // ------------------------------------------------------------------

    /**
     * What {@code ImMessage.createBase} does, for the content types it has no
     * public factory for. Kept identical to it — including the PENDING status —
     * so these vectors describe the same object the app would build.
     */
    private static ImMessage base(ImType type, String senderId, String targetId, ContentType contentType) {
        ImMessage m = new ImMessage();
        m.setType(type);
        m.setSenderId(senderId);
        m.setTargetId(targetId);
        m.setContentType(contentType);
        m.setStatus(MessageStatus.PENDING);
        return m;
    }

    /** The ordinary case: one line of text, id already assigned by FudpNode. */
    private static ImMessage p2pText() {
        ImMessage m = ImMessage.createText(ImType.P2P, FID_A, FID_B, "Meet me at the usual place.");
        m.setTimestamp(1755100000123L);
        m.setId("00000000deadbeef");
        return m;
    }

    private static ImMessage p2pTextUnicode() {
        ImMessage m = ImMessage.createText(ImType.P2P, FID_A, FID_B, "老地方见 — naïve café 🚀");
        m.setTimestamp(1755100000456L);
        m.setId("0123456789abcdef");
        return m;
    }

    private static ImMessage p2pTextHtmlEscapable() {
        ImMessage m = ImMessage.createText(ImType.P2P, FID_A, FID_B, "a<b & c='d' => e");
        m.setTimestamp(1755100000789L);
        m.setId("fedcba9876543210");
        return m;
    }

    /**
     * A message that has not been through the FUDP layer yet, so FLAG_MESSAGE_ID
     * is clear and the receiver has to name it from the packet header instead.
     */
    private static ImMessage noId() {
        ImMessage m = ImMessage.createText(ImType.P2P, FID_A, FID_B, "sent before an id was assigned");
        m.setTimestamp(1755100001000L);
        return m;
    }

    /** A file share: the HAT JSON rides in content, the bytes do not. */
    private static ImMessage hatShare() {
        ImMessage m = base(ImType.ROOM, FID_A, ROOM_ID, ContentType.HAT);
        m.setContent("{\"key\":\"3d1f0c\",\"locas\":[\"disk1\"],\"size\":1048576,\"id\":\"abc123\"}");
        m.setTimestamp(1755100002000L);
        m.setId("00000000cafebabe");
        return m;
    }

    /**
     * Inline audio: metadata in the body's content section, AAC payload in its
     * data section. Both are inside one body now, and in v2 both would be
     * inside one seal -- which is the whole point of the version.
     */
    private static ImMessage voice() {
        ImMessage m = ImMessage.createVoice(ImType.P2P, FID_B, FID_A,
                "{\"durationMs\":3400,\"sampleRate\":44100,\"format\":\"aac\"}",
                new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
        m.setTimestamp(1755100003000L);
        m.setId("00000000feedface");
        return m;
    }

    /** A joiner asking a member for the room's symmetric key. */
    private static ImMessage requestSymkey() {
        ImMessage m = ImMessage.createRequest(ImType.ROOM, FID_B, ROOM_ID,
                RequestType.SYMKEY, ROOM_ID);
        m.setTimestamp(1755100004000L);
        m.setId("00000000a1b2c3d4");
        return m;
    }

    /** The answer, naming the request it answers. */
    private static ImMessage response() {
        ImMessage m = ImMessage.createResponse(ImType.ROOM, FID_A, FID_B,
                "00000000a1b2c3d4", "{\"keyName\":\"room-1\",\"key\":\"0f0e0d\"}");
        m.setTimestamp(1755100005000L);
        m.setId("00000000d4c3b2a1");
        return m;
    }

    private static ImMessage receipt() {
        ImMessage m = ImMessage.createReceipt(FID_B, FID_A, "00000000deadbeef", true);
        m.setTimestamp(1755100006000L);
        m.setId("000000001a2b3c4d");
        return m;
    }

    private static ImMessage roomInfo() {
        ImMessage m = ImMessage.createRoomInfo(ImType.ROOM, FID_A, FID_B,
                "{\"roomId\":\"" + ROOM_ID + "\",\"name\":\"The Usual Place\",\"members\":[\""
                        + FID_A + "\",\"" + FID_B + "\"]}");
        m.setTimestamp(1755100007000L);
        m.setId("000000004d3c2b1a");
        return m;
    }

    /**
     * Team traffic: the body is sealed, so `body` carries the bundle and both
     * content and data are null.
     *
     * <p>The bundle bytes here are a fixed stand-in, not a real seal: a real
     * one uses a random IV and would make the vector different on every run.
     * The wire format treats the body as opaque, so a stand-in exercises it
     * exactly as a real bundle would.
     */
    private static ImMessage teamCipher() {
        ImMessage m = base(ImType.TEAM, FID_A, ROOM_ID, ContentType.TEXT);
        m.setBody(new byte[] {
            // alg prefix for AesGcm256, then type=Symkey(0), keyName, iv, cipher
            (byte) 0x76, (byte) 0xf7, (byte) 0xb2, (byte) 0x26, (byte) 0xa8, (byte) 0xb3,
            0x00,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef
        });
        m.setSymkeyVersion(7L);
        m.setTimestamp(1755100008000L);
        m.setId("00000000beefcafe");
        return m;
    }

    /**
     * symkeyVersion is a Long in the model but is written to the wire with
     * {@code putInt(intValue())} and read back with {@code (long) getInt()}. A
     * version past 2^31 therefore does not survive the trip, and a sign bit
     * comes back negative. This vector fixes that behaviour so the Swift port
     * reproduces it rather than "fixing" it into an incompatibility.
     */
    private static ImMessage symkeyVersionTruncated() {
        ImMessage m = base(ImType.TEAM, FID_A, ROOM_ID, ContentType.TEXT);
        m.setContent("key rotation past the int boundary");
        m.setSymkeyVersion(0x1_8000_0001L);
        m.setTimestamp(1755100009000L);
        m.setId("00000000000000ff");
        return m;
    }

    /**
     * Empty and null are the same thing on the far side, in two different ways.
     *
     * <p>A length-prefixed <em>string</em> field (threadId) writes a zero
     * length and reads back as "". The <em>body</em> does not: its framing
     * records a length rather than a presence, so an empty content section
     * cannot come back as "" -- it comes back null, and the encoder therefore
     * omits the body entirely rather than writing an all-zero framing that
     * would not survive a second encode. Pinning both stops a port from
     * guessing either way.
     */
    private static ImMessage emptyStrings() {
        ImMessage m = ImMessage.createText(ImType.P2P, FID_A, FID_B, "");
        m.setThreadId("");
        m.setTimestamp(1755100010000L);
        m.setId("0000000000000000");
        return m;
    }

    /**
     * Every field set, wire-carried and local-only alike. The local-only ones
     * exist here to be missing from {@code wire_decoded_json}.
     *
     * <p>Every field <em>except</em> a sealed body, which is mutually exclusive
     * with content and data: a sealed message has one or the other, never both,
     * and toWireBytes carries the sealed body in preference to framing the
     * plaintext. The sealed shape is covered by the team-cipher vector.
     */
    private static ImMessage full() {
        ImMessage m = ImMessage.createText(ImType.ROOM, FID_A, ROOM_ID, "everything at once");
        m.setId("00000000ffffffff");
        m.setTimestamp(1755100011000L);
        m.setSequence(42L);
        m.setData(new byte[] {0, 1, 2, 3});
        m.setSymkeyVersion(3L);
        m.setRequestType(RequestType.HISTORY);
        m.setRequestId("00000000deadbeef");
        m.setReplyToId("00000000cafebabe");
        m.setThreadId("thread-1");
        m.setRoadIds(List.of("road-a", "road-b"));
        m.setDockId("dock-1");
        m.setDeliveryMethod(DeliveryMethod.ROAD_RELAY);
        m.setStatus(MessageStatus.DELIVERED);
        m.setDeliveredAt(1755100012000L);
        m.setReadAt(1755100013000L);
        m.setSenderName("alice");
        m.setUnread(true);
        m.setPinned(true);
        m.setDeleted(false);
        return m;
    }
}
