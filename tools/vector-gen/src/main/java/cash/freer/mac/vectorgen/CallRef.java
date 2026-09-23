package cash.freer.mac.vectorgen;

import com.fc.fc_ajdk.call.Attestation;
import com.fc.fc_ajdk.call.CallKeys;
import com.fc.fc_ajdk.call.Delegation;
import com.fc.fc_ajdk.call.MediaFrame;
import com.fc.fc_ajdk.core.crypto.KeyTools;
import com.google.gson.JsonObject;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Golden vectors for voice calls (VOICE_SPEC §4–§5), produced by the REAL
 * FC-AJDK {@code com.fc.fc_ajdk.call} classes. Every input is fixed and every
 * primitive deterministic (BCH Schnorr nonces are derived from key and
 * message), so the file only changes when the wire format does. The Mac
 * port (FCDomain) and FC-JDK's verify-only copy must reproduce each output.
 */
final class CallRef {

    private CallRef() {}

    static JsonObject generate() throws Exception {
        byte[] fidPrivA = seed("fid A"), fidPrivB = seed("fid B");
        byte[] tPrivA = seed("transport A"), tPrivB = seed("transport B");
        byte[] tPubA = KeyTools.prikeyToPubkey(tPrivA), tPubB = KeyTools.prikeyToPubkey(tPrivB);
        String fidA = KeyTools.pubkeyToFchAddr(KeyTools.prikeyToPubkey(fidPrivA));
        String fidB = KeyTools.pubkeyToFchAddr(KeyTools.prikeyToPubkey(fidPrivB));
        String callId = "00112233445566778899aabbccddeeff";
        long expires = 1_790_003_600L;
        int ssrc = 0xCAFEBABE;

        JsonObject root = new JsonObject();
        root.addProperty("schema_version", 1);
        root.addProperty("generator", "FreerForMac VectorGen (com.fc.fc_ajdk.call from FC-AJDK)");

        JsonObject keys = new JsonObject();
        keys.addProperty("fid_priv_a", hex(fidPrivA));
        keys.addProperty("fid_a", fidA);
        keys.addProperty("fid_priv_b", hex(fidPrivB));
        keys.addProperty("fid_b", fidB);
        keys.addProperty("t_priv_a", hex(tPrivA));
        keys.addProperty("t_pub_a", hex(tPubA));
        keys.addProperty("t_priv_b", hex(tPrivB));
        keys.addProperty("t_pub_b", hex(tPubB));
        keys.addProperty("call_id", callId);
        root.add("keys", keys);

        // §4.1
        Delegation d = Delegation.sign(fidPrivA, callId, tPubA, expires);
        require(d.verify(callId, expires - 60) == Delegation.Check.OK, "delegation verifies");
        JsonObject del = new JsonObject();
        del.addProperty("expires_sec", expires);
        del.addProperty("json", d.toJson());
        del.addProperty("sig", d.sig);
        root.add("delegation", del);

        // §4.2, both ends
        byte[] p2p = CallKeys.p2pSecret(tPrivA, tPubB, callId, fidA, fidB);
        require(java.util.Arrays.equals(p2p, CallKeys.p2pSecret(tPrivB, tPubA, callId, fidB, fidA)),
                "p2p secret is symmetric");
        root.addProperty("p2p_secret", hex(p2p));

        byte[] symkey = seed("room symkey v3"), nonce = seed("meeting nonce");
        JsonObject meeting = new JsonObject();
        meeting.addProperty("symkey", hex(symkey));
        meeting.addProperty("nonce", hex(nonce));
        meeting.addProperty("entity_id", "room_vectors");
        meeting.addProperty("symkey_version", 3);
        meeting.addProperty("meeting_id", "mtg_000102030405060708090a0b");
        meeting.addProperty("secret", hex(CallKeys.meetingSecret(symkey, nonce, "room_vectors", 3,
                "mtg_000102030405060708090a0b")));
        root.add("meeting", meeting);

        // §4.3
        JsonObject sender = new JsonObject();
        sender.addProperty("ssrc", Integer.toUnsignedString(ssrc));
        sender.addProperty("epoch0", hex(CallKeys.senderKey(p2p, fidA, ssrc, 0)));
        sender.addProperty("epoch1", hex(CallKeys.senderKey(p2p, fidA, ssrc, 1)));
        sender.addProperty("nonce_seq_258", hex(CallKeys.frameNonce(ssrc, 258)));
        root.add("sender_key", sender);

        // §4.4
        byte[] authPriv = CallKeys.authPriv(p2p);
        long ts = 1_790_000_000_123L;
        JsonObject admit = new JsonObject();
        admit.addProperty("auth_priv", hex(authPriv));
        admit.addProperty("auth_pub", hex(CallKeys.authPub(authPriv)));
        admit.addProperty("ts_ms", ts);
        admit.addProperty("admit_sig", hex(CallKeys.admitSig(authPriv, callId, tPubB, ssrc, ts)));
        root.add("admission", admit);

        // §5
        byte[] senderKey = CallKeys.senderKey(p2p, fidA, ssrc, 0);
        byte[] opus = new byte[20];
        for (int i = 0; i < opus.length; i++) opus[i] = (byte) (0xA0 + i);
        MediaFrame.Header h = new MediaFrame.Header(MediaFrame.FLAG_VAD, 0x01020304, ssrc, 258, 0x00ABCDEF, 38, 0);
        byte[] frame = MediaFrame.seal(senderKey, h, opus);
        require(java.util.Arrays.equals(opus, MediaFrame.open(senderKey, frame)), "frame opens");
        JsonObject media = new JsonObject();
        media.addProperty("header", hex(h.toBytes()));
        media.addProperty("payload", hex(opus));
        media.addProperty("frame", hex(frame));
        root.add("media_frame", media);

        // §5.1
        List<byte[]> frames = new ArrayList<>();
        for (long seq = 258; seq < 261; seq++) {
            MediaFrame.Header hs = new MediaFrame.Header(MediaFrame.FLAG_VAD, 0x01020304, ssrc, seq,
                    0x00ABCDEF + (seq - 258) * 960, 38, 0);
            frames.add(MediaFrame.seal(senderKey, hs, opus));
        }
        Attestation a = Attestation.sign(tPrivA, callId, 0x01020304, ssrc, 258, frames);
        require(a.verify(tPubA, callId), "attestation verifies");
        JsonObject att = new JsonObject();
        com.google.gson.JsonArray fr = new com.google.gson.JsonArray();
        for (byte[] f : frames) fr.add(hex(f));
        att.add("frames", fr);
        att.addProperty("attestation", hex(a.toBytes()));
        root.add("attestation", att);
        return root;
    }

    private static byte[] seed(String label) throws Exception {
        return MessageDigest.getInstance("SHA-256")
                .digest(("FreerCall vector " + label).getBytes(StandardCharsets.UTF_8));
    }

    private static String hex(byte[] b) {
        return Hex.toHexString(b);
    }

    private static void require(boolean ok, String what) {
        if (!ok) throw new IllegalStateException("call vector self-check failed: " + what);
    }
}
