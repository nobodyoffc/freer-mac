package cash.freer.mac.vectorgen;

import com.fc.fc_ajdk.core.crypto.CryptoDataByte;
import com.fc.fc_ajdk.core.crypto.Decryptor;
import com.fc.fc_ajdk.core.crypto.Encryptor;
import com.fc.fc_ajdk.core.crypto.KeyTools;
import com.fc.fc_ajdk.data.fcData.AlgorithmId;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

/**
 * Golden vectors for the <b>AsyTwoWay</b> CryptoDataStr envelope, produced
 * by the REAL FC-AJDK {@code Encryptor} — the class that seals every mail
 * the Android app carves.
 *
 * <p>AsyTwoWay differs from the AsyOneWay envelope the Swift side already
 * reads (contacts, secrets) in exactly one way that matters, and it is the
 * whole reason the format exists: the sender does <b>not</b> use an
 * ephemeral key. The ECDH is between the sender's real private key and the
 * recipient's public key, so the envelope carries <b>both</b>
 * {@code pubkeyA} (sender) and {@code pubkeyB} (recipient) and either party
 * can re-derive the shared secret. Without that, a sender could never
 * re-read a mail they had sent — which is most of an outbox.
 *
 * <p>Two algorithms appear on the wire, and the Android app uses both:
 * {@code Mail.encryptContent} — the path a <i>carved</i> mail goes through —
 * asks for {@code FC_EccK1AesCbc256_No1_NrC7}, while
 * {@code CreateMailActivity.encryptMailContent} — the local-save path —
 * asks for {@code FC_EccK1AesGcm256_No1_NrC7}. So a Mac client that only
 * understood GCM would fail on every mail Android has ever sent on-chain.
 * Both are pinned below.
 *
 * <p>The trailing {@code self-*} vector covers {@code from == to}: a note to
 * self is sealed AsyOneWay, because AsyTwoWay with both pubkeys equal gives
 * Java's side-selection nothing to pick and it gives up.
 */
final class AsyTwoWayRef {

    private AsyTwoWayRef() {}

    // Leaked test keys — safe to publish. A is the sender, B the recipient.
    private static final String PRIKEY_A_HEX =
            "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575";
    private static final String PRIKEY_B_HEX =
            "5b7c1e3d9a4f08c2e6b5d3417f8a90c4d2e6b8137a5c9f0e4d2b6a8c135e7f90";
    // A third party who must NOT be able to open any of these.
    private static final String PRIKEY_C_HEX =
            "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    static JsonObject generate() {
        byte[] prikeyA = Hex.decode(PRIKEY_A_HEX);
        byte[] prikeyB = Hex.decode(PRIKEY_B_HEX);
        byte[] prikeyC = Hex.decode(PRIKEY_C_HEX);
        byte[] pubkeyA = KeyTools.prikeyToPubkey(prikeyA);
        byte[] pubkeyB = KeyTools.prikeyToPubkey(prikeyB);

        JsonObject root = new JsonObject();
        root.addProperty("prikeyA", PRIKEY_A_HEX);
        root.addProperty("pubkeyA", Hex.toHexString(pubkeyA));
        root.addProperty("prikeyB", PRIKEY_B_HEX);
        root.addProperty("pubkeyB", Hex.toHexString(pubkeyB));
        root.addProperty("prikeyC_stranger", PRIKEY_C_HEX);

        JsonArray vectors = new JsonArray();
        for (AlgorithmId alg : new AlgorithmId[]{
                AlgorithmId.FC_EccK1AesGcm256_No1_NrC7,
                AlgorithmId.FC_EccK1AesCbc256_No1_NrC7}) {
            String tag = alg == AlgorithmId.FC_EccK1AesGcm256_No1_NrC7 ? "gcm" : "cbc";
            vectors.add(twoWay(tag + "-ascii", alg, prikeyA, pubkeyB,
                    "Meet me at the usual place."));
            vectors.add(twoWay(tag + "-unicode", alg, prikeyA, pubkeyB,
                    "你好，世界 — naïve café 🚀"));
            // Shortest body that exists in practice. A zero-length payload is
            // deliberately NOT a vector: FC-AJDK's own Decryptor rejects what
            // its Encryptor produces for empty data (code 1029), so there is
            // no correct answer to pin. Neither client can send an empty mail.
            vectors.add(twoWay(tag + "-one-char", alg, prikeyA, pubkeyB, "x"));
            // A mail is capped at the OP_RETURN size, so this is roughly the
            // largest body that can ever reach the chain.
            vectors.add(twoWay(tag + "-long", alg, prikeyA, pubkeyB, repeat("0123456789", 400)));
        }
        // from == to: sealed to my own pubkey, one-way.
        vectors.add(oneWay("self-gcm", AlgorithmId.FC_EccK1AesGcm256_No1_NrC7,
                pubkeyA, "A note I wrote to myself."));
        vectors.add(oneWay("self-cbc", AlgorithmId.FC_EccK1AesCbc256_No1_NrC7,
                pubkeyA, "A note I wrote to myself."));

        root.add("vectors", vectors);
        // Prove the stranger's key is genuinely useless against the first
        // vector rather than merely untested.
        root.addProperty("stranger_can_decrypt",
                opens(vectors.get(0).getAsJsonObject().get("envelope").getAsString(), prikeyC));
        return root;
    }

    private static JsonObject twoWay(String name, AlgorithmId alg,
                                     byte[] prikeyA, byte[] pubkeyB, String plaintext) {
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        CryptoDataByte c = new Encryptor(alg).encryptByAsyTwoWay(data, prikeyA, pubkeyB);
        if (c == null || c.getCode() != 0) {
            throw new IllegalStateException("encryptByAsyTwoWay failed for " + name
                    + ": " + (c == null ? "null" : c.getMessage()));
        }
        String envelope = c.toJson();

        JsonObject o = base(name, alg, plaintext, envelope);
        o.addProperty("mode", "AsyTwoWay");
        return o;
    }

    private static JsonObject oneWay(String name, AlgorithmId alg,
                                     byte[] pubkeyB, String plaintext) {
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        CryptoDataByte c = new Encryptor(alg).encryptByAsyOneWay(data, pubkeyB);
        if (c == null || c.getCode() != 0) {
            throw new IllegalStateException("encryptByAsyOneWay failed for " + name
                    + ": " + (c == null ? "null" : c.getMessage()));
        }
        JsonObject o = base(name, alg, plaintext, c.toJson());
        o.addProperty("mode", "AsyOneWay");
        return o;
    }

    private static JsonObject base(String name, AlgorithmId alg,
                                   String plaintext, String envelope) {
        JsonObject o = new JsonObject();
        o.addProperty("name", name);
        o.addProperty("alg", alg.name());
        o.addProperty("plaintext", plaintext);
        o.addProperty("plaintext_hex",
                Hex.toHexString(plaintext.getBytes(StandardCharsets.UTF_8)));
        o.addProperty("envelope", envelope);
        return o;
    }

    /** Round-trips an envelope through the real Decryptor. */
    static boolean opens(String envelope, byte[] prikey) {
        CryptoDataByte c = Decryptor.decryptTry(envelope, prikey, null, null);
        return c != null && c.getCode() == 0 && c.getData() != null;
    }

    /**
     * Every vector must open with BOTH keys for AsyTwoWay (recipient side and
     * sender side) and with the recipient's key for AsyOneWay — verified here
     * so a broken vector fails at generation time rather than in Swift, where
     * it would look like a port bug.
     */
    static void verify(JsonObject root) {
        byte[] prikeyA = Hex.decode(root.get("prikeyA").getAsString());
        byte[] prikeyB = Hex.decode(root.get("prikeyB").getAsString());
        for (var el : root.getAsJsonArray("vectors")) {
            JsonObject v = el.getAsJsonObject();
            String name = v.get("name").getAsString();
            String envelope = v.get("envelope").getAsString();
            boolean twoWay = "AsyTwoWay".equals(v.get("mode").getAsString());
            byte[] expected = Hex.decode(v.get("plaintext_hex").getAsString());

            check(name, "recipient", envelope, twoWay ? prikeyB : prikeyA, expected);
            if (twoWay) check(name, "sender", envelope, prikeyA, expected);
        }
    }

    private static void check(String name, String side, String envelope,
                              byte[] prikey, byte[] expected) {
        CryptoDataByte c = Decryptor.decryptTry(envelope, prikey, null, null);
        if (c == null || c.getCode() != 0 || c.getData() == null
                || !java.util.Arrays.equals(c.getData(), expected)) {
            throw new IllegalStateException(
                    "vector " + name + " does not round-trip on the " + side + " side"
                    + " — code=" + (c == null ? "null" : c.getCode())
                    + " message=" + (c == null ? "null" : c.getMessage())
                    + " data=" + (c == null || c.getData() == null
                            ? "null" : Hex.toHexString(c.getData())));
        }
    }

    private static String repeat(String s, int times) {
        StringBuilder sb = new StringBuilder(s.length() * times);
        for (int i = 0; i < times; i++) sb.append(s);
        return sb.toString();
    }
}
