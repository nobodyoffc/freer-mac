package cash.freer.mac.vectorgen;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.fch.FchMainNetwork;

import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

/**
 * Emits a testVectors.json consumed by Swift unit tests in FCCore.
 *
 * The generator uses the same JVM libraries the Android app uses —
 * freecashj v0.16 and the BouncyCastle that ships with it — so whatever
 * the Swift implementations compute must match these values byte for byte.
 *
 * Run with:
 *   ./gradlew run --args="../../Packages/FCCore/Tests/FCCoreTests/Resources/testVectors.json"
 */
public final class VectorGen {

    // Leaked test key — safe to publish. Used as a canonical identity across
    // the whole test suite so multiple primitives can be verified end-to-end.
    private static final String SAMPLE_PRIVKEY_HEX =
            "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575";
    private static final String EXPECTED_SAMPLE_PUBKEY_HEX =
            "030be1d7e633feb2338a74a860e76d893bac525f35a5813cb7b21e27ba1bc8312a";
    private static final String EXPECTED_SAMPLE_WIF =
            "L2bHRej6Fxxipvb4TiR5bu1rkT3tRp8yWEsUy4R1Zb8VMm2x7sd8";
    private static final String EXPECTED_SAMPLE_FID =
            "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: gradle run --args=\"<output.json>\"");
            System.exit(64);
        }
        Path out = Paths.get(args[0]);

        JsonObject root = new JsonObject();
        root.addProperty("generated_at", Instant.now().toString());
        root.addProperty("schema_version", 1);
        root.addProperty("generator", "FreerForMac VectorGen (freecashj v0.16 + BouncyCastle)");

        root.add("sample_key", buildSampleKey());
        root.add("argon2id", buildArgon2idVectors());
        root.add("sha256", buildSha256Vectors());
        root.add("ripemd160", buildRipemd160Vectors());
        root.add("hash160", buildHash160Vectors());
        root.add("aes_gcm_256", buildAesGcm256Vectors());
        root.add("chacha20_poly1305", buildChaCha20Poly1305Vectors());
        root.add("hkdf_sha256", buildHkdfVectors(new SHA256Digest()));
        root.add("hkdf_sha512", buildHkdfVectors(new SHA512Digest()));
        root.add("ecdsa", buildEcdsaVectors());
        root.add("ecdh", buildEcdhVectors());

        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        Files.createDirectories(out.toAbsolutePath().getParent());
        Files.writeString(out, gson.toJson(root));
        System.out.println("Wrote " + out.toAbsolutePath());
    }

    private static JsonObject buildSampleKey() {
        byte[] privkey = Hex.decode(SAMPLE_PRIVKEY_HEX);
        ECKey key = ECKey.fromPrivate(privkey, /* compressed */ true);
        NetworkParameters params = FchMainNetwork.MAINNETWORK;

        String pubkeyHex = Hex.toHexString(key.getPubKey());
        String wif = key.getPrivateKeyEncoded(params).toString();
        String fid = Address.fromKey(params, key).toString();

        require(pubkeyHex.equalsIgnoreCase(EXPECTED_SAMPLE_PUBKEY_HEX),
                "pubkey mismatch: got " + pubkeyHex + ", expected " + EXPECTED_SAMPLE_PUBKEY_HEX);
        require(wif.equals(EXPECTED_SAMPLE_WIF),
                "WIF mismatch: got " + wif + ", expected " + EXPECTED_SAMPLE_WIF);
        require(fid.equals(EXPECTED_SAMPLE_FID),
                "FID mismatch: got " + fid + ", expected " + EXPECTED_SAMPLE_FID);

        JsonObject obj = new JsonObject();
        obj.addProperty("note", "Leaked test key — safe to publish. Canonical identity used throughout the test suite.");
        obj.addProperty("privkey_hex", SAMPLE_PRIVKEY_HEX);
        obj.addProperty("privkey_wif", wif);
        obj.addProperty("pubkey_hex", pubkeyHex);
        obj.addProperty("fid", fid);
        obj.addProperty("pubkey_hash160_hex", Hex.toHexString(hash160(key.getPubKey())));
        return obj;
    }

    private static JsonArray buildArgon2idVectors() {
        JsonArray arr = new JsonArray();
        arr.add(argon2id("ascii password, Freer params",
                "password", "01234567", 3, 65_536, 1, 32));
        arr.add(argon2id("utf-8 multi-byte password, Freer params",
                "秘密パスワード", "saltsaltsaltsalt", 3, 65_536, 1, 32));
        arr.add(argon2id("quick profile — matches the Swift Self.quick profile",
                "hunter2", "01234567", 1, 32, 1, 32));
        return arr;
    }

    private static JsonObject argon2id(String label,
                                        String passwordUtf8,
                                        String saltUtf8,
                                        int iterations,
                                        int memoryKiB,
                                        int parallelism,
                                        int outLen) {
        byte[] password = passwordUtf8.getBytes(StandardCharsets.UTF_8);
        byte[] salt = saltUtf8.getBytes(StandardCharsets.UTF_8);

        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(memoryKiB)
                .withParallelism(parallelism)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[outLen];
        gen.generateBytes(password, out);

        JsonObject o = new JsonObject();
        o.addProperty("label", label);
        o.addProperty("password_utf8", passwordUtf8);
        o.addProperty("password_hex", Hex.toHexString(password));
        o.addProperty("salt_utf8", saltUtf8);
        o.addProperty("salt_hex", Hex.toHexString(salt));
        o.addProperty("iterations", iterations);
        o.addProperty("memory_kib", memoryKiB);
        o.addProperty("parallelism", parallelism);
        o.addProperty("output_length", outLen);
        o.addProperty("output_hex", Hex.toHexString(out));
        return o;
    }

    private static JsonArray buildSha256Vectors() {
        JsonArray arr = new JsonArray();
        arr.add(shaCase("empty input", new byte[0]));
        arr.add(shaCase("ascii abc", "abc".getBytes(StandardCharsets.UTF_8)));
        arr.add(shaCase("brown fox",
                "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8)));
        arr.add(shaCase("64 zero bytes (SHA-256 block boundary)", new byte[64]));
        arr.add(shaCase("65 zero bytes (one past block)", new byte[65]));
        return arr;
    }

    private static JsonObject shaCase(String label, byte[] input) {
        JsonObject o = new JsonObject();
        o.addProperty("label", label);
        o.addProperty("input_hex", Hex.toHexString(input));
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] single = sha.digest(input);
            sha.reset();
            byte[] doubled = sha.digest(single);
            o.addProperty("sha256_hex", Hex.toHexString(single));
            o.addProperty("double_sha256_hex", Hex.toHexString(doubled));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return o;
    }

    private static JsonArray buildRipemd160Vectors() {
        JsonArray arr = new JsonArray();
        String[][] cases = {
                {"empty input", ""},
                {"ascii abc", "abc"},
                {"brown fox", "The quick brown fox jumps over the lazy dog"}
        };
        for (String[] pair : cases) {
            byte[] input = pair[1].getBytes(StandardCharsets.UTF_8);
            JsonObject o = new JsonObject();
            o.addProperty("label", pair[0]);
            o.addProperty("input_hex", Hex.toHexString(input));
            o.addProperty("output_hex", Hex.toHexString(ripemd160(input)));
            arr.add(o);
        }
        return arr;
    }

    private static JsonArray buildHash160Vectors() {
        JsonArray arr = new JsonArray();

        byte[] pubkey = Hex.decode(EXPECTED_SAMPLE_PUBKEY_HEX);
        JsonObject pubCase = new JsonObject();
        pubCase.addProperty("label", "sample pubkey → pubkey hash (feeds into FID derivation)");
        pubCase.addProperty("input_hex", Hex.toHexString(pubkey));
        pubCase.addProperty("output_hex", Hex.toHexString(hash160(pubkey)));
        arr.add(pubCase);

        String[][] extra = {
                {"empty input", ""},
                {"ascii abc", "abc"}
        };
        for (String[] pair : extra) {
            byte[] input = pair[1].getBytes(StandardCharsets.UTF_8);
            JsonObject o = new JsonObject();
            o.addProperty("label", pair[0]);
            o.addProperty("input_hex", Hex.toHexString(input));
            o.addProperty("output_hex", Hex.toHexString(hash160(input)));
            arr.add(o);
        }
        return arr;
    }

    private static JsonArray buildAesGcm256Vectors() {
        JsonArray arr = new JsonArray();
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] iv = Hex.decode("202122232425262728292a2b");

        arr.add(aeadCase("AES-256-GCM", "plaintext with empty AAD", key, iv,
                "Freer wallet encryption test".getBytes(StandardCharsets.UTF_8),
                new byte[0]));
        arr.add(aeadCase("AES-256-GCM", "plaintext + 8-byte AAD", key, iv,
                Hex.decode("0102030405060708090a0b0c0d0e0f00"),
                "metadata".getBytes(StandardCharsets.UTF_8)));
        arr.add(aeadCase("AES-256-GCM", "empty plaintext + 16-byte AAD (auth-only)", key, iv,
                new byte[0],
                Hex.decode("ffeeddccbbaa99887766554433221100")));
        arr.add(aeadCase("AES-256-GCM", "100-byte plaintext, empty AAD", key, iv,
                patternBytes(100, (byte) 0x5a),
                new byte[0]));
        return arr;
    }

    private static JsonArray buildChaCha20Poly1305Vectors() {
        JsonArray arr = new JsonArray();
        byte[] key = Hex.decode("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] nonce = Hex.decode("606162636465666768696a6b");

        arr.add(aeadCase("ChaCha20-Poly1305", "plaintext with empty AAD", key, nonce,
                "Freer wallet encryption test".getBytes(StandardCharsets.UTF_8),
                new byte[0]));
        arr.add(aeadCase("ChaCha20-Poly1305", "plaintext + 8-byte AAD", key, nonce,
                Hex.decode("0102030405060708090a0b0c0d0e0f00"),
                "metadata".getBytes(StandardCharsets.UTF_8)));
        arr.add(aeadCase("ChaCha20-Poly1305", "empty plaintext + 16-byte AAD (auth-only)", key, nonce,
                new byte[0],
                Hex.decode("ffeeddccbbaa99887766554433221100")));
        arr.add(aeadCase("ChaCha20-Poly1305", "100-byte plaintext, empty AAD", key, nonce,
                patternBytes(100, (byte) 0x5a),
                new byte[0]));
        return arr;
    }

    private static JsonObject aeadCase(String algorithm, String label,
                                        byte[] key, byte[] iv,
                                        byte[] plaintext, byte[] aad) {
        try {
            Cipher cipher;
            if ("AES-256-GCM".equals(algorithm)) {
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            } else if ("ChaCha20-Poly1305".equals(algorithm)) {
                cipher = Cipher.getInstance("ChaCha20-Poly1305");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(iv));
            } else {
                throw new IllegalArgumentException(algorithm);
            }
            if (aad.length > 0) {
                cipher.updateAAD(aad);
            }
            byte[] ctWithTag = cipher.doFinal(plaintext);
            int tagLen = 16;
            byte[] ct = new byte[ctWithTag.length - tagLen];
            byte[] tag = new byte[tagLen];
            System.arraycopy(ctWithTag, 0, ct, 0, ct.length);
            System.arraycopy(ctWithTag, ct.length, tag, 0, tagLen);

            JsonObject o = new JsonObject();
            o.addProperty("label", label);
            o.addProperty("key_hex", Hex.toHexString(key));
            o.addProperty("iv_hex", Hex.toHexString(iv));
            o.addProperty("plaintext_hex", Hex.toHexString(plaintext));
            o.addProperty("aad_hex", Hex.toHexString(aad));
            o.addProperty("ciphertext_hex", Hex.toHexString(ct));
            o.addProperty("tag_hex", Hex.toHexString(tag));
            return o;
        } catch (Exception e) {
            throw new RuntimeException("AEAD case '" + label + "' failed", e);
        }
    }

    private static JsonArray buildHkdfVectors(Digest digest) {
        JsonArray arr = new JsonArray();
        byte[] ikm = patternBytes(32, (byte) 0x11);
        byte[] salt = patternBytes(16, (byte) 0x22);

        arr.add(hkdfCase(digest, "32B ikm, 16B salt, 'hkdf' info, 32B output",
                ikm, salt, "hkdf".getBytes(StandardCharsets.UTF_8), 32));
        arr.add(hkdfCase(digest, "extended output (64B)",
                ikm, salt, "hkdf".getBytes(StandardCharsets.UTF_8), 64));
        arr.add(hkdfCase(digest, "context-specific info string",
                patternBytes(32, (byte) 0x33),
                patternBytes(16, (byte) 0x44),
                "fudp-session-key".getBytes(StandardCharsets.UTF_8),
                32));
        return arr;
    }

    private static JsonObject hkdfCase(Digest digest, String label,
                                        byte[] ikm, byte[] salt, byte[] info, int length) {
        HKDFBytesGenerator gen = new HKDFBytesGenerator(digest);
        gen.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[length];
        gen.generateBytes(out, 0, length);

        JsonObject o = new JsonObject();
        o.addProperty("label", label);
        o.addProperty("ikm_hex", Hex.toHexString(ikm));
        o.addProperty("salt_hex", Hex.toHexString(salt));
        o.addProperty("info_hex", Hex.toHexString(info));
        o.addProperty("output_length", length);
        o.addProperty("output_hex", Hex.toHexString(out));
        return o;
    }

    private static JsonArray buildEcdsaVectors() {
        ECKey key = ECKey.fromPrivate(Hex.decode(SAMPLE_PRIVKEY_HEX), true);
        JsonArray arr = new JsonArray();
        arr.add(ecdsaCase(key, "Hello, Freer!"));
        arr.add(ecdsaCase(key, ""));
        arr.add(ecdsaCase(key, "Test transaction payload #42"));
        return arr;
    }

    private static JsonObject ecdsaCase(ECKey key, String messageUtf8) {
        try {
            byte[] message = messageUtf8.getBytes(StandardCharsets.UTF_8);
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(message);
            ECKey.ECDSASignature sig = key.sign(Sha256Hash.wrap(hash));
            byte[] der = sig.encodeToDER();
            byte[] compact = new byte[64];
            System.arraycopy(toFixed32(sig.r), 0, compact, 0, 32);
            System.arraycopy(toFixed32(sig.s), 0, compact, 32, 32);

            JsonObject o = new JsonObject();
            o.addProperty("label", "sample key signs: \"" + messageUtf8 + "\"");
            o.addProperty("message_utf8", messageUtf8);
            o.addProperty("message_hex", Hex.toHexString(message));
            o.addProperty("message_hash_hex", Hex.toHexString(hash));
            o.addProperty("signature_der_hex", Hex.toHexString(der));
            o.addProperty("signature_compact_hex", Hex.toHexString(compact));
            o.addProperty("signature_r_hex", Hex.toHexString(toFixed32(sig.r)));
            o.addProperty("signature_s_hex", Hex.toHexString(toFixed32(sig.s)));
            o.addProperty("is_canonical_low_s", sig.isCanonical());
            return o;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static JsonArray buildEcdhVectors() {
        ECKey alice = ECKey.fromPrivate(Hex.decode(SAMPLE_PRIVKEY_HEX), true);

        // Deterministic counterparty key so the vectors are reproducible.
        // 0x42 x 32 is a valid scalar (well below the curve order).
        byte[] bobPrivBytes = patternBytes(32, (byte) 0x42);
        ECKey bob = ECKey.fromPrivate(bobPrivBytes, true);

        byte[] sharedAB = computeEcdh(Hex.decode(SAMPLE_PRIVKEY_HEX), bob.getPubKey());
        byte[] sharedBA = computeEcdh(bobPrivBytes, alice.getPubKey());
        require(java.util.Arrays.equals(sharedAB, sharedBA),
                "ECDH is not symmetric — aborting");

        JsonArray arr = new JsonArray();

        JsonObject o = new JsonObject();
        o.addProperty("label", "sample_key (alice) × counterparty (bob)");
        o.addProperty("alice_privkey_hex", SAMPLE_PRIVKEY_HEX);
        o.addProperty("alice_pubkey_hex", Hex.toHexString(alice.getPubKey()));
        o.addProperty("bob_privkey_hex", Hex.toHexString(bobPrivBytes));
        o.addProperty("bob_pubkey_hex", Hex.toHexString(bob.getPubKey()));
        o.addProperty("shared_x_hex", Hex.toHexString(sharedAB));
        arr.add(o);

        return arr;
    }

    private static byte[] computeEcdh(byte[] privkey, byte[] pubkeyCompressed) {
        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(
                new BigInteger(1, privkey), ECKey.CURVE);
        ECPublicKeyParameters pub = new ECPublicKeyParameters(
                ECKey.CURVE.getCurve().decodePoint(pubkeyCompressed), ECKey.CURVE);
        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.init(priv);
        BigInteger shared = agreement.calculateAgreement(pub);
        return toFixed32(shared);
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length == 32) return raw;
        if (raw.length == 33 && raw[0] == 0x00) {
            byte[] out = new byte[32];
            System.arraycopy(raw, 1, out, 0, 32);
            return out;
        }
        if (raw.length < 32) {
            byte[] out = new byte[32];
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
            return out;
        }
        throw new IllegalArgumentException(
                "BigInteger does not fit in 32 bytes: " + raw.length);
    }

    private static byte[] patternBytes(int length, byte value) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = value;
        }
        return out;
    }

    private static byte[] ripemd160(byte[] data) {
        RIPEMD160Digest d = new RIPEMD160Digest();
        d.update(data, 0, data.length);
        byte[] out = new byte[20];
        d.doFinal(out, 0);
        return out;
    }

    private static byte[] hash160(byte[] data) {
        try {
            byte[] sha = MessageDigest.getInstance("SHA-256").digest(data);
            return ripemd160(sha);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static void require(boolean cond, String msg) {
        if (!cond) {
            System.err.println("Vector consistency check FAILED: " + msg);
            System.exit(1);
        }
    }
}
