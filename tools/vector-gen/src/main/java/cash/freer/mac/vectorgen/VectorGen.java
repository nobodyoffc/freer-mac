package cash.freer.mac.vectorgen;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.VarInt;
import org.bitcoinj.fch.FchMainNetwork;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;

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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
        root.add("schnorr_bch", buildSchnorrBchVectors());
        root.add("base58", buildBase58Vectors());
        root.add("base58check", buildBase58CheckVectors());
        root.add("phrase_to_privkey", buildPhraseToPrivkeyVectors());
        root.add("varint", buildVarIntVectors());
        root.add("fch_address", buildFchAddressVectors());
        root.add("script", buildScriptVectors());
        root.add("transaction", buildTransactionVectors());
        root.add("bch_sighash", buildBchSighashVectors());

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

    private static JsonArray buildSchnorrBchVectors() {
        byte[] privkeyBytes = Hex.decode(SAMPLE_PRIVKEY_HEX);
        BigInteger seckey = new BigInteger(1, privkeyBytes);
        ECKey key = ECKey.fromPrivate(privkeyBytes, true);
        byte[] pubkey = key.getPubKey();

        JsonArray arr = new JsonArray();
        arr.add(schnorrCase(seckey, pubkey, "Hello, Freer!"));
        arr.add(schnorrCase(seckey, pubkey, ""));
        arr.add(schnorrCase(seckey, pubkey, "Test transaction payload #42"));
        return arr;
    }

    private static JsonObject schnorrCase(BigInteger seckey, byte[] pubkey, String messageUtf8) {
        try {
            byte[] message = messageUtf8.getBytes(StandardCharsets.UTF_8);
            byte[] msgHash = MessageDigest.getInstance("SHA-256").digest(message);
            byte[] sig = BchSchnorr.sign(msgHash, seckey);
            if (!BchSchnorr.verify(msgHash, pubkey, sig)) {
                throw new IllegalStateException("Self-verify failed — generator bug");
            }

            JsonObject o = new JsonObject();
            o.addProperty("label", "sample key schnorr-signs: \"" + messageUtf8 + "\"");
            o.addProperty("message_utf8", messageUtf8);
            o.addProperty("message_hex", Hex.toHexString(message));
            o.addProperty("message_hash_hex", Hex.toHexString(msgHash));
            o.addProperty("signature_hex", Hex.toHexString(sig));
            return o;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
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

    private static JsonArray buildBase58Vectors() {
        JsonArray arr = new JsonArray();
        arr.add(b58Case("empty", new byte[0]));
        arr.add(b58Case("single zero byte", new byte[]{0x00}));
        arr.add(b58Case("two leading zeros preserved", new byte[]{0x00, 0x00, 0x01, 0x02, 0x03}));
        arr.add(b58Case("ascii string payload",
                "The quick brown fox".getBytes(StandardCharsets.UTF_8)));
        arr.add(b58Case("sample privkey bytes (no checksum)",
                Hex.decode(SAMPLE_PRIVKEY_HEX)));
        return arr;
    }

    private static JsonObject b58Case(String label, byte[] input) {
        String encoded = Base58.encode(input);
        byte[] roundTrip;
        try {
            roundTrip = Base58.decode(encoded);
        } catch (Exception e) {
            throw new RuntimeException("Base58 round-trip failed: " + label, e);
        }
        require(java.util.Arrays.equals(input, roundTrip),
                "Base58 round-trip mismatch for '" + label + "'");

        JsonObject o = new JsonObject();
        o.addProperty("label", label);
        o.addProperty("input_hex", Hex.toHexString(input));
        o.addProperty("encoded", encoded);
        return o;
    }

    private static JsonArray buildBase58CheckVectors() {
        JsonArray arr = new JsonArray();

        // WIF: payload = 0x80 (mainnet) || privkey(32) || 0x01 (compressed flag)
        byte[] wifPayload;
        try {
            wifPayload = Base58.decodeChecked(EXPECTED_SAMPLE_WIF);
        } catch (Exception e) {
            throw new RuntimeException("failed to decode sample WIF", e);
        }
        arr.add(b58CheckCase("sample key WIF (0x80 || privkey || 0x01)",
                wifPayload, EXPECTED_SAMPLE_WIF));

        // FID: payload = version_byte || hash160(20)
        byte[] fidPayload;
        try {
            fidPayload = Base58.decodeChecked(EXPECTED_SAMPLE_FID);
        } catch (Exception e) {
            throw new RuntimeException("failed to decode sample FID", e);
        }
        arr.add(b58CheckCase("sample FID (FCH version || pubkeyhash)",
                fidPayload, EXPECTED_SAMPLE_FID));

        arr.add(b58CheckCase("all-zero 5-byte payload",
                new byte[]{0x00, 0x00, 0x00, 0x00, 0x00}, null));
        arr.add(b58CheckCase("arbitrary 8-byte payload",
                Hex.decode("deadbeef12345678"), null));

        return arr;
    }

    private static JsonObject b58CheckCase(String label, byte[] payload, String expectedEncoded) {
        String encoded = base58CheckEncode(payload);
        if (expectedEncoded != null) {
            require(encoded.equals(expectedEncoded),
                    "Base58Check encode mismatch for '" + label + "': got " + encoded + ", expected " + expectedEncoded);
        }
        byte[] decoded;
        try {
            decoded = Base58.decodeChecked(encoded);
        } catch (Exception e) {
            throw new RuntimeException("Base58Check round-trip decode failed: " + label, e);
        }
        require(java.util.Arrays.equals(decoded, payload),
                "Base58Check round-trip payload mismatch for '" + label + "'");

        JsonObject o = new JsonObject();
        o.addProperty("label", label);
        o.addProperty("payload_hex", Hex.toHexString(payload));
        o.addProperty("encoded", encoded);
        return o;
    }

    private static String base58CheckEncode(byte[] payload) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] checksum = md.digest(md.digest(payload));
            byte[] out = new byte[payload.length + 4];
            System.arraycopy(payload, 0, out, 0, payload.length);
            System.arraycopy(checksum, 0, out, payload.length, 4);
            return Base58.encode(out);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Protocol-constant salt for the argon2id phrase → privkey derivation.
     * A fixed salt is required so the same phrase always yields the same key
     * (this is a deterministic-recovery scheme, not password storage). The
     * Mac and Android sides must agree on this string byte-for-byte.
     */
    private static final String PHRASE_ARGON2ID_SALT = "fc.freer.phrase.v1";

    private static JsonArray buildPhraseToPrivkeyVectors() {
        JsonArray arr = new JsonArray();
        arr.add(phraseCase("correct horse battery staple"));
        arr.add(phraseCase("my freer wallet phrase 2026 🔐"));
        arr.add(phraseCase("short"));
        return arr;
    }

    private static JsonObject phraseCase(String phrase) {
        byte[] phraseBytes = phrase.getBytes(StandardCharsets.UTF_8);

        // Legacy: plain SHA-256 of the phrase bytes. Matches current Android.
        byte[] legacyPrivkey;
        try {
            legacyPrivkey = MessageDigest.getInstance("SHA-256").digest(phraseBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // Argon2id with Freer params and the fixed protocol salt.
        byte[] salt = PHRASE_ARGON2ID_SALT.getBytes(StandardCharsets.UTF_8);
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(3)
                .withMemoryAsKB(65_536)
                .withParallelism(1)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] argonPrivkey = new byte[32];
        gen.generateBytes(phraseBytes, argonPrivkey);

        ECKey legacyKey = ECKey.fromPrivate(legacyPrivkey, true);
        ECKey argonKey = ECKey.fromPrivate(argonPrivkey, true);

        JsonObject o = new JsonObject();
        o.addProperty("phrase_utf8", phrase);
        o.addProperty("phrase_hex", Hex.toHexString(phraseBytes));

        JsonObject legacy = new JsonObject();
        legacy.addProperty("scheme", "legacy_sha256");
        legacy.addProperty("privkey_hex", Hex.toHexString(legacyPrivkey));
        legacy.addProperty("pubkey_hex", Hex.toHexString(legacyKey.getPubKey()));
        o.add("legacy", legacy);

        JsonObject argon = new JsonObject();
        argon.addProperty("scheme", "argon2id");
        argon.addProperty("salt_utf8", PHRASE_ARGON2ID_SALT);
        argon.addProperty("salt_hex", Hex.toHexString(salt));
        argon.addProperty("argon2id_iterations", 3);
        argon.addProperty("argon2id_memory_kib", 65_536);
        argon.addProperty("argon2id_parallelism", 1);
        argon.addProperty("privkey_hex", Hex.toHexString(argonPrivkey));
        argon.addProperty("pubkey_hex", Hex.toHexString(argonKey.getPubKey()));
        o.add("argon2id", argon);

        return o;
    }

    private static JsonArray buildVarIntVectors() {
        JsonArray arr = new JsonArray();
        // Boundary values where the VarInt prefix byte changes.
        long[] values = {
                0L,
                1L,
                0xFCL,                  // last 1-byte form
                0xFDL,                  // first 0xFD-prefixed form
                0xFFFFL,                // last 0xFD-prefixed form
                0x10000L,               // first 0xFE-prefixed form
                0xFFFFFFFFL,            // last 0xFE-prefixed form
                0x100000000L,           // first 0xFF-prefixed form
                0x0123456789ABCDEFL     // arbitrary 64-bit value
        };
        for (long v : values) {
            byte[] encoded = new VarInt(v).encode();
            JsonObject o = new JsonObject();
            o.addProperty("value", v);
            o.addProperty("encoded_hex", Hex.toHexString(encoded));
            arr.add(o);
        }
        return arr;
    }

    private static JsonArray buildFchAddressVectors() {
        JsonArray arr = new JsonArray();

        byte[] samplePrivkey = Hex.decode(SAMPLE_PRIVKEY_HEX);
        ECKey sampleKey = ECKey.fromPrivate(samplePrivkey, true);
        arr.add(addrCase("sample key", sampleKey.getPubKey()));

        // Two more deterministic keys so we're not relying on a single identity.
        ECKey k2 = ECKey.fromPrivate(patternBytes(32, (byte) 0x11), true);
        arr.add(addrCase("deterministic 0x11 key", k2.getPubKey()));

        ECKey k3 = ECKey.fromPrivate(patternBytes(32, (byte) 0x42), true);
        arr.add(addrCase("counterparty (0x42) key", k3.getPubKey()));

        return arr;
    }

    private static JsonArray buildScriptVectors() {
        JsonArray arr = new JsonArray();
        NetworkParameters params = FchMainNetwork.MAINNETWORK;

        // 1) P2PKH output for the sample key's address.
        ECKey sampleKey = ECKey.fromPrivate(Hex.decode(SAMPLE_PRIVKEY_HEX), true);
        Address sampleAddr = Address.fromKey(params, sampleKey);
        Script p2pkh = ScriptBuilder.createOutputScript(sampleAddr);
        JsonObject p2pkhObj = scriptBase("sample key P2PKH output", "p2pkh", p2pkh.getProgram());
        p2pkhObj.addProperty("hash160_hex", Hex.toHexString(hash160(sampleKey.getPubKey())));
        arr.add(p2pkhObj);

        // 2) P2SH output with a deterministic script hash.
        byte[] redeemHash = patternBytes(20, (byte) 0x7e);
        Script p2sh = ScriptBuilder.createP2SHOutputScript(redeemHash);
        JsonObject p2shObj = scriptBase("P2SH output (script hash = 0x7e * 20)", "p2sh", p2sh.getProgram());
        p2shObj.addProperty("script_hash_hex", Hex.toHexString(redeemHash));
        arr.add(p2shObj);

        // 3) 2-of-3 multisig output.
        ECKey k1 = ECKey.fromPrivate(patternBytes(32, (byte) 0x11), true);
        ECKey k2 = ECKey.fromPrivate(patternBytes(32, (byte) 0x22), true);
        ECKey k3 = ECKey.fromPrivate(patternBytes(32, (byte) 0x33), true);
        java.util.List<ECKey> keyList = java.util.Arrays.asList(k1, k2, k3);
        Script multisig = ScriptBuilder.createMultiSigOutputScript(2, keyList);
        JsonObject msObj = scriptBase("2-of-3 multisig output", "multisig", multisig.getProgram());
        msObj.addProperty("required", 2);
        JsonArray pubs = new JsonArray();
        for (ECKey k : keyList) pubs.add(Hex.toHexString(k.getPubKey()));
        msObj.add("pubkeys_hex", pubs);
        arr.add(msObj);

        // 4) P2PKH input scriptSig (sig+hashType push, then pubkey push).
        // Uses a real ECDSA sig from an earlier vector just so bytes are
        // realistic-looking; the Script layer only cares about length/push
        // encoding, not sig validity.
        byte[] fakeDerSig = Hex.decode("3044022058f2d82305446e042ef880510f45604f2f5f327dca37984876e3a4049301fb1c02203e2477ecfb9981a8ff5a0c62634bdd9131ed629b310c49c6edef5b9e94956538");
        byte sighashFlag = (byte) 0x41;  // SIGHASH_ALL | SIGHASH_FORKID
        byte[] sigPlusFlag = new byte[fakeDerSig.length + 1];
        System.arraycopy(fakeDerSig, 0, sigPlusFlag, 0, fakeDerSig.length);
        sigPlusFlag[fakeDerSig.length] = sighashFlag;
        Script inputScript = new ScriptBuilder()
                .data(sigPlusFlag)
                .data(sampleKey.getPubKey())
                .build();
        JsonObject inObj = scriptBase("sample key P2PKH scriptSig (ALL|FORKID)",
                "p2pkh_input", inputScript.getProgram());
        inObj.addProperty("der_sig_hex", Hex.toHexString(fakeDerSig));
        inObj.addProperty("sighash_flag", sighashFlag & 0xff);
        inObj.addProperty("pubkey_hex", Hex.toHexString(sampleKey.getPubKey()));
        arr.add(inObj);

        return arr;
    }

    private static JsonArray buildTransactionVectors() {
        JsonArray arr = new JsonArray();
        NetworkParameters params = FchMainNetwork.MAINNETWORK;

        ECKey sampleKey = ECKey.fromPrivate(Hex.decode(SAMPLE_PRIVKEY_HEX), true);
        ECKey recipientKey = ECKey.fromPrivate(patternBytes(32, (byte) 0x42), true);
        Address sampleAddr = Address.fromKey(params, sampleKey);
        Address recipientAddr = Address.fromKey(params, recipientKey);

        // Previous UTXO. Natural-order prev hash = 32 bytes of 0x7a.
        byte[] prevHashBytes = patternBytes(32, (byte) 0x7a);
        Sha256Hash prevHash = Sha256Hash.wrap(prevHashBytes);
        long prevIndex = 0L;
        long prevValueSats = 100_000L;
        long sendSats = 80_000L;
        long changeSats = 15_000L;  // implicit 5 000-sat fee

        Transaction tx = new Transaction(params);
        tx.setVersion(2);

        TransactionOutPoint outpoint = new TransactionOutPoint(params, prevIndex, prevHash);
        TransactionInput in = new TransactionInput(params, tx, new byte[0], outpoint, Coin.valueOf(prevValueSats));
        in.setSequenceNumber(0xFFFFFFFFL);
        tx.addInput(in);

        tx.addOutput(Coin.valueOf(sendSats), ScriptBuilder.createOutputScript(recipientAddr));
        tx.addOutput(Coin.valueOf(changeSats), ScriptBuilder.createOutputScript(sampleAddr));

        byte[] serialized = tx.bitcoinSerialize();
        byte[] txidNatural = doubleSha256(serialized);
        byte[] txidDisplay = reverseBytes(txidNatural);

        JsonObject o = new JsonObject();
        o.addProperty("label", "unsigned 1-in 2-out P2PKH tx");
        o.addProperty("version", 2);
        o.addProperty("locktime", 0);

        JsonArray inputs = new JsonArray();
        JsonObject inputObj = new JsonObject();
        inputObj.addProperty("prev_tx_hash_hex", Hex.toHexString(prevHashBytes));
        inputObj.addProperty("prev_output_index", prevIndex);
        inputObj.addProperty("script_sig_hex", "");
        inputObj.addProperty("sequence", 0xFFFFFFFFL);
        inputObj.addProperty("prev_value_sats", prevValueSats);
        inputObj.addProperty("spent_script_pubkey_hex",
                Hex.toHexString(ScriptBuilder.createOutputScript(sampleAddr).getProgram()));
        inputs.add(inputObj);
        o.add("inputs", inputs);

        JsonArray outputs = new JsonArray();
        outputs.add(outputObj(sendSats, recipientAddr));
        outputs.add(outputObj(changeSats, sampleAddr));
        o.add("outputs", outputs);

        o.addProperty("serialized_hex", Hex.toHexString(serialized));
        o.addProperty("txid_natural_hex", Hex.toHexString(txidNatural));
        o.addProperty("txid_display_hex", Hex.toHexString(txidDisplay));
        arr.add(o);

        return arr;
    }

    private static JsonArray buildBchSighashVectors() {
        JsonArray arr = new JsonArray();
        NetworkParameters params = FchMainNetwork.MAINNETWORK;

        // Reuse the exact tx shape buildTransactionVectors() produces so
        // the Swift side can re-build it from the earlier 'transaction'
        // vector and verify sighash against this section.
        ECKey sampleKey = ECKey.fromPrivate(Hex.decode(SAMPLE_PRIVKEY_HEX), true);
        ECKey recipientKey = ECKey.fromPrivate(patternBytes(32, (byte) 0x42), true);
        Address sampleAddr = Address.fromKey(params, sampleKey);
        Address recipientAddr = Address.fromKey(params, recipientKey);

        byte[] prevHashBytes = patternBytes(32, (byte) 0x7a);
        long prevIndex = 0L;
        long prevValueSats = 100_000L;

        Transaction tx = new Transaction(params);
        tx.setVersion(2);
        TransactionOutPoint outpoint = new TransactionOutPoint(params, prevIndex, Sha256Hash.wrap(prevHashBytes));
        TransactionInput in = new TransactionInput(params, tx, new byte[0], outpoint, Coin.valueOf(prevValueSats));
        in.setSequenceNumber(0xFFFFFFFFL);
        tx.addInput(in);
        tx.addOutput(Coin.valueOf(80_000L), ScriptBuilder.createOutputScript(recipientAddr));
        tx.addOutput(Coin.valueOf(15_000L), ScriptBuilder.createOutputScript(sampleAddr));

        byte[] scriptCode = ScriptBuilder.createOutputScript(sampleAddr).getProgram();
        int hashType = 0x41;  // SIGHASH_ALL | SIGHASH_FORKID
        byte[] preimage = buildBchPreimage(tx, 0, scriptCode, prevValueSats, hashType);
        byte[] sighash = doubleSha256(preimage);

        // Cross-check against bitcoinj's built-in method (freecashj is BCH-aware,
        // so hashForSignatureWitness already applies FORKID).
        try {
            Sha256Hash bjSighash = tx.hashForSignatureWitness(
                    0,
                    scriptCode,
                    Coin.valueOf(prevValueSats),
                    Transaction.SigHash.ALL,
                    false
            );
            require(java.util.Arrays.equals(sighash, bjSighash.getBytes()),
                    "manual BCH preimage sighash does not match freecashj's: "
                            + Hex.toHexString(sighash) + " vs " + bjSighash);
        } catch (NoSuchMethodError e) {
            // Method signature differs on this bitcoinj build — skip the
            // cross-check. Manual preimage is still the spec authority.
            System.err.println("[warn] hashForSignatureWitness not found; skipping freecashj cross-check");
        }

        JsonObject o = new JsonObject();
        o.addProperty("label", "BCH BIP-143 + FORKID sighash for input 0, ALL|FORKID (0x41)");
        o.addProperty("input_index", 0);
        o.addProperty("script_code_hex", Hex.toHexString(scriptCode));
        o.addProperty("prev_value_sats", prevValueSats);
        o.addProperty("hash_type", hashType);
        o.addProperty("preimage_hex", Hex.toHexString(preimage));
        o.addProperty("sighash_hex", Hex.toHexString(sighash));
        arr.add(o);

        return arr;
    }

    private static byte[] buildBchPreimage(Transaction tx, int inputIndex, byte[] scriptCode, long prevValueSats, int hashType) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // 1. version (4 bytes LE)
            writeUInt32LE(out, tx.getVersion());

            // 2. hashPrevouts = double-sha256 of concat(outpoint serializations)
            ByteArrayOutputStream po = new ByteArrayOutputStream();
            for (TransactionInput input : tx.getInputs()) {
                po.write(input.getOutpoint().bitcoinSerialize());
            }
            out.write(doubleSha256(po.toByteArray()));

            // 3. hashSequence = double-sha256 of concat(sequence LE)
            ByteArrayOutputStream so = new ByteArrayOutputStream();
            for (TransactionInput input : tx.getInputs()) {
                writeUInt32LE(so, input.getSequenceNumber());
            }
            out.write(doubleSha256(so.toByteArray()));

            // 4. outpoint being signed (32+4)
            out.write(tx.getInput(inputIndex).getOutpoint().bitcoinSerialize());

            // 5. scriptCode (varInt || bytes)
            out.write(new VarInt(scriptCode.length).encode());
            out.write(scriptCode);

            // 6. prev value (8 bytes LE)
            writeUInt64LE(out, prevValueSats);

            // 7. nSequence of input being signed (4 bytes LE)
            writeUInt32LE(out, tx.getInput(inputIndex).getSequenceNumber());

            // 8. hashOutputs = double-sha256 of concat(serialized outputs)
            ByteArrayOutputStream oo = new ByteArrayOutputStream();
            for (TransactionOutput output : tx.getOutputs()) {
                oo.write(output.bitcoinSerialize());
            }
            out.write(doubleSha256(oo.toByteArray()));

            // 9. locktime (4 bytes LE)
            writeUInt32LE(out, tx.getLockTime());

            // 10. hashType (4 bytes LE)
            writeUInt32LE(out, hashType & 0xFFFFFFFFL);

            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void writeUInt32LE(ByteArrayOutputStream out, long value) {
        out.write((int) (value & 0xFF));
        out.write((int) ((value >> 8) & 0xFF));
        out.write((int) ((value >> 16) & 0xFF));
        out.write((int) ((value >> 24) & 0xFF));
    }

    private static void writeUInt64LE(ByteArrayOutputStream out, long value) {
        for (int i = 0; i < 8; i++) {
            out.write((int) ((value >> (8 * i)) & 0xFF));
        }
    }

    private static JsonObject outputObj(long valueSats, Address address) {
        JsonObject o = new JsonObject();
        o.addProperty("value_sats", valueSats);
        o.addProperty("script_pubkey_hex",
                Hex.toHexString(ScriptBuilder.createOutputScript(address).getProgram()));
        o.addProperty("address", address.toString());
        return o;
    }

    private static byte[] doubleSha256(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(md.digest(input));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] reverseBytes(byte[] input) {
        byte[] out = new byte[input.length];
        for (int i = 0; i < input.length; i++) out[i] = input[input.length - 1 - i];
        return out;
    }

    private static JsonObject scriptBase(String label, String kind, byte[] programBytes) {
        JsonObject o = new JsonObject();
        o.addProperty("label", label);
        o.addProperty("kind", kind);
        o.addProperty("program_hex", Hex.toHexString(programBytes));
        return o;
    }

    private static JsonObject addrCase(String label, byte[] pubkeyCompressed) {
        byte[] h160 = hash160(pubkeyCompressed);
        byte[] payload = new byte[21];
        payload[0] = 0x23;  // FCH mainnet P2PKH version byte
        System.arraycopy(h160, 0, payload, 1, 20);
        String fid = base58CheckEncode(payload);

        JsonObject o = new JsonObject();
        o.addProperty("label", label);
        o.addProperty("pubkey_hex", Hex.toHexString(pubkeyCompressed));
        o.addProperty("pubkey_hash160_hex", Hex.toHexString(h160));
        o.addProperty("version_byte", 0x23);
        o.addProperty("fid", fid);
        return o;
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
