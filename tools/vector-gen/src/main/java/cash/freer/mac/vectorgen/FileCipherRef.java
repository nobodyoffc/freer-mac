package cash.freer.mac.vectorgen;

import com.fc.fc_ajdk.core.crypto.CryptoDataByte;
import com.fc.fc_ajdk.core.crypto.Decryptor;
import com.fc.fc_ajdk.core.crypto.Encryptor;
import com.fc.fc_ajdk.data.fcData.AlgorithmId;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Emits golden vectors for the FAPI DISK cipher-file format, produced by
 * the REAL FC-AJDK {@code Encryptor}/{@code Decryptor} — the same classes
 * the Android app runs. Nothing here re-implements the format, so the
 * Swift {@code FileCipher} is checked against the actual wire producer
 * rather than against a second guess at it.
 *
 * File layout (verified against {@code Encryptor.encryptFileBySymkey}):
 * <pre>
 *   UTF-8 JSON header, Gson field order, nulls omitted:
 *     {"type":"Symkey","alg":"AesGcm256@No1_NrC7","iv":"&lt;24 hex&gt;"}
 *   immediately followed by:
 *     AES-256-GCM ciphertext || 16-byte tag   (one GCM pass over the file)
 * </pre>
 *
 * The header is delimited by brace COUNTING on read
 * ({@code JsonUtils.readOneJsonFromInputStream}), not by a length prefix,
 * so the reader is not JSON-string-aware. Header values are hex/enum
 * text and never contain braces, which is what makes that safe.
 */
final class FileCipherRef {

    private FileCipherRef() {}

    /** One vector: inputs plus the exact bytes FC-AJDK produced. */
    private record Case(String label, String symkeyHex, String ivHex, byte[] plaintext) {}

    static JsonArray generate() throws Exception {
        Case[] cases = new Case[] {
            new Case("empty",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "a0a1a2a3a4a5a6a7a8a9aaab",
                new byte[0]),
            new Case("short-ascii",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "a0a1a2a3a4a5a6a7a8a9aaab",
                "hello freer".getBytes("UTF-8")),
            new Case("utf8-multibyte",
                "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c",
                "0f0e0d0c0b0a09080706050403".substring(0, 24),
                "自由现金 · freer 🚀".getBytes("UTF-8")),
            new Case("block-aligned-64",
                "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
                "0123456789abcdef01234567",
                repeat((byte) 0x5a, 64)),
            new Case("large-5000",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "222222222222222222222222",
                counting(5000)),
        };

        JsonArray out = new JsonArray();
        Path dir = Files.createTempDirectory("fc-filecipher-vectors");
        for (Case c : cases) {
            byte[] key = hexToBytes(c.symkeyHex());
            byte[] iv = hexToBytes(c.ivHex());

            Path plainFile = dir.resolve(c.label() + ".plain");
            Path cipherFile = dir.resolve(c.label() + ".cipher");
            Files.write(plainFile, c.plaintext());

            Encryptor encryptor = new Encryptor(AlgorithmId.FC_AesGcm256_No1_NrC7);
            CryptoDataByte encResult = encryptor.encryptFileBySymkey(
                    plainFile.toString(), cipherFile.toString(), key, iv);
            if (encResult.getCode() != null && encResult.getCode() != 0) {
                throw new IllegalStateException(
                        "FC-AJDK encrypt failed for '" + c.label() + "': " + encResult.getMessage());
            }
            byte[] cipherFileBytes = Files.readAllBytes(cipherFile);

            // Round-trip through FC-AJDK's own decryptor: proves the vector
            // is self-consistent before Swift ever sees it.
            Path roundTrip = dir.resolve(c.label() + ".roundtrip");
            CryptoDataByte decResult = new Decryptor().decryptFileBySymkey(
                    cipherFile.toString(), roundTrip.toString(), key);
            if (decResult.getCode() != null && decResult.getCode() != 0) {
                throw new IllegalStateException(
                        "FC-AJDK decrypt failed for '" + c.label() + "': " + decResult.getMessage());
            }
            if (!java.util.Arrays.equals(Files.readAllBytes(roundTrip), c.plaintext())) {
                throw new IllegalStateException("FC-AJDK round-trip mismatch for '" + c.label() + "'");
            }

            // Split point: where the brace-counted JSON header ends.
            int headerLen = headerLength(cipherFileBytes);

            JsonObject v = new JsonObject();
            v.addProperty("label", c.label());
            v.addProperty("symkey_hex", c.symkeyHex());
            v.addProperty("iv_hex", c.ivHex());
            v.addProperty("plaintext_hex", bytesToHex(c.plaintext()));
            v.addProperty("cipher_file_hex", bytesToHex(cipherFileBytes));
            v.addProperty("header_json", new String(cipherFileBytes, 0, headerLen, "UTF-8"));
            v.addProperty("header_length", headerLen);
            v.addProperty("body_hex", bytesToHex(
                    java.util.Arrays.copyOfRange(cipherFileBytes, headerLen, cipherFileBytes.length)));
            out.add(v);
        }
        return out;
    }

    /**
     * Mirrors {@code JsonUtils.readOneJsonFromInputStream}: count braces,
     * stop when the depth returns to zero. Deliberately NOT string-aware,
     * because the reader on the other side isn't either — matching its
     * behaviour is what keeps the ciphertext offset identical.
     */
    private static int headerLength(byte[] fileBytes) {
        int depth = 0;
        boolean counting = false;
        for (int i = 0; i < fileBytes.length; i++) {
            char ch = (char) (fileBytes[i] & 0xff);
            if (ch == '\\') continue;
            if (ch == '{') {
                counting = true;
                depth++;
            } else if (ch == '}' && counting) {
                depth--;
            }
            if (counting && depth == 0) return i + 1;
        }
        throw new IllegalStateException("no complete JSON header found in cipher file");
    }

    private static byte[] repeat(byte b, int n) {
        byte[] out = new byte[n];
        java.util.Arrays.fill(out, b);
        return out;
    }

    private static byte[] counting(int n) {
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) out[i] = (byte) (i % 251);
        return out;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
