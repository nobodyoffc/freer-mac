package cash.freer.mac.vectorgen;

import com.fc.fc_ajdk.data.fcData.Hat;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.Arrays;
import java.util.List;

/**
 * Emits golden vectors for the {@code Hat} wire format, produced by the
 * REAL FC-AJDK {@code Hat} class — the same one the Android app puts in
 * IM file messages and HAT export files. The Swift port must decode
 * these and re-encode them byte-identically, or a HAT shared between
 * the two apps would change shape (and, for id-less HATs, change DID).
 *
 * Three behaviours these vectors pin down:
 *
 * <ol>
 *   <li><b>Field order and casing.</b> Gson emits declaring-class fields
 *       first, then superclass fields, so Hat's own fields come before
 *       {@code objName} (FcObject) and {@code id} (FcEntity). The names
 *       keep Java's field spelling: {@code hAlg}, {@code tDid},
 *       {@code tSize}, {@code kCipher}, and {@code Leaked} with a
 *       capital L.</li>
 *   <li><b>Null omission.</b> Both writers drop null fields, so a
 *       minimal HAT is a two-key object.</li>
 *   <li><b>The escaping split.</b> {@code toJson()} uses
 *       {@code disableHtmlEscaping()}, but {@code toBytes()} — whose
 *       output {@code checkIdWithCreate()} hashes into the DID — uses a
 *       plain {@code new Gson()}, which escapes {@code < > & = '} as
 *       \\uXXXX. A name containing any of those hashes differently than
 *       its stored JSON suggests, so the id vectors below exist to keep
 *       the Swift derivation honest.</li>
 * </ol>
 */
final class HatRef {

    private HatRef() {}

    static JsonArray generate() {
        JsonArray out = new JsonArray();
        out.add(vector("minimal", minimal()));
        out.add(vector("full", full()));
        out.add(vector("cipher-hat", cipherHat()));
        out.add(vector("html-escapable-name", escapableName()));
        out.add(vector("unicode-name", unicodeName()));
        out.add(vector("empty-lists", emptyLists()));
        for (Hat.DataState state : Hat.DataState.values()) {
            Hat h = new Hat();
            h.setId("state-" + state.name().toLowerCase());
            h.setState(state);
            out.add(vector("state-" + state.name(), h));
        }
        return out;
    }

    /**
     * One vector: the JSON Android would store/transmit, plus the DID a
     * Hat with no id would receive from {@code checkIdWithCreate()}.
     */
    private static JsonObject vector(String label, Hat hat) {
        JsonObject v = new JsonObject();
        v.addProperty("label", label);
        v.addProperty("json", hat.toJson());
        v.addProperty("id_bytes_json", new String(hat.toBytes(), java.nio.charset.StandardCharsets.UTF_8));

        // Derive the id the way HatManager does for an imported id-less
        // HAT: strip the id, then checkIdWithCreate() over what remains.
        Hat idless = Hat.fromJson(hat.toJson(), Hat.class);
        idless.setId(null);
        idless.checkIdWithCreate();
        v.addProperty("derived_id_without_id_field", idless.getId());
        v.addProperty("derived_id_source_json",
                new String(sourceBytesFor(hat), java.nio.charset.StandardCharsets.UTF_8));
        return v;
    }

    /** The exact bytes checkIdWithCreate() hashes (the object minus its id). */
    private static byte[] sourceBytesFor(Hat hat) {
        Hat idless = Hat.fromJson(hat.toJson(), Hat.class);
        idless.setId(null);
        return idless.toBytes();
    }

    private static Hat minimal() {
        Hat h = new Hat();
        h.setId("aa11");
        h.setName("readme.txt");
        return h;
    }

    private static Hat full() {
        Hat h = new Hat();
        h.sethAlg("sha256x2");
        h.setSize(1234L);
        h.setBorn(1700000000000L);
        h.setLast(1700000009999L);
        h.setName("photo.jpg");
        h.setDesc("a photo of the sea");
        h.setTypes(Arrays.asList("image/jpeg", "image"));
        h.setAids(Arrays.asList("app-1", "app-2"));
        h.setPids(Arrays.asList("pid-1"));
        h.setSrcDid("5c1d0000000000000000000000000000000000000000000000000000000000src");
        h.setPreDid("5c1d0000000000000000000000000000000000000000000000000000000000pre");
        h.settDid("5c1d00000000000000000000000000000000000000000000000000000000tdid");
        h.settSize(999999L);
        h.setOffset(4096L);
        h.setKey("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        h.setLeaked(false);
        h.setCipherIds(Arrays.asList("c1c1", "c2c2"));
        h.setRank(3);
        h.setState(Hat.DataState.ACTIVE);
        h.setLocas(Arrays.asList("local:///Users/x/Pictures/photo.jpg", "(sid)abc123", "fudp://1.2.3.4:9000"));
        h.setObjName("Hat");
        h.setId("0f3c000000000000000000000000000000000000000000000000000000000id0");
        return h;
    }

    /** The other half of the two-HAT model: rawDid + kCipher set. */
    private static Hat cipherHat() {
        Hat h = new Hat();
        h.setId("c1phe000000000000000000000000000000000000000000000000000000000r0");
        h.setRawDid("0f3c000000000000000000000000000000000000000000000000000000000id0");
        h.setkCipher("{\"type\":\"AsyOneWay\",\"alg\":\"EccK1AesGcm256@No1_NrC7\",\"cipher\":\"YWJj\"}");
        h.setSize(4096L);
        h.setBorn(1700000000000L);
        h.setLast(1700000000000L);
        h.setState(Hat.DataState.ACTIVE);
        h.setLocas(Arrays.asList("(sid)disk-service-1"));
        return h;
    }

    /**
     * Name with every character Gson's HTML-safe writer escapes. Proves
     * the toJson/toBytes split: the stored JSON keeps them literal while
     * the DID is computed over the escaped form.
     */
    private static Hat escapableName() {
        Hat h = new Hat();
        h.setId("e5ca9e00000000000000000000000000000000000000000000000000000000d0");
        h.setName("a&b<c>d='e'.txt");
        h.setDesc("x=1 & y<2 > z 'q'");
        h.setSize(7L);
        return h;
    }

    private static Hat unicodeName() {
        Hat h = new Hat();
        h.setId("un1c0de0000000000000000000000000000000000000000000000000000000d0");
        h.setName("自由现金 · 文件 🚀.pdf");
        h.setDesc("多字节描述");
        h.setTypes(Arrays.asList("application/pdf"));
        h.setSize(2048L);
        return h;
    }

    /** Empty lists must survive the round trip as [] rather than becoming null. */
    private static Hat emptyLists() {
        Hat h = new Hat();
        h.setId("e0000000000000000000000000000000000000000000000000000000000000d0");
        h.setTypes(List.of());
        h.setAids(List.of());
        h.setCipherIds(List.of());
        h.setLocas(List.of());
        return h;
    }
}
