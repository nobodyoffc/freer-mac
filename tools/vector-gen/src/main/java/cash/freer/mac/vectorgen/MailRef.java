package cash.freer.mac.vectorgen;

import com.fc.fc_ajdk.data.feipData.Mail;
import com.fc.fc_ajdk.utils.JsonUtils;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;

/**
 * Golden vectors for the {@code Mail} wire format, produced by the REAL
 * FC-AJDK {@code Mail} class.
 *
 * <p>Two things need pinning, and both are Gson behaviours rather than
 * anything a schema would tell you:
 *
 * <ol>
 *   <li><b>Field order.</b> Gson emits the declaring class's fields before
 *       its superclasses', so Mail's own fields come first and
 *       {@code objName} (FcObject) then {@code id} (FcEntity) trail them.
 *       Order is invisible to a parser but decides the bytes, and the bytes
 *       decide the id below.</li>
 *   <li><b>The local id.</b> {@code checkIdWithCreate()} is
 *       {@code sha256x2(JsonUtils.toJson(this))} — the whole object as it
 *       stands at that moment, with nulls omitted and HTML escaping
 *       <i>disabled</i> (unlike {@code Hat.toBytes()}, which escapes). So a
 *       draft's id depends on which fields happen to be set when it is
 *       derived, and the {@code local-draft-*} vectors below fix the exact
 *       shape the Android compose screen derives from: from, to, content,
 *       and nothing else.</li>
 * </ol>
 *
 * <p>An on-chain mail never uses that derivation — its id is the carve
 * txid — but a locally-saved draft does, and two clients that disagree
 * about it would each think the other's draft was a different mail.
 */
final class MailRef {

    private MailRef() {}

    private static final String FID_A = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK";
    private static final String FID_B = "F6vqNGkbAqZQ1YkPWLcXfNfwvJXCTGmzUM";

    static JsonArray generate() {
        JsonArray out = new JsonArray();
        out.add(vector("local-draft", localDraft("Meet me at the usual place.")));
        out.add(vector("local-draft-unicode", localDraft("老地方见 — naïve café 🚀")));
        // '<' '>' '&' '=' '\'' are escaped by Gson's default writer but NOT by
        // JsonUtils.toJson, which disables HTML escaping. A mail body full of
        // them is the case where a port that reached for the wrong writer
        // would produce a different id.
        out.add(vector("local-draft-html-escapable", localDraft("a<b & c='d' => e")));
        out.add(vector("self-draft", selfDraft()));
        out.add(vector("on-chain-received", onChainReceived()));
        out.add(vector("on-chain-deleted", onChainDeleted()));
        out.add(vector("full", full()));
        return out;
    }

    /**
     * One vector: the JSON Android stores, plus the id it derives when the
     * mail has none.
     */
    private static JsonObject vector(String label, Mail mail) {
        JsonObject v = new JsonObject();
        v.addProperty("label", label);
        v.addProperty("json", JsonUtils.toJson(mail));
        v.addProperty("id_source_json",
                new String(idless(mail).toBytes(), StandardCharsets.UTF_8));

        Mail copy = idless(mail);
        copy.checkIdWithCreate();
        v.addProperty("derived_id_without_id_field", copy.getId());
        return v;
    }

    private static Mail idless(Mail mail) {
        Mail copy = JsonUtils.fromJson(JsonUtils.toJson(mail), Mail.class);
        copy.setId(null);
        return copy;
    }

    /** What CreateMailActivity has in hand when it calls checkIdWithCreate(). */
    private static Mail localDraft(String content) {
        Mail m = new Mail();
        m.setFrom(FID_A);
        m.setTo(FID_B);
        m.setContent(content);
        return m;
    }

    /** from == to — the note-to-self case, sealed AsyOneWay. */
    private static Mail selfDraft() {
        Mail m = new Mail();
        m.setFrom(FID_A);
        m.setTo(FID_A);
        m.setContent("remember to renew the domain");
        return m;
    }

    /** A row as it comes back from base.search, before parseDetail runs. */
    private static Mail onChainReceived() {
        Mail m = new Mail();
        m.setId("9f2c4b1a00000000000000000000000000000000000000000000000000000txid");
        m.setFrom(FID_B);
        m.setTo(FID_A);
        m.setAlg("EccK1AesCbc256@No1_NrC7");
        m.setCipher("{\"type\":\"AsyTwoWay\",\"alg\":\"EccK1AesCbc256@No1_NrC7\",\"cipher\":\"c2FtcGxl\"}");
        m.setBirthTime(1755100000L);
        m.setBirthHeight(4100000L);
        m.setLastHeight(4100000L);
        m.setActive(true);
        m.setOnChain(true);
        m.setNoticeFee(10000L);
        return m;
    }

    /** The newest carve for this mail was a delete op. */
    private static Mail onChainDeleted() {
        Mail m = onChainReceived();
        m.setActive(false);
        m.setLastHeight(4100050L);
        return m;
    }

    /** Every field populated, to pin order exhaustively. */
    private static Mail full() {
        Mail m = onChainReceived();
        m.setContent("decrypted body");
        m.setDecrypted(true);
        m.setFromName("alice");
        m.setToName("bob");
        m.setUnread(true);
        m.setObjName("Mail");
        return m;
    }
}
