package cash.freer.mac.vectorgen;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import com.fc.fc_ajdk.core.crypto.KeyTools;
import com.fc.fc_ajdk.core.fch.RawTxInfo;
import com.fc.fc_ajdk.core.fch.TxHandler;
import com.fc.fc_ajdk.data.fchData.Cash;
import com.fc.fc_ajdk.data.fchData.Multisig;
import com.fc.fc_ajdk.data.fchData.P2SH;
import com.fc.fc_ajdk.utils.Hex;

import org.bitcoinj.core.ECKey;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Ground truth for the Swift `P2sh` and `TxFee` ports, produced by the
 * REAL FC-AJDK classes ({@code data.fchData.P2SH} and
 * {@code core.fch.TxHandler}) rather than by a re-implementation here.
 *
 * Redeem scripts are hashed into addresses, so "close" is not a thing:
 * a script that differs by one byte of push encoding sends the coins to
 * a different address than the Android client would compute for the
 * same lock. The same goes for the fee — a different fee means a
 * different change amount, which means a different transaction.
 */
final class P2shRef {

    // Leaked test keys — safe to publish. Three of them, so a 2-of-3
    // group is a real group rather than a degenerate one.
    private static final String[] GROUP_PRIVKEYS = {
        "a048f6c843f92bfe036057f7fc2bf2c27353c624cf7ad97e98ed41432f700575",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
    };

    private static final String SAMPLE_FID = "FEk41Kqjar45fLDriztUDTUkdki7mmcjWK";
    private static final long SAMPLE_LOCK_TIME = 900_000L;
    private static final String SAMPLE_TXID =
        "6ff4e2c4d2b9c9c53d69b0b3e2b6a94b6f5d1e0f8a7c6b5a4d3e2f1a0b9c8d7e";

    static JsonObject generate() {
        JsonObject root = new JsonObject();
        root.add("cltv", cltvVector());
        root.add("multisig", multisigVector(null));
        root.add("multisig_cltv", multisigVector(SAMPLE_LOCK_TIME));
        root.add("op_return_manifest", opReturnManifest());
        return root;
    }

    private static List<String> groupPubkeys() {
        List<String> out = new ArrayList<>();
        for (String hex : GROUP_PRIVKEYS) {
            ECKey key = ECKey.fromPrivate(new BigInteger(1, Hex.fromHex(hex)));
            out.add(Hex.toHex(key.getPubKey()));
        }
        return out;
    }

    private static JsonObject describe(P2SH p2sh) {
        JsonObject o = new JsonObject();
        o.addProperty("redeem_script_hex", p2sh.getRedeemScript());
        o.addProperty("script_hash_hex", p2sh.getId());
        o.addProperty("type", p2sh.getType().name());
        o.addProperty("fid", p2sh.getFid());
        // The address the coins actually go to: hash160 of THIS script.
        o.addProperty("address", KeyTools.hash160ToMultiAddr(Hex.fromHex(p2sh.getId())));
        if (p2sh.getLockTime() != null) o.addProperty("lock_time", p2sh.getLockTime());
        if (p2sh.getM() != null) o.addProperty("m", p2sh.getM());
        if (p2sh.getN() != null) o.addProperty("n", p2sh.getN());
        return o;
    }

    private static JsonObject cltvVector() {
        P2SH p2sh = new P2SH(SAMPLE_FID, SAMPLE_LOCK_TIME);
        JsonObject o = describe(p2sh);
        o.addProperty("input_fid", SAMPLE_FID);
        o.addProperty("input_lock_time", SAMPLE_LOCK_TIME);
        // Re-parsing the script must recover the same everything.
        o.add("reparsed", describe(new P2SH(p2sh.getRedeemScript())));
        return o;
    }

    private static JsonObject multisigVector(Long lockTime) {
        List<String> pubkeys = groupPubkeys();
        P2SH p2sh = new P2SH(pubkeys, 2, 3, lockTime);
        JsonObject o = describe(p2sh);
        JsonArray keys = new JsonArray();
        pubkeys.forEach(keys::add);
        o.add("input_pubkeys", keys);
        o.addProperty("input_m", 2);
        o.addProperty("input_n", 3);
        if (lockTime != null) o.addProperty("input_lock_time", lockTime);
        o.add("reparsed", describe(new P2SH(p2sh.getRedeemScript())));
        return o;
    }

    /**
     * The OP_RETURN payload that publishes a transaction's redeem
     * scripts — de-duplicated, in first-use order.
     */
    private static JsonObject opReturnManifest() {
        P2SH cltv = new P2SH(SAMPLE_FID, SAMPLE_LOCK_TIME);
        P2SH multi = new P2SH(groupPubkeys(), 2, 3, SAMPLE_LOCK_TIME);
        List<P2SH> list = Arrays.asList(cltv, multi, cltv);   // duplicate on purpose
        String json = P2SH.makeRedeemScriptListJsonForOpReturn(list);
        JsonObject o = new JsonObject();
        JsonArray scripts = new JsonArray();
        for (P2SH p : list) scripts.add(p.getRedeemScript());
        o.add("input_redeem_scripts", scripts);
        o.addProperty("json", json);
        o.addProperty("byte_length", json.getBytes(StandardCharsets.UTF_8).length);
        return o;
    }

    // ---- fee ----

    private static Cash inputCash(long value, int index, Long lockTime, String redeemScript) {
        Cash cash = new Cash();
        cash.setOwner(SAMPLE_FID);
        cash.setValue(value);
        cash.setBirthTxId(SAMPLE_TXID);
        cash.setBirthIndex(index);
        if (lockTime != null) cash.setLockTime(lockTime);
        if (redeemScript != null) cash.setRedeemScript(redeemScript);
        return cash;
    }

    private static JsonObject feeCase(String label, RawTxInfo info) {
        TxHandler.FeeResult result = TxHandler.calcFee(info);
        JsonObject o = new JsonObject();
        o.addProperty("label", label);
        o.addProperty("sender", info.getSender());
        o.addProperty("change_to", info.getChangeTo());
        o.addProperty("fee_rate", info.getFeeRate());
        o.addProperty("op_return_in", info.getOpReturn());

        JsonArray inputs = new JsonArray();
        for (Cash c : info.getInputs()) {
            JsonObject j = new JsonObject();
            j.addProperty("value", c.getValue());
            j.addProperty("birth_tx_id", c.getBirthTxId());
            j.addProperty("birth_index", c.getBirthIndex());
            if (c.getLockTime() != null) j.addProperty("lock_time", c.getLockTime());
            if (c.getRedeemScript() != null) j.addProperty("redeem_script", c.getRedeemScript());
            j.addProperty("owner", c.getOwner());
            inputs.add(j);
        }
        o.add("inputs", inputs);

        JsonArray outputs = new JsonArray();
        for (Cash c : info.getOutputs()) {
            JsonObject j = new JsonObject();
            j.addProperty("value", c.getValue());
            j.addProperty("owner", c.getOwner());
            if (c.getLockTime() != null) j.addProperty("lock_time", c.getLockTime());
            if (c.getRedeemScript() != null) j.addProperty("redeem_script", c.getRedeemScript());
            outputs.add(j);
        }
        o.add("outputs", outputs);

        o.addProperty("fee", result.fee());
        byte[] finalOpReturn = result.finalOpReturnBytes();
        o.addProperty("final_op_return",
            finalOpReturn == null ? null : new String(finalOpReturn, StandardCharsets.UTF_8));
        o.addProperty("p2sh_output_count",
            result.p2SHOutputs() == null ? 0 : result.p2SHOutputs().size());
        return o;
    }

    private static RawTxInfo baseInfo() {
        RawTxInfo info = new RawTxInfo();
        info.setSender(SAMPLE_FID);
        info.setChangeTo(SAMPLE_FID);
        info.setFeeRate(TxHandler.DEFAULT_FEE_RATE);
        return info;
    }

    /** Fee vectors, written to their own file — see VectorGen. */
    static JsonArray feeVectors() {
        JsonArray cases = new JsonArray();

        // 1. One plain input, one plain output, change left over.
        RawTxInfo plain = baseInfo();
        plain.getInputs().add(inputCash(1_000_000L, 0, null, null));
        plain.getOutputs().add(new Cash(SAMPLE_FID, 0.001));
        cases.add(feeCase("one-in-one-out-with-change", plain));

        // 2. Same, but the output takes almost everything, so what
        //    would be left cannot pay for its own change output.
        RawTxInfo noChange = baseInfo();
        noChange.getInputs().add(inputCash(1_000_000L, 0, null, null));
        noChange.getOutputs().add(new Cash(SAMPLE_FID, 0.00999));
        cases.add(feeCase("one-in-one-out-no-change", noChange));

        // 2b. Right at the boundary: enough left to clear dust before
        //     the change output is priced, not enough after.
        RawTxInfo boundary = baseInfo();
        boundary.getInputs().add(inputCash(1_000_000L, 0, null, null));
        boundary.getOutputs().add(new Cash(SAMPLE_FID, 0.009988));
        cases.add(feeCase("change-boundary", boundary));

        // 3. Several inputs and outputs.
        RawTxInfo many = baseInfo();
        many.getInputs().add(inputCash(1_000_000L, 0, null, null));
        many.getInputs().add(inputCash(2_000_000L, 1, null, null));
        many.getInputs().add(inputCash(3_000_000L, 2, null, null));
        many.getOutputs().add(new Cash(SAMPLE_FID, 0.001));
        many.getOutputs().add(new Cash(SAMPLE_FID, 0.002));
        cases.add(feeCase("three-in-two-out", many));

        // 4. With an OP_RETURN the user typed.
        RawTxInfo carved = baseInfo();
        carved.getInputs().add(inputCash(1_000_000L, 0, null, null));
        carved.getOutputs().add(new Cash(SAMPLE_FID, 0.001));
        carved.setOpReturn("Hello, FreeCash. This is a message on chain.");
        cases.add(feeCase("with-op-return", carved));

        // 5. A time-locked output — the redeem-script manifest takes
        //    the OP_RETURN over from the user's text.
        RawTxInfo locked = baseInfo();
        locked.getInputs().add(inputCash(10_000_000L, 0, null, null));
        locked.getOutputs().add(new Cash(SAMPLE_FID, 0.01, SAMPLE_LOCK_TIME));
        locked.setOpReturn("this text is displaced by the manifest");
        cases.add(feeCase("cltv-output", locked));

        // 6. Spending a time-locked input.
        P2SH cltv = new P2SH(SAMPLE_FID, SAMPLE_LOCK_TIME);
        RawTxInfo spendLocked = baseInfo();
        spendLocked.getInputs().add(
            inputCash(10_000_000L, 0, SAMPLE_LOCK_TIME, cltv.getRedeemScript()));
        spendLocked.getOutputs().add(new Cash(SAMPLE_FID, 0.01));
        cases.add(feeCase("cltv-input", spendLocked));

        // 7. A 2-of-3 multisig sender spending a plain group output.
        Multisig group = new Multisig(new P2SH(groupPubkeys(), 2, 3, null));
        RawTxInfo multisigSpend = new RawTxInfo();
        multisigSpend.setSenderMultisig(group);
        multisigSpend.setSender(group.getId());
        multisigSpend.setChangeTo(group.getId());
        multisigSpend.setFeeRate(TxHandler.DEFAULT_FEE_RATE);
        Cash groupInput = inputCash(10_000_000L, 0, null, group.getRedeemScript());
        groupInput.setOwner(group.getId());
        multisigSpend.getInputs().add(groupInput);
        multisigSpend.getOutputs().add(new Cash(SAMPLE_FID, 0.01));
        cases.add(feeCase("multisig-input", multisigSpend));

        return cases;
    }

    private P2shRef() {}
}
