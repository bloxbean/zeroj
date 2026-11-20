package org.zeroj.examples.bbs;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.TransactionEvaluator;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.EvaluationResult;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.exception.CborDeserializationException;
import com.bloxbean.cardano.client.exception.CborSerializationException;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ExUnits;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.plutus.spec.Redeemer;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.transaction.spec.Transaction;
import org.julclang.clientlib.JulcScriptLoader;
import org.julclang.clientlib.eval.JulcTransactionEvaluator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.zeroj.bbs.BbsKeyPair;
import org.zeroj.bbs.BbsPresentation;
import org.zeroj.bbs.BbsService;
import org.zeroj.bbs.BbsSignature;
import org.zeroj.bbs.cardano.BbsToCardano;
import org.zeroj.bbs.internal.BbsCodec;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.Bls12381Hash;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.examples.bbs.onchain.BbsClaimExampleValidator;
import org.zeroj.examples.dsl.common.YaciHelper;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0064 Yaci DevKit E2E test for on-chain BBS {@code ProofVerify} on a real Cardano Plutus V3 node.
 *
 * <p>Before spending the locked output with an honest 5-message BBS presentation, submits three
 * adversarial transactions directly to the node (with generous fixed ExUnits so they reach Phase 2):
 * <ol>
 *   <li>All-non-zero identity-point forgery ({@code Abar = Bbar = O}, {@code D = Bv},
 *       {@code r3Hat = r - c}) — must be rejected by the node.</li>
 *   <li>Scalar-malleated redeemer ({@code eHat + r}) — must be rejected by the node.</li>
 *   <li>Zero-scalar redeemer ({@code eHat = 0}) — must be rejected by the node.</li>
 * </ol>
 * Then spends the same UTxO with the honest presentation and verifies on-chain confirmation.</p>
 *
 * <p>Run with: {@code ./gradlew :zeroj-integration-tests:e2eTest --tests "*BbsProofVerifyDevKitE2ETest"}</p>
 */
@Tag("e2e")
class BbsProofVerifyDevKitE2ETest {

    private static final BigInteger R = G1Point.R;
    private static final BbsService BBS = BbsService.pureJava();
    private static final byte[] HEADER = "reusable-kyc/v1|issuer=kyc-provider-1".getBytes(StandardCharsets.UTF_8);
    private static final List<byte[]> MESSAGES = List.of(
            "Alice Example".getBytes(StandardCharsets.UTF_8),
            "1990-05-01".getBytes(StandardCharsets.UTF_8),
            "USA".getBytes(StandardCharsets.UTF_8),
            "verified".getBytes(StandardCharsets.UTF_8),
            "9f86d081".getBytes(StandardCharsets.UTF_8));
    private static final ExUnits TAMPERED_BUDGET = new ExUnits(
            BigInteger.valueOf(5_000_000L),
            BigInteger.valueOf(4_000_000_000L));

    private static boolean available;
    private static BackendService backend;
    private static Account owner;
    private static byte[] ownerPkh;

    @BeforeAll
    static void setup() {
        available = YaciHelper.isYaciReachable();
        if (!available) {
            return;
        }
        backend = YaciHelper.createBackendService();
        owner = new Account(Networks.testnet());
        ownerPkh = owner.hdKeyPair().getPublicKey().getKeyHash();
        YaciHelper.topUp(owner.baseAddress(), 1000);
    }

    @Test
    @DisplayName("DevKit: node rejects BBS identity-point forgery and scalar malleability, then accepts honest presentation")
    void bbsOnChainAcceptsHonestAndRejectsForgeries() throws Exception {
        assumeTrue(available, "Yaci DevKit not running");

        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 7);
        BbsKeyPair kp = BBS.keyPair(seed, "kyc-provider-1".getBytes(StandardCharsets.UTF_8));
        BbsSignature sig = BBS.sign(kp.secretKey(), kp.publicKey(), MESSAGES, HEADER);
        byte[] ph = "devkit-bbs-session-1".getBytes(StandardCharsets.UTF_8);
        BbsPresentation presentation = BBS.derivePresentation(
                kp.publicKey(), sig, MESSAGES, HEADER, ph, new int[]{2, 3});

        BbsToCardano.VerifierParams params = BbsToCardano.verifierParams(kp.publicKey(), HEADER, MESSAGES.size());
        BbsToCardano.OnChainProof honest = BbsToCardano.onChainProof(presentation);

        PlutusScript script = JulcScriptLoader.load(
                BbsClaimExampleValidator.class,
                new BytesPlutusData(params.publicKey()),
                new BytesPlutusData(params.g2Generator()),
                new BytesPlutusData(params.p1()),
                new BytesPlutusData(params.q1()),
                new BytesPlutusData(params.h().get(0)),
                new BytesPlutusData(params.h().get(1)),
                new BytesPlutusData(params.h().get(2)),
                new BytesPlutusData(params.h().get(3)),
                new BytesPlutusData(params.h().get(4)),
                new BytesPlutusData(params.domain()),
                new BytesPlutusData(params.dstHashToScalar()),
                new BytesPlutusData(params.dstMapToScalar()));
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();

        PlutusData datum = claimPolicy(ownerPkh, MESSAGES.get(2), MESSAGES.get(3), ph);
        Utxo locked = lock(scriptAddress, datum);

        // 1. All-non-zero identity-point forgery must be rejected by the real Cardano node in Phase 2.
        PlutusData forgedRedeemer = buildAllNonZeroForgery(params, MESSAGES.get(2), MESSAGES.get(3), ph);
        Outcome forged = spend(script, locked, forgedRedeemer, fixedBudget());
        assertNodeRejected(forged, "all-non-zero identity-point forgery");

        // 2. Scalar malleability (eHat + r) must be rejected by the node.
        PlutusData malleatedRedeemer = claimProof(
                honest.aBar(), honest.bBar(), honest.d(),
                honest.eHat().add(R), honest.r1Hat(), honest.r3Hat(),
                honest.mHats().get(0), honest.mHats().get(1), honest.mHats().get(2),
                honest.challenge(),
                honest.disclosed().get(0).message(), honest.disclosed().get(1).message(), ph);
        Outcome malleated = spend(script, locked, malleatedRedeemer, fixedBudget());
        assertNodeRejected(malleated, "scalar malleability (eHat + r)");

        // 3. Zero scalar (eHat = 0) must be rejected by the node.
        PlutusData zeroScalarRedeemer = claimProof(
                honest.aBar(), honest.bBar(), honest.d(),
                BigInteger.ZERO, honest.r1Hat(), honest.r3Hat(),
                honest.mHats().get(0), honest.mHats().get(1), honest.mHats().get(2),
                honest.challenge(),
                honest.disclosed().get(0).message(), honest.disclosed().get(1).message(), ph);
        Outcome zeroScalar = spend(script, locked, zeroScalarRedeemer, fixedBudget());
        assertNodeRejected(zeroScalar, "zero scalar (eHat = 0)");

        // 4. Honest presentation must be accepted and confirmed on-chain.
        PlutusData honestRedeemer = claimProof(
                honest.aBar(), honest.bBar(), honest.d(),
                honest.eHat(), honest.r1Hat(), honest.r3Hat(),
                honest.mHats().get(0), honest.mHats().get(1), honest.mHats().get(2),
                honest.challenge(),
                honest.disclosed().get(0).message(), honest.disclosed().get(1).message(), ph);
        Outcome accepted = spend(script, locked, honestRedeemer, localEvaluator());
        assertAccepted(accepted, "honest BBS presentation");
        report("honest BBS presentation", accepted);
    }

    private static PlutusData buildAllNonZeroForgery(
            BbsToCardano.VerifierParams params, byte[] msg2, byte[] msg3, byte[] ph) {
        byte[] g1Identity = new byte[48];
        g1Identity[0] = (byte) 0xc0;
        BigInteger domain = new BigInteger(1, params.domain());
        BigInteger s2 = Bls12381Hash.hashToScalar(msg2, params.dstMapToScalar());
        BigInteger s3 = Bls12381Hash.hashToScalar(msg3, params.dstMapToScalar());

        G1Point p1 = Bls12381Codecs.g1FromCompressed(params.p1());
        G1Point q1 = Bls12381Codecs.g1FromCompressed(params.q1());
        G1Point h0 = Bls12381Codecs.g1FromCompressed(params.h().get(0));
        G1Point h1 = Bls12381Codecs.g1FromCompressed(params.h().get(1));
        G1Point h2 = Bls12381Codecs.g1FromCompressed(params.h().get(2));
        G1Point h3 = Bls12381Codecs.g1FromCompressed(params.h().get(3));
        G1Point h4 = Bls12381Codecs.g1FromCompressed(params.h().get(4));

        G1Point bv = p1.add(q1.scalarMul(domain)).add(h2.scalarMul(s2)).add(h3.scalarMul(s3));
        byte[] dBytes = Bls12381Codecs.g1ToCompressed(bv);

        BigInteger eHat = BigInteger.valueOf(7);
        BigInteger r1Hat = BigInteger.valueOf(11);
        BigInteger mHat0 = BigInteger.valueOf(13);
        BigInteger mHat1 = BigInteger.valueOf(17);
        BigInteger mHat2 = BigInteger.valueOf(19);
        G1Point t1 = bv.scalarMul(r1Hat);
        G1Point t2 = h0.scalarMul(mHat0).add(h1.scalarMul(mHat1)).add(h4.scalarMul(mHat2));

        byte[] cInput = BbsCodec.concat(
                BbsCodec.serialize(2L, 2L, s2, 3L, s3,
                        G1Point.INFINITY, G1Point.INFINITY, bv, t1, t2, domain),
                BbsCodec.i2osp(ph.length, 8),
                ph);
        BigInteger c = Bls12381Hash.hashToScalar(cInput, params.dstHashToScalar());
        BigInteger r3Hat = R.subtract(c).mod(R);

        return claimProof(g1Identity, g1Identity, dBytes,
                eHat, r1Hat, r3Hat, mHat0, mHat1, mHat2, c, msg2, msg3, ph);
    }

    private record Outcome(Result<String> result, Transaction tx) {}

    private static Utxo lock(String scriptAddress, PlutusData datum) throws Exception {
        var lock = new Tx().payToContract(scriptAddress, Amount.ada(5), datum).from(owner.baseAddress());
        Result<String> locked = new QuickTxBuilder(backend).compose(lock)
                .withSigner(SignerProviders.signerFrom(owner)).complete();
        assertTrue(locked.isSuccessful(), "lock failed: " + locked.getResponse());
        YaciHelper.waitForConfirmation(backend, locked.getValue());
        return YaciHelper.findUtxo(backend, scriptAddress, locked.getValue());
    }

    private static Outcome spend(PlutusScript script, Utxo locked, PlutusData redeemer,
                                 TransactionEvaluator evaluator) {
        var tx = new ScriptTx()
                .collectFrom(locked, redeemer)
                .payToAddress(owner.baseAddress(), Amount.ada(5))
                .attachSpendingValidator(script);
        AtomicReference<Transaction> built = new AtomicReference<>();
        try {
            Result<String> result = new QuickTxBuilder(backend).compose(tx)
                    .withTxEvaluator(evaluator)
                    .withTxInspector(built::set)
                    .withSigner(SignerProviders.signerFrom(owner))
                    .withRequiredSigners(ownerPkh)
                    .feePayer(owner.baseAddress())
                    .collateralPayer(owner.baseAddress())
                    .complete();
            return new Outcome(result, built.get());
        } catch (RuntimeException e) {
            YaciHelper.assumeNoBlsCostingFailure(e);
            return new Outcome(Result.error(e.getMessage()), built.get());
        }
    }

    private static void assertNodeRejected(Outcome outcome, String label) {
        assertFalse(outcome.result().isSuccessful(), label + ": must be rejected");
        assertTrue(outcome.tx() != null, label + ": transaction was never built: " + outcome.result().getResponse());
        String response = String.valueOf(outcome.result().getResponse());
        System.out.println("[DevKit BBS] tampered (" + label + ") rejected by node: " + abbreviate(response));
        assertTrue(response.contains("PlutusFailure") || response.contains("ValidationTagMismatch")
                        || response.contains("FailedUnexpectedly"),
                label + ": node must reject script, not something else: " + response);
        assertFalse(response.contains("overspending"), label + ": rejected for budget, not by script: " + response);
    }

    private static void assertAccepted(Outcome outcome, String label) throws Exception {
        assertTrue(outcome.result().isSuccessful(), label + " failed: " + outcome.result().getResponse());
        YaciHelper.waitForConfirmation(backend, outcome.result().getValue());
        for (Redeemer r : outcome.tx().getWitnessSet().getRedeemers()) {
            assertTrue(r.getExUnits().getMem().compareTo(TAMPERED_BUDGET.getMem()) < 0
                            && r.getExUnits().getSteps().compareTo(TAMPERED_BUDGET.getSteps()) < 0,
                    label + ": tampered budget must exceed honest cost");
        }
    }

    private static void report(String label, Outcome outcome) throws CborSerializationException {
        Transaction tx = outcome.tx();
        StringBuilder units = new StringBuilder();
        for (Redeemer r : tx.getWitnessSet().getRedeemers()) {
            units.append(" ").append(r.getTag()).append("[").append(r.getIndex()).append("] mem=")
                    .append(r.getExUnits().getMem()).append(" steps=").append(r.getExUnits().getSteps());
        }
        System.out.println("[DevKit BBS] " + label + ": tx " + outcome.result().getValue()
                + " fee=" + tx.getBody().getFee() + " lovelace, size=" + tx.serialize().length + " octets,"
                + units);
    }

    private static TransactionEvaluator localEvaluator() {
        return new JulcTransactionEvaluator(
                new DefaultUtxoSupplier(backend.getUtxoService()),
                new DefaultProtocolParamsSupplier(backend.getEpochService()),
                new DefaultScriptSupplier(backend.getScriptService()));
    }

    @SuppressWarnings("unchecked")
    private static TransactionEvaluator fixedBudget() {
        return (cbor, inputUtxos) -> {
            Transaction tx;
            try {
                tx = Transaction.deserialize(cbor);
            } catch (CborDeserializationException e) {
                return Result.error(e.getMessage());
            }
            List<EvaluationResult> results = new ArrayList<>();
            for (Redeemer r : tx.getWitnessSet().getRedeemers()) {
                results.add(new EvaluationResult(r.getTag(), r.getIndex().intValue(), TAMPERED_BUDGET));
            }
            return Result.success("fixed budget").withValue(results);
        };
    }

    private static PlutusData claimPolicy(byte[] ownerKeyHash, byte[] msg2, byte[] msg3, byte[] ph) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(ownerKeyHash),
                new BytesPlutusData(msg2),
                new BytesPlutusData(msg3),
                new BytesPlutusData(ph))).build();
    }

    private static PlutusData claimProof(
            byte[] abar, byte[] bbar, byte[] d,
            BigInteger eHat, BigInteger r1Hat, BigInteger r3Hat,
            BigInteger mHat0, BigInteger mHat1, BigInteger mHat2, BigInteger c,
            byte[] msg2, byte[] msg3, byte[] ph) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(abar),
                new BytesPlutusData(bbar),
                new BytesPlutusData(d),
                BigIntPlutusData.of(eHat),
                BigIntPlutusData.of(r1Hat),
                BigIntPlutusData.of(r3Hat),
                BigIntPlutusData.of(mHat0),
                BigIntPlutusData.of(mHat1),
                BigIntPlutusData.of(mHat2),
                BigIntPlutusData.of(c),
                new BytesPlutusData(msg2),
                new BytesPlutusData(msg3),
                new BytesPlutusData(ph))).build();
    }

    private static String abbreviate(String s) {
        return s.length() <= 400 ? s : s.substring(0, 400) + "…";
    }
}
