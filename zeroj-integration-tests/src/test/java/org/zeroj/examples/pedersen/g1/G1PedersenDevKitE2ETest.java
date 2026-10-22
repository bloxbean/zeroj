package org.zeroj.examples.pedersen.g1;

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
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenBytesCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.examples.dsl.common.YaciHelper;
import org.zeroj.examples.pedersen.g1.onchain.G1BytesOpeningValidator;
import org.zeroj.examples.pedersen.g1.onchain.G1RunningTotalValidator;
import org.zeroj.examples.pedersen.g1.onchain.G1ScalarOpeningValidator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0060 M4 on Yaci DevKit: the three {@code pedersen-bls12-381-g1} example validators on a real
 * ledger.
 *
 * <ul>
 *   <li>{@link G1ScalarOpeningValidator}: lock, then spend with the disclosed opening.</li>
 *   <li>{@link G1RunningTotalValidator}: lock a total of 1000, apply {@code +250} and then
 *       {@code −100} in two transactions, each with its continuing output; the final datum is
 *       checked against a fresh off-chain commitment to 1150.</li>
 *   <li>{@link G1BytesOpeningValidator}: lock, then open with a 300-octet payload.</li>
 * </ul>
 *
 * <p>Before each honest spend, a tampered transaction (wrong blinding, wrong next commitment, one
 * flipped payload octet) is <b>submitted to the node</b> and must be rejected there. Script costs for
 * a tampered transaction cannot be evaluated (the script fails), so it is built with a fixed budget
 * well above the honest cost; the node then rejects it in phase 2. Honest transactions are costed
 * locally with Julc (DevKit's {@code /evaluate} cannot initialise blst in the aarch64 container,
 * ADR-0056), and the node validates every submitted transaction. Fee and ex-units of each honest
 * transaction are printed.
 *
 * <p>Tagged {@code e2e}; skips when DevKit is not reachable. Run with
 * {@code ./gradlew :zeroj-integration-tests:e2eTest --tests "*G1PedersenDevKitE2ETest"}.
 */
@Tag("e2e")
class G1PedersenDevKitE2ETest {

    private static final BigInteger Q = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final G1Pedersen PEDERSEN = G1Pedersen.pureJava();
    /** Budget for a tampered transaction: within DevKit's per-transaction maximum (16.5M mem, 10G steps). */
    private static final ExUnits TAMPERED_BUDGET = new ExUnits(BigInteger.valueOf(10_000_000),
            BigInteger.valueOf(5_000_000_000L));

    private static boolean available;
    private static BackendService backend;
    private static Account owner;
    private static byte[] ownerPkh;

    @BeforeAll
    static void setup() {
        available = YaciHelper.isYaciReachable();
        if (!available) return;
        backend = YaciHelper.createBackendService();
        owner = new Account(Networks.testnet());
        ownerPkh = owner.hdKeyPair().getPublicKey().getKeyHash();
        YaciHelper.topUp(owner.baseAddress(), 1000);
    }

    @Test
    @DisplayName("DevKit: a scalar opening spends the output; a wrong blinding is rejected by the node")
    void scalarOpening() throws Exception {
        assumeTrue(available, "Yaci DevKit not running");
        PlutusScript script = JulcScriptLoader.load(G1ScalarOpeningValidator.class);
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();

        BigInteger value = BigInteger.valueOf(1_234_567);
        BigInteger blinding = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenCommitment c = PEDERSEN.commitScalar(value, blinding);
        assertTrue(PEDERSEN.verifyScalar(c, value, blinding, 64), "off-chain oracle");

        Utxo locked = lock(scriptAddress, holding(ownerPkh, c.toPointBytes()));

        Outcome tampered = spend(script, locked, opening(value, blinding.add(BigInteger.ONE).mod(Q)), null, null,
                fixedBudget());
        assertNodeRejected(tampered, "wrong blinding");

        Outcome honest = spend(script, locked, opening(value, blinding), null, null, localEvaluator());
        assertAccepted(honest, "scalar opening");
        report("G1ScalarOpeningValidator opening", honest);
    }

    @Test
    @DisplayName("DevKit: a running total takes +250 then −100; a wrong next commitment is rejected by the node")
    void runningTotal() throws Exception {
        assumeTrue(available, "Yaci DevKit not running");
        PlutusScript script = JulcScriptLoader.load(G1RunningTotalValidator.class);
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();

        BigInteger blinding = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenCommitment c0 = PEDERSEN.commitScalar(BigInteger.valueOf(1_000), blinding);
        G1PedersenCommitment c1 = c0.withPublicDelta(BigInteger.valueOf(250), 64);
        G1PedersenCommitment c2 = c1.withPublicDelta(BigInteger.valueOf(-100), 64);
        assertEquals(PEDERSEN.commitScalar(BigInteger.valueOf(1_250), blinding), c1, "off-chain oracle, +250");
        assertEquals(PEDERSEN.commitScalar(BigInteger.valueOf(1_150), blinding), c2, "off-chain oracle, −100");

        Utxo locked = lock(scriptAddress, holding(ownerPkh, c0.toPointBytes()));

        // Update 1: +250.
        Outcome tampered1 = spend(script, locked, update(BigInteger.valueOf(250)), scriptAddress,
                holding(ownerPkh, c0.withPublicDelta(BigInteger.valueOf(251), 64).toPointBytes()), fixedBudget());
        assertNodeRejected(tampered1, "+250 with a +251 successor");
        Outcome honest1 = spend(script, locked, update(BigInteger.valueOf(250)), scriptAddress,
                holding(ownerPkh, c1.toPointBytes()), localEvaluator());
        assertAccepted(honest1, "+250 update");
        report("G1RunningTotalValidator +250", honest1);
        Utxo afterFirst = YaciHelper.findUtxo(backend, scriptAddress, honest1.result().getValue());

        // Update 2: −100.
        Outcome tampered2 = spend(script, afterFirst, update(BigInteger.valueOf(-100)), scriptAddress,
                holding(ownerPkh, c1.withPublicDelta(BigInteger.valueOf(100), 64).toPointBytes()), fixedBudget());
        assertNodeRejected(tampered2, "−100 with a +100 successor");
        Outcome honest2 = spend(script, afterFirst, update(BigInteger.valueOf(-100)), scriptAddress,
                holding(ownerPkh, c2.toPointBytes()), localEvaluator());
        assertAccepted(honest2, "−100 update");
        report("G1RunningTotalValidator −100", honest2);

        Utxo afterSecond = YaciHelper.findUtxo(backend, scriptAddress, honest2.result().getValue());
        assertEquals(holding(ownerPkh, PEDERSEN.commitScalar(BigInteger.valueOf(1_150), blinding).toPointBytes())
                        .serializeToHex(), afterSecond.getInlineDatum(),
                "the on-chain total must be the commitment to 1150 under the original blinding");
    }

    @Test
    @DisplayName("DevKit: a 300-octet bytes opening spends the output; one flipped octet is rejected by the node")
    void bytesOpening() throws Exception {
        assumeTrue(available, "Yaci DevKit not running");
        PlutusScript script = JulcScriptLoader.load(G1BytesOpeningValidator.class);
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();

        byte[] payload = G1PedersenOnChainTest.pattern(300);
        BigInteger blinding = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(payload, blinding);
        assertTrue(PEDERSEN.verifyBytes(c, payload, blinding), "off-chain oracle");

        Utxo locked = lock(scriptAddress, holding(ownerPkh, c.toPointBytes()));

        byte[] flipped = payload.clone();
        flipped[150] ^= 1;
        Outcome tampered = spend(script, locked, bytesOpening(flipped, blinding), null, null, fixedBudget());
        assertNodeRejected(tampered, "one flipped payload octet");

        Outcome honest = spend(script, locked, bytesOpening(payload, blinding), null, null, localEvaluator());
        assertAccepted(honest, "bytes opening");
        report("G1BytesOpeningValidator 300-octet opening", honest);
    }

    // ------------------------------------------------------------------
    //  Harness
    // ------------------------------------------------------------------

    /** A submission result and the transaction as it was built and signed (null if building failed). */
    record Outcome(Result<String> result, Transaction tx) {}

    private static Utxo lock(String scriptAddress, PlutusData datum) throws Exception {
        var lock = new Tx().payToContract(scriptAddress, Amount.ada(5), datum).from(owner.baseAddress());
        Result<String> locked = new QuickTxBuilder(backend).compose(lock)
                .withSigner(SignerProviders.signerFrom(owner)).complete();
        assertTrue(locked.isSuccessful(), "lock failed: " + locked.getResponse());
        YaciHelper.waitForConfirmation(backend, locked.getValue());
        return YaciHelper.findUtxo(backend, scriptAddress, locked.getValue());
    }

    /**
     * Spends {@code locked} with {@code redeemer}. With a {@code continuingAddress}, pays the locked
     * 5 ADA back to it with {@code continuingDatum} inline; otherwise pays it to the owner.
     */
    private static Outcome spend(PlutusScript script, Utxo locked, PlutusData redeemer,
                                 String continuingAddress, PlutusData continuingDatum,
                                 TransactionEvaluator evaluator) {
        var tx = new ScriptTx().collectFrom(locked, redeemer);
        if (continuingAddress != null) {
            tx = tx.payToContract(continuingAddress, Amount.ada(5), continuingDatum);
        } else {
            tx = tx.payToAddress(owner.baseAddress(), Amount.ada(5));
        }
        tx = tx.attachSpendingValidator(script);
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

    /**
     * The tampered transaction must have been built and submitted (so it is the node that refuses
     * it), within the fixed budget, and refused for a failing script rather than anything else.
     */
    private static void assertNodeRejected(Outcome outcome, String label) {
        assertFalse(outcome.result().isSuccessful(), label + ": must be rejected");
        assertTrue(outcome.tx() != null, label + ": the transaction was never built: " + outcome.result().getResponse());
        String response = String.valueOf(outcome.result().getResponse());
        System.out.println("[DevKit] tampered (" + label + ") rejected by the node: " + abbreviate(response));
        assertTrue(response.contains("PlutusFailure") || response.contains("ValidationTagMismatch")
                        || response.contains("FailedUnexpectedly"),
                label + ": the node must reject the script, not something else: " + response);
        assertFalse(response.contains("overspending"), label + ": rejected for budget, not by the script: " + response);
        int reason = response.indexOf("The machine terminated");
        if (reason >= 0) {
            System.out.println("[DevKit]   node's reason: " + abbreviate(response.substring(reason)));
        }
    }

    private static void assertAccepted(Outcome outcome, String label) throws Exception {
        assertTrue(outcome.result().isSuccessful(), label + " failed: " + outcome.result().getResponse());
        YaciHelper.waitForConfirmation(backend, outcome.result().getValue());
        for (Redeemer r : outcome.tx().getWitnessSet().getRedeemers()) {
            assertTrue(r.getExUnits().getMem().compareTo(TAMPERED_BUDGET.getMem()) < 0
                            && r.getExUnits().getSteps().compareTo(TAMPERED_BUDGET.getSteps()) < 0,
                    label + ": the tampered budget must exceed the honest cost, so a rejection is not a budget failure");
        }
    }

    private static void report(String label, Outcome outcome) throws CborSerializationException {
        Transaction tx = outcome.tx();
        StringBuilder units = new StringBuilder();
        for (Redeemer r : tx.getWitnessSet().getRedeemers()) {
            units.append(" ").append(r.getTag()).append("[").append(r.getIndex()).append("] mem=")
                    .append(r.getExUnits().getMem()).append(" steps=").append(r.getExUnits().getSteps());
        }
        System.out.println("[DevKit] " + label + ": tx " + outcome.result().getValue()
                + " fee=" + tx.getBody().getFee() + " lovelace, size=" + tx.serialize().length + " octets,"
                + units);
    }

    /** Julc-costed evaluation of honest transactions; the node still validates them. */
    private static TransactionEvaluator localEvaluator() {
        return new JulcTransactionEvaluator(
                new DefaultUtxoSupplier(backend.getUtxoService()),
                new DefaultProtocolParamsSupplier(backend.getEpochService()),
                new DefaultScriptSupplier(backend.getScriptService()));
    }

    /** Assigns {@link #TAMPERED_BUDGET} to every redeemer, so a failing script still reaches the node. */
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

    private static PlutusData holding(byte[] ownerKeyHash, byte[] commitment) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(ownerKeyHash), new BytesPlutusData(commitment))).build();
    }

    private static PlutusData opening(BigInteger value, BigInteger blinding) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                BigIntPlutusData.of(value), BigIntPlutusData.of(blinding))).build();
    }

    private static PlutusData update(BigInteger delta) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(BigIntPlutusData.of(delta))).build();
    }

    private static PlutusData bytesOpening(byte[] payload, BigInteger blinding) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(payload), BigIntPlutusData.of(blinding))).build();
    }

    private static String abbreviate(String s) {
        return s.length() <= 400 ? s : s.substring(0, 400) + "…";
    }
}
