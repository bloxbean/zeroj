package org.zeroj.examples.pedersen;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.crypto.VerificationKey;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.transaction.spec.script.ScriptPubkey;
import com.bloxbean.cardano.client.util.HexUtil;
import org.julclang.clientlib.JulcScriptLoader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema.Entry;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.examples.dsl.common.YaciHelper;
import org.zeroj.examples.pedersen.ConfidentialNoteOnChainTest.Note;
import org.zeroj.examples.pedersen.PedersenVectorSchemaBindingTest.Deployment;
import org.zeroj.examples.pedersen.PedersenVectorSchemaBindingTest.Opening;
import org.zeroj.examples.pedersen.PedersenVectorSchemaBindingTest.Presentation;
import org.zeroj.examples.pedersen.onchain.ConfidentialNoteValidator;
import org.zeroj.examples.pedersen.onchain.VectorCommitmentConsumerValidator;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0051 M4 on Yaci DevKit: the two Pedersen reference validators on a real ledger.
 *
 * <ul>
 *   <li>A confidential note is locked at {@link ConfidentialNoteValidator} and split into two
 *       notes with a pure-Java Groth16 proof; a tampered proof is rejected by the node.</li>
 *   <li>A vector commitment issued under schema A gets an issuance record (a token minted under
 *       the issuer's native-script policy, inline datum {@code (u, v, σ_A)}). A's consumer accepts
 *       the honest presentation; B's consumer rejects a fresh, valid same-shape B proof for the
 *       same commitment because the referenced record binds it to A.</li>
 * </ul>
 *
 * <p>Tagged {@code e2e}; skips when DevKit is not reachable. Run with
 * {@code ./gradlew :zeroj-integration-tests:e2eTest --tests "*PedersenOnChainDevKitE2ETest"}.
 */
@Tag("e2e")
class PedersenOnChainDevKitE2ETest {

    private static boolean available;
    private static BackendService backend;
    private static Account owner;

    @BeforeAll
    static void setup() {
        available = YaciHelper.isYaciReachable();
        if (!available) return;
        backend = YaciHelper.createBackendService();
        owner = new Account(Networks.testnet());
        YaciHelper.topUp(owner.baseAddress(), 1000);
    }

    @Test
    @DisplayName("DevKit: a confidential note is split with a valid proof; a tampered proof is rejected")
    void confidentialNoteSplit() throws Exception {
        assumeTrue(available, "Yaci DevKit not running");
        CircuitBuilder circuit = ConfidentialNoteOnChainTest.transferCircuit(64);
        R1CSConstraintSystem r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        Groth16Keys keys = Groth16Keys.setupInMemory(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                BigInteger.valueOf(0xde7c1L));
        SnarkjsToCardano.VkCompressed vk = ProverToCardano.compressVk(keys);
        PlutusScript script = JulcScriptLoader.load(ConfidentialNoteValidator.class,
                new BytesPlutusData(vk.alpha()), new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()), new BytesPlutusData(vk.delta()), icData(vk.ic()));
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        byte[] ownerPkh = owner.hdKeyPair().getPublicKey().getKeyHash();
        byte[] recipientPkh = new Account(Networks.testnet()).hdKeyPair().getPublicKey().getKeyHash();

        Note input = Note.of(ownerPkh, 1_000);
        Note out1 = Note.of(recipientPkh, 700);
        Note out2 = Note.of(ownerPkh, 300);
        BigInteger[] witness = circuit.calculateWitness(
                ConfidentialNoteOnChainTest.witness(input, out1, out2), CurveId.BLS12_381);
        var proof = ProverToCardano.compressProof(keys.prove(witness, r1cs.constraints()));

        var quickTx = new QuickTxBuilder(backend);
        var lock = new Tx().payToContract(scriptAddress, Amount.ada(5), noteDatum(input)).from(owner.baseAddress());
        Result<String> locked = quickTx.compose(lock).withSigner(SignerProviders.signerFrom(owner)).complete();
        assertTrue(locked.isSuccessful(), "lock failed: " + locked.getResponse());
        YaciHelper.waitForConfirmation(backend, locked.getValue());
        Utxo noteUtxo = YaciHelper.findUtxo(backend, scriptAddress, locked.getValue());

        // Tampered proof first: the node must reject it and leave the note unspent.
        byte[] tamperedA = proof.piA().clone();
        tamperedA[tamperedA.length - 1] ^= 1;
        Result<String> tampered = spend(quickTx, script, scriptAddress, noteUtxo, out1, out2,
                tamperedA, proof.piB(), proof.piC(), ownerPkh);
        assertFalse(tampered.isSuccessful(), "a tampered proof must be rejected");

        Result<String> split = spend(quickTx, script, scriptAddress, noteUtxo, out1, out2,
                proof.piA(), proof.piB(), proof.piC(), ownerPkh);
        assertTrue(split.isSuccessful(), "split failed: " + split.getResponse());
        YaciHelper.waitForConfirmation(backend, split.getValue());
        System.out.println("Confidential note split on DevKit: " + split.getValue());
    }

    @Test
    @DisplayName("DevKit: A's consumer accepts an issued commitment; B's consumer rejects the relabelled proof")
    void vectorIssuanceAndRelabelling() throws Exception {
        assumeTrue(available, "Yaci DevKit not running");
        List<Entry> entries = List.of(new Entry("amount", 64), new Entry("asset", 32));
        PedersenVectorSchema a = PedersenVectorSchema.of("zeroj.example.balance", 1, entries);
        PedersenVectorSchema b = PedersenVectorSchema.of("zeroj.example.balance", 1,
                List.of(new Entry("fee", 64), new Entry("asset", 32)));
        Deployment deployA = PedersenVectorSchemaBindingTest.deploy(a, 71);
        Deployment deployB = PedersenVectorSchemaBindingTest.deploy(b, 72);

        // Issuer's native-script policy: only the issuer's key can mint issuance tokens.
        ScriptPubkey issuerPolicy = ScriptPubkey.create(VerificationKey.create(owner.publicKeyBytes()));
        byte[] policyId = HexUtil.decodeHexString(issuerPolicy.getPolicyId());
        byte[] tokenName = "pedersen-issuance".getBytes(StandardCharsets.US_ASCII);

        PlutusScript consumerA = consumer(a, deployA, policyId, tokenName);
        PlutusScript consumerB = consumer(b, deployB, policyId, tokenName);
        String consumerAAddress = AddressProvider.getEntAddress(consumerA, Networks.testnet()).toBech32();
        String consumerBAddress = AddressProvider.getEntAddress(consumerB, Networks.testnet()).toBech32();

        Opening opening = PedersenVectorSchemaBindingTest.opening();
        var issued = PedersenVectorCommitment.commit(a, opening.values(), opening.blinding());
        Presentation honest = PedersenVectorSchemaBindingTest.prove(deployA, a.digest(), issued, opening);
        var relabelled = PedersenVectorCommitment.commit(b, opening.values(), opening.blinding());
        Presentation adversary = PedersenVectorSchemaBindingTest.prove(deployB, b.digest(), relabelled, opening);

        var quickTx = new QuickTxBuilder(backend);
        // Issuance record: token + inline datum (u, v, σ_A) at the issuer's address.
        String tokenUnit = HexUtil.encodeHexString(policyId) + HexUtil.encodeHexString(tokenName);
        var issue = new Tx()
                .mintAssets(issuerPolicy, new Asset("0x" + HexUtil.encodeHexString(tokenName), BigInteger.ONE))
                .payToContract(owner.baseAddress(),
                        List.of(Amount.ada(2), new Amount(tokenUnit, BigInteger.ONE)),
                        recordDatum(issued, a))
                .payToContract(consumerAAddress, Amount.ada(3), unitDatum())
                .payToContract(consumerBAddress, Amount.ada(3), unitDatum())
                .from(owner.baseAddress());
        Result<String> issuedTx = quickTx.compose(issue).withSigner(SignerProviders.signerFrom(owner)).complete();
        assertTrue(issuedTx.isSuccessful(), "issuance failed: " + issuedTx.getResponse());
        YaciHelper.waitForConfirmation(backend, issuedTx.getValue());

        Utxo record = YaciHelper.findAllUtxos(backend, owner.baseAddress(), issuedTx.getValue()).stream()
                .filter(u -> u.getAmount().stream().anyMatch(x -> x.getUnit().equals(tokenUnit)))
                .findFirst().orElseThrow();
        Utxo lockedA = YaciHelper.findUtxo(backend, consumerAAddress, issuedTx.getValue());
        Utxo lockedB = YaciHelper.findUtxo(backend, consumerBAddress, issuedTx.getValue());

        Result<String> relabel = present(quickTx, consumerB, lockedB, record, adversary);
        assertFalse(relabel.isSuccessful(), "B's consumer must reject a commitment issued under A");

        Result<String> accepted = present(quickTx, consumerA, lockedA, record, honest);
        assertTrue(accepted.isSuccessful(), "A's consumer must accept: " + accepted.getResponse());
        YaciHelper.waitForConfirmation(backend, accepted.getValue());
        System.out.println("Vector commitment presentation accepted on DevKit: " + accepted.getValue());
    }

    // ------------------------------------------------------------------
    //  Harness
    // ------------------------------------------------------------------

    private static Result<String> spend(QuickTxBuilder quickTx, PlutusScript script, String scriptAddress,
                                        Utxo noteUtxo, Note out1, Note out2,
                                        byte[] piA, byte[] piB, byte[] piC, byte[] ownerPkh) {
        var redeemer = ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(piA), new BytesPlutusData(piB), new BytesPlutusData(piC))).build();
        var tx = new ScriptTx()
                .collectFrom(noteUtxo, redeemer)
                .payToContract(scriptAddress, Amount.ada(2), noteDatum(out1))
                .payToContract(scriptAddress, Amount.ada(2), noteDatum(out2))
                .attachSpendingValidator(script);
        try {
            return quickTx.compose(tx)
                    .withSigner(SignerProviders.signerFrom(owner))
                    .withRequiredSigners(ownerPkh)
                    .feePayer(owner.baseAddress())
                    .collateralPayer(owner.baseAddress())
                    .complete();
        } catch (RuntimeException e) {
            YaciHelper.assumeNoBlsCostingFailure(e);
            return Result.error(e.getMessage());
        }
    }

    private static Result<String> present(QuickTxBuilder quickTx, PlutusScript consumer, Utxo locked,
                                          Utxo record, Presentation p) {
        var compressed = ProverToCardano.compressProof(p.proof());
        var redeemer = ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                BigIntPlutusData.of(p.publicInputs()[1]),
                BigIntPlutusData.of(p.publicInputs()[2]),
                new BytesPlutusData(compressed.piA()),
                new BytesPlutusData(compressed.piB()),
                new BytesPlutusData(compressed.piC()))).build();
        var tx = new ScriptTx()
                .collectFrom(locked, redeemer)
                .readFrom(record)
                .payToAddress(owner.baseAddress(), Amount.ada(2))
                .attachSpendingValidator(consumer);
        try {
            return quickTx.compose(tx)
                    .withSigner(SignerProviders.signerFrom(owner))
                    .feePayer(owner.baseAddress())
                    .collateralPayer(owner.baseAddress())
                    .complete();
        } catch (RuntimeException e) {
            YaciHelper.assumeNoBlsCostingFailure(e);
            return Result.error(e.getMessage());
        }
    }

    private static PlutusScript consumer(PedersenVectorSchema schema, Deployment d, byte[] policyId, byte[] tokenName) {
        SnarkjsToCardano.VkCompressed vk = ProverToCardano.compressVk(d.keys());
        return JulcScriptLoader.load(VectorCommitmentConsumerValidator.class,
                new BytesPlutusData(digestBytes(schema)),
                new BytesPlutusData(policyId),
                new BytesPlutusData(tokenName),
                new BytesPlutusData(vk.alpha()), new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()), new BytesPlutusData(vk.delta()), icData(vk.ic()));
    }

    private static PlutusData noteDatum(Note n) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(n.owner()),
                BigIntPlutusData.of(n.commitment().affineU()),
                BigIntPlutusData.of(n.commitment().affineV()))).build();
    }

    private static PlutusData recordDatum(PedersenVectorCommitment c, PedersenVectorSchema schema) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                BigIntPlutusData.of(c.point().affineU()),
                BigIntPlutusData.of(c.point().affineV()),
                BigIntPlutusData.of(schema.digest()))).build();
    }

    private static PlutusData unitDatum() {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of()).build();
    }

    private static ListPlutusData icData(List<byte[]> ic) {
        List<PlutusData> values = new ArrayList<>();
        for (byte[] point : ic) values.add(new BytesPlutusData(point));
        return ListPlutusData.of(values.toArray(new PlutusData[0]));
    }

    private static byte[] digestBytes(PedersenVectorSchema schema) {
        byte[] raw = schema.digest().toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }
}
