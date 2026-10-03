package org.zeroj.examples.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PolicyId;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.TokenName;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.TxOutRef;
import org.julclang.ledger.Value;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.ScriptContextTestBuilder;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema.Entry;
import org.zeroj.examples.pedersen.PedersenVectorSchemaBindingTest.Deployment;
import org.zeroj.examples.pedersen.PedersenVectorSchemaBindingTest.Opening;
import org.zeroj.examples.pedersen.PedersenVectorSchemaBindingTest.Presentation;
import org.zeroj.examples.pedersen.onchain.VectorCommitmentConsumerValidator;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * ADR-0051 M4: the {@code pedersen-jubjub-vector-v1} cross-schema and relabelling scenarios,
 * repeated against the on-chain consumer {@link VectorCommitmentConsumerValidator} in the Julc VM.
 *
 * <p>One applied validator per schema plays the verifier's registry entry (verification key and
 * expected digest are script parameters). Issuance records are reference inputs holding the
 * issuance token with inline datum {@code (u, v, σ)}.
 */
class VectorCommitmentConsumerOnChainTest extends ContractTest {

    private static final byte[] POLICY = filled(28, (byte) 0x1e);
    private static final byte[] TOKEN = "pedersen-issuance".getBytes(StandardCharsets.US_ASCII);
    private static final Address REGISTRY = new Address(
            new Credential.ScriptCredential(ScriptHash.of(filled(28, (byte) 0x2e))), Optional.empty());
    private static final Address CONSUMER = new Address(
            new Credential.ScriptCredential(ScriptHash.of(filled(28, (byte) 0x3e))), Optional.empty());

    private static final List<Entry> ENTRIES = List.of(new Entry("amount", 64), new Entry("asset", 32));
    private static final PedersenVectorSchema A = PedersenVectorSchema.of("zeroj.example.balance", 1, ENTRIES);
    /** Same dimension and widths as A; index 0 means something else. */
    private static final PedersenVectorSchema B = PedersenVectorSchema.of("zeroj.example.balance", 1,
            List.of(new Entry("fee", 64), new Entry("asset", 32)));

    private static Deployment deployA;
    private static Deployment deployB;
    private static Program consumerA;
    private static Program consumerB;
    private static Opening opening;
    private static PedersenVectorCommitment issuedUnderA;
    private static Presentation honestA;
    private static Presentation adversaryB;

    @BeforeAll
    static void setup() throws Exception {
        deployA = PedersenVectorSchemaBindingTest.deploy(A, 41);
        deployB = PedersenVectorSchemaBindingTest.deploy(B, 42);
        var self = new VectorCommitmentConsumerOnChainTest();
        consumerA = self.consumer(A, deployA);
        consumerB = self.consumer(B, deployB);

        opening = PedersenVectorSchemaBindingTest.opening();
        issuedUnderA = PedersenVectorCommitment.commit(A, opening.values(), opening.blinding());
        honestA = PedersenVectorSchemaBindingTest.prove(deployA, A.digest(), issuedUnderA, opening);
        var relabelled = PedersenVectorCommitment.commit(B, opening.values(), opening.blinding());
        adversaryB = PedersenVectorSchemaBindingTest.prove(deployB, B.digest(), relabelled, opening);
    }

    @Test
    @DisplayName("Honest: a commitment issued under A, presented to A's consumer with its record, is accepted")
    void honestAccepted() {
        var result = evaluate(consumerA, context(honestA, record(issuedUnderA, A, true)));
        assertSuccess(result);
        System.out.println("[VectorCommitmentConsumerValidator] budget consumed: " + result.budgetConsumed());
    }

    @Test
    @DisplayName("Cross-schema: a proof made under B is rejected by A's consumer, record or not")
    void crossSchemaRejected() {
        rejected(consumerA, context(adversaryB, record(issuedUnderA, A, true)), "B proof at A's consumer");
        rejected(consumerA, context(adversaryB, record(issuedUnderA, B, true)), "B proof with a B record at A's consumer");
    }

    @Test
    @DisplayName("Relabelling: a fresh valid B proof for a commitment issued under A is rejected by B's consumer")
    void relabellingRejected() {
        rejected(consumerB, context(adversaryB, record(issuedUnderA, A, true)), "record binds the commitment to A");
        rejected(consumerB, context(adversaryB, null), "no record: fail closed");
        rejected(consumerB, context(adversaryB, record(issuedUnderA, B, false)),
                "a B-labelled record without the issuance token");
    }

    @Test
    @DisplayName("Control: the same commitment genuinely issued under B is accepted by B's consumer")
    void genuineBIssuanceAccepted() {
        assertSuccess(evaluate(consumerB, context(adversaryB, record(issuedUnderA, B, true))));
    }

    @Test
    @DisplayName("A record for a different commitment, or a tampered proof, is rejected")
    void otherMismatchesRejected() {
        var other = PedersenVectorCommitment.commit(A, opening.values(),
                opening.blinding().add(BigInteger.ONE));
        rejected(consumerA, context(honestA, record(other, A, true)), "record for another commitment");
        byte[] proofBytesTampered = ProverToCardano.compressProof(honestA.proof()).piA().clone();
        proofBytesTampered[proofBytesTampered.length - 1] ^= 1;
        rejected(consumerA, context(honestA, record(issuedUnderA, A, true), proofBytesTampered), "tampered proof");
    }

    // ------------------------------------------------------------------
    //  Harness
    // ------------------------------------------------------------------

    private Program consumer(PedersenVectorSchema schema, Deployment d) {
        SnarkjsToCardano.VkCompressed vk = ProverToCardano.compressVk(d.keys());
        PlutusData[] ic = new PlutusData[vk.ic().size()];
        for (int i = 0; i < ic.length; i++) ic[i] = PlutusData.bytes(vk.ic().get(i));
        return compileValidator(VectorCommitmentConsumerValidator.class, Path.of("src/test/java"))
                .program()
                .applyParams(
                        PlutusData.bytes(digestBytes(schema)),
                        PlutusData.bytes(POLICY),
                        PlutusData.bytes(TOKEN),
                        PlutusData.bytes(vk.alpha()),
                        PlutusData.bytes(vk.beta()),
                        PlutusData.bytes(vk.gamma()),
                        PlutusData.bytes(vk.delta()),
                        PlutusData.list(ic));
    }

    /** An issuance record output: optionally holding the issuance token, datum (u, v, σ). */
    private static TxOut record(PedersenVectorCommitment c, PedersenVectorSchema recordedSchema, boolean withToken) {
        Value value = Value.lovelace(BigInteger.valueOf(2_000_000));
        if (withToken) {
            value = value.merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(TOKEN), BigInteger.ONE));
        }
        PlutusData datum = PlutusData.constr(0,
                PlutusData.integer(c.point().affineU()),
                PlutusData.integer(c.point().affineV()),
                PlutusData.integer(recordedSchema.digest()));
        return new TxOut(REGISTRY, value, new OutputDatum.OutputDatumInline(datum), Optional.empty());
    }

    private PlutusData context(Presentation p, TxOut recordOutput) {
        return context(p, recordOutput, null);
    }

    private PlutusData context(Presentation p, TxOut recordOutput, byte[] piAOverride) {
        var compressed = ProverToCardano.compressProof(p.proof());
        PlutusData redeemer = PlutusData.constr(0,
                PlutusData.integer(p.publicInputs()[1]),
                PlutusData.integer(p.publicInputs()[2]),
                PlutusData.bytes(piAOverride != null ? piAOverride : compressed.piA()),
                PlutusData.bytes(compressed.piB()),
                PlutusData.bytes(compressed.piC()));
        TxOutRef ownRef = TestDataBuilder.randomTxOutRef_typed();
        PlutusData unit = PlutusData.constr(0);
        TxOut own = new TxOut(CONSUMER, Value.lovelace(BigInteger.valueOf(2_000_000)),
                new OutputDatum.OutputDatumInline(unit), Optional.empty());
        ScriptContextTestBuilder builder = spendingContext(ownRef, unit)
                .input(new TxInInfo(ownRef, own))
                .redeemer(redeemer);
        if (recordOutput != null) {
            builder.referenceInput(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), recordOutput));
        }
        return builder.buildPlutusData();
    }

    private void rejected(Program program, PlutusData context, String scenario) {
        EvalResult result = evaluate(program, context);
        assertFalse(result instanceof EvalResult.Success, scenario + " must be rejected");
    }

    private static byte[] digestBytes(PedersenVectorSchema schema) {
        byte[] raw = schema.digest().toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    private static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
