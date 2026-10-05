package org.zeroj.examples.pedersen;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PolicyId;
import org.julclang.ledger.PubKeyHash;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.StakingCredential;
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
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
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
 * ADR-0051 M4: the {@code pedersen-jubjub-vector-v1} statement, provenance and context bindings,
 * against the on-chain consumer {@link VectorCommitmentConsumerValidator} in the Julc VM.
 *
 * <p>One applied validator per schema plays the verifier's registry entry. Claims are locked with
 * datum {@code Claim(beneficiary, u, v)}. Issuance records are reference inputs holding the
 * issuer-minted token named {@code blake2b_256(u ‖ v ‖ σ)} with inline datum {@code (u, v, σ)}.
 */
class VectorCommitmentConsumerOnChainTest extends ContractTest {

    private static final byte[] POLICY = filled(28, (byte) 0x1e);
    private static final byte[] BENEFICIARY = filled(28, (byte) 0x0b);
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
    private static PedersenVectorCommitment issued;
    private static Presentation honestA;
    private static Presentation adversaryB;

    /** What a spend presents: the claim datum fields, the proof, and the context around them. */
    record Spend(BigInteger claimU, BigInteger claimV, Presentation proof, byte[] piAOverride,
                 boolean signed, boolean extraScriptInput, boolean extraStakedInput, TxOut... references) {}

    @BeforeAll
    static void setup() throws Exception {
        deployA = PedersenVectorSchemaBindingTest.deploy(A, 41);
        deployB = PedersenVectorSchemaBindingTest.deploy(B, 42);
        var self = new VectorCommitmentConsumerOnChainTest();
        consumerA = self.consumer(A, deployA);
        consumerB = self.consumer(B, deployB);

        opening = PedersenVectorSchemaBindingTest.opening();
        issued = PedersenVectorCommitment.commit(A, opening.values(), opening.blinding());
        honestA = PedersenVectorSchemaBindingTest.prove(deployA, A.digest(), issued, opening);
        var relabelled = PedersenVectorCommitment.commit(B, opening.values(), opening.blinding());
        adversaryB = PedersenVectorSchemaBindingTest.prove(deployB, B.digest(), relabelled, opening);
    }

    @Test
    @DisplayName("Honest: a claim on a commitment issued under A, redeemed at A's consumer with its record, is accepted")
    void honestAccepted() {
        var result = evaluate(consumerA, context(honest(record(issued, A))));
        assertSuccess(result);
        System.out.println("[VectorCommitmentConsumerValidator] budget consumed: " + result.budgetConsumed());
    }

    @Test
    @DisplayName("Cross-schema: a proof made under B is rejected by A's consumer")
    void crossSchemaRejected() {
        rejected(consumerA, spend(adversaryB, record(issued, A)), "B proof at A's consumer");
        rejected(consumerA, spend(adversaryB, record(issued, B)), "B proof with a B record at A's consumer");
    }

    @Test
    @DisplayName("Relabelling: a fresh valid B proof for a commitment issued under A is rejected by B's consumer")
    void relabellingRejected() {
        rejected(consumerB, spend(adversaryB, record(issued, A)), "the only record binds the commitment to A");
        rejected(consumerB, spend(adversaryB), "no record: fail closed");
    }

    @Test
    @DisplayName("Control: the same commitment genuinely issued under B is accepted by B's consumer")
    void genuineBIssuanceAccepted() {
        assertSuccess(evaluate(consumerB, context(spend(adversaryB, record(issued, B)))));
    }

    @Test
    @DisplayName("Forged or moved records are rejected: fungible token name, token for another record, altered datum")
    void forgedRecordsRejected() {
        byte[] genericName = "pedersen-issuance".getBytes(StandardCharsets.US_ASCII);
        rejected(consumerA, spend(honestA, recordWith(genericName, issued, A)), "generic token name");
        var other = PedersenVectorCommitment.commit(A, opening.values(), opening.blinding().add(BigInteger.ONE));
        // The other record's token, moved to an output whose datum names this commitment.
        rejected(consumerA, spend(honestA, recordWith(tokenName(other, A), issued, A)), "token of another record");
        // This record's token, but a datum altered to another commitment.
        rejected(consumerA, spend(honestA, recordWith(tokenName(issued, A), other, A)), "altered datum");
        rejected(consumerA, spend(honestA, record(other, A)), "record for another commitment only");
    }

    @Test
    @DisplayName("Context binding: replay against another claim, missing signer, extra script input, non-canonical datum")
    void contextBindingRejected() {
        var otherClaim = PedersenVectorCommitment.commit(A, opening.values(), opening.blinding().add(BigInteger.TWO));
        rejected(consumerA, context(new Spend(otherClaim.point().affineU(), otherClaim.point().affineV(),
                honestA, null, true, false, false, record(otherClaim, A))), "proof replayed against another claim");
        rejected(consumerA, context(new Spend(u(issued), v(issued), honestA, null, false, false, false, record(issued, A))),
                "missing beneficiary signature");
        rejected(consumerA, context(new Spend(u(issued), v(issued), honestA, null, true, true, false, record(issued, A))),
                "a second input from the script address");
        rejected(consumerA, context(new Spend(u(issued), v(issued), honestA, null, true, false, true, record(issued, A))),
                "a second claim under the same script with a different staking credential");
        BigInteger nonCanonicalU = u(issued).add(JubjubCurve.BASE_FIELD_PRIME);
        rejected(consumerA, context(new Spend(nonCanonicalU, v(issued), honestA, null, true, false, false, record(issued, A))),
                "non-canonical claim coordinate");
        byte[] tampered = ProverToCardano.compressProof(honestA.proof()).piA().clone();
        tampered[tampered.length - 1] ^= 1;
        rejected(consumerA, context(new Spend(u(issued), v(issued), honestA, tampered, true, false, false, record(issued, A))),
                "tampered proof");
    }

    // ------------------------------------------------------------------
    //  Harness
    // ------------------------------------------------------------------

    /** {@code blake2b_256(I2OSP32(u) ‖ I2OSP32(v) ‖ I2OSP32(σ))}, as the validator computes it. */
    static byte[] tokenName(PedersenVectorCommitment c, PedersenVectorSchema schema) {
        byte[] preimage = new byte[96];
        put32(preimage, 0, c.point().affineU());
        put32(preimage, 32, c.point().affineV());
        put32(preimage, 64, schema.digest());
        return Blake2bUtil.blake2bHash256(preimage);
    }

    private Program consumer(PedersenVectorSchema schema, Deployment d) {
        SnarkjsToCardano.VkCompressed vk = ProverToCardano.compressVk(d.keys());
        PlutusData[] ic = new PlutusData[vk.ic().size()];
        for (int i = 0; i < ic.length; i++) ic[i] = PlutusData.bytes(vk.ic().get(i));
        byte[] digest = new byte[32];
        put32(digest, 0, schema.digest());
        return compileValidator(VectorCommitmentConsumerValidator.class, Path.of("src/test/java"))
                .program()
                .applyParams(
                        PlutusData.bytes(digest),
                        PlutusData.bytes(POLICY),
                        PlutusData.bytes(vk.alpha()),
                        PlutusData.bytes(vk.beta()),
                        PlutusData.bytes(vk.gamma()),
                        PlutusData.bytes(vk.delta()),
                        PlutusData.list(ic));
    }

    private static Spend honest(TxOut... references) {
        return spend(honestA, references);
    }

    private static Spend spend(Presentation p, TxOut... references) {
        return new Spend(u(issued), v(issued), p, null, true, false, false, references);
    }

    private static TxOut record(PedersenVectorCommitment c, PedersenVectorSchema schema) {
        return recordWith(tokenName(c, schema), c, schema);
    }

    private static TxOut recordWith(byte[] tokenName, PedersenVectorCommitment c, PedersenVectorSchema schema) {
        Value value = Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(tokenName), BigInteger.ONE));
        PlutusData datum = PlutusData.constr(0,
                PlutusData.integer(u(c)), PlutusData.integer(v(c)), PlutusData.integer(schema.digest()));
        return new TxOut(REGISTRY, value, new OutputDatum.OutputDatumInline(datum), Optional.empty());
    }

    private PlutusData context(Spend s) {
        var compressed = ProverToCardano.compressProof(s.proof().proof());
        PlutusData redeemer = PlutusData.constr(0,
                PlutusData.bytes(s.piAOverride() != null ? s.piAOverride() : compressed.piA()),
                PlutusData.bytes(compressed.piB()),
                PlutusData.bytes(compressed.piC()));
        PlutusData claim = PlutusData.constr(0,
                PlutusData.bytes(BENEFICIARY), PlutusData.integer(s.claimU()), PlutusData.integer(s.claimV()));
        TxOutRef ownRef = TestDataBuilder.randomTxOutRef_typed();
        TxOut own = new TxOut(CONSUMER, Value.lovelace(BigInteger.valueOf(2_000_000)),
                new OutputDatum.OutputDatumInline(claim), Optional.empty());
        ScriptContextTestBuilder builder = spendingContext(ownRef, claim)
                .input(new TxInInfo(ownRef, own))
                .redeemer(redeemer);
        if (s.signed()) builder.signer(BENEFICIARY);
        if (s.extraScriptInput()) {
            builder.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), own));
        }
        if (s.extraStakedInput()) {
            // Same script payment credential, different staking credential, same claim datum.
            Address staked = new Address(CONSUMER.credential(), Optional.of(new StakingCredential.StakingHash(
                    new Credential.PubKeyCredential(PubKeyHash.of(filled(28, (byte) 0x5a))))));
            builder.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(),
                    new TxOut(staked, own.value(), own.datum(), Optional.empty())));
        }
        for (TxOut reference : s.references()) {
            builder.referenceInput(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), reference));
        }
        return builder.buildPlutusData();
    }

    private void rejected(Program program, Spend s, String scenario) {
        rejected(program, context(s), scenario);
    }

    private void rejected(Program program, PlutusData context, String scenario) {
        EvalResult result = evaluate(program, context);
        assertFalse(result instanceof EvalResult.Success, scenario + " must be rejected");
    }

    private static BigInteger u(PedersenVectorCommitment c) {
        return c.point().affineU();
    }

    private static BigInteger v(PedersenVectorCommitment c) {
        return c.point().affineV();
    }

    private static void put32(byte[] out, int offset, BigInteger value) {
        byte[] raw = value.toByteArray();
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, offset + 32 - copy, copy);
    }

    private static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
