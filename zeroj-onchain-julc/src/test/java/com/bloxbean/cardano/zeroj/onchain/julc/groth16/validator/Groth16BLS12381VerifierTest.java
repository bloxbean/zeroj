package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.TxOutRef;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the arbitrary-public-input Groth16 BLS12-381 verifier in the Julc VM.
 */
class Groth16BLS12381VerifierTest extends ContractTest {

    private static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    private static SnarkjsToCardano.VkCompressed sealedBidVk;
    private static SnarkjsToCardano.ProofCompressed sealedBidProof;
    private static List<BigInteger> sealedBidPublicInputs;
    private static TestProof threePublicInputs;
    private static TestProof fourPublicInputs;

    @BeforeAll
    static void setup() throws Exception {
        String proofJson = loadResource("/test-circuits/sealed-bid-bls12381/proof.json");
        String vkJson = loadResource("/test-circuits/sealed-bid-bls12381/verification_key.json");
        String publicJson = loadResource("/test-circuits/sealed-bid-bls12381/public.json");

        sealedBidVk = SnarkjsToCardano.parseVk(vkJson);
        sealedBidProof = SnarkjsToCardano.parseProof(proofJson);
        sealedBidPublicInputs = SnarkjsToCardano.parsePublicInputs(publicJson);
        threePublicInputs = buildThreePublicInputProof();
        fourPublicInputs = buildFourPublicInputProof();
    }

    @Test
    void sealedBid_twoPublicInputs_passes() {
        assertEquals(3, sealedBidVk.ic().size(), "IC must have public input count + 1 entries");

        assertVerification(
                sealedBidVk,
                sealedBidProof,
                datum(sealedBidPublicInputs.get(0), sealedBidPublicInputs.get(1)),
                vkIcData(sealedBidVk.ic()),
                true);
    }

    @Test
    void threePublicInputs_pureJavaProof_passes() {
        assertEquals(4, threePublicInputs.vk().ic().size(), "IC must have public input count + 1 entries");

        assertVerification(
                threePublicInputs.vk(),
                threePublicInputs.proof(),
                datum(threePublicInputs.publicInputs()),
                vkIcData(threePublicInputs.vk().ic()),
                true);
    }

    @Test
    void threePublicInputs_wrongPublicInput_fails() {
        BigInteger[] publicInputs = threePublicInputs.publicInputs().clone();
        publicInputs[2] = publicInputs[2].add(BigInteger.ONE);

        assertVerification(
                threePublicInputs.vk(),
                threePublicInputs.proof(),
                datum(publicInputs),
                vkIcData(threePublicInputs.vk().ic()),
                false);
    }

    @Test
    void threePublicInputs_publicInputAboveScalarField_fails() {
        BigInteger[] publicInputs = threePublicInputs.publicInputs().clone();
        publicInputs[0] = publicInputs[0].add(FR);

        assertVerification(
                threePublicInputs.vk(),
                threePublicInputs.proof(),
                datum(publicInputs),
                vkIcData(threePublicInputs.vk().ic()),
                false);
    }

    @Test
    void threePublicInputs_negativePublicInput_fails() {
        BigInteger[] publicInputs = threePublicInputs.publicInputs().clone();
        publicInputs[0] = BigInteger.ONE.negate();

        assertVerification(
                threePublicInputs.vk(),
                threePublicInputs.proof(),
                datum(publicInputs),
                vkIcData(threePublicInputs.vk().ic()),
                false);
    }

    @Test
    void threePublicInputs_tooFewPublicInputs_fails() {
        assertVerification(
                threePublicInputs.vk(),
                threePublicInputs.proof(),
                datum(threePublicInputs.publicInputs()[0], threePublicInputs.publicInputs()[1]),
                vkIcData(threePublicInputs.vk().ic()),
                false);
    }

    @Test
    void threePublicInputs_tooManyPublicInputs_fails() {
        assertVerification(
                threePublicInputs.vk(),
                threePublicInputs.proof(),
                datum(
                        threePublicInputs.publicInputs()[0],
                        threePublicInputs.publicInputs()[1],
                        threePublicInputs.publicInputs()[2],
                        BigInteger.ONE),
                vkIcData(threePublicInputs.vk().ic()),
                false);
    }

    @Test
    void fourPublicInputs_fixedArityPath_passes() {
        assertEquals(5, fourPublicInputs.vk().ic().size(), "IC must have public input count + 1 entries");
        assertFixedFourVerification(fourPublicInputs.publicInputs(), true);
    }

    @Test
    void fourPublicInputs_fixedArityPathWrongInput_fails() {
        BigInteger[] publicInputs = fourPublicInputs.publicInputs().clone();
        publicInputs[3] = publicInputs[3].add(BigInteger.ONE);

        assertFixedFourVerification(publicInputs, false);
    }

    @Test
    void fourPublicInputs_fixedArityPublicInputAboveScalarField_fails() {
        BigInteger[] publicInputs = fourPublicInputs.publicInputs().clone();
        publicInputs[0] = publicInputs[0].add(FR);

        assertFixedFourVerification(publicInputs, false);
    }

    @Test
    void fourPublicInputs_fixedArityNegativePublicInput_fails() {
        BigInteger[] publicInputs = fourPublicInputs.publicInputs().clone();
        publicInputs[0] = BigInteger.ONE.negate();

        assertFixedFourVerification(publicInputs, false);
    }

    @Test
    void emptyIcList_fails() {
        assertVerification(
                threePublicInputs.vk(),
                threePublicInputs.proof(),
                datum(threePublicInputs.publicInputs()),
                PlutusData.list(),
                false);
    }

    @Test
    void proofInfinityPoint_fails() {
        var proof = new SnarkjsToCardano.ProofCompressed(
                compressedInfinityG1(),
                threePublicInputs.proof().piB(),
                threePublicInputs.proof().piC());

        assertVerification(
                threePublicInputs.vk(),
                proof,
                datum(threePublicInputs.publicInputs()),
                vkIcData(threePublicInputs.vk().ic()),
                false);
    }

    @Test
    void vkIcInfinityPoint_fails() {
        List<byte[]> ic = new ArrayList<>(threePublicInputs.vk().ic());
        ic.set(0, compressedInfinityG1());

        assertVerification(
                threePublicInputs.vk(),
                threePublicInputs.proof(),
                datum(threePublicInputs.publicInputs()),
                vkIcData(ic),
                false);
    }

    @Test
    void txOutRefBoundValidator_acceptsBoundSpendAndRejectsReplay() {
        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var boundPublicInput = txOutRefScalar(txOutRef);
        var boundProof = buildSinglePublicInputProof(boundPublicInput);
        var program = txOutRefBoundProgram(boundProof.vk());
        var datum = datum(boundProof.publicInputs());
        var redeemer = redeemer(boundProof.proof());

        var validCtx = spendingContext(txOutRef, datum)
                .redeemer(redeemer)
                .buildPlutusData();
        assertSuccess(evaluate(program, validCtx));

        var replayCtx = spendingContext(TestDataBuilder.randomTxOutRef_typed(), datum)
                .redeemer(redeemer)
                .buildPlutusData();
        assertFailure(evaluate(program, replayCtx));
    }

    private void assertVerification(SnarkjsToCardano.VkCompressed vk,
                                    SnarkjsToCardano.ProofCompressed proof,
                                    PlutusData datum,
                                    PlutusData vkIc,
                                    boolean expectSuccess) {
        var compiled = compileValidator(Groth16BLS12381Verifier.class);
        var program = compiled.program().applyParams(
                PlutusData.bytes(vk.alpha()),
                PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()),
                PlutusData.bytes(vk.delta()),
                vkIc);

        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(proof.piA()),
                PlutusData.bytes(proof.piB()),
                PlutusData.bytes(proof.piC()));

        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var ctx = spendingContext(txOutRef, datum)
                .redeemer(redeemer)
                .buildPlutusData();

        var result = evaluate(program, ctx);
        if (expectSuccess) {
            assertSuccess(result);
            System.out.println("[Groth16BLS12381Verifier] Budget consumed: " + result.budgetConsumed());
        } else {
            assertFailure(result);
        }
    }

    private void assertFixedFourVerification(BigInteger[] publicInputs, boolean expectSuccess) {
        var compiled = compileValidator(Groth16BLS12381FixedFourInputVerifier.class,
                Path.of("src/test/java"));
        var program = compiled.program().applyParams(
                PlutusData.bytes(fourPublicInputs.vk().alpha()),
                PlutusData.bytes(fourPublicInputs.vk().beta()),
                PlutusData.bytes(fourPublicInputs.vk().gamma()),
                PlutusData.bytes(fourPublicInputs.vk().delta()),
                vkIcData(fourPublicInputs.vk().ic()));

        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(fourPublicInputs.proof().piA()),
                PlutusData.bytes(fourPublicInputs.proof().piB()),
                PlutusData.bytes(fourPublicInputs.proof().piC()));

        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var ctx = spendingContext(txOutRef, datum(publicInputs))
                .redeemer(redeemer)
                .buildPlutusData();

        var result = evaluate(program, ctx);
        if (expectSuccess) {
            assertSuccess(result);
        } else {
            assertFailure(result);
        }
    }

    private static TestProof buildSinglePublicInputProof(BigInteger boundPublicInput) {
        var circuit = CircuitBuilder.create("txoutref-bound")
                .publicVar("bound")
                .secretVar("witness")
                .define(api -> api.assertEqual(api.var("bound"), api.var("witness")));

        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertEquals(1, r1cs.numPublicInputs(), "test circuit should have one public input");

        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "bound", List.of(boundPublicInput),
                "witness", List.of(boundPublicInput)), CurveId.BLS12_381);

        var srs = PowersOfTauBLS381.generate(8);
        var setupResult = Groth16SetupBLS381.setup(
                r1cs.constraints(),
                r1cs.numWires(),
                r1cs.numPublicInputs(),
                srs.tauScalar());
        var proof = Groth16ProverBLS381.prove(
                setupResult.provingKey(),
                witness,
                r1cs.constraints(),
                r1cs.numWires());

        return new TestProof(
                ProverToCardano.compressVk(setupResult),
                ProverToCardano.compressProof(proof),
                new BigInteger[] { witness[1] });
    }

    private static TestProof buildThreePublicInputProof() {
        var circuit = CircuitBuilder.create("three-public-linear")
                .publicVar("a")
                .publicVar("b")
                .publicVar("c")
                .secretVar("x")
                .define(api -> api.assertEqual(
                        api.add(api.mul(api.var("a"), api.var("x")), api.var("b")),
                        api.var("c")));

        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertEquals(3, r1cs.numPublicInputs(), "test circuit should have three public inputs");

        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(4)),
                "c", List.of(BigInteger.valueOf(25)),
                "x", List.of(BigInteger.valueOf(7))), CurveId.BLS12_381);

        var srs = PowersOfTauBLS381.generate(8);
        var setupResult = Groth16SetupBLS381.setup(
                r1cs.constraints(),
                r1cs.numWires(),
                r1cs.numPublicInputs(),
                srs.tauScalar());
        var proof = Groth16ProverBLS381.prove(
                setupResult.provingKey(),
                witness,
                r1cs.constraints(),
                r1cs.numWires());

        assertTrue(proof.a().isOnCurve());
        assertTrue(proof.b().isOnCurve());
        assertTrue(proof.c().isOnCurve());

        return new TestProof(
                ProverToCardano.compressVk(setupResult),
                ProverToCardano.compressProof(proof),
                new BigInteger[] { witness[1], witness[2], witness[3] });
    }

    private static TestProof buildFourPublicInputProof() {
        var circuit = CircuitBuilder.create("four-public-linear")
                .publicVar("a")
                .publicVar("b")
                .publicVar("c")
                .publicVar("d")
                .secretVar("x")
                .define(api -> api.assertEqual(
                        api.add(api.add(api.mul(api.var("a"), api.var("x")), api.var("b")), api.var("c")),
                        api.var("d")));

        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertEquals(4, r1cs.numPublicInputs(), "test circuit should have four public inputs");

        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(4)),
                "c", List.of(BigInteger.valueOf(5)),
                "d", List.of(BigInteger.valueOf(30)),
                "x", List.of(BigInteger.valueOf(7))), CurveId.BLS12_381);

        var srs = PowersOfTauBLS381.generate(8);
        var setupResult = Groth16SetupBLS381.setup(
                r1cs.constraints(),
                r1cs.numWires(),
                r1cs.numPublicInputs(),
                srs.tauScalar());
        var proof = Groth16ProverBLS381.prove(
                setupResult.provingKey(),
                witness,
                r1cs.constraints(),
                r1cs.numWires());

        assertTrue(proof.a().isOnCurve());
        assertTrue(proof.b().isOnCurve());
        assertTrue(proof.c().isOnCurve());

        return new TestProof(
                ProverToCardano.compressVk(setupResult),
                ProverToCardano.compressProof(proof),
                new BigInteger[] { witness[1], witness[2], witness[3], witness[4] });
    }

    private static PlutusData datum(BigInteger... inputs) {
        PlutusData[] values = new PlutusData[inputs.length];
        for (int i = 0; i < inputs.length; i++) {
            values[i] = PlutusData.integer(inputs[i]);
        }
        return PlutusData.list(values);
    }

    private static PlutusData vkIcData(List<byte[]> ic) {
        List<PlutusData> values = new ArrayList<>();
        for (byte[] point : ic) {
            values.add(PlutusData.bytes(point));
        }
        return PlutusData.list(values.toArray(new PlutusData[0]));
    }

    private com.bloxbean.cardano.julc.core.Program txOutRefBoundProgram(SnarkjsToCardano.VkCompressed vk) {
        var compiled = compileValidator(Groth16BLS12381TxOutRefBindingVerifier.class);
        return compiled.program().applyParams(
                PlutusData.bytes(vk.alpha()),
                PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()),
                PlutusData.bytes(vk.delta()),
                vkIcData(vk.ic()));
    }

    private static PlutusData redeemer(SnarkjsToCardano.ProofCompressed proof) {
        return PlutusData.constr(0,
                PlutusData.bytes(proof.piA()),
                PlutusData.bytes(proof.piB()),
                PlutusData.bytes(proof.piC()));
    }

    private static BigInteger txOutRefScalar(TxOutRef txOutRef) {
        byte[] preimage = concat(txOutRef.txId().hash(), fixedBigEndian(txOutRef.index(), 32));
        return new BigInteger(1, Blake2bUtil.blake2bHash256(preimage)).mod(FR);
    }

    private static byte[] fixedBigEndian(BigInteger value, int size) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[size];
        int copy = Math.min(raw.length, size);
        System.arraycopy(raw, raw.length - copy, out, size - copy, copy);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] compressedInfinityG1() {
        byte[] bytes = new byte[48];
        bytes[0] = (byte) 0xC0;
        return bytes;
    }

    private static String loadResource(String path) throws IOException {
        try (var is = Groth16BLS12381VerifierTest.class.getResourceAsStream(path)) {
            if (is == null) throw new IOException("Resource not found: " + path);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private record TestProof(SnarkjsToCardano.VkCompressed vk,
                             SnarkjsToCardano.ProofCompressed proof,
                             BigInteger[] publicInputs) {}
}
