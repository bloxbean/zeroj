package com.bloxbean.cardano.zeroj.onchain.julc;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
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

    private static SnarkjsToCardano.VkCompressed sealedBidVk;
    private static SnarkjsToCardano.ProofCompressed sealedBidProof;
    private static List<BigInteger> sealedBidPublicInputs;
    private static TestProof threePublicInputs;

    @BeforeAll
    static void setup() throws Exception {
        String proofJson = loadResource("/test-circuits/sealed-bid-bls12381/proof.json");
        String vkJson = loadResource("/test-circuits/sealed-bid-bls12381/verification_key.json");
        String publicJson = loadResource("/test-circuits/sealed-bid-bls12381/public.json");

        sealedBidVk = SnarkjsToCardano.parseVk(vkJson);
        sealedBidProof = SnarkjsToCardano.parseProof(proofJson);
        sealedBidPublicInputs = SnarkjsToCardano.parsePublicInputs(publicJson);
        threePublicInputs = buildThreePublicInputProof();
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
    void emptyIcList_fails() {
        assertVerification(
                threePublicInputs.vk(),
                threePublicInputs.proof(),
                datum(threePublicInputs.publicInputs()),
                PlutusData.list(),
                false);
    }

    @Test
    void customValidator_composesGroth16LibraryWithDomainLogic_passes() {
        assertFirstInputBindingVerification(sealedBidPublicInputs.get(0), true);
    }

    @Test
    void customValidator_domainLogicFailure_fails() {
        assertFirstInputBindingVerification(sealedBidPublicInputs.get(0).add(BigInteger.ONE), false);
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

    private void assertFirstInputBindingVerification(BigInteger expectedFirstPublicInput,
                                                     boolean expectSuccess) {
        var compiled = compileValidator(Groth16BLS12381FirstInputBindingVerifier.class,
                Path.of("src/test/java"));
        var program = compiled.program().applyParams(
                PlutusData.integer(expectedFirstPublicInput),
                PlutusData.bytes(sealedBidVk.alpha()),
                PlutusData.bytes(sealedBidVk.beta()),
                PlutusData.bytes(sealedBidVk.gamma()),
                PlutusData.bytes(sealedBidVk.delta()),
                vkIcData(sealedBidVk.ic()));

        var datum = datum(sealedBidPublicInputs.get(0), sealedBidPublicInputs.get(1));
        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(sealedBidProof.piA()),
                PlutusData.bytes(sealedBidProof.piB()),
                PlutusData.bytes(sealedBidProof.piC()));

        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var ctx = spendingContext(txOutRef, datum)
                .redeemer(redeemer)
                .buildPlutusData();

        var result = evaluate(program, ctx);
        if (expectSuccess) {
            assertSuccess(result);
        } else {
            assertFailure(result);
        }
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
