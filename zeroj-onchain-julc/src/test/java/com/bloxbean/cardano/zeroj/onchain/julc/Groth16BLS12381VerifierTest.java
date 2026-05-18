package com.bloxbean.cardano.zeroj.onchain.julc;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Compatibility tests for the deprecated fixed two-public-input Groth16
 * BLS12-381 verifier using the Julc VM.
 * <p>
 * This demonstrates the full end-to-end flow:
 * 1. Parse snarkjs JSON artifacts → compressed BLS12-381 bytes
 * 2. Compile the on-chain verifier with VK params
 * 3. Evaluate with proof redeemer and public inputs datum
 * 4. Assert the pairing check passes in the Julc VM
 */
@SuppressWarnings("deprecation")
class Groth16BLS12381VerifierTest extends ContractTest {

    private static SnarkjsToCardano.VkCompressed vk;
    private static SnarkjsToCardano.ProofCompressed proof;
    private static List<BigInteger> publicInputs;

    @BeforeAll
    static void loadTestVectors() throws Exception {
        String proofJson = loadResource("/test-circuits/sealed-bid-bls12381/proof.json");
        String vkJson = loadResource("/test-circuits/sealed-bid-bls12381/verification_key.json");
        String publicJson = loadResource("/test-circuits/sealed-bid-bls12381/public.json");

        vk = SnarkjsToCardano.parseVk(vkJson);
        proof = SnarkjsToCardano.parseProof(proofJson);
        publicInputs = SnarkjsToCardano.parsePublicInputs(publicJson);
    }

    @Test
    void validProof_passes() {
        // 1. Compile validator
        var compiled = compileValidator(Groth16BLS12381Verifier.class);

        // 2. Apply VK params (compressed bytes)
        var program = compiled.program().applyParams(
                PlutusData.bytes(vk.alpha()),
                PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()),
                PlutusData.bytes(vk.delta()),
                PlutusData.bytes(vk.ic().get(0)),
                PlutusData.bytes(vk.ic().get(1)),
                PlutusData.bytes(vk.ic().get(2)));

        // 3. Build redeemer: Groth16Proof record → Constr(0, [piA, piB, piC])
        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(proof.piA()),
                PlutusData.bytes(proof.piB()),
                PlutusData.bytes(proof.piC()));

        // 4. Build datum: list of public inputs
        var datum = PlutusData.list(
                PlutusData.integer(publicInputs.get(0)),
                PlutusData.integer(publicInputs.get(1)));

        // 5. Build spending context
        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var ctx = spendingContext(txOutRef, datum)
                .redeemer(redeemer)
                .buildPlutusData();

        // 6. Evaluate
        var result = evaluate(program, ctx);

        // 7. Assert
        assertSuccess(result);
        System.out.println("[validProof_passes] Budget consumed: " + result.budgetConsumed());
    }

    @Test
    void invalidProof_fails() {
        // Same as validProof but tamper one byte of piA
        var compiled = compileValidator(Groth16BLS12381Verifier.class);
        var program = compiled.program().applyParams(
                PlutusData.bytes(vk.alpha()),
                PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()),
                PlutusData.bytes(vk.delta()),
                PlutusData.bytes(vk.ic().get(0)),
                PlutusData.bytes(vk.ic().get(1)),
                PlutusData.bytes(vk.ic().get(2)));

        // Tamper the proof: flip a byte in piA
        byte[] tamperedPiA = proof.piA().clone();
        tamperedPiA[10] ^= 0xFF;

        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(tamperedPiA),
                PlutusData.bytes(proof.piB()),
                PlutusData.bytes(proof.piC()));

        var datum = PlutusData.list(
                PlutusData.integer(publicInputs.get(0)),
                PlutusData.integer(publicInputs.get(1)));

        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var ctx = spendingContext(txOutRef, datum)
                .redeemer(redeemer)
                .buildPlutusData();

        var result = evaluate(program, ctx);
        assertFailure(result);
    }

    @Test
    void wrongPublicInputs_fails() {
        var compiled = compileValidator(Groth16BLS12381Verifier.class);
        var program = compiled.program().applyParams(
                PlutusData.bytes(vk.alpha()),
                PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()),
                PlutusData.bytes(vk.delta()),
                PlutusData.bytes(vk.ic().get(0)),
                PlutusData.bytes(vk.ic().get(1)),
                PlutusData.bytes(vk.ic().get(2)));

        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(proof.piA()),
                PlutusData.bytes(proof.piB()),
                PlutusData.bytes(proof.piC()));

        // Wrong public inputs: use incorrect values
        var datum = PlutusData.list(
                PlutusData.integer(99),
                PlutusData.integer(99));

        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var ctx = spendingContext(txOutRef, datum)
                .redeemer(redeemer)
                .buildPlutusData();

        var result = evaluate(program, ctx);
        assertFailure(result);
    }

    private static String loadResource(String path) throws IOException {
        try (var is = Groth16BLS12381VerifierTest.class.getResourceAsStream(path)) {
            if (is == null) throw new IOException("Resource not found: " + path);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
