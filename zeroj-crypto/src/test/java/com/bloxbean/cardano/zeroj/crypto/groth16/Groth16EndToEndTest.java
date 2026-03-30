package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BN254;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.BN254Pairing;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.Fp;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.Fp2;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.G1Point;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.G2Point;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end test: .zkey + .wtns → pure Java Groth16 prove → pairing verify.
 *
 * <p>This test uses:
 * <ul>
 *   <li>snarkjs .zkey: pre-generated trusted setup (multiplier circuit: c = a * b)</li>
 *   <li>snarkjs .wtns: pre-computed witness (a=3, b=11, c=33)</li>
 *   <li>zeroj-crypto: Groth16Prover for pure Java proof generation</li>
 *   <li>zeroj-verifier-groth16: BN254Pairing for proof verification</li>
 * </ul>
 *
 * <p>This closes the full pure Java ZK proving loop — zero native dependencies.</p>
 */
class Groth16EndToEndTest {

    private static final String ZKEY_PATH = "/test-circuits/multiplier/multiplier.zkey";
    private static final String WTNS_PATH = "/test-circuits/multiplier/multiplier_witness.wtns";
    private static final String R1CS_PATH = "/test-circuits/multiplier/multiplier.r1cs";
    private static final String VK_PATH = "/test-circuits/multiplier/verification_key.json";

    /**
     * Full pipeline: .zkey + .wtns → Groth16Prover.prove() → BN254 pairing verify.
     * All pure Java — zero native dependencies.
     */
    @Test
    void fullPipeline_multiplier_proveAndVerify() throws IOException {
        // === Step 1: Import .zkey (proving key + constraints) ===
        var zkeyData = ZkeyImporter.importZkeyFull(
                getClass().getResourceAsStream(ZKEY_PATH).readAllBytes());
        var pk = zkeyData.provingKey();
        assertFalse(pk.alphaG1().isInfinity(), "alpha must not be infinity");
        assertTrue(pk.alphaG1().isOnCurve(), "alpha must be on curve");

        // === Step 2: Import .wtns (witness) ===
        var witness = ZkeyImporter.importWtns(getClass().getResourceAsStream(WTNS_PATH));
        assertEquals(BigInteger.ONE, witness[0], "witness[0] = 1");
        assertEquals(BigInteger.valueOf(33), witness[1], "c=33");

        // === Step 3: PROVE (pure Java!) ===
        var proof = Groth16Prover.prove(pk, witness, zkeyData.constraints(), zkeyData.numWires());

        assertNotNull(proof);
        assertFalse(proof.a().isInfinity(), "Proof A should not be infinity");
        assertFalse(proof.c().isInfinity(), "Proof C should not be infinity");
        assertFalse(proof.b().isInfinity(), "Proof B should not be infinity");
        assertTrue(proof.a().isOnCurve(), "Proof A must be on BN254 G1 curve");
        assertTrue(proof.b().isOnCurve(), "Proof B must be on BN254 G2 twist curve");
        assertTrue(proof.c().isOnCurve(), "Proof C must be on BN254 G1 curve");

        System.out.println("Proof generated successfully (pure Java):");
        System.out.println("  A.x = " + proof.a().xBigInt());
        System.out.println("  C.x = " + proof.c().xBigInt());

        // === Step 4: VERIFY via BN254 pairing check ===
        var vkJson = new String(getClass().getResourceAsStream(VK_PATH).readAllBytes());
        var vk = com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec.parseVerificationKey(vkJson);

        var piA = toVerifierG1(proof.a());
        var piB = toVerifierG2(proof.b());
        var piC = toVerifierG1(proof.c());

        var alpha = parseG1(vk.vkAlpha1());
        var beta = parseG2(vk.vkBeta2());
        var gamma = parseG2(vk.vkGamma2());
        var delta = parseG2(vk.vkDelta2());

        // vk_x = IC[0] + sum(pub_i * IC[i+1])
        var vkX = parseG1(vk.ic().get(0));
        for (int i = 0; i < vk.nPublic(); i++) {
            var icPoint = parseG1(vk.ic().get(i + 1));
            vkX = vkX.add(icPoint.scalarMul(witness[i + 1])); // public inputs = witness[1..nPublic]
        }

        // Pairing check: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1
        boolean valid = BN254Pairing.pairingCheck(
                new G1Point[]{piA, alpha.negate(), vkX.negate(), piC.negate()},
                new G2Point[]{piB, beta, gamma, delta}
        );

        assertTrue(valid, "Groth16 proof MUST verify via BN254 pairing check!\n"
                + "This proves the full pure Java ZK pipeline works.");

        System.out.println("VERIFIED! Pure Java Groth16 proof is VALID.");
        System.out.println("Pipeline: .zkey + .wtns -> prove (pure Java) -> pairing check -> VALID");
    }

    /**
     * Wrong witness produces a proof that fails verification against correct public inputs.
     */
    @Test
    void tamperedWitness_failsVerification() throws IOException {
        var zkeyData2 = ZkeyImporter.importZkeyFull(
                getClass().getResourceAsStream(ZKEY_PATH).readAllBytes());

        var witness = ZkeyImporter.importWtns(getClass().getResourceAsStream(WTNS_PATH));
        // Tamper: change c from 33 to 99
        witness[1] = BigInteger.valueOf(99);

        var proof = Groth16Prover.prove(zkeyData2.provingKey(), witness,
                zkeyData2.constraints(), zkeyData2.numWires());
        assertNotNull(proof);

        // Verify against the ORIGINAL public input (33)
        var vkJson = new String(getClass().getResourceAsStream(VK_PATH).readAllBytes());
        var vk = com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec.parseVerificationKey(vkJson);

        var vkX = parseG1(vk.ic().get(0));
        // Use original c=33 (not tampered 99)
        vkX = vkX.add(parseG1(vk.ic().get(1)).scalarMul(BigInteger.valueOf(33)));
        if (vk.nPublic() > 1) {
            vkX = vkX.add(parseG1(vk.ic().get(2)).scalarMul(witness[2]));
        }

        boolean valid = BN254Pairing.pairingCheck(
                new G1Point[]{toVerifierG1(proof.a()), parseG1(vk.vkAlpha1()).negate(),
                        vkX.negate(), toVerifierG1(proof.c()).negate()},
                new G2Point[]{toVerifierG2(proof.b()), parseG2(vk.vkBeta2()),
                        parseG2(vk.vkGamma2()), parseG2(vk.vkDelta2())}
        );

        assertFalse(valid, "Tampered witness proof should NOT verify against original public inputs");
    }

    /**
     * Tamper a PRIVATE wire value (not the public output), then verify against the
     * claimed (correct) public inputs. The proof must fail even though public inputs
     * are unchanged — this ensures the private witness is actually bound by the proof.
     *
     * <p>Circuit: c = a * b.  Witness: a=3, b=11, c=33.
     * We tamper b (a private wire) from 11 → 7 while leaving public input c=33 intact.
     * The R1CS relation 3*7 = 21 != 33 is violated, so the proof must not verify.</p>
     */
    @Test
    void tamperedPrivateWire_failsVerification() throws IOException {
        var zkeyData = ZkeyImporter.importZkeyFull(
                getClass().getResourceAsStream(ZKEY_PATH).readAllBytes());
        var pk = zkeyData.provingKey();

        var witness = ZkeyImporter.importWtns(getClass().getResourceAsStream(WTNS_PATH));
        assertEquals(BigInteger.valueOf(33), witness[1], "public output c=33");

        // Tamper a PRIVATE wire: change b from 11 to 7
        // In the multiplier circuit, the wire layout is [1, c, a, b]
        // witness[3] = b (private), witness[1] = c (public)
        witness[3] = BigInteger.valueOf(7);

        var proof = Groth16Prover.prove(pk, witness, zkeyData.constraints(), zkeyData.numWires());
        assertNotNull(proof);

        // Verify against the CORRECT public input c=33
        var vkJson = new String(getClass().getResourceAsStream(VK_PATH).readAllBytes());
        var vk = com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec.parseVerificationKey(vkJson);

        var vkX = parseG1(vk.ic().get(0));
        // Public input is c=33 (correct, untampered)
        vkX = vkX.add(parseG1(vk.ic().get(1)).scalarMul(BigInteger.valueOf(33)));
        if (vk.nPublic() > 1) {
            vkX = vkX.add(parseG1(vk.ic().get(2)).scalarMul(witness[2]));
        }

        boolean valid = BN254Pairing.pairingCheck(
                new G1Point[]{toVerifierG1(proof.a()), parseG1(vk.vkAlpha1()).negate(),
                        vkX.negate(), toVerifierG1(proof.c()).negate()},
                new G2Point[]{toVerifierG2(proof.b()), parseG2(vk.vkBeta2()),
                        parseG2(vk.vkGamma2()), parseG2(vk.vkDelta2())}
        );

        assertFalse(valid,
                "Tampered PRIVATE wire proof should NOT verify — the R1CS relation is violated "
                        + "even though public inputs are correct");
    }

    /**
     * Cubic circuit: x^3 + x + 5 = y (multiple constraints, larger domain).
     * This tests that the prover works beyond the trivial 1-constraint multiplier.
     */
    @Test
    void cubicCircuit_proveAndVerify() throws IOException {
        var zkeyData = ZkeyImporter.importZkeyFull(
                getClass().getResourceAsStream("/test-circuits/cubic/cubic.zkey").readAllBytes());
        var witness = ZkeyImporter.importWtns(
                getClass().getResourceAsStream("/test-circuits/cubic/cubic_witness.wtns"));

        assertTrue(zkeyData.numConstraints() > 1,
                "Cubic circuit should have multiple constraints, got " + zkeyData.numConstraints());

        var proof = Groth16Prover.prove(zkeyData.provingKey(), witness,
                zkeyData.constraints(), zkeyData.numWires());

        assertNotNull(proof);
        assertTrue(proof.a().isOnCurve(), "A on curve");
        assertTrue(proof.b().isOnCurve(), "B on curve");
        assertTrue(proof.c().isOnCurve(), "C on curve");

        // Verify via pairing
        var vkJson = new String(getClass().getResourceAsStream("/test-circuits/cubic/verification_key.json").readAllBytes());
        var vk = com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec.parseVerificationKey(vkJson);

        var vkX = parseG1(vk.ic().get(0));
        for (int i = 0; i < vk.nPublic(); i++) {
            vkX = vkX.add(parseG1(vk.ic().get(i + 1)).scalarMul(witness[i + 1]));
        }

        boolean valid = BN254Pairing.pairingCheck(
                new G1Point[]{toVerifierG1(proof.a()), parseG1(vk.vkAlpha1()).negate(),
                        vkX.negate(), toVerifierG1(proof.c()).negate()},
                new G2Point[]{toVerifierG2(proof.b()), parseG2(vk.vkBeta2()),
                        parseG2(vk.vkGamma2()), parseG2(vk.vkDelta2())}
        );

        assertTrue(valid, "Cubic circuit proof should verify");
        System.out.println("Cubic circuit: VERIFIED (pure Java)");
    }

    /**
     * Validates that validateWitness rejects an invalid witness with a clear error.
     */
    @Test
    void invalidWitness_validateWitnessThrows() throws IOException {
        var r1csData = R1CSImporter.importR1CS(getClass().getResourceAsStream(R1CS_PATH));
        var witness = ZkeyImporter.importWtns(getClass().getResourceAsStream(WTNS_PATH));

        // Corrupt the witness
        witness[1] = BigInteger.valueOf(99);

        var ex = assertThrows(IllegalArgumentException.class, () ->
                Groth16Prover.validateWitness(r1csData.constraints(), witness, r1csData.numConstraints()));

        assertTrue(ex.getMessage().contains("does not satisfy"),
                "Error should mention constraint violation: " + ex.getMessage());
    }

    // --- Conversion helpers ---

    private static G1Point toVerifierG1(JacobianG1BN254.AffineG1 p) {
        if (p.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toVerifierG2(JacobianG2BN254.AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }

    private static G1Point parseG1(List<BigInteger> coords) {
        return G1Point.fromProjective(coords.get(0), coords.get(1), coords.get(2));
    }

    private static G2Point parseG2(List<List<BigInteger>> coords) {
        return G2Point.fromProjective(
                coords.get(0).get(0), coords.get(0).get(1),
                coords.get(1).get(0), coords.get(1).get(1),
                coords.get(2).get(0), coords.get(2).get(1));
    }
}
