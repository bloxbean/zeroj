package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.field.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end test: R1CS → BLS381 Groth16 setup → prove → pairing verify.
 *
 * <p>This closes the full pure Java ZK proving loop for BLS12-381:
 * prove with the BLS381 prover, verify with the BLS12381 pairing verifier.</p>
 */
class Groth16BLS381EndToEndTest {

    @Test
    void fullPipeline_multiplier_proveAndPairingVerify() {
        // Circuit: c = a * b (multiplier)
        // R1CS: 1 constraint, 4 wires [1, c, a, b]
        var constraints = List.of(
                new R1CSConstraint(
                        Map.of(2, BigInteger.ONE),    // A: wire 2 (a)
                        Map.of(3, BigInteger.ONE),    // B: wire 3 (b)
                        Map.of(1, BigInteger.ONE))    // C: wire 1 (c)
        );
        int numWires = 4;
        int numPublic = 1; // wire 1 = c (public output)

        // Step 1: Generate SRS
        var srs = PowersOfTauBLS381.generate(4);

        // Step 2: Setup (returns PK + VK components for pairing verification)
        var setupResult = Groth16SetupBLS381.setup(constraints, numWires, numPublic, srs.tauScalar());
        var pk = setupResult.provingKey();
        var gammaG2 = setupResult.gammaG2();
        var ic = setupResult.ic();

        assertTrue(pk.alphaG1().isOnCurve());
        assertTrue(pk.betaG2().isOnCurve());

        // Step 3: Witness: a=3, b=11, c=33
        BigInteger[] witness = {BigInteger.ONE, BigInteger.valueOf(33), BigInteger.valueOf(3), BigInteger.valueOf(11)};

        // Step 4: PROVE with BLS381 (with random blinding for zero-knowledge)
        var proof = Groth16ProverBLS381.prove(pk, witness, constraints, numWires);

        assertNotNull(proof);
        assertTrue(proof.a().isOnCurve(), "Proof A on BLS12-381 G1");
        assertTrue(proof.b().isOnCurve(), "Proof B on BLS12-381 G2");
        assertTrue(proof.c().isOnCurve(), "Proof C on BLS12-381 G1");

        // Step 5: VERIFY via BLS12-381 pairing check
        // Groth16 verification equation:
        //   e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
        // Equivalently:
        //   e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1
        //
        // Where vk_x = IC[0] + sum(pub_i * IC[i+1])

        G1Point piA = toG1(proof.a());
        G2Point piB = toG2(proof.b());
        G1Point piC = toG1(proof.c());

        G1Point alpha1 = toG1(pk.alphaG1());
        G2Point beta2 = toG2(pk.betaG2());
        G2Point gamma2 = toG2(gammaG2);
        G2Point delta2 = toG2(pk.deltaG2());

        // Compute vk_x = IC[0] + pub[0] * IC[1]
        G1Point vkX = toG1(ic[0]);
        BigInteger[] pubInputs = {BigInteger.valueOf(33)}; // c=33
        for (int i = 0; i < pubInputs.length; i++) {
            G1Point icPoint = toG1(ic[i + 1]);
            vkX = vkX.add(icPoint.scalarMul(pubInputs[i]));
        }

        // Pairing check: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1
        boolean verified = BLS12381Pairing.pairingCheck(
                new G1Point[]{piA, alpha1.negate(), vkX.negate(), piC.negate()},
                new G2Point[]{piB, beta2, gamma2, delta2});

        assertTrue(verified, "BLS12-381 Groth16 pairing verification MUST pass");

        System.out.println("BLS12-381 Groth16 end-to-end PROVED + VERIFIED (pure Java pairing check)!");

        // Step 6: Verify that a wrong public input fails
        G1Point badVkX = toG1(ic[0]);
        badVkX = badVkX.add(toG1(ic[1]).scalarMul(BigInteger.valueOf(99))); // wrong c=99

        boolean badVerified = BLS12381Pairing.pairingCheck(
                new G1Point[]{piA, alpha1.negate(), badVkX.negate(), piC.negate()},
                new G2Point[]{piB, beta2, gamma2, delta2});

        assertFalse(badVerified, "Pairing check must FAIL with wrong public input");
        System.out.println("Tampered public input correctly rejected by pairing check.");
    }

    // --- Conversion helpers: prover types → verifier types ---

    private static G1Point toG1(JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2(JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
