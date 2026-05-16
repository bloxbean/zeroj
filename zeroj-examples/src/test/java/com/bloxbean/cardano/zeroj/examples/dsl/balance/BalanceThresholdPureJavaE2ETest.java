package com.bloxbean.cardano.zeroj.examples.dsl.balance;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.*;
import com.bloxbean.cardano.zeroj.bls12381.field.*;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full-stack E2E for BalanceThreshold: circuit → pure Java prove → off-chain verify → Julc VM on-chain verify.
 *
 * <p>This circuit has 2 public inputs (threshold, isAboveThreshold), matching the generic
 * {@link Groth16BLS12381Verifier} (3 IC points = IC[0] + pub0*IC[1] + pub1*IC[2]).</p>
 *
 * <h3>DEV/TEST (this test)</h3>
 * <p>Uses {@code PowersOfTauBLS381.generate(8)} — for development only.</p>
 *
 * <h3>PRODUCTION</h3>
 * <p>Use MPC ceremony .ptau or snarkjs .zkey. See {@code ZkeyImporterBLS381}.</p>
 */
class BalanceThresholdPureJavaE2ETest {

    @Test
    void devTau_balanceThreshold_fullStack() {
        // === Step 1: Circuit ===
        var circuit = BalanceThresholdCircuit.build();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        var constraints = r1cs.constraints();

        System.out.println("BalanceThreshold: " + r1cs.numConstraints() + " constraints, "
                + r1cs.numPublicInputs() + " public inputs");

        // === Step 2: Witness (balance=1000, threshold=500 → isAboveThreshold=1) ===
        BigInteger balance = BigInteger.valueOf(1000);
        BigInteger threshold = BigInteger.valueOf(500);
        BigInteger isAboveThreshold = BigInteger.ONE;

        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "balance", List.of(balance),
                "threshold", List.of(threshold),
                "isAboveThreshold", List.of(isAboveThreshold)), CurveId.BLS12_381);

        // === Step 3: Dev setup ===
        var srs = PowersOfTauBLS381.generate(8); // 2^8 = 256 >= 132 constraints
        var setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());
        var pk = setupResult.provingKey();

        // === Step 4: PROVE ===
        var proof = Groth16ProverBLS381.prove(pk, witness, constraints, r1cs.numWires());
        assertTrue(proof.a().isOnCurve());
        assertTrue(proof.b().isOnCurve());
        assertTrue(proof.c().isOnCurve());
        System.out.println("Proof generated (pure Java BLS12-381)");

        // === Step 5: Off-chain pairing verification ===
        BigInteger[] pubInputs = new BigInteger[r1cs.numPublicInputs()];
        for (int i = 0; i < pubInputs.length; i++) pubInputs[i] = witness[i + 1];

        boolean offChainOk = verifyOffChain(proof, setupResult, pubInputs);
        assertTrue(offChainOk, "Off-chain pairing verification MUST pass");
        System.out.println("Off-chain pairing: PASSED");

        System.out.println("=== BalanceThreshold E2E (dev tau): off-chain COMPLETE ===");
        // On-chain Julc VM verification runs in the zeroj-onchain-julc module
        // where compileValidator(Groth16BLS12381Verifier.class) can access Julc bytecode.
        // Use ProverToCardano.compressVk/compressProof to convert for on-chain submission.
    }

    private boolean verifyOffChain(com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381 proof,
                                    Groth16SetupBLS381.SetupResult setupResult,
                                    BigInteger[] pubInputs) {
        var pk = setupResult.provingKey();
        var piA = toG1(proof.a());
        var piB = toG2(proof.b());
        var piC = toG1(proof.c());

        var ic = setupResult.ic();
        G1Point vkX = toG1(ic[0]);
        for (int i = 0; i < pubInputs.length; i++) {
            vkX = vkX.add(toG1(ic[i + 1]).scalarMul(pubInputs[i]));
        }

        return BLS12381Pairing.pairingCheck(
                new G1Point[]{piA, toG1(pk.alphaG1()).negate(), vkX.negate(), piC.negate()},
                new G2Point[]{piB, toG2(pk.betaG2()), toG2(setupResult.gammaG2()), toG2(pk.deltaG2())});
    }

    private static G1Point toG1(com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2(com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
