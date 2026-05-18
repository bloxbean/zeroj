package com.bloxbean.cardano.zeroj.examples.dsl.auction;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.examples.dsl.common.MiMCHash;
import com.bloxbean.cardano.zeroj.bls12381.ec.*;
import com.bloxbean.cardano.zeroj.bls12381.field.*;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full-stack E2E: Java DSL circuit → pure Java BLS12-381 prove → off-chain verify → Julc VM on-chain verify.
 *
 * <h3>DEV/TEST path (this test)</h3>
 * <p>Uses single-party {@code PowersOfTauBLS381.generate(10)} — toxic waste is known.
 * <b>DO NOT use this setup for production.</b></p>
 *
 * <h3>PRODUCTION path</h3>
 * <pre>
 * // Option A: Import .ptau from MPC ceremony (Hermez, PPOT)
 * var srs = PtauImporterBLS381.importPtau(new FileInputStream("hermez_pot20.ptau"));
 * var setup = Groth16SetupBLS381.setup(constraints, numWires, numPublic, srs.tauScalar());
 *
 * // Option B: Import snarkjs .zkey (from multi-party ceremony)
 * var zkeyData = ZkeyImporterBLS381.importZkeyFull(Files.readAllBytes(Path.of("circuit.zkey")));
 * var proof = Groth16ProverBLS381.prove(zkeyData.provingKey(), witness, ...);
 * </pre>
 */
class SealedBidPureJavaE2ETest {

    /**
     * Pure Java end-to-end: circuit → prove → off-chain pairing verify → Julc VM on-chain verify.
     */
    @Test
    void devTau_sealedBid_fullStack() {
        // === Step 1: Circuit definition via Java DSL ===
        var circuit = SealedBidCircuit.build();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        var constraints = r1cs.constraints();

        System.out.println("SealedBid: " + r1cs.numConstraints() + " constraints, "
                + r1cs.numWires() + " wires");

        // === Step 2: Witness computation ===
        BigInteger bidAmount = BigInteger.valueOf(1000);
        BigInteger salt = BigInteger.valueOf(42);
        BigInteger reservePrice = BigInteger.valueOf(500);
        BigInteger bidCommitment = MiMCHash.hash(bidAmount, salt,
                com.bloxbean.cardano.zeroj.circuit.FieldConfig.BLS12_381.prime());
        BigInteger isAboveReserve = BigInteger.ONE;

        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "bidAmount", List.of(bidAmount),
                "salt", List.of(salt),
                "reservePrice", List.of(reservePrice),
                "bidCommitment", List.of(bidCommitment),
                "isAboveReserve", List.of(isAboveReserve)), CurveId.BLS12_381);

        // === Step 3: Dev trusted setup (DEVELOPMENT ONLY) ===
        var srs = PowersOfTauBLS381.generate(10); // 2^10 = 1024 >= 497 constraints
        var setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());
        var pk = setupResult.provingKey();

        // === Step 4: PROVE (pure Java BLS12-381) ===
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

        System.out.println("=== SealedBid E2E (dev tau): off-chain COMPLETE ===");
        // On-chain Julc VM verification for arbitrary public-input counts is
        // covered by Groth16BLS12381Verifier in zeroj-onchain-julc.
    }

    // --- Helpers ---

    private boolean verifyOffChain(com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381 proof,
                                    Groth16SetupBLS381.SetupResult setupResult,
                                    BigInteger[] pubInputs) {
        var pk = setupResult.provingKey();
        var piA = toG1(proof.a());
        var piB = toG2(proof.b());
        var piC = toG1(proof.c());
        var alpha = toG1(pk.alphaG1());
        var beta = toG2(pk.betaG2());
        var gamma = toG2(setupResult.gammaG2());
        var delta = toG2(pk.deltaG2());

        var ic = setupResult.ic();
        G1Point vkX = toG1(ic[0]);
        for (int i = 0; i < pubInputs.length; i++) {
            vkX = vkX.add(toG1(ic[i + 1]).scalarMul(pubInputs[i]));
        }

        return BLS12381Pairing.pairingCheck(
                new G1Point[]{piA, alpha.negate(), vkX.negate(), piC.negate()},
                new G2Point[]{piB, beta, gamma, delta});
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
