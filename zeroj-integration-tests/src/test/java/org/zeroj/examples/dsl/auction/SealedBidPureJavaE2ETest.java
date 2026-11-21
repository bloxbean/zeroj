package org.zeroj.examples.dsl.auction;

import org.zeroj.api.CurveId;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.crypto.groth16.Groth16ProverBLS381;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.zeroj.bls12381.ec.*;
import org.zeroj.bls12381.field.*;
import org.zeroj.bls12381.pairing.BLS12381Pairing;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Off-chain E2E: Java DSL circuit → pure Java BLS12-381 prove → off-chain pairing verify.
 *
 * <h3>DEV/TEST path (this test)</h3>
 * <p>Uses single-party {@code PowersOfTauBLS381.generate(10)} — toxic waste is known.
 * <b>DO NOT use this setup for production.</b></p>
 *
 * <h3>PRODUCTION path</h3>
 * <p>Production Groth16 keys must come from an independently verified BLS12-381 multi-party
 * ceremony (e.g., {@code snarkjs groth16 setup} + {@code zkey contribute} + {@code zkey beacon}
 * + {@code zkey verify}). Production {@code .ptau} files never expose {@code tau}.</p>
 * <pre>
 * // Import snarkjs .zkey (from an independently verified BLS12-381 MPC ceremony)
 * var zkeyData = ZkeyImporterBLS381.importZkeyFull(Files.readAllBytes(Path.of("circuit.zkey")));
 * var proof = Groth16ProverBLS381.prove(zkeyData.provingKey(), witness, ...);
 * </pre>
 */
class SealedBidPureJavaE2ETest {

    /**
     * Pure Java end-to-end: circuit → prove → off-chain pairing verify.
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
        BigInteger bidCommitment = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, bidAmount, salt);

        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "bidAmount", List.of(bidAmount),
                "salt", List.of(salt),
                "reservePrice", List.of(reservePrice),
                "bidCommitment", List.of(bidCommitment)), CurveId.BLS12_381);

        // === Step 3: Dev trusted setup (DEVELOPMENT ONLY) ===
        var srs = PowersOfTauBLS381.generate(12);
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

    private boolean verifyOffChain(org.zeroj.crypto.groth16.Groth16ProofBLS381 proof,
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

    private static G1Point toG1(org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2(org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
