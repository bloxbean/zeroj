package com.bloxbean.cardano.zeroj.examples.dsl.voting;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
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
 * Pure Java E2E for AnonymousVoting: circuit → prove → off-chain pairing verify.
 *
 * <h3>DEV/TEST (this test)</h3>
 * <p>Uses {@code PowersOfTauBLS381.generate(9)} — for development only.</p>
 *
 * <h3>PRODUCTION</h3>
 * <p>Use MPC ceremony .ptau or snarkjs .zkey. See {@code ZkeyImporterBLS381}.</p>
 */
class AnonymousVotingPureJavaE2ETest {

    @Test
    void devTau_voteYes_proveAndVerify() {
        var circuit = AnonymousVotingCircuit.build();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        var constraints = r1cs.constraints();

        System.out.println("AnonymousVoting: " + r1cs.numConstraints() + " constraints");

        BigInteger vote = BigInteger.ONE; // YES
        BigInteger nullifier = BigInteger.valueOf(12345);
        BigInteger commitment = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, vote, nullifier);

        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "vote", List.of(vote),
                "nullifier", List.of(nullifier),
                "commitment", List.of(commitment)), CurveId.BLS12_381);

        var srs = PowersOfTauBLS381.generate(11);
        var setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());

        var proof = Groth16ProverBLS381.prove(setupResult.provingKey(), witness,
                constraints, r1cs.numWires());

        assertTrue(proof.a().isOnCurve());
        System.out.println("Vote=YES proof generated");

        BigInteger[] pubInputs = {witness[1]}; // commitment
        boolean verified = verifyOffChain(proof, setupResult, pubInputs);
        assertTrue(verified, "Vote YES pairing verification MUST pass");
        System.out.println("Off-chain pairing: PASSED");

        // Verify commitment matches standalone Poseidon
        assertEquals(commitment, pubInputs[0], "Commitment matches BLS12-381 Poseidon hash");
        System.out.println("=== AnonymousVoting E2E (vote=YES, dev tau): COMPLETE ===");
    }

    @Test
    void devTau_voteNo_proveAndVerify() {
        var circuit = AnonymousVotingCircuit.build();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        var constraints = r1cs.constraints();

        BigInteger vote = BigInteger.ZERO; // NO
        BigInteger nullifier = BigInteger.valueOf(67890);
        BigInteger commitment = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, vote, nullifier);

        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "vote", List.of(vote),
                "nullifier", List.of(nullifier),
                "commitment", List.of(commitment)), CurveId.BLS12_381);

        var srs = PowersOfTauBLS381.generate(11);
        var setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());

        var proof = Groth16ProverBLS381.prove(setupResult.provingKey(), witness,
                constraints, r1cs.numWires());

        BigInteger[] pubInputs = {witness[1]};
        assertTrue(verifyOffChain(proof, setupResult, pubInputs));
        System.out.println("=== AnonymousVoting E2E (vote=NO, dev tau): COMPLETE ===");
    }

    private boolean verifyOffChain(com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381 proof,
                                    Groth16SetupBLS381.SetupResult setupResult,
                                    BigInteger[] pubInputs) {
        var pk = setupResult.provingKey();
        var ic = setupResult.ic();
        G1Point vkX = toG1(ic[0]);
        for (int i = 0; i < pubInputs.length; i++) {
            vkX = vkX.add(toG1(ic[i + 1]).scalarMul(pubInputs[i]));
        }

        return BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(proof.a()), toG1(pk.alphaG1()).negate(), vkX.negate(), toG1(proof.c()).negate()},
                new G2Point[]{toG2(proof.b()), toG2(pk.betaG2()), toG2(setupResult.gammaG2()), toG2(pk.deltaG2())});
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
