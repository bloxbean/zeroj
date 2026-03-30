package com.bloxbean.cardano.zeroj.examples.dsl.templates;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Prover.R1CSConstraint;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.examples.dsl.common.MiMCHash;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.field.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Demonstrates parameterized (templated) circuits using Java as the template system.
 *
 * <p>Each test instantiates a circuit with <em>different parameters</em> (depth, size,
 * hash function) and proves + verifies end-to-end with the pure Java BLS12-381 prover.</p>
 *
 * <p>This is the Java equivalent of Circom's {@code template Foo(n)} —
 * constructor parameters replace template parameters, Java loops replace
 * Circom's for-loop unrolling.</p>
 */
class ParameterizedCircuitE2ETest {

    private static final BigInteger PRIME = FieldConfig.BLS12_381.prime();

    // ===================================================================
    // HashChainCircuit — parameterized by depth
    // ===================================================================

    @Test
    void hashChain_depth1_proveAndVerify() {
        // hash(secret, 0) = digest
        var result = proveHashChain(1, BigInteger.valueOf(42));
        assertTrue(result.verified, "depth=1 hash chain must verify");
        System.out.println("HashChain(depth=1): " + result.constraints + " constraints — VERIFIED");
    }

    @Test
    void hashChain_depth3_proveAndVerify() {
        // hash(hash(hash(secret, 0), 0), 0) = digest
        var result = proveHashChain(3, BigInteger.valueOf(42));
        assertTrue(result.verified, "depth=3 hash chain must verify");
        System.out.println("HashChain(depth=3): " + result.constraints + " constraints — VERIFIED");
    }

    @Test
    void hashChain_depth5_proveAndVerify() {
        var result = proveHashChain(5, BigInteger.valueOf(12345));
        assertTrue(result.verified, "depth=5 hash chain must verify");
        System.out.println("HashChain(depth=5): " + result.constraints + " constraints — VERIFIED");
    }

    @Test
    void hashChain_differentDepths_differentConstraintCounts() {
        int c1 = HashChainCircuit.build(1).compileR1CS(CurveId.BLS12_381).numConstraints();
        int c3 = HashChainCircuit.build(3).compileR1CS(CurveId.BLS12_381).numConstraints();
        int c5 = HashChainCircuit.build(5).compileR1CS(CurveId.BLS12_381).numConstraints();

        assertTrue(c3 > c1, "depth=3 should have more constraints than depth=1");
        assertTrue(c5 > c3, "depth=5 should have more constraints than depth=3");
        // Each additional hash adds ~273 constraints (MiMC-7)
        assertTrue(c3 - c1 > 200, "Each depth level adds ~273 MiMC constraints");

        System.out.println("Constraint scaling: depth=1→" + c1 + ", depth=3→" + c3 + ", depth=5→" + c5);
    }

    // ===================================================================
    // MultiInputCommitmentCircuit — parameterized by number of inputs
    // ===================================================================

    @Test
    void multiCommit_2inputs_proveAndVerify() {
        var result = proveMultiCommit(2, new BigInteger[]{BigInteger.valueOf(100), BigInteger.valueOf(200)});
        assertTrue(result.verified, "2-input commitment must verify");
        System.out.println("MultiCommit(n=2): " + result.constraints + " constraints — VERIFIED");
    }

    @Test
    void multiCommit_4inputs_proveAndVerify() {
        var values = new BigInteger[]{
                BigInteger.valueOf(10), BigInteger.valueOf(20),
                BigInteger.valueOf(30), BigInteger.valueOf(40)};
        var result = proveMultiCommit(4, values);
        assertTrue(result.verified, "4-input commitment must verify");
        System.out.println("MultiCommit(n=4): " + result.constraints + " constraints — VERIFIED");
    }

    @Test
    void multiCommit_withNamedFields_proveAndVerify() {
        // Demonstrates string parameters — impossible in Circom templates
        var circuit = MultiInputCommitmentCircuit.build(3, "name", "age", "balance");
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        BigInteger name = BigInteger.valueOf(12345);   // encoded name
        BigInteger age = BigInteger.valueOf(30);
        BigInteger balance = BigInteger.valueOf(1000000);

        // Compute expected commitment: MiMC(MiMC(name, age), balance)
        BigInteger step1 = MiMCHash.hash(name, age, PRIME);
        BigInteger commitment = MiMCHash.hash(step1, balance, PRIME);

        var witness = circuit.calculateWitness(Map.of(
                "name", List.of(name),
                "age", List.of(age),
                "balance", List.of(balance),
                "commitment", List.of(commitment)), CurveId.BLS12_381);

        var result = proveAndVerify(circuit, r1cs, witness);
        assertTrue(result, "Named-field commitment must verify");
        System.out.println("MultiCommit(name,age,balance): VERIFIED — Java string params, not possible in Circom");
    }

    // ===================================================================
    // NWayMerkleCircuit — parameterized by depth AND hash function
    // ===================================================================

    @Test
    void merkle_depth2_mimc_proveAndVerify() {
        var result = proveMerkle(2, NWayMerkleCircuit.HashType.MIMC);
        assertTrue(result.verified, "depth=2 MiMC Merkle must verify");
        System.out.println("Merkle(depth=2, MiMC): " + result.constraints + " constraints — VERIFIED");
    }

    @Test
    void merkle_depth3_mimc_proveAndVerify() {
        var result = proveMerkle(3, NWayMerkleCircuit.HashType.MIMC);
        assertTrue(result.verified, "depth=3 MiMC Merkle must verify");
        System.out.println("Merkle(depth=3, MiMC): " + result.constraints + " constraints — VERIFIED");
    }

    @Test
    void merkle_sameDepth_differentHash_differentConstraints() {
        int mimcC = NWayMerkleCircuit.build(2, NWayMerkleCircuit.HashType.MIMC)
                .compileR1CS(CurveId.BLS12_381).numConstraints();
        int poseidonC = NWayMerkleCircuit.build(2, NWayMerkleCircuit.HashType.POSEIDON)
                .compileR1CS(CurveId.BLS12_381).numConstraints();

        // Poseidon (~330/hash) vs MiMC (~273/hash) — different constraint counts for same depth
        assertNotEquals(mimcC, poseidonC, "Different hash functions should produce different constraint counts");
        System.out.println("Merkle(depth=2): MiMC=" + mimcC + " vs Poseidon=" + poseidonC + " constraints");
    }

    // ===================================================================
    // Helpers — shared prove + verify logic
    // ===================================================================

    record ProveResult(boolean verified, int constraints) {}

    private ProveResult proveHashChain(int depth, BigInteger secret) {
        var circuit = HashChainCircuit.build(depth);
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        // Compute expected digest by applying MiMC `depth` times
        BigInteger current = secret;
        for (int i = 0; i < depth; i++) {
            current = MiMCHash.hash(current, BigInteger.ZERO, PRIME);
        }

        var witness = circuit.calculateWitness(Map.of(
                "secret", List.of(secret),
                "digest", List.of(current)), CurveId.BLS12_381);

        boolean ok = proveAndVerify(circuit, r1cs, witness);
        return new ProveResult(ok, r1cs.numConstraints());
    }

    private ProveResult proveMultiCommit(int n, BigInteger[] values) {
        var circuit = MultiInputCommitmentCircuit.build(n);
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        // Compute expected commitment
        BigInteger acc = MiMCHash.hash(values[0], values[1], PRIME);
        for (int i = 2; i < n; i++) {
            acc = MiMCHash.hash(acc, values[i], PRIME);
        }

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        for (int i = 0; i < n; i++) {
            inputs.put("value_" + i, List.of(values[i]));
        }
        inputs.put("commitment", List.of(acc));

        var witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        boolean ok = proveAndVerify(circuit, r1cs, witness);
        return new ProveResult(ok, r1cs.numConstraints());
    }

    private ProveResult proveMerkle(int depth, NWayMerkleCircuit.HashType hashType) {
        var circuit = NWayMerkleCircuit.build(depth, hashType);
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);

        // Build a minimal Merkle tree and generate a valid proof
        // Leaf = 42, siblings are random, path bits define position
        BigInteger leaf = BigInteger.valueOf(42);
        BigInteger[] siblings = new BigInteger[depth];
        BigInteger[] pathBits = new BigInteger[depth];

        // Build tree bottom-up: leaf goes left at every level
        BigInteger current = leaf;
        for (int i = 0; i < depth; i++) {
            siblings[i] = BigInteger.valueOf(100 + i); // arbitrary sibling
            pathBits[i] = BigInteger.ZERO;              // leaf on left side
            current = MiMCHash.hash(current, siblings[i], PRIME);
        }
        BigInteger root = current;

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("leaf", List.of(leaf));
        inputs.put("root", List.of(root));
        for (int i = 0; i < depth; i++) {
            inputs.put("sibling_" + i, List.of(siblings[i]));
            inputs.put("pathBit_" + i, List.of(pathBits[i]));
        }

        var witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        boolean ok = proveAndVerify(circuit, r1cs, witness);
        return new ProveResult(ok, r1cs.numConstraints());
    }

    /**
     * Core: compile → setup → prove → pairing verify.
     */
    private boolean proveAndVerify(CircuitBuilder circuit,
                                    com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem r1cs,
                                    BigInteger[] witness) {
        var constraints = r1cs.constraints().stream()
                .map(c -> new R1CSConstraint(c.a(), c.b(), c.c()))
                .toArray(R1CSConstraint[]::new);

        int power = nextPowerOf2Log(r1cs.numConstraints());
        var srs = PowersOfTauBLS381.generate(power);
        var setupResult = Groth16SetupBLS381.setup(constraints, r1cs.numWires(),
                r1cs.numPublicInputs(), srs.tauScalar());

        var proof = Groth16ProverBLS381.prove(setupResult.provingKey(), witness,
                constraints, r1cs.numWires());

        // Pairing verification
        var pk = setupResult.provingKey();
        var ic = setupResult.ic();
        BigInteger[] pubInputs = new BigInteger[r1cs.numPublicInputs()];
        for (int i = 0; i < pubInputs.length; i++) pubInputs[i] = witness[i + 1];

        G1Point vkX = toG1(ic[0]);
        for (int i = 0; i < pubInputs.length; i++) {
            vkX = vkX.add(toG1(ic[i + 1]).scalarMul(pubInputs[i]));
        }

        return BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(proof.a()), toG1(pk.alphaG1()).negate(), vkX.negate(), toG1(proof.c()).negate()},
                new G2Point[]{toG2(proof.b()), toG2(pk.betaG2()), toG2(setupResult.gammaG2()), toG2(pk.deltaG2())});
    }

    private static int nextPowerOf2Log(int n) {
        int p = 4; // minimum
        while ((1 << p) < n) p++;
        return p;
    }

    private static G1Point toG1(com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2(com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
