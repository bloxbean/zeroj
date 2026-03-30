package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for production-ready stdlib functions: AliasCheck, MiMCSponge, PoseidonN.
 */
class NewStdlibTest {

    private static final BigInteger BN254_FR = FieldConfig.BN254.prime();

    // ===================================================================
    // AliasCheck
    // ===================================================================

    @Test
    void aliasCheck_validValue_passes() {
        var circuit = CircuitBuilder.create("alias-test")
                .secretVar("value")
                .define(api -> AliasCheck.check(api, api.var("value"), 253));

        assertDoesNotThrow(() -> circuit.calculateWitness(
                Map.of("value", List.of(BigInteger.valueOf(42))), CurveId.BN254));
    }

    @Test
    void aliasCheck_largeValid_passes() {
        var circuit = CircuitBuilder.create("alias-test")
                .secretVar("value")
                .define(api -> AliasCheck.check(api, api.var("value"), 253));

        // 2^253 - 1 is the largest value that fits in 253 bits
        BigInteger maxVal = BigInteger.ONE.shiftLeft(253).subtract(BigInteger.ONE);
        assertDoesNotThrow(() -> circuit.calculateWitness(
                Map.of("value", List.of(maxVal)), CurveId.BN254));
    }

    // ===================================================================
    // MiMCSponge
    // ===================================================================

    @Test
    void mimcSponge_singleInput_producesOutput() {
        var circuit = CircuitBuilder.create("sponge-test")
                .publicVar("out")
                .secretVar("in0")
                .define(api -> {
                    var result = MiMCSponge.hash(api, new com.bloxbean.cardano.zeroj.circuit.Variable[]{api.var("in0")});
                    api.assertEqual(result, api.var("out"));
                });

        var r1cs = circuit.compileR1CS(CurveId.BN254);
        assertTrue(r1cs.numConstraints() > 0, "Should have constraints");

        // Compute expected output — MiMCSponge(42)
        var witness = circuit.calculateWitness(Map.of(
                "in0", List.of(BigInteger.valueOf(42)),
                "out", List.of(computeMiMCSponge(new BigInteger[]{BigInteger.valueOf(42)}))),
                CurveId.BN254);
        assertNotNull(witness);
    }

    @Test
    void mimcSponge_multipleInputs_producesOutput() {
        var circuit = CircuitBuilder.create("sponge-multi")
                .publicVar("out")
                .secretVar("in0").secretVar("in1").secretVar("in2")
                .define(api -> {
                    var result = MiMCSponge.hash(api, new com.bloxbean.cardano.zeroj.circuit.Variable[]{
                            api.var("in0"), api.var("in1"), api.var("in2")});
                    api.assertEqual(result, api.var("out"));
                });

        BigInteger[] inputs = {BigInteger.valueOf(1), BigInteger.valueOf(2), BigInteger.valueOf(3)};
        BigInteger expected = computeMiMCSponge(inputs);

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "in0", List.of(inputs[0]),
                "in1", List.of(inputs[1]),
                "in2", List.of(inputs[2]),
                "out", List.of(expected)), CurveId.BN254));
    }

    @Test
    void mimcSponge_wrongOutput_fails() {
        var circuit = CircuitBuilder.create("sponge-fail")
                .publicVar("out")
                .secretVar("in0")
                .define(api -> {
                    var result = MiMCSponge.hash(api, new com.bloxbean.cardano.zeroj.circuit.Variable[]{api.var("in0")});
                    api.assertEqual(result, api.var("out"));
                });

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "in0", List.of(BigInteger.valueOf(42)),
                "out", List.of(BigInteger.valueOf(99))), CurveId.BN254));
    }

    // ===================================================================
    // PoseidonN (variable arity)
    // ===================================================================

    @Test
    void poseidonN_2inputs_matchesPoseidon2() {
        // PoseidonN(a, b) should equal Poseidon(a, b)
        var circuit2 = CircuitBuilder.create("poseidon2")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(Poseidon.hash(api, api.var("a"), api.var("b")), api.var("out")));

        var circuitN = CircuitBuilder.create("poseidonN-2")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(PoseidonN.hash(api, api.var("a"), api.var("b")), api.var("out")));

        BigInteger a = BigInteger.ONE, b = BigInteger.TWO;
        var w2 = circuit2.calculateWitness(Map.of(
                "a", List.of(a), "b", List.of(b),
                "out", List.of(computePoseidon2(a, b))), CurveId.BN254);
        var wN = circuitN.calculateWitness(Map.of(
                "a", List.of(a), "b", List.of(b),
                "out", List.of(computePoseidon2(a, b))), CurveId.BN254);

        // Both should produce the same output
        assertEquals(w2[1], wN[1], "PoseidonN(2) must equal Poseidon(2)");
    }

    @Test
    void poseidonN_3inputs_produces_output() {
        var circuit = CircuitBuilder.create("poseidonN-3")
                .publicVar("out").secretVar("a").secretVar("b").secretVar("c")
                .define(api -> api.assertEqual(
                        PoseidonN.hash(api, api.var("a"), api.var("b"), api.var("c")),
                        api.var("out")));

        // Expected: Poseidon(Poseidon(a, b), c)
        BigInteger a = BigInteger.ONE, b = BigInteger.TWO, c = BigInteger.valueOf(3);
        BigInteger step1 = computePoseidon2(a, b);
        BigInteger expected = computePoseidon2(step1, c);

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "a", List.of(a), "b", List.of(b), "c", List.of(c),
                "out", List.of(expected)), CurveId.BN254));
    }

    @Test
    void poseidonN_4inputs_produces_output() {
        var circuit = CircuitBuilder.create("poseidonN-4")
                .publicVar("out").secretVar("a").secretVar("b").secretVar("c").secretVar("d")
                .define(api -> api.assertEqual(
                        PoseidonN.hash(api, api.var("a"), api.var("b"), api.var("c"), api.var("d")),
                        api.var("out")));

        BigInteger a = BigInteger.valueOf(10), b = BigInteger.valueOf(20);
        BigInteger c = BigInteger.valueOf(30), d = BigInteger.valueOf(40);
        BigInteger s1 = computePoseidon2(a, b);
        BigInteger s2 = computePoseidon2(s1, c);
        BigInteger expected = computePoseidon2(s2, d);

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "a", List.of(a), "b", List.of(b), "c", List.of(c), "d", List.of(d),
                "out", List.of(expected)), CurveId.BN254));
    }

    // ===================================================================
    // MiMCSponge — multi-output squeeze
    // ===================================================================

    @Test
    void mimcSponge_multiOutput_producesDistinctOutputs() {
        var circuit = CircuitBuilder.create("sponge-multi-out")
                .publicVar("out0").publicVar("out1")
                .secretVar("in0")
                .define(api -> {
                    var results = MiMCSponge.hashMulti(api,
                            new com.bloxbean.cardano.zeroj.circuit.Variable[]{api.var("in0")}, 2);
                    api.assertEqual(results[0], api.var("out0"));
                    api.assertEqual(results[1], api.var("out1"));
                });

        // Compute expected: Feistel absorb + 2 squeezes
        BigInteger p = BN254_FR;
        BigInteger left = BigInteger.ZERO, right = BigInteger.ZERO;
        BigInteger input = BigInteger.valueOf(42);

        // Absorb
        left = left.add(input).mod(p);
        BigInteger oldLeft = left;
        BigInteger mimc = computeMiMCDirect(left, right);
        left = mimc.add(right).mod(p);
        right = oldLeft;
        BigInteger out0 = left;

        // Second squeeze
        oldLeft = left;
        mimc = computeMiMCDirect(left, right);
        left = mimc.add(right).mod(p);
        BigInteger out1 = left;

        assertNotEquals(out0, out1, "Multi-output should produce distinct values");

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "in0", List.of(input),
                "out0", List.of(out0),
                "out1", List.of(out1)), CurveId.BN254));
    }


    // ===================================================================
    // PoseidonN — single input + wrong output
    // ===================================================================

    @Test
    void poseidonN_1input_producesOutput() {
        var circuit = CircuitBuilder.create("poseidonN-1")
                .publicVar("out").secretVar("a")
                .define(api -> api.assertEqual(PoseidonN.hash(api, api.var("a")), api.var("out")));

        // PoseidonN(a) = Poseidon(a, 0)
        BigInteger expected = computePoseidonDirect(BigInteger.valueOf(42), BigInteger.ZERO);

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.valueOf(42)),
                "out", List.of(expected)), CurveId.BN254));
    }

    @Test
    void poseidonN_wrongOutput_fails() {
        var circuit = CircuitBuilder.create("poseidonN-fail")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(PoseidonN.hash(api, api.var("a"), api.var("b")), api.var("out")));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.ONE),
                "b", List.of(BigInteger.TWO),
                "out", List.of(BigInteger.valueOf(99))), CurveId.BN254));
    }

    // ===================================================================
    // Signal API tests
    // ===================================================================

    @Test
    void signalAPI_mimcSponge_matchesFunctionalAPI() {
        BigInteger input = BigInteger.valueOf(42);

        // Functional API circuit
        var funcCircuit = CircuitBuilder.create("func")
                .publicVar("out").secretVar("in0")
                .define(api -> {
                    var r = MiMCSponge.hash(api, new com.bloxbean.cardano.zeroj.circuit.Variable[]{api.var("in0")});
                    api.assertEqual(r, api.var("out"));
                });

        // Signal API circuit
        var sigCircuit = CircuitBuilder.create("sig")
                .publicVar("out").secretVar("in0")
                .defineSignals(c -> {
                    var r = MiMCSponge.hash(c, new com.bloxbean.cardano.zeroj.circuit.Signal[]{c.privateInput("in0")});
                    c.assertEqual(r, c.publicOutput("out"));
                });

        BigInteger expected = computeMiMCSponge(new BigInteger[]{input});

        var wFunc = funcCircuit.calculateWitness(Map.of("in0", List.of(input), "out", List.of(expected)), CurveId.BN254);
        var wSig = sigCircuit.calculateWitness(Map.of("in0", List.of(input), "out", List.of(expected)), CurveId.BN254);

        assertEquals(wFunc[1], wSig[1], "Signal API must produce same output as functional API");
    }

    @Test
    void signalAPI_poseidonN_matchesFunctionalAPI() {
        BigInteger a = BigInteger.ONE, b = BigInteger.TWO;
        BigInteger expected = computePoseidonDirect(a, b);

        var sigCircuit = CircuitBuilder.create("posN-sig")
                .publicVar("out").secretVar("a").secretVar("b")
                .defineSignals(c -> {
                    var r = PoseidonN.hash(c, c.privateInput("a"), c.privateInput("b"));
                    c.assertEqual(r, c.publicOutput("out"));
                });

        assertDoesNotThrow(() -> sigCircuit.calculateWitness(Map.of(
                "a", List.of(a), "b", List.of(b), "out", List.of(expected)), CurveId.BN254));
    }

    // ===================================================================
    // Helper: compute expected values outside the circuit (for verification)
    // ===================================================================

    /** Compute Poseidon(a, b) outside the circuit for test vectors. */
    private BigInteger computePoseidon2(BigInteger a, BigInteger b) {
        var circuit = CircuitBuilder.create("helper")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(Poseidon.hash(api, api.var("a"), api.var("b")), api.var("out")));

        // Use a dummy output, compute witness, extract actual output
        var dummyCircuit = CircuitBuilder.create("compute")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, api.var("a"), api.var("b"));
                    api.assertEqual(h, api.var("out"));
                });

        // For now, use the known test vector or compute via witness
        // Poseidon(1, 2) from the known test vector
        if (a.equals(BigInteger.ONE) && b.equals(BigInteger.TWO)) {
            return new BigInteger("7853200120776062878684798364095072458815029376092732009249414926327459813530");
        }

        // For other values, compute by running the circuit with a wildcard output
        // and reading back the computed value
        var computeCircuit = CircuitBuilder.create("compute-poseidon")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, api.var("a"), api.var("b"));
                    api.assertEqual(h, api.var("out"));
                });

        // Run with placeholder — need actual computation
        // Use direct field arithmetic to compute Poseidon outside the circuit
        return computePoseidonDirect(a, b);
    }

    /** Direct computation of Poseidon(a, b) using field arithmetic. */
    private BigInteger computePoseidonDirect(BigInteger a, BigInteger b) {
        BigInteger p = BN254_FR;
        BigInteger[] state = {BigInteger.ZERO, a, b};

        int RF = 8, RP = 57, N = RF + RP;
        for (int r = 0; r < N; r++) {
            // AddRoundConstants
            for (int j = 0; j < 3; j++)
                state[j] = state[j].add(PoseidonConstants.C[r * 3 + j]).mod(p);

            // S-box
            if (r < RF / 2 || r >= RF / 2 + RP) {
                for (int j = 0; j < 3; j++) state[j] = sbox5(state[j], p);
            } else {
                state[0] = sbox5(state[0], p);
            }

            // MDS
            BigInteger[] t = new BigInteger[3];
            for (int i = 0; i < 3; i++) {
                t[i] = BigInteger.ZERO;
                for (int j = 0; j < 3; j++)
                    t[i] = t[i].add(state[j].multiply(PoseidonConstants.M[i * 3 + j])).mod(p);
            }
            state = t;
        }
        return state[0];
    }

    private BigInteger sbox5(BigInteger x, BigInteger p) {
        BigInteger x2 = x.multiply(x).mod(p);
        BigInteger x4 = x2.multiply(x2).mod(p);
        return x4.multiply(x).mod(p);
    }

    /** Compute MiMCSponge outside the circuit (Feistel construction). */
    private BigInteger computeMiMCSponge(BigInteger[] inputs) {
        BigInteger p = BN254_FR;
        BigInteger left = BigInteger.ZERO, right = BigInteger.ZERO;

        for (BigInteger input : inputs) {
            left = left.add(input).mod(p);
            BigInteger oldLeft = left;
            BigInteger mimc = computeMiMCDirect(left, right);
            left = mimc.add(right).mod(p);
            right = oldLeft;
        }
        return left;
    }

    /** Direct MiMC-7 computation. */
    private BigInteger computeMiMCDirect(BigInteger x, BigInteger k) {
        BigInteger p = BN254_FR;
        BigInteger state = x;
        for (int i = 0; i < 91; i++) {
            BigInteger rc = MiMC.roundConstant(i);
            BigInteger t = state.add(rc).add(k).mod(p);
            BigInteger t2 = t.multiply(t).mod(p);
            BigInteger t4 = t2.multiply(t2).mod(p);
            BigInteger t6 = t4.multiply(t2).mod(p);
            state = t6.multiply(t).mod(p);
        }
        return state.add(k).mod(p);
    }
}
