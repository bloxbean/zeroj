package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.Poseidon;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Consolidated cross-verification test suite for the Poseidon stack, per
 * ADR-0015 section 6.
 *
 * <h2>Evidence layers</h2>
 * <ol>
 *   <li><b>circomlibjs BN254 vectors</b> — {@link PoseidonHash} reproduces
 *       Poseidon(0,0), Poseidon(1,2), Poseidon(123,456) exactly as published
 *       by circomlibjs.</li>
 *   <li><b>Self-consistency</b> — the in-circuit {@link Poseidon} gadget and
 *       the off-circuit {@link PoseidonHash} produce byte-identical output
 *       for 100 random input pairs under each preset.</li>
 *   <li><b>BLS12-381 regression fixtures</b> — {@link PoseidonHash} output
 *       for a small set of fixed inputs is committed as a hex fixture; any
 *       change to the generator, preset, or hash function breaks the
 *       fixture. To verify the fixture matches the Poseidon paper spec, run
 *       the pinned hadeshash Sage script (see
 *       {@code src/main/resources/poseidon/README.md}).</li>
 * </ol>
 *
 * <h2>External paper-spec cross-check</h2>
 * The BLS12-381 fixtures {@link #BLS_POSEIDON_0_0_HEX} / {@code 1_2} / {@code 123_456}
 * were cross-verified against an <b>independent SageMath reference</b>
 * implementation of the Poseidon paper spec. See
 * {@code src/test/resources/poseidon-sage/README.md} for reproduction. The
 * Sage-produced hashes are captured in {@code sage-reference-output.txt}
 * and byte-match ZeroJ's pure-Java output for all three fixtures — closing
 * the ADR-0015 §6 "paper-spec cross-check" requirement.
 */
class PoseidonCrossVerificationTest {

    // --------------------------------------------------------------------
    //  circomlibjs BN254 test vectors — the canonical external oracle for
    //  BN254 Poseidon. These are the hashes any correct Poseidon(BN254, t=3,
    //  α=5, RF=8, RP=57) implementation must reproduce.
    // --------------------------------------------------------------------

    private static final BigInteger POSEIDON_BN254_0_0 = new BigInteger(
            "14744269619966411208579211824598458697587494354926760081771325075741142829156");
    private static final BigInteger POSEIDON_BN254_1_2 = new BigInteger(
            "7853200120776062878684798364095072458815029376092732009249414926327459813530");
    private static final BigInteger POSEIDON_BN254_123_456 = new BigInteger(
            "19620391833206800292073497099357851348339828238212863168390691880932172496143");

    @Test
    @DisplayName("circomlibjs: off-circuit PoseidonHash reproduces the three canonical BN254 test vectors")
    void circomlibjs_bn254_knownAnswers() {
        PoseidonParams p = PoseidonParamsBN254T3.INSTANCE;

        assertEquals(POSEIDON_BN254_0_0,
                PoseidonHash.hash(p, BigInteger.ZERO, BigInteger.ZERO),
                "Poseidon(0, 0) diverged — generator or permutation is broken");
        assertEquals(POSEIDON_BN254_1_2,
                PoseidonHash.hash(p, BigInteger.ONE, BigInteger.TWO),
                "Poseidon(1, 2) diverged");
        assertEquals(POSEIDON_BN254_123_456,
                PoseidonHash.hash(p, BigInteger.valueOf(123), BigInteger.valueOf(456)),
                "Poseidon(123, 456) diverged");
    }

    @Test
    @DisplayName("circomlibjs: in-circuit Poseidon gadget via explicit BN254_T3 params reproduces all three vectors")
    void circomlibjs_bn254_inCircuit_explicitParams() {
        BigInteger[][] pairs = {
                { BigInteger.ZERO, BigInteger.ZERO },
                { BigInteger.ONE, BigInteger.TWO },
                { BigInteger.valueOf(123), BigInteger.valueOf(456) },
        };
        BigInteger[] expected = { POSEIDON_BN254_0_0, POSEIDON_BN254_1_2, POSEIDON_BN254_123_456 };

        for (int i = 0; i < pairs.length; i++) {
            BigInteger a = pairs[i][0], b = pairs[i][1], h = expected[i];
            var circuit = CircuitBuilder.create("bn254_fixture_" + i)
                    .publicVar("hash").secretVar("a").secretVar("b")
                    .define(api -> {
                        var out = Poseidon.hash(api, PoseidonParamsBN254T3.INSTANCE,
                                api.var("a"), api.var("b"));
                        api.assertEqual(out, api.var("hash"));
                    });
            final int iter = i;
            assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                    "hash", List.of(h),
                    "a", List.of(a),
                    "b", List.of(b)), CurveId.BN254),
                    () -> "BN254 explicit-params fixture " + iter + " diverged");
        }
    }

    @Test
    @DisplayName("Self-consistency: circuit gadget matches off-circuit PoseidonHash over 100 random BN254 inputs")
    void selfConsistency_bn254_100randomInputs() {
        assertSelfConsistent(PoseidonParamsBN254T3.INSTANCE, CurveId.BN254, 100, 0xB5C254L);
    }

    @Test
    @DisplayName("Self-consistency: circuit gadget matches off-circuit PoseidonHash over 100 random BLS12-381 inputs")
    void selfConsistency_bls12_381_100randomInputs() {
        assertSelfConsistent(PoseidonParamsBLS12_381T3.INSTANCE, CurveId.BLS12_381, 100, 0xB1512381L);
    }

    /**
     * For {@code rounds} random {@code (a, b)} input pairs, asserts that the
     * in-circuit {@link Poseidon} gadget's witness output equals the
     * off-circuit {@link PoseidonHash} output under the same params.
     *
     * <p>The circuit is built once up front and reused across iterations —
     * each random pair calls {@code calculateWitness} with the pair
     * asserted-equal to the expected hash. A wrong expected hash would cause
     * {@code calculateWitness} to throw.
     */
    private void assertSelfConsistent(PoseidonParams params, CurveId curve,
                                      int rounds, long seed) {
        Random rnd = new Random(seed);
        BigInteger prime = params.field().prime();
        int bitLen = prime.bitLength();

        var circuit = CircuitBuilder.create("poseidonXc")
                .publicVar("hash").secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, params, api.var("a"), api.var("b"));
                    api.assertEqual(h, api.var("hash"));
                });

        for (int i = 0; i < rounds; i++) {
            BigInteger a = new BigInteger(bitLen, rnd).mod(prime);
            BigInteger b = new BigInteger(bitLen, rnd).mod(prime);
            BigInteger expected = PoseidonHash.hash(params, a, b);

            final int iter = i;
            assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                    "hash", List.of(expected),
                    "a", List.of(a),
                    "b", List.of(b)), curve),
                    () -> "iter=" + iter + " a=" + a + " b=" + b + " expected=" + expected);
        }
    }

    /**
     * Locked regression fixtures for BLS12-381 Poseidon t=3 α=5 RF=8 RP=57.
     *
     * <p>These values were produced by ZeroJ's {@link PoseidonHash} over
     * {@link PoseidonParamsBLS12_381T3}. They are <b>not</b> directly cross-
     * checked against an external library (no widely-used library uses the
     * paper-canonical RP=57 for BLS12-381 t=3). To independently verify:
     * <ol>
     *   <li>Run {@code sage src/main/resources/poseidon/generate_parameters_grain.sage
     *       1 0 255 3 8 57 <bls_prime>} — reproduces our C, M.</li>
     *   <li>Implement Poseidon permutation with those constants in any
     *       correct Poseidon implementation — must produce these hashes.</li>
     * </ol>
     * The chain of trust terminates at the Poseidon paper spec.
     */
    private static final String BLS_POSEIDON_0_0_HEX =
            "57c7e6cea4c40c3956e13ae6f8d644edff6f14577a581058eaa651b4675c7156";
    private static final String BLS_POSEIDON_1_2_HEX =
            "28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a";
    private static final String BLS_POSEIDON_123_456_HEX =
            "6eadb49364ff22d841d40765ef4ac418f19467e8511541850aebf2936338a0fa";

    @Test
    @DisplayName("BLS12-381 regression: Poseidon(0,0), (1,2), (123,456) match locked hex fixtures")
    void bls12_381_regressionFixtures() {
        PoseidonParams p = PoseidonParamsBLS12_381T3.INSTANCE;

        assertEquals(new BigInteger(BLS_POSEIDON_0_0_HEX, 16),
                PoseidonHash.hash(p, BigInteger.ZERO, BigInteger.ZERO),
                "BLS12-381 Poseidon(0, 0) diverged — recompute via Sage to confirm which side is broken");
        assertEquals(new BigInteger(BLS_POSEIDON_1_2_HEX, 16),
                PoseidonHash.hash(p, BigInteger.ONE, BigInteger.TWO),
                "BLS12-381 Poseidon(1, 2) diverged");
        assertEquals(new BigInteger(BLS_POSEIDON_123_456_HEX, 16),
                PoseidonHash.hash(p, BigInteger.valueOf(123), BigInteger.valueOf(456)),
                "BLS12-381 Poseidon(123, 456) diverged");
    }

    @Test
    @DisplayName("BLS12-381 regression: in-circuit Poseidon gadget also produces the locked fixtures")
    void bls12_381_inCircuit_matchesLockedFixtures() {
        PoseidonParams p = PoseidonParamsBLS12_381T3.INSTANCE;
        BigInteger[] inputs = { BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                BigInteger.valueOf(123), BigInteger.valueOf(456) };
        BigInteger[][] pairs = {
                { inputs[0], inputs[0] }, // (0, 0)
                { inputs[1], inputs[2] }, // (1, 2)
                { inputs[3], inputs[4] }, // (123, 456)
        };
        String[] expectedHex = {
                BLS_POSEIDON_0_0_HEX, BLS_POSEIDON_1_2_HEX, BLS_POSEIDON_123_456_HEX
        };

        for (int i = 0; i < pairs.length; i++) {
            BigInteger expected = new BigInteger(expectedHex[i], 16);
            BigInteger a = pairs[i][0], b = pairs[i][1];
            var circuit = CircuitBuilder.create("bls_fixture_" + i)
                    .publicVar("hash").secretVar("a").secretVar("b")
                    .define(api -> {
                        var h = Poseidon.hash(api, p, api.var("a"), api.var("b"));
                        api.assertEqual(h, api.var("hash"));
                    });
            final int iter = i;
            assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                    "hash", List.of(expected),
                    "a", List.of(a),
                    "b", List.of(b)), CurveId.BLS12_381),
                    () -> "Fixture " + iter + " — circuit disagreed with locked hash for (" + a + ", " + b + ")");
        }
    }

    @Test
    @DisplayName("Variable-arity self-consistency: PoseidonHash.hashN == PoseidonN circuit for 1..5 inputs")
    void hashN_matchesPoseidonN_circuit() {
        PoseidonParams p = PoseidonParamsBLS12_381T3.INSTANCE;
        BigInteger[][] inputSets = {
                { BigInteger.valueOf(7) },
                { BigInteger.valueOf(7), BigInteger.valueOf(11) },
                { BigInteger.valueOf(7), BigInteger.valueOf(11), BigInteger.valueOf(13) },
                { BigInteger.valueOf(7), BigInteger.valueOf(11), BigInteger.valueOf(13), BigInteger.valueOf(17) },
                { BigInteger.valueOf(7), BigInteger.valueOf(11), BigInteger.valueOf(13), BigInteger.valueOf(17), BigInteger.valueOf(19) },
        };
        for (BigInteger[] inputs : inputSets) {
            BigInteger expected = PoseidonHash.hashN(p, inputs);

            // Build a matching N-input circuit
            var b = CircuitBuilder.create("pnXc_" + inputs.length).publicVar("hash");
            for (int i = 0; i < inputs.length; i++) b = b.secretVar("x" + i);
            final BigInteger[] inputsFinal = inputs;
            var circuit = b.define(api -> {
                com.bloxbean.cardano.zeroj.circuit.Variable[] vars = new com.bloxbean.cardano.zeroj.circuit.Variable[inputsFinal.length];
                for (int i = 0; i < inputsFinal.length; i++) vars[i] = api.var("x" + i);
                var h = com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN.hash(api, p, vars);
                api.assertEqual(h, api.var("hash"));
            });

            java.util.Map<String, java.util.List<BigInteger>> witnessInputs = new java.util.HashMap<>();
            witnessInputs.put("hash", List.of(expected));
            for (int i = 0; i < inputs.length; i++) {
                witnessInputs.put("x" + i, List.of(inputs[i]));
            }
            final int n = inputs.length;
            assertDoesNotThrow(() -> circuit.calculateWitness(witnessInputs, CurveId.BLS12_381),
                    () -> "hashN/PoseidonN disagree for N=" + n);
        }
    }

    @Test
    @DisplayName("Paper-spec: Java fixtures match the pinned SageMath reference output byte-for-byte")
    void java_matches_sageReferenceOutput() throws java.io.IOException {
        String golden;
        try (var in = getClass().getClassLoader().getResourceAsStream(
                "poseidon-sage/sage-reference-output.txt")) {
            if (in == null) {
                throw new IllegalStateException("sage-reference-output.txt missing from test resources");
            }
            golden = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
        // The golden file contains `Poseidon(a, b) = 0x<hex>` lines. Extract them and
        // compare to the locked BLS_POSEIDON_*_HEX constants (and thus to
        // PoseidonHash output, which the other tests in this class have already
        // proven equal to those constants).
        assertTrue(golden.contains("= 0x" + BLS_POSEIDON_0_0_HEX),
                "Sage golden file missing or stale Poseidon(0,0) — run docker reproduction");
        assertTrue(golden.contains("= 0x" + BLS_POSEIDON_1_2_HEX),
                "Sage golden file missing or stale Poseidon(1,2)");
        assertTrue(golden.contains("= 0x" + BLS_POSEIDON_123_456_HEX),
                "Sage golden file missing or stale Poseidon(123,456)");
    }

    @Test
    @DisplayName("Sanity: FieldConfig primes used by presets are distinct")
    void sanity_presetFieldsDistinct() {
        assertTrue(!PoseidonParamsBN254T3.INSTANCE.field().prime()
                .equals(PoseidonParamsBLS12_381T3.INSTANCE.field().prime()));
        assertEquals(FieldConfig.BN254, PoseidonParamsBN254T3.INSTANCE.field());
        assertEquals(FieldConfig.BLS12_381, PoseidonParamsBLS12_381T3.INSTANCE.field());
    }
}
