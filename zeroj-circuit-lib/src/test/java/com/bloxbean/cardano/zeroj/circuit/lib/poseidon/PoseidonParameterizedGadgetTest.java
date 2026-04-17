package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.Poseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the parameterized {@link Poseidon} / {@link PoseidonN} overloads
 * added in step 3 of ADR-0015: new {@code PoseidonParams}-accepting overloads
 * alongside back-compat no-params overloads.
 */
class PoseidonParameterizedGadgetTest {

    // Known circomlibjs BN254 test vectors.
    private static final BigInteger POSEIDON_1_2_BN254 = new BigInteger(
            "7853200120776062878684798364095072458815029376092732009249414926327459813530");

    @Test
    @DisplayName("Explicit BN254_T3 params produce the same hash as the legacy no-params overload")
    void bn254T3_explicitParams_matchesLegacy() {
        var explicit = CircuitBuilder.create("poseidonExplicit")
                .secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, PoseidonParamsBN254T3.INSTANCE, api.var("a"), api.var("b"));
                    api.assertEqual(h, api.constant(POSEIDON_1_2_BN254));
                });

        var legacy = CircuitBuilder.create("poseidonLegacy")
                .secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, api.var("a"), api.var("b"));
                    api.assertEqual(h, api.constant(POSEIDON_1_2_BN254));
                });

        var inputs = Map.of(
                "a", List.of(BigInteger.ONE),
                "b", List.of(BigInteger.TWO));

        BigInteger[] wExplicit = explicit.calculateWitness(inputs, CurveId.BN254);
        BigInteger[] wLegacy = legacy.calculateWitness(inputs, CurveId.BN254);
        assertArrayEquals(wExplicit, wLegacy,
                "explicit BN254_T3 params must produce bit-identical witness to the legacy default");
    }

    @Test
    @DisplayName("BLS12-381 preset compiles over BLS12-381 scalar field and produces a different hash than BN254")
    void bls12_381T3_producesDifferentHashThanBn254() {
        // Build two circuits, one per preset, hashing the same inputs and capturing the output.
        // Witness layout is implementation-defined, but the last variable assigned (the output)
        // ends up at a consistent index — so to compare hashes we instead check that a witness
        // asserting one hash under the other preset will fail.
        var bls = CircuitBuilder.create("poseidonBls")
                .publicVar("hash").secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, PoseidonParamsBLS12_381T3.INSTANCE, api.var("a"), api.var("b"));
                    api.assertEqual(h, api.var("hash"));
                });

        // Passing the BN254 POSEIDON(1,2) hash as expected output when using BLS12-381
        // constants should fail — proving the gadget is actually using BLS12-381 constants.
        assertThrows(ArithmeticException.class, () -> bls.calculateWitness(Map.of(
                "hash", List.of(POSEIDON_1_2_BN254),
                "a", List.of(BigInteger.ONE),
                "b", List.of(BigInteger.TWO)), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("BLS12-381 preset: gadget produces SOME valid witness (no crashes on a new field)")
    void bls12_381T3_produces_witness() {
        // We don't yet have a published external Poseidon_BLS12_381(1, 2) triple
        // to assert against — that's step 4's job (standalone permutation oracle).
        // Here we just confirm compilation and witness calculation over BLS12-381
        // run to completion without arithmetic errors.
        var bls = CircuitBuilder.create("poseidonBls")
                .secretVar("a").secretVar("b")
                .define(api -> Poseidon.hash(api, PoseidonParamsBLS12_381T3.INSTANCE,
                        api.var("a"), api.var("b")));

        BigInteger[] witness = bls.calculateWitness(Map.of(
                "a", List.of(BigInteger.ONE),
                "b", List.of(BigInteger.TWO)), CurveId.BLS12_381);
        assertTrue(witness.length > 0);
    }

    @Test
    @DisplayName("Gadget rejects PoseidonParams with t != 3")
    void gadget_rejectsNonT3Params() {
        // Construct a plausibly-shaped params with t=5 (even though no BLS_T5 preset exists yet,
        // we can fake one up for the test by providing correctly-sized arrays).
        BigInteger[] c = new BigInteger[(8 + 60) * 5]; // RF=8, RP=60, t=5 => 340 constants
        BigInteger[] m = new BigInteger[5 * 5];
        for (int i = 0; i < c.length; i++) c[i] = BigInteger.ONE;
        for (int i = 0; i < m.length; i++) m[i] = BigInteger.ONE;
        PoseidonParams badShape = new PoseidonParams(
                com.bloxbean.cardano.zeroj.circuit.FieldConfig.BLS12_381, 5, 5, 8, 60, c, m);

        var circuit = CircuitBuilder.create("bad").secretVar("a").secretVar("b");
        assertThrows(IllegalArgumentException.class, () -> circuit.define(api ->
                Poseidon.hash(api, badShape, api.var("a"), api.var("b"))));
    }

    @Test
    @DisplayName("Field guard: BLS12-381 params compiled for BN254 curve throws at witness time")
    void fieldGuard_blsParams_bn254Curve_throws() {
        var circuit = CircuitBuilder.create("mismatch")
                .publicVar("hash").secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, PoseidonParamsBLS12_381T3.INSTANCE,
                            api.var("a"), api.var("b"));
                    api.assertEqual(h, api.var("hash"));
                });

        var ex = assertThrows(IllegalStateException.class, () -> circuit.calculateWitness(Map.of(
                "hash", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.ONE),
                "b", List.of(BigInteger.TWO)), CurveId.BN254));
        assertTrue(ex.getMessage().contains("Field mismatch"),
                "Expected field-mismatch message, got: " + ex.getMessage());
    }

    @Test
    @DisplayName("Field guard: BN254 params compiled for BLS12-381 curve throws at compile time")
    void fieldGuard_bn254Params_blsCurve_throws() {
        var circuit = CircuitBuilder.create("mismatch2")
                .publicVar("hash").secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, PoseidonParamsBN254T3.INSTANCE,
                            api.var("a"), api.var("b"));
                    api.assertEqual(h, api.var("hash"));
                });

        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BLS12_381));
    }

    @Test
    @DisplayName("Field guard: conflicting params within one circuit throw at define time")
    void fieldGuard_conflictingParams_throws() {
        var builder = CircuitBuilder.create("conflict")
                .secretVar("a").secretVar("b");

        assertThrows(IllegalStateException.class, () -> builder.define(api -> {
            Poseidon.hash(api, PoseidonParamsBN254T3.INSTANCE, api.var("a"), api.var("b"));
            // Second call with different field — should throw immediately.
            Poseidon.hash(api, PoseidonParamsBLS12_381T3.INSTANCE, api.var("a"), api.var("b"));
        }));
    }

    @Test
    @DisplayName("PoseidonN preserves legacy default when no params given")
    void poseidonN_legacyDefault_works() {
        var circuit = CircuitBuilder.create("pn")
                .secretVar("a").secretVar("b").secretVar("c")
                .define(api -> PoseidonN.hash(api, api.var("a"), api.var("b"), api.var("c")));

        BigInteger[] w = circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.valueOf(10)),
                "b", List.of(BigInteger.valueOf(20)),
                "c", List.of(BigInteger.valueOf(30))), CurveId.BN254);
        assertTrue(w.length > 0);
    }

    @Test
    @DisplayName("Gadget rejects PoseidonParams with alpha != 5")
    void gadget_rejectsNonAlpha5Params() {
        // Fake params with t=3 but alpha=3 (still constructible since PoseidonParams doesn't
        // enforce alpha=5 — only the Poseidon gadget does).
        BigInteger[] c = new BigInteger[(8 + 57) * 3];
        BigInteger[] m = new BigInteger[3 * 3];
        for (int i = 0; i < c.length; i++) c[i] = BigInteger.ONE;
        for (int i = 0; i < m.length; i++) m[i] = BigInteger.ONE;
        PoseidonParams wrongAlpha = new PoseidonParams(
                FieldConfig.BN254, 3, 3, 8, 57, c, m);

        var circuit = CircuitBuilder.create("bad").secretVar("a").secretVar("b");
        assertThrows(IllegalArgumentException.class, () -> circuit.define(api ->
                com.bloxbean.cardano.zeroj.circuit.lib.Poseidon.hash(api, wrongAlpha,
                        api.var("a"), api.var("b"))));
    }

    @Test
    @DisplayName("PoseidonN single input pads with zero and matches Poseidon(x, 0)")
    void poseidonN_singleInput_padsWithZero() {
        // Documented semantics: PoseidonN(x) = Poseidon(x, 0). Lock this in.
        var nHash = CircuitBuilder.create("pn1")
                .secretVar("a")
                .define(api -> PoseidonN.hash(api, api.var("a")));
        var p2Hash = CircuitBuilder.create("p2Zero")
                .secretVar("a")
                .define(api -> com.bloxbean.cardano.zeroj.circuit.lib.Poseidon.hash(
                        api, api.var("a"), api.constant(0)));

        var inputs = Map.of("a", List.of(BigInteger.valueOf(42)));
        assertArrayEquals(
                nHash.calculateWitness(inputs, CurveId.BN254),
                p2Hash.calculateWitness(inputs, CurveId.BN254));
    }

    @Test
    @DisplayName("Signal-API explicit-params overload delegates to the CircuitAPI overload")
    void signalApi_withParams_matchesCircuitApi() {
        var signalCircuit = CircuitBuilder.create("sigExplicit")
                .secretVar("a").secretVar("b")
                .defineSignals(c -> {
                    var h = com.bloxbean.cardano.zeroj.circuit.lib.Poseidon.hash(
                            c, PoseidonParamsBN254T3.INSTANCE,
                            c.privateInput("a"), c.privateInput("b"));
                    c.assertEqual(h, c.constant(POSEIDON_1_2_BN254));
                });
        var inputs = Map.of(
                "a", List.of(BigInteger.ONE),
                "b", List.of(BigInteger.TWO));
        assertTrue(signalCircuit.calculateWitness(inputs, CurveId.BN254).length > 0);
    }

    @Test
    @DisplayName("PoseidonN explicit params equivalent to legacy default for BN254_T3")
    void poseidonN_explicitParams_matchesLegacy() {
        var inputs = Map.of(
                "a", List.of(BigInteger.valueOf(10)),
                "b", List.of(BigInteger.valueOf(20)),
                "c", List.of(BigInteger.valueOf(30)),
                "d", List.of(BigInteger.valueOf(40)));

        var legacy = CircuitBuilder.create("pnLegacy")
                .secretVar("a").secretVar("b").secretVar("c").secretVar("d")
                .define(api -> PoseidonN.hash(api,
                        api.var("a"), api.var("b"), api.var("c"), api.var("d")));

        var explicit = CircuitBuilder.create("pnExplicit")
                .secretVar("a").secretVar("b").secretVar("c").secretVar("d")
                .define(api -> PoseidonN.hash(api, PoseidonParamsBN254T3.INSTANCE,
                        api.var("a"), api.var("b"), api.var("c"), api.var("d")));

        assertArrayEquals(
                legacy.calculateWitness(inputs, CurveId.BN254),
                explicit.calculateWitness(inputs, CurveId.BN254));
    }
}
