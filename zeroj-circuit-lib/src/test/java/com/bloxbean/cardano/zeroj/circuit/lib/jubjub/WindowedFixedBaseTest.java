package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0037 M5 item 3: the windowed fixed-base scalar multiplication.
 *
 * <p>The windowed form replaces one conditional addition per bit with one addition per 3-bit
 * window, selecting the table entry through the multilinear (Möbius) form of the table rather
 * than a mux tree. Since the table entries are compile-time constants and the compiler folds
 * constant multiplications, the selection is nearly free.
 *
 * <p>That correctness argument holds <em>only on the boolean cube</em>, so these tests cover
 * both halves: agreement with the bit-by-bit reference across the interesting scalars, and
 * rejection of a non-boolean "bit".
 */
class WindowedFixedBaseTest {

    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;

    /** Scalars chosen to hit the window boundaries, not just random values. */
    private static BigInteger[] interestingScalars() {
        return new BigInteger[]{
                BigInteger.ZERO,
                BigInteger.ONE,
                BigInteger.valueOf(7),          // fills exactly one 3-bit window
                BigInteger.valueOf(8),          // first value needing a second window
                BigInteger.valueOf(63),         // two full windows
                BigInteger.valueOf(64),
                BigInteger.valueOf(123_456_789L),
                BigInteger.ONE.shiftLeft(251),  // only the top window set
                L.subtract(BigInteger.ONE),     // largest valid Jubjub scalar
        };
    }

    @Test
    @DisplayName("windowed result matches off-circuit [k]·G across window boundaries")
    void matchesOffCircuit() {
        for (BigInteger k : interestingScalars()) {
            JubjubPoint expected = G.scalarMul(k);
            var circuit = CircuitBuilder.create("win_" + k.bitLength())
                    .publicVar("outU").publicVar("outV").secretVar("k")
                    .define(api -> {
                        var r = InCircuitJubjub.scalarMulFixedBase(api, G, api.var("k"), 252);
                        api.assertEqual(api.mul(api.var("outU"), r.z()), r.u());
                        api.assertEqual(api.mul(api.var("outV"), r.z()), r.v());
                    });
            assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                    "outU", List.of(expected.affineU()),
                    "outV", List.of(expected.affineV()),
                    "k", List.of(k)), CurveId.BLS12_381),
                    () -> "windowed [k]·G disagreed with off-circuit for k=" + k);
        }
    }

    @Test
    @DisplayName("windowed agrees with the bit-by-bit reference on random scalars")
    void agreesWithBitwiseReference() {
        Random rnd = new Random(0xC0FFEE);   // fixed seed: reproducible failures
        for (int i = 0; i < 12; i++) {
            BigInteger k = new BigInteger(252, rnd).mod(L);
            JubjubPoint expected = G.scalarMul(k);

            var windowed = CircuitBuilder.create("dw_" + i)
                    .publicVar("outU").publicVar("outV").secretVar("k")
                    .define(api -> {
                        var r = InCircuitJubjub.scalarMulFixedBaseWindowed(
                                api, G, api.decompose(api.var("k"), 252).bits());
                        api.assertEqual(api.mul(api.var("outU"), r.z()), r.u());
                        api.assertEqual(api.mul(api.var("outV"), r.z()), r.v());
                    });
            var bitwise = CircuitBuilder.create("db_" + i)
                    .publicVar("outU").publicVar("outV").secretVar("k")
                    .define(api -> {
                        var r = InCircuitJubjub.scalarMulFixedBaseBitwise(
                                api, G, api.decompose(api.var("k"), 252).bits());
                        api.assertEqual(api.mul(api.var("outU"), r.z()), r.u());
                        api.assertEqual(api.mul(api.var("outV"), r.z()), r.v());
                    });
            var w = Map.of("outU", List.of(expected.affineU()),
                    "outV", List.of(expected.affineV()), "k", List.of(k));
            final int iter = i;
            assertDoesNotThrow(() -> windowed.calculateWitness(w, CurveId.BLS12_381),
                    () -> "windowed failed at i=" + iter);
            assertDoesNotThrow(() -> bitwise.calculateWitness(w, CurveId.BLS12_381),
                    () -> "bitwise reference failed at i=" + iter);
        }
    }

    @Test
    @DisplayName("a wrong output is still rejected — the test above is not vacuous")
    void wrongOutputRejected() {
        var circuit = CircuitBuilder.create("win_neg")
                .publicVar("outU").publicVar("outV").secretVar("k")
                .define(api -> {
                    var r = InCircuitJubjub.scalarMulFixedBase(api, G, api.var("k"), 252);
                    api.assertEqual(api.mul(api.var("outU"), r.z()), r.u());
                    api.assertEqual(api.mul(api.var("outV"), r.z()), r.v());
                });
        assertThrows(Exception.class, () -> circuit.calculateWitness(Map.of(
                "outU", List.of(BigInteger.valueOf(999)),
                "outV", List.of(BigInteger.valueOf(888)),
                "k", List.of(BigInteger.valueOf(5))), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("a non-boolean scalar bit is rejected — the multilinear form needs the boolean cube")
    void nonBooleanBitRejected() {
        // Feed the bits directly so a caller can attempt to supply 2 instead of 0/1. The
        // multilinear selector interpolates the table only at boolean assignments, so without
        // the booleanity assertion this would select a point that is in no table at all.
        var circuit = CircuitBuilder.create("win_nonbool")
                .publicVar("outU").publicVar("outV")
                .secretVar("b0").secretVar("b1").secretVar("b2")
                .define(api -> {
                    var bits = new com.bloxbean.cardano.zeroj.circuit.Variable[]{
                            api.var("b0"), api.var("b1"), api.var("b2")};
                    var r = InCircuitJubjub.scalarMulFixedBaseWindowed(api, G, bits);
                    api.assertEqual(api.mul(api.var("outU"), r.z()), r.u());
                    api.assertEqual(api.mul(api.var("outV"), r.z()), r.v());
                });
        JubjubPoint two = G.scalarMul(BigInteger.TWO);
        assertThrows(Exception.class, () -> circuit.calculateWitness(Map.of(
                "outU", List.of(two.affineU()), "outV", List.of(two.affineV()),
                "b0", List.of(BigInteger.TWO),        // not boolean
                "b1", List.of(BigInteger.ZERO),
                "b2", List.of(BigInteger.ZERO)), CurveId.BLS12_381),
                "a non-boolean bit must be rejected by the booleanity constraint");

        // Sanity: the same circuit accepts the honest boolean encoding of 2 = 0b010.
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(two.affineU()), "outV", List.of(two.affineV()),
                "b0", List.of(BigInteger.ZERO),
                "b1", List.of(BigInteger.ONE),
                "b2", List.of(BigInteger.ZERO)), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("windowing is cheaper than the bit-by-bit form it replaced")
    void windowedIsCheaper() {
        int windowed = CircuitBuilder.create("cost_w").secretVar("k")
                .define(api -> InCircuitJubjub.scalarMulFixedBaseWindowed(
                        api, G, api.decompose(api.var("k"), 252).bits()))
                .compileR1CS(CurveId.BLS12_381).constraints().size();
        int bitwise = CircuitBuilder.create("cost_b").secretVar("k")
                .define(api -> InCircuitJubjub.scalarMulFixedBaseBitwise(
                        api, G, api.decompose(api.var("k"), 252).bits()))
                .compileR1CS(CurveId.BLS12_381).constraints().size();
        assertEquals(1_506, windowed, "252-bit windowed fixed-base cost");
        assertEquals(2_513, bitwise, "252-bit bit-by-bit fixed-base cost");
        assertTrue(windowed < bitwise);
    }

    @Test
    @DisplayName("Pedersen commitments still match off-circuit after windowing")
    void pedersenStillCorrect() {
        BigInteger v = BigInteger.valueOf(42), r = BigInteger.valueOf(12345);
        JubjubPoint expected = PedersenCommitment.commit(v, r);
        var circuit = CircuitBuilder.create("ped_win")
                .publicVar("outU").publicVar("outV").secretVar("v").secretVar("r")
                .define(api -> {
                    var c = InCircuitPedersen.commit(api, api.var("v"), api.var("r"), 252);
                    api.assertEqual(api.mul(api.var("outU"), c.z()), c.u());
                    api.assertEqual(api.mul(api.var("outV"), c.z()), c.v());
                });
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(expected.affineU()),
                "outV", List.of(expected.affineV()),
                "v", List.of(v), "r", List.of(r)), CurveId.BLS12_381));
    }
}
