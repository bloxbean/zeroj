package com.bloxbean.cardano.zeroj.circuit;

import com.bloxbean.cardano.zeroj.api.CurveId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Adversarial tests for {@link CircuitAPI#lessThan}, per ADR-0037 Decision 2.
 *
 * <p>The comparison forms {@code diff = (2^n - 1) + b - a} and reads the top bit of an
 * {@code (n+1)}-bit decomposition. If either operand can exceed {@code 2^n} the subtraction
 * wraps modulo the field prime and the answer is meaningless. Before ADR-0037 the gadget
 * range-constrained neither operand, so <b>both</b> directions were forgeable:
 *
 * <ul>
 *   <li>an unconstrained <em>left</em> operand forges {@code a < b}
 *       — {@code lessThan(p-1, l, 252)} returned true;</li>
 *   <li>an unconstrained <em>right</em> operand forges {@code a >= b}
 *       — {@code greaterOrEqual(0, p-(2^64-1), 64)} returned true.</li>
 * </ul>
 *
 * <p>Each witness below is one that the pre-fix implementation accepted.
 */
class ComparatorSoundnessTest {

    /** BLS12-381 scalar field prime. */
    private static final BigInteger P = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    /** Jubjub subgroup order, the bound the EdDSA gadget compares against. */
    private static final BigInteger L = new BigInteger(
            "0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7", 16);

    // ------------------------------------------------------------------
    //  Forgeable direction 1: unconstrained LEFT operand claims a < b
    // ------------------------------------------------------------------

    @Nested
    @DisplayName("left operand unconstrained: 'a < b' must not be forgeable")
    class LeftOperand {

        private CircuitBuilder assertALessThanB(BigInteger bound, int nBits) {
            return CircuitBuilder.create("lt_left_" + nBits)
                    .secretVar("a")
                    .define(api -> api.assertEqual(
                            api.lessThan(api.var("a"), api.constant(bound), nBits), api.constant(1)));
        }

        @Test
        @DisplayName("lessThan(p-1, l, 252) is rejected (pre-fix: accepted)")
        void pMinusOneIsNotLessThanL() {
            var circuit = assertALessThanB(L, 252);
            assertThrows(Exception.class, () -> circuit.calculateWitness(
                    Map.of("a", List.of(P.subtract(BigInteger.ONE))), CurveId.BLS12_381),
                    "p-1 is far larger than l; accepting it would break the EdDSA S < l check");
        }

        @Test
        @DisplayName("lessThan(p-12345, l, 252) is rejected (pre-fix: accepted)")
        void anotherWrapBandWitnessRejected() {
            var circuit = assertALessThanB(L, 252);
            assertThrows(Exception.class, () -> circuit.calculateWitness(
                    Map.of("a", List.of(P.subtract(BigInteger.valueOf(12345)))), CurveId.BLS12_381));
        }

        @Test
        @DisplayName("lessThan(p-1, 10^6, 64) is rejected (pre-fix: accepted)")
        void smallWidthWrapBandRejected() {
            var circuit = assertALessThanB(BigInteger.valueOf(1_000_000L), 64);
            assertThrows(Exception.class, () -> circuit.calculateWitness(
                    Map.of("a", List.of(P.subtract(BigInteger.ONE))), CurveId.BLS12_381));
        }

        @Test
        @DisplayName("honest a < b still accepted")
        void honestCaseAccepted() {
            var circuit = assertALessThanB(L, 252);
            assertDoesNotThrow(() -> circuit.calculateWitness(
                    Map.of("a", List.of(L.subtract(BigInteger.ONE))), CurveId.BLS12_381));
        }

        @Test
        @DisplayName("honest a == b correctly rejected")
        void equalCaseRejected() {
            var circuit = assertALessThanB(L, 252);
            assertThrows(Exception.class, () -> circuit.calculateWitness(
                    Map.of("a", List.of(L)), CurveId.BLS12_381));
        }
    }

    // ------------------------------------------------------------------
    //  Forgeable direction 2: unconstrained RIGHT operand claims a >= b
    // ------------------------------------------------------------------

    @Nested
    @DisplayName("right operand unconstrained: 'a >= b' must not be forgeable")
    class RightOperand {

        /** greaterOrEqual(a, b) == !lessThan(a, b) — the shape both example circuits use. */
        private CircuitBuilder assertAGreaterOrEqualB(int nBits) {
            return CircuitBuilder.create("ge_right_" + nBits)
                    .publicVar("b").secretVar("a")
                    .define(api -> api.assertEqual(
                            api.not(api.lessThan(api.var("a"), api.var("b"), nBits)), api.constant(1)));
        }

        @Test
        @DisplayName("0 >= p-(2^64-1) is rejected (pre-fix: accepted)")
        void zeroIsNotGreaterThanHugeThreshold() {
            var circuit = assertAGreaterOrEqualB(64);
            BigInteger b = P.subtract(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE));
            assertThrows(Exception.class, () -> circuit.calculateWitness(
                    Map.of("b", List.of(b), "a", List.of(BigInteger.ZERO)), CurveId.BLS12_381),
                    "0 >= p-(2^64-1) is false; accepting it defeats any threshold/reserve check");
        }

        @Test
        @DisplayName("a small bid 'clears' a wrapped reserve price — rejected (pre-fix: accepted)")
        void smallValueDoesNotClearWrappedThreshold() {
            var circuit = assertAGreaterOrEqualB(64);
            BigInteger b = P.subtract(BigInteger.ONE.shiftLeft(64)).add(BigInteger.valueOf(100));
            assertThrows(Exception.class, () -> circuit.calculateWitness(
                    Map.of("b", List.of(b), "a", List.of(BigInteger.valueOf(42))), CurveId.BLS12_381));
        }

        @Test
        @DisplayName("honest a >= b still accepted")
        void honestCaseAccepted() {
            var circuit = assertAGreaterOrEqualB(64);
            assertDoesNotThrow(() -> circuit.calculateWitness(
                    Map.of("b", List.of(BigInteger.valueOf(1_000_000L)),
                           "a", List.of(BigInteger.valueOf(1_000_001L))), CurveId.BLS12_381));
        }

        @Test
        @DisplayName("honest a < b correctly rejected")
        void belowThresholdRejected() {
            var circuit = assertAGreaterOrEqualB(64);
            assertThrows(Exception.class, () -> circuit.calculateWitness(
                    Map.of("b", List.of(BigInteger.valueOf(1_000_000L)),
                           "a", List.of(BigInteger.valueOf(999_999L))), CurveId.BLS12_381));
        }
    }

    // ------------------------------------------------------------------
    //  Constant operands are validated statically, not silently wrapped
    // ------------------------------------------------------------------

    @Test
    @DisplayName("a constant operand too large for nBits throws at definition time")
    void oversizedConstantRejectedAtDefineTime() {
        var ex = assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("const_too_big").secretVar("a")
                        .define(api -> api.lessThan(api.var("a"), api.constant(P.subtract(BigInteger.ONE)), 64)));
        assertTrue(ex.getMessage().contains("does not fit in 64 bits"), ex.getMessage());
    }

    @Test
    @DisplayName("a constant operand that fits is accepted and emits no decomposition for it")
    void fittingConstantAccepted() {
        assertDoesNotThrow(() -> CircuitBuilder.create("const_ok").secretVar("a")
                .define(api -> api.lessThan(api.var("a"), api.constant(1000), 64)));
    }

    // ------------------------------------------------------------------
    //  BitDecomposition reuse
    // ------------------------------------------------------------------

    @Test
    @DisplayName("BitDecomposition overload reuses the bound instead of re-deriving it")
    void bitDecompositionOverloadAvoidsDuplicateRangeConstraints() {
        var withReuse = CircuitBuilder.create("lt_reuse")
                .secretVar("a").secretVar("b")
                .define(api -> {
                    var da = api.decompose(api.var("a"), 64);
                    var db = api.decompose(api.var("b"), 64);
                    api.lessThan(da, db);
                });
        var withoutReuse = CircuitBuilder.create("lt_noreuse")
                .secretVar("a").secretVar("b")
                .define(api -> {
                    api.decompose(api.var("a"), 64);
                    api.decompose(api.var("b"), 64);
                    api.lessThan(api.var("a"), api.var("b"), 64);
                });
        int reuse = withReuse.compileR1CS(CurveId.BLS12_381).constraints().size();
        int noReuse = withoutReuse.compileR1CS(CurveId.BLS12_381).constraints().size();
        // The Variable overload must notice the existing bounds and not re-decompose either
        // operand, so the two forms cost the same.
        assertEquals(reuse, noReuse,
                "an already-established range bound should not be re-emitted");
    }

    @Test
    @DisplayName("an existing tighter bound satisfies a looser request; a looser one does not satisfy a tighter")
    void rangeBoundCacheRespectsTightening() {
        // 32-bit bound already proven; asking for 64 must not re-emit.
        var tightThenLoose = CircuitBuilder.create("tight_then_loose")
                .secretVar("a")
                .define(api -> {
                    api.decompose(api.var("a"), 32);
                    api.lessThan(api.var("a"), api.constant(1000), 64);
                });
        // 64-bit bound already proven; asking for 32 must emit the tighter one.
        var looseThenTight = CircuitBuilder.create("loose_then_tight")
                .secretVar("a")
                .define(api -> {
                    api.decompose(api.var("a"), 64);
                    api.lessThan(api.var("a"), api.constant(1000), 32);
                });
        int a = tightThenLoose.compileR1CS(CurveId.BLS12_381).constraints().size();
        int b = looseThenTight.compileR1CS(CurveId.BLS12_381).constraints().size();
        assertTrue(b > a,
                "a tighter request must emit a new bound; got loose-then-tight=" + b
                        + " vs tight-then-loose=" + a);

        // And the tighter bound must actually bite at witness time.
        assertThrows(Exception.class, () -> looseThenTight.calculateWitness(
                Map.of("a", List.of(BigInteger.ONE.shiftLeft(40))), CurveId.BLS12_381),
                "2^40 exceeds the 32-bit bound and must be rejected");
    }

    @Test
    @DisplayName("BitDecomposition binds its source variable and is immutable")
    void bitDecompositionIsBoundAndImmutable() {
        CircuitBuilder.create("bd_props").secretVar("a").define(api -> {
            var d = api.decompose(api.var("a"), 8);
            assertEquals(api.var("a"), d.source());
            assertEquals(8, d.width());
            Variable[] first = d.bits();
            first[0] = null;                       // mutate the copy
            assertEquals(8, d.bits().length);
            org.junit.jupiter.api.Assertions.assertNotNull(d.bits()[0],
                    "bits() must return a defensive copy");
        });
    }
}
