package org.zeroj.api;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Issue #46 — the shared relation-shape checks used by every Groth16 setup/prove ingress. */
class R1CSValidationTest {

    private static final BigInteger ONE = BigInteger.ONE;
    private static final int[] OUT_OF_RANGE = {4, 5, 1 << 30, Integer.MAX_VALUE, -1, Integer.MIN_VALUE};

    @Test
    void dimensions() {
        assertDoesNotThrow(() -> R1CSValidation.requireDimensions(1, 0));
        assertDoesNotThrow(() -> R1CSValidation.requireDimensions(4, 0));
        assertDoesNotThrow(() -> R1CSValidation.requireDimensions(4, 3));
        assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireDimensions(0, 0));
        assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireDimensions(-1, 0));
        assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireDimensions(4, -1));
        assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireDimensions(4, 4));
        assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireDimensions(4, 5));
    }

    private static List<R1CSConstraint> single(String matrix, int wire) {
        Map<Integer, BigInteger> a = matrix.equals("A") ? Map.of(wire, ONE) : Map.of(0, ONE);
        Map<Integer, BigInteger> b = matrix.equals("B") ? Map.of(wire, ONE) : Map.of(1, ONE);
        Map<Integer, BigInteger> c = matrix.equals("C") ? Map.of(wire, ONE) : Map.of(2, ONE);
        return List.of(new R1CSConstraint(a, b, c));
    }

    private static R1CSFlat flatOf(List<R1CSConstraint> cons) {
        var b = R1CSFlat.builder();
        for (var c : cons) b.add(c.a(), c.b(), c.c());
        return b.build();
    }

    @Test
    void list_acceptsInRangeAndRejectsOutOfRange_perMatrix() {
        var ok = List.of(new R1CSConstraint(Map.of(0, ONE, 3, ONE), Map.of(), Map.of(1, ONE)));
        assertDoesNotThrow(() -> R1CSValidation.requireWireIndices(ok, 4));
        // numWires - 1 is the last valid index; numWires is not
        assertDoesNotThrow(() -> R1CSValidation.requireWireIndices(single("A", 3), 4));
        for (String m : List.of("A", "B", "C")) {
            for (int bad : OUT_OF_RANGE) {
                var ex = assertThrows(IllegalArgumentException.class,
                        () -> R1CSValidation.requireWireIndices(single(m, bad), 4), m + "[" + bad + "]");
                assertTrue(ex.getMessage().contains("R1CS " + m + " row 0"), ex.getMessage());
                assertTrue(ex.getMessage().contains("wire " + bad), ex.getMessage());
            }
        }
        // a later row is reported with its index
        var rows = List.of(single("A", 0).get(0), single("B", 7).get(0));
        var ex = assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireWireIndices(rows, 4));
        assertTrue(ex.getMessage().contains("R1CS B row 1"), ex.getMessage());
        // the lazy asList() view of a packed relation is validated the same way
        assertDoesNotThrow(() -> R1CSValidation.requireWireIndices(flatOf(ok).asList(), 4));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requireWireIndices(flatOf(single("C", 4)).asList(), 4));
    }

    @Test
    void list_rejectsNullsAndBadNumWires() {
        var ok = single("A", 0);
        assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireWireIndices((List<R1CSConstraint>) null, 4));
        assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireWireIndices(ok, 0));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requireWireIndices(Arrays.asList((R1CSConstraint) null), 4));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requireWireIndices(List.of(new R1CSConstraint(null, Map.of(), Map.of())), 4));
        Map<Integer, BigInteger> nullCoefficient = new HashMap<>();
        nullCoefficient.put(1, null);
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requireWireIndices(List.of(new R1CSConstraint(nullCoefficient, Map.of(), Map.of())), 4));
    }

    @Test
    void flat_acceptsInRangeAndRejectsOutOfRange_perMatrix() {
        var ok = flatOf(List.of(new R1CSConstraint(Map.of(0, ONE, 3, ONE), Map.of(), Map.of(1, ONE))));
        assertDoesNotThrow(() -> R1CSValidation.requireWireIndices(ok, 4));
        assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireWireIndices(ok, 3));
        for (String m : List.of("A", "B", "C")) {
            for (int bad : OUT_OF_RANGE) {
                var flat = flatOf(single(m, bad));
                var ex = assertThrows(IllegalArgumentException.class,
                        () -> R1CSValidation.requireWireIndices(flat, 4), m + "[" + bad + "]");
                assertTrue(ex.getMessage().contains("R1CS " + m + " row 0"), ex.getMessage());
                assertTrue(ex.getMessage().contains("wire " + bad), ex.getMessage());
            }
        }
        assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireWireIndices((R1CSFlat) null, 4));
        assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireWireIndices(ok, 0));
    }

    @Test
    void flat_rejectsMalformedCsrStructure() {
        BigInteger[] dict = {ONE};
        var empty = new R1CSFlat.HeapMatrix(new int[]{0, 0}, new int[0], new int[0]);
        var good = new R1CSFlat.HeapMatrix(new int[]{0, 1}, new int[]{0}, new int[]{0});
        assertDoesNotThrow(() -> R1CSValidation.requireWireIndices(R1CSFlat.fromArrays(1, good, empty, empty, dict), 4));

        // row end past the stored terms
        var endPastNnz = new R1CSFlat.HeapMatrix(new int[]{0, 2}, new int[]{0}, new int[]{0});
        expectMalformed(R1CSFlat.fromArrays(1, endPastNnz, empty, empty, dict), "CSR row offsets");
        // row start not at the previous row's end
        var gap = new R1CSFlat.HeapMatrix(new int[]{1, 1}, new int[]{0}, new int[]{0});
        expectMalformed(R1CSFlat.fromArrays(1, empty, gap, empty, dict), "CSR row offsets");
        // row end before its start (two rows, so the sibling matrices need two-row offsets too)
        var empty2 = new R1CSFlat.HeapMatrix(new int[]{0, 0, 0}, new int[0], new int[0]);
        var reversed = new R1CSFlat.HeapMatrix(new int[]{0, 2, 1}, new int[]{0, 0}, new int[]{0, 0});
        expectMalformed(R1CSFlat.fromArrays(2, empty2, empty2, reversed, dict), "CSR row offsets");
        // stored terms no row reaches
        var trailing = new R1CSFlat.HeapMatrix(new int[]{0, 0}, new int[]{0}, new int[]{0});
        expectMalformed(R1CSFlat.fromArrays(1, trailing, empty, empty, dict), "unreachable trailing terms");
        // coefficient index outside the dictionary
        var badCoefficient = new R1CSFlat.HeapMatrix(new int[]{0, 1}, new int[]{0}, new int[]{1});
        expectMalformed(R1CSFlat.fromArrays(1, badCoefficient, empty, empty, dict), "outside the dictionary");
        var negativeCoefficient = new R1CSFlat.HeapMatrix(new int[]{0, 1}, new int[]{0}, new int[]{-1});
        expectMalformed(R1CSFlat.fromArrays(1, empty, negativeCoefficient, empty, dict), "outside the dictionary");
    }

    // ---- ADR-0045 S1: every public wire (and the constant wire) must be bound -----------------

    /** A stand-in scalar-field order: small enough to make "coefficient ≡ 0 mod r" cases explicit. */
    private static final BigInteger R = BigInteger.valueOf(101);

    /** {@code a * b = c} over {@code [1, c, p, a, b]} with public {@code c, p}; {@code p} is unbound. */
    private static List<R1CSConstraint> unboundPublic() {
        return List.of(new R1CSConstraint(Map.of(3, ONE), Map.of(4, ONE), Map.of(1, ONE)),
                new R1CSConstraint(Map.of(0, ONE), Map.of(0, ONE), Map.of(0, ONE)));
    }

    @Test
    void publicWires_acceptsWhenEveryPublicWireIsBoundInAnyMatrix() {
        for (String m : List.of("A", "B", "C")) {
            var bound = new java.util.ArrayList<>(unboundPublic());
            bound.add(new R1CSConstraint(
                    m.equals("A") ? Map.of(2, ONE) : Map.of(),
                    m.equals("B") ? Map.of(2, ONE) : Map.of(),
                    m.equals("C") ? Map.of(2, ONE) : Map.of()));
            assertDoesNotThrow(() -> R1CSValidation.requirePublicWiresConstrained(bound, 2, R), m);
            assertDoesNotThrow(() -> R1CSValidation.requirePublicWiresConstrained(flatOf(bound), 2, R), m);
        }
        // numPublic = 0: only the constant wire must be bound
        var constantOnly = List.of(new R1CSConstraint(Map.of(0, ONE), Map.of(), Map.of()));
        assertDoesNotThrow(() -> R1CSValidation.requirePublicWiresConstrained(constantOnly, 0, R));
        assertDoesNotThrow(() -> R1CSValidation.requirePublicWiresConstrained(flatOf(constantOnly), 0, R));
    }

    @Test
    void publicWires_rejectsUnboundPublicWire_namingIt() {
        var ex = assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained(unboundPublic(), 2, R));
        assertTrue(ex.getMessage().contains("public wire 2"), ex.getMessage());
        assertTrue(ex.getMessage().contains("IC[2]"), ex.getMessage());
        var exFlat = assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained(flatOf(unboundPublic()), 2, R));
        assertTrue(exFlat.getMessage().contains("public wire 2"), exFlat.getMessage());
        // the same relation declared with one public input (p private) is fine
        assertDoesNotThrow(() -> R1CSValidation.requirePublicWiresConstrained(unboundPublic(), 1, R));
    }

    @Test
    void publicWires_rejectsRelationWithoutConstantTerm() {
        var noConstant = List.of(new R1CSConstraint(Map.of(2, ONE), Map.of(3, ONE), Map.of(1, ONE)));
        var ex = assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained(noConstant, 1, R));
        assertTrue(ex.getMessage().contains("constant wire 0"), ex.getMessage());
        assertTrue(ex.getMessage().contains("IC[0]"), ex.getMessage());
        var exFlat = assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained(flatOf(noConstant), 1, R));
        assertTrue(exFlat.getMessage().contains("constant wire 0"), exFlat.getMessage());
    }

    @Test
    void publicWires_coefficientZeroModuloFieldDoesNotBind() {
        // p appears, but only with coefficients that are 0 mod R (0, R, 2R, -R): not bound
        for (BigInteger zeroish : List.of(BigInteger.ZERO, R, R.shiftLeft(1), R.negate())) {
            var withZeroTerm = new java.util.ArrayList<>(unboundPublic());
            var lc = new HashMap<Integer, BigInteger>();
            lc.put(2, zeroish);
            withZeroTerm.add(new R1CSConstraint(lc, Map.of(0, ONE), Map.of()));
            var ex = assertThrows(IllegalArgumentException.class,
                    () -> R1CSValidation.requirePublicWiresConstrained(withZeroTerm, 2, R), zeroish.toString());
            assertTrue(ex.getMessage().contains("public wire 2"), ex.getMessage());
        }
        // a coefficient that is nonzero mod R but numerically "large" does bind
        var withLargeTerm = new java.util.ArrayList<>(unboundPublic());
        withLargeTerm.add(new R1CSConstraint(Map.of(2, R.add(ONE)), Map.of(0, ONE), Map.of()));
        assertDoesNotThrow(() -> R1CSValidation.requirePublicWiresConstrained(withLargeTerm, 2, R));
        // CSR form reduces dictionary entries the same way
        BigInteger[] dict = {R};
        var empty = new R1CSFlat.HeapMatrix(new int[]{0, 0}, new int[0], new int[0]);
        var pOnlyZeroCoefficient = new R1CSFlat.HeapMatrix(new int[]{0, 2}, new int[]{0, 1}, new int[]{0, 0});
        var flat = R1CSFlat.fromArrays(1, pOnlyZeroCoefficient, empty, empty, dict);
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained(flat, 1, R));
    }

    @Test
    void publicWires_rejectsBadArguments() {
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained((List<R1CSConstraint>) null, 1, R));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained((R1CSFlat) null, 1, R));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained(unboundPublic(), -1, R));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained(unboundPublic(), 1, null));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained(unboundPublic(), 1, BigInteger.ZERO));
        // the scan stops once every public wire is bound, so the null row must come first to be seen
        var nullRow = Arrays.asList(null, new R1CSConstraint(Map.of(0, ONE), Map.of(), Map.of()));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained(nullRow, 0, R));
    }

    private static void expectMalformed(R1CSFlat flat, String fragment) {
        var ex = assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireWireIndices(flat, 4));
        assertTrue(ex.getMessage().contains(fragment), ex.getMessage());
    }
}
