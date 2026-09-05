package com.bloxbean.cardano.zeroj.api;

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

    private static void expectMalformed(R1CSFlat flat, String fragment) {
        var ex = assertThrows(IllegalArgumentException.class, () -> R1CSValidation.requireWireIndices(flat, 4));
        assertTrue(ex.getMessage().contains(fragment), ex.getMessage());
    }
}
