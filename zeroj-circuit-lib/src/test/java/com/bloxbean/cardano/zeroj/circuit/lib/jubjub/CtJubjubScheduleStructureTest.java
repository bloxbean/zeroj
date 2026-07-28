package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.HardenedBytecodePolicy.read;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Deterministic CI gate for the compiled fixed-limb secret-scalar schedule.
 *
 * <p>Functional vectors cannot detect a secret branch whose two arms return the same point.
 * This test therefore pins the compiled call structure and proves that the scalar bit only
 * reaches the branch-free mask-selection chain. It establishes a uniform high-level
 * operation schedule; it does not claim JVM- or machine-level constant time.
 */
class CtJubjubScheduleStructureTest {

    private static final String POINT =
            "com/bloxbean/cardano/zeroj/circuit/lib/jubjub/CtJubjubPointOps";
    private static final String FQ =
            "com/bloxbean/cardano/zeroj/circuit/lib/jubjub/CtJubjubFqOps";
    private static final String FR =
            "com/bloxbean/cardano/zeroj/circuit/lib/jubjub/CtJubjubFrOps";
    private static final String MONTGOMERY =
            "com/bloxbean/cardano/zeroj/circuit/lib/jubjub/CtMontgomery256Ops";

    private static final String POINT_BINARY =
            "([JI[JI[JI[JI)V";
    private static final String POINT_UNARY =
            "([JI[JI[JI)V";
    private static final String POINT_SELECT =
            "([JI[JI[JIJ)V";

    @Test
    @DisplayName("fixed-limb scalar multiplication has the pinned branch-free schedule")
    void scalarMultiplicationScheduleIsPinned() throws Exception {
        HardenedBytecodePolicy.ClassFile point = read(CtJubjubPointOps.class);
        HardenedBytecodePolicy.MethodCode add = point.method("add", POINT_BINARY);
        HardenedBytecodePolicy.MethodCode doubled =
                point.method("doublePoint", POINT_UNARY);
        HardenedBytecodePolicy.MethodCode select =
                point.method("select", POINT_SELECT);
        HardenedBytecodePolicy.MethodCode scalarMul =
                point.method("scalarMul", POINT_BINARY);

        assertFqCalls(add, "mul", 9);
        assertFqCalls(add, "add", 5);
        assertFqCalls(add, "sub", 4);
        assertEquals(0, add.conditionalBranchCount());
        assertEquals(0, add.unconditionalBranchCount());

        assertFqCalls(doubled, "mul", 4);
        assertFqCalls(doubled, "square", 4);
        assertFqCalls(doubled, "add", 3);
        assertFqCalls(doubled, "sub", 4);
        assertFqCalls(doubled, "neg", 1);
        assertEquals(0, doubled.conditionalBranchCount());
        assertEquals(0, doubled.unconditionalBranchCount());

        assertFqCalls(select, "select", 1);
        assertEquals(1, select.conditionalBranchCount(),
                "only the fixed four-coordinate loop may branch");
        assertEquals(1, select.unconditionalBranchCount());

        assertEquals(1, scalarMul.callsTo(POINT, "add"));
        assertEquals(1, scalarMul.callsTo(POINT, "doublePoint"));
        assertEquals(1, scalarMul.callsTo(POINT, "select"));
        assertEquals(1, scalarMul.callsTo(FR, "toNormal"));
        assertTrue(scalarMul.containsIntPush(JubjubCurve.SCALAR_BITS),
                "compiled schedule must retain the fixed 252-bit loop bound");
        assertEquals(1, scalarMul.conditionalBranchCount(),
                "only the public fixed-loop counter may branch");
        assertEquals(1, scalarMul.unconditionalBranchCount());

        HardenedBytecodePolicy.MethodCode fqSelect =
                read(CtJubjubFqOps.class).method("select", POINT_SELECT);
        assertEquals(1, fqSelect.callsTo(MONTGOMERY, "select"));
        assertEquals(0, fqSelect.conditionalBranchCount());
        assertEquals(0, fqSelect.unconditionalBranchCount());

        HardenedBytecodePolicy.MethodCode limbSelect =
                read(CtMontgomery256Ops.class).method("select", POINT_SELECT);
        assertEquals(0, limbSelect.conditionalBranchCount(),
                "the scalar bit must select with masks, never a Java branch");
        assertEquals(0, limbSelect.unconditionalBranchCount());

        int iterations = JubjubCurve.SCALAR_BITS;
        ScheduleSignature kernel = new ScheduleSignature(
                1 + iterations * (9 + 4 + 4),
                iterations * (5 + 3),
                iterations * (4 + 4 + 1),
                iterations * 4,
                0);
        assertEquals(new ScheduleSignature(4_285, 2_016, 2_268, 1_008, 0),
                kernel);

        // Importing a canonical scalar performs one additional Montgomery multiplication.
        // This is the 4286/2016/2268/1008/0 signature measured by mutation review.
        assertEquals(4_286, kernel.multiplications() + 1);
    }

    @Test
    @DisplayName("reviewed scalar reductions retain their explicit fixed round counts")
    void reductionSchedulesArePinned() throws Exception {
        HardenedBytecodePolicy.ClassFile fr = read(CtJubjubFrOps.class);
        HardenedBytecodePolicy.MethodCode unsigned = fr.method(
                "fromUnsigned256Reduced", "([JI[BII[JI)J");
        HardenedBytecodePolicy.MethodCode fqReduction =
                fr.method("reduceFromFq", POINT_UNARY);
        HardenedBytecodePolicy.MethodCode nonZeroMapping =
                fr.method("mapFromFqNonZero", POINT_UNARY);

        assertTrue(unsigned.containsIntPush(17),
                "unsigned-256 reduction must retain all 17 rounds");
        assertEquals(1, unsigned.callsTo(MONTGOMERY, "conditionalSubtract"));

        assertTrue(fqReduction.containsIntPush(8),
                "p-to-l reduction must retain all eight rounds");
        assertEquals(1, fqReduction.callsTo(MONTGOMERY, "conditionalSubtract"));
        assertEquals(1, fqReduction.conditionalBranchCount());
        assertEquals(1, fqReduction.unconditionalBranchCount());

        assertTrue(nonZeroMapping.containsIntPush(8),
                "nonzero mapping must retain all eight reduction rounds");
        assertEquals(1, nonZeroMapping.callsTo(MONTGOMERY, "conditionalSubtract"));
        assertEquals(2, nonZeroMapping.conditionalBranchCount(),
                "only the fixed eight-round reduction and four-limb carry loops may branch");
        assertEquals(2, nonZeroMapping.unconditionalBranchCount());
    }

    private static void assertFqCalls(
            HardenedBytecodePolicy.MethodCode method, String name, long expected) {
        assertEquals(expected, method.callsTo(FQ, name),
                method.name() + " calls Fq." + name);
    }

    private record ScheduleSignature(
            int multiplications,
            int additions,
            int subtractions,
            int selections,
            int secretBranches) {
    }
}
