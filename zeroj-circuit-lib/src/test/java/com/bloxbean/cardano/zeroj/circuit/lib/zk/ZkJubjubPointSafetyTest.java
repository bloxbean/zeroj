package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0038 P2: {@link ZkJubjubPoint} is safe by construction.
 *
 * <p>Before this milestone the adapter emitted no point-validity constraints at all —
 * {@code fromTrustedAffine} pinned {@code z = 1} and {@code t = u·v} without asserting the
 * curve equation, and {@code assertWellFormed()} delegated to four empty
 * {@link ZkField#assertWellFormed()} calls. An off-curve {@code (1,1)} was accepted.
 *
 * <p>The invalid-point tests here assert <b>witness-time</b> rejection, which is the right
 * level for this defect: the constraints now exist in the compiled system, and an off-curve
 * assignment fails to satisfy them. That is different from P1, where the failure mode was a
 * missing constraint and only definition-time rejection could catch it.
 */
class ZkJubjubPointSafetyTest {

    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;

    // ------------------------------------------------------------------
    //  The reported defect: off-curve affine (1,1)
    // ------------------------------------------------------------------

    /**
     * {@code (u,v) = (1,1)} is not on Jubjub: {@code v² − u² = 0} but
     * {@code 1 + d·u²·v² = 1 + d ≠ 0}. ADR-0038 finding 1's exact witness.
     */
    @Test
    void offCurveAffinePoint_oneOne_rejected() {
        var circuit = affineBinderCircuit();

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                        "u", List.of(BigInteger.ONE),
                        "v", List.of(BigInteger.ONE)), CurveId.BLS12_381),
                "off-curve (1,1) must not satisfy the bound point's constraints");
    }

    @Test
    void offCurveAffinePoint_assortedWitnesses_rejected() {
        var circuit = affineBinderCircuit();

        for (BigInteger[] bad : new BigInteger[][]{
                {BigInteger.TWO, BigInteger.valueOf(3)},
                {BigInteger.valueOf(5), BigInteger.ZERO},
                {P.subtract(BigInteger.ONE), P.subtract(BigInteger.ONE)},
                {BigInteger.ZERO, BigInteger.TWO},
        }) {
            assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                            "u", List.of(bad[0]),
                            "v", List.of(bad[1])), CurveId.BLS12_381),
                    "off-curve (" + bad[0] + ", " + bad[1] + ") must be rejected");
        }
    }

    /** A genuine subgroup point must still be accepted — the binder must not over-constrain. */
    @Test
    void onCurveAffinePoint_accepted() {
        var circuit = affineBinderCircuit();
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "u", List.of(g.affineU()),
                "v", List.of(g.affineV())), CurveId.BLS12_381));
    }

    /** The identity (0,1) is on the curve and must be accepted by the binder. */
    @Test
    void identityAffinePoint_acceptedByBinder() {
        var circuit = affineBinderCircuit();

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                        "u", List.of(BigInteger.ZERO),
                        "v", List.of(BigInteger.ONE)), CurveId.BLS12_381),
                "the identity is a curve point; excluding it is a separate policy decision");
    }

    // ------------------------------------------------------------------
    //  The deprecated name must delegate to the safe binder, not merely be marked
    // ------------------------------------------------------------------

    /**
     * Proving delegation rather than annotation: the deprecated entry point must reject the
     * same off-curve witness the new one does. A {@code @Deprecated} tag that left the unsafe
     * body in place would pass a "is it deprecated" check and fail this one.
     */
    @Test
    void deprecatedFromTrustedAffine_delegatesToSafeBinder() {
        @SuppressWarnings("deprecation")
        var circuit = CircuitBuilder.create("deprecated-binder")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkJubjubPoint.fromTrustedAffine(
                            zk, ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v"));
                });

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                        "u", List.of(BigInteger.ONE),
                        "v", List.of(BigInteger.ONE)), CurveId.BLS12_381),
                "the deprecated name must bind safely, not just carry an annotation");
    }

    /** Both entry points must compile to exactly the same constraint system. */
    @Test
    void deprecatedAndNewBinder_produceIdenticalConstraintCounts() {
        @SuppressWarnings("deprecation")
        var viaDeprecated = CircuitBuilder.create("via-deprecated")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> ZkJubjubPoint.fromTrustedAffine(
                        new ZkContext(c), ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v")))
                .compileR1CS(CurveId.BLS12_381);

        var viaWitnessAffine = CircuitBuilder.create("via-witness-affine")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> ZkJubjubPoint.witnessAffine(
                        new ZkContext(c), ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v")))
                .compileR1CS(CurveId.BLS12_381);

        assertEquals(viaWitnessAffine.constraints().size(), viaDeprecated.constraints().size());
    }

    // ------------------------------------------------------------------
    //  Projective invariants via assertWellFormed()
    // ------------------------------------------------------------------

    /**
     * A valid rescaling {@code (λU, λV, λZ, λT)} is a legitimate representation of the same
     * point and must be <b>accepted</b>. This is the completeness half of the check — an
     * implementation that only accepted {@code Z = 1} would be over-constrained.
     */
    @Test
    void projectiveWellFormed_validRescaling_accepted() {
        var circuit = projectiveCircuit();
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        BigInteger lambda = BigInteger.valueOf(7);
        BigInteger u = g.affineU().multiply(lambda).mod(P);
        BigInteger v = g.affineV().multiply(lambda).mod(P);
        BigInteger z = lambda;
        // T = U·V/Z = λ·u·v
        BigInteger t = g.affineU().multiply(g.affineV()).mod(P).multiply(lambda).mod(P);

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                        "u", List.of(u), "v", List.of(v),
                        "z", List.of(z), "t", List.of(t)), CurveId.BLS12_381),
                "a rescaled representation of a valid point must be accepted");
    }

    /**
     * {@code Z = 0} must be rejected. This is the conjunct that excludes the all-zero forgery;
     * ADR-0037 records that the first proposed fix omitted it and left the forgery intact.
     */
    @Test
    void projectiveWellFormed_zeroZ_rejected() {
        var circuit = projectiveCircuit();

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                        "u", List.of(BigInteger.ZERO), "v", List.of(BigInteger.ONE),
                        "z", List.of(BigInteger.ZERO), "t", List.of(BigInteger.ZERO)),
                CurveId.BLS12_381));
    }

    /**
     * The all-zero point {@code (0,0,0,0)} satisfies the curve equation and the {@code T}
     * invariant identically — each reduces to {@code 0 == 0}. Only the {@code Z != 0} conjunct
     * rejects it.
     */
    @Test
    void projectiveWellFormed_allZeroPoint_rejected() {
        var circuit = projectiveCircuit();

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                        "u", List.of(BigInteger.ZERO), "v", List.of(BigInteger.ZERO),
                        "z", List.of(BigInteger.ZERO), "t", List.of(BigInteger.ZERO)),
                CurveId.BLS12_381),
                "the all-zero point passes both algebraic conjuncts and must be caught by Z != 0");
    }

    /**
     * Comparison helpers must reject malformed projective representations locally rather than
     * relying only on today's closed construction inventory. Otherwise all-zero cross-products
     * reduce to 0 == 0 and the identity predicate also returns true.
     */
    @Test
    void allZeroPoint_rejectedByEveryProjectiveComparisonBoundary() {
        for (String operation : List.of(
                "assertEqual", "isEqual", "isIdentity", "assertNotIdentity", "assertAffine")) {
            var circuit = rawProjectiveComparisonCircuit(operation);
            assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                            "u", List.of(BigInteger.ZERO),
                            "v", List.of(BigInteger.ZERO),
                            "z", List.of(BigInteger.ZERO),
                            "t", List.of(BigInteger.ZERO)),
                    CurveId.BLS12_381), operation);
        }
    }

    /** {@code T·Z == U·V} broken while the curve equation still holds. */
    @Test
    void projectiveWellFormed_brokenTInvariant_rejected() {
        var circuit = projectiveCircuit();
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                        "u", List.of(g.affineU()), "v", List.of(g.affineV()),
                        "z", List.of(BigInteger.ONE),
                        "t", List.of(g.affineU().multiply(g.affineV()).add(BigInteger.ONE).mod(P))),
                CurveId.BLS12_381));
    }

    /** Off-curve coordinates with a self-consistent {@code T} must still fail. */
    @Test
    void projectiveWellFormed_offCurveWithConsistentT_rejected() {
        var circuit = projectiveCircuit();
        BigInteger u = BigInteger.ONE, v = BigInteger.ONE;

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                        "u", List.of(u), "v", List.of(v),
                        "z", List.of(BigInteger.ONE),
                        "t", List.of(u.multiply(v).mod(P))), CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  Idempotency
    // ------------------------------------------------------------------

    /** A second {@code assertWellFormed()} on the same point must emit nothing further. */
    @Test
    void assertWellFormed_isIdempotent() {
        var once = projectiveCircuitWithAssertions(1).compileR1CS(CurveId.BLS12_381);
        var thrice = projectiveCircuitWithAssertions(3).compileR1CS(CurveId.BLS12_381);

        assertEquals(once.constraints().size(), thrice.constraints().size(),
                "repeated assertWellFormed() must not re-emit the projective invariants");
    }

    /** A point bound by the eager affine binder is already established; asserting is free. */
    @Test
    void assertWellFormed_onAffineBoundPoint_emitsNothing() {
        var plain = CircuitBuilder.create("affine-plain")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> ZkJubjubPoint.witnessAffine(
                        new ZkContext(c), ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v")))
                .compileR1CS(CurveId.BLS12_381);

        var asserted = CircuitBuilder.create("affine-asserted")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> ZkJubjubPoint.witnessAffine(
                                new ZkContext(c), ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v"))
                        .assertWellFormed())
                .compileR1CS(CurveId.BLS12_381);

        assertEquals(plain.constraints().size(), asserted.constraints().size(),
                "the affine binder already established well-formedness eagerly");
    }

    /** A constant point is validated at construction; asserting it is free too. */
    @Test
    void assertWellFormed_onConstantPoint_emitsNothing() {
        var plain = CircuitBuilder.create("const-plain")
                .publicVar("dummy")
                .defineSignals(c -> ZkJubjubPoint.constant(
                        new ZkContext(c), JubjubPoint.SUBGROUP_GENERATOR))
                .compileR1CS(CurveId.BLS12_381);

        var asserted = CircuitBuilder.create("const-asserted")
                .publicVar("dummy")
                .defineSignals(c -> ZkJubjubPoint.constant(
                        new ZkContext(c), JubjubPoint.SUBGROUP_GENERATOR).assertWellFormed())
                .compileR1CS(CurveId.BLS12_381);

        assertEquals(plain.constraints().size(), asserted.constraints().size());
    }

    /**
     * The projective assertion must actually cost something on a gadget-derived point —
     * otherwise the idempotency tests above would be vacuously satisfied by a no-op.
     */
    @Test
    void assertWellFormed_onProjectivePoint_actuallyEmitsConstraints() {
        var plain = CircuitBuilder.create("proj-plain")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkJubjubPoint.witnessAffine(zk, ZkField.publicInput(c, "u"),
                            ZkField.publicInput(c, "v")).doubled(zk);
                })
                .compileR1CS(CurveId.BLS12_381);

        var asserted = CircuitBuilder.create("proj-asserted")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkJubjubPoint.witnessAffine(zk, ZkField.publicInput(c, "u"),
                            ZkField.publicInput(c, "v")).doubled(zk).assertWellFormed();
                })
                .compileR1CS(CurveId.BLS12_381);

        assertTrue(asserted.constraints().size() > plain.constraints().size(),
                "assertWellFormed on a projective point must emit the invariants");
    }

    // ------------------------------------------------------------------
    //  R1CS-level pins: the rows must exist in the COMPILED system
    // ------------------------------------------------------------------

    /**
     * The invalid-point tests above assert at witness time, and {@code WitnessCalculator}
     * evaluates {@code Gate.AssertEq} whether or not {@code R1CSCompiler} emitted a row for it
     * — it drops rows whose difference expression is empty. So a gate that exists but compiles
     * away would leave every one of those tests green while the proof system accepted the
     * forgery. These absolute pins close that gap by measuring the compiled system.
     */
    @Test
    void witnessAffine_emitsFiveRowsInTheCompiledSystem() {
        var bound = affineBinderCircuit().compileR1CS(CurveId.BLS12_381);
        assertEquals(5, bound.constraints().size(),
                "witnessAffine: 3 squarings + curve equation + T = u*v");
    }

    @Test
    void assertWellFormed_emitsThirteenRowsInTheCompiledSystem() {
        var plain = CircuitBuilder.create("proj-plain-pin")
                .publicVar("u").publicVar("v").publicVar("z").publicVar("t")
                .defineSignals(c -> wrapProjective(c, 0))
                .compileR1CS(CurveId.BLS12_381);
        var asserted = CircuitBuilder.create("proj-asserted-pin")
                .publicVar("u").publicVar("v").publicVar("z").publicVar("t")
                .defineSignals(c -> wrapProjective(c, 1))
                .compileR1CS(CurveId.BLS12_381);

        assertEquals(13, asserted.constraints().size() - plain.constraints().size(),
                "assertWellFormed: curve equation + T invariant + Z != 0");
    }

    // ------------------------------------------------------------------
    //  A point that outlived its circuit must not appear to constrain it
    // ------------------------------------------------------------------

    /**
     * {@code assertWellFormed()} takes no {@link ZkContext} — {@code ZkValue} gives it none —
     * so it uses the context retained at construction. If that circuit has already been built,
     * the gate list has been snapshotted and anything emitted now is discarded. Returning
     * normally would be the worst outcome: the call also marks the point as established, so a
     * later, correctly-scoped assertion would be skipped as redundant.
     */
    @Test
    void assertWellFormed_afterCircuitIsBuilt_throwsRatherThanSilentlyDoingNothing() {
        var escaped = new java.util.concurrent.atomic.AtomicReference<ZkJubjubPoint>();
        CircuitBuilder.create("origin")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    escaped.set(ZkJubjubPoint.witnessAffine(
                            zk, ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v"))
                            .doubled(zk));
                });

        assertThrows(IllegalStateException.class, () -> escaped.get().assertWellFormed(),
                "a point whose circuit is already built must not silently emit nothing");
    }

    // ------------------------------------------------------------------
    //  Cross-builder inputs
    // ------------------------------------------------------------------

    @Test
    void crossBuilderCoordinates_rejected() {
        var foreign = new java.util.concurrent.atomic.AtomicReference<ZkField>();
        CircuitBuilder.create("foreign")
                .publicVar("fu")
                .defineSignals(c -> foreign.set(ZkField.publicInput(c, "fu")));

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("v")
                        .defineSignals(c -> ZkJubjubPoint.witnessAffine(
                                new ZkContext(c), foreign.get(), ZkField.publicInput(c, "v"))));
    }

    @Test
    void crossBuilderPointOperand_rejected() {
        var foreignPoint = new java.util.concurrent.atomic.AtomicReference<ZkJubjubPoint>();
        CircuitBuilder.create("foreign")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> foreignPoint.set(ZkJubjubPoint.witnessAffine(
                        new ZkContext(c), ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v"))));

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("u").publicVar("v")
                        .defineSignals(c -> {
                            var zk = new ZkContext(c);
                            var local = ZkJubjubPoint.witnessAffine(
                                    zk, ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v"));
                            local.add(zk, foreignPoint.get());
                        }));
    }

    /** The BLS12-381 field guard must survive the rework. */
    @Test
    void nonBls12381Field_rejectedAtCompileTime() {
        var circuit = affineBinderCircuit();
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private static CircuitBuilder affineBinderCircuit() {
        return CircuitBuilder.create("affine-binder")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> ZkJubjubPoint.witnessAffine(
                        new ZkContext(c), ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v")));
    }

    /**
     * Binds four raw coordinate wires as a projective point and asserts the invariants. Uses
     * the package-private {@code wrap} indirectly by going through the gadget-facing path:
     * the coordinates are fed in as public inputs so a test can drive arbitrary values.
     */
    private static CircuitBuilder projectiveCircuit() {
        return projectiveCircuitWithAssertions(1);
    }

    private static CircuitBuilder projectiveCircuitWithAssertions(int times) {
        return CircuitBuilder.create("projective-" + times)
                .publicVar("u").publicVar("v").publicVar("z").publicVar("t")
                .defineSignals(c -> wrapProjective(c, times));
    }

    /** Binds four raw coordinate wires as a projective point and asserts {@code times} times. */
    private static void wrapProjective(
            com.bloxbean.cardano.zeroj.circuit.SignalBuilder c, int times) {
        var point = new com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitJubjub.Point(
                c.publicInput("u").variable(),
                c.publicInput("v").variable(),
                c.publicInput("z").variable(),
                c.publicInput("t").variable());
        var zkPoint = ZkJubjubPoint.wrap(new ZkContext(c), point);
        for (int i = 0; i < times; i++) {
            zkPoint.assertWellFormed();
        }
        c.api().requireField(com.bloxbean.cardano.zeroj.circuit.lib.poseidon
                .PoseidonParamsBLS12_381T3.INSTANCE.field());
    }

    private static CircuitBuilder rawProjectiveComparisonCircuit(String operation) {
        return CircuitBuilder.create("raw-projective-" + operation)
                .publicVar("u").publicVar("v").publicVar("z").publicVar("t")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var raw = new com.bloxbean.cardano.zeroj.circuit.lib.jubjub
                            .InCircuitJubjub.Point(
                            c.publicInput("u").variable(),
                            c.publicInput("v").variable(),
                            c.publicInput("z").variable(),
                            c.publicInput("t").variable());
                    var point = ZkJubjubPoint.wrap(zk, raw);
                    var identity = ZkJubjubPoint.constant(zk, JubjubPoint.IDENTITY);
                    switch (operation) {
                        case "assertEqual" -> point.assertEqual(zk, identity);
                        case "isEqual" -> point.isEqual(zk, identity);
                        case "isIdentity" -> point.isIdentity(zk);
                        case "assertNotIdentity" -> point.assertNotIdentity(zk);
                        case "assertAffine" -> point.assertAffineEquals(
                                zk, ZkField.wrap(zk, c.constant(BigInteger.ZERO)),
                                ZkField.wrap(zk, c.constant(BigInteger.ONE)));
                        default -> throw new IllegalArgumentException(operation);
                    }
                });
    }
}
