package com.bloxbean.cardano.zeroj.circuit;

import com.bloxbean.cardano.zeroj.api.CurveId;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0038 P1: a {@link BitDecomposition} is evidence about the circuit that emitted its
 * constraints, and nothing else.
 *
 * <p>Every test here asserts <b>definition-time</b> rejection. That distinction is the point:
 * a foreign decomposition whose wire ids happen to collide with local wires produces a
 * perfectly satisfiable witness — the circuit is simply missing the constraints it believes
 * it has. Waiting for witness calculation to fail would be waiting for something that never
 * happens.
 */
class BitDecompositionOwnershipTest {

    /** 2^252 < l < 2^253; the forgery witness from ADR-0037 Context item 11. */
    private static final BigInteger BLS12_381_R = new BigInteger(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513");

    /**
     * Mints a decomposition inside a throwaway circuit and hands it back out. This is the
     * whole attack: nothing stops a decomposition from outliving its circuit.
     */
    private static BitDecomposition mintForeign(String varName, int width) {
        var captured = new AtomicReference<BitDecomposition>();
        CircuitBuilder.create("foreign")
                .publicVar("out").secretVar(varName)
                .define(api -> {
                    captured.set(api.decompose(api.var(varName), width));
                    api.assertEqual(api.var("out"), api.var("out"));
                });
        return captured.get();
    }

    // ------------------------------------------------------------------
    //  lessThan(BitDecomposition, BitDecomposition) — all operand positions
    // ------------------------------------------------------------------

    @Test
    void lessThan_foreignLeftOperand_rejectedAtDefinitionTime() {
        BitDecomposition foreign = mintForeign("x", 64);

        var ex = assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("a")
                        .define(api -> {
                            var local = api.decompose(api.var("a"), 64);
                            api.assertEqual(api.lessThan(foreign, local), api.constant(1));
                        }));

        assertTrue(ex.getMessage().contains("different circuit"),
                "rejection must name the provenance failure, got: " + ex.getMessage());
    }

    @Test
    void lessThan_foreignRightOperand_rejectedAtDefinitionTime() {
        BitDecomposition foreign = mintForeign("x", 64);

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("a")
                        .define(api -> {
                            var local = api.decompose(api.var("a"), 64);
                            api.assertEqual(api.lessThan(local, foreign), api.constant(1));
                        }));
    }

    @Test
    void lessThan_bothOperandsForeign_rejectedAtDefinitionTime() {
        BitDecomposition left = mintForeign("x", 64);
        BitDecomposition right = mintForeign("x", 64);

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("a")
                        .define(api -> api.assertEqual(api.lessThan(left, right), api.constant(1))));
    }

    @Test
    void lessThan_twoForeignOperandsFromTheSameOtherCircuit_rejected() {
        var first = new AtomicReference<BitDecomposition>();
        var second = new AtomicReference<BitDecomposition>();
        CircuitBuilder.create("foreign")
                .publicVar("out").secretVar("x").secretVar("y")
                .define(api -> {
                    first.set(api.decompose(api.var("x"), 64));
                    second.set(api.decompose(api.var("y"), 64));
                });

        // Mutually consistent evidence — but consistent about the WRONG circuit.
        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("a")
                        .define(api -> api.assertEqual(
                                api.lessThan(first.get(), second.get()), api.constant(1))));
    }

    @Test
    void lessThan_evidenceReusedAcrossTwoDefineCallsOnSameBuilder_rejected() {
        var captured = new AtomicReference<BitDecomposition>();
        var builder = CircuitBuilder.create("same-builder")
                .publicVar("out").secretVar("a");

        builder.define(api -> captured.set(api.decompose(api.var("a"), 64)));

        // define() mints a fresh CircuitAPIImpl, so the second circuit is a different
        // constraint system even though the builder object is the same one.
        assertThrows(IllegalArgumentException.class, () ->
                builder.define(api -> {
                    var local = api.decompose(api.var("a"), 64);
                    api.assertEqual(api.lessThan(captured.get(), local), api.constant(1));
                }));
    }

    @Test
    void lessThan_ownDecompositions_stillWork() {
        var circuit = CircuitBuilder.create("honest")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> {
                    var da = api.decompose(api.var("a"), 16);
                    var db = api.decompose(api.var("b"), 16);
                    api.assertEqual(api.lessThan(da, db), api.var("out"));
                });

        var witness = circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.valueOf(7)),
                "b", List.of(BigInteger.valueOf(9))), CurveId.BN254);
        assertEquals(BigInteger.ONE, witness[1], "7 < 9");
    }

    // ------------------------------------------------------------------
    //  The reported forgery: p-1 < 1,000,000 under a nominal 64-bit compare
    // ------------------------------------------------------------------

    /**
     * The concrete exploit ADR-0038 finding 2 describes. Without the ownership check the
     * victim circuit compares a 253-bit value under a nominal 64-bit width, emitting no range
     * constraint on it, and {@code p − 1 < 1,000,000} is accepted. The decomposition is minted
     * against a *different* circuit's wire that genuinely is 64-bit-bounded.
     */
    @Test
    void reportedForgery_pMinusOneLessThanMillion_rejectedAtDefinitionTime() {
        BitDecomposition foreignBounded = mintForeign("small", 64);

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("forgery")
                        .publicVar("verdict").secretVar("huge")
                        .define(api -> {
                            var million = api.decompose(api.constant(1_000_000), 64);
                            // Claim: huge < 1,000,000, "proved" with someone else's evidence.
                            api.assertEqual(api.lessThan(foreignBounded, million), api.constant(1));
                        }),
                "the p-1 < 10^6 forgery must be rejected when it is built on foreign evidence");
    }

    // ------------------------------------------------------------------
    //  Wire-id collision: ids alone do not authenticate evidence provenance
    // ------------------------------------------------------------------

    /**
     * The configuration that makes ownership checking load-bearing rather than cosmetic: two
     * circuits built with identical shapes allocate identical wire ids, so the foreign
     * evidence names wires that genuinely exist here and looks locally plausible. Nothing but
     * provenance distinguishes it — the constraints it attests to were emitted in the other
     * circuit.
     */
    @Test
    void foreignDecompositionWithCollidingWireIds_rejected() {
        var captured = new AtomicReference<BitDecomposition>();
        CircuitBuilder.create("twin-a")
                .publicVar("out").secretVar("a")
                .define(api -> captured.set(api.decompose(api.var("a"), 32)));

        BitDecomposition foreign = captured.get();

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("twin-b")
                        .publicVar("out").secretVar("a")
                        .define(api -> {
                            // Identical prefix => identical ids. That still does not mean the
                            // decomposition's binding equation was emitted in this circuit.
                            var local = api.decompose(api.var("a"), 32);
                            assertEquals(foreign.source().id(), local.source().id(),
                                    "test premise: wire ids must collide across circuits");
                            for (int i = 0; i < foreign.width(); i++) {
                                assertEquals(foreign.bit(i).id(), local.bit(i).id(),
                                        "test premise: bit wire ids must collide too");
                            }
                            api.assertEqual(api.lessThan(foreign, local), api.constant(1));
                        }),
                "colliding ids must not let a foreign decomposition through");
    }

    /**
     * The typed overload intentionally reuses binding/range constraints already emitted by
     * {@code decompose}; it must not emit them a second time. This is why provenance is
     * security evidence rather than a cosmetic owner label.
     *
     * <p>Demonstrated directly: the {@code Variable} overload and local
     * decompose-then-typed form cost the same, while adding the typed comparison after two
     * decompositions costs only the comparison rows. If the evidence came from another
     * circuit, the local binding/range prefix would be absent.
     */
    @Test
    void typedOverloadReusesTheLocalBindingConstraintsItAuthenticates() {
        var viaVariable = CircuitBuilder.create("via-variable")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(
                        api.lessThan(api.var("a"), api.var("b"), 32), api.var("out")))
                .compileR1CS(CurveId.BN254);

        var viaTyped = CircuitBuilder.create("via-typed")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> {
                    // Decompose at 32 bits, then compare — the comparison itself adds no
                    // range constraints because the decompositions already prove the bound.
                    var da = api.decompose(api.var("a"), 32);
                    var db = api.decompose(api.var("b"), 32);
                    api.assertEqual(api.lessThan(da, db), api.var("out"));
                })
                .compileR1CS(CurveId.BN254);

        var decompositionOnly = CircuitBuilder.create("decomposition-only")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> {
                    api.decompose(api.var("a"), 32);
                    api.decompose(api.var("b"), 32);
                })
                .compileR1CS(CurveId.BN254);

        assertEquals(viaVariable.constraints().size(), viaTyped.constraints().size(),
                "the typed overload should cost the same when the evidence is genuinely local");
        assertTrue(viaTyped.constraints().size() > decompositionOnly.constraints().size(),
                "the typed comparison itself must still emit its comparison/equality rows");
        assertTrue(decompositionOnly.constraints().size() > 0,
                "the local evidence prefix must contain load-bearing binding/range rows");
    }

    /** A fabricated {@link Variable} naming a wire this circuit never allocated is rejected. */
    @Test
    void decompose_rejectsVariableThatIsNotAWireOfThisCircuit() {
        var ex = assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("ghost-wire")
                        .publicVar("out").secretVar("a")
                        .define(api -> api.decompose(new Variable(9999, "ghost"), 32)));
        assertTrue(ex.getMessage().contains("not a wire of this circuit"),
                "got: " + ex.getMessage());
    }

    /**
     * Exact allocation frontier: {@code id == nextId} is not allocated yet and is also the id
     * that {@code bits[0]} would receive. Accepting it aliases the decomposition source with its
     * first output bit.
     */
    @Test
    void decompose_rejectsVariableAtTheNextAllocationId() {
        var ex = assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("next-wire-boundary")
                        .secretVar("a")
                        .define(api -> {
                            Variable a = api.var("a");
                            api.decompose(new Variable(a.id() + 1, "next"), 1);
                        }));
        assertTrue(ex.getMessage().contains("not a wire of this circuit"),
                "got: " + ex.getMessage());
    }

    // ------------------------------------------------------------------
    //  A CircuitAPI that has not opted into provenance must fail closed
    // ------------------------------------------------------------------

    /**
     * ADR-0038 Decision 1: {@code requireOwned}'s default implementation throws, exactly as
     * {@code requirePublicOrConstant}'s does. An alternate {@code CircuitAPI} that cannot
     * authenticate provenance must refuse typed evidence rather than accept evidence minted by
     * a different implementation entirely.
     */
    @Test
    void alternateCircuitApi_defaultRequireOwned_throwsUnsupported() {
        BitDecomposition foreign = mintForeign("x", 64);
        CircuitAPI nonOwning = new NonOwningCircuitAPI();

        var ex = assertThrows(UnsupportedOperationException.class,
                () -> nonOwning.requireOwned(foreign));
        assertTrue(ex.getMessage().contains("requireOwned"),
                "message should name the unsupported seam, got: " + ex.getMessage());
    }

    /** The token must never leak through diagnostics. */
    @Test
    void ownerTokenIsNotDisclosed() {
        BitDecomposition foreign = mintForeign("x", 64);
        assertFalse(foreign.toString().toLowerCase().contains("owner"),
                "toString must not mention the owner token: " + foreign);
        assertFalse(foreign.toString().contains("java.lang.Object@"),
                "toString must not leak the token identity: " + foreign);

        var ex = assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("a")
                        .define(api -> {
                            var local = api.decompose(api.var("a"), 64);
                            api.lessThan(foreign, local);
                        }));
        assertFalse(ex.getMessage().contains("java.lang.Object@"),
                "rejection message must not leak the token identity: " + ex.getMessage());
    }

    /**
     * A minimal {@link CircuitAPI} that implements only what these tests touch. Everything
     * else throws, so an accidental fallback shows up as a failure rather than a pass. It
     * deliberately does NOT override {@code requireOwned}: the default must fail closed.
     */
    private static final class NonOwningCircuitAPI implements CircuitAPI {
        private final List<Variable> vars = new ArrayList<>();

        @Override public Variable add(Variable a, Variable b) { return next(); }
        @Override public Variable mul(Variable a, Variable b) { return next(); }
        @Override public void assertEqual(Variable a, Variable b) { }
        @Override public Variable select(Variable c, Variable t, Variable f) { return next(); }
        @Override public Variable sub(Variable a, Variable b) { return next(); }
        @Override public Variable neg(Variable a) { return next(); }
        @Override public Variable inv(Variable a) { return next(); }
        @Override public Variable div(Variable a, Variable b) { return next(); }
        @Override public Variable constant(long v) { return next(); }
        @Override public Variable constant(BigInteger v) { return next(); }
        @Override public Variable[] toBinary(Variable a, int n) { throw new UnsupportedOperationException(); }
        @Override public BitDecomposition decompose(Variable a, int n) { throw new UnsupportedOperationException(); }
        @Override public Variable fromBinary(Variable[] bits) { return next(); }
        @Override public Variable xor(Variable a, Variable b) { return next(); }
        @Override public Variable and(Variable a, Variable b) { return next(); }
        @Override public Variable or(Variable a, Variable b) { return next(); }
        @Override public Variable not(Variable a) { return next(); }
        @Override public void assertBoolean(Variable a) { }
        @Override public void assertInRange(Variable a, int n) { }
        @Override public void assertNotEqual(Variable a, Variable b) { }
        @Override public Variable isZero(Variable a) { return next(); }
        @Override public Variable isEqual(Variable a, Variable b) { return next(); }
        @Override public Variable lessThan(Variable a, Variable b, int n) { return next(); }

        @Override
        public Variable lessThan(BitDecomposition a, BitDecomposition b) {
            // Mirrors CircuitAPIImpl: authenticate before anything else. Here the default
            // requireOwned throws, which is the fail-closed behaviour under test.
            requireOwned(a);
            requireOwned(b);
            return next();
        }

        @Override public Variable arrayAccess(Variable[] arr, Variable i) { return next(); }
        @Override public Variable var(String name) { return next(); }

        private Variable next() {
            var v = new Variable(vars.size(), "v" + vars.size());
            vars.add(v);
            return v;
        }
    }
}
