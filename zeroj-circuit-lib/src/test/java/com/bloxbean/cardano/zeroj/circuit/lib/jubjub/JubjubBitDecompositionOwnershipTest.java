package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.BitDecomposition;
import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0038 P1, gadget half.
 *
 * <p>The ownership fixtures for {@code lessThan} live in {@code zeroj-circuit-dsl}, which
 * cannot see this module — so without this file the {@code requireOwned} guards on
 * {@link InCircuitJubjub#scalarMulFixedBase(CircuitAPI, JubjubPoint, BitDecomposition)} and
 * {@link InCircuitJubjub#scalarMulVariableBase(CircuitAPI, InCircuitJubjub.Point,
 * BitDecomposition)} could both be deleted with the whole suite still green.
 *
 * <p>What breaks without them is specific: the gadget re-asserts that each bit is boolean, but
 * the constraint binding those bits to the scalar they decompose — {@code Σ bits[i]·2^i ==
 * source} — was emitted in the circuit that minted them. Consuming a foreign decomposition
 * therefore multiplies by bits nothing here ties to any particular value, so the prover picks
 * the effective scalar freely. Inside {@code InCircuitEdDSAJubjub.verifyCore} that is
 * signature forgery.
 */
class JubjubBitDecompositionOwnershipTest {

    /** Mints a decomposition in a throwaway circuit and lets it escape. */
    private static BitDecomposition mintForeign(int width) {
        var captured = new AtomicReference<BitDecomposition>();
        CircuitBuilder.create("foreign")
                .publicVar("out").secretVar("k")
                .define(api -> captured.set(api.decompose(api.var("k"), width)));
        return captured.get();
    }

    // ------------------------------------------------------------------
    //  scalarMulFixedBase(api, base, BitDecomposition)
    // ------------------------------------------------------------------

    @Test
    void scalarMulFixedBase_foreignDecomposition_rejectedAtDefinitionTime() {
        BitDecomposition foreign = mintForeign(252);

        var ex = assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("k")
                        .define(api -> InCircuitJubjub.scalarMulFixedBase(
                                api, JubjubPoint.SUBGROUP_GENERATOR, foreign)));

        assertTrue(ex.getMessage().contains("different circuit"),
                "rejection must name the provenance failure, got: " + ex.getMessage());
    }

    /** Same wire ids on both sides — the case where the foreign evidence looks local. */
    @Test
    void scalarMulFixedBase_foreignDecompositionWithCollidingIds_rejected() {
        var captured = new AtomicReference<BitDecomposition>();
        CircuitBuilder.create("twin-a")
                .publicVar("out").secretVar("k")
                .define(api -> captured.set(api.decompose(api.var("k"), 252)));
        BitDecomposition foreign = captured.get();

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("twin-b")
                        .publicVar("out").secretVar("k")
                        .define(api -> {
                            var local = api.decompose(api.var("k"), 252);
                            assertEquals(foreign.source().id(), local.source().id(),
                                    "test premise: wire ids must collide across circuits");
                            InCircuitJubjub.scalarMulFixedBase(
                                    api, JubjubPoint.SUBGROUP_GENERATOR, foreign);
                        }));
    }

    @Test
    void scalarMulFixedBase_ownDecomposition_works() {
        var circuit = CircuitBuilder.create("honest")
                .publicVar("outU").secretVar("k")
                .define(api -> {
                    var bits = api.decompose(api.var("k"), 8);
                    var point = InCircuitJubjub.scalarMulFixedBase(
                            api, JubjubPoint.SUBGROUP_GENERATOR, bits);
                    api.assertEqual(api.mul(api.var("outU"), point.z()), point.u());
                });

        JubjubPoint expected = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(5));
        assertDoesNotThrow(() -> circuit.calculateWitness(java.util.Map.of(
                "outU", List.of(expected.affineU()),
                "k", List.of(BigInteger.valueOf(5))), CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  scalarMulVariableBase(api, base, BitDecomposition)
    // ------------------------------------------------------------------

    @Test
    void scalarMulVariableBase_foreignDecomposition_rejectedAtDefinitionTime() {
        BitDecomposition foreign = mintForeign(252);

        var ex = assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("k").secretVar("pu").secretVar("pv")
                        .define(api -> {
                            var base = InCircuitJubjub.witnessAffine(
                                    api, api.var("pu"), api.var("pv"));
                            InCircuitJubjub.scalarMulVariableBase(api, base, foreign);
                        }));

        assertTrue(ex.getMessage().contains("different circuit"),
                "rejection must name the provenance failure, got: " + ex.getMessage());
    }

    @Test
    void scalarMulVariableBase_ownDecomposition_works() {
        assertDoesNotThrow(() -> CircuitBuilder.create("honest-var-base")
                .publicVar("out").secretVar("k").secretVar("pu").secretVar("pv")
                .define(api -> {
                    var base = InCircuitJubjub.witnessAffine(api, api.var("pu"), api.var("pv"));
                    var bits = api.decompose(api.var("k"), 8);
                    InCircuitJubjub.scalarMulVariableBase(api, base, bits);
                })
                .compileR1CS(CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  InCircuitPedersen.commit(api, BitDecomposition, BitDecomposition) — 4th consumer
    // ------------------------------------------------------------------

    @Test
    void pedersenCommit_foreignValue_rejectedAtDefinitionTime() {
        BitDecomposition foreign = mintForeign(64);

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("r")
                        .define(api -> {
                            var blinding = api.decompose(api.var("r"), 64);
                            InCircuitPedersen.commit(api, foreign, blinding);
                        }));
    }

    @Test
    void pedersenCommit_foreignBlinding_rejectedAtDefinitionTime() {
        BitDecomposition foreign = mintForeign(64);

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("v")
                        .define(api -> {
                            var value = api.decompose(api.var("v"), 64);
                            InCircuitPedersen.commit(api, value, foreign);
                        }));
    }

    @Test
    void pedersenCommit_bothForeign_rejectedAtDefinitionTime() {
        BitDecomposition value = mintForeign(64);
        BitDecomposition blinding = mintForeign(64);

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("x")
                        .define(api -> InCircuitPedersen.commit(api, value, blinding)));
    }

    /**
     * A foreign blinding must be rejected <b>before</b> the value leg emits anything —
     * validation is up front, not delegated to the two scalar multiplications in sequence.
     *
     * <p>A proxy records every API call between the first and second ownership checks. This is
     * intentionally an ordering assertion, not a failed-builder constraint-count proxy: a
     * failed {@code define()} exposes no graph, so comparing it with a successful graph cannot
     * reveal whether partial constraints were emitted before the exception.
     */
    @Test
    void pedersenCommit_foreignBlinding_rejectsBeforeValueLegEmits() {
        BitDecomposition foreign = mintForeign(64);
        var ownershipChecks = new AtomicInteger();
        var callBetweenChecks = new AtomicBoolean();

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("victim")
                        .publicVar("out").secretVar("v")
                        .define(api -> {
                            var value = api.decompose(api.var("v"), 64);
                            CircuitAPI observed = observingOwnershipOrder(
                                    api, ownershipChecks, callBetweenChecks);
                            InCircuitPedersen.commit(observed, value, foreign);
                        }));

        assertEquals(2, ownershipChecks.get(),
                "both operands must be validated at the typed boundary");
        assertFalse(callBetweenChecks.get(),
                "no API operation may occur between value and blinding ownership validation");
    }

    private static CircuitAPI observingOwnershipOrder(
            CircuitAPI delegate, AtomicInteger ownershipChecks, AtomicBoolean callBetweenChecks) {
        return (CircuitAPI) Proxy.newProxyInstance(
                CircuitAPI.class.getClassLoader(),
                new Class<?>[]{CircuitAPI.class},
                (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return method.invoke(delegate, args);
                    }
                    if (method.getName().equals("requireOwned")) {
                        ownershipChecks.incrementAndGet();
                    } else if (ownershipChecks.get() == 1) {
                        callBetweenChecks.set(true);
                    }
                    try {
                        return method.invoke(delegate, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    @Test
    void pedersenCommit_ownDecompositions_matchesOffCircuitCommitment() {
        BigInteger value = BigInteger.valueOf(42);
        BigInteger blinding = BigInteger.valueOf(12345);
        JubjubPoint expected = PedersenCommitment.commit(value, blinding);

        var circuit = CircuitBuilder.create("pedersen-typed")
                .publicVar("outU").publicVar("outV").secretVar("v").secretVar("r")
                .define(api -> {
                    var vBits = api.decompose(api.var("v"), 64);
                    var rBits = api.decompose(api.var("r"), 64);
                    var c = InCircuitPedersen.commit(api, vBits, rBits);
                    api.assertEqual(api.mul(api.var("outU"), c.z()), c.u());
                    api.assertEqual(api.mul(api.var("outV"), c.z()), c.v());
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(java.util.Map.of(
                "outU", List.of(expected.affineU()),
                "outV", List.of(expected.affineV()),
                "v", List.of(value),
                "r", List.of(blinding)), CurveId.BLS12_381));
    }

    /** Per-scalar widths: a small value must not pay for the blinding's width. */
    @Test
    void pedersenCommit_asymmetricWidths_cheaperThanSharedMaximum() {
        var asymmetric = CircuitBuilder.create("asymmetric")
                .publicVar("out").secretVar("v").secretVar("r")
                .define(api -> InCircuitPedersen.commit(
                        api, api.decompose(api.var("v"), 16), api.decompose(api.var("r"), 252)))
                .compileR1CS(CurveId.BLS12_381);

        var shared = CircuitBuilder.create("shared")
                .publicVar("out").secretVar("v").secretVar("r")
                .define(api -> InCircuitPedersen.commit(
                        api, api.decompose(api.var("v"), 252), api.decompose(api.var("r"), 252)))
                .compileR1CS(CurveId.BLS12_381);

        assertTrue(asymmetric.constraints().size() < shared.constraints().size(),
                "a 16-bit value must cost less than a 252-bit one: "
                        + asymmetric.constraints().size() + " vs " + shared.constraints().size());
    }

    @Test
    void pedersenCommit_rawArraysRejectEitherOversizedOperandBeforeEmission() {
        Variable[] valid = rawBits(252);
        Variable[] oversized = rawBits(253);
        var apiCalls = new AtomicInteger();
        CircuitAPI observed = observingEveryApiCall(new NonOwningCircuitAPI(), apiCalls);

        assertThrows(IllegalArgumentException.class,
                () -> InCircuitPedersen.commit(observed, oversized, valid));
        assertEquals(0, apiCalls.get(), "invalid value width must fail before API use");

        assertThrows(IllegalArgumentException.class,
                () -> InCircuitPedersen.commit(observed, valid, oversized));
        assertEquals(0, apiCalls.get(),
                "invalid blinding width must fail before the valid value leg emits");
    }

    @Test
    void pedersenCommit_rawArraysRejectNullElementBeforeEmission() {
        Variable[] valid = rawBits(8);
        Variable[] malformedBlinding = rawBits(8);
        malformedBlinding[7] = null;
        var apiCalls = new AtomicInteger();
        CircuitAPI observed = observingEveryApiCall(new NonOwningCircuitAPI(), apiCalls);

        assertThrows(NullPointerException.class,
                () -> InCircuitPedersen.commit(observed, valid, malformedBlinding));
        assertEquals(0, apiCalls.get(),
                "all elements of both operands must be validated before scalar multiplication");
    }

    private static Variable[] rawBits(int width) {
        Variable[] bits = new Variable[width];
        Arrays.setAll(bits, i -> new Variable(i + 1, "b" + i));
        return bits;
    }

    private static CircuitAPI observingEveryApiCall(CircuitAPI delegate, AtomicInteger calls) {
        return (CircuitAPI) Proxy.newProxyInstance(
                CircuitAPI.class.getClassLoader(),
                new Class<?>[]{CircuitAPI.class},
                (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return method.invoke(delegate, args);
                    }
                    calls.incrementAndGet();
                    try {
                        return method.invoke(delegate, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    // ------------------------------------------------------------------
    //  Fail-closed on a CircuitAPI that does not track provenance
    // ------------------------------------------------------------------

    /**
     * Exercises the real gadget — not a stub that calls {@code requireOwned} because the test
     * author wrote it that way. {@link InCircuitJubjub#scalarMulFixedBase} must refuse to
     * consume typed evidence on an implementation that cannot authenticate it.
     */
    @Test
    void scalarMulFixedBase_nonOwningCircuitApi_failsClosed() {
        BitDecomposition foreign = mintForeign(8);

        assertThrows(UnsupportedOperationException.class, () ->
                InCircuitJubjub.scalarMulFixedBase(
                        new NonOwningCircuitAPI(), JubjubPoint.SUBGROUP_GENERATOR, foreign));
    }

    @Test
    void pedersenCommit_nonOwningCircuitApi_failsClosed() {
        BitDecomposition foreign = mintForeign(8);

        assertThrows(UnsupportedOperationException.class, () ->
                InCircuitPedersen.commit(new NonOwningCircuitAPI(), foreign, foreign));
    }

    /**
     * Minimal {@link CircuitAPI} that does not override {@code requireOwned}, so the
     * interface default must fail closed. Everything else is a stub; anything a gadget
     * actually needs would show up as a different failure.
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
        @Override public Variable lessThan(BitDecomposition a, BitDecomposition b) { return next(); }
        @Override public Variable arrayAccess(Variable[] arr, Variable i) { return next(); }
        @Override public Variable var(String name) { return next(); }

        private Variable next() {
            var v = new Variable(vars.size(), "v" + vars.size());
            vars.add(v);
            return v;
        }
    }
}
