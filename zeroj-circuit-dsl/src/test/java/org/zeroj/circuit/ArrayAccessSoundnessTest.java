package org.zeroj.circuit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.halo2.Halo2CircuitSystem;
import org.zeroj.circuit.halo2.Halo2Compiler;
import org.zeroj.circuit.plonk.PlonKCompiler;
import org.zeroj.circuit.plonk.PlonKConstraintSystem;
import org.zeroj.circuit.r1cs.R1CSCompiler;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Soundness and regression tests for {@link CircuitAPI#arrayAccess} and
 * {@link CircuitAPI#arrayAccessOrZero} (ADR-0065).
 */
class ArrayAccessSoundnessTest {

    @ParameterizedTest
    @EnumSource(value = CurveId.class, names = {"BLS12_381", "BN254"})
    @DisplayName("in-bounds arrayAccess succeeds and satisfies R1CS, PlonK, and Halo2")
    void inBoundsArrayAccessSucceeds(CurveId curve) {
        var circuit = CircuitBuilder.create("array-access-in-bounds")
                .publicVar("expected")
                .secretVar("index")
                .define(api -> {
                    Variable[] arr = {
                            api.constant(10), api.constant(20), api.constant(30), api.constant(40)
                    };
                    Variable out = api.arrayAccess(arr, api.var("index"));
                    api.assertEqual(out, api.var("expected"));
                });

        var field = FieldConfig.forCurve(curve);
        var r1cs = R1CSCompiler.compile(circuit.constraintGraph(), field);
        var plonk = PlonKCompiler.compile(circuit.constraintGraph(), field);
        var halo2 = Halo2Compiler.compile(circuit.constraintGraph(), field);

        long[] expected = {10, 20, 30, 40};
        for (int idx = 0; idx < expected.length; idx++) {
            var inputs = Map.of(
                    "index", List.of(BigInteger.valueOf(idx)),
                    "expected", List.of(BigInteger.valueOf(expected[idx])));
            BigInteger[] witness = circuit.calculateWitness(inputs, curve);
            assertTrue(r1csSatisfied(r1cs, witness), "R1CS must accept valid index=" + idx);
            assertTrue(plonkSatisfied(plonk, witness), "PlonK must accept valid index=" + idx);
            assertTrue(halo2Satisfied(halo2, witness), "Halo2 must accept valid index=" + idx);
        }
    }

    @ParameterizedTest
    @EnumSource(value = CurveId.class, names = {"BLS12_381", "BN254"})
    @DisplayName("out-of-bounds arrayAccess cannot forge 0 (index = length, length+1, p-1)")
    void outOfBoundsArrayAccessIsRejected(CurveId curve) {
        BigInteger p = FieldConfig.forCurve(curve).prime();
        var circuit = CircuitBuilder.create("array-access-oob-forgery")
                .publicVar("expected")
                .secretVar("index")
                .define(api -> {
                    // Include both non-zero and zero entries to ensure zero elements do not mask OOB.
                    Variable[] arr = {
                            api.constant(0), api.constant(11), api.constant(22), api.constant(33)
                    };
                    Variable out = api.arrayAccess(arr, api.var("index"));
                    api.assertEqual(out, api.var("expected"));
                });

        // Pre-fix: all of these satisfied the circuit with expected = 0.
        BigInteger[] oobIndices = {
                BigInteger.valueOf(4),
                BigInteger.valueOf(5),
                BigInteger.valueOf(64),
                p.subtract(BigInteger.ONE),
                p.subtract(BigInteger.valueOf(12345))
        };
        for (BigInteger badIndex : oobIndices) {
            var inputs = Map.of(
                    "index", List.of(badIndex),
                    "expected", List.of(BigInteger.ZERO));
            assertThrows(ArithmeticException.class,
                    () -> circuit.calculateWitness(inputs, curve),
                    "arrayAccess must reject OOB index=" + badIndex + " on " + curve);
        }
    }

    @ParameterizedTest
    @EnumSource(value = CurveId.class, names = {"BLS12_381", "BN254"})
    @DisplayName("forged OOB witnesses for {n, n+1, p-1} fail R1CS, PlonK, and Halo2 while passing arrayAccessOrZero control")
    void forgedOobWitnessFailsConstraintMatricesDirectly(CurveId curve) {
        var strictCircuit = CircuitBuilder.create("array-access-matrix-check")
                .secretVar("index")
                .define(api -> {
                    Variable[] arr = {api.constant(7), api.constant(9)};
                    Variable out = api.arrayAccess(arr, api.var("index"));
                    api.assertEqual(out, api.constant(0));
                });
        var controlCircuit = CircuitBuilder.create("array-access-or-zero-control")
                .secretVar("index")
                .define(api -> {
                    Variable[] arr = {api.constant(7), api.constant(9)};
                    Variable out = api.arrayAccessOrZero(arr, api.var("index"));
                    api.assertEqual(out, api.constant(0));
                });

        var strictGraph = strictCircuit.constraintGraph();
        var controlGraph = controlCircuit.constraintGraph();
        var field = FieldConfig.forCurve(curve);
        var strictR1cs = R1CSCompiler.compile(strictGraph, field);
        var strictPlonk = PlonKCompiler.compile(strictGraph, field);
        var strictHalo2 = Halo2Compiler.compile(strictGraph, field);
        var controlR1cs = R1CSCompiler.compile(controlGraph, field);
        var controlPlonk = PlonKCompiler.compile(controlGraph, field);
        var controlHalo2 = Halo2Compiler.compile(controlGraph, field);

        BigInteger p = field.prime();
        BigInteger[] oobIndices = {
                BigInteger.valueOf(2),
                BigInteger.valueOf(3),
                p.subtract(BigInteger.ONE)
        };
        for (BigInteger oob : oobIndices) {
            BigInteger[] forgedStrict = computeForgedWitnessIgnoringFinalAssert(strictGraph, oob, p);
            assertFalse(r1csSatisfied(strictR1cs, forgedStrict),
                    "R1CS matrix must reject forged OOB index=" + oob + " on " + curve);
            assertFalse(plonkSatisfied(strictPlonk, forgedStrict),
                    "PlonK constraint system must reject forged OOB index=" + oob + " on " + curve);
            assertFalse(halo2Satisfied(strictHalo2, forgedStrict),
                    "Halo2 constraint system must reject forged OOB index=" + oob + " on " + curve);

            // Positive control: the exact same forged OOB assignment satisfies arrayAccessOrZero
            // on all three backends, proving rejection comes specifically from the ADR-0065 check.
            BigInteger[] forgedControl = computeForgedWitnessIgnoringFinalAssert(controlGraph, oob, p);
            assertTrue(r1csSatisfied(controlR1cs, forgedControl),
                    "R1CS control (arrayAccessOrZero) must accept OOB index=" + oob + " on " + curve);
            assertTrue(plonkSatisfied(controlPlonk, forgedControl),
                    "PlonK control (arrayAccessOrZero) must accept OOB index=" + oob + " on " + curve);
            assertTrue(halo2Satisfied(controlHalo2, forgedControl),
                    "Halo2 control (arrayAccessOrZero) must accept OOB index=" + oob + " on " + curve);
        }
    }

    @ParameterizedTest
    @EnumSource(value = CurveId.class, names = {"BLS12_381", "BN254"})
    @DisplayName("single-element arrayAccess accepts index 0 and rejects index 1 and p-1")
    void singleElementArrayAccess(CurveId curve) {
        BigInteger p = FieldConfig.forCurve(curve).prime();
        var circuit = CircuitBuilder.create("array-access-single")
                .publicVar("expected")
                .secretVar("index")
                .defineSignals(c -> {
                    Signal out = c.arrayAccess(new Signal[]{c.constant(42)}, c.privateInput("index"));
                    c.assertEqual(out, c.publicInput("expected"));
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(
                Map.of("index", List.of(BigInteger.ZERO), "expected", List.of(BigInteger.valueOf(42))),
                curve));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                Map.of("index", List.of(BigInteger.ONE), "expected", List.of(BigInteger.ZERO)),
                curve));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                Map.of("index", List.of(p.subtract(BigInteger.ONE)), "expected", List.of(BigInteger.ZERO)),
                curve));
    }

    @Test
    @DisplayName("arrayAccess rejects empty array, null arguments atomically, and frozen builders")
    void guardRailsRejectEmptyNullAndFrozen() {
        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("empty-api")
                        .secretVar("index")
                        .define(api -> api.arrayAccess(new Variable[0], api.var("index"))));

        assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("empty-signal")
                        .secretVar("index")
                        .defineSignals(c -> c.arrayAccess(new Signal[0], c.privateInput("index"))));

        // Null array, null element, or null index must fail before emitting any gates.
        var escapedApi = new AtomicReference<CircuitAPI>();
        var escapedIndex = new AtomicReference<Variable>();
        var graph = CircuitBuilder.create("null-atomic-check")
                .secretVar("index")
                .define(api -> {
                    Variable idx = api.var("index");
                    assertThrows(NullPointerException.class, () -> api.arrayAccess(null, idx));
                    assertThrows(NullPointerException.class,
                            () -> api.arrayAccess(new Variable[]{api.constant(1), null}, idx));
                    assertThrows(NullPointerException.class,
                            () -> api.arrayAccess(new Variable[]{api.constant(1)}, null));
                    escapedApi.set(api);
                    escapedIndex.set(idx);
                })
                .constraintGraph();
        // Only the constant(1) created while constructing the test array argument may exist; no
        // isEqual/mul/AssertEq gates were emitted by the rejected arrayAccess calls.
        assertTrue(graph.gates().stream().noneMatch(g -> g instanceof Gate.AssertEq || g instanceof Gate.Mul),
                "rejected arrayAccess calls must not emit partial constraints");

        // Post-freeze calls must fail loudly on both arrayAccess and arrayAccessOrZero.
        assertThrows(IllegalStateException.class, () ->
                escapedApi.get().arrayAccess(new Variable[]{escapedIndex.get()}, escapedIndex.get()));
        assertThrows(IllegalStateException.class, () ->
                escapedApi.get().arrayAccessOrZero(new Variable[]{escapedIndex.get()}, escapedIndex.get()));
    }

    @Test
    @DisplayName("published Gate.LinComb term lists reject post-build mutation")
    void linCombTermsAreImmutableAfterGraphConstruction() {
        var graph = CircuitBuilder.create("lincomb-immutable")
                .secretVar("index")
                .secretVar("bit0")
                .secretVar("bit1")
                .define(api -> {
                    api.arrayAccess(new Variable[]{api.constant(10), api.constant(20)}, api.var("index"));
                    api.fromBinary(new Variable[]{api.var("bit0"), api.var("bit1")});
                })
                .constraintGraph();

        List<Gate.LinComb> linCombs = graph.gates().stream()
                .filter(Gate.LinComb.class::isInstance)
                .map(Gate.LinComb.class::cast)
                .toList();
        assertFalse(linCombs.isEmpty(), "expected LinComb gates from arrayAccess and fromBinary");
        for (Gate.LinComb linComb : linCombs) {
            assertThrows(UnsupportedOperationException.class, () -> linComb.terms().clear(),
                    "Gate.LinComb.terms() must be immutable after graph construction");
        }
    }

    @ParameterizedTest
    @EnumSource(value = CurveId.class, names = {"BLS12_381", "BN254"})
    @DisplayName("arrayAccessOrZero preserves opt-in total semantics and per-backend cost deltas")
    void arrayAccessOrZeroTotalSemanticsAndCost(CurveId curve) {
        BigInteger p = FieldConfig.forCurve(curve).prime();
        int n = 3;
        var strictCircuit = CircuitBuilder.create("cost-strict")
                .secretVar("index")
                .defineSignals(c -> c.arrayAccess(
                        new Signal[]{c.constant(5), c.constant(6), c.constant(7)},
                        c.privateInput("index")));
        var totalCircuit = CircuitBuilder.create("cost-total")
                .publicVar("expected")
                .secretVar("index")
                .defineSignals(c -> {
                    Signal out = c.arrayAccessOrZero(
                            new Signal[]{c.constant(5), c.constant(6), c.constant(7)},
                            c.privateInput("index"));
                    c.assertEqual(out, c.publicInput("expected"));
                });
        var totalNoAssert = CircuitBuilder.create("cost-total-raw")
                .secretVar("index")
                .defineSignals(c -> c.arrayAccessOrZero(
                        new Signal[]{c.constant(5), c.constant(6), c.constant(7)},
                        c.privateInput("index")));

        var field = FieldConfig.forCurve(curve);
        assertEquals(totalNoAssert.compileR1CS(curve).numConstraints() + 1,
                strictCircuit.compileR1CS(curve).numConstraints(),
                "strict arrayAccess must cost +1 R1CS constraint when selector sum is inlined");
        assertEquals(PlonKCompiler.compile(totalNoAssert.constraintGraph(), field).numGates() + n,
                PlonKCompiler.compile(strictCircuit.constraintGraph(), field).numGates(),
                "strict arrayAccess must cost +n PlonK gates");
        assertEquals(Halo2Compiler.compile(totalNoAssert.constraintGraph(), field).numRows() + n,
                Halo2Compiler.compile(strictCircuit.constraintGraph(), field).numRows(),
                "strict arrayAccess must cost +n Halo2 rows");

        var r1cs = R1CSCompiler.compile(totalCircuit.constraintGraph(), field);
        var plonk = PlonKCompiler.compile(totalCircuit.constraintGraph(), field);
        var halo2 = Halo2Compiler.compile(totalCircuit.constraintGraph(), field);

        // In-bounds reads return arr[index].
        BigInteger[] inBoundsWitness = totalCircuit.calculateWitness(
                Map.of("index", List.of(BigInteger.ONE), "expected", List.of(BigInteger.valueOf(6))), curve);
        assertTrue(r1csSatisfied(r1cs, inBoundsWitness));
        assertTrue(plonkSatisfied(plonk, inBoundsWitness));
        assertTrue(halo2Satisfied(halo2, inBoundsWitness));

        // Out-of-bounds reads return 0 explicitly.
        for (BigInteger oob : new BigInteger[]{BigInteger.valueOf(3), p.subtract(BigInteger.ONE)}) {
            BigInteger[] oobWitness = totalCircuit.calculateWitness(
                    Map.of("index", List.of(oob), "expected", List.of(BigInteger.ZERO)), curve);
            assertTrue(r1csSatisfied(r1cs, oobWitness));
            assertTrue(plonkSatisfied(plonk, oobWitness));
            assertTrue(halo2Satisfied(halo2, oobWitness));
        }

        // Empty array returns 0 under arrayAccessOrZero.
        var emptyTotal = CircuitBuilder.create("empty-total")
                .publicVar("expected")
                .secretVar("index")
                .defineSignals(c -> c.assertEqual(
                        c.arrayAccessOrZero(new Signal[0], c.privateInput("index")),
                        c.publicInput("expected")));
        assertDoesNotThrow(() -> emptyTotal.calculateWitness(
                Map.of("index", List.of(BigInteger.ZERO), "expected", List.of(BigInteger.ZERO)), curve));
    }

    /**
     * Evaluates all assignment gates in {@code graph} for an OOB {@code index} without throwing on
     * {@link Gate.AssertEq}, producing the exact witness an adversary would submit to a prover.
     */
    private static BigInteger[] computeForgedWitnessIgnoringFinalAssert(
            ConstraintGraph graph, BigInteger indexValue, BigInteger p) {
        BigInteger[] w = new BigInteger[graph.numWires()];
        w[0] = BigInteger.ONE;
        for (Variable secret : graph.secretInputs()) {
            if ("index".equals(secret.name())) {
                w[secret.id()] = indexValue.mod(p);
            }
        }
        for (Gate gate : graph.gates()) {
            switch (gate) {
                case Gate.Const(var out, var value) -> w[out.id()] = value.mod(p);
                case Gate.Add(var out, var a, var b) -> w[out.id()] = w[a.id()].add(w[b.id()]).mod(p);
                case Gate.Mul(var out, var a, var b) -> w[out.id()] = w[a.id()].multiply(w[b.id()]).mod(p);
                case Gate.LinComb(var out, var terms) -> {
                    BigInteger sum = BigInteger.ZERO;
                    for (Gate.Term t : terms) {
                        sum = sum.add(t.coefficient().multiply(w[t.variable().id()]));
                    }
                    w[out.id()] = sum.mod(p);
                }
                case Gate.Hint(var out, var type, var in) -> {
                    if (type == Gate.HintType.IS_ZERO_INVERSE) {
                        BigInteger val = w[in.id()].mod(p);
                        w[out.id()] = val.signum() == 0 ? BigInteger.ZERO : val.modInverse(p);
                    } else if (type == Gate.HintType.IS_ZERO_RESULT) {
                        w[out.id()] = w[in.id()].mod(p).signum() == 0 ? BigInteger.ONE : BigInteger.ZERO;
                    } else {
                        throw new IllegalStateException("Unexpected hint: " + type);
                    }
                }
                case Gate.AssertEq ignored -> {
                    // Intentionally ignored so we can test the compiled R1CS/PlonK/Halo2 matrices directly.
                }
                default -> throw new IllegalStateException("Unexpected gate: " + gate);
            }
        }
        return w;
    }

    private static boolean r1csSatisfied(R1CSConstraintSystem system, BigInteger[] witness) {
        BigInteger p = system.prime();
        for (var row : system.constraints()) {
            BigInteger a = dot(row.a(), witness, p);
            BigInteger b = dot(row.b(), witness, p);
            BigInteger c = dot(row.c(), witness, p);
            if (!a.multiply(b).subtract(c).mod(p).equals(BigInteger.ZERO)) {
                return false;
            }
        }
        return true;
    }

    private static BigInteger dot(Map<Integer, BigInteger> terms, BigInteger[] witness, BigInteger p) {
        BigInteger value = BigInteger.ZERO;
        for (var term : terms.entrySet()) {
            value = value.add(term.getValue().multiply(witness[term.getKey()]));
        }
        return value.mod(p);
    }

    private static boolean plonkSatisfied(PlonKConstraintSystem system, BigInteger[] witness) {
        BigInteger[] extended = system.extendWitness(witness);
        BigInteger p = system.fieldConfig().prime();
        for (int i = system.numPublicInputs(); i < system.numGates(); i++) {
            var row = system.gateRows().get(i);
            BigInteger a = extended[row.wireA()];
            BigInteger b = extended[row.wireB()];
            BigInteger c = extended[row.wireC()];
            BigInteger eval = row.qL().multiply(a)
                    .add(row.qR().multiply(b))
                    .add(row.qO().multiply(c))
                    .add(row.qM().multiply(a).multiply(b))
                    .add(row.qC())
                    .mod(p);
            if (!eval.equals(BigInteger.ZERO)) {
                return false;
            }
        }
        return true;
    }

    private static boolean halo2Satisfied(Halo2CircuitSystem system, BigInteger[] witness) {
        BigInteger[] extended = system.extendWitness(witness);
        BigInteger p = system.fieldConfig().prime();
        var selectors = system.selectorColumns();
        var advice = system.adviceColumns();
        for (int i = 0; i < system.numRows(); i++) {
            BigInteger ql = selectors.get(0).values()[i];
            BigInteger qr = selectors.get(1).values()[i];
            BigInteger qo = selectors.get(2).values()[i];
            BigInteger qm = selectors.get(3).values()[i];
            BigInteger qc = selectors.get(4).values()[i];
            BigInteger a = extended[advice.get(0).wireIndices()[i]];
            BigInteger b = extended[advice.get(1).wireIndices()[i]];
            BigInteger c = extended[advice.get(2).wireIndices()[i]];
            BigInteger eval = ql.multiply(a)
                    .add(qr.multiply(b))
                    .add(qo.multiply(c))
                    .add(qm.multiply(a).multiply(b))
                    .add(qc)
                    .mod(p);
            if (!eval.equals(BigInteger.ZERO)) {
                return false;
            }
        }
        return true;
    }
}
