package org.zeroj.circuit.r1cs;

import org.junit.jupiter.api.Test;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.ConstraintGraph;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.Gate;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.WitnessCalculator;
import org.zeroj.circuit.halo2.Halo2Compiler;
import org.zeroj.circuit.halo2.Halo2CircuitSystem;
import org.zeroj.circuit.plonk.PlonKCompiler;
import org.zeroj.circuit.plonk.PlonKConstraintSystem;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** ADR-0063: direct Boolean equations, including malicious witnesses bypassing evaluation. */
class BooleanAssertionTest {
    private static final List<FieldConfig> FIELDS = List.of(
            FieldConfig.BLS12_381, FieldConfig.BN254, FieldConfig.PALLAS);

    @Test
    void publicAndSecretBitsUseOneRowAndRejectNonbinaryWitnessesInEveryBackend() {
        for (FieldConfig field : FIELDS) {
            for (boolean publicInput : new boolean[]{false, true}) {
                var builder = CircuitBuilder.create("boolean");
                if (publicInput) builder.publicVar("bit"); else builder.secretVar("bit");
                var graph = builder.define(api -> {
                    api.assertBoolean(api.var("bit"));
                    api.assertBoolean(api.var("bit")); // Idempotency must retain exactly one assertion.
                }).constraintGraph();
                assertEquals(2, graph.numWires(), "no intermediate output allocated");
                assertEquals(1, graph.gates().stream().filter(Gate.AssertBoolean.class::isInstance).count());
                assertEquals(1, R1CSCompiler.compile(graph, field).numConstraints());
                checkValues(graph, field, "bit");
            }
        }
    }

    @Test
    void publicRawGraphGateIsConstrainedWithoutDslExpansion() {
        Variable one = new Variable(0, "one");
        Variable bit = new Variable(1, "bit");
        var graph = new ConstraintGraph("raw-boolean", List.of(new Gate.AssertBoolean(bit)),
                one, List.of(), List.of(bit), List.of(), 2);
        for (FieldConfig field : FIELDS) checkValues(graph, field, "bit");
    }

    @Test
    void constantAssertionsFoldOnlyWhenTrue() {
        for (FieldConfig field : FIELDS) {
            for (BigInteger value : List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                    field.prime().subtract(BigInteger.ONE))) {
                var graph = CircuitBuilder.create("constant-boolean")
                        .define(api -> api.assertBoolean(api.constant(value))).constraintGraph();
                boolean valid = value.equals(BigInteger.ZERO) || value.equals(BigInteger.ONE);
                if (valid) {
                    var witness = WitnessCalculator.calculate(graph, Map.of(), field);
                    assertEquals(0, R1CSCompiler.compile(graph, field).numConstraints());
                    assertRelations(graph, field, witness, true);
                } else {
                    assertThrows(ArithmeticException.class,
                            () -> WitnessCalculator.calculate(graph, Map.of(), field));
                    assertThrows(ArithmeticException.class,
                            () -> WitnessCalculator.calculateFlat(graph, Map.of(), field));
                    // Construct the constant assignment directly, bypassing witness assertions.
                    var witness = new BigInteger[graph.numWires()];
                    witness[graph.oneWire().id()] = BigInteger.ONE;
                    for (Gate gate : graph.gates()) {
                        if (gate instanceof Gate.Const c) witness[c.output().id()] = c.value().mod(field.prime());
                    }
                    assertRelations(graph, field, witness, false);
                }
            }
        }
    }

    @Test
    void booleanExpressionRemainsBoundAcrossInliningPolicies() {
        var graph = CircuitBuilder.create("boolean-expression").secretVar("x").secretVar("y")
                .define(api -> {
                    var sum = api.add(api.var("x"), api.var("y"));
                    api.assertBoolean(sum);
                    // A later consumer tests that assertion consumption retains live expressions.
                    api.assertEqual(api.mul(sum, sum), sum);
                }).constraintGraph();
        for (FieldConfig field : FIELDS) {
            var witness = WitnessCalculator.calculate(graph,
                    Map.of("x", List.of(BigInteger.ONE), "y", List.of(BigInteger.ZERO)), field);
            assertRelations(graph, field, witness, true);
            for (LinearInliningPolicy policy : List.of(LinearInliningPolicy.inlineAll(graph),
                    LinearInliningPolicy.materialiseAll(graph, field.prime()),
                    LinearInliningPolicy.select(graph, field.prime()))) {
                var system = R1CSCompiler.compile(graph, field, policy);
                assertTrue(satisfied(system, witness));
                var bad = witness.clone();
                bad[graph.secretInputs().get(0).id()] = BigInteger.TWO;
                assertFalse(satisfied(system, bad));
            }
            var bad = witness.clone();
            bad[graph.secretInputs().get(0).id()] = BigInteger.TWO;
            assertRelations(graph, field, bad, false);
        }
    }

    @Test
    void assertionAtEndOfPressuredExpressionChainPreservesItsInputBinding() {
        var builder = CircuitBuilder.create("pressure-boolean");
        var inputs = new HashMap<String, List<BigInteger>>();
        for (int i = 0; i < 300; i++) {
            builder.secretVar("x" + i);
            inputs.put("x" + i, List.of(i == 0 ? BigInteger.ONE : BigInteger.ZERO));
        }
        var graph = builder.define(api -> {
            Variable sum = api.constant(0);
            for (int i = 0; i < 300; i++) sum = api.add(sum, api.var("x" + i));
            for (int i = 0; i < 5_000; i++) sum = api.add(sum, api.constant(0));
            api.assertBoolean(sum);
        }).constraintGraph();
        var result = R1CSCompiler.compileWithDiagnostics(graph, FieldConfig.BLS12_381);
        assertTrue(result.diagnostics().pressureModeEntered());
        assertTrue(result.diagnostics().totalCsrTerms() <= R1CSCompiler.resourceLimits(graph).csrHardTerms());
        var witness = WitnessCalculator.calculate(graph, inputs, FieldConfig.BLS12_381);
        assertTrue(satisfied(result.system(), witness));
        witness[graph.secretInputs().getFirst().id()] = BigInteger.TWO;
        assertFalse(satisfied(result.system(), witness));
    }

    private static void checkValues(ConstraintGraph graph, FieldConfig field, String inputName) {
        for (BigInteger value : List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                BigInteger.valueOf(255), field.prime().subtract(BigInteger.ONE),
                field.prime().subtract(BigInteger.TWO))) {
            boolean valid = value.equals(BigInteger.ZERO) || value.equals(BigInteger.ONE);
            var inputs = Map.of(inputName, List.of(value));
            // Start from a valid complete witness, then overwrite the declared wire ourselves.
            var witness = WitnessCalculator.calculate(graph,
                    Map.of(inputName, List.of(BigInteger.ZERO)), field);
            witness[graph.namedVariables().get(inputName).id()] = value;
            assertRelations(graph, field, witness, valid);
            if (valid) {
                assertArrayEquals(witness, WitnessCalculator.calculate(graph, inputs, field));
                assertDoesNotThrow(() -> WitnessCalculator.calculateFlat(graph, inputs, field));
                assertDoesNotThrow(() -> WitnessCalculator.calculateFlatChunked(graph, inputs, field));
            } else {
                assertThrows(ArithmeticException.class, () -> WitnessCalculator.calculate(graph, inputs, field));
                assertThrows(ArithmeticException.class, () -> WitnessCalculator.calculateFlat(graph, inputs, field));
                assertThrows(ArithmeticException.class, () -> WitnessCalculator.calculateFlatChunked(graph, inputs, field));
            }
        }
    }

    private static void assertRelations(ConstraintGraph graph, FieldConfig field, BigInteger[] witness, boolean expected) {
        assertEquals(expected, satisfied(R1CSCompiler.compile(graph, field), witness), "R1CS");
        assertEquals(expected, satisfied(PlonKCompiler.compile(graph, field), witness), "PlonK");
        assertEquals(expected, satisfied(Halo2Compiler.compile(graph, field), witness), "Halo2");
    }

    private static boolean satisfied(R1CSConstraintSystem system, BigInteger[] witness) {
        BigInteger p = system.prime();
        for (var row : system.constraints()) {
            if (!dot(row.a(), witness, p).multiply(dot(row.b(), witness, p))
                    .subtract(dot(row.c(), witness, p)).mod(p).equals(BigInteger.ZERO)) return false;
        }
        return true;
    }

    private static BigInteger dot(Map<Integer, BigInteger> terms, BigInteger[] witness, BigInteger p) {
        BigInteger value = BigInteger.ZERO;
        for (var term : terms.entrySet()) value = value.add(term.getValue().multiply(witness[term.getKey()]));
        return value.mod(p);
    }

    private static boolean satisfied(PlonKConstraintSystem system, BigInteger[] witness) {
        var extended = system.extendWitness(witness);
        for (int i = system.numPublicInputs(); i < system.numGates(); i++) {
            var row = system.gateRows().get(i);
            if (!arithmeticRow(row.qL(), row.qR(), row.qO(), row.qM(), row.qC(),
                    extended[row.wireA()], extended[row.wireB()], extended[row.wireC()], system.fieldConfig().prime()))
                return false;
        }
        return true;
    }

    private static boolean satisfied(Halo2CircuitSystem system, BigInteger[] witness) {
        var extended = system.extendWitness(witness);
        var selectors = system.selectorColumns();
        var advice = system.adviceColumns();
        for (int i = 0; i < system.numRows(); i++) {
            if (!arithmeticRow(selectors.get(0).values()[i], selectors.get(1).values()[i],
                    selectors.get(2).values()[i], selectors.get(3).values()[i], selectors.get(4).values()[i],
                    extended[advice.get(0).wireIndices()[i]], extended[advice.get(1).wireIndices()[i]],
                    extended[advice.get(2).wireIndices()[i]], system.fieldConfig().prime())) return false;
        }
        return true;
    }

    private static boolean arithmeticRow(BigInteger ql, BigInteger qr, BigInteger qo,
                                         BigInteger qm, BigInteger qc, BigInteger a,
                                         BigInteger b, BigInteger c, BigInteger p) {
        return ql.multiply(a).add(qr.multiply(b)).add(qo.multiply(c))
                .add(qm.multiply(a).multiply(b)).add(qc).mod(p).equals(BigInteger.ZERO);
    }
}
