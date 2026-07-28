package com.bloxbean.cardano.zeroj.circuit.r1cs;

import com.bloxbean.cardano.zeroj.circuit.ConstraintGraph;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.Gate;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.WitnessCalculator;
import com.bloxbean.cardano.zeroj.circuit.halo2.Halo2Compiler;
import com.bloxbean.cardano.zeroj.circuit.plonk.PlonKCompiler;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fail-closed checks for public graph shapes that the ordinary DSL never emits.
 */
class R1CSCompilerHardeningTest {

    /**
     * {@link Gate.Select} and {@link ConstraintGraph} are public, so a caller can construct
     * this graph without going through {@code CircuitAPI.select}. Treating the select output
     * as a base wire would make it unconstrained and let a prover choose {@code out}
     * independently of {@code cond}, {@code a}, and {@code b}. PlonK and Halo2 already reject
     * this raw gate; R1CS must fail closed too.
     */
    @Test
    void rawSelectGateIsRejectedRatherThanCompiledAsAnUnconstrainedWire() {
        Variable one = new Variable(0, "_one");
        Variable publicResult = new Variable(1, "result");
        Variable cond = new Variable(2, "cond");
        Variable a = new Variable(3, "a");
        Variable b = new Variable(4, "b");
        Variable selected = Variable.intermediate(5);

        ConstraintGraph graph = new ConstraintGraph(
                "raw-select",
                List.of(
                        new Gate.Const(one, BigInteger.ONE),
                        new Gate.Select(selected, cond, a, b),
                        new Gate.AssertEq(selected, publicResult)),
                one,
                List.of(publicResult),
                List.of(cond, a, b),
                List.of(selected),
                6);

        UnsupportedOperationException error = assertThrows(
                UnsupportedOperationException.class,
                () -> R1CSCompiler.compile(graph, FieldConfig.BLS12_381));
        assertTrue(error.getMessage().contains("Gate.Select")
                        || error.getMessage().contains("Select gate"),
                error.getMessage());
    }

    @Test
    void directPublicCompilerAndWitnessEntryPointsEnforceExpectedField() {
        ConstraintGraph graph = CircuitBuilder.create("field-bound")
                .secretVar("x")
                .define(api -> {
                    api.requireField(FieldConfig.BLS12_381);
                    api.assertEqual(api.var("x"), api.var("x"));
                })
                .constraintGraph();

        assertFieldMismatch(() -> R1CSCompiler.compile(graph, FieldConfig.BN254));
        assertFieldMismatch(() -> PlonKCompiler.compile(graph, FieldConfig.BN254));
        assertFieldMismatch(() -> Halo2Compiler.compile(graph, FieldConfig.BN254));
        assertFieldMismatch(() -> WitnessCalculator.calculate(
                graph, Map.of("x", List.of(BigInteger.ONE)), FieldConfig.BN254));
        assertFieldMismatch(() -> WitnessCalculator.calculateFlat(
                graph, Map.of("x", List.of(BigInteger.ONE)), FieldConfig.BN254));
        assertFieldMismatch(() -> WitnessCalculator.calculateFlatChunked(
                graph, Map.of("x", List.of(BigInteger.ONE)), FieldConfig.BN254));
    }

    @Test
    void expressionReadCountFailsBeforeSignedIntegerWrap() {
        int[] reads = new int[]{0, Integer.MAX_VALUE};

        IllegalStateException overflow = assertThrows(
                IllegalStateException.class,
                () -> R1CSCompiler.incrementRead(reads, 1));
        assertTrue(overflow.getMessage().contains("read-count"), overflow.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> R1CSCompiler.incrementRead(reads, 2));
    }

    private static void assertFieldMismatch(org.junit.jupiter.api.function.Executable operation) {
        IllegalStateException error = assertThrows(IllegalStateException.class, operation);
        assertTrue(error.getMessage().contains("Field mismatch"), error.getMessage());
    }
}
