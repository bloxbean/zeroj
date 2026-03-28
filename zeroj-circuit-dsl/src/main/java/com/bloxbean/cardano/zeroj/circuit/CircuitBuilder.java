package com.bloxbean.cardano.zeroj.circuit;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSCompiler;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.circuit.plonk.PlonKCompiler;
import com.bloxbean.cardano.zeroj.circuit.plonk.PlonKConstraintSystem;
import com.bloxbean.cardano.zeroj.circuit.halo2.Halo2Compiler;
import com.bloxbean.cardano.zeroj.circuit.halo2.Halo2CircuitSystem;

import java.math.BigInteger;
import java.util.*;

/**
 * Fluent API for defining ZK arithmetic circuits.
 *
 * <p>Usage:</p>
 * <pre>{@code
 * var circuit = CircuitBuilder.create("multiplier")
 *     .publicVar("z")
 *     .secretVar("x")
 *     .secretVar("y")
 *     .define(api -> {
 *         var product = api.mul(api.var("x"), api.var("y"));
 *         api.assertEqual(product, api.var("z"));
 *     });
 *
 * // Compile to R1CS (for Groth16)
 * var r1cs = circuit.compileR1CS(CurveId.BN254);
 *
 * // Compile to PlonK
 * var plonk = circuit.compilePlonK(CurveId.BN254);
 *
 * // Calculate witness
 * var witness = circuit.calculateWitness(Map.of(
 *     "x", List.of(BigInteger.valueOf(3)),
 *     "y", List.of(BigInteger.valueOf(11)),
 *     "z", List.of(BigInteger.valueOf(33))), CurveId.BN254);
 * }</pre>
 */
public final class CircuitBuilder {

    private final String name;
    private final List<String> publicVarNames = new ArrayList<>();
    private final List<String> secretVarNames = new ArrayList<>();
    private ConstraintGraph graph;

    private CircuitBuilder(String name) {
        this.name = Objects.requireNonNull(name);
    }

    /** Create a new circuit builder with the given name. */
    public static CircuitBuilder create(String name) {
        return new CircuitBuilder(name);
    }

    /** Declare a public input variable. */
    public CircuitBuilder publicVar(String name) {
        publicVarNames.add(name);
        return this;
    }

    /** Declare a secret (private) input variable. */
    public CircuitBuilder secretVar(String name) {
        secretVarNames.add(name);
        return this;
    }

    /** Define the circuit constraints. This freezes the circuit. */
    public CircuitBuilder define(CircuitDefinition definition) {
        var impl = new CircuitAPIImpl(publicVarNames, secretVarNames);
        definition.define(impl);
        this.graph = impl.buildGraph(name);
        return this;
    }

    /** Get the proof-system-agnostic constraint graph. */
    public ConstraintGraph constraintGraph() {
        requireDefined();
        return graph;
    }

    /** Compile to R1CS constraint system for Groth16. */
    public R1CSConstraintSystem compileR1CS(CurveId curve) {
        requireDefined();
        return R1CSCompiler.compile(graph, FieldConfig.forCurve(curve));
    }

    /** Compile to PlonK constraint system. */
    public PlonKConstraintSystem compilePlonK(CurveId curve) {
        requireDefined();
        return PlonKCompiler.compile(graph, FieldConfig.forCurve(curve));
    }

    /** Compile to Halo2 PLONKish circuit system. */
    public Halo2CircuitSystem compileHalo2(CurveId curve) {
        requireDefined();
        return Halo2Compiler.compile(graph, FieldConfig.forCurve(curve));
    }

    /** Calculate witness for given inputs. */
    public BigInteger[] calculateWitness(Map<String, List<BigInteger>> inputs, CurveId curve) {
        requireDefined();
        return WitnessCalculator.calculate(graph, inputs, FieldConfig.forCurve(curve));
    }

    private void requireDefined() {
        if (graph == null) throw new IllegalStateException("Circuit not defined yet. Call define() first.");
    }
}
