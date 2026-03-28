package com.bloxbean.cardano.zeroj.circuit;

/**
 * Interface for defining circuits as Java classes.
 *
 * <p>This is the class-based alternative to the lambda-based {@link CircuitDefinition}.
 * Implement this interface to define reusable, testable circuit components:</p>
 *
 * <pre>{@code
 * public class MulCircuit implements CircuitSpec {
 *     @Override
 *     public void define(SignalBuilder c) {
 *         Signal a = c.privateInput("a");
 *         Signal b = c.privateInput("b");
 *         Signal out = c.publicOutput("out");
 *         c.assertEqual(a.mul(b), out);
 *     }
 * }
 *
 * // Use:
 * var circuit = CircuitBuilder.fromSpec("multiplier", new MulCircuit());
 * var witness = circuit.calculateWitness(inputs, CurveId.BN254);
 * }</pre>
 */
@FunctionalInterface
public interface CircuitSpec {

    /**
     * Define the circuit using the signal builder.
     */
    void define(SignalBuilder c);
}
