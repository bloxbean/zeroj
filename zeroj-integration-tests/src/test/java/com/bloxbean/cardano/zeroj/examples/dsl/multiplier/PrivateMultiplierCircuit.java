package com.bloxbean.cardano.zeroj.examples.dsl.multiplier;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

/**
 * Private multiplier circuit — proves knowledge of a secret factor.
 *
 * <p>The prover knows a secret {@code b} such that {@code a * b = c},
 * where both {@code a} and {@code c} are public. This is a simple but
 * complete circuit that demonstrates the ZK proving pipeline.</p>
 *
 * <p>Signals:</p>
 * <ul>
 *   <li><b>Public input:</b> {@code a} — the known factor</li>
 *   <li><b>Private input:</b> {@code b} — the secret factor (never revealed)</li>
 *   <li><b>Public output:</b> {@code c} — the product (a * b)</li>
 * </ul>
 *
 * <p>Use case: prove you know a secret multiplier without revealing it.
 * For example, prove you know a discount factor applied to a price.</p>
 */
public class PrivateMultiplierCircuit implements CircuitSpec {

    @Override
    public void define(SignalBuilder ctx) {
        Signal a = ctx.publicInput("a");
        Signal b = ctx.privateInput("b");
        Signal c = ctx.publicOutput("c");

        ctx.assertEqual(a.mul(b), c);
    }

    /**
     * Build the circuit with the standard variable layout.
     *
     * @return configured CircuitBuilder ready for compilation
     */
    public static CircuitBuilder build() {
        return CircuitBuilder.create("private-multiplier")
                .publicVar("a")
                .publicVar("c")
                .secretVar("b")
                .defineSignals(new PrivateMultiplierCircuit());
    }
}
