package com.bloxbean.cardano.zeroj.examples.dsl.templates;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * Parameterized hash chain circuit — demonstrates Java-as-template-system.
 *
 * <p>Proves knowledge of a secret preimage that, when hashed {@code depth} times,
 * produces a known public digest. This is the ZK equivalent of a hash-based
 * time-lock or proof-of-work chain.</p>
 *
 * <pre>{@code
 * // Circom equivalent:
 * template HashChain(depth) {
 *     signal input secret;
 *     signal output digest;
 *     signal intermediate[depth + 1];
 *     intermediate[0] <== secret;
 *     for (var i = 0; i < depth; i++) {
 *         intermediate[i+1] <== PoseidonBLS12_381(intermediate[i], 0);
 *     }
 *     digest <== intermediate[depth];
 * }
 * }</pre>
 *
 * <p>In Java, the constructor parameter replaces Circom's template parameter.
 * Java loops unroll the circuit at build time — no special DSL syntax needed.</p>
 *
 * @param depth number of hash iterations (Circom: template parameter)
 */
public class HashChainCircuit implements CircuitSpec {

    private final int depth;

    public HashChainCircuit(int depth) {
        if (depth < 1) throw new IllegalArgumentException("depth must be >= 1, got " + depth);
        this.depth = depth;
    }

    @Override
    public void define(SignalBuilder c) {
        Signal secret = c.privateInput("secret");
        Signal digest = c.publicOutput("digest");

        // Hash chain: h_0 = secret, h_{i+1} = PoseidonBLS12_381(h_i, 0)
        Signal current = secret;
        Signal zero = c.constant(0);
        for (int i = 0; i < depth; i++) {
            current = SignalPoseidon.hash(c, PoseidonParamsBLS12_381T3.INSTANCE, current, zero);
        }

        c.assertEqual(current, digest);
    }

    public static CircuitBuilder build(int depth) {
        return CircuitBuilder.create("hash-chain-" + depth)
                .publicVar("digest")
                .secretVar("secret")
                .defineSignals(new HashChainCircuit(depth));
    }
}
