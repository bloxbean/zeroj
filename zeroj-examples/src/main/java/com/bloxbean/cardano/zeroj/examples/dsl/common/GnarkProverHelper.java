package com.bloxbean.cardano.zeroj.examples.dsl.common;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkProver;
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkProver.FullProveResponse;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Clean wrapper for using gnark FFM native prover with Java DSL circuits.
 *
 * <p>Unlike {@link SnarkjsProver} which shells out to the snarkjs CLI, this helper
 * performs everything in-process via gnark FFM — no external tools needed at runtime.</p>
 *
 * <p>Usage:</p>
 * <pre>{@code
 * try (var prover = new GnarkProver()) {
 *     var result = GnarkProverHelper.groth16Prove(
 *             SealedBidCircuit.build(), inputs, CurveId.BLS12_381, prover);
 *     // result.proveResponse() has proof JSON + public signals
 *     // result.vkJson() has the verification key
 * }
 * }</pre>
 */
public final class GnarkProverHelper {

    private GnarkProverHelper() {}

    /**
     * Groth16 full prove: compile circuit + calculate witness + gnark native prove.
     *
     * @param circuit  built circuit (with signals defined)
     * @param inputs   input signal values
     * @param curve    elliptic curve
     * @param prover   gnark native prover instance
     * @return full prove response including proof, public signals, and VK
     */
    public static FullProveResponse groth16Prove(
            CircuitBuilder circuit,
            Map<String, List<BigInteger>> inputs,
            CurveId curve,
            GnarkProver prover) {

        var r1cs = circuit.compileR1CS(curve);
        BigInteger[] witness = circuit.calculateWitness(inputs, curve);

        return prover.groth16FullProve(r1cs, witness, curve);
    }

    /**
     * PlonK full prove: compile circuit + calculate witness + gnark native prove.
     */
    public static FullProveResponse plonkProve(
            CircuitBuilder circuit,
            Map<String, List<BigInteger>> inputs,
            CurveId curve,
            GnarkProver prover) {

        var r1cs = circuit.compileR1CS(curve);
        BigInteger[] witness = circuit.calculateWitness(inputs, curve);

        return prover.plonkFullProve(r1cs, witness, curve);
    }
}
