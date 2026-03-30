package com.bloxbean.cardano.zeroj.examples.dsl.templates;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMiMC;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;

/**
 * Parameterized Merkle inclusion proof — depth and hash function as template parameters.
 *
 * <p>Proves that a secret {@code leaf} is included in a Merkle tree with a known
 * public {@code root}, given a path of {@code depth} sibling hashes.</p>
 *
 * <pre>{@code
 * // Circom equivalent:
 * template MerkleProof(depth) {
 *     signal input leaf;
 *     signal input root;
 *     signal input siblings[depth];
 *     signal input pathBits[depth];
 *     // ... hash chain verification
 * }
 * }</pre>
 *
 * <p>In Java, both {@code depth} and {@code hashFn} are constructor parameters —
 * more flexible than Circom templates which only support integer parameters.</p>
 *
 * @param depth   tree depth (number of sibling levels)
 * @param hashFn  hash function to use (MiMC, Poseidon, or any 2-to-1 hash)
 */
public class NWayMerkleCircuit implements CircuitSpec {

    /** Supported hash functions for Merkle nodes. */
    public enum HashType { MIMC, POSEIDON }

    private final int depth;
    private final HashType hashType;

    public NWayMerkleCircuit(int depth, HashType hashType) {
        if (depth < 1) throw new IllegalArgumentException("depth must be >= 1");
        this.depth = depth;
        this.hashType = hashType;
    }

    @Override
    public void define(SignalBuilder c) {
        Signal leaf = c.privateInput("leaf");
        Signal root = c.publicOutput("root");

        // Sibling hashes and path direction bits — array signals via Java arrays
        Signal[] siblings = new Signal[depth];
        Signal[] pathBits = new Signal[depth];
        for (int i = 0; i < depth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("pathBit_" + i);
        }

        // Hash function selection — resolved at circuit build time (not runtime)
        SignalMerkle.HashFn hashFn = switch (hashType) {
            case MIMC -> SignalMiMC::hash;
            case POSEIDON -> SignalPoseidon::hash;
        };

        // Verify the Merkle path
        SignalMerkle.verifyProof(c, leaf, root, siblings, pathBits, hashFn);
    }

    public static CircuitBuilder build(int depth, HashType hashType) {
        var builder = CircuitBuilder.create("merkle-" + hashType.name().toLowerCase() + "-d" + depth)
                .publicVar("root")
                .secretVar("leaf");

        for (int i = 0; i < depth; i++) {
            builder = builder.secretVar("sibling_" + i);
        }
        for (int i = 0; i < depth; i++) {
            builder = builder.secretVar("pathBit_" + i);
        }

        return builder.defineSignals(new NWayMerkleCircuit(depth, hashType));
    }
}
