package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

/**
 * Merkle tree proof verification circuit.
 *
 * <p>Parameterized by hash function — works with any 2-to-1 hash (Poseidon, MiMC, etc.).</p>
 */
public final class Merkle {

    private Merkle() {}

    /**
     * Hash function interface for Merkle tree nodes.
     */
    @FunctionalInterface
    public interface HashFunction {
        Variable hash(CircuitAPI api, Variable left, Variable right);
    }

    /**
     * Verify a Merkle proof.
     *
     * @param api       circuit API
     * @param leaf      the leaf value
     * @param root      the expected root
     * @param siblings  sibling hashes at each level (bottom to top)
     * @param pathBits  direction at each level: 0 = leaf is left child, 1 = leaf is right child
     * @param hashFn    hash function for internal nodes
     */
    public static void verifyProof(CircuitAPI api, Variable leaf, Variable root,
                                    Variable[] siblings, Variable[] pathBits,
                                    HashFunction hashFn) {
        if (siblings.length != pathBits.length) {
            throw new IllegalArgumentException("siblings and pathBits must have equal length");
        }

        Variable current = leaf;
        for (int i = 0; i < siblings.length; i++) {
            api.assertBoolean(pathBits[i]);

            // If pathBit == 0: current is left, sibling is right
            // If pathBit == 1: sibling is left, current is right
            var left = api.select(pathBits[i], siblings[i], current);
            var right = api.select(pathBits[i], current, siblings[i]);

            current = hashFn.hash(api, left, right);
        }

        api.assertEqual(current, root);
    }

    /**
     * Verify a Merkle proof and return the computed root (for inspection).
     */
    public static Variable computeRoot(CircuitAPI api, Variable leaf,
                                        Variable[] siblings, Variable[] pathBits,
                                        HashFunction hashFn) {
        Variable current = leaf;
        for (int i = 0; i < siblings.length; i++) {
            api.assertBoolean(pathBits[i]);
            var left = api.select(pathBits[i], siblings[i], current);
            var right = api.select(pathBits[i], current, siblings[i]);
            current = hashFn.hash(api, left, right);
        }
        return current;
    }
}
