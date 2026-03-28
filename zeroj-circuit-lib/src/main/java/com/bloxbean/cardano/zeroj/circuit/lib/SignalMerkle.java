package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

/**
 * Merkle proof verification using the Signal API.
 *
 * <pre>{@code
 * SignalMerkle.verifyProof(c, leaf, root, siblings, pathBits, SignalMiMC::hash);
 * }</pre>
 */
public final class SignalMerkle {

    private SignalMerkle() {}

    /** Hash function interface for Merkle nodes. */
    @FunctionalInterface
    public interface HashFn {
        Signal hash(SignalBuilder c, Signal left, Signal right);
    }

    /**
     * Verify a Merkle proof.
     */
    public static void verifyProof(SignalBuilder c, Signal leaf, Signal root,
                                    Signal[] siblings, Signal[] pathBits, HashFn hashFn) {
        Signal current = leaf;
        for (int i = 0; i < siblings.length; i++) {
            pathBits[i].assertBoolean();
            Signal left = pathBits[i].select(siblings[i], current);
            Signal right = pathBits[i].select(current, siblings[i]);
            current = hashFn.hash(c, left, right);
        }
        c.assertEqual(current, root);
    }

    /**
     * Compute the Merkle root (without asserting).
     */
    public static Signal computeRoot(SignalBuilder c, Signal leaf,
                                      Signal[] siblings, Signal[] pathBits, HashFn hashFn) {
        Signal current = leaf;
        for (int i = 0; i < siblings.length; i++) {
            pathBits[i].assertBoolean();
            Signal left = pathBits[i].select(siblings[i], current);
            Signal right = pathBits[i].select(current, siblings[i]);
            current = hashFn.hash(c, left, right);
        }
        return current;
    }
}
