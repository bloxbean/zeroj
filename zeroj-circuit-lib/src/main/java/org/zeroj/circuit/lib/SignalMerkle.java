package org.zeroj.circuit.lib;

import org.zeroj.circuit.Signal;
import org.zeroj.circuit.SignalBuilder;

/**
 * Merkle proof verification using the Signal API.
 *
 * <pre>{@code
 * SignalMerkle.verifyProof(c, leaf, root, siblings, pathBits,
 *         (cb, l, r) -> SignalPoseidon.hash(cb, PoseidonParamsBLS12_381T3.INSTANCE, l, r));
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
        Signal current = computeRoot(c, leaf, siblings, pathBits, hashFn);
        c.assertEqual(current, root);
    }

    /**
     * Compute the Merkle root (without asserting).
     */
    public static Signal computeRoot(SignalBuilder c, Signal leaf,
                                      Signal[] siblings, Signal[] pathBits, HashFn hashFn) {
        if (siblings == null || pathBits == null) {
            throw new IllegalArgumentException("siblings and pathBits must not be null");
        }
        if (siblings.length != pathBits.length) {
            throw new IllegalArgumentException("siblings and pathBits must have equal length");
        }
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
