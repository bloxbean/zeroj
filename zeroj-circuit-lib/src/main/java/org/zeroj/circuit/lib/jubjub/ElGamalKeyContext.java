package org.zeroj.circuit.lib.jubjub;

/**
 * The key an {@code elgamal-jubjub-v1} ciphertext is under, together with how that key is
 * shared (ADR-0052 D2c, invariant I13).
 *
 * <p>Every safe-layer ciphertext carries its context. Homomorphic operations and decryption
 * refuse ciphertexts whose contexts differ, because adding ciphertexts under different keys
 * can decrypt to a wrong in-range value instead of failing. Contexts compare by value: the
 * joint key and the registered share set.
 */
public sealed interface ElGamalKeyContext permits NOfNKeyContext, ThresholdKeyContext {

    /** The key ciphertexts are encrypted to. */
    ElGamalPublicKey jointKey();
}
