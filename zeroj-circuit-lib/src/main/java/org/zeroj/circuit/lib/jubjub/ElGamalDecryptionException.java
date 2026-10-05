package org.zeroj.circuit.lib.jubjub;

/**
 * Decryption failed closed: no integer in {@code [0, bound]} maps to the unmasked point
 * ({@code elgamal-jubjub-v1} §6.3). Decryption never returns an out-of-range or approximate
 * value instead.
 */
public final class ElGamalDecryptionException extends IllegalStateException {

    public ElGamalDecryptionException(String message) {
        super(message);
    }
}
