package org.zeroj.circuit.lib.jubjub;

/**
 * Checks that a raw ciphertext is a well-formed encryption of an in-range message
 * ({@code elgamal-jubjub-v1} §9.1, §10.1), supplied by the caller at admission.
 *
 * <p><b>Delegated verifier obligation.</b> Return {@code true} only if a proof of
 * {@code R_enc(w)} was verified for exactly {@link EncryptionStatement#publicInputs()} (or
 * the same key and ciphertext embedded in an application statement), with a verification key
 * whose circuit has exactly {@link EncryptionStatement#width()}.
 *
 * <p>One legitimate delegation is an on-chain validator that already verified the statement
 * before the ciphertext reached the ledger. The implementation must then establish, from chain
 * data, that this ciphertext is one such validator accepted. A verifier that returns
 * {@code true} without either check lets a ciphertext in with a false bound, and a homomorphic
 * sum can then wrap mod {@code l} undetected.
 */
@FunctionalInterface
public interface EncryptionStatementVerifier {

    /** Returns {@code true} iff the statement is proved for this exact key, ciphertext and width. */
    boolean verify(EncryptionStatement statement);
}
