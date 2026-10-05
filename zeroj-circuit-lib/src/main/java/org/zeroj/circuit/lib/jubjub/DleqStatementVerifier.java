package org.zeroj.circuit.lib.jubjub;

/**
 * Checks a proof of an {@code elgamal-jubjub-v1} DLEQ statement (spec §9.2), supplied by the
 * caller (ADR-0052 D4: the proof system is the application's).
 *
 * <p><b>Delegated verifier obligation.</b> An implementation must return {@code true} only if
 * it verified a proof for <b>exactly</b> {@link DleqStatement#publicInputs()}, in that order,
 * under the verification key of the DLEQ relation. For a Groth16 proof that means passing these
 * six values as the public inputs, not values taken from the proof's sender. A verifier that
 * returns {@code true} without such a check defeats the possession and share-verification
 * guarantees. The library cannot detect it.
 */
@FunctionalInterface
public interface DleqStatementVerifier {

    /** Returns {@code true} iff a valid proof exists for this exact statement. */
    boolean verify(DleqStatement statement);
}
