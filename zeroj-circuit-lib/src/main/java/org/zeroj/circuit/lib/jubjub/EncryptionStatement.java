package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.List;

/**
 * The {@code R_enc(w)} statement of {@code elgamal-jubjub-v1} §9.1 for one ciphertext, as the
 * library hands it to an {@link EncryptionStatementVerifier} during admission (§10.1).
 *
 * <p>The library builds it from the context's joint key, the raw ciphertext and the width.
 * The verifier must check a proof for exactly these values at exactly this width: an
 * admission at a narrower width than the proof's circuit would understate the plaintext
 * bound.
 */
public final class EncryptionStatement {

    private final ElGamalPublicKey key;
    private final JubjubPoint handle;
    private final JubjubPoint blinded;
    private final int width;

    EncryptionStatement(ElGamalPublicKey key, JubjubPoint handle, JubjubPoint blinded, int width) {
        this.key = key;
        this.handle = handle.normalized();
        this.blinded = blinded.normalized();
        this.width = width;
    }

    /** The joint key {@code PK}. */
    public ElGamalPublicKey key() {
        return key;
    }

    /** {@code A}. */
    public JubjubPoint handle() {
        return handle;
    }

    /** {@code B}. */
    public JubjubPoint blinded() {
        return blinded;
    }

    /** The message width {@code w} the circuit must prove. */
    public int width() {
        return width;
    }

    /** Spec §8 order: {@code PK.u, PK.v, A.u, A.v, B.u, B.v}. */
    public List<BigInteger> publicInputs() {
        return ElGamalEncodings.affine(key.point(), handle, blinded);
    }

    /** {@code PK.u, PK.v}. */
    public List<BigInteger> keyPublicInputs() {
        return key.publicInputs();
    }

    /** {@code A.u, A.v, B.u, B.v}. */
    public List<BigInteger> ciphertextPublicInputs() {
        return ElGamalEncodings.affine(handle, blinded);
    }

    @Override
    public String toString() {
        return "EncryptionStatement{width=" + width + ", publicInputs=" + publicInputs() + "}";
    }
}
