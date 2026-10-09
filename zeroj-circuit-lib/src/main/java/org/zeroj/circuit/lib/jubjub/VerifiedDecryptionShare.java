package org.zeroj.circuit.lib.jubjub;

import java.util.Objects;

/**
 * A decryption share {@code D_j = [sk_j]·A} that is known to be correct for one admitted
 * ciphertext and one registered trustee ({@code elgamal-jubjub-v1} §10.2; ADR-0052 D2b,
 * invariant I14).
 *
 * <p>Obtained only by:
 * <ul>
 *   <li>{@link #verify}: a caller-supplied verifier accepted the DLEQ statement the library
 *       built, with {@code X} = the ciphertext's handle and {@code P} = the trustee's key as
 *       registered in the ciphertext's context;</li>
 *   <li>{@link ElGamal#decryptionShare}: computed locally from a secret whose public key is
 *       registered.</li>
 * </ul>
 * An unverified share lets a trustee who saw the others choose the decrypted result.
 */
public final class VerifiedDecryptionShare {

    private final ElGamalCiphertext ciphertext;
    private final int trustee;
    private final JubjubPoint share;
    private final DleqStatement statement;

    VerifiedDecryptionShare(ElGamalCiphertext ciphertext, int trustee, JubjubPoint share, DleqStatement statement) {
        this.ciphertext = ciphertext;
        this.trustee = trustee;
        this.share = share.normalized();
        this.statement = statement;
    }

    /**
     * Verifies a claimed share from an n-of-n trustee.
     *
     * @param ciphertext the admitted ciphertext the share is for
     * @param trusteeKey the trustee's public key; it must be registered in the ciphertext's
     *                   context, which supplies {@code P}
     * @param share      the claimed {@code D_j}, as 32 bytes
     * @param verifier   checks a proof of the statement the library builds
     * @throws IllegalArgumentException if the trustee is not registered, the share does not
     *         decode to a subgroup point, or the verifier rejects the statement
     */
    public static VerifiedDecryptionShare verify(
            ElGamalCiphertext ciphertext, ElGamalPublicKey trusteeKey, byte[] share,
            DleqStatementVerifier verifier) {
        return verify(ciphertext, trusteeKey,
                ElGamalEncodings.decodeSubgroupPoint(share, "decryption share"), verifier);
    }

    /** As {@link #verify(ElGamalCiphertext, ElGamalPublicKey, byte[], DleqStatementVerifier)}. */
    public static VerifiedDecryptionShare verify(
            ElGamalCiphertext ciphertext, ElGamalPublicKey trusteeKey, JubjubPoint share,
            DleqStatementVerifier verifier) {
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(trusteeKey, "trusteeKey");
        Objects.requireNonNull(verifier, "verifier");
        if (!(ciphertext.context() instanceof NOfNKeyContext context)) {
            throw new IllegalArgumentException(
                    "an n-of-n trustee key cannot verify a share for this context");
        }
        int index = context.indexOf(trusteeKey);
        if (index < 0) {
            throw new IllegalArgumentException("trustee key is not registered in the ciphertext's context");
        }
        JubjubPoint d = ElGamalEncodings.requireSubgroup(share, "decryption share");
        JubjubPoint registered = context.shares().get(index).publicKey().point();
        DleqStatement statement = DleqStatement.decryptionShare(ciphertext.handle(), registered, d);
        if (!verifier.verify(statement)) {
            throw new IllegalArgumentException("decryption-share proof rejected");
        }
        return new VerifiedDecryptionShare(ciphertext, index, d, statement);
    }

    /**
     * Verifies a claimed share from threshold participant {@code id} (spec §9). {@code P} is the
     * identifier's verification key {@code Y_j} from the ciphertext's context, which may be the
     * identity; so may {@code D}.
     *
     * @throws IllegalArgumentException if the ciphertext is not under a threshold context, the
     *         participant is not in {@code QUAL}, the share does not decode to a subgroup point,
     *         or the verifier rejects the statement
     */
    public static VerifiedDecryptionShare verify(ElGamalCiphertext ciphertext, int id, byte[] share,
                                                 DleqStatementVerifier verifier) {
        return verify(ciphertext, id, ElGamalEncodings.decodeSubgroupPoint(share, "decryption share"), verifier);
    }

    /** As {@link #verify(ElGamalCiphertext, int, byte[], DleqStatementVerifier)}. */
    public static VerifiedDecryptionShare verify(ElGamalCiphertext ciphertext, int id, JubjubPoint share,
                                                 DleqStatementVerifier verifier) {
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(verifier, "verifier");
        if (!(ciphertext.context() instanceof ThresholdKeyContext context)) {
            throw new IllegalArgumentException("a participant identifier cannot verify a share for this context");
        }
        if (!context.qual().contains(id)) {
            throw new IllegalArgumentException("participant " + id + " is not qualified");
        }
        JubjubPoint d = ElGamalEncodings.requireSubgroup(share, "decryption share");
        DleqStatement statement = DleqStatement.decryptionShare(ciphertext.handle(), context.verificationKey(id), d);
        if (!verifier.verify(statement)) {
            throw new IllegalArgumentException("decryption-share proof rejected");
        }
        return new VerifiedDecryptionShare(ciphertext, id, d, statement);
    }

    /** {@code D_j}. */
    public JubjubPoint share() {
        return share;
    }

    /** The 32-byte encoding of {@code D_j}, for publication. */
    public byte[] encode() {
        return share.toBytes();
    }

    /**
     * The DLEQ statement {@code (X = A, P = PK_j, D = D_j)} this share satisfies. A trustee
     * proves it with {@code sk_j} as the witness, so that others can verify the share.
     */
    public DleqStatement statement() {
        return statement;
    }

    ElGamalCiphertext ciphertext() {
        return ciphertext;
    }

    /** The trustee: an index into the n-of-n registry, or a threshold participant identifier. */
    int trustee() {
        return trustee;
    }

    @Override
    public String toString() {
        return "VerifiedDecryptionShare{trustee=" + trustee + ", D=" + share + "}";
    }
}
