package org.zeroj.circuit.lib.jubjub;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * An n-of-n key context ({@code elgamal-jubjub-v1} §3.2): the joint key {@code Σ PK_j} and its
 * possession-verified shares, sorted by encoding. Decrypting needs one verified share from
 * every registered trustee. A single key is the case {@code n = 1}.
 *
 * <p>Built only by {@link ElGamalPublicKey#aggregate} or {@link #singleKey}. Two contexts are
 * equal iff their joint keys and sorted share encodings are equal.
 */
public final class NOfNKeyContext implements ElGamalKeyContext {

    private final ElGamalPublicKey jointKey;
    private final List<VerifiedKeyShare> shares;
    private final byte[] identity;

    NOfNKeyContext(ElGamalPublicKey jointKey, List<VerifiedKeyShare> sortedShares) {
        this.jointKey = jointKey;
        this.shares = List.copyOf(sortedShares);
        ByteArrayOutputStream out = new ByteArrayOutputStream(32 * (shares.size() + 1));
        out.writeBytes(jointKey.encodingRef());
        for (VerifiedKeyShare share : shares) {
            out.writeBytes(share.publicKey().encodingRef());
        }
        this.identity = out.toByteArray();
    }

    /** A single-key context for a secret this party holds. */
    public static NOfNKeyContext singleKey(ElGamalSecretKey secretKey) {
        return ElGamalPublicKey.aggregate(List.of(VerifiedKeyShare.fromSecret(secretKey)));
    }

    @Override
    public ElGamalPublicKey jointKey() {
        return jointKey;
    }

    /** The registered shares, sorted by encoding. */
    public List<VerifiedKeyShare> shares() {
        return shares;
    }

    /** The number of registered trustees. */
    public int size() {
        return shares.size();
    }

    /** The index of a registered share's key, or {@code −1}. */
    int indexOf(ElGamalPublicKey key) {
        Objects.requireNonNull(key, "key");
        for (int i = 0; i < shares.size(); i++) {
            if (shares.get(i).publicKey().equals(key)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof NOfNKeyContext other && Arrays.equals(identity, other.identity);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(identity);
    }

    @Override
    public String toString() {
        return "NOfNKeyContext{jointKey=" + jointKey + ", trustees=" + shares.size() + "}";
    }
}
