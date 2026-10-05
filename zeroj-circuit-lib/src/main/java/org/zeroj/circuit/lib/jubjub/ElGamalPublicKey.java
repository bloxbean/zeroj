package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * An {@code elgamal-jubjub-v1} public key: a non-identity point of the prime-order subgroup
 * (spec §3.1, ADR-0052 invariant I1).
 *
 * <p>A key is never accepted from a bare claim. It is produced by
 * {@link ElGamalSecretKey#publicKey()}, by {@link VerifiedKeyShare} after a possession check,
 * or as the joint key of an aggregation of verified shares ({@link #aggregate}). That is what
 * makes a forgotten proof of possession, the rogue-key attack, impossible on the safe path.
 */
public final class ElGamalPublicKey {

    private final JubjubPoint point;
    private final byte[] encoding;

    /** The point must already be validated as a non-identity subgroup point. */
    ElGamalPublicKey(JubjubPoint validatedPoint) {
        this.point = validatedPoint.normalized();
        this.encoding = this.point.toBytes();
    }

    /**
     * Sums verified key shares into an n-of-n joint key (spec §3.2, ADR-0052 D5).
     *
     * @return the key context: the joint key and the registered shares
     * @throws IllegalArgumentException if the list is empty, holds two equal shares, or sums to
     *         the identity
     */
    public static NOfNKeyContext aggregate(List<VerifiedKeyShare> shares) {
        Objects.requireNonNull(shares, "shares");
        if (shares.isEmpty()) {
            throw new IllegalArgumentException("at least one key share is required");
        }
        List<VerifiedKeyShare> sorted = new ArrayList<>(shares.size());
        for (VerifiedKeyShare share : shares) {
            sorted.add(Objects.requireNonNull(share, "share"));
        }
        sorted.sort((a, b) -> Arrays.compareUnsigned(
                a.publicKey().encodingRef(), b.publicKey().encodingRef()));
        FastJubjubPoint sum = FastJubjubPoint.IDENTITY;
        for (int i = 0; i < sorted.size(); i++) {
            if (i > 0 && Arrays.equals(sorted.get(i - 1).publicKey().encodingRef(),
                    sorted.get(i).publicKey().encodingRef())) {
                throw new IllegalArgumentException("key shares must be pairwise distinct");
            }
            sum = sum.add(FastJubjubPoint.of(sorted.get(i).publicKey().point()));
        }
        if (sum.isIdentity()) {
            throw new IllegalArgumentException("key shares must not sum to the identity");
        }
        return new NOfNKeyContext(new ElGamalPublicKey(sum.toJubjubPoint()), sorted);
    }

    /** The point, normalized. */
    public JubjubPoint point() {
        return point;
    }

    /** Affine {@code u} (named like {@link JubjubPoint#affineU()}, unlike the projective {@code JubjubPoint.u()}). */
    public BigInteger affineU() {
        return point.u();
    }

    /** Affine {@code v}. */
    public BigInteger affineV() {
        return point.v();
    }

    /** The 32-byte encoding (spec §7.3). */
    public byte[] encode() {
        return encoding.clone();
    }

    /** Public inputs {@code PK.u, PK.v} (spec §8). */
    public List<BigInteger> publicInputs() {
        return List.of(point.u(), point.v());
    }

    byte[] encodingRef() {
        return encoding;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ElGamalPublicKey other && Arrays.equals(encoding, other.encoding);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoding);
    }

    @Override
    public String toString() {
        return "ElGamalPublicKey{" + HexFormat.of().formatHex(encoding) + "}";
    }
}
