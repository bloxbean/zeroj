package org.zeroj.bls12381.pedersen;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;

import java.math.BigInteger;
import java.util.Objects;

/**
 * A canonical {@code pedersen-bls12-381-g1-v1} opening {@code (m, r)} and its wire form
 * {@code I2OSP(m, 32) ‖ I2OSP(r, 32)} ({@code pedersen-bls12-381-g1-v1} §6.1).
 *
 * <p>Both scalars satisfy check 1, {@code 0 ≤ m, r < q}; nothing is reduced. An application
 * amount bound (check 2) is applied on top, with
 * {@link G1Pedersen#verifyScalar(G1PedersenCommitment, BigInteger, BigInteger, int)}.
 *
 * <p><b>Secret.</b> The value and blinding are secret until disclosed. This holder is not a
 * record, not {@code Serializable}, does not override {@code equals}/{@code hashCode}, and its
 * {@code toString} is redacted. Its {@link BigInteger} fields are immutable and cannot be wiped
 * from memory; the caller owns and should wipe the arrays {@link #encode()} returns and
 * {@link #decode(byte[])} reads.
 */
public final class G1PedersenOpening {

    /** Octets of an encoded opening. */
    static final int ENCODED_BYTES = 2 * G1PedersenStrict.SCALAR_BYTES;

    private final BigInteger value;
    private final BigInteger blinding;

    private G1PedersenOpening(BigInteger value, BigInteger blinding) {
        this.value = value;
        this.blinding = blinding;
    }

    /**
     * Checks, in order: nulls; one snapshot of each argument; {@code value}, then {@code blinding},
     * in {@code [0, q)}.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException ({@code NON_CANONICAL_SCALAR}) if {@code value}, then
     *                                   {@code blinding}, is not in {@code [0, q)}
     */
    public static G1PedersenOpening of(BigInteger value, BigInteger blinding) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        BigInteger m = G1PedersenStrict.snapshot(value);
        BigInteger r = G1PedersenStrict.snapshot(blinding);
        G1PedersenStrict.requireCanonical(m, "value");
        G1PedersenStrict.requireCanonical(r, "blinding");
        return new G1PedersenOpening(m, r);
    }

    /**
     * Decodes {@code I2OSP(m, 32) ‖ I2OSP(r, 32)}: a length other than 64 is
     * {@code MALFORMED_ENCODING}; then {@code m ≥ q}, then {@code r ≥ q}, is
     * {@code NON_CANONICAL_SCALAR}.
     *
     * @throws NullPointerException      if {@code encoded} is null
     * @throws CommitmentFormatException with the class of the first failure
     */
    public static G1PedersenOpening decode(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length != ENCODED_BYTES) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "a pedersen-bls12-381-g1-v1 opening is " + ENCODED_BYTES + " octets");
        }
        BigInteger value = G1PedersenStrict.readScalar(encoded, 0);
        BigInteger blinding = G1PedersenStrict.readScalar(encoded, G1PedersenStrict.SCALAR_BYTES);
        return new G1PedersenOpening(G1PedersenStrict.requireCanonical(value, "value"),
                G1PedersenStrict.requireCanonical(blinding, "blinding"));
    }

    /** A fresh 64-octet encoding; the caller should wipe it after use. */
    public byte[] encode() {
        byte[] out = new byte[ENCODED_BYTES];
        G1PedersenStrict.writeScalar(value, out, 0);
        G1PedersenStrict.writeScalar(blinding, out, G1PedersenStrict.SCALAR_BYTES);
        return out;
    }

    /** The committed value {@code m ∈ [0, q)}. */
    public BigInteger value() {
        return value;
    }

    /** The blinding {@code r ∈ [0, q)}. */
    public BigInteger blinding() {
        return blinding;
    }

    @Override
    public String toString() {
        return "G1PedersenOpening[redacted]";
    }
}
