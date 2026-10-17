package org.zeroj.circuit.lib.jubjub;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;

import java.math.BigInteger;
import java.util.Objects;

/**
 * A canonical {@code pedersen-jubjub-v1} opening {@code (m, r)} and its wire form
 * {@code I2OSP(m, 32) ‖ I2OSP(r, 32)} ({@code commitment-profiles-v1} §8.1).
 *
 * <p>Both scalars satisfy check 1, {@code 0 ≤ m, r < l}; nothing is reduced. An application
 * amount bound (check 2) is applied on top, with
 * {@link PedersenCommitment#verifyScalar(PedersenScalarCommitment, BigInteger, BigInteger, int)}.
 *
 * <p><b>Secret.</b> The value and blinding are secret until disclosed. This holder is not a
 * record, not {@code Serializable}, does not override {@code equals}/{@code hashCode}, and its
 * {@code toString} is redacted. Its {@link BigInteger} fields are immutable and cannot be wiped
 * from memory; the caller owns and should wipe the arrays {@link #encode()} returns and
 * {@link #decode(byte[])} reads.
 */
public final class PedersenScalarOpening {

    /** Octets of an encoded opening. */
    static final int ENCODED_BYTES = 2 * PedersenStrict.SCALAR_BYTES;

    private final BigInteger value;
    private final BigInteger blinding;

    private PedersenScalarOpening(BigInteger value, BigInteger blinding) {
        this.value = value;
        this.blinding = blinding;
    }

    /**
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException ({@code NON_CANONICAL_SCALAR}) if {@code value}, then
     *                                   {@code blinding}, is not in {@code [0, l)}
     */
    public static PedersenScalarOpening of(BigInteger value, BigInteger blinding) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        BigInteger m = PedersenStrict.canonical(value, "value");
        BigInteger r = PedersenStrict.canonical(blinding, "blinding");
        return new PedersenScalarOpening(m, r);
    }

    /**
     * Decodes {@code I2OSP(m, 32) ‖ I2OSP(r, 32)}: a length other than 64 is
     * {@code MALFORMED_ENCODING}; then {@code m ≥ l}, then {@code r ≥ l}, is
     * {@code NON_CANONICAL_SCALAR}.
     *
     * @throws NullPointerException      if {@code encoded} is null
     * @throws CommitmentFormatException with the class of the first failure
     */
    public static PedersenScalarOpening decode(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length != ENCODED_BYTES) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "a pedersen-jubjub-v1 opening is " + ENCODED_BYTES + " octets");
        }
        BigInteger value = PedersenStrict.readScalar(encoded, 0);
        BigInteger blinding = PedersenStrict.readScalar(encoded, PedersenStrict.SCALAR_BYTES);
        return new PedersenScalarOpening(PedersenStrict.canonical(value, "value"),
                PedersenStrict.canonical(blinding, "blinding"));
    }

    /** A fresh 64-octet encoding; the caller should wipe it after use. */
    public byte[] encode() {
        byte[] out = new byte[ENCODED_BYTES];
        PedersenStrict.writeScalar(value, out, 0);
        PedersenStrict.writeScalar(blinding, out, PedersenStrict.SCALAR_BYTES);
        return out;
    }

    /** The committed value {@code m ∈ [0, l)}. */
    public BigInteger value() {
        return value;
    }

    /** The blinding {@code r ∈ [0, l)}. */
    public BigInteger blinding() {
        return blinding;
    }

    @Override
    public String toString() {
        return "PedersenScalarOpening[redacted]";
    }
}
