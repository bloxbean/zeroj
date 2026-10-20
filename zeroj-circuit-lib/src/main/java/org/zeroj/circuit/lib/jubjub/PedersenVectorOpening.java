package org.zeroj.circuit.lib.jubjub;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * A canonical {@code pedersen-jubjub-vector-v1} opening under a bound policy, and its wire form
 * {@code u8(n) ‖ I2OSP(v_0, 32) ‖ … ‖ I2OSP(v_{n−1}, 32) ‖ I2OSP(r, 32)}
 * ({@code commitment-profiles-v1} §8.3).
 *
 * <p>Every component satisfies check 1 and the policy's check 3, and the blinding check 1; nothing
 * is reduced. The policy, and through it the schema, come from the verifier's configuration.
 *
 * <p><b>Secret.</b> The values and blinding are secret until disclosed. This holder is not a
 * record, not {@code Serializable}, does not override {@code equals}/{@code hashCode}, and its
 * {@code toString} is redacted. Its {@link BigInteger} fields are immutable and cannot be wiped
 * from memory; the caller owns and should wipe the arrays {@link #encode()} returns and
 * {@link #decode} reads.
 */
public final class PedersenVectorOpening {

    private final PedersenVectorBoundPolicy policy;
    private final List<BigInteger> values;
    private final BigInteger blinding;

    private PedersenVectorOpening(PedersenVectorBoundPolicy policy, List<BigInteger> values, BigInteger blinding) {
        this.policy = policy;
        this.values = values;
        this.blinding = blinding;
    }

    /**
     * Checks, in order: nulls (including null elements; at most
     * {@value PedersenVectorBases#MAX_DIMENSION} + 1 elements are read, so a longer list costs
     * bounded work and fails the dimension check); dimension ({@code MALFORMED_ENCODING});
     * each value's check 1, then the blinding's ({@code NON_CANONICAL_SCALAR}); each value's check 3
     * ({@code OUT_OF_RANGE}).
     *
     * @throws NullPointerException      if an argument or element is null
     * @throws CommitmentFormatException with the class of the first failure
     */
    public static PedersenVectorOpening of(PedersenVectorBoundPolicy policy, List<BigInteger> values,
                                           BigInteger blinding) {
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(values, "values");
        Objects.requireNonNull(blinding, "blinding");
        PedersenVectorBoundPolicy.CheckedOpening checked = policy.requireOpening(values, blinding);
        return new PedersenVectorOpening(policy, checked.values(), checked.blinding());
    }

    /**
     * Decodes under {@code policy}, in the order of spec §8.3: length {@code < 1}, {@code n} other
     * than the schema dimension, or total length other than {@code 33 + 32·n}
     * ({@code MALFORMED_ENCODING}); each {@code v_i ≥ l} in index order, then {@code r ≥ l}
     * ({@code NON_CANONICAL_SCALAR}); each {@code v_i} outside the policy in index order
     * ({@code OUT_OF_RANGE}).
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException with the class of the first failure
     */
    public static PedersenVectorOpening decode(byte[] encoded, PedersenVectorBoundPolicy policy) {
        Objects.requireNonNull(encoded, "encoded");
        Objects.requireNonNull(policy, "policy");
        int dimension = policy.schema().dimension();
        if (encoded.length < 1 || (encoded[0] & 0xFF) != dimension
                || encoded.length != encodedLength(dimension)) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "a vector opening of dimension " + dimension + " is " + encodedLength(dimension) + " octets");
        }
        BigInteger[] parsed = new BigInteger[dimension];
        for (int i = 0; i < dimension; i++) {
            parsed[i] = PedersenStrict.readScalar(encoded, 1 + i * PedersenStrict.SCALAR_BYTES);
        }
        BigInteger blinding = PedersenStrict.readScalar(encoded, 1 + dimension * PedersenStrict.SCALAR_BYTES);
        PedersenVectorBoundPolicy.CheckedOpening checked = policy.requireOpening(List.of(parsed), blinding);
        return new PedersenVectorOpening(policy, checked.values(), checked.blinding());
    }

    /** A fresh {@code 33 + 32·n}-octet encoding; the caller should wipe it after use. */
    public byte[] encode() {
        byte[] out = new byte[encodedLength(values.size())];
        out[0] = (byte) values.size();
        for (int i = 0; i < values.size(); i++) {
            PedersenStrict.writeScalar(values.get(i), out, 1 + i * PedersenStrict.SCALAR_BYTES);
        }
        PedersenStrict.writeScalar(blinding, out, 1 + values.size() * PedersenStrict.SCALAR_BYTES);
        return out;
    }

    /**
     * The component values: an unmodifiable snapshot taken at construction, so no caller can change
     * it (the spec's "copy" requirement, without a per-call copy).
     */
    public List<BigInteger> values() {
        return values;
    }

    /** The blinding {@code r ∈ [0, l)}. */
    public BigInteger blinding() {
        return blinding;
    }

    /** The bound policy (and schema) this opening was checked under. */
    public PedersenVectorBoundPolicy policy() {
        return policy;
    }

    @Override
    public String toString() {
        return "PedersenVectorOpening[" + policy.schema().id() + ", redacted]";
    }

    private static int encodedLength(int dimension) {
        return 1 + (dimension + 1) * PedersenStrict.SCALAR_BYTES;
    }
}
