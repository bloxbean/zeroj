package org.zeroj.bls12381.pedersen;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;

import java.math.BigInteger;
import java.util.Objects;

/**
 * The canonical blinding encoding {@code I2OSP(r, 32)} of a {@code pedersen-bls12-381-g1-bytes-v1}
 * opening ({@code pedersen-bls12-381-g1-v1} §6.2). The payload travels separately, as its exact
 * octets.
 *
 * <p><b>Secret.</b> {@code r} is secret until disclosed. {@link BigInteger} values cannot be wiped
 * from memory; the caller owns and should wipe the arrays this class returns and reads.
 */
public final class G1PedersenBlinding {

    private G1PedersenBlinding() {
    }

    /**
     * Checks, in order: null; one snapshot; {@code r ∈ [0, q)}.
     *
     * @throws NullPointerException      if {@code blinding} is null
     * @throws CommitmentFormatException ({@code NON_CANONICAL_SCALAR}) if it is not in {@code [0, q)}
     */
    public static byte[] encode(BigInteger blinding) {
        Objects.requireNonNull(blinding, "blinding");
        BigInteger r = G1PedersenStrict.canonical(blinding, "blinding");
        byte[] out = new byte[G1PedersenStrict.SCALAR_BYTES];
        G1PedersenStrict.writeScalar(r, out, 0);
        return out;
    }

    /**
     * A length other than 32 is {@code MALFORMED_ENCODING}; {@code r ≥ q} is
     * {@code NON_CANONICAL_SCALAR}.
     *
     * @throws NullPointerException      if {@code encoded} is null
     * @throws CommitmentFormatException with the class of the first failure
     */
    public static BigInteger decode(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length != G1PedersenStrict.SCALAR_BYTES) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "a blinding is " + G1PedersenStrict.SCALAR_BYTES + " octets");
        }
        return G1PedersenStrict.requireCanonical(G1PedersenStrict.readScalar(encoded, 0), "blinding");
    }
}
