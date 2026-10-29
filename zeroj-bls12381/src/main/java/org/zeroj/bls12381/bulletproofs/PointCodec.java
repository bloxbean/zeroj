package org.zeroj.bls12381.bulletproofs;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * The {@code sigma-proofs_Shake128_BLS12381} group and scalar codecs (sigma-03 §8.2; spec
 * {@code bulletproof-range-bls12-381-g1-v1} §3), and the bridge from a G1 Pedersen commitment to its
 * point. No message ever contains a scalar value.
 */
final class PointCodec {

    /** {@code Ne}: octets of a compressed G1 point. */
    static final int POINT_BYTES = Bls12381Codecs.G1_COMPRESSED_BYTES;

    /** {@code Ns}: octets of a serialized scalar. */
    static final int SCALAR_BYTES = 32;

    /** The order {@code q} of the prime-order subgroup and of the scalar field. */
    static final BigInteger Q = G1Point.R;

    private PointCodec() {
    }

    /**
     * The group-element deserializer of spec §3: the strict decoder of
     * {@code pedersen-bls12-381-g1-v1.md} §4 in its order (length, flags, the exact infinity form,
     * {@code x < P_381}, on the curve → {@code MALFORMED_ENCODING}; outside the prime-order subgroup →
     * {@code NOT_IN_SUBGROUP}), then the identity is rejected ({@code MALFORMED_ENCODING}, sigma-03
     * §8.2.1). Never cofactor-clears.
     */
    static G1Point decode(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        G1Point point;
        try {
            point = Bls12381Codecs.g1FromCompressedUnchecked(encoded);
        } catch (IllegalArgumentException e) {
            // The codec's messages describe only the public encoding.
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING, e.getMessage());
        }
        if (!point.isInSubgroup()) {
            throw new CommitmentFormatException(CommitmentError.NOT_IN_SUBGROUP,
                    "G1 point is not in the prime-order subgroup");
        }
        if (point.isInfinity()) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "the identity is not a valid proof element");
        }
        return point;
    }

    /** {@code compress(P)} for {@code P ≠ O}; a caller bug ({@link IllegalStateException}) otherwise. */
    static byte[] encode(G1Point point) {
        if (point.isInfinity()) {
            throw new IllegalStateException("the identity is never serialized as a proof element");
        }
        return Bls12381Codecs.g1ToCompressed(point);
    }

    /** {@code I2OSP(s, 32)} of {@code 0 ≤ s < q}, written into {@code out} at {@code offset}. */
    static void writeScalar(BigInteger s, byte[] out, int offset) {
        if (s.signum() < 0 || s.compareTo(Q) >= 0) {
            throw new IllegalStateException("a non-canonical scalar reached serialization");
        }
        byte[] raw = s.toByteArray();
        try {
            int skip = raw.length > SCALAR_BYTES ? raw.length - SCALAR_BYTES : 0;
            int length = raw.length - skip;
            Arrays.fill(out, offset, offset + SCALAR_BYTES, (byte) 0);
            System.arraycopy(raw, skip, out, offset + SCALAR_BYTES - length, length);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    /** {@code OS2IP} of 32 octets at {@code offset}; {@code NON_CANONICAL_SCALAR} unless below {@code q}. */
    static BigInteger readScalar(byte[] in, int offset) {
        BigInteger s = new BigInteger(1, in, offset, SCALAR_BYTES);
        if (s.compareTo(Q) >= 0) {
            throw new CommitmentFormatException(CommitmentError.NON_CANONICAL_SCALAR, "proof scalar must be in [0, q)");
        }
        return s;
    }

    /**
     * The point of a commitment. A {@link G1PedersenCommitment} is a validated element of the
     * prime-order subgroup by construction (it is produced only by the strict decoder or by group
     * operations on such elements), so its canonical encoding is decompressed without repeating the
     * subgroup check (spec §8.1 step 4). The identity is returned as is; the caller decides.
     */
    static G1Point point(G1PedersenCommitment commitment) {
        byte[] encoding = commitment.toPointBytes();
        try {
            return Bls12381Codecs.g1FromCompressedUnchecked(encoding);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("a G1 Pedersen commitment has a malformed encoding", e);
        }
    }
}
