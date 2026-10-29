package org.zeroj.bls12381.pedersen;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Shared checks and encodings of the strict G1 Pedersen paths ({@code pedersen-bls12-381-g1-v1}
 * §4, §6, §7). Package-private. No message ever contains a scalar value.
 */
final class G1PedersenStrict {

    /** The order {@code q} of the prime-order subgroup of G1 (spec §1). Never the Jubjub order. */
    static final BigInteger Q = G1Point.R;

    /** Octets of one {@code I2OSP(x, 32)} scalar. */
    static final int SCALAR_BYTES = 32;

    /** Octets of a compressed point (spec §4). */
    static final int POINT_BYTES = Bls12381Codecs.G1_COMPRESSED_BYTES;

    /** Largest amount-bound width: {@code ⌊log₂ q⌋ = 254} (spec §6.3). */
    static final int MAX_BITS = Q.bitLength() - 1;

    /**
     * Largest delta-bound width, 253 (spec §6.4): the signed range {@code (−2^k, 2^k)} holds
     * {@code 2^{k+1} − 1} integers, at most {@code q} only for {@code k ≤ 253}, so a bounded delta is
     * unique mod {@code q}. At 254 both {@code δ} and {@code δ − q} would pass for some {@code δ}.
     */
    static final int MAX_DELTA_BITS = Q.bitLength() - 2;

    private G1PedersenStrict() {
    }

    /**
     * {@code x} if it is exactly a {@link BigInteger}, else a plain copy of its value (spec §7, the
     * scalar snapshot). The intermediate octets of a copy are wiped (the value may be secret).
     * Every later check and use reads only the returned value.
     */
    static BigInteger snapshot(BigInteger x) {
        if (x.getClass() == BigInteger.class) {
            return x;
        }
        byte[] raw = x.toByteArray();
        try {
            return new BigInteger(raw);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    /**
     * Check 1 on a snapshot: {@code x ∈ [0, q)}, else {@code NON_CANONICAL_SCALAR}. Never reduces.
     */
    static BigInteger requireCanonical(BigInteger snapshot, String name) {
        if (snapshot.signum() < 0 || snapshot.compareTo(Q) >= 0) {
            // Never echo the value: it is secret.
            throw new CommitmentFormatException(CommitmentError.NON_CANONICAL_SCALAR, name + " must be in [0, q)");
        }
        return snapshot;
    }

    /** {@link #snapshot} then {@link #requireCanonical}: the order of the single-scalar paths. */
    static BigInteger canonical(BigInteger x, String name) {
        return requireCanonical(snapshot(x), name);
    }

    /**
     * {@code [x]·base} with the public, variable-time multiplication, for a value that is already
     * canonical. A value outside {@code [0, q)} here is a bug in the caller, never an input error:
     * no negative or out-of-range integer reaches a multiplication (ADR-0060 I3).
     */
    static G1Point publicMul(G1Point base, BigInteger canonical) {
        return base.scalarMul(requireMultipliable(canonical));
    }

    /** {@code x} if it is in {@code [0, q)}; otherwise a caller bug ({@link IllegalStateException}). */
    static BigInteger requireMultipliable(BigInteger x) {
        if (x.signum() < 0 || x.compareTo(Q) >= 0) {
            // Never echo the value: it may be secret.
            throw new IllegalStateException("a non-canonical scalar reached a G1 multiplication");
        }
        return x;
    }

    /** A width {@code k ∈ [1, max]}, else {@code INVALID_CONFIGURATION}. */
    static void requireBits(int bits, int max, String name) {
        if (bits < 1 || bits > max) {
            throw new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION,
                    name + " must be in [1, " + max + "]");
        }
    }

    /** {@code I2OSP(x, 32)} of a checked value {@code 0 ≤ x < q}, written into {@code out} at {@code offset}. */
    static void writeScalar(BigInteger x, byte[] out, int offset) {
        if (x.signum() < 0 || x.bitLength() > 8 * SCALAR_BYTES) {
            throw new IllegalStateException("I2OSP(x, 32) is undefined for this value");
        }
        byte[] raw = x.toByteArray();
        try {
            // Below 2^256: raw is at most 32 octets, or 33 with a leading sign octet.
            int skip = raw.length > SCALAR_BYTES ? raw.length - SCALAR_BYTES : 0;
            int length = raw.length - skip;
            System.arraycopy(raw, skip, out, offset + SCALAR_BYTES - length, length);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    /** {@code OS2IP} of 32 octets at {@code offset}. */
    static BigInteger readScalar(byte[] in, int offset) {
        return new BigInteger(1, in, offset, SCALAR_BYTES);
    }

    /**
     * The strict point decoder of spec §4, steps 1–7 in order: null →
     * {@link NullPointerException}; wrong length, compression flag clear, an infinity encoding
     * other than exactly {@code 0xC0 ‖ 0^47}, {@code x ≥ P_381}, or {@code x³ + 4} not a square →
     * {@code MALFORMED_ENCODING}; a curve point outside the prime-order subgroup →
     * {@code NOT_IN_SUBGROUP}. The identity returns at step 4. Never cofactor-clears.
     */
    static G1Point decodePoint(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        G1Point point;
        try {
            // Steps 2-6 (length, compression flag, infinity form, x range, square root), in order.
            point = Bls12381Codecs.g1FromCompressedUnchecked(encoded);
        } catch (IllegalArgumentException e) {
            // The codec's messages describe only the public encoding.
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING, e.getMessage());
        }
        // Step 7. The identity, returned at step 4, is in the subgroup.
        if (!point.isInSubgroup()) {
            throw new CommitmentFormatException(CommitmentError.NOT_IN_SUBGROUP,
                    "G1 Pedersen commitment is not in the prime-order subgroup");
        }
        return point;
    }
}
