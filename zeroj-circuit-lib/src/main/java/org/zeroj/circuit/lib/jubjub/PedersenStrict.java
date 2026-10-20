package org.zeroj.circuit.lib.jubjub;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/**
 * Shared checks and encodings of the strict Pedersen paths ({@code commitment-profiles-v1} §7,
 * §8, §10). Package-private. No message ever contains a scalar value.
 */
final class PedersenStrict {

    /** Octets of one {@code I2OSP(x, 32)} scalar. */
    static final int SCALAR_BYTES = 32;

    private PedersenStrict() {
    }

    /**
     * Check 1: {@code x ∈ [0, l)}, else {@code NON_CANONICAL_SCALAR}. Never reduces. Returns the
     * value to use from here on: {@code x} itself, or a plain {@link BigInteger} copy if {@code x} is
     * a subclass. The guarantee is consistency: the value checked is exactly the value used. (A
     * subclass that overrides {@code bitLength} also controls what {@code toByteArray} returns, so
     * no copy can recover a "true" value from a hostile subclass; the copy is what is checked.)
     */
    static BigInteger canonical(BigInteger x, String name) {
        BigInteger value = trusted(x);
        if (value.signum() < 0 || value.compareTo(JubjubCurve.SUBGROUP_ORDER) >= 0) {
            // Never echo the value: it is secret.
            throw new CommitmentFormatException(CommitmentError.NON_CANONICAL_SCALAR, name + " must be in [0, l)");
        }
        return value;
    }

    /**
     * {@code x} if it is exactly a {@link BigInteger}, else a plain copy of its value. The
     * intermediate octets of a copy are wiped (the value may be secret).
     */
    static BigInteger trusted(BigInteger x) {
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
     * Elements a vector snapshot reads at most: one past the largest schema dimension, so a longer
     * list still fails the dimension check ({@code commitment-profiles-v1} §12.3).
     */
    static final int MAX_SNAPSHOT = PedersenVectorBases.MAX_DIMENSION + 1;

    /**
     * An unmodifiable snapshot of the first {@code min(size, }{@value #MAX_SNAPSHOT}{@code )} elements
     * of {@code values}, in index order, each {@link #trusted}; a null among them is rejected. Work and
     * memory are bounded by {@value #MAX_SNAPSHOT} elements whatever the list's size; a list longer than
     * that yields a snapshot of exactly {@value #MAX_SNAPSHOT} elements, which no schema dimension
     * matches. Callers use only the snapshot, never {@code values} again.
     */
    static List<BigInteger> trustedSnapshot(List<BigInteger> values) {
        BigInteger[] copy = new BigInteger[MAX_SNAPSHOT];
        int count = 0;
        for (Iterator<BigInteger> it = values.iterator(); count < MAX_SNAPSHOT && it.hasNext(); count++) {
            copy[count] = trusted(Objects.requireNonNull(it.next(), "values element"));
        }
        return List.of(Arrays.copyOf(copy, count));
    }

    /**
     * {@code I2OSP(x, 32)} of a checked value {@code 0 ≤ x < 2^256} (a canonical scalar or a schema
     * digest), written into {@code out} at {@code offset}.
     */
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
     * The strict point decoder of spec §10: null → {@link NullPointerException}; an encoding the
     * profile spec rejects (wrong length, {@code v ≥ p}, off-curve, either {@code u = 0} sign alias)
     * → {@code MALFORMED_ENCODING}; a curve point outside the prime-order subgroup →
     * {@code NOT_IN_SUBGROUP}. Never cofactor-clears; the identity is accepted.
     */
    static JubjubPoint decodePoint(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        JubjubPoint point;
        try {
            point = JubjubPoint.fromBytes(encoded);
        } catch (IllegalArgumentException e) {
            // fromBytes messages describe only the public encoding.
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING, e.getMessage());
        }
        if (!point.isInSubgroup()) {
            throw new CommitmentFormatException(CommitmentError.NOT_IN_SUBGROUP,
                    "Pedersen commitment is not in the prime-order subgroup");
        }
        return point;
    }
}
