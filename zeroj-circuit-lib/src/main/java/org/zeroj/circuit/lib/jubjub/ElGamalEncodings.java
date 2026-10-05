package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.BASE_FIELD_PRIME;
import static org.zeroj.circuit.lib.jubjub.JubjubCurve.COMPRESSED_POINT_BYTES;

/** Decoding and validation rules of {@code elgamal-jubjub-v1} §7, shared by the host types. */
final class ElGamalEncodings {

    static final int CIPHERTEXT_BYTES = 2 * COMPRESSED_POINT_BYTES;

    private ElGamalEncodings() {}

    /**
     * Decodes one point of a ciphertext or share (§7.1, §7.2): canonical encoding and
     * prime-order subgroup membership. The identity is accepted.
     */
    static JubjubPoint decodeSubgroupPoint(byte[] encoded, int offset, String what) {
        byte[] slice = Arrays.copyOfRange(encoded, offset, offset + COMPRESSED_POINT_BYTES);
        JubjubPoint point = JubjubPoint.fromBytes(slice);
        return requireSubgroup(point, what);
    }

    /** Decodes a 32-byte point (§7.1) and requires subgroup membership. */
    static JubjubPoint decodeSubgroupPoint(byte[] encoded, String what) {
        Objects.requireNonNull(encoded, what);
        if (encoded.length != COMPRESSED_POINT_BYTES) {
            throw new IllegalArgumentException(
                    what + " must be " + COMPRESSED_POINT_BYTES + " bytes, got " + encoded.length);
        }
        return requireSubgroup(JubjubPoint.fromBytes(encoded), what);
    }

    /** A key point (§3.1, §7.3): in the subgroup and not the identity. */
    static JubjubPoint requireKeyPoint(JubjubPoint point, String what) {
        requireSubgroup(point, what);
        if (point.isIdentity()) {
            throw new IllegalArgumentException(what + " must not be the identity");
        }
        return point.normalized();
    }

    static JubjubPoint requireSubgroup(JubjubPoint point, String what) {
        Objects.requireNonNull(point, what);
        if (!FastJubjubPoint.isInPrimeOrderSubgroup(point)) {
            throw new IllegalArgumentException(what + " is not in the prime-order subgroup");
        }
        return point.normalized();
    }

    /**
     * A point given as affine integers (§7.4): each coordinate canonical in {@code [0, p)}
     * without reduction, on the curve, and in the subgroup.
     */
    static JubjubPoint affineSubgroupPoint(BigInteger u, BigInteger v, String what) {
        Objects.requireNonNull(u, what + ".u");
        Objects.requireNonNull(v, what + ".v");
        if (u.signum() < 0 || u.compareTo(BASE_FIELD_PRIME) >= 0
                || v.signum() < 0 || v.compareTo(BASE_FIELD_PRIME) >= 0) {
            throw new IllegalArgumentException(what + " coordinates must be canonical, in [0, p)");
        }
        return requireSubgroup(JubjubPoint.fromAffine(u, v), what);
    }

    /** Affine public inputs of points, in the given order (§8). */
    static List<BigInteger> affine(JubjubPoint... points) {
        BigInteger[] out = new BigInteger[points.length * 2];
        for (int i = 0; i < points.length; i++) {
            JubjubPoint n = points[i].normalized();
            out[2 * i] = n.u();
            out[2 * i + 1] = n.v();
        }
        return List.of(out);
    }
}
