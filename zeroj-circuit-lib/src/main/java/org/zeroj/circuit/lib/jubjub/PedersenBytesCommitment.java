package org.zeroj.circuit.lib.jubjub;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A Jubjub Pedersen commitment to an exact octet string, profile {@code pedersen-jubjub-bytes-v1}
 * ({@code docs/specs/pedersen-jubjub-bytes-v1.md}, ADR-0058):
 * {@code C = [HashBytesToScalar(B)]·G + [r]·H}.
 *
 * <p>Created by {@link PedersenCommitment#commitBytes(byte[], java.math.BigInteger)} and its
 * stream variants, or decoded from a received point with {@link #decode(byte[])}. An instance
 * holds only the validated, normalized point: never the payload, the derived scalar or the
 * blinding. It offers no addition, subtraction or balance arithmetic, because sums relate only the
 * derived scalars modulo {@code l}, not the payloads.
 *
 * <p><b>The type is not provenance.</b> The point is an ordinary commitment under the numeric
 * profile's bases, so whoever knows a byte opening {@code (B, r)} also knows the numeric opening
 * {@code (s, r)}. The wire encoding is just the 32-byte point. A verifier selects this profile
 * from trusted configuration and, when issuance context matters, authenticates the association of
 * point, profile and context separately (spec §8).
 */
public final class PedersenBytesCommitment {

    /** The profile identifier. Metadata for configuration and documentation; never serialized. */
    public static final String PROFILE_ID = "pedersen-jubjub-bytes-v1";

    private final JubjubPoint point;
    private final byte[] encoding;

    PedersenBytesCommitment(JubjubPoint point) {
        this.point = point.normalized();
        this.encoding = this.point.toBytes();
    }

    /**
     * Decodes a byte commitment received from another party: exactly the rules of
     * {@link PedersenCommitment#decode(byte[])} (canonical ZIP 216 encoding and prime-order
     * subgroup membership; identity accepted as a point). Small-order, mixed-order and off-curve
     * points are rejected, never cofactor-cleared. Decoding does not accept any opening and does
     * not authenticate the profile.
     *
     * @param pointBytes the 32-byte point encoding
     * @throws IllegalArgumentException if the bytes are not a canonical subgroup point
     */
    public static PedersenBytesCommitment decode(byte[] pointBytes) {
        Objects.requireNonNull(pointBytes, "pointBytes");
        return new PedersenBytesCommitment(PedersenCommitment.decode(pointBytes));
    }

    /** Returns {@link #PROFILE_ID}. */
    public String profileId() {
        return PROFILE_ID;
    }

    /** Returns a fresh copy of the 32-byte point encoding: the complete wire format of this profile. */
    public byte[] toPointBytes() {
        return encoding.clone();
    }

    JubjubPoint point() {
        return point;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PedersenBytesCommitment that && Arrays.equals(encoding, that.encoding);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoding);
    }

    @Override
    public String toString() {
        return "PedersenBytesCommitment[" + PROFILE_ID + ", " + HexFormat.of().formatHex(encoding) + "]";
    }
}
