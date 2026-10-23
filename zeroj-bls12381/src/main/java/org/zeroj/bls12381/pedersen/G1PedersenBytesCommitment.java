package org.zeroj.bls12381.pedersen;

import org.zeroj.api.commitment.Commitment;
import org.zeroj.api.commitment.CommitmentCodec;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.CommitmentProfile;
import org.zeroj.api.commitment.CommitmentProfiles;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * A G1 Pedersen commitment to an exact octet string, profile {@code pedersen-bls12-381-g1-bytes-v1}
 * ({@code docs/specs/pedersen-bls12-381-g1-v1.md} §3.2, ADR-0060):
 * {@code C = [HashBytesToScalarG1(B)]·G + [r]·H}.
 *
 * <p>Created by {@link G1Pedersen#commitBytes(byte[], java.math.BigInteger)} and its stream
 * variants, or decoded from a received point with {@link #decode(byte[])}. An instance holds only
 * the validated point and its encoding: never the payload, the derived scalar or the blinding. It
 * has no arithmetic, because sums relate only the derived scalars modulo {@code q}, not payloads.
 *
 * <p><b>The type is not provenance.</b> The point is an ordinary commitment under the scalar
 * profile's bases, so whoever knows a byte opening {@code (B, r)} also knows the scalar opening
 * {@code (s, r)}. A verifier selects this profile from trusted configuration (spec §3).
 */
public final class G1PedersenBytesCommitment implements Commitment {

    /**
     * The {@code pedersen-bls12-381-g1-bytes-v1} descriptor,
     * {@link CommitmentProfiles#PEDERSEN_BLS12_381_G1_BYTES_V1}. Compare with {@code ==}.
     */
    public static final CommitmentProfile PROFILE = CommitmentProfiles.PEDERSEN_BLS12_381_G1_BYTES_V1;

    /** The {@code pedersen-bls12-381-g1-bytes-v1} codec: strict point decoding (spec §4), no context. */
    public static final CommitmentCodec<G1PedersenBytesCommitment> CODEC = new Codec();

    private final G1Point point;
    private final byte[] encoding;

    G1PedersenBytesCommitment(G1Point point) {
        this.point = point;
        this.encoding = Bls12381Codecs.g1ToCompressed(point);
    }

    /**
     * Decodes a byte commitment received from another party with the strict decoder of spec §4
     * (identity accepted). Decoding accepts no opening and does not authenticate the profile.
     *
     * @throws NullPointerException      if {@code pointBytes} is null
     * @throws CommitmentFormatException {@code MALFORMED_ENCODING} or {@code NOT_IN_SUBGROUP}
     */
    public static G1PedersenBytesCommitment decode(byte[] pointBytes) {
        return new G1PedersenBytesCommitment(G1PedersenStrict.decodePoint(pointBytes));
    }

    @Override
    public CommitmentProfile profile() {
        return PROFILE;
    }

    /** A fresh copy of the 48-octet compressed point encoding: the complete wire format. */
    @Override
    public byte[] toPointBytes() {
        return encoding.clone();
    }

    G1Point point() {
        return point;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof G1PedersenBytesCommitment that && Arrays.equals(encoding, that.encoding);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoding);
    }

    @Override
    public String toString() {
        return "G1PedersenBytesCommitment[" + PROFILE.id() + ", " + HexFormat.of().formatHex(encoding) + "]";
    }

    private static final class Codec implements CommitmentCodec<G1PedersenBytesCommitment> {
        @Override
        public CommitmentProfile profile() {
            return PROFILE;
        }

        @Override
        public Class<G1PedersenBytesCommitment> commitmentType() {
            return G1PedersenBytesCommitment.class;
        }

        @Override
        public G1PedersenBytesCommitment decodePoint(byte[] pointBytes) {
            return decode(pointBytes);
        }
    }
}
