package org.zeroj.api.commitment;

import java.util.Arrays;
import java.util.Objects;

/**
 * Envelope v1 ({@code commitment-profiles-v1} §9): an off-chain container for one commitment,
 * {@code 0x01 ‖ u8(len(id)) ‖ ASCII(id) ‖ point}.
 *
 * <p>An envelope is never used in datums, redeemers or circuit public inputs, which carry the
 * profile's raw point. It prevents accidental mix-ups and makes stored data self-describing; it is
 * <b>not authentication</b>. There is no decoder that selects a profile from the embedded
 * identifier: the caller supplies the expected codec from its own configuration.
 */
public final class CommitmentEnvelope {

    /** The envelope format version octet. */
    static final byte VERSION = 0x01;

    private CommitmentEnvelope() {
    }

    /**
     * Writes the commitment's own profile identifier and raw point. Producer side: the input is
     * trusted, apart from a check that the point has its profile's length.
     *
     * @throws NullPointerException      if {@code commitment} is null
     * @throws CommitmentFormatException ({@code MALFORMED_ENCODING}) if the point encoding has the
     *                                   wrong length for the profile
     */
    public static byte[] encode(Commitment commitment) {
        Objects.requireNonNull(commitment, "commitment");
        CommitmentProfile profile = Objects.requireNonNull(commitment.profile(), "profile");
        byte[] id = profile.id().toAsciiBytes();
        byte[] point = CommitmentKey.pointBytes(commitment, profile);
        byte[] out = new byte[2 + id.length + point.length];
        out[0] = VERSION;
        out[1] = (byte) id.length;
        System.arraycopy(id, 0, out, 2, id.length);
        System.arraycopy(point, 0, out, 2 + id.length, point.length);
        return out;
    }

    /**
     * Decodes an envelope under the expected profile, in the order of spec §9:
     * <ol>
     *   <li>length {@code < 2} or version other than {@code 0x01} → {@code MALFORMED_ENCODING};</li>
     *   <li>{@code 2 + len(id)} greater than the length → {@code MALFORMED_ENCODING};</li>
     *   <li>identifier octets not identical to the expected one → {@code PROFILE_MISMATCH};</li>
     *   <li>remaining length other than the point-encoding length → {@code MALFORMED_ENCODING};</li>
     *   <li>the codec's strict point decoder → {@code MALFORMED_ENCODING} or
     *       {@code NOT_IN_SUBGROUP};</li>
     *   <li>the decoded object's class, descriptor and context, as in {@link CommitmentKey#of} →
     *       {@code PROFILE_MISMATCH}.</li>
     * </ol>
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException with the class of the first failing step
     */
    public static <C extends Commitment> C decode(byte[] envelope, CommitmentCodec<C> expected) {
        Objects.requireNonNull(envelope, "envelope");
        Objects.requireNonNull(expected, "expected");
        CommitmentProfile profile = Objects.requireNonNull(expected.profile(), "profile");
        if (envelope.length < 2 || envelope[0] != VERSION) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "not a version 1 commitment envelope");
        }
        int idLength = envelope[1] & 0xFF;
        if (2 + idLength > envelope.length) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "truncated commitment envelope identifier");
        }
        byte[] expectedId = profile.id().toAsciiBytes();
        if (!Arrays.equals(envelope, 2, 2 + idLength, expectedId, 0, expectedId.length)) {
            throw new CommitmentFormatException(CommitmentError.PROFILE_MISMATCH,
                    "envelope identifier is not " + profile.id());
        }
        int pointOffset = 2 + idLength;
        if (envelope.length - pointOffset != profile.pointEncodingLength()) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "envelope point must be " + profile.pointEncodingLength() + " octets");
        }
        C decoded = Objects.requireNonNull(
                expected.decodePoint(Arrays.copyOfRange(envelope, pointOffset, envelope.length)), "decodePoint");
        return CommitmentKey.requireExpected(decoded, expected);
    }
}
