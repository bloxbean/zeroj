package org.zeroj.api.commitment;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A safe in-memory key for a commitment ({@code commitment-profiles-v1} §12.1): the profile
 * identifier, the raw point and the codec's context (the schema digest for vectors).
 *
 * <p>Use it instead of a commitment's own {@code equals} in maps and sets. Profiles that share a
 * basis set produce the same points, and vector commitments of different schemas can share a
 * point, so a key over the point alone would conflate them. A key has no serialized form.
 */
public final class CommitmentKey {

    private final byte[] id;
    private final byte[] point;
    private final byte[] context;

    private CommitmentKey(byte[] id, byte[] point, byte[] context) {
        this.id = id;
        this.point = point;
        this.context = context;
    }

    /**
     * Builds the key of {@code commitment} under the expected codec.
     *
     * <p>Checks, in order: the commitment's concrete class is exactly
     * {@link CommitmentCodec#commitmentType()} (before any method of the commitment is called);
     * its descriptor is the codec's ({@code ==}); the codec's context check.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException ({@code PROFILE_MISMATCH}) if a check fails, or
     *                                   ({@code MALFORMED_ENCODING}) if the point encoding has the
     *                                   wrong length for the profile
     */
    public static CommitmentKey of(Commitment commitment, CommitmentCodec<?> expected) {
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(expected, "expected");
        Commitment checked = requireExpected(commitment, expected);
        CommitmentProfile profile = expected.profile();
        return new CommitmentKey(profile.id().toAsciiBytes(), pointBytes(checked, profile),
                Objects.requireNonNull(expected.keyContext(), "keyContext").clone());
    }

    /**
     * The exact-class, descriptor-identity and context checks shared by {@link #of} and envelope
     * decoding step 6. The generic parameter captures the codec's type, so {@code requireContext}
     * can be called through a {@code CommitmentCodec<?>}.
     */
    static <C extends Commitment> C requireExpected(Commitment commitment, CommitmentCodec<C> expected) {
        Class<C> type = expected.commitmentType();
        // getClass() is final on Object, so this runs no code of the (possibly foreign) commitment.
        if (type == null || commitment.getClass() != type) {
            throw new CommitmentFormatException(CommitmentError.PROFILE_MISMATCH,
                    "commitment class is not the expected profile's commitment type");
        }
        C typed = type.cast(commitment);
        CommitmentProfile profile = Objects.requireNonNull(expected.profile(), "profile");
        if (typed.profile() != profile) {
            throw new CommitmentFormatException(CommitmentError.PROFILE_MISMATCH,
                    "commitment profile is not " + profile.id());
        }
        expected.requireContext(typed);
        return typed;
    }

    /** The commitment's point encoding, checked against the profile's length. */
    static byte[] pointBytes(Commitment commitment, CommitmentProfile profile) {
        byte[] point = Objects.requireNonNull(commitment.toPointBytes(), "toPointBytes");
        if (point.length != profile.pointEncodingLength()) {
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "point encoding of " + profile.id() + " must be " + profile.pointEncodingLength() + " octets");
        }
        return point;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof CommitmentKey that
                && Arrays.equals(id, that.id)
                && Arrays.equals(point, that.point)
                && Arrays.equals(context, that.context);
    }

    @Override
    public int hashCode() {
        return 31 * (31 * Arrays.hashCode(id) + Arrays.hashCode(point)) + Arrays.hashCode(context);
    }

    @Override
    public String toString() {
        HexFormat hex = HexFormat.of();
        return "CommitmentKey[" + new String(id, StandardCharsets.US_ASCII) + ", "
                + hex.formatHex(point) + (context.length == 0 ? "" : ", " + hex.formatHex(context)) + "]";
    }
}
