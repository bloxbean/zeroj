package org.zeroj.api.commitment;

import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The descriptor of one commitment profile ({@code commitment-profiles-v1} §12.1).
 *
 * <p>Each profile has exactly one descriptor, held as a public constant by its profile module.
 * {@link #define} refuses an identifier that was already defined through this loaded class, so two
 * copies of a profile module sharing one {@code zeroj-api} fail at class initialization, which is
 * fail-closed. <b>Descriptors compare by identity</b>: every check uses {@code ==}, never
 * {@code equals}.
 *
 * <p>The descriptor is configuration, not provenance. The cryptographic definition of a profile
 * lives in its specification; this type carries only what the shared contracts need.
 */
public final class CommitmentProfile {

    static final int MAX_POINT_ENCODING_LENGTH = 255;

    // Scope: this class's defining class loader (spec §12.1).
    private static final Set<CommitmentProfileId> DEFINED = ConcurrentHashMap.newKeySet();

    private final CommitmentProfileId id;
    private final CommitmentKind kind;
    private final CommitmentGroup group;
    private final int pointEncodingLength;

    private CommitmentProfile(CommitmentProfileId id, CommitmentKind kind, CommitmentGroup group,
                              int pointEncodingLength) {
        this.id = id;
        this.kind = kind;
        this.group = group;
        this.pointEncodingLength = pointEncodingLength;
    }

    /**
     * Defines the descriptor of a profile. Called once per profile, by the profile module.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException ({@code INVALID_CONFIGURATION}) if
     *                                   {@code pointEncodingLength} is not in {@code [1, 255]} or
     *                                   {@code id} is already defined
     */
    public static CommitmentProfile define(CommitmentProfileId id, CommitmentKind kind, CommitmentGroup group,
                                           int pointEncodingLength) {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(group, "group");
        if (pointEncodingLength < 1 || pointEncodingLength > MAX_POINT_ENCODING_LENGTH) {
            throw new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION,
                    "point encoding length must be in [1, " + MAX_POINT_ENCODING_LENGTH + "]");
        }
        // Registered only after every other check, so a rejected definition reserves nothing.
        if (!DEFINED.add(id)) {
            throw new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION,
                    "commitment profile " + id + " is already defined");
        }
        return new CommitmentProfile(id, kind, group, pointEncodingLength);
    }

    /** The profile identifier. */
    public CommitmentProfileId id() {
        return id;
    }

    /** What the profile's commitments open to. */
    public CommitmentKind kind() {
        return kind;
    }

    /** The group the profile works in. */
    public CommitmentGroup group() {
        return group;
    }

    /** The exact length in octets of the profile's raw point encoding. */
    public int pointEncodingLength() {
        return pointEncodingLength;
    }

    @Override
    public String toString() {
        return "CommitmentProfile[" + id + ", " + kind + ", " + group + ", " + pointEncodingLength + "]";
    }
}
