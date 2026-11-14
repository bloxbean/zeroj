package org.zeroj.api.commitment;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The descriptor of one commitment profile ({@code commitment-profiles-v1} §12.1).
 *
 * <p>Each profile has exactly one descriptor per loaded copy of this class. The descriptors of the
 * built-in ZeroJ profiles are created and registered while this class is initialised, before any
 * caller can reach {@link #define}, and are published as {@link CommitmentProfiles} constants
 * (ADR-0060 D8). {@link #define} refuses an identifier that is already defined through this loaded
 * class, built-in or not, so no caller of this API can pre-empt a built-in profile, and two
 * definitions of one identifier never coexist. It also refuses every other identifier the registry
 * already uses (basis sets, proof protocols and generator sets) and every reserved document name
 * ({@code commitment-profiles-v1} §2.2): this class's own initialisation seeds them, so the
 * built-in proof protocols ({@link ProofProtocols}) cannot be pre-empted either (ADR-0061 D7a). (In-process reflection can bypass any Java access
 * rule and is outside this guarantee.) <b>Descriptors compare by identity</b>: every check uses
 * {@code ==}, never {@code equals}.
 *
 * <p>The descriptor is configuration, not provenance. The cryptographic definition of a profile
 * lives in its specification; this type carries only what the shared contracts need.
 */
public final class CommitmentProfile {

    static final int MAX_POINT_ENCODING_LENGTH = 255;

    /**
     * The registry identifiers that are not commitment profiles, and the reserved document names
     * (spec §2.2, §2.3). {@code ReservedIdentifiersTest} checks this set, with the built-in profiles,
     * against the registry document.
     */
    static final Set<CommitmentProfileId> RESERVED = reserved(
            // Basis sets (§3).
            "pedersen-jubjub-basis-v1",
            "pedersen-jubjub-vector-basis-v1",
            "pedersen-bls12-381-g1-basis-v1",
            "bulletproof-bls12-381-g1-gens-v1",
            // Proof protocols (§5).
            "bulletproof-range-bls12-381-g1-v1",
            // Reserved document names (§2.2).
            "commitment-profiles-v1",
            "zeroj-commitment-vectors-v1",
            "zeroj-proof-vectors-v1",
            "confidential-note-jubjub-v1",
            "elgamal-jubjub-v1",
            "elgamal-jubjub-threshold-v1",
            "dkg-share-delivery-hpke-v1",
            "jubjub-eddsa-v1",
            "jubjub-eddsa-hedged-v1");

    // Scope: this class's defining class loader (spec §12.1). Declared before the built-ins, which
    // register themselves in it during class initialisation; seeded with RESERVED first, so no
    // define can take a reserved identifier.
    private static final Set<CommitmentProfileId> DEFINED = seeded(RESERVED);

    // Built-in descriptors (ADR-0060 D8), published through CommitmentProfiles. Point lengths are the
    // compressed encodings: Jubjub 32 octets, BLS12-381 G1 48 octets.
    static final CommitmentProfile PEDERSEN_JUBJUB_V1 =
            builtIn("pedersen-jubjub-v1", CommitmentKind.SCALAR, CommitmentGroup.JUBJUB, 32);
    static final CommitmentProfile PEDERSEN_JUBJUB_BYTES_V1 =
            builtIn("pedersen-jubjub-bytes-v1", CommitmentKind.BYTES, CommitmentGroup.JUBJUB, 32);
    static final CommitmentProfile PEDERSEN_JUBJUB_VECTOR_V1 =
            builtIn("pedersen-jubjub-vector-v1", CommitmentKind.VECTOR, CommitmentGroup.JUBJUB, 32);
    static final CommitmentProfile PEDERSEN_BLS12_381_G1_V1 =
            builtIn("pedersen-bls12-381-g1-v1", CommitmentKind.SCALAR, CommitmentGroup.BLS12_381_G1, 48);
    static final CommitmentProfile PEDERSEN_BLS12_381_G1_BYTES_V1 =
            builtIn("pedersen-bls12-381-g1-bytes-v1", CommitmentKind.BYTES, CommitmentGroup.BLS12_381_G1, 48);

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

    private static Set<CommitmentProfileId> reserved(String... ids) {
        Set<CommitmentProfileId> out = new LinkedHashSet<>();
        for (String id : ids) {
            if (!out.add(CommitmentProfileId.of(id))) {
                throw new IllegalStateException("reserved identifier " + id + " is listed twice");
            }
        }
        return Collections.unmodifiableSet(out);
    }

    private static Set<CommitmentProfileId> seeded(Set<CommitmentProfileId> reserved) {
        Set<CommitmentProfileId> out = ConcurrentHashMap.newKeySet();
        out.addAll(reserved);
        return out;
    }

    private static CommitmentProfile builtIn(String id, CommitmentKind kind, CommitmentGroup group,
                                             int pointEncodingLength) {
        CommitmentProfileId profileId = CommitmentProfileId.of(id);
        if (!DEFINED.add(profileId)) {
            throw new IllegalStateException("built-in commitment profile " + id + " is listed twice");
        }
        return new CommitmentProfile(profileId, kind, group, pointEncodingLength);
    }

    /**
     * Defines the descriptor of a profile that is not built into ZeroJ. Called once per profile, by
     * the profile module. The built-in profiles are already defined ({@link CommitmentProfiles}), so
     * defining one of their identifiers is always rejected. A profile that is not built in is
     * protected only by being defined first: if untrusted code defines its identifier earlier, the
     * profile module's own {@code define} fails (fail-closed), so define such a descriptor before
     * untrusted code runs.
     *
     * @throws NullPointerException      if an argument is null
     * @throws CommitmentFormatException ({@code INVALID_CONFIGURATION}) if
     *                                   {@code pointEncodingLength} is not in {@code [1, 255]}, or
     *                                   {@code id} is already defined or is another registry
     *                                   identifier or a reserved document name (spec §2.2)
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
                    "identifier " + id + " is already defined or reserved");
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
