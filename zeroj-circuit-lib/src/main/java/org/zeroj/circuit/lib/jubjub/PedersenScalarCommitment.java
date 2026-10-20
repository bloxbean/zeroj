package org.zeroj.circuit.lib.jubjub;

import org.zeroj.api.commitment.Commitment;
import org.zeroj.api.commitment.CommitmentCodec;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.CommitmentGroup;
import org.zeroj.api.commitment.CommitmentKind;
import org.zeroj.api.commitment.CommitmentProfile;
import org.zeroj.api.commitment.CommitmentProfileId;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A typed {@code pedersen-jubjub-v1} commitment, {@code C = [m]·G + [r]·H}
 * ({@code docs/specs/pedersen-jubjub-v1.md}, {@code commitment-profiles-v1} §4.2, ADR-0059).
 *
 * <p>Created only by {@link PedersenCommitment#commitScalar}, by the strict decoder
 * {@link #decode(byte[])} (or {@link #CODEC}), and by same-type {@link #add}, {@link #subtract}
 * and {@link #negate}. It holds only the validated, normalized point: never a value or blinding.
 *
 * <p><b>Arithmetic is on residues mod {@code l}</b>, not integers: a sum or difference opens to
 * {@code (m₁ ± m₂) mod l}. Reading it as integer conservation needs the side-bound rule of
 * ADR-0051 D3a or a range proof (spec §6.1, §7). Operations accept only this type, so a
 * commitment of another profile (for example a byte commitment, whose point is formed with the
 * same bases) cannot be combined with it by accident.
 *
 * <p>Closure is a language-level property: the package-private constructor stops ordinary
 * callers, not code that can define classes in this package or use reflection, which is outside
 * the threat model (the {@code zeroj-circuit-lib} jar does not seal this package).
 *
 * <p>The type is not provenance. A verifier selects this profile from trusted configuration and,
 * when issuance context matters, authenticates the association of point, profile and context
 * separately (spec §6.3).
 */
public final class PedersenScalarCommitment implements Commitment {

    /** The {@code pedersen-jubjub-v1} descriptor. Compare with {@code ==}. */
    public static final CommitmentProfile PROFILE = CommitmentProfile.define(
            CommitmentProfileId.of("pedersen-jubjub-v1"), CommitmentKind.SCALAR, CommitmentGroup.JUBJUB,
            JubjubCurve.COMPRESSED_POINT_BYTES);

    /** The {@code pedersen-jubjub-v1} codec: strict point decoding (spec §10), no context. */
    public static final CommitmentCodec<PedersenScalarCommitment> CODEC = new Codec();

    private final JubjubPoint point;
    private final byte[] encoding;

    PedersenScalarCommitment(JubjubPoint point) {
        this.point = point.normalized();
        this.encoding = this.point.toBytes();
    }

    /**
     * Strictly decodes a received commitment (spec §10): canonical ZIP 216 encoding, then
     * prime-order subgroup membership. Never cofactor-clears; the identity is accepted.
     *
     * @throws NullPointerException      if {@code pointBytes} is null
     * @throws CommitmentFormatException {@code MALFORMED_ENCODING} or {@code NOT_IN_SUBGROUP}
     */
    public static PedersenScalarCommitment decode(byte[] pointBytes) {
        return new PedersenScalarCommitment(PedersenStrict.decodePoint(pointBytes));
    }

    @Override
    public CommitmentProfile profile() {
        return PROFILE;
    }

    /** A fresh copy of the 32-byte point encoding ({@code pedersen-jubjub-v1} §4). */
    @Override
    public byte[] toPointBytes() {
        return encoding.clone();
    }

    /** {@code this + other}: opens to {@code (m₁ + m₂) mod l} with blinding {@code (r₁ + r₂) mod l}. */
    public PedersenScalarCommitment add(PedersenScalarCommitment other) {
        Objects.requireNonNull(other, "other");
        return new PedersenScalarCommitment(point.add(other.point));
    }

    /** {@code this − other}: opens to {@code (m₁ − m₂) mod l} with blinding {@code (r₁ − r₂) mod l}. */
    public PedersenScalarCommitment subtract(PedersenScalarCommitment other) {
        Objects.requireNonNull(other, "other");
        return new PedersenScalarCommitment(point.add(other.point.negate()));
    }

    /** {@code −this}: opens to {@code (−m) mod l} with blinding {@code (−r) mod l}. */
    public PedersenScalarCommitment negate() {
        return new PedersenScalarCommitment(point.negate());
    }

    JubjubPoint point() {
        return point;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PedersenScalarCommitment that && Arrays.equals(encoding, that.encoding);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoding);
    }

    @Override
    public String toString() {
        return "PedersenScalarCommitment[" + PROFILE.id() + ", " + HexFormat.of().formatHex(encoding) + "]";
    }

    private static final class Codec implements CommitmentCodec<PedersenScalarCommitment> {
        @Override
        public CommitmentProfile profile() {
            return PROFILE;
        }

        @Override
        public Class<PedersenScalarCommitment> commitmentType() {
            return PedersenScalarCommitment.class;
        }

        @Override
        public PedersenScalarCommitment decodePoint(byte[] pointBytes) {
            return decode(pointBytes);
        }
    }
}
