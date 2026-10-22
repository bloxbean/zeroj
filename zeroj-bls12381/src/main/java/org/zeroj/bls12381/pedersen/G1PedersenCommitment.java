package org.zeroj.bls12381.pedersen;

import org.zeroj.api.commitment.Commitment;
import org.zeroj.api.commitment.CommitmentCodec;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.CommitmentProfile;
import org.zeroj.api.commitment.CommitmentProfiles;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A typed {@code pedersen-bls12-381-g1-v1} commitment, {@code C = [m]·G + [r]·H}
 * ({@code docs/specs/pedersen-bls12-381-g1-v1.md}, ADR-0060).
 *
 * <p>Created only by {@link G1Pedersen#commitScalar}, by the strict decoder {@link #decode(byte[])}
 * (or {@link #CODEC}), and by same-type {@link #add}, {@link #subtract}, {@link #negate} and
 * {@link #withPublicDelta}. It holds only the validated point and its 48-octet encoding: never a
 * value or blinding.
 *
 * <p><b>Arithmetic is on residues mod {@code q}</b>, not integers: a sum or difference opens to
 * {@code (m₁ ± m₂) mod q}. Reading it as integer conservation needs the application's own bounds
 * (spec §6.4, ADR-0051 D3a). Operations accept only this type, so a commitment of another profile
 * (a G1 byte commitment, or any Jubjub commitment) cannot be combined with it.
 *
 * <p>Closure is a language-level property: the private constructor stops ordinary callers, not
 * reflection, which is outside the threat model.
 *
 * <p>The type is not provenance. A verifier selects this profile from trusted configuration and,
 * when issuance context matters, authenticates the association of point, profile and context
 * separately ({@code commitment-profiles-v1} §6.3).
 */
public final class G1PedersenCommitment implements Commitment {

    /**
     * The {@code pedersen-bls12-381-g1-v1} descriptor,
     * {@link CommitmentProfiles#PEDERSEN_BLS12_381_G1_V1}. Compare with {@code ==}.
     */
    public static final CommitmentProfile PROFILE = CommitmentProfiles.PEDERSEN_BLS12_381_G1_V1;

    /** The {@code pedersen-bls12-381-g1-v1} codec: strict point decoding (spec §4), no context. */
    public static final CommitmentCodec<G1PedersenCommitment> CODEC = new Codec();

    private final G1Point point;
    private final byte[] encoding;

    G1PedersenCommitment(G1Point point) {
        this.point = point;
        this.encoding = Bls12381Codecs.g1ToCompressed(point);
    }

    /**
     * Strictly decodes a received commitment (spec §4): the 48-octet compressed form, then
     * prime-order subgroup membership. Never cofactor-clears; exactly {@code 0xC0 ‖ 0^47} is the
     * identity and is accepted.
     *
     * @throws NullPointerException      if {@code pointBytes} is null
     * @throws CommitmentFormatException {@code MALFORMED_ENCODING} or {@code NOT_IN_SUBGROUP}
     */
    public static G1PedersenCommitment decode(byte[] pointBytes) {
        return new G1PedersenCommitment(G1PedersenStrict.decodePoint(pointBytes));
    }

    @Override
    public CommitmentProfile profile() {
        return PROFILE;
    }

    /** A fresh copy of the 48-octet compressed point encoding (spec §4). */
    @Override
    public byte[] toPointBytes() {
        return encoding.clone();
    }

    /** {@code this + other}: opens to {@code (m₁ + m₂) mod q} with blinding {@code (r₁ + r₂) mod q}. */
    public G1PedersenCommitment add(G1PedersenCommitment other) {
        Objects.requireNonNull(other, "other");
        return new G1PedersenCommitment(point.add(other.point));
    }

    /** {@code this − other}: opens to {@code (m₁ − m₂) mod q} with blinding {@code (r₁ − r₂) mod q}. */
    public G1PedersenCommitment subtract(G1PedersenCommitment other) {
        Objects.requireNonNull(other, "other");
        return new G1PedersenCommitment(point.add(other.point.negate()));
    }

    /** {@code −this}: opens to {@code (−m) mod q} with blinding {@code (−r) mod q}. */
    public G1PedersenCommitment negate() {
        return new G1PedersenCommitment(point.negate());
    }

    /**
     * {@code this + [δ]·G} for a public signed delta (spec §6.4): opens to {@code (m + δ) mod q} with
     * the same blinding. The point {@code [|δ|]·G} is computed with the canonical scalar {@code |δ|}
     * and negated when {@code δ < 0}; no negative or out-of-range integer reaches a scalar
     * multiplication. {@code δ} is public, so the variable-time public multiplication is used.
     *
     * <p>Checks, in order: nulls; {@code deltaBits ∈ [1, 253]} ({@code INVALID_CONFIGURATION}); one
     * snapshot of {@code delta}; {@code |δ| < 2^deltaBits} ({@code OUT_OF_RANGE}); then the arithmetic.
     * The width is at most 253 so that an accepted delta is unique mod {@code q}: no {@code δ − q}
     * alias also passes the bound.
     *
     * @throws NullPointerException      if {@code delta} is null
     * @throws CommitmentFormatException with the class of the first failure
     */
    public G1PedersenCommitment withPublicDelta(BigInteger delta, int deltaBits) {
        Objects.requireNonNull(delta, "delta");
        G1PedersenStrict.requireBits(deltaBits, G1PedersenStrict.MAX_DELTA_BITS, "deltaBits");
        BigInteger d = G1PedersenStrict.snapshot(delta);
        BigInteger magnitude = d.abs();
        // magnitude is non-negative, so |δ| < 2^k iff bitLength(|δ|) ≤ k.
        if (magnitude.bitLength() > deltaBits) {
            throw new CommitmentFormatException(CommitmentError.OUT_OF_RANGE,
                    "|delta| must be below 2^" + deltaBits);
        }
        // deltaBits ≤ 253, so magnitude < 2^253 < q: a canonical scalar.
        G1Point step = G1PedersenStrict.publicMul(G1PedersenBases.G, magnitude);
        if (d.signum() < 0) {
            step = step.negate();
        }
        return new G1PedersenCommitment(point.add(step));
    }

    G1Point point() {
        return point;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof G1PedersenCommitment that && Arrays.equals(encoding, that.encoding);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoding);
    }

    @Override
    public String toString() {
        return "G1PedersenCommitment[" + PROFILE.id() + ", " + HexFormat.of().formatHex(encoding) + "]";
    }

    private static final class Codec implements CommitmentCodec<G1PedersenCommitment> {
        @Override
        public CommitmentProfile profile() {
            return PROFILE;
        }

        @Override
        public Class<G1PedersenCommitment> commitmentType() {
            return G1PedersenCommitment.class;
        }

        @Override
        public G1PedersenCommitment decodePoint(byte[] pointBytes) {
            return decode(pointBytes);
        }
    }
}
