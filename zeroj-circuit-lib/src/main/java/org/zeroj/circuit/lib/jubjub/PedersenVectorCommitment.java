package org.zeroj.circuit.lib.jubjub;

import org.zeroj.api.commitment.Commitment;
import org.zeroj.api.commitment.CommitmentCodec;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.CommitmentGroup;
import org.zeroj.api.commitment.CommitmentKind;
import org.zeroj.api.commitment.CommitmentProfile;
import org.zeroj.api.commitment.CommitmentProfileId;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * An off-circuit {@code pedersen-jubjub-vector-v1} commitment typed by its schema
 * ({@code docs/specs/pedersen-jubjub-vector-v1.md} §3, ADR-0051 D5):
 * {@code C = Σ_{i<n} [v_i]·G_i + [r]·H_V}.
 *
 * <p>The point itself binds neither its dimension nor its schema — {@code C([a], r)} equals
 * {@code C([a, 0], r)}. This type carries the schema so cooperating code cannot combine
 * commitments across schemas by accident; it is a convenience, <b>not</b> the security boundary.
 * The boundary is the constrained schema digest in every proof (spec §5) and, for commitments
 * received from elsewhere, an authenticated issuance record (spec §6).
 *
 * <p><b>Same execution restriction as {@link PedersenCommitment#commit}.</b> Generation runs
 * secret scalars through variable-time {@link BigInteger} arithmetic: generate offline or in an
 * isolated process (ADR-0038).
 *
 * <p><b>Strict verification (ADR-0059).</b> {@link #verifyOpening} checks an opening under an
 * explicitly configured {@link PedersenVectorBoundPolicy}, so sums and differences can be opened;
 * the legacy {@link #verify} keeps its schema-width check and its {@code false}-for-malformed
 * behaviour. Equality stays reference identity: use {@code CommitmentKey} with
 * {@link #codec(PedersenVectorSchema)} for maps and sets.
 */
public final class PedersenVectorCommitment implements Commitment {

    /** The {@code pedersen-jubjub-vector-v1} descriptor. Compare with {@code ==}. */
    public static final CommitmentProfile PROFILE = CommitmentProfile.define(
            CommitmentProfileId.of("pedersen-jubjub-vector-v1"), CommitmentKind.VECTOR, CommitmentGroup.JUBJUB,
            JubjubCurve.COMPRESSED_POINT_BYTES);

    private final PedersenVectorSchema schema;
    private final JubjubPoint point;

    private PedersenVectorCommitment(PedersenVectorSchema schema, JubjubPoint point) {
        this.schema = Objects.requireNonNull(schema, "schema");
        this.point = Objects.requireNonNull(point, "point").normalized();
    }

    /**
     * Commits to {@code values} under {@code schema}. Each value must lie in
     * {@code [0, 2^width)} for its index, so it can be opened in a circuit built for the schema;
     * the blinding is reduced mod {@code l} and should come from
     * {@link PedersenCommitment#randomBlinding}.
     */
    public static PedersenVectorCommitment commit(PedersenVectorSchema schema,
                                                  List<BigInteger> values,
                                                  BigInteger blinding) {
        Objects.requireNonNull(schema, "schema");
        requireValues(schema, values);
        Objects.requireNonNull(blinding, "blinding");
        JubjubPoint acc = PedersenVectorBases.blindingBase()
                .scalarMulSecretBlindedBestEffort(blinding.mod(JubjubCurve.SUBGROUP_ORDER));
        for (int i = 0; i < values.size(); i++) {
            acc = acc.add(PedersenVectorBases.valueBase(i).scalarMulSecretBlindedBestEffort(values.get(i)));
        }
        return new PedersenVectorCommitment(schema, acc);
    }

    /**
     * Decodes a commitment received under {@code schema}: canonical encoding plus prime-order
     * subgroup membership ({@link PedersenCommitment#decode}). The caller must obtain
     * {@code schema} from an authenticated issuance record for this exact commitment, never from
     * data travelling with it (spec §6).
     */
    public static PedersenVectorCommitment decode(PedersenVectorSchema schema, byte[] encoded) {
        Objects.requireNonNull(schema, "schema");
        return new PedersenVectorCommitment(schema, PedersenCommitment.decode(encoded));
    }

    /**
     * The codec of this profile bound to {@code schema}, which the caller takes from its trusted
     * configuration or issuance record. Its context is {@code I2OSP(σ, 32)} for the schema digest
     * {@code σ}; {@code requireContext} rejects a commitment of another schema
     * ({@code PROFILE_MISMATCH}).
     *
     * @throws NullPointerException if {@code schema} is null
     */
    public static CommitmentCodec<PedersenVectorCommitment> codec(PedersenVectorSchema schema) {
        Objects.requireNonNull(schema, "schema");
        return new Codec(schema);
    }

    /**
     * Strict disclosed verification under a bound policy (class V1, {@code commitment-profiles-v1}
     * §7 check 3, §12.3): {@code true} iff {@code Σ [v_i]·G_i + [r]·H_V} equals this commitment.
     *
     * <p>Checks, in order: nulls (including null elements, while snapshotting the list); the
     * policy's schema equals this commitment's ({@code PROFILE_MISMATCH}); dimension
     * ({@code MALFORMED_ENCODING}); each value's check 1 in index order, then the blinding's
     * ({@code NON_CANONICAL_SCALAR}); each value's check 3 in index order ({@code OUT_OF_RANGE});
     * then the equation, computed here on the variable-time public-scalar path. It never delegates
     * to {@link #verify}, whose width check would reject valid {@code residue-only} and
     * {@code widened} openings. The timing rule of {@link PedersenCommitment#verifyScalar} applies.
     *
     * @throws NullPointerException      if an argument or element is null
     * @throws CommitmentFormatException with the class of the first failure
     */
    public boolean verifyOpening(List<BigInteger> values, BigInteger blinding, PedersenVectorBoundPolicy policy) {
        Objects.requireNonNull(values, "values");
        Objects.requireNonNull(blinding, "blinding");
        Objects.requireNonNull(policy, "policy");
        // The snapshot (which also rejects null elements) precedes the schema comparison (§12.3).
        List<BigInteger> snapshot = PedersenStrict.trustedSnapshot(values);
        if (!policy.schema().equals(schema)) {
            throw new CommitmentFormatException(CommitmentError.PROFILE_MISMATCH,
                    "the bound policy is for another schema than this commitment's");
        }
        PedersenVectorBoundPolicy.CheckedOpening checked = policy.requireOpening(snapshot, blinding);
        JubjubPoint expected = PedersenVectorBases.blindingBase().scalarMul(checked.blinding());
        for (int i = 0; i < checked.values().size(); i++) {
            expected = expected.add(PedersenVectorBases.valueBase(i).scalarMul(checked.values().get(i)));
        }
        return expected.projectiveEquals(point);
    }

    /**
     * Returns {@code true} iff {@code (values, blinding)} opens this commitment under its schema,
     * with each value in {@code [0, min(2^width, l))}; malformed input is {@code false}, and the
     * blinding is reduced mod {@code l} (legacy behaviour, unchanged).
     *
     * <p><b>Timing rule (class V1, ADR-0059 A2).</b> This is variable-time disclosed verification:
     * use it only where the opening is already public or no party from whom it is still secret can
     * observe the verifier's timing; otherwise verify offline or in an isolated process. For sums,
     * differences and strict error classes use {@link #verifyOpening}.
     */
    public boolean verify(List<BigInteger> values, BigInteger blinding) {
        Objects.requireNonNull(blinding, "blinding");
        if (values == null || values.size() != schema.dimension()) {
            return false;
        }
        for (int i = 0; i < values.size(); i++) {
            BigInteger v = values.get(i);
            if (v == null || v.signum() < 0 || v.bitLength() > schema.width(i)
                    || v.compareTo(JubjubCurve.SUBGROUP_ORDER) >= 0) {
                return false;
            }
        }
        JubjubPoint expected = PedersenVectorBases.blindingBase()
                .scalarMul(blinding.mod(JubjubCurve.SUBGROUP_ORDER));
        for (int i = 0; i < values.size(); i++) {
            expected = expected.add(PedersenVectorBases.valueBase(i).scalarMul(values.get(i)));
        }
        return expected.projectiveEquals(point);
    }

    /** {@code this + other}, component-wise mod {@code l}. Requires an identical schema. */
    public PedersenVectorCommitment add(PedersenVectorCommitment other) {
        requireSameSchema(other);
        return new PedersenVectorCommitment(schema, point.add(other.point));
    }

    /** {@code this − other}, component-wise mod {@code l}. Requires an identical schema. */
    public PedersenVectorCommitment subtract(PedersenVectorCommitment other) {
        requireSameSchema(other);
        return new PedersenVectorCommitment(schema, point.add(other.point.negate()));
    }

    public PedersenVectorSchema schema() {
        return schema;
    }

    public JubjubPoint point() {
        return point;
    }

    /** The 32-byte encoding of the point ({@code pedersen-jubjub-v1} §4); carries no schema. */
    public byte[] toBytes() {
        return point.toBytes();
    }

    /** Returns {@link #PROFILE}. */
    @Override
    public CommitmentProfile profile() {
        return PROFILE;
    }

    /** The same octets as {@link #toBytes()}: a fresh 32-byte point encoding, carrying no schema. */
    @Override
    public byte[] toPointBytes() {
        return point.toBytes();
    }

    private void requireSameSchema(PedersenVectorCommitment other) {
        Objects.requireNonNull(other, "other");
        if (!schema.equals(other.schema)) {
            throw new IllegalArgumentException("vector commitments under different schemas cannot be combined: "
                    + schema + " vs " + other.schema);
        }
    }

    private static final class Codec implements CommitmentCodec<PedersenVectorCommitment> {
        private final PedersenVectorSchema schema;
        private final byte[] context;

        Codec(PedersenVectorSchema schema) {
            this.schema = schema;
            this.context = new byte[PedersenStrict.SCALAR_BYTES];
            // σ < p < 2^255, so it fits 32 octets.
            PedersenStrict.writeScalar(schema.digest(), context, 0);
        }

        @Override
        public CommitmentProfile profile() {
            return PROFILE;
        }

        @Override
        public Class<PedersenVectorCommitment> commitmentType() {
            return PedersenVectorCommitment.class;
        }

        @Override
        public PedersenVectorCommitment decodePoint(byte[] pointBytes) {
            return new PedersenVectorCommitment(schema, PedersenStrict.decodePoint(pointBytes));
        }

        @Override
        public byte[] keyContext() {
            return context.clone();
        }

        @Override
        public void requireContext(PedersenVectorCommitment commitment) {
            Objects.requireNonNull(commitment, "commitment");
            if (!schema.equals(commitment.schema)) {
                throw new CommitmentFormatException(CommitmentError.PROFILE_MISMATCH,
                        "vector commitment schema is not the codec's schema");
            }
        }
    }

    private static void requireValues(PedersenVectorSchema schema, List<BigInteger> values) {
        Objects.requireNonNull(values, "values");
        if (values.size() != schema.dimension()) {
            throw new IllegalArgumentException("schema " + schema.id() + " has dimension "
                    + schema.dimension() + ", got " + values.size() + " values");
        }
        for (int i = 0; i < values.size(); i++) {
            BigInteger v = Objects.requireNonNull(values.get(i), "values[" + i + "]");
            // Below l as well: a 252-bit circuit value is asserted canonical, so a value in
            // [l, 2^252) could never be opened in-circuit.
            if (v.signum() < 0 || v.bitLength() > schema.width(i)
                    || v.compareTo(JubjubCurve.SUBGROUP_ORDER) >= 0) {
                throw new IllegalArgumentException("value " + i + " (" + schema.entries().get(i).label()
                        + ") must be in [0, min(2^" + schema.width(i) + ", l))");
            }
        }
    }
}
