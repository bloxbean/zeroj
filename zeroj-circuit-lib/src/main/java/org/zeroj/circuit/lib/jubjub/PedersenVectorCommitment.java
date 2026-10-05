package org.zeroj.circuit.lib.jubjub;

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
 */
public final class PedersenVectorCommitment {

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

    /** Returns {@code true} iff {@code (values, blinding)} opens this commitment under its schema. */
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

    private void requireSameSchema(PedersenVectorCommitment other) {
        Objects.requireNonNull(other, "other");
        if (!schema.equals(other.schema)) {
            throw new IllegalArgumentException("vector commitments under different schemas cannot be combined: "
                    + schema + " vs " + other.schema);
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
