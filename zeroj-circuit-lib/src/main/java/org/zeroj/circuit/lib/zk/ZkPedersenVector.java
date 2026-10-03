package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.BitDecomposition;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.InCircuitPedersenVector;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Symbolic {@code pedersen-jubjub-vector-v1} commitments
 * ({@code docs/specs/pedersen-jubjub-vector-v1.md}, ADR-0051 D5, invariant I11).
 *
 * <p>A vector commitment binds neither its dimension nor its schema, so every circuit that
 * creates or consumes one first {@link #bindSchema binds the schema}: the schema digest becomes
 * a declared public input constrained to the schema's constant digest. The verifier compares
 * that public input with the digest its trusted registry expects for the verification key
 * (spec §5). Commitments are then created against the binding, so a circuit cannot commit
 * without having put its schema into the public statement.
 */
public final class ZkPedersenVector {

    private ZkPedersenVector() {}

    /** Proof that a schema's digest is constrained into this circuit's public statement. */
    public static final class SchemaBinding {
        private final ZkContext context;
        private final PedersenVectorSchema schema;

        private SchemaBinding(ZkContext context, PedersenVectorSchema schema) {
            this.context = context;
            this.schema = schema;
        }

        public PedersenVectorSchema schema() {
            return schema;
        }

        void requireSameContext(ZkContext zk) {
            Objects.requireNonNull(zk, "zk");
            if (zk.builder() != context.builder()) {
                throw new IllegalArgumentException("schema binding belongs to a different circuit builder");
            }
        }
    }

    /**
     * Binds {@code schema} into the public statement: {@code schemaDigest} must be a declared
     * public input (a constant or a secret wire is rejected at circuit-definition time) and is
     * constrained to equal {@code schema.digest()} (one linear constraint).
     */
    public static SchemaBinding bindSchema(ZkContext zk, PedersenVectorSchema schema, ZkField schemaDigest) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(schema, "schema");
        Objects.requireNonNull(schemaDigest, "schemaDigest");
        zk.requireSignal(schemaDigest.signal());
        var api = zk.builder().api();
        api.requirePublicInput(schemaDigest.signal().variable());
        api.assertEqual(schemaDigest.signal().variable(), api.constant(schema.digest()));
        return new SchemaBinding(zk, schema);
    }

    /**
     * Commits to {@code values} under the bound schema with a full-width {@code blinding}.
     *
     * <p>Each value's declared width must equal its schema width exactly (spec §5 item 2): it is
     * range-bounded by its own decomposition. A value declared at 252 bits is additionally
     * asserted {@code < l}; narrower widths imply it. The blinding follows ADR-0051 D2: exactly
     * 252 bits, asserted canonical, not a public input or a constant.
     */
    public static ZkPedersenVectorCommitment commit(ZkContext zk, SchemaBinding binding,
                                                    List<ZkUInt> values, ZkUInt blinding) {
        Objects.requireNonNull(binding, "binding");
        binding.requireSameContext(zk);
        Objects.requireNonNull(values, "values");
        Objects.requireNonNull(blinding, "blinding");
        PedersenVectorSchema schema = binding.schema();
        if (values.size() != schema.dimension()) {
            throw new IllegalArgumentException("schema " + schema.id() + " has dimension "
                    + schema.dimension() + ", got " + values.size() + " values");
        }
        for (int i = 0; i < values.size(); i++) {
            ZkUInt value = Objects.requireNonNull(values.get(i), "values[" + i + "]");
            zk.requireSignal(value.signal());
            if (value.bits() != schema.width(i)) {
                throw new IllegalArgumentException("value " + i + " (" + schema.entries().get(i).label()
                        + ") must be declared at the schema width " + schema.width(i)
                        + ", got " + value.bits());
            }
        }
        zk.requireSignal(blinding.signal());
        ZkPedersen.requireBlindingWidth(blinding.bits());
        zk.builder().api().requireNotPublicOrConstant(blinding.signal().variable());

        List<BitDecomposition> valueBits = new ArrayList<>(values.size());
        for (ZkUInt value : values) {
            valueBits.add(value.decomposition());
        }
        BitDecomposition blindingBits = blinding.decomposition();
        for (int i = 0; i < values.size(); i++) {
            if (schema.width(i) == ZkPedersen.MAX_SCALAR_BITS) {
                ZkPedersen.assertCanonicalScalar(zk, values.get(i).signal().variable());
            }
        }
        ZkPedersen.assertCanonicalScalar(zk, blinding.signal().variable());

        ZkJubjubPoint point = ZkJubjubPoint.wrap(zk, InCircuitPedersenVector.commit(
                zk.builder().api(), valueBits, blindingBits));
        return new ZkPedersenVectorCommitment(binding, point, List.copyOf(values),
                ZkPedersenCommitment.Origin.COMPUTED);
    }

    /**
     * Binds an unopened, prover-supplied vector commitment under the bound schema, proving
     * prime-order subgroup membership in-circuit (ADR-0051 I4 case b).
     */
    public static ZkPedersenVectorCommitment witnessInSubgroup(ZkContext zk, SchemaBinding binding,
                                                               ZkField u, ZkField v) {
        Objects.requireNonNull(binding, "binding");
        binding.requireSameContext(zk);
        ZkJubjubPoint point = ZkJubjubPoint.witnessAffine(zk, u, v);
        point.assertInPrimeOrderSubgroup(zk);
        return new ZkPedersenVectorCommitment(binding, point, null,
                ZkPedersenCommitment.Origin.WITNESSED_IN_SUBGROUP);
    }

    /**
     * Binds an unopened vector commitment with public or constant coordinates; the verifier must
     * check subgroup membership with {@code PedersenVectorCommitment.decode} (I4 case c).
     */
    public static ZkPedersenVectorCommitment fromVerifierCheckedPublic(ZkContext zk, SchemaBinding binding,
                                                                       ZkField u, ZkField v) {
        Objects.requireNonNull(binding, "binding");
        binding.requireSameContext(zk);
        ZkPedersenCommitment scalar = ZkPedersenCommitment.fromVerifierCheckedPublic(zk, u, v);
        return new ZkPedersenVectorCommitment(binding, scalar.point(), null,
                ZkPedersenCommitment.Origin.VERIFIER_CHECKED_PUBLIC);
    }
}
