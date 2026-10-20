package org.zeroj.circuit.lib.jubjub;

import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Check 3 of {@code commitment-profiles-v1} §7: the bound a vector opening's components are held
 * to, configured explicitly by the verifier for one schema and never inferred from the data.
 *
 * <ul>
 *   <li>{@link #schemaWidths} — each {@code v_i < min(2^{k_i}, l)} for the schema widths
 *       {@code k_i}. For commitments issued under the schema.</li>
 *   <li>{@link #residueOnly} — check 1 only. For derived commitments, including differences whose
 *       negative components open to residues {@code l − x}.</li>
 *   <li>{@link #widened} — for the sum of {@code n} commitments under the schema, each
 *       {@code v_i < 2^{k_i + ⌈log₂ n⌉}}.</li>
 * </ul>
 *
 * <p>A policy applies only to its own schema: a vector verification under a policy for another
 * schema is {@code PROFILE_MISMATCH}.
 */
public final class PedersenVectorBoundPolicy {

    /** Upper limit of {@link #widened}'s term count; larger sums use {@link #residueOnly}. */
    static final int MAX_ADDED_TERMS = 65536;

    private enum Kind { SCHEMA_WIDTHS, RESIDUE_ONLY, WIDENED }

    private final PedersenVectorSchema schema;
    private final Kind kind;
    private final int extraBits;

    private PedersenVectorBoundPolicy(PedersenVectorSchema schema, Kind kind, int extraBits) {
        this.schema = schema;
        this.kind = kind;
        this.extraBits = extraBits;
    }

    /** Each component below {@code min(2^{k_i}, l)}. */
    public static PedersenVectorBoundPolicy schemaWidths(PedersenVectorSchema schema) {
        Objects.requireNonNull(schema, "schema");
        return new PedersenVectorBoundPolicy(schema, Kind.SCHEMA_WIDTHS, 0);
    }

    /** Check 1 only: each component in {@code [0, l)}. */
    public static PedersenVectorBoundPolicy residueOnly(PedersenVectorSchema schema) {
        Objects.requireNonNull(schema, "schema");
        return new PedersenVectorBoundPolicy(schema, Kind.RESIDUE_ONLY, 0);
    }

    /**
     * Each component below {@code 2^{k_i + ⌈log₂ addedTerms⌉}}: the bound of a sum of
     * {@code addedTerms} commitments issued under the schema.
     *
     * @throws NullPointerException      if {@code schema} is null
     * @throws CommitmentFormatException ({@code INVALID_CONFIGURATION}) if {@code addedTerms} is
     *                                   not in {@code [2, 65536]} or any widened bound exceeds
     *                                   {@code l}, where it would stop being a bound
     */
    public static PedersenVectorBoundPolicy widened(PedersenVectorSchema schema, int addedTerms) {
        Objects.requireNonNull(schema, "schema");
        if (addedTerms < 2 || addedTerms > MAX_ADDED_TERMS) {
            throw new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION,
                    "addedTerms must be in [2, " + MAX_ADDED_TERMS + "]");
        }
        // ⌈log₂ n⌉ for n ≥ 2.
        int extraBits = Integer.SIZE - Integer.numberOfLeadingZeros(addedTerms - 1);
        for (int i = 0; i < schema.dimension(); i++) {
            if (BigInteger.ONE.shiftLeft(schema.width(i) + extraBits).compareTo(JubjubCurve.SUBGROUP_ORDER) > 0) {
                throw new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION,
                        "widened bound 2^" + (schema.width(i) + extraBits) + " of component " + i + " exceeds l");
            }
        }
        return new PedersenVectorBoundPolicy(schema, Kind.WIDENED, extraBits);
    }

    /** The schema this policy is bound to. */
    public PedersenVectorSchema schema() {
        return schema;
    }

    /** Whether the canonical component {@code value} at {@code index} is within this policy. */
    boolean admits(int index, BigInteger value) {
        return switch (kind) {
            // value < l already holds (check 1), so min(2^k, l) reduces to 2^k.
            case SCHEMA_WIDTHS -> value.bitLength() <= schema.width(index);
            case RESIDUE_ONLY -> true;
            case WIDENED -> value.bitLength() <= schema.width(index) + extraBits;
        };
    }

    /**
     * Snapshots ({@link PedersenStrict#trustedSnapshot}, bounded) and checks an opening under this
     * policy. The caller has already rejected a null list or blinding.
     */
    CheckedOpening requireOpening(List<BigInteger> rawValues, BigInteger rawBlinding) {
        return requireSnapshot(PedersenStrict.trustedSnapshot(rawValues), rawBlinding);
    }

    /**
     * Checks an opening whose values are already a {@link PedersenStrict#trustedSnapshot}, in the
     * order of spec §12.3: dimension ({@code MALFORMED_ENCODING}), each component's check 1 in index
     * order, the blinding's check 1 ({@code NON_CANONICAL_SCALAR}), each component's check 3 in index
     * order ({@code OUT_OF_RANGE}).
     *
     * <p>Returns the checked opening: the snapshot and a plain {@link BigInteger} blinding. Callers
     * must use only the returned values, so a subclass cannot pass the checks with one value and
     * present another to the equation or the encoding.
     */
    CheckedOpening requireSnapshot(List<BigInteger> values, BigInteger rawBlinding) {
        BigInteger blinding = PedersenStrict.trusted(rawBlinding);
        if (values.size() != schema.dimension()) {
            String got = values.size() == PedersenStrict.MAX_SNAPSHOT
                    ? "more than " + PedersenVectorBases.MAX_DIMENSION : String.valueOf(values.size());
            throw new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING,
                    "schema " + schema.id() + " has dimension " + schema.dimension() + ", got " + got + " values");
        }
        for (int i = 0; i < values.size(); i++) {
            PedersenStrict.canonical(values.get(i), "value " + i);
        }
        PedersenStrict.canonical(blinding, "blinding");
        for (int i = 0; i < values.size(); i++) {
            if (!admits(i, values.get(i))) {
                throw new CommitmentFormatException(CommitmentError.OUT_OF_RANGE,
                        "value " + i + " is outside the " + describe() + " bound");
            }
        }
        return new CheckedOpening(values, blinding);
    }

    /**
     * An opening that passed checks 1 and 3 under this policy; plain, immutable values only. A class,
     * not a record: like every opening holder it has no value equality or hashing over its secrets.
     */
    static final class CheckedOpening {
        private final List<BigInteger> values;
        private final BigInteger blinding;

        private CheckedOpening(List<BigInteger> values, BigInteger blinding) {
            this.values = values;
            this.blinding = blinding;
        }

        List<BigInteger> values() {
            return values;
        }

        BigInteger blinding() {
            return blinding;
        }

        @Override
        public String toString() {
            return "CheckedOpening[redacted]";
        }
    }

    private String describe() {
        return switch (kind) {
            case SCHEMA_WIDTHS -> "schema-widths";
            case RESIDUE_ONLY -> "residue-only";
            case WIDENED -> "widened(+" + extraBits + " bits)";
        };
    }

    @Override
    public String toString() {
        return "PedersenVectorBoundPolicy[" + describe() + ", " + schema.id() + " v" + schema.version() + "]";
    }
}
