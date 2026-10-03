package org.zeroj.circuit.lib.jubjub;

import org.zeroj.circuit.BitDecomposition;
import org.zeroj.circuit.CircuitAPI;

import java.util.List;
import java.util.Objects;

/**
 * In-circuit {@code pedersen-jubjub-vector-v1} commitment
 * ({@code docs/specs/pedersen-jubjub-vector-v1.md}, ADR-0051 D5):
 * {@code Σ_{i<n} [v_i]·G_i + [r]·H_V} with the pinned {@link PedersenVectorBases}.
 *
 * <p>Low level: like {@link InCircuitPedersen}, it proves the residues the decompositions
 * represent and does not assert {@code < l}, and it knows nothing about schemas. Use
 * {@code ZkPedersenVector}, which binds the schema digest into the public statement and asserts
 * canonicity, unless you are building another symbolic layer.
 *
 * <p>The blinding follows the hiding-safe rule of ADR-0051 D2: exactly
 * {@value InCircuitPedersen#BLINDING_BITS} bits, not wired directly to a public input or a
 * constant. Every operand's ownership, width and the blinding's provenance are validated before
 * the first constraint is emitted.
 */
public final class InCircuitPedersenVector {

    private InCircuitPedersenVector() {}

    /**
     * Commits to {@code values} (one decomposition per index, each at its own width, 1–252) with
     * a 252-bit {@code blinding}. {@code 1 ≤ values.size() ≤ }{@value PedersenVectorBases#MAX_DIMENSION}.
     *
     * @throws IllegalArgumentException if any decomposition was minted by another circuit, a
     *         width is out of range, the dimension is out of range, or the blinding is not a
     *         full-width, non-public, non-constant scalar
     */
    public static InCircuitJubjub.Point commit(CircuitAPI api,
                                               List<BitDecomposition> values,
                                               BitDecomposition blinding) {
        Objects.requireNonNull(api, "api");
        Objects.requireNonNull(values, "values");
        Objects.requireNonNull(blinding, "blinding");
        if (values.isEmpty() || values.size() > PedersenVectorBases.MAX_DIMENSION) {
            throw new IllegalArgumentException("dimension must be in [1, "
                    + PedersenVectorBases.MAX_DIMENSION + "], got " + values.size());
        }
        // Authenticate and size every operand before ANY constraint is emitted.
        for (int i = 0; i < values.size(); i++) {
            api.requireOwned(Objects.requireNonNull(values.get(i), "values[" + i + "]"));
        }
        api.requireOwned(blinding);
        for (int i = 0; i < values.size(); i++) {
            int width = values.get(i).width();
            if (width < 1 || width > InCircuitPedersen.MAX_VALUE_BITS) {
                throw new IllegalArgumentException("value " + i + " width must be in [1, "
                        + InCircuitPedersen.MAX_VALUE_BITS + "], got " + width);
            }
        }
        if (blinding.width() != InCircuitPedersen.BLINDING_BITS) {
            throw new IllegalArgumentException("blinding width must be exactly "
                    + InCircuitPedersen.BLINDING_BITS + ", got " + blinding.width() + " (ADR-0051 D2)");
        }
        api.requireNotPublicOrConstant(blinding.source());

        InCircuitJubjub.Point acc = null;
        for (int i = 0; i < values.size(); i++) {
            InCircuitJubjub.Point term = InCircuitJubjub.scalarMulFixedBase(
                    api, PedersenVectorBases.valueBase(i), values.get(i).bits());
            acc = (acc == null) ? term : InCircuitJubjub.add(api, acc, term);
        }
        InCircuitJubjub.Point blindingTerm = InCircuitJubjub.scalarMulFixedBase(
                api, PedersenVectorBases.blindingBase(), blinding.bits());
        return InCircuitJubjub.add(api, acc, blindingTerm);
    }
}
