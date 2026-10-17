package org.zeroj.api.commitment;

/**
 * The group a commitment profile works in. Deliberately separate from
 * {@link org.zeroj.api.CurveId}, which names proof-system curves (ADR-0059 D5).
 */
public enum CommitmentGroup {
    /** The Jubjub prime-order subgroup (order {@code l}). */
    JUBJUB,
    /** The BLS12-381 G1 prime-order subgroup. */
    BLS12_381_G1
}
