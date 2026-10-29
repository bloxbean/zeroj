package org.zeroj.api.commitment;

/** What a commitment opens to ({@code commitment-profiles-v1} §6.1). */
public enum CommitmentKind {
    /** A residue mod {@code q}. */
    SCALAR,
    /** An exact octet string, through a hash-derived scalar. */
    BYTES,
    /** {@code n} residues under one schema. */
    VECTOR
}
