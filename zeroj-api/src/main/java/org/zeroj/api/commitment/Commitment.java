package org.zeroj.api.commitment;

/**
 * A commitment of one profile ({@code commitment-profiles-v1} §12.1).
 *
 * <p>This interface offers no arithmetic and no equality contract: homomorphic operations exist
 * only on concrete profile types, accepting only the same concrete type (spec §6.1). Use
 * {@link CommitmentKey} for map keys and set membership.
 */
public interface Commitment {

    /** The profile's descriptor; compare it with {@code ==}. */
    CommitmentProfile profile();

    /** A fresh copy of the profile's raw point encoding. */
    byte[] toPointBytes();
}
