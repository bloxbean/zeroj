package com.bloxbean.cardano.zeroj.cardano;

/**
 * Defines what data is anchored on Cardano L1 for a verified ZK proof.
 *
 * <p>Different patterns trade off between on-chain footprint and verifiability.
 * All patterns encode as CIP-10 metadata labels under a ZeroJ-specific label.</p>
 */
public enum AnchorPattern {

    /**
     * Minimal: only the proof hash.
     * Proves that a specific proof was verified at a point in time.
     * On-chain: ~32 bytes of metadata.
     */
    PROOF_HASH_ONLY,

    /**
     * State root + proof hash.
     * Links a state transition to a proof.
     * On-chain: ~64 bytes of metadata.
     */
    STATE_ROOT_AND_PROOF_HASH,

    /**
     * Full reference: state root + circuit id + VK hash.
     * Allows independent verification of what was proven and by which circuit.
     * On-chain: ~96+ bytes of metadata.
     */
    FULL_VERIFICATION_REF,

    /**
     * Nullifier commitment.
     * For privacy-preserving double-spend prevention on L1.
     * On-chain: ~32 bytes of metadata.
     */
    NULLIFIER_COMMITMENT
}
