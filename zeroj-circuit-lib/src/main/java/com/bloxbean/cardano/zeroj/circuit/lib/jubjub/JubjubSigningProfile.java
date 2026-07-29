package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

/**
 * Explicit assurance/profile label for a Jubjub signer.
 *
 * <p>A signature does not encode its profile. The label describes the implementation and
 * deployment that produced it, not the validity of the public {@code (R,S)} bytes.
 */
public enum JubjubSigningProfile {
    /** Existing variable-time BigInteger implementation; isolated/offline use only. */
    COMPATIBILITY_OFFLINE,

    /** Fixed-limb deterministic-v1 compatibility/testing implementation; not online-approved. */
    FIXED_LIMB_DETERMINISTIC_V1_COMPATIBILITY,

    /**
     * Hedged fixed-limb candidate used only for validation and external review. It is not a
     * validated dedicated-host release profile.
     */
    HEDGED_DEDICATED_HOST_CANDIDATE
}
