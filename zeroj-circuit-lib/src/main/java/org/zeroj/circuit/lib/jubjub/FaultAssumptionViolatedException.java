package org.zeroj.circuit.lib.jubjub;

/**
 * A threshold key generation aborted because something happened that cannot happen while at
 * most {@code t} participants are faulty and broadcast has agreement
 * ({@code elgamal-jubjub-threshold-v1} §5.1, ADR-0053 D1a and invariant I13).
 *
 * <p>The run is not repaired: no dealer is silently excluded and the session is not restarted.
 * A new attempt needs a new session.
 */
public final class FaultAssumptionViolatedException extends RuntimeException {

    /** The abort condition of spec §5.1. */
    public enum Reason {
        /** A1: fewer than {@code n − t} dealers qualified. */
        TOO_FEW_QUALIFIED,
        /** A2: this participant's own dealing was disqualified. */
        OWN_DEALING_DISQUALIFIED,
        /** A3: a marked dealer has fewer than {@code t + 1} valid reconstruction pairs. */
        TOO_FEW_RECONSTRUCTION_PAIRS,
        /** A4: valid pairs disagree, or do not reproduce the commitments. */
        INCONSISTENT_RECONSTRUCTION,
        /** A5: the joint key is the identity. */
        IDENTITY_JOINT_KEY,
        /** A6: this participant's share does not match its verification key. */
        SHARE_MISMATCH,
        /** A7: a qualified participant confirmed a different transcript or key. */
        CONFLICTING_CONFIRMATION,
        /** A8: this participant's own dealing was marked for reconstruction. */
        OWN_DEALING_MARKED,
        /** A9: this participant's own complaint is missing from its delivered round-2 set. */
        OWN_COMPLAINT_MISSING
    }

    private final Reason reason;

    public FaultAssumptionViolatedException(Reason reason, String detail) {
        super("fault assumption violated (" + reason + "): " + detail);
        this.reason = reason;
    }

    /** Which abort condition fired. */
    public Reason reason() {
        return reason;
    }
}
