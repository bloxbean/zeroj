package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.Objects;

/**
 * A participant's result of threshold key generation: its identifier, its secret share
 * {@code x_j}, and the {@link ThresholdKeyContext} of the run. {@code [x_j]·G} equals the
 * context's verification key {@code Y_j}; the participant checked that before producing this
 * object (abort A6).
 *
 * <p><b>Secret.</b> {@code x_j} is compatibility/offline class (ADR-0039 §3.1). It may be zero,
 * with {@code Y_j = O}, in a valid run. {@link #toString()} redacts it.
 */
public final class ThresholdKeyShare {

    private final ThresholdKeyContext context;
    private final int id;
    private final BigInteger secret;

    ThresholdKeyShare(ThresholdKeyContext context, int id, BigInteger secret) {
        this.context = context;
        this.id = id;
        this.secret = secret;
    }

    /**
     * Restores a participant's share, for example from secure storage between key generation and
     * the tally. Checks that {@code id} is in the context's {@code QUAL} and that
     * {@code [x]·G = Y_id}, on the blinded schedule.
     *
     * @throws IllegalArgumentException if either check fails or {@code x} is not in {@code [0, l)}
     */
    public static ThresholdKeyShare restore(ThresholdKeyContext context, int id, BigInteger x) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(x, "x");
        if (!context.qual().contains(id)) {
            throw new IllegalArgumentException("participant " + id + " is not qualified in this context");
        }
        if (x.signum() < 0 || x.compareTo(JubjubCurve.SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException("the share must satisfy 0 <= x < l");
        }
        if (!JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(x).projectiveEquals(context.verificationKey(id))) {
            throw new IllegalArgumentException("the share does not match participant " + id + "'s verification key");
        }
        return new ThresholdKeyShare(context, id, x);
    }

    /** The key context. */
    public ThresholdKeyContext context() {
        return context;
    }

    /** This participant's identifier. */
    public int id() {
        return id;
    }

    /**
     * {@code x_j}, for building a decryption-share proof witness only (spec §9). Handle it
     * offline or in an isolated process.
     */
    public BigInteger secretScalar() {
        return secret;
    }

    BigInteger secret() {
        return secret;
    }

    @Override
    public String toString() {
        return "ThresholdKeyShare{id=" + id + ", context=" + context + ", secret=<redacted>}";
    }
}
