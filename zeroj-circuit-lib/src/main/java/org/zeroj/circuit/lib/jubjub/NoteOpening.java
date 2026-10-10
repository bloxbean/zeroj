package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * The opening {@code (v, r)} of a {@code pedersen-jubjub-v1} note commitment
 * {@code C = [v]·G + [r]·H}, as {@code confidential-note-jubjub-v1} delivers it (ADR-0055 D6;
 * spec §3.1): a value {@code v ∈ [0, 2^64)} and a blinding {@code r ∈ [0, l)}.
 *
 * <p>Both are secret. {@link #toString()} redacts them. {@code BigInteger} copies cannot be
 * wiped (ADR-0039 §3.1).
 */
public final class NoteOpening {

    /** The largest value a note carries, {@code 2^64 − 1} (ADR-0055 Q8). */
    public static final BigInteger MAX_VALUE = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

    private final BigInteger value;
    private final BigInteger blinding;

    private NoteOpening(BigInteger value, BigInteger blinding) {
        this.value = value;
        this.blinding = blinding;
    }

    /**
     * An opening with a given value and blinding.
     *
     * @throws IllegalArgumentException unless {@code 0 ≤ value < 2^64} and {@code 0 ≤ blinding < l}
     */
    public static NoteOpening of(BigInteger value, BigInteger blinding) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(blinding, "blinding");
        if (value.signum() < 0 || value.compareTo(MAX_VALUE) > 0) {
            throw new IllegalArgumentException("value must satisfy 0 <= v < 2^64");
        }
        if (blinding.signum() < 0 || blinding.compareTo(SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException("blinding must satisfy 0 <= r < l");
        }
        return new NoteOpening(value, blinding);
    }

    /** An opening of {@code value} with a fresh blinding ({@code pedersen-jubjub-v1} §3.1). */
    public static NoteOpening random(BigInteger value, SecureRandom random) {
        return of(value, PedersenCommitment.randomBlinding(Objects.requireNonNull(random, "random")));
    }

    /** The value {@code v}. */
    public BigInteger value() {
        return value;
    }

    /** The blinding {@code r}. */
    public BigInteger blinding() {
        return blinding;
    }

    /** The commitment {@code [v]·G + [r]·H}, computed on the blinded secret-bearing path. */
    public JubjubPoint commitment() {
        return PedersenCommitment.commit(value, blinding);
    }

    @Override
    public String toString() {
        return "NoteOpening{value=<redacted>, blinding=<redacted>}";
    }
}
