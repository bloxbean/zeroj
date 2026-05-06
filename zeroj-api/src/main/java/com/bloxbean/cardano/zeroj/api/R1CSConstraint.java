package com.bloxbean.cardano.zeroj.api;

import java.math.BigInteger;
import java.util.Map;

/**
 * A single R1CS (Rank-1 Constraint System) constraint of the form
 * {@code (A · w) × (B · w) = (C · w)}, where {@code A}, {@code B}, and
 * {@code C} are sparse vectors mapping wire indices to field coefficients
 * and {@code w} is the witness vector.
 */
public record R1CSConstraint(
        Map<Integer, BigInteger> a,
        Map<Integer, BigInteger> b,
        Map<Integer, BigInteger> c
) {}
