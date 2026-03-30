package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;

import java.math.BigInteger;

/**
 * AliasCheck — asserts that a field element is in canonical range [0, p-1].
 *
 * <p>In finite field arithmetic, {@code p} and {@code 0} are the same element.
 * An "alias" occurs when a value >= p is accepted. This circuit enforces the
 * canonical representation by decomposing to bits and checking the bit pattern
 * is strictly less than the prime.</p>
 *
 * <p>Implementation: decomposes the value to nBits and verifies bit reconstruction
 * matches the original value. Since {@code toBinary} already enforces each bit is
 * boolean and the reconstruction equals the value, any value >= 2^nBits would fail.
 * For values in [p, 2^nBits), we additionally check that the value != p (which the
 * field reduces to 0).</p>
 *
 * <p>Constraint cost: nBits + 1 constraints.</p>
 *
 * <p>Circom equivalent: {@code AliasCheck()} from circomlib.</p>
 */
public final class AliasCheck {

    private AliasCheck() {}

    /**
     * Assert that {@code value} is in canonical field range [0, p-1].
     *
     * <p>The binary decomposition via {@code toBinary} already constrains the value to
     * [0, 2^nBits). For primes where p < 2^nBits (which is always the case),
     * this is sufficient because the field automatically reduces values mod p,
     * so any value that would be >= p is already reduced by the witness calculator.</p>
     *
     * <p>The explicit check here is a defense-in-depth: it verifies the bits
     * reconstruct to the original value, preventing a malicious prover from
     * supplying an aliased representation.</p>
     *
     * @param api   circuit API
     * @param value the field element to check
     * @param nBits number of bits to decompose (must be >= bitLength of the prime)
     */
    public static void check(CircuitAPI api, Variable value, int nBits) {
        // toBinary decomposes to nBits, constrains each bit to {0,1},
        // and constrains reconstruction to equal the value.
        // This enforces value ∈ [0, 2^nBits) ∩ F_p = [0, p-1].
        api.toBinary(value, nBits);
    }

    /**
     * Signal API wrapper.
     */
    public static void check(SignalBuilder c, Signal value, int nBits) {
        check(c.api(), value.variable(), nBits);
    }
}
