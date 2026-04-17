package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Standalone off-circuit Poseidon hash over {@link PoseidonParams}. This is
 * the reference implementation used by application code (hash computation
 * outside the proof) and by tests (oracle to cross-check the in-circuit
 * gadget output).
 *
 * <p>Currently supports {@code t=3, alpha=5} (two-to-one hash). Wider states
 * or different S-boxes require a different driver; the
 * {@link PoseidonGrainLFSR} generator already supports them, but the hash
 * function body here is intentionally specialized for the t=3 case that
 * matches the {@link com.bloxbean.cardano.zeroj.circuit.lib.Poseidon} circuit
 * gadget.
 *
 * <p>All arithmetic is reduced modulo {@code params.field().prime()} — the
 * inputs are reduced on entry, so callers may pass any non-negative
 * BigInteger.
 */
public final class PoseidonHash {

    private PoseidonHash() {}

    /**
     * Hashes two BigInteger inputs into a field element using the Poseidon
     * permutation defined by {@code params}.
     *
     * @param params Poseidon parameters (must have t=3, alpha=5)
     * @param a      first input (reduced mod prime)
     * @param b      second input (reduced mod prime)
     * @return hash output in {@code [0, prime)}
     */
    public static BigInteger hash(PoseidonParams params, BigInteger a, BigInteger b) {
        Objects.requireNonNull(params, "params");
        Objects.requireNonNull(a, "a");
        Objects.requireNonNull(b, "b");
        if (params.t() != 3 || params.alpha() != 5) {
            throw new IllegalArgumentException(
                    "PoseidonHash supports only t=3, alpha=5 (got t=" + params.t()
                            + ", alpha=" + params.alpha() + ")");
        }

        BigInteger p = params.field().prime();
        int rf = params.rf();
        int rp = params.rp();
        int totalRounds = rf + rp;

        BigInteger s0 = BigInteger.ZERO;
        BigInteger s1 = a.mod(p);
        BigInteger s2 = b.mod(p);

        for (int r = 0; r < totalRounds; r++) {
            // AddRoundConstants
            s0 = s0.add(params.cAt(r, 0)).mod(p);
            s1 = s1.add(params.cAt(r, 1)).mod(p);
            s2 = s2.add(params.cAt(r, 2)).mod(p);

            // S-box (x^5)
            if (r < rf / 2 || r >= rf / 2 + rp) {
                s0 = sbox(s0, p);
                s1 = sbox(s1, p);
                s2 = sbox(s2, p);
            } else {
                s0 = sbox(s0, p);
            }

            // MDS matrix multiplication (t=3)
            BigInteger t0 = params.mAt(0, 0).multiply(s0)
                    .add(params.mAt(0, 1).multiply(s1))
                    .add(params.mAt(0, 2).multiply(s2))
                    .mod(p);
            BigInteger t1 = params.mAt(1, 0).multiply(s0)
                    .add(params.mAt(1, 1).multiply(s1))
                    .add(params.mAt(1, 2).multiply(s2))
                    .mod(p);
            BigInteger t2 = params.mAt(2, 0).multiply(s0)
                    .add(params.mAt(2, 1).multiply(s1))
                    .add(params.mAt(2, 2).multiply(s2))
                    .mod(p);
            s0 = t0;
            s1 = t1;
            s2 = t2;
        }

        return s0;
    }

    /**
     * Variable-arity hash matching the left-fold convention used by
     * {@link com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN}. For 0 inputs
     * throws; for 1 input, hashes {@code (x, 0)} — this is a ZeroJ-specific
     * convention, not a published Poseidon spec; see {@link PoseidonN} for
     * the authoritative statement. For N inputs,
     * {@code hash(...hash(hash(a, b), c), ...)}.
     */
    public static BigInteger hashN(PoseidonParams params, BigInteger... inputs) {
        Objects.requireNonNull(params, "params");
        Objects.requireNonNull(inputs, "inputs");
        if (inputs.length == 0) throw new IllegalArgumentException("inputs must not be empty");
        if (inputs.length == 1) {
            return hash(params, inputs[0], BigInteger.ZERO);
        }
        BigInteger acc = hash(params, inputs[0], inputs[1]);
        for (int i = 2; i < inputs.length; i++) {
            acc = hash(params, acc, inputs[i]);
        }
        return acc;
    }

    private static BigInteger sbox(BigInteger x, BigInteger p) {
        BigInteger x2 = x.multiply(x).mod(p);
        BigInteger x4 = x2.multiply(x2).mod(p);
        return x4.multiply(x).mod(p);
    }
}
