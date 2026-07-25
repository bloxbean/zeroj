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

    /**
     * Poseidon permutation over a state of arbitrary width {@code t}, the off-circuit
     * counterpart of {@code Poseidon.permute}.
     *
     * <p>ZeroJ sponge convention: {@code state[0]} is the capacity cell (zero, or a domain
     * tag) and {@code state[1..t-1]} are rate cells; the hash output is {@code state[0]}
     * after permuting.
     *
     * @param state input state of length {@code params.t()}; not modified
     * @return the permuted state, a fresh array
     */
    public static BigInteger[] permute(PoseidonParams params, BigInteger[] state) {
        Objects.requireNonNull(params, "params");
        Objects.requireNonNull(state, "state");
        if (params.alpha() != 5) {
            throw new IllegalArgumentException("PoseidonHash supports only alpha=5, got " + params.alpha());
        }
        int t = params.t();
        if (state.length != t) {
            throw new IllegalArgumentException(
                    "state length must equal t=" + t + ", got " + state.length);
        }
        BigInteger p = params.field().prime();
        int rf = params.rf();
        int rp = params.rp();
        int totalRounds = rf + rp;

        BigInteger[] s = new BigInteger[t];
        for (int i = 0; i < t; i++) s[i] = state[i].mod(p);

        for (int r = 0; r < totalRounds; r++) {
            for (int i = 0; i < t; i++) {
                s[i] = s[i].add(params.cAt(r, i)).mod(p);
            }
            boolean fullRound = r < rf / 2 || r >= rf / 2 + rp;
            if (fullRound) {
                for (int i = 0; i < t; i++) s[i] = sbox(s[i], p);
            } else {
                s[0] = sbox(s[0], p);
            }
            BigInteger[] next = new BigInteger[t];
            for (int i = 0; i < t; i++) {
                BigInteger acc = BigInteger.ZERO;
                for (int j = 0; j < t; j++) {
                    acc = acc.add(params.mAt(i, j).multiply(s[j]));
                }
                next[i] = acc.mod(p);
            }
            s = next;
        }
        return s;
    }

    /**
     * Sponge hash of {@code inputs} in a single permutation, with {@code capacity} seeding
     * the capacity cell — the natural place for a domain-separation tag.
     *
     * <p>Requires {@code inputs.length <= params.t() - 1}. Returns {@code state[0]} after
     * permuting. This is the off-circuit counterpart of {@code Poseidon.spongeHash}, and the
     * two must agree exactly for any value used in both places.
     */
    public static BigInteger spongeHash(PoseidonParams params, BigInteger capacity,
                                        BigInteger... inputs) {
        Objects.requireNonNull(params, "params");
        Objects.requireNonNull(capacity, "capacity");
        int t = params.t();
        requireExactRate(t, inputs.length);
        BigInteger[] state = new BigInteger[t];
        state[0] = capacity;
        System.arraycopy(inputs, 0, state, 1, t - 1);
        return permute(params, state)[0];
    }

    /**
     * Requires exactly {@code t-1} inputs — the full rate — rather than zero-padding a short
     * vector.
     *
     * <p>Zero-padding would make this construction length-ambiguous: with no length encoding
     * or padding delimiter, {@code H(x1..xm)} and {@code H(x1..xm, 0)} are the same value for
     * any {@code m < t-1}. That is harmless for the fixed-arity uses in this codebase, but it
     * is a collision waiting for the first caller who absorbs a variable-length vector, and
     * such a caller would get no warning.
     *
     * <p>Rejecting short input costs nothing today (every call site already passes exactly the
     * rate) and forces any future variable-length use to choose an explicit, unambiguous
     * encoding — length-prefixing the vector, or folding the length into the capacity tag —
     * rather than inheriting a silent one.
     *
     * <p>Public so the in-circuit {@code Poseidon.spongeHash} in the sibling package shares
     * this exact definition. A duplicated copy is how the two sides would drift, and a value
     * computed on one side would then fail to reproduce on the other.
     */
    public static void requireExactRate(int t, int suppliedInputs) {
        if (suppliedInputs != t - 1) {
            throw new IllegalArgumentException(
                    "spongeHash requires exactly " + (t - 1) + " inputs for t=" + t
                            + " (the full rate), got " + suppliedInputs
                            + ". Short input is rejected rather than zero-padded, because "
                            + "zero-padding is length-ambiguous: H(x) would equal H(x, 0). "
                            + "Pad explicitly, or use a wider/narrower preset.");
        }
    }

    private static BigInteger sbox(BigInteger x, BigInteger p) {
        BigInteger x2 = x.multiply(x).mod(p);
        BigInteger x4 = x2.multiply(x2).mod(p);
        return x4.multiply(x).mod(p);
    }
}
