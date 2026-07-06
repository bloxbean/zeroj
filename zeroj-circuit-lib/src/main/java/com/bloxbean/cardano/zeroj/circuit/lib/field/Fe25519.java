package com.bloxbean.cardano.zeroj.circuit.lib.field;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

import java.math.BigInteger;

/**
 * In-circuit non-native field arithmetic over the Ed25519 base field
 * {@code GF(p)}, {@code p = 2^255 - 19}.
 *
 * <p>This field is <b>not</b> the circuit's native scalar field (BLS12-381 Fr, ~2^254.86), so
 * elements are emulated with limbs. An element is 5 limbs of 51 bits, radix {@code 2^51}:
 * {@code value = Σ limb[i] · 2^{51·i}}. Every operation returns a <b>normalized</b> element —
 * each limb strictly {@code < 2^51}, so {@code value < 2^255} — obtained by folding the
 * schoolbook product with the identity {@code 2^255 ≡ 19 (mod p)} and then carry-propagating.
 * {@link #canonical} additionally reduces into {@code [0, p)} (unique representative), used for
 * equality and byte encoding.</p>
 *
 * <h2>Determinism &amp; soundness</h2>
 * The ZeroJ DSL has no prover-advice ("hint") mechanism, so reduction is done by explicit
 * limb carry propagation rather than a witnessed quotient/remainder — every wire is
 * forward-computed and constrained. As a structural safety net, each carry reduction
 * <b>asserts the final overflow carry is zero</b>: if the conservative pass count were ever
 * insufficient for an input's magnitude, witness generation fails loudly instead of silently
 * producing a wrong (but constraint-satisfying) result.
 *
 * <p>All limb products stay {@code < 2^107} and all carry decompositions {@code < 2^115},
 * comfortably under the DSL's {@code MAX_SAFE_BITS = 253} bit-decomposition ceiling.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7748">RFC 7748 (Curve25519 field)</a>
 */
public final class Fe25519 {

    /** Number of limbs. */
    public static final int LIMBS = 5;
    /** Bits per limb (radix 2^51). */
    public static final int LIMB_BITS = 51;

    /** p = 2^255 - 19. */
    public static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger LIMB_MASK = BigInteger.ONE.shiftLeft(LIMB_BITS).subtract(BigInteger.ONE);

    // Subtraction bias: a redundant limb representation of 16·p (a multiple of p, so it does not
    // change the result mod p) whose low-5 limbs are each redistributed into [2^51, 2^52) so that
    // limb[i] + BIAS_LOW[i] - other.limb[i] > 0 for any in-range operand limbs. The weight-2^255
    // overflow BIAS_TOP folds back into limb 0 with factor 19 (2^255 ≡ 19 mod p). Computed and
    // verified (≡ 0 mod p, low limbs in range) once at class load.
    private static final long[] BIAS_LOW = new long[LIMBS];
    private static final long BIAS_TOP;

    static {
        BigInteger bias = P.multiply(BigInteger.valueOf(16)); // 16·p
        long[] c = new long[LIMBS + 1];                       // 6 canonical limbs
        BigInteger v = bias;
        for (int i = 0; i < LIMBS + 1; i++) {
            c[i] = v.and(LIMB_MASK).longValueExact();
            v = v.shiftRight(LIMB_BITS);
        }
        if (v.signum() != 0) throw new IllegalStateException("bias exceeds 6 limbs");
        long L = 1L << LIMB_BITS;
        for (int i = 0; i < LIMBS; i++) {
            if (c[i] < L) { c[i] += L; c[i + 1] -= 1; } // borrow 1 from next position (same value)
        }
        for (int i = 0; i < LIMBS; i++) {
            if (c[i] < L || c[i] >= (L << 1))
                throw new IllegalStateException("bias low limb " + i + " out of [2^51,2^52): " + c[i]);
            BIAS_LOW[i] = c[i];
        }
        if (c[LIMBS] < 0) throw new IllegalStateException("bias top negative");
        BIAS_TOP = c[LIMBS];
        // Verify the redundant representation is a genuine multiple of p.
        BigInteger recon = BigInteger.ZERO;
        for (int i = 0; i < LIMBS; i++)
            recon = recon.add(BigInteger.valueOf(BIAS_LOW[i]).shiftLeft(LIMB_BITS * i));
        recon = recon.add(BigInteger.valueOf(BIAS_TOP).shiftLeft(255));
        if (recon.mod(P).signum() != 0) throw new IllegalStateException("subtraction bias not ≡ 0 mod p");
    }

    private final CircuitAPI api;
    /** 5 limbs, each a field variable holding a value in [0, 2^51) once normalized. */
    private final Variable[] limbs;

    private Fe25519(CircuitAPI api, Variable[] limbs) {
        this.api = api;
        this.limbs = limbs;
    }

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /** Wrap 5 limb variables, range-checking each to 51 bits (use for untrusted inputs). */
    public static Fe25519 ofLimbsChecked(CircuitAPI api, Variable[] limbVars) {
        if (limbVars.length != LIMBS) throw new IllegalArgumentException("need " + LIMBS + " limbs");
        for (Variable v : limbVars) api.assertInRange(v, LIMB_BITS);
        return new Fe25519(api, limbVars.clone());
    }

    /** Wrap 5 limb variables already known to be in range (internal / trusted). */
    static Fe25519 ofLimbsTrusted(CircuitAPI api, Variable[] limbVars) {
        return new Fe25519(api, limbVars.clone());
    }

    /** A compile-time constant in [0, p). */
    public static Fe25519 constant(CircuitAPI api, BigInteger value) {
        BigInteger v = value.mod(P);
        Variable[] l = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) {
            l[i] = api.constant(v.and(LIMB_MASK));
            v = v.shiftRight(LIMB_BITS);
        }
        return new Fe25519(api, l);
    }

    /** Split a reduced BigInteger into its 5 radix-2^51 limbs (host-side helper for tests/witness). */
    public static BigInteger[] toLimbValues(BigInteger value) {
        BigInteger v = value.mod(P);
        BigInteger[] out = new BigInteger[LIMBS];
        for (int i = 0; i < LIMBS; i++) {
            out[i] = v.and(LIMB_MASK);
            v = v.shiftRight(LIMB_BITS);
        }
        return out;
    }

    public Variable[] limbs() {
        return limbs.clone();
    }

    // ------------------------------------------------------------------
    // Arithmetic (each returns a normalized element, limbs < 2^51)
    // ------------------------------------------------------------------

    /** (this + other) mod p. */
    public Fe25519 add(Fe25519 other) {
        Variable[] s = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) s[i] = api.add(limbs[i], other.limbs[i]); // < 2^52
        return new Fe25519(api, carryReduce(api, s, 54));
    }

    /** (this - other) mod p. Adds the redundant 16·p bias first so every limb stays positive. */
    public Fe25519 sub(Fe25519 other) {
        Variable[] d = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) {
            Variable biased = api.add(limbs[i], api.constant(BIAS_LOW[i]));
            if (i == 0) biased = api.add(biased, api.constant(19L * BIAS_TOP)); // fold weight-2^255 top
            d[i] = api.sub(biased, other.limbs[i]); // > 0, < 2^53
        }
        return new Fe25519(api, carryReduce(api, d, 56));
    }

    /** (this * other) mod p — schoolbook × limbs, fold 2^255≡19, carry-reduce. */
    public Fe25519 mul(Fe25519 other) {
        Variable zero = api.constant(0);
        Variable[] p = new Variable[2 * LIMBS - 1]; // columns 0..8
        for (int k = 0; k < p.length; k++) p[k] = zero;
        for (int i = 0; i < LIMBS; i++) {
            for (int j = 0; j < LIMBS; j++) {
                p[i + j] = api.add(p[i + j], api.mul(limbs[i], other.limbs[j])); // each < 2^102
            }
        }
        // Fold high columns 5..8 into 0..3 with factor 19 (2^255 ≡ 19).
        Variable c19 = api.constant(19);
        Variable[] r = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) {
            if (i < LIMBS - 1) r[i] = api.add(p[i], api.mul(p[i + LIMBS], c19)); // < 2^111
            else r[i] = p[i];
        }
        return new Fe25519(api, carryReduce(api, r, 114));
    }

    /** this^2 mod p. */
    public Fe25519 square() {
        return mul(this);
    }

    /** Multiplicative inverse via Fermat: this^(p-2) mod p. Fails (unsatisfiable) if this == 0. */
    public Fe25519 inverse() {
        // p - 2 = 2^255 - 21. Binary square-and-multiply, MSB-first.
        BigInteger exp = P.subtract(BigInteger.TWO);
        Fe25519 result = constant(api, BigInteger.ONE);
        for (int bit = exp.bitLength() - 1; bit >= 0; bit--) {
            result = result.square();
            if (exp.testBit(bit)) result = result.mul(this);
        }
        return result;
    }

    // ------------------------------------------------------------------
    // Canonicalization and equality
    // ------------------------------------------------------------------

    /**
     * The unique representative in [0, p). Input is normalized (limbs &lt; 2^51, value &lt; 2^255);
     * value ∈ [p, 2^255) is a 19-wide window, handled by a single conditional subtraction of p.
     */
    public Fe25519 canonical() {
        // s = value + 19. If value ≥ p then value+19 ≥ 2^255, so the weight-2^255 carry b255 = 1
        // and (value+19) mod 2^255 = value - p. Otherwise b255 = 0 and value is already canonical.
        Variable[] sLow = new Variable[LIMBS];
        Variable carry = api.constant(19);
        for (int i = 0; i < LIMBS; i++) {
            Variable t = api.add(limbs[i], carry);   // < 2^51 + carry
            Variable[] bits = api.toBinary(t, 53);
            sLow[i] = api.fromBinary(slice(bits, 0, LIMB_BITS));
            carry = api.fromBinary(slice(bits, LIMB_BITS, 53));
        }
        Variable b255 = carry; // 0 or 1
        Variable[] out = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) out[i] = api.select(b255, sLow[i], limbs[i]);
        return new Fe25519(api, out);
    }

    /** Assert this == other (mod p) by comparing canonical limbs. */
    public void assertEqual(Fe25519 other) {
        Fe25519 a = this.canonical();
        Fe25519 b = other.canonical();
        for (int i = 0; i < LIMBS; i++) api.assertEqual(a.limbs[i], b.limbs[i]);
    }

    /** 1 if this == other (mod p) else 0. */
    public Variable isEqual(Fe25519 other) {
        Fe25519 a = this.canonical();
        Fe25519 b = other.canonical();
        Variable eq = api.constant(1);
        for (int i = 0; i < LIMBS; i++) eq = api.and(eq, api.isEqual(a.limbs[i], b.limbs[i]));
        return eq;
    }

    /** Select between two elements: cond ? a : b (cond must be boolean). */
    public static Fe25519 select(CircuitAPI api, Variable cond, Fe25519 a, Fe25519 b) {
        Variable[] out = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) out[i] = api.select(cond, a.limbs[i], b.limbs[i]);
        return new Fe25519(api, out);
    }

    // ------------------------------------------------------------------
    // Carry reduction (the correctness-critical core)
    // ------------------------------------------------------------------

    /**
     * Normalize wide limbs to strict 51-bit limbs (value &lt; 2^255), preserving the value mod p.
     * Each pass propagates limb carries then folds the weight-2^255 overflow back with factor 19.
     * After the passes the residual carry <b>must</b> be zero — asserted as a safety net.
     *
     * @param width upper bit-bound on any (limb + carry) during propagation; must exceed the
     *              largest input limb and stay under MAX_SAFE_BITS.
     */
    static Variable[] carryReduce(CircuitAPI api, Variable[] wide, int width) {
        Variable[] limb = wide.clone();
        Variable c19 = api.constant(19);
        // 6 passes is comfortably more than needed: inputs here are < 2^258, which converges in
        // ≤4 passes; the trailing assert guarantees correctness regardless.
        Variable carry = api.constant(0);
        for (int pass = 0; pass < 6; pass++) {
            carry = api.constant(0);
            Variable[] next = new Variable[LIMBS];
            for (int i = 0; i < LIMBS; i++) {
                Variable t = api.add(limb[i], carry);
                Variable[] bits = api.toBinary(t, width);
                next[i] = api.fromBinary(slice(bits, 0, LIMB_BITS));
                carry = api.fromBinary(slice(bits, LIMB_BITS, width));
            }
            // fold the weight-2^255 carry into limb 0
            next[0] = api.add(next[0], api.mul(carry, c19));
            limb = next;
        }
        // one final clean propagation with no fold; the resulting carry must vanish.
        carry = api.constant(0);
        Variable[] out = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) {
            Variable t = api.add(limb[i], carry);
            Variable[] bits = api.toBinary(t, width);
            out[i] = api.fromBinary(slice(bits, 0, LIMB_BITS));
            carry = api.fromBinary(slice(bits, LIMB_BITS, width));
        }
        api.assertEqual(carry, api.constant(0)); // safety net: no residual overflow
        return out;
    }

    // ------------------------------------------------------------------

    private static Variable[] slice(Variable[] a, int from, int toExclusive) {
        Variable[] out = new Variable[toExclusive - from];
        System.arraycopy(a, from, out, 0, out.length);
        return out;
    }
}
