package com.bloxbean.cardano.zeroj.circuit.lib.field;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Gate;
import com.bloxbean.cardano.zeroj.circuit.Variable;

import java.math.BigInteger;

/**
 * In-circuit non-native field arithmetic over the Ed25519 base field
 * {@code GF(p)}, {@code p = 2^255 - 19}.
 *
 * <p>This field is <b>not</b> the circuit's native scalar field (BLS12-381 Fr, ~2^254.86), so
 * elements are emulated with 5 limbs of 51 bits, radix {@code 2^51}: {@code value = Σ limb[i]·2^{51i}}.</p>
 *
 * <h2>Overflow tracking &amp; lazy reduction (ADR-0028 Phase B)</h2>
 * Each element carries an {@code overflow} count: every limb is {@code < 2^{51+overflow}}. A
 * <b>normalized</b> element has {@code overflow == 0} (limbs {@code < 2^51}, value {@code < 2^255}).
 * The eager {@link #add}/{@link #sub}/{@link #mul} return normalized elements (frozen, unchanged
 * behavior, still cross-checked vs {@link BigInteger}). The lazy {@link #addLazy}/{@link #subLazy}
 * skip the carry-reduction and merely grow the overflow — nearly free — deferring normalization
 * until a {@link #mul}, {@link #canonical}, or equality needs it. {@code mul} accepts loosely
 * reduced operands directly (only reducing past a safety cap) and always returns a normalized
 * result; its reduced-operand path is bit-identical to before.
 *
 * <h2>Determinism &amp; soundness</h2>
 * The DSL has no prover-advice, so reduction is deterministic limb carry-propagation. Each
 * reduction <b>asserts the final overflow carry is zero</b> — if the pass count or a width were
 * ever insufficient, witness generation fails loudly rather than producing a wrong-but-satisfiable
 * result. Overflow bounds are tracked so no operation exceeds the native field or the
 * {@code MAX_SAFE_BITS = 253} bit-decomposition ceiling; exceeding {@link #MAX_MUL_OVERFLOW}
 * forces a reduction first.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7748">RFC 7748 (Curve25519 field)</a>
 */
public final class Fe25519 {

    /** Number of limbs. */
    public static final int LIMBS = 5;
    /** Bits per limb (radix 2^51). */
    public static final int LIMB_BITS = 51;
    /** Max operand overflow {@link #mul} accepts before force-reducing (keeps widths well under 253). */
    static final int MAX_MUL_OVERFLOW = 6;
    /**
     * Explicit ceiling on the {@link #overflow} a lazy op may produce (ADR-0028 pillar 3:
     * loud magnitude bound). Far below the ~195 point where the {@code toBinary} width guard
     * would trip and the ~204 point where the native field could wrap, so a pathological lazy
     * chain fails early and clearly instead of relying on the downstream guard. Real gadgets
     * (Ed25519 point-add) stay ≤ ~2; anything approaching this ceiling is misuse.
     */
    static final int MAX_OVERFLOW = 96;

    /** p = 2^255 - 19. */
    public static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger LIMB_MASK = BigInteger.ONE.shiftLeft(LIMB_BITS).subtract(BigInteger.ONE);

    // Subtraction bias: a redundant limb representation of 16·p (a multiple of p) whose low-5 limbs
    // are each redistributed into [2^51, 2^52) so that limb[i] + BIAS_LOW[i] - other.limb[i] > 0 for
    // any reduced operand limb. The weight-2^255 overflow BIAS_TOP folds into limb 0 with factor 19.
    private static final long[] BIAS_LOW = new long[LIMBS];
    private static final long BIAS_TOP;

    static {
        BigInteger bias = P.multiply(BigInteger.valueOf(16)); // 16·p
        long[] c = new long[LIMBS + 1];
        BigInteger v = bias;
        for (int i = 0; i < LIMBS + 1; i++) { c[i] = v.and(LIMB_MASK).longValueExact(); v = v.shiftRight(LIMB_BITS); }
        if (v.signum() != 0) throw new IllegalStateException("bias exceeds 6 limbs");
        long L = 1L << LIMB_BITS;
        for (int i = 0; i < LIMBS; i++) if (c[i] < L) { c[i] += L; c[i + 1] -= 1; }
        for (int i = 0; i < LIMBS; i++) {
            if (c[i] < L || c[i] >= (L << 1))
                throw new IllegalStateException("bias low limb " + i + " out of [2^51,2^52): " + c[i]);
            BIAS_LOW[i] = c[i];
        }
        if (c[LIMBS] < 0) throw new IllegalStateException("bias top negative");
        BIAS_TOP = c[LIMBS];
        BigInteger recon = BigInteger.ZERO;
        for (int i = 0; i < LIMBS; i++) recon = recon.add(BigInteger.valueOf(BIAS_LOW[i]).shiftLeft(LIMB_BITS * i));
        recon = recon.add(BigInteger.valueOf(BIAS_TOP).shiftLeft(255));
        if (recon.mod(P).signum() != 0) throw new IllegalStateException("subtraction bias not ≡ 0 mod p");
    }

    private final CircuitAPI api;
    private final Variable[] limbs;
    /** Each limb is {@code < 2^{51+overflow}}. 0 = normalized. */
    private final int overflow;

    private Fe25519(CircuitAPI api, Variable[] limbs, int overflow) {
        this.api = api;
        this.limbs = limbs;
        this.overflow = overflow;
    }

    // ------------------------------------------------------------------
    // Construction (all normalized: overflow 0)
    // ------------------------------------------------------------------

    /** Wrap 5 limb variables, range-checking each to 51 bits (use for untrusted inputs). */
    public static Fe25519 ofLimbsChecked(CircuitAPI api, Variable[] limbVars) {
        if (limbVars.length != LIMBS) throw new IllegalArgumentException("need " + LIMBS + " limbs");
        for (Variable v : limbVars) api.assertInRange(v, LIMB_BITS);
        return new Fe25519(api, limbVars.clone(), 0);
    }

    /** Wrap 5 limb variables already known to be in range (internal / trusted). */
    static Fe25519 ofLimbsTrusted(CircuitAPI api, Variable[] limbVars) {
        return new Fe25519(api, limbVars.clone(), 0);
    }

    /** A compile-time constant in [0, p). */
    public static Fe25519 constant(CircuitAPI api, BigInteger value) {
        BigInteger v = value.mod(P);
        Variable[] l = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) { l[i] = api.constant(v.and(LIMB_MASK)); v = v.shiftRight(LIMB_BITS); }
        return new Fe25519(api, l, 0);
    }

    /** Split a reduced BigInteger into its 5 radix-2^51 limbs (host-side helper for tests/witness). */
    public static BigInteger[] toLimbValues(BigInteger value) {
        BigInteger v = value.mod(P);
        BigInteger[] out = new BigInteger[LIMBS];
        for (int i = 0; i < LIMBS; i++) { out[i] = v.and(LIMB_MASK); v = v.shiftRight(LIMB_BITS); }
        return out;
    }

    public Variable[] limbs() { return limbs.clone(); }
    int overflow() { return overflow; }

    // ------------------------------------------------------------------
    // Eager arithmetic (frozen — returns normalized elements, cross-checked vs BigInteger)
    // ------------------------------------------------------------------

    /** (this + other) mod p, normalized. */
    public Fe25519 add(Fe25519 other) { return addLazy(other).reduce(); }

    /** (this - other) mod p, normalized. */
    public Fe25519 sub(Fe25519 other) { return subLazy(other).reduce(); }

    /**
     * ADR-0028 Phase C opt-in: when {@code true}, {@link #mul} routes through the hint-based
     * {@link #mulHint}. <b>AUDIT-GATED — do not enable in production until the hint path's
     * integer-identity argument is externally audited</b> (ADR-0028 pillar 5). Default {@code false}
     * keeps the deterministic path. Used by tests to measure/validate the wired end-to-end circuit.
     */
    public static volatile boolean USE_HINT_MUL = false;

    /** (this * other) mod p, normalized. */
    public Fe25519 mul(Fe25519 other) {
        if (USE_HINT_MUL) return mulHint(other);
        Fe25519 a = (this.overflow > MAX_MUL_OVERFLOW) ? this.reduce() : this;
        Fe25519 b = (other.overflow > MAX_MUL_OVERFLOW) ? other.reduce() : other;

        Variable zero = api.constant(0);
        Variable[] p = new Variable[2 * LIMBS - 1];
        for (int k = 0; k < p.length; k++) p[k] = zero;
        for (int i = 0; i < LIMBS; i++)
            for (int j = 0; j < LIMBS; j++)
                p[i + j] = api.add(p[i + j], api.mul(a.limbs[i], b.limbs[j]));
        Variable c19 = api.constant(19);
        Variable[] r = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++)
            r[i] = (i < LIMBS - 1) ? api.add(p[i], api.mul(p[i + LIMBS], c19)) : p[i];
        // fold value < 2^{110 + overflow(a) + overflow(b)}; +4 bits margin. overflow(0,0) => 114 (unchanged).
        int width = 110 + a.overflow + b.overflow + 4;
        return new Fe25519(api, carryReduce(api, r, width, 6), 0);
    }

    /** this^2 mod p, normalized. */
    public Fe25519 square() { return mul(this); }

    // ------------------------------------------------------------------
    // Hint-based multiplication (ADR-0028 Phase C — AUDIT-GATED)
    // ------------------------------------------------------------------

    // Constant limbs of p, the subtraction-free product-check offset, and the target digits of
    // OFF·S (S = Σ_{k=0}^{8} 2^{51k}) for the integer-identity carry chain.
    private static final long[] P_LIMB = new long[LIMBS];
    private static final BigInteger MUL_OFFSET = BigInteger.ONE.shiftLeft(106); // ≥ max column of q·p+r
    private static final BigInteger[] TARGET_DIGIT = new BigInteger[2 * LIMBS - 1];
    private static final BigInteger TARGET_HIGH;
    private static final int MUL_CHECK_WIDTH = 112; // > max (column + carry) ≈ 2^108
    static {
        for (int i = 0; i < LIMBS; i++) P_LIMB[i] = P.shiftRight(LIMB_BITS * i).and(LIMB_MASK).longValueExact();
        BigInteger s = BigInteger.ZERO;
        for (int k = 0; k < 2 * LIMBS - 1; k++) s = s.add(BigInteger.ONE.shiftLeft(LIMB_BITS * k));
        BigInteger target = MUL_OFFSET.multiply(s);
        for (int k = 0; k < 2 * LIMBS - 1; k++) TARGET_DIGIT[k] = target.shiftRight(LIMB_BITS * k).and(LIMB_MASK);
        TARGET_HIGH = target.shiftRight(LIMB_BITS * (2 * LIMBS - 1));
    }

    /**
     * (this * other) mod p using prover-supplied advice (ADR-0028 Phase C). The prover supplies the
     * quotient/remainder of the integer product via a {@link Gate.HintKind#MUL_MOD_REDUCE} hint;
     * {@link #mulFromQR} then range-checks them, forces {@code r < p}, and enforces
     * {@code a·b = q·p + r} <b>over the integers</b>. Operands are canonicalized ({@code < p}) so
     * {@code q} fits 5 limbs.
     *
     * <p><b>AUDIT-GATED (ADR-0028 pillar 5):</b> the hint path is not yet audited; it is behind an
     * explicit opt-in and the deterministic {@link #mul} remains the default until an external audit
     * of the integer-identity argument clears.</p>
     */
    public Fe25519 mulHint(Fe25519 other) {
        Variable[] a = this.canonical().limbs;
        Variable[] b = other.canonical().limbs;
        Variable[] inputs = new Variable[2 * LIMBS];
        System.arraycopy(a, 0, inputs, 0, LIMBS);
        System.arraycopy(b, 0, inputs, LIMBS, LIMBS);
        BigInteger[] params = {P, BigInteger.valueOf(LIMB_BITS), BigInteger.valueOf(LIMBS)};
        Variable[] hint = api.hintN(Gate.HintKind.MUL_MOD_REDUCE, params, 2 * LIMBS, inputs);
        Variable[] q = slice(hint, 0, LIMBS);
        Variable[] r = slice(hint, LIMBS, 2 * LIMBS);
        return mulFromQR(api, a, b, q, r);
    }

    /**
     * Enforce {@code a·b = q·p + r} with {@code 0 ≤ r < p} for the given (already 51-bit) operand
     * limbs and candidate {@code q, r}, returning {@code r} as the normalized product. Package-visible
     * so soundness tests can feed <b>adversarial</b> {@code q, r} directly (the hint is bypassed) and
     * assert rejection — the soundness of the whole scheme lives entirely in these constraints.
     *
     * <p>Soundness rests on: (1) every {@code q, r} limb is range-checked to 51 bits, bounding each
     * product column {@code < 2^106} so it never wraps the native field; (2) {@code r < p} makes the
     * remainder unique; (3) the identity is checked <b>over the integers</b> — the carry chain keeps
     * every intermediate {@code < 2^112 ≪ nativeP}, so a difference of any nonzero multiple of the
     * native modulus cannot hide.</p>
     */
    static Fe25519 mulFromQR(CircuitAPI api, Variable[] a, Variable[] b, Variable[] q, Variable[] r) {
        // Range-check ALL operands to 51 bits so the gadget is self-contained: the magnitude
        // bounds the integer-identity check relies on (dk > 0, t < 2^112) require a,b limbs < 2^51,
        // not just q,r. (mulHint already passes canonical() limbs; this hardens direct callers.)
        for (Variable v : a) api.assertInRange(v, LIMB_BITS);
        for (Variable v : b) api.assertInRange(v, LIMB_BITS);
        for (Variable v : q) api.assertInRange(v, LIMB_BITS);
        for (Variable v : r) api.assertInRange(v, LIMB_BITS);
        assertLessThanP(api, r);

        Variable zero = api.constant(0);
        Variable[] lhs = new Variable[2 * LIMBS - 1];
        Variable[] rhs = new Variable[2 * LIMBS - 1];
        for (int k = 0; k < lhs.length; k++) { lhs[k] = zero; rhs[k] = zero; }
        for (int i = 0; i < LIMBS; i++) {
            for (int j = 0; j < LIMBS; j++) {
                lhs[i + j] = api.add(lhs[i + j], api.mul(a[i], b[j]));              // a·b columns
                rhs[i + j] = api.add(rhs[i + j], api.mul(q[i], api.constant(P_LIMB[j]))); // q·p columns
            }
        }
        for (int k = 0; k < LIMBS; k++) rhs[k] = api.add(rhs[k], r[k]);            // + r

        // Verify Σ_k (lhs[k] + OFF − rhs[k])·2^{51k} == OFF·S over the integers via a positive carry
        // chain: each digit must equal OFF·S's digit and the final carry its high part.
        Variable off = api.constant(MUL_OFFSET);
        Variable carry = zero;
        for (int k = 0; k < 2 * LIMBS - 1; k++) {
            Variable dk = api.sub(api.add(lhs[k], off), rhs[k]); // > 0, < 2^107
            Variable t = api.add(dk, carry);
            Variable[] bits = api.toBinary(t, MUL_CHECK_WIDTH);
            Variable low = api.fromBinary(slice(bits, 0, LIMB_BITS));
            carry = api.fromBinary(slice(bits, LIMB_BITS, MUL_CHECK_WIDTH));
            api.assertEqual(low, api.constant(TARGET_DIGIT[k]));
        }
        api.assertEqual(carry, api.constant(TARGET_HIGH));
        return new Fe25519(api, r.clone(), 0);
    }

    /** Assert the value in {@code r} (5 limbs < 2^51) is strictly less than p. */
    static void assertLessThanP(CircuitAPI api, Variable[] r) {
        Variable carry = api.constant(19); // r + 19 < 2^255  ⟺  r < p
        for (int i = 0; i < LIMBS; i++) {
            Variable t = api.add(r[i], carry);
            Variable[] bits = api.toBinary(t, 53);
            carry = api.fromBinary(slice(bits, LIMB_BITS, 53));
        }
        api.assertEqual(carry, api.constant(0)); // no weight-2^255 carry ⟹ r < p
    }

    /** Multiplicative inverse via Fermat: this^(p-2) mod p. Fails (unsatisfiable) if this == 0. */
    public Fe25519 inverse() {
        BigInteger exp = P.subtract(BigInteger.TWO);
        Fe25519 result = constant(api, BigInteger.ONE);
        for (int bit = exp.bitLength() - 1; bit >= 0; bit--) {
            result = result.square();
            if (exp.testBit(bit)) result = result.mul(this);
        }
        return result;
    }

    // ------------------------------------------------------------------
    // Lazy arithmetic (ADR-0028 Phase B — no reduction, overflow grows)
    // ------------------------------------------------------------------

    /** (this + other) mod p without normalizing — limbs added, overflow grows by 1. Nearly free. */
    public Fe25519 addLazy(Fe25519 other) {
        int ovf = Math.max(overflow, other.overflow) + 1;
        checkOverflow(ovf);
        Variable[] s = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) s[i] = api.add(limbs[i], other.limbs[i]);
        return new Fe25519(api, s, ovf);
    }

    /**
     * (this - other) mod p without normalizing. {@code other} is reduced so the 16·p bias covers it;
     * {@code this} is kept lazy. Result limbs stay positive and small; overflow grows modestly.
     */
    public Fe25519 subLazy(Fe25519 other) {
        int ovf = Math.max(overflow, 1) + 1;
        checkOverflow(ovf);
        Fe25519 o = (other.overflow == 0) ? other : other.reduce();
        Variable[] d = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) {
            Variable biased = api.add(limbs[i], api.constant(BIAS_LOW[i]));
            if (i == 0) biased = api.add(biased, api.constant(19L * BIAS_TOP));
            d[i] = api.sub(biased, o.limbs[i]); // > 0
        }
        return new Fe25519(api, d, ovf);
    }

    private static void checkOverflow(int ovf) {
        if (ovf > MAX_OVERFLOW)
            throw new IllegalStateException("Fe25519 lazy overflow " + ovf + " exceeds MAX_OVERFLOW "
                    + MAX_OVERFLOW + " — insert a reduce()/mul()/canonical() to normalize sooner");
    }

    /** Normalize to overflow 0 (limbs &lt; 2^51). No-op when already normalized. */
    public Fe25519 reduce() {
        if (overflow == 0) return this;
        int width = LIMB_BITS + overflow + 8; // limbs < 2^{51+overflow}; margin for carries
        return new Fe25519(api, carryReduce(api, limbs.clone(), width, 6), 0);
    }

    // ------------------------------------------------------------------
    // Canonicalization and equality (normalize inputs first)
    // ------------------------------------------------------------------

    /** The unique representative in [0, p). */
    public Fe25519 canonical() {
        Fe25519 n = this.reduce();
        Variable[] sLow = new Variable[LIMBS];
        Variable carry = api.constant(19);
        for (int i = 0; i < LIMBS; i++) {
            Variable t = api.add(n.limbs[i], carry);
            Variable[] bits = api.toBinary(t, 53);
            sLow[i] = api.fromBinary(slice(bits, 0, LIMB_BITS));
            carry = api.fromBinary(slice(bits, LIMB_BITS, 53));
        }
        Variable b255 = carry; // 0 or 1
        Variable[] out = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) out[i] = api.select(b255, sLow[i], n.limbs[i]);
        return new Fe25519(api, out, 0);
    }

    /** Assert this == other (mod p) by comparing canonical limbs. */
    public void assertEqual(Fe25519 other) {
        Fe25519 a = this.canonical(), b = other.canonical();
        for (int i = 0; i < LIMBS; i++) api.assertEqual(a.limbs[i], b.limbs[i]);
    }

    /** 1 if this == other (mod p) else 0. */
    public Variable isEqual(Fe25519 other) {
        Fe25519 a = this.canonical(), b = other.canonical();
        Variable eq = api.constant(1);
        for (int i = 0; i < LIMBS; i++) eq = api.and(eq, api.isEqual(a.limbs[i], b.limbs[i]));
        return eq;
    }

    /** Select between two elements: cond ? a : b (cond must be boolean). */
    public static Fe25519 select(CircuitAPI api, Variable cond, Fe25519 a, Fe25519 b) {
        Variable[] out = new Variable[LIMBS];
        for (int i = 0; i < LIMBS; i++) out[i] = api.select(cond, a.limbs[i], b.limbs[i]);
        return new Fe25519(api, out, Math.max(a.overflow, b.overflow));
    }

    // ------------------------------------------------------------------
    // Carry reduction (the correctness-critical core)
    // ------------------------------------------------------------------

    /**
     * Normalize wide limbs to strict 51-bit limbs (value &lt; 2^255), preserving the value mod p.
     * Each pass propagates limb carries then folds the weight-2^255 overflow back with factor 19;
     * a final fold-free pass must leave zero residual carry — asserted as the safety net.
     *
     * @param width upper bit-bound on any (limb + carry) during propagation; must exceed the largest
     *              input limb and stay under MAX_SAFE_BITS (253).
     * @param foldPasses number of fold passes before the final clean pass.
     */
    static Variable[] carryReduce(CircuitAPI api, Variable[] wide, int width, int foldPasses) {
        if (width > 253) throw new IllegalArgumentException("carryReduce width " + width + " exceeds MAX_SAFE_BITS");
        Variable[] limb = wide.clone();
        Variable c19 = api.constant(19);
        for (int pass = 0; pass < foldPasses; pass++) {
            Variable carry = api.constant(0);
            Variable[] next = new Variable[LIMBS];
            for (int i = 0; i < LIMBS; i++) {
                Variable t = api.add(limb[i], carry);
                Variable[] bits = api.toBinary(t, width);
                next[i] = api.fromBinary(slice(bits, 0, LIMB_BITS));
                carry = api.fromBinary(slice(bits, LIMB_BITS, width));
            }
            next[0] = api.add(next[0], api.mul(carry, c19)); // fold weight-2^255 carry into limb 0
            limb = next;
        }
        Variable carry = api.constant(0);
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

    private static Variable[] slice(Variable[] a, int from, int toExclusive) {
        Variable[] out = new Variable[toExclusive - from];
        System.arraycopy(a, from, out, 0, out.length);
        return out;
    }
}
