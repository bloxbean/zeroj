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

    /**
     * ADR-0028 opt-in: when {@code true}, {@link Ed25519Point#encode}-style inversions route through
     * the hint-based {@link #inverseHint} (~300× cheaper than the Fermat {@link #inverse}).
     * <b>Audit-gated</b> like {@link #USE_HINT_MUL}, though the inverse hint is trivially sound
     * ({@code a·a⁻¹ = 1} uniquely pins the inverse). Its identity check uses the <b>deterministic</b>
     * mul, so it is independent of the CRT-mul audit.
     */
    public static volatile boolean USE_HINT_INVERSE = false;

    /** (this * other) mod p, normalized. Routes to {@link #mulHint} when {@link #USE_HINT_MUL}. */
    public Fe25519 mul(Fe25519 other) {
        return USE_HINT_MUL ? mulHint(other) : mulDeterministic(other);
    }

    /** Deterministic schoolbook multiply (the frozen reference path; never uses advice). */
    Fe25519 mulDeterministic(Fe25519 other) {
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

    /**
     * Multiplicative inverse via prover advice (ADR-0028): the prover supplies {@code a⁻¹} through an
     * {@link Gate.HintKind#INV_MOD} hint and the circuit enforces {@code a · a⁻¹ == 1 (mod p)} — a
     * range-checked, canonical {@code a⁻¹}, one deterministic mul, and one equality — replacing the
     * ~3M-constraint Fermat {@link #inverse}. Fails (unsatisfiable) if {@code this == 0}, as required.
     */
    public Fe25519 inverseHint() {
        Fe25519 a = this.canonical();
        BigInteger[] params = {P, BigInteger.valueOf(LIMB_BITS), BigInteger.valueOf(LIMBS)};
        Variable[] ainv = api.hintN(Gate.HintKind.INV_MOD, params, LIMBS, a.limbs);
        return inverseFromCandidate(api, a.limbs, ainv);
    }

    /**
     * Enforce that {@code cand} is the inverse of {@code a}: range-check + canonical + {@code a·cand
     * == 1 (mod p)}, returning {@code cand}. Package-visible so soundness tests can feed adversarial
     * candidates and assert rejection. Soundness is one line: {@code a·cand ≡ 1} uniquely determines
     * {@code cand = a⁻¹} for {@code a != 0} (and is unsatisfiable for {@code a == 0}). Uses the
     * deterministic mul, so it is independent of the CRT-mul audit.
     */
    static Fe25519 inverseFromCandidate(CircuitAPI api, Variable[] aLimbs, Variable[] cand) {
        for (Variable v : cand) api.assertInRange(v, LIMB_BITS);
        assertLessThanP(api, cand);
        Fe25519 inv = new Fe25519(api, cand.clone(), 0);
        Fe25519 a = new Fe25519(api, aLimbs.clone(), 0);
        a.mulDeterministic(inv).assertEqual(constant(api, BigInteger.ONE));
        return inv;
    }

    // ------------------------------------------------------------------
    // Hint-based multiplication (ADR-0028 Phase C — AUDIT-GATED)
    // ------------------------------------------------------------------

    // Hint-mul parameters (loose-operand version — ADR-0028 Phase C.2).
    static final int HINT_MAX_OVERFLOW = 2;                       // operand overflow accepted directly
    private static final int HINT_AB_BITS = LIMB_BITS + HINT_MAX_OVERFLOW; // a,b limb range-check (53)
    static final int HINT_Q_LIMBS = 6;                           // q up to ~2^260 for overflow-2 operands
    private static final int MUL_COLUMNS = HINT_Q_LIMBS + LIMBS - 1;       // 10 (q·p spans 0..9)
    private static final long[] P_LIMB = new long[LIMBS];
    private static final BigInteger MUL_OFFSET = BigInteger.ONE.shiftLeft(110); // ≥ max column (~2^104.3)
    private static final BigInteger[] TARGET_DIGIT = new BigInteger[MUL_COLUMNS];
    private static final BigInteger TARGET_HIGH;
    private static final int MUL_CHECK_WIDTH = 116;              // > max (column + carry) ≈ 2^110.5
    static {
        for (int i = 0; i < LIMBS; i++) P_LIMB[i] = P.shiftRight(LIMB_BITS * i).and(LIMB_MASK).longValueExact();
        BigInteger s = BigInteger.ZERO;
        for (int k = 0; k < MUL_COLUMNS; k++) s = s.add(BigInteger.ONE.shiftLeft(LIMB_BITS * k));
        BigInteger target = MUL_OFFSET.multiply(s);
        for (int k = 0; k < MUL_COLUMNS; k++) TARGET_DIGIT[k] = target.shiftRight(LIMB_BITS * k).and(LIMB_MASK);
        TARGET_HIGH = target.shiftRight(LIMB_BITS * MUL_COLUMNS);
    }

    /**
     * (this * other) mod p using prover-supplied advice (ADR-0028 Phase C). The prover supplies the
     * quotient/remainder of the integer product via a {@link Gate.HintKind#MUL_MOD_REDUCE} hint;
     * {@link #mulFromQR} then range-checks them, forces {@code r < p}, and enforces
     * {@code a·b = q·p + r} <b>over the integers</b>.
     *
     * <p><b>Loose operands (Phase C.2):</b> accepts operands with overflow up to
     * {@link #HINT_MAX_OVERFLOW} directly (no canonicalization — so it composes with Phase B's lazy
     * reduction), using a {@value #HINT_Q_LIMBS}-limb quotient. Operands with larger overflow are
     * reduced first.</p>
     *
     * <p><b>AUDIT-GATED (ADR-0028 pillar 5):</b> the hint path is behind {@link #USE_HINT_MUL}
     * (default off); the deterministic {@link #mul} remains the default until an external audit of
     * the integer-identity argument clears.</p>
     */
    public Fe25519 mulHint(Fe25519 other) {
        Variable[] a = (this.overflow > HINT_MAX_OVERFLOW) ? this.reduce().limbs : this.limbs;
        Variable[] b = (other.overflow > HINT_MAX_OVERFLOW) ? other.reduce().limbs : other.limbs;
        Variable[] inputs = new Variable[2 * LIMBS];
        System.arraycopy(a, 0, inputs, 0, LIMBS);
        System.arraycopy(b, 0, inputs, LIMBS, LIMBS);
        BigInteger[] params = {P, BigInteger.valueOf(LIMB_BITS), BigInteger.valueOf(LIMBS), BigInteger.valueOf(HINT_Q_LIMBS)};
        Variable[] hint = api.hintN(Gate.HintKind.MUL_MOD_REDUCE, params, HINT_Q_LIMBS + LIMBS, inputs);
        Variable[] q = slice(hint, 0, HINT_Q_LIMBS);
        Variable[] r = slice(hint, HINT_Q_LIMBS, HINT_Q_LIMBS + LIMBS);
        return mulFromQR(api, a, b, q, r);
    }

    /**
     * Enforce {@code a·b = q·p + r} with {@code 0 ≤ r < p}, returning {@code r} as the normalized
     * product. {@code a,b} are 5 limbs {@code < 2^53} (overflow ≤ {@link #HINT_MAX_OVERFLOW});
     * {@code q} is {@value #HINT_Q_LIMBS} limbs; {@code r} is 5 limbs. Package-visible so soundness
     * tests can feed <b>adversarial</b> {@code q, r} directly and assert rejection.
     *
     * <p>Soundness: (1) all operand limbs are range-checked (a,b to {@value #HINT_AB_BITS} bits, q,r
     * to 51) so {@code a·b} columns stay {@code < 2^108.4} and {@code q·p+r} columns {@code < 2^104.4}
     * — bounding {@code dk = lhs+OFF−rhs > 0} and the carry-chain value {@code t < 2^110.4}; (2)
     * {@code r < p} makes the remainder unique; (3) the identity is checked <b>over the integers</b>
     * — every intermediate stays {@code < 2^110.4 ≪ nativeP} (≥143 bits of headroom), so no nonzero
     * multiple of the native modulus can hide.</p>
     */
    static Fe25519 mulFromQR(CircuitAPI api, Variable[] a, Variable[] b, Variable[] q, Variable[] r) {
        for (Variable v : a) api.assertInRange(v, HINT_AB_BITS);
        for (Variable v : b) api.assertInRange(v, HINT_AB_BITS);
        for (Variable v : q) api.assertInRange(v, LIMB_BITS);
        for (Variable v : r) api.assertInRange(v, LIMB_BITS);
        assertLessThanP(api, r);

        Variable zero = api.constant(0);
        Variable[] lhs = new Variable[MUL_COLUMNS];
        Variable[] rhs = new Variable[MUL_COLUMNS];
        for (int k = 0; k < MUL_COLUMNS; k++) { lhs[k] = zero; rhs[k] = zero; }
        for (int i = 0; i < LIMBS; i++)
            for (int j = 0; j < LIMBS; j++)
                lhs[i + j] = api.add(lhs[i + j], api.mul(a[i], b[j]));                 // a·b columns 0..8
        for (int i = 0; i < HINT_Q_LIMBS; i++)
            for (int j = 0; j < LIMBS; j++)
                rhs[i + j] = api.add(rhs[i + j], api.mul(q[i], api.constant(P_LIMB[j]))); // q·p columns 0..9
        for (int k = 0; k < LIMBS; k++) rhs[k] = api.add(rhs[k], r[k]);               // + r

        // Verify Σ_k (lhs[k] + OFF − rhs[k])·2^{51k} == OFF·S over the integers via a positive carry
        // chain: each 51-bit digit must equal OFF·S's digit and the final carry its high part.
        Variable off = api.constant(MUL_OFFSET);
        Variable carry = zero;
        for (int k = 0; k < MUL_COLUMNS; k++) {
            Variable dk = api.sub(api.add(lhs[k], off), rhs[k]); // > 0, < 2^110.4
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
