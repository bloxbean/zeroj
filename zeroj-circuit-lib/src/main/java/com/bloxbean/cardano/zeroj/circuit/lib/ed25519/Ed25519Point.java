package com.bloxbean.cardano.zeroj.circuit.lib.ed25519;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.lib.field.Fe25519;

/**
 * In-circuit Ed25519 group arithmetic on the twisted Edwards curve {@code -x²+y² = 1+d·x²·y²}
 * over {@code GF(2^255-19)}, in extended coordinates {@code (X, Y, Z, T)} with
 * {@code x = X/Z, y = Y/Z, x·y = T/Z} (RFC 8032 §5.1). Field ops are {@link Fe25519}.
 *
 * <h2>Fixed-base scalar multiplication</h2>
 * {@link #scalarMulFixedBaseB} computes {@code k·B} using a precomputed table {@code [2^i]·B}
 * (host constants from {@link Ed25519Host}) and one conditional point-add per scalar bit — no
 * in-circuit doublings. This is the optimization the reference circom Ed25519 lacks; the base
 * point is a compile-time constant, so only the runtime conditional adds cost constraints.
 *
 * <h2>Cost note</h2>
 * Each addition is ~9 {@link Fe25519} muls (~8k constraints each), so a full 255-bit scalar mult
 * is on the order of a few million constraints in the current (correct-first) field
 * implementation — see ADR-0027 §6.1/§7 for the proving envelope and planned optimizations.
 */
public final class Ed25519Point {

    private final CircuitAPI api;
    final Fe25519 x, y, z, t; // extended coordinates

    private Ed25519Point(CircuitAPI api, Fe25519 x, Fe25519 y, Fe25519 z, Fe25519 t) {
        this.api = api;
        this.x = x;
        this.y = y;
        this.z = z;
        this.t = t;
    }

    /** The neutral element (0, 1, 1, 0). */
    public static Ed25519Point identity(CircuitAPI api) {
        return new Ed25519Point(api,
                Fe25519.constant(api, java.math.BigInteger.ZERO),
                Fe25519.constant(api, java.math.BigInteger.ONE),
                Fe25519.constant(api, java.math.BigInteger.ONE),
                Fe25519.constant(api, java.math.BigInteger.ZERO));
    }

    /** A compile-time constant point from affine (x, y). */
    public static Ed25519Point constant(CircuitAPI api, Ed25519Host.Affine a) {
        Fe25519 x = Fe25519.constant(api, a.x());
        Fe25519 y = Fe25519.constant(api, a.y());
        Fe25519 z = Fe25519.constant(api, java.math.BigInteger.ONE);
        Fe25519 t = Fe25519.constant(api, a.x().multiply(a.y()).mod(Ed25519Host.P));
        return new Ed25519Point(api, x, y, z, t);
    }

    /** Curve constant 2·d as a field element (used in the addition formula). */
    private static Fe25519 twoD(CircuitAPI api) {
        return Fe25519.constant(api, Ed25519Host.D.shiftLeft(1).mod(Ed25519Host.P));
    }

    /**
     * Complete twisted-Edwards addition (RFC 8032 §5.1.4), valid for {@code a = -1}:
     * <pre>
     *   A=(Y1-X1)(Y2-X2)  B=(Y1+X1)(Y2+X2)  C=T1·2d·T2  D=Z1·2·Z2
     *   E=B-A  F=D-C  G=D+C  H=B+A
     *   X3=E·F  Y3=G·H  T3=E·H  Z3=F·G
     * </pre>
     */
    public Ed25519Point add(Ed25519Point o) {
        Fe25519 a = y.sub(x).mul(o.y.sub(o.x));
        Fe25519 b = y.add(x).mul(o.y.add(o.x));
        Fe25519 c = t.mul(twoD(api)).mul(o.t);
        Fe25519 zz = z.mul(o.z);
        Fe25519 d = zz.add(zz); // Z1·2·Z2 = Z1Z2 + Z1Z2 (one mul, not two)
        Fe25519 e = b.sub(a);
        Fe25519 f = d.sub(c);
        Fe25519 g = d.add(c);
        Fe25519 h = b.add(a);
        return new Ed25519Point(api, e.mul(f), g.mul(h), f.mul(g), e.mul(h));
    }

    /** cond ? a : b, coordinate-wise (cond must be boolean). */
    public static Ed25519Point select(CircuitAPI api, Variable cond, Ed25519Point a, Ed25519Point b) {
        return new Ed25519Point(api,
                Fe25519.select(api, cond, a.x, b.x),
                Fe25519.select(api, cond, a.y, b.y),
                Fe25519.select(api, cond, a.z, b.z),
                Fe25519.select(api, cond, a.t, b.t));
    }

    /**
     * Fixed-base scalar multiplication {@code Σ bit_i · [2^i]·B}. {@code scalarBits} are LSB-first
     * and each is asserted boolean. Uses precomputed doublings of B (no in-circuit doublings).
     */
    public static Ed25519Point scalarMulFixedBaseB(CircuitAPI api, Variable[] scalarBits) {
        Ed25519Host.Affine[] table = Ed25519Host.precompDoublingsOfB(scalarBits.length);
        Ed25519Point acc = identity(api);
        for (int i = 0; i < scalarBits.length; i++) {
            api.assertBoolean(scalarBits[i]);
            Ed25519Point added = acc.add(constant(api, table[i]));
            acc = select(api, scalarBits[i], added, acc);
        }
        return acc;
    }

    /**
     * Fixed-base windowed scalar multiplication {@code k·B} (ADR-0028 Phase A). Processes
     * {@code windowBits} scalar bits per step against per-window precomputed tables
     * {@code table_j[v] = (v · 2^{w·j}) · B} (compile-time constants), selecting the window multiple
     * with a binary MUX tree and performing <b>one point-add per window</b> — {@code ⌈n/w⌉} adds
     * instead of {@code n}. Result is identical to {@link #scalarMulFixedBaseB}; the base point is a
     * compile-time constant, so only the runtime adds + tiny MUX cost constraints.
     *
     * @param windowBits window size (e.g. 4 → ~4× fewer adds). Must be ≥ 1.
     */
    public static Ed25519Point scalarMulFixedBaseBWindowed(CircuitAPI api, Variable[] scalarBits, int windowBits) {
        if (windowBits < 1 || windowBits > 16)
            throw new IllegalArgumentException("windowBits must be in [1, 16], got " + windowBits);
        int n = scalarBits.length;
        for (Variable b : scalarBits) api.assertBoolean(b);

        Ed25519Point acc = identity(api);
        int numWindows = (n + windowBits - 1) / windowBits;
        for (int j = 0; j < numWindows; j++) {
            int lo = j * windowBits;
            int w = Math.min(windowBits, n - lo);           // last window may be narrower
            Variable[] bits = new Variable[w];
            System.arraycopy(scalarBits, lo, bits, 0, w);

            // table[v] = (v · 2^{w·j}) · B for v = 0..2^w-1 (v=0 is the identity).
            int size = 1 << w;
            Ed25519Point[] table = new Ed25519Point[size];
            for (int v = 0; v < size; v++) {
                java.math.BigInteger scalar = java.math.BigInteger.valueOf(v).shiftLeft(lo);
                table[v] = (v == 0) ? identity(api)
                        : constant(api, Ed25519Host.scalarMulBase(scalar));
            }
            Ed25519Point selected = muxTree(api, table, bits);
            acc = acc.add(selected);
        }
        return acc;
    }

    /** Select {@code table[Σ bits[i]·2^i]} via a binary MUX tree (bits LSB-first). */
    private static Ed25519Point muxTree(CircuitAPI api, Ed25519Point[] table, Variable[] bits) {
        if (bits.length == 0) return table[0];
        int half = table.length / 2;
        Variable[] lower = new Variable[bits.length - 1];
        System.arraycopy(bits, 0, lower, 0, lower.length);
        Ed25519Point loHalf = muxTree(api, java.util.Arrays.copyOfRange(table, 0, half), lower);
        Ed25519Point hiHalf = muxTree(api, java.util.Arrays.copyOfRange(table, half, table.length), lower);
        // top bit selects between the high and low halves of the index range.
        return select(api, bits[bits.length - 1], hiHalf, loHalf);
    }

    /**
     * RFC 8032 point encoding: 32 little-endian bytes of the affine {@code y}, with the top bit
     * of the last byte set to {@code x mod 2}. Costs one field inversion (for {@code 1/Z}).
     * Returns 32 field-element bytes in [0,255], ready to feed to {@code Blake2b}.
     */
    public Variable[] encode() {
        Fe25519 zInv = z.inverse();
        Fe25519 ax = x.mul(zInv).canonical();
        Fe25519 ay = y.mul(zInv).canonical();

        // 255 bits of y (5 limbs × 51 bits), LSB-first; bit 255 = parity of x.
        Variable[] bits = new Variable[256];
        Variable[] yl = ay.limbs();
        for (int i = 0; i < Fe25519.LIMBS; i++) {
            Variable[] lb = api.toBinary(yl[i], Fe25519.LIMB_BITS);
            System.arraycopy(lb, 0, bits, i * Fe25519.LIMB_BITS, Fe25519.LIMB_BITS);
        }
        Variable[] x0 = api.toBinary(ax.limbs()[0], Fe25519.LIMB_BITS);
        bits[255] = x0[0]; // x mod 2

        Variable[] out = new Variable[32];
        for (int i = 0; i < 32; i++) {
            Variable[] byteBits = new Variable[8];
            System.arraycopy(bits, i * 8, byteBits, 0, 8);
            out[i] = api.fromBinary(byteBits);
        }
        return out;
    }

    /** Affine x, canonical (for tests). */
    Fe25519 affineX() { return x.mul(z.inverse()).canonical(); }
    /** Affine y, canonical (for tests). */
    Fe25519 affineY() { return y.mul(z.inverse()).canonical(); }
}
