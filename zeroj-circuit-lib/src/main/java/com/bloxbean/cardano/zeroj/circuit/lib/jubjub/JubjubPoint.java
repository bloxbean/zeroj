package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.A;
import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.BASE_FIELD_PRIME;
import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.COFACTOR;
import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.COMPRESSED_POINT_BYTES;
import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.D;
import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.FULL_GENERATOR_U;
import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.FULL_GENERATOR_V;
import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;
import static com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve.TWO_D;

/**
 * A Jubjub point in extended twisted-Edwards coordinates
 * {@code (U, V, Z, T)} with affine {@code (u, v) = (U/Z, V/Z)} and
 * {@code T = U·V/Z}.
 *
 * <p>All arithmetic is done modulo {@link JubjubCurve#BASE_FIELD_PRIME}.
 * Operations use the unified add / dedicated doubling formulas from
 * Hisil–Wong–Carter–Dawson 2008 — complete for {@code a = -1} (Jubjub's
 * choice) and non-square {@code d}.
 *
 * <h2>Subgroup safety</h2>
 * Jubjub has cofactor 8. The full group {@code E(Fq)} contains points
 * outside the prime-order subgroup; these points enable small-subgroup
 * attacks in cryptographic protocols. <b>Untrusted points must pass
 * {@link #isInSubgroup} before use</b>. The {@link #SUBGROUP_GENERATOR}
 * constant and any point produced by {@link #mulByCofactor} are
 * subgroup-safe by construction.
 *
 * <h2>Immutability</h2>
 * Instances are immutable. Arithmetic returns new instances.
 */
public final class JubjubPoint {

    // ---------- Extended coordinates ----------
    private final BigInteger u;
    private final BigInteger v;
    private final BigInteger z;
    private final BigInteger t;

    /** Identity element: {@code (0, 1, 1, 0)} in extended coords, = affine {@code (0, 1)}. */
    public static final JubjubPoint IDENTITY = new JubjubPoint(
            BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO);

    /**
     * Full curve generator (order {@code 8·l}). For cryptographic use prefer
     * {@link #SUBGROUP_GENERATOR}, which is cofactor-cleared.
     */
    public static final JubjubPoint FULL_GENERATOR = fromAffine(FULL_GENERATOR_U, FULL_GENERATOR_V);

    /**
     * Prime-order subgroup generator = {@code [8] · FULL_GENERATOR}. Safe
     * for EdDSA, Pedersen, and all downstream gadgets.
     */
    public static final JubjubPoint SUBGROUP_GENERATOR = FULL_GENERATOR.mulByCofactor();

    private JubjubPoint(BigInteger u, BigInteger v, BigInteger z, BigInteger t) {
        this.u = u;
        this.v = v;
        this.z = z;
        this.t = t;
    }

    // ---------- Construction ----------

    /**
     * Builds a point from affine {@code (u, v)} coordinates. Throws if the
     * point is not on the curve.
     *
     * @param u affine u-coordinate
     * @param v affine v-coordinate
     * @return extended-coord representation
     * @throws IllegalArgumentException if {@code (u, v)} is not on the curve
     */
    public static JubjubPoint fromAffine(BigInteger u, BigInteger v) {
        BigInteger uRed = reduce(u);
        BigInteger vRed = reduce(v);
        if (!isOnCurveAffine(uRed, vRed)) {
            throw new IllegalArgumentException(
                    "Point (" + uRed.toString(16) + ", " + vRed.toString(16) + ") is not on the Jubjub curve");
        }
        BigInteger tRed = uRed.multiply(vRed).mod(BASE_FIELD_PRIME);
        return new JubjubPoint(uRed, vRed, BigInteger.ONE, tRed);
    }

    private static boolean isOnCurveAffine(BigInteger u, BigInteger v) {
        // -u^2 + v^2 == 1 + d·u^2·v^2
        BigInteger uu = u.multiply(u).mod(BASE_FIELD_PRIME);
        BigInteger vv = v.multiply(v).mod(BASE_FIELD_PRIME);
        BigInteger lhs = vv.subtract(uu).mod(BASE_FIELD_PRIME);
        BigInteger rhs = BigInteger.ONE.add(D.multiply(uu).multiply(vv)).mod(BASE_FIELD_PRIME);
        return lhs.equals(rhs);
    }

    // ---------- Accessors ----------

    /** Extended coord {@code U}. */
    public BigInteger u() { return u; }
    /** Extended coord {@code V}. */
    public BigInteger v() { return v; }
    /** Extended coord {@code Z}. */
    public BigInteger z() { return z; }
    /** Extended coord {@code T = U·V/Z}. */
    public BigInteger t() { return t; }

    /** Affine u-coordinate = {@code U/Z (mod p)}. */
    public BigInteger affineU() {
        return u.multiply(z.modInverse(BASE_FIELD_PRIME)).mod(BASE_FIELD_PRIME);
    }

    /** Affine v-coordinate = {@code V/Z (mod p)}. */
    public BigInteger affineV() {
        return v.multiply(z.modInverse(BASE_FIELD_PRIME)).mod(BASE_FIELD_PRIME);
    }

    /** {@code true} iff this point is the identity {@code (0, 1)}. */
    public boolean isIdentity() {
        // In extended coords, identity has U = 0 and V = Z (so affineV = 1).
        return u.signum() == 0 && v.equals(z);
    }

    // ---------- Arithmetic ----------

    /**
     * Point addition per Hisil–Wong–Carter–Dawson §3.2 (unified formula,
     * complete for {@code a = -1} and non-square {@code d}).
     */
    public JubjubPoint add(JubjubPoint other) {
        Objects.requireNonNull(other, "other");
        // HWCD §3.2 unified, a=-1. Locals named rA..rH to avoid shadowing
        // the static imports JubjubCurve.A / D.
        BigInteger rA = v.subtract(u).multiply(other.v.subtract(other.u)).mod(BASE_FIELD_PRIME);
        BigInteger rB = v.add(u).multiply(other.v.add(other.u)).mod(BASE_FIELD_PRIME);
        BigInteger rC = t.multiply(TWO_D).multiply(other.t).mod(BASE_FIELD_PRIME);
        BigInteger rD = z.multiply(BigInteger.TWO).multiply(other.z).mod(BASE_FIELD_PRIME);
        BigInteger rE = rB.subtract(rA).mod(BASE_FIELD_PRIME);
        BigInteger rF = rD.subtract(rC).mod(BASE_FIELD_PRIME);
        BigInteger rG = rD.add(rC).mod(BASE_FIELD_PRIME);
        BigInteger rH = rB.add(rA).mod(BASE_FIELD_PRIME);
        return new JubjubPoint(
                rE.multiply(rF).mod(BASE_FIELD_PRIME),
                rG.multiply(rH).mod(BASE_FIELD_PRIME),
                rF.multiply(rG).mod(BASE_FIELD_PRIME),
                rE.multiply(rH).mod(BASE_FIELD_PRIME));
    }

    /**
     * Dedicated doubling formula per HWCD §3.3 for twisted Edwards with
     * {@code a = -1}. Slightly cheaper than {@code add(this)}.
     */
    public JubjubPoint doubled() {
        // HWCD §3.3 dedicated doubling, a=-1.
        BigInteger rA = u.multiply(u).mod(BASE_FIELD_PRIME);              // A = U^2
        BigInteger rB = v.multiply(v).mod(BASE_FIELD_PRIME);              // B = V^2
        BigInteger rC = z.multiply(z).shiftLeft(1).mod(BASE_FIELD_PRIME); // C = 2·Z^2
        BigInteger rD = A.multiply(rA).mod(BASE_FIELD_PRIME);             // D = a·A = -A
        BigInteger sum = u.add(v);
        BigInteger rE = sum.multiply(sum)                                 // E = (U+V)^2 - A - B
                .subtract(rA).subtract(rB).mod(BASE_FIELD_PRIME);
        BigInteger rG = rD.add(rB).mod(BASE_FIELD_PRIME);                 // G = D + B
        BigInteger rF = rG.subtract(rC).mod(BASE_FIELD_PRIME);            // F = G - C
        BigInteger rH = rD.subtract(rB).mod(BASE_FIELD_PRIME);            // H = D - B
        return new JubjubPoint(
                rE.multiply(rF).mod(BASE_FIELD_PRIME),
                rG.multiply(rH).mod(BASE_FIELD_PRIME),
                rF.multiply(rG).mod(BASE_FIELD_PRIME),
                rE.multiply(rH).mod(BASE_FIELD_PRIME));
    }

    /** Point negation: {@code -P = (-U, V, Z, -T)}. */
    public JubjubPoint negate() {
        return new JubjubPoint(
                u.negate().mod(BASE_FIELD_PRIME),
                v,
                z,
                t.negate().mod(BASE_FIELD_PRIME));
    }

    /**
     * Scalar multiplication {@code [k] · P} via simple double-and-add.
     *
     * <p><b>Does not</b> pre-reduce {@code k} by {@link JubjubCurve#SUBGROUP_ORDER}.
     * Pre-reduction is only valid when {@code P} is in the prime-order
     * subgroup — for arbitrary curve points (e.g. inside a subgroup check
     * that multiplies {@code FULL_GENERATOR} by {@code l}), reduction would
     * silently produce the identity and mask a subgroup-membership failure.
     *
     * <p>Negative {@code k} is handled by negating the result of
     * {@code [|k|] · P}.
     *
     * <p>Not constant-time — caller is responsible for side-channel
     * considerations if applicable.
     */
    public JubjubPoint scalarMul(BigInteger k) {
        Objects.requireNonNull(k, "k");
        if (k.signum() == 0) return IDENTITY;
        boolean negate = k.signum() < 0;
        BigInteger scalar = negate ? k.negate() : k;
        JubjubPoint result = IDENTITY;
        JubjubPoint base = this;
        int bits = scalar.bitLength();
        for (int i = 0; i < bits; i++) {
            if (scalar.testBit(i)) {
                result = result.add(base);
            }
            base = base.doubled();
        }
        return negate ? result.negate() : result;
    }

    /** Cofactor-clear: returns {@code [8] · P}, guaranteed to be in the prime-order subgroup. */
    public JubjubPoint mulByCofactor() {
        // 8 = 2^3, so three doublings.
        JubjubPoint r = this.doubled();
        r = r.doubled();
        r = r.doubled();
        return r;
    }

    /**
     * Prime-order subgroup membership check: {@code [l] · P == O}.
     *
     * <p>Cryptographic protocols must reject untrusted points that fail
     * this — they may lie in the 8-element kernel and bypass group-
     * theoretic security assumptions.
     */
    public boolean isInSubgroup() {
        return scalarMul(SUBGROUP_ORDER).isIdentity();
    }

    // ---------- Equality ----------

    /**
     * Projective equality: compares affine coordinates after normalization.
     * Two extended representations can have different {@code (U, V, Z, T)}
     * but the same underlying affine point.
     */
    public boolean projectiveEquals(JubjubPoint other) {
        if (other == null) return false;
        // U1·Z2 == U2·Z1 && V1·Z2 == V2·Z1
        BigInteger left1 = u.multiply(other.z).mod(BASE_FIELD_PRIME);
        BigInteger right1 = other.u.multiply(z).mod(BASE_FIELD_PRIME);
        if (!left1.equals(right1)) return false;
        BigInteger left2 = v.multiply(other.z).mod(BASE_FIELD_PRIME);
        BigInteger right2 = other.v.multiply(z).mod(BASE_FIELD_PRIME);
        return left2.equals(right2);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof JubjubPoint p)) return false;
        return projectiveEquals(p);
    }

    @Override
    public int hashCode() {
        // Hash affine coordinates so equal points get equal hashes.
        return Objects.hash(affineU(), affineV());
    }

    @Override
    public String toString() {
        return "JubjubPoint{u=" + affineU().toString(16) + ", v=" + affineV().toString(16) + "}";
    }

    // ---------- Encoding ----------

    /**
     * Compressed 32-byte encoding per Zcash/zkcrypto convention:
     * 255 bits for {@code v} (little-endian) + top bit = sign of {@code u}
     * (1 iff {@code u} is odd when encoded as the least non-negative
     * residue in {@code [0, p)}).
     */
    public byte[] toBytes() {
        BigInteger uAff = affineU();
        BigInteger vAff = affineV();
        byte[] out = toFixedLE(vAff, COMPRESSED_POINT_BYTES);
        if (uAff.testBit(0)) {
            out[COMPRESSED_POINT_BYTES - 1] = (byte) (out[COMPRESSED_POINT_BYTES - 1] | 0x80);
        }
        return out;
    }

    /**
     * Inverse of {@link #toBytes}. Rejects if the decoded point is not on
     * the curve. <b>Does not</b> check subgroup membership — call
     * {@link #isInSubgroup} after decoding if you received the point from
     * an untrusted source.
     *
     * @throws IllegalArgumentException if {@code bytes} does not decode
     *         to a valid curve point
     */
    public static JubjubPoint fromBytes(byte[] bytes) {
        if (bytes == null || bytes.length != COMPRESSED_POINT_BYTES) {
            throw new IllegalArgumentException("Encoded point must be " + COMPRESSED_POINT_BYTES + " bytes");
        }
        byte[] copy = bytes.clone();
        boolean uOdd = (copy[COMPRESSED_POINT_BYTES - 1] & 0x80) != 0;
        copy[COMPRESSED_POINT_BYTES - 1] = (byte) (copy[COMPRESSED_POINT_BYTES - 1] & 0x7F);

        BigInteger vAff = fromLE(copy);
        if (vAff.compareTo(BASE_FIELD_PRIME) >= 0) {
            throw new IllegalArgumentException("v-coordinate out of range");
        }

        // Recover u from -u^2 + v^2 = 1 + d·u^2·v^2
        //   u^2 · (d·v^2 + 1) = v^2 - 1
        //   u^2 = (v^2 - 1) / (d·v^2 + 1)
        BigInteger vv = vAff.multiply(vAff).mod(BASE_FIELD_PRIME);
        BigInteger numerator = vv.subtract(BigInteger.ONE).mod(BASE_FIELD_PRIME);
        BigInteger denominator = D.multiply(vv).add(BigInteger.ONE).mod(BASE_FIELD_PRIME);
        if (denominator.signum() == 0) {
            throw new IllegalArgumentException("Invalid encoded point (zero denominator)");
        }
        BigInteger uSquared = numerator.multiply(denominator.modInverse(BASE_FIELD_PRIME)).mod(BASE_FIELD_PRIME);

        BigInteger uAff = modSqrt(uSquared, BASE_FIELD_PRIME);
        if (uAff == null) {
            throw new IllegalArgumentException("Invalid encoded point (no square root for u²)");
        }
        // Reject non-canonical encoding: if u = 0, the sign bit is meaningless
        // (there is no distinct -u), so encodings with u=0 AND sign bit=1 alias
        // the same point as sign bit=0. Per RFC 8032 canonicalization, reject.
        if (uAff.signum() == 0 && uOdd) {
            throw new IllegalArgumentException("Non-canonical encoding: u = 0 with sign bit set");
        }
        if (uAff.testBit(0) != uOdd) {
            uAff = BASE_FIELD_PRIME.subtract(uAff);
        }
        return fromAffine(uAff, vAff);
    }

    // ---------- Helpers ----------

    private static BigInteger reduce(BigInteger x) {
        BigInteger r = x.mod(BASE_FIELD_PRIME);
        return r.signum() < 0 ? r.add(BASE_FIELD_PRIME) : r;
    }

    private static byte[] toFixedLE(BigInteger v, int length) {
        byte[] be = v.toByteArray(); // two's-complement big-endian, possibly with sign byte
        // Strip leading zero sign byte if present.
        int start = (be.length > 1 && be[0] == 0) ? 1 : 0;
        int effLen = be.length - start;
        byte[] out = new byte[length];
        if (effLen > length) {
            throw new IllegalStateException("Value exceeds " + length + " bytes");
        }
        for (int i = 0; i < effLen; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private static BigInteger fromLE(byte[] bytes) {
        byte[] be = new byte[bytes.length + 1];
        be[0] = 0; // positive sign
        for (int i = 0; i < bytes.length; i++) {
            be[be.length - 1 - i] = bytes[i];
        }
        return new BigInteger(be);
    }

    /**
     * Tonelli–Shanks for a generic prime, returning one square root (or
     * null if {@code a} is not a quadratic residue). For Jubjub's base
     * field {@code p ≡ 1 (mod 4)}, so the {@code (p+1)/4} shortcut does
     * not apply — use full Tonelli–Shanks.
     */
    private static BigInteger modSqrt(BigInteger a, BigInteger p) {
        if (a.signum() == 0) return BigInteger.ZERO;
        if (a.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p).equals(p.subtract(BigInteger.ONE))) {
            return null; // non-residue
        }
        // Tonelli–Shanks
        BigInteger s = p.subtract(BigInteger.ONE);
        int e = 0;
        while (!s.testBit(0)) { s = s.shiftRight(1); e++; }
        // Find a non-residue n
        BigInteger n = BigInteger.TWO;
        BigInteger pMinusOneHalf = p.subtract(BigInteger.ONE).shiftRight(1);
        while (!n.modPow(pMinusOneHalf, p).equals(p.subtract(BigInteger.ONE))) {
            n = n.add(BigInteger.ONE);
        }
        BigInteger x = a.modPow(s.add(BigInteger.ONE).shiftRight(1), p);
        BigInteger b = a.modPow(s, p);
        BigInteger g = n.modPow(s, p);
        int r = e;
        while (true) {
            BigInteger tmp = b;
            int m = 0;
            while (!tmp.equals(BigInteger.ONE)) {
                tmp = tmp.multiply(tmp).mod(p);
                m++;
                if (m == r) return null;
            }
            if (m == 0) return x;
            BigInteger gs = g.modPow(BigInteger.TWO.modPow(BigInteger.valueOf(r - m - 1), p.subtract(BigInteger.ONE)), p);
            g = gs.multiply(gs).mod(p);
            x = x.multiply(gs).mod(p);
            b = b.multiply(g).mod(p);
            r = m;
        }
    }

    /** Byte-equal encoded-form comparison. Convenience for tests. */
    public boolean encodingEquals(byte[] expected) {
        return Arrays.equals(toBytes(), expected);
    }
}
