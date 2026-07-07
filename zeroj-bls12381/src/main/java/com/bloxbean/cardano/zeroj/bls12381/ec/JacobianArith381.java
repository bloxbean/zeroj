package com.bloxbean.cardano.zeroj.bls12381.ec;

import com.bloxbean.cardano.zeroj.bls12381.field.FpArith381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;

/**
 * Allocation-free BLS12-381 G1 Jacobian point arithmetic over flat {@code long[]} storage
 * (ADR-0029 M1b), built on {@link FpArith381}.
 *
 * <p>A point is 18 consecutive longs at an offset: {@code X} at {@code +0}, {@code Y} at {@code +6},
 * {@code Z} at {@code +12} (each a 6-limb Montgomery Fp). The point at infinity is {@code Z == 0}
 * (matching {@link JacobianG1BLS381#isInfinity}). Every op computes into a caller-supplied scratch
 * buffer ({@code >= SCRATCH_LONGS}) and writes the 18 result limbs at the end, so <b>the output may
 * alias an input</b> (required by the MSM bucket loop, e.g. {@code add(bucket, bucket, P)}).</p>
 *
 * <p>Byte-for-byte port of {@link JacobianG1BLS381}'s dbl-2009-l double and general/mixed adds;
 * {@link JacobianG1BLS381} stays the bit-identical oracle (see {@code JacobianArith381Test}).</p>
 */
public final class JacobianArith381 {

    private JacobianArith381() {}

    /** Longs per point (X,Y,Z × 6 limbs). */
    public static final int POINT_LONGS = 18;
    /** Minimum scratch size the ops require. */
    public static final int SCRATCH_LONGS = 96;

    private static final int L = FpArith381.LIMBS; // 6
    private static final long[] FP_ONE = MontFp381.ONE.toLimbs();

    // point sub-offsets
    private static int X(int p) { return p; }
    private static int Y(int p) { return p + L; }
    private static int Z(int p) { return p + 2 * L; }

    public static void setInfinity(long[] o, int oo) {
        for (int i = 0; i < POINT_LONGS; i++) o[oo + i] = 0L; // Z=0 ⇒ infinity; X,Y irrelevant
    }

    public static boolean isInfinity(long[] a, int ao) { return FpArith381.isZero(a, Z(ao)); }

    public static void copyPoint(long[] o, int oo, long[] a, int ao) {
        System.arraycopy(a, ao, o, oo, POINT_LONGS);
    }

    /** Load an affine (x,y) into a Jacobian point (Z=1) at {@code o[oo..]}. */
    public static void fromAffine(long[] o, int oo, long[] ax, int axo, long[] ay, int ayo) {
        FpArith381.copy(o, X(oo), ax, axo);
        FpArith381.copy(o, Y(oo), ay, ayo);
        System.arraycopy(FP_ONE, 0, o, Z(oo), L);
    }

    // ------------------------------------------------------------------
    // doubling — dbl-2009-l  (port of JacobianG1BLS381.doublePoint)
    // ------------------------------------------------------------------

    public static void dbl(long[] o, int oo, long[] a, int ao, long[] s) {
        if (isInfinity(a, ao)) { copyPoint(o, oo, a, ao); return; }
        if (FpArith381.isZero(a, Y(ao))) { setInfinity(o, oo); return; }

        final int A = 0, B = 6, C = 12, D = 18, E = 24, F = 30, T = 36, C8 = 42, X3 = 48, Y3 = 54, Z3 = 60;
        FpArith381.sqr(s, A, a, X(ao));            // A = X^2
        FpArith381.sqr(s, B, a, Y(ao));            // B = Y^2
        FpArith381.sqr(s, C, s, B);                // C = B^2
        FpArith381.add(s, T, a, X(ao), s, B);      // X+B
        FpArith381.sqr(s, T, s, T);                // (X+B)^2
        FpArith381.sub(s, T, s, T, s, A);          // -A
        FpArith381.sub(s, T, s, T, s, C);          // -C
        FpArith381.add(s, D, s, T, s, T);          // D = 2*(...)
        FpArith381.add(s, E, s, A, s, A);          // 2A
        FpArith381.add(s, E, s, E, s, A);          // E = 3A
        FpArith381.sqr(s, F, s, E);                // F = E^2
        FpArith381.add(s, T, s, D, s, D);          // 2D
        FpArith381.sub(s, X3, s, F, s, T);         // X3 = F - 2D
        FpArith381.add(s, C8, s, C, s, C);         // 2C
        FpArith381.add(s, C8, s, C8, s, C8);       // 4C
        FpArith381.add(s, C8, s, C8, s, C8);       // 8C
        FpArith381.sub(s, T, s, D, s, X3);         // D - X3
        FpArith381.mul(s, Y3, s, E, s, T);         // E*(D-X3)
        FpArith381.sub(s, Y3, s, Y3, s, C8);       // Y3 = E*(D-X3) - 8C
        FpArith381.mul(s, T, a, Y(ao), a, Z(ao));  // Y*Z
        FpArith381.add(s, Z3, s, T, s, T);         // Z3 = 2*Y*Z

        FpArith381.copy(o, X(oo), s, X3);
        FpArith381.copy(o, Y(oo), s, Y3);
        FpArith381.copy(o, Z(oo), s, Z3);
    }

    // ------------------------------------------------------------------
    // general addition  (port of JacobianG1BLS381.add)
    // ------------------------------------------------------------------

    public static void add(long[] o, int oo, long[] a, int ao, long[] b, int bo, long[] s) {
        if (isInfinity(a, ao)) { copyPoint(o, oo, b, bo); return; }
        if (isInfinity(b, bo)) { copyPoint(o, oo, a, ao); return; }

        final int Z1Z1 = 0, Z2Z2 = 6, U1 = 12, U2 = 18, S1 = 24, S2 = 30, H = 36, R = 42,
                HH = 48, HHH = 54, V = 60, T = 66, X3 = 72, Y3 = 78, Z3 = 84;
        FpArith381.sqr(s, Z1Z1, a, Z(ao));
        FpArith381.sqr(s, Z2Z2, b, Z(bo));
        FpArith381.mul(s, U1, a, X(ao), s, Z2Z2);
        FpArith381.mul(s, U2, b, X(bo), s, Z1Z1);
        FpArith381.mul(s, S1, a, Y(ao), s, Z2Z2); FpArith381.mul(s, S1, s, S1, b, Z(bo)); // Y1*Z2Z2*Z2
        FpArith381.mul(s, S2, b, Y(bo), s, Z1Z1); FpArith381.mul(s, S2, s, S2, a, Z(ao)); // Y2*Z1Z1*Z1
        FpArith381.sub(s, H, s, U2, s, U1);
        FpArith381.sub(s, R, s, S2, s, S1);

        if (FpArith381.isZero(s, H)) {
            if (FpArith381.isZero(s, R)) dbl(o, oo, a, ao, s); else setInfinity(o, oo);
            return;
        }
        FpArith381.sqr(s, HH, s, H);
        FpArith381.mul(s, HHH, s, HH, s, H);
        FpArith381.mul(s, V, s, U1, s, HH);
        FpArith381.sqr(s, X3, s, R); FpArith381.sub(s, X3, s, X3, s, HHH);
        FpArith381.add(s, T, s, V, s, V); FpArith381.sub(s, X3, s, X3, s, T);       // R^2 - HHH - 2V
        FpArith381.sub(s, T, s, V, s, X3); FpArith381.mul(s, Y3, s, R, s, T);
        FpArith381.mul(s, T, s, S1, s, HHH); FpArith381.sub(s, Y3, s, Y3, s, T);    // R*(V-X3) - S1*HHH
        FpArith381.mul(s, Z3, a, Z(ao), b, Z(bo)); FpArith381.mul(s, Z3, s, Z3, s, H); // Z1*Z2*H

        FpArith381.copy(o, X(oo), s, X3);
        FpArith381.copy(o, Y(oo), s, Y3);
        FpArith381.copy(o, Z(oo), s, Z3);
    }

    // ------------------------------------------------------------------
    // mixed addition (affine b, Z2=1)  (port of JacobianG1BLS381.addAffine)
    // ------------------------------------------------------------------

    public static void addAffine(long[] o, int oo, long[] a, int ao,
                                 long[] ax, int axo, long[] ay, int ayo, long[] s) {
        if (isInfinity(a, ao)) { fromAffine(o, oo, ax, axo, ay, ayo); return; }
        if (FpArith381.isZero(ax, axo) && FpArith381.isZero(ay, ayo)) { copyPoint(o, oo, a, ao); return; }

        final int Z1Z1 = 0, Z1Z1Z1 = 6, U2 = 12, S2 = 18, H = 24, R = 30,
                HH = 36, HHH = 42, V = 48, T = 54, X3 = 60, Y3 = 66, Z3 = 72;
        FpArith381.sqr(s, Z1Z1, a, Z(ao));
        FpArith381.mul(s, Z1Z1Z1, s, Z1Z1, a, Z(ao));
        FpArith381.mul(s, U2, ax, axo, s, Z1Z1);
        FpArith381.mul(s, S2, ay, ayo, s, Z1Z1Z1);
        FpArith381.sub(s, H, s, U2, a, X(ao));
        FpArith381.sub(s, R, s, S2, a, Y(ao));

        if (FpArith381.isZero(s, H)) {
            if (FpArith381.isZero(s, R)) dbl(o, oo, a, ao, s); else setInfinity(o, oo);
            return;
        }
        FpArith381.sqr(s, HH, s, H);
        FpArith381.mul(s, HHH, s, HH, s, H);
        FpArith381.mul(s, V, a, X(ao), s, HH);
        FpArith381.sqr(s, X3, s, R); FpArith381.sub(s, X3, s, X3, s, HHH);
        FpArith381.add(s, T, s, V, s, V); FpArith381.sub(s, X3, s, X3, s, T);       // R^2 - HHH - 2V
        FpArith381.sub(s, T, s, V, s, X3); FpArith381.mul(s, Y3, s, R, s, T);
        FpArith381.mul(s, T, a, Y(ao), s, HHH); FpArith381.sub(s, Y3, s, Y3, s, T); // R*(V-X3) - Y1*HHH
        FpArith381.mul(s, Z3, a, Z(ao), s, H);                                       // Z1*H

        FpArith381.copy(o, X(oo), s, X3);
        FpArith381.copy(o, Y(oo), s, Y3);
        FpArith381.copy(o, Z(oo), s, Z3);
    }
}
