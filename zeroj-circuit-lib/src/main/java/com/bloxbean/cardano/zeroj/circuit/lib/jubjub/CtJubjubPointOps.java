package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

/**
 * Stateless fixed-limb extended-coordinate Jubjub kernel for ADR-0039.
 *
 * <p>A point occupies 16 longs: four Montgomery limbs each for {@code U,V,Z,T}. Methods use
 * complete formulas, fixed public loop bounds, mask-based selection, and caller-owned work
 * storage. No identity or zero-scalar fast path exists.
 */
final class CtJubjubPointOps {

    static final int U = 0;
    static final int V = 4;
    static final int Z = 8;
    static final int T = 12;
    static final int POINT_LIMBS = 16;
    static final int SCALAR_MUL_WORK_LIMBS = 109;
    static final int POINT_OP_WORK_LIMBS = 41;

    private static final long[] TWO_D = {
            0x54a448ac72e9ed5fL, 0xa51befdb1b373967L,
            0xc0d81f217b4a799eL, 0x3c0445fed27ecf14L
    };
    private static final long[] D = {
            0x2a522455b974f6b0L, 0xfc6cc9ef0d9acab3L,
            0x7a08fb94c27628d1L, 0x57f8f6a8fe0e262eL
    };
    private static final long[] GENERATOR = {
            0x264ab2ae27790d7aL, 0x7715419fe4328d1bL,
            0x26e742fccd3474aeL, 0x0edae7e0e475434bL,
            0x30b42f35b6518e59L, 0x599e51c9ec7ab10aL,
            0x3798281a9e12a20fL, 0x30af1cc0df805b82L,
            0x00000001fffffffeL, 0x5884b7fa00034802L,
            0x998c4fefecbc4ff5L, 0x1824b159acc5056fL,
            0x93d0ee2bcb1fd9f0L, 0xe23717d83b934c01L,
            0xe894838031e74212L, 0x4450a03034b1ec71L
    };
    private static final long[] PEDERSEN_H = {
            0x025b5076c1280fc7L, 0x7f4e73a2ecbe9352L,
            0xabdd6d94fa8f55feL, 0x411a80320b6fdce5L,
            0x523cf0e7ba728a6eL, 0x38e8b9f352a542f5L,
            0x8e8e59d4af97ba45L, 0x5d8a00086cae56c3L,
            0x00000001fffffffeL, 0x5884b7fa00034802L,
            0x998c4fefecbc4ff5L, 0x1824b159acc5056fL,
            0x27bd6a0a7f295b14L, 0x5c2028f66c2f7e4aL,
            0x8e43c231b9de2855L, 0x6b60763b2b3e6986L
    };

    private CtJubjubPointOps() {
    }

    static void copy(long[] out, int oo, long[] in, int io) {
        for (int i = 0; i < POINT_LIMBS; i++) {
            out[oo + i] = in[io + i];
        }
    }

    static void identity(long[] out, int oo) {
        CtJubjubFqOps.zero(out, oo + U);
        CtJubjubFqOps.one(out, oo + V);
        CtJubjubFqOps.one(out, oo + Z);
        CtJubjubFqOps.zero(out, oo + T);
    }

    static void generator(long[] out, int oo) {
        copy(out, oo, GENERATOR, 0);
    }

    static void pedersenH(long[] out, int oo) {
        copy(out, oo, PEDERSEN_H, 0);
    }

    static void fromAffine(long[] out, int oo, long[] u, int uo, long[] v, int vo,
                           long[] work, int wo) {
        CtJubjubFqOps.copy(out, oo + U, u, uo);
        CtJubjubFqOps.copy(out, oo + V, v, vo);
        CtJubjubFqOps.one(out, oo + Z);
        CtJubjubFqOps.mul(out, oo + T, u, uo, v, vo, work, wo);
    }

    /**
     * Complete unified addition for {@code a=-1}. Work uses 41 limbs.
     */
    static void add(long[] out, int oo,
                    long[] left, int lo, long[] right, int ro,
                    long[] work, int wo) {
        int a = wo;
        int b = wo + 4;
        int c = wo + 8;
        int d = wo + 12;
        int e = wo + 16;
        int f = wo + 20;
        int g = wo + 24;
        int h = wo + 28;
        int tmp1 = wo + 32;
        int tmp2 = wo + 36;
        int carry = wo + 40;

        CtJubjubFqOps.sub(work, tmp1, left, lo + V, left, lo + U);
        CtJubjubFqOps.sub(work, tmp2, right, ro + V, right, ro + U);
        CtJubjubFqOps.mul(work, a, work, tmp1, work, tmp2, work, carry);

        CtJubjubFqOps.add(work, tmp1, left, lo + V, left, lo + U);
        CtJubjubFqOps.add(work, tmp2, right, ro + V, right, ro + U);
        CtJubjubFqOps.mul(work, b, work, tmp1, work, tmp2, work, carry);

        CtJubjubFqOps.mul(work, tmp1, left, lo + T, right, ro + T, work, carry);
        CtJubjubFqOps.mul(work, c, work, tmp1, TWO_D, 0, work, carry);

        CtJubjubFqOps.mul(work, tmp1, left, lo + Z, right, ro + Z, work, carry);
        CtJubjubFqOps.add(work, d, work, tmp1, work, tmp1);

        CtJubjubFqOps.sub(work, e, work, b, work, a);
        CtJubjubFqOps.sub(work, f, work, d, work, c);
        CtJubjubFqOps.add(work, g, work, d, work, c);
        CtJubjubFqOps.add(work, h, work, b, work, a);

        CtJubjubFqOps.mul(out, oo + U, work, e, work, f, work, carry);
        CtJubjubFqOps.mul(out, oo + V, work, g, work, h, work, carry);
        CtJubjubFqOps.mul(out, oo + Z, work, f, work, g, work, carry);
        CtJubjubFqOps.mul(out, oo + T, work, e, work, h, work, carry);
    }

    /**
     * Dedicated complete doubling for {@code a=-1}. Work uses 41 limbs.
     */
    static void doublePoint(long[] out, int oo, long[] point, int po,
                            long[] work, int wo) {
        int a = wo;
        int b = wo + 4;
        int c = wo + 8;
        int d = wo + 12;
        int e = wo + 16;
        int f = wo + 20;
        int g = wo + 24;
        int h = wo + 28;
        int tmp1 = wo + 32;
        int tmp2 = wo + 36;
        int carry = wo + 40;

        CtJubjubFqOps.square(work, a, point, po + U, work, carry);
        CtJubjubFqOps.square(work, b, point, po + V, work, carry);
        CtJubjubFqOps.square(work, tmp1, point, po + Z, work, carry);
        CtJubjubFqOps.add(work, c, work, tmp1, work, tmp1);
        CtJubjubFqOps.neg(work, d, work, a);

        CtJubjubFqOps.add(work, tmp1, point, po + U, point, po + V);
        CtJubjubFqOps.square(work, tmp2, work, tmp1, work, carry);
        CtJubjubFqOps.sub(work, e, work, tmp2, work, a);
        CtJubjubFqOps.sub(work, e, work, e, work, b);

        CtJubjubFqOps.add(work, g, work, d, work, b);
        CtJubjubFqOps.sub(work, f, work, g, work, c);
        CtJubjubFqOps.sub(work, h, work, d, work, b);

        CtJubjubFqOps.mul(out, oo + U, work, e, work, f, work, carry);
        CtJubjubFqOps.mul(out, oo + V, work, g, work, h, work, carry);
        CtJubjubFqOps.mul(out, oo + Z, work, f, work, g, work, carry);
        CtJubjubFqOps.mul(out, oo + T, work, e, work, h, work, carry);
    }

    static void negate(long[] out, int oo, long[] point, int po) {
        CtJubjubFqOps.neg(out, oo + U, point, po + U);
        CtJubjubFqOps.copy(out, oo + V, point, po + V);
        CtJubjubFqOps.copy(out, oo + Z, point, po + Z);
        CtJubjubFqOps.neg(out, oo + T, point, po + T);
    }

    static void select(long[] out, int oo,
                       long[] whenSet, int so, long[] whenClear, int co,
                       long mask) {
        for (int coordinate = 0; coordinate < 4; coordinate++) {
            int offset = coordinate * 4;
            CtJubjubFqOps.select(out, oo + offset,
                    whenSet, so + offset, whenClear, co + offset, mask);
        }
    }

    /**
     * Fixed 252-iteration scalar multiplication. Work uses 109 limbs.
     */
    static void scalarMul(long[] out, int oo, long[] base, int bo,
                          long[] scalar, int so, long[] work, int wo) {
        int normalScalar = wo;
        int result = wo + 4;
        int current = wo + 20;
        int sum = wo + 36;
        int doubled = wo + 52;
        int pointWork = wo + 68;

        CtJubjubFrOps.toNormal(work, normalScalar, scalar, so, work, pointWork);
        identity(work, result);
        copy(work, current, base, bo);

        for (int bit = 0; bit < JubjubCurve.SCALAR_BITS; bit++) {
            add(work, sum, work, result, work, current, work, pointWork);
            doublePoint(work, doubled, work, current, work, pointWork);
            long bitValue = (work[normalScalar + (bit >>> 6)] >>> (bit & 63)) & 1L;
            select(work, result, work, sum, work, result, -bitValue);
            copy(work, current, work, doubled);
        }
        copy(out, oo, work, result);
    }

    /**
     * Converts a projective point to canonical affine extended coordinates. Work uses 26 limbs.
     */
    static void normalize(long[] out, int oo, long[] point, int po,
                          long[] work, int wo) {
        int inverseZ = wo;
        int affineU = wo + 4;
        int affineV = wo + 8;
        int powWork = wo + 12;
        CtJubjubFqOps.invert(work, inverseZ, point, po + Z, work, powWork);
        CtJubjubFqOps.mul(work, affineU, point, po + U, work, inverseZ,
                work, powWork);
        CtJubjubFqOps.mul(work, affineV, point, po + V, work, inverseZ,
                work, powWork);
        fromAffine(out, oo, work, affineU, work, affineV, work, powWork);
    }

    /**
     * Projective equality mask. Work uses 17 limbs.
     */
    static long equalMask(long[] left, int lo, long[] right, int ro,
                          long[] work, int wo) {
        int uLeft = wo;
        int uRight = wo + 4;
        int vLeft = wo + 8;
        int vRight = wo + 12;
        int carry = wo + 16;
        CtJubjubFqOps.mul(work, uLeft, left, lo + U, right, ro + Z, work, carry);
        CtJubjubFqOps.mul(work, uRight, right, ro + U, left, lo + Z, work, carry);
        CtJubjubFqOps.mul(work, vLeft, left, lo + V, right, ro + Z, work, carry);
        CtJubjubFqOps.mul(work, vRight, right, ro + V, left, lo + Z, work, carry);
        return CtJubjubFqOps.equalMask(work, uLeft, work, uRight)
                & CtJubjubFqOps.equalMask(work, vLeft, work, vRight);
    }

    static long identityMask(long[] point, int po) {
        return CtJubjubFqOps.zeroMask(point, po + U)
                & CtJubjubFqOps.equalMask(point, po + V, point, po + Z);
    }

    /**
     * Checks the extended-coordinate and curve equations without branches. Work uses 45 limbs.
     */
    static long wellFormedMask(long[] point, int po, long[] work, int wo) {
        int tz = wo;
        int uv = wo + 4;
        int u2 = wo + 8;
        int v2 = wo + 12;
        int z2 = wo + 16;
        int left = wo + 20;
        int z4 = wo + 24;
        int u2v2 = wo + 28;
        int du2v2 = wo + 32;
        int right = wo + 36;
        int tmp = wo + 40;
        int carry = wo + 44;

        CtJubjubFqOps.mul(work, tz, point, po + T, point, po + Z, work, carry);
        CtJubjubFqOps.mul(work, uv, point, po + U, point, po + V, work, carry);
        long extended = CtJubjubFqOps.equalMask(work, tz, work, uv);

        CtJubjubFqOps.square(work, u2, point, po + U, work, carry);
        CtJubjubFqOps.square(work, v2, point, po + V, work, carry);
        CtJubjubFqOps.square(work, z2, point, po + Z, work, carry);
        CtJubjubFqOps.sub(work, tmp, work, v2, work, u2);
        CtJubjubFqOps.mul(work, left, work, tmp, work, z2, work, carry);
        CtJubjubFqOps.square(work, z4, work, z2, work, carry);
        CtJubjubFqOps.mul(work, u2v2, work, u2, work, v2, work, carry);
        CtJubjubFqOps.mul(work, du2v2, work, u2v2, D, 0, work, carry);
        CtJubjubFqOps.add(work, right, work, z4, work, du2v2);
        long curve = CtJubjubFqOps.equalMask(work, left, work, right);
        long nonZeroZ = ~CtJubjubFqOps.zeroMask(point, po + Z);
        return extended & curve & nonZeroZ;
    }
}
