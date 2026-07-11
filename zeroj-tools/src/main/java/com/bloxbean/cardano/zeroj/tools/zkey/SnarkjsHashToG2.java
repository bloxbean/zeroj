package com.bloxbean.cardano.zeroj.ceremony;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;

import java.math.BigInteger;

/**
 * Bit-exact port of snarkjs's {@code hashToG2} challenge-point derivation (ADR-0031 M5): the G2
 * point a phase-2 contribution's proof-of-knowledge is verified against. Any mismatch and
 * {@code snarkjs zkey verify} rejects the contribution, so this mirrors ffjavascript precisely:
 *
 * <ol>
 *   <li>seed = 8 <b>big-endian</b> u32 from the first 32 bytes of the 64-byte transcript hash;</li>
 *   <li>{@code ChaCha(seed)} stream (ffjavascript layout, see {@link ChaChaRng});</li>
 *   <li>sample x ∈ Fp2: per Fp coordinate (c0 then c1), v = Σᵢ₌₀..₅ nextU64ᵢ·2⁶⁴ⁱ masked to
 *       2³⁸¹−1, retry while v ≥ p;</li>
 *   <li>greatest = nextBool(); loop from (3) until x³+b₂ is a square (Euler criterion);</li>
 *   <li>y = √(x³+b₂); negate so that isNegative(y) == greatest, where isNegative on Fp2 checks
 *       c1 (or c0 if c1 = 0) against (p+1)/2 — the exact wasmcurves convention;</li>
 *   <li>clear the G2 cofactor; return affine.</li>
 * </ol>
 */
final class SnarkjsHashToG2 {

    private SnarkjsHashToG2() {}

    private static final BigInteger P = MontFp381.modulus();
    private static final BigInteger MASK_381 = BigInteger.ONE.shiftLeft(381).subtract(BigInteger.ONE);
    private static final BigInteger P_HALF_PLUS_ONE = P.subtract(BigInteger.ONE).shiftRight(1).add(BigInteger.ONE);
    private static final BigInteger SQRT_EXP = P.add(BigInteger.ONE).shiftRight(2);       // (p+1)/4, p ≡ 3 mod 4
    private static final BigInteger EULER_FP2 = P.multiply(P).subtract(BigInteger.ONE).shiftRight(1); // (p²−1)/2
    /** BLS12-381 twist: y² = x³ + 4(1+u). */
    private static final MontFp2_381 B2 = MontFp2_381.of(BigInteger.valueOf(4), BigInteger.valueOf(4));
    private static final BigInteger COFACTOR_G2 = new BigInteger(
            "5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a"
                    + "6691ae1616ec6e786f0c70cf1c38e31c7238e5", 16);

    /** snarkjs {@code hashToG2(curve, transcript)} — {@code transcript} is the 64-byte blake2b hash. */
    static AffineG2 hashToG2(byte[] transcript64) {
        int[] seed = new int[8];
        for (int i = 0; i < 8; i++) {
            seed[i] = ((transcript64[i * 4] & 0xFF) << 24) | ((transcript64[i * 4 + 1] & 0xFF) << 16)
                    | ((transcript64[i * 4 + 2] & 0xFF) << 8) | (transcript64[i * 4 + 3] & 0xFF);
        }
        ChaChaRng rng = new ChaChaRng(seed);

        BigInteger[] x;
        boolean greatest;
        BigInteger[] x3b;
        while (true) {
            x = new BigInteger[]{sampleFp(rng), sampleFp(rng)};
            greatest = rng.nextBool();
            x3b = add(mul(mul(x, x), x), new BigInteger[]{BigInteger.valueOf(4), BigInteger.valueOf(4)});
            if (isSquare(x3b)) break;
        }
        BigInteger[] y = sqrt(x3b);
        if (greatest ^ isNegative(y)) y = neg(y);

        var point = JacobianG2BLS381.fromAffine(
                MontFp2_381.of(x[0], x[1]), MontFp2_381.of(y[0], y[1]));
        return point.scalarMul(COFACTOR_G2).toAffine();
    }

    private static final BigInteger MONT_R_INV = BigInteger.ONE.shiftLeft(384).mod(P).modInverse(P);

    /**
     * ffjavascript Fp sampling: 6 × nextU64 (i-th shifted 64·i), 381-bit mask, retry while ≥ p —
     * <b>then ·R⁻¹</b>: {@code fromRng} writes the sampled bytes canonically but every WASM field op
     * treats buffers as Montgomery form, so the <em>semantic</em> value snarkjs computes with is
     * {@code v·R⁻¹ mod p}. Bug-compatible by design (bellman/snarkjs lineage).
     */
    private static BigInteger sampleFp(ChaChaRng rng) {
        while (true) {
            BigInteger v = BigInteger.ZERO;
            for (int i = 0; i < 6; i++) v = v.or(rng.nextU64().shiftLeft(64 * i));
            v = v.and(MASK_381);
            if (v.compareTo(P) < 0) return v.multiply(MONT_R_INV).mod(P);
        }
    }

    // ---- Fp2 arithmetic on canonical [c0, c1], u² = −1 ----

    private static BigInteger[] mul(BigInteger[] a, BigInteger[] b) {
        BigInteger c0 = a[0].multiply(b[0]).subtract(a[1].multiply(b[1])).mod(P);
        BigInteger c1 = a[0].multiply(b[1]).add(a[1].multiply(b[0])).mod(P);
        return new BigInteger[]{c0, c1};
    }

    private static BigInteger[] add(BigInteger[] a, BigInteger[] b) {
        return new BigInteger[]{a[0].add(b[0]).mod(P), a[1].add(b[1]).mod(P)};
    }

    private static BigInteger[] neg(BigInteger[] a) {
        return new BigInteger[]{a[0].signum() == 0 ? BigInteger.ZERO : P.subtract(a[0]),
                a[1].signum() == 0 ? BigInteger.ZERO : P.subtract(a[1])};
    }

    private static BigInteger[] pow(BigInteger[] base, BigInteger e) {
        BigInteger[] acc = {BigInteger.ONE, BigInteger.ZERO};
        BigInteger[] b = base;
        for (int i = e.bitLength() - 1; i >= 0; i--) {
            acc = mul(acc, acc);
            if (e.testBit(i)) acc = mul(acc, b);
        }
        return acc;
    }

    private static boolean isSquare(BigInteger[] a) {
        if (a[0].signum() == 0 && a[1].signum() == 0) return true;
        BigInteger[] r = pow(a, EULER_FP2);
        return r[0].equals(BigInteger.ONE) && r[1].signum() == 0;
    }

    /** √ in Fp2 for p ≡ 3 (mod 4); caller guarantees the input is a square. */
    private static BigInteger[] sqrt(BigInteger[] a) {
        if (a[1].signum() == 0) {
            // a = a0: either √a0 ∈ Fp, or √(−a0)·u
            BigInteger r = a[0].modPow(SQRT_EXP, P);
            if (r.multiply(r).mod(P).equals(a[0])) return new BigInteger[]{r, BigInteger.ZERO};
            BigInteger r2 = P.subtract(a[0]).modPow(SQRT_EXP, P);
            return new BigInteger[]{BigInteger.ZERO, r2};
        }
        // norm = a0² + a1² (u² = −1); α = √norm; x0 = √((a0+α)/2) (or (a0−α)/2); x1 = a1/(2x0)
        BigInteger norm = a[0].multiply(a[0]).add(a[1].multiply(a[1])).mod(P);
        BigInteger alpha = norm.modPow(SQRT_EXP, P);
        BigInteger inv2 = BigInteger.TWO.modInverse(P);
        BigInteger delta = a[0].add(alpha).multiply(inv2).mod(P);
        BigInteger x0 = delta.modPow(SQRT_EXP, P);
        if (!x0.multiply(x0).mod(P).equals(delta)) {
            delta = a[0].subtract(alpha).multiply(inv2).mod(P);
            x0 = delta.modPow(SQRT_EXP, P);
        }
        BigInteger x1 = a[1].multiply(x0.shiftLeft(1).modInverse(P)).mod(P);
        BigInteger[] root = {x0, x1};
        BigInteger[] check = mul(root, root);
        if (!check[0].equals(a[0]) || !check[1].equals(a[1]))
            throw new IllegalStateException("Fp2 sqrt failed on a certified square");
        return root;
    }

    /** wasmcurves f2m_isNegative: judge c1, falling back to c0 when c1 = 0; negative ⇔ ≥ (p+1)/2. */
    private static boolean isNegative(BigInteger[] a) {
        BigInteger judge = a[1].signum() == 0 ? a[0] : a[1];
        return judge.compareTo(P_HALF_PLUS_ONE) >= 0;
    }
}
