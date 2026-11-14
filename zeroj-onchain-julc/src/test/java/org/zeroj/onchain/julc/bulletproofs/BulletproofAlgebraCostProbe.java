package org.zeroj.onchain.julc.bulletproofs;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcG1;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/**
 * <b>NOT A VERIFIER.</b> ADR-0061 M4 cost study (D8): the algebra of the
 * {@code bulletproof-range-bls12-381-g1-v1} verifier (spec §8.3) in the Julc VM, with the
 * <b>challenges supplied as inputs</b>. A real verifier must derive them with SHAKE128 (spec §5), and
 * Plutus V3 has no SHAKE128, so this script proves nothing and is never published or admitted. It
 * exists to measure what the algebra costs under PV11.
 *
 * <p>What it does, so the measurement is realistic: checks the proof scalars are canonical and the
 * supplied challenge inverses are inverses; refuses the identity encoding for {@code V} and every
 * proof point; hashes the supplied generator encodings (binding cost, against a digest in the
 * redeemer); computes {@code δ(y, z)}, the challenge products {@code s_i} (most significant bit
 * first) and every check-2 coefficient on-chain; decompresses every point (with its subgroup check)
 * and evaluates check 1 (5 terms) and check 2 ({@code 2n + 2k + 4} terms) with
 * {@code bls12_381_G1_multiScalarMul}, each compared with the identity.
 */
@SpendingValidator
public class BulletproofAlgebraCostProbe {

    record Probe(BigInteger n, BigInteger y, BigInteger yInv, BigInteger z, BigInteger x, BigInteger xu,
                 JulcList<BigInteger> xj, JulcList<BigInteger> xjInv,
                 BigInteger tHat, BigInteger tauX, BigInteger mu, BigInteger a, BigInteger b,
                 byte[] v, byte[] bigA, byte[] bigS, byte[] t1, byte[] t2, JulcList<byte[]> ls, JulcList<byte[]> rs,
                 JulcList<byte[]> gens, byte[] gensDigest) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe p, ScriptContext ctx) {
        BigInteger q = PedersenG1Lib.groupOrder();
        if (!canonical(p.tHat(), q) || !canonical(p.tauX(), q) || !canonical(p.mu(), q)
                || !canonical(p.a(), q) || !canonical(p.b(), q)) {
            Builtins.error();
        }
        if (!inverse(p.y(), p.yInv(), q) || !inverses(p.xj(), p.xjInv(), q)) {
            Builtins.error();
        }
        if (isInfinity(p.v()) || isInfinity(p.bigA()) || isInfinity(p.bigS()) || isInfinity(p.t1()) || isInfinity(p.t2())
                || anyInfinity(p.ls()) || anyInfinity(p.rs())) {
            Builtins.error();
        }
        // Binding the generators: a real verifier would embed them or their digest.
        if (!Builtins.equalsByteString(Builtins.sha2_256(concat(p.gens())), p.gensDigest())) {
            Builtins.error();
        }
        byte[] g = PedersenG1Lib.baseGEncoding();
        byte[] h = PedersenG1Lib.baseHEncoding();

        // Check 1: [t̂ − δ]·G + [τ_x]·H + [−z²]·V + [−x]·T₁ + [−x²]·T₂ == O.
        BigInteger z2 = p.z().multiply(p.z()).mod(q);
        BigInteger delta = delta(p.y(), p.z(), z2, p.n(), q);
        JulcList<BigInteger> s1 = JulcList.of(p.tHat().subtract(delta).mod(q), p.tauX(), q.subtract(z2).mod(q),
                q.subtract(p.x()).mod(q), q.subtract(p.x().multiply(p.x()).mod(q)).mod(q));
        JulcList<byte[]> pts1 = JulcList.of(g, h, p.v(), p.t1(), p.t2());
        boolean check1 = isIdentity(Builtins.bls12_381_G1_multiScalarMul(Builtins.scalarsFromList(s1),
                Builtins.g1PointsFromCompressed(pts1)));

        // Check 2 (paper (105) with the independent U).
        JulcList<BigInteger> s = products(p.xj(), p.xjInv(), JulcList.of(BigInteger.ONE), q);
        JulcList<BigInteger> sInv = products(p.xjInv(), p.xj(), JulcList.of(BigInteger.ONE), q);
        JulcList<BigInteger> gCoeffs = gCoefficients(s, p.a(), p.z(), q, JulcList.empty()).reverse();
        JulcList<BigInteger> hCoeffs = hCoefficients(sInv, p.b(), p.z(), z2, BigInteger.ONE, p.yInv(), BigInteger.ONE, q,
                JulcList.empty()).reverse();
        BigInteger uCoeff = p.xu().multiply(p.a().multiply(p.b()).subtract(p.tHat())).mod(q);
        JulcList<BigInteger> tail = JulcList.of(uCoeff, p.mu(), q.subtract(BigInteger.ONE), q.subtract(p.x()).mod(q));
        JulcList<BigInteger> scalars2 = gCoeffs.concat(hCoeffs).concat(tail)
                .concat(negSquares(p.xj(), q, JulcList.empty()).reverse())
                .concat(negSquares(p.xjInv(), q, JulcList.empty()).reverse());
        JulcList<byte[]> pts2 = p.gens().concat(JulcList.of(h, p.bigA(), p.bigS())).concat(p.ls()).concat(p.rs());
        boolean check2 = isIdentity(Builtins.bls12_381_G1_multiScalarMul(Builtins.scalarsFromList(scalars2),
                Builtins.g1PointsFromCompressed(pts2)));
        return check1 && check2;
    }

    static boolean canonical(BigInteger s, BigInteger q) {
        return s.signum() >= 0 && s.compareTo(q) < 0;
    }

    static boolean inverse(BigInteger c, BigInteger cInv, BigInteger q) {
        return c.signum() != 0 && c.multiply(cInv).mod(q).equals(BigInteger.ONE);
    }

    static boolean inverses(JulcList<BigInteger> cs, JulcList<BigInteger> invs, BigInteger q) {
        if (cs.isEmpty()) {
            return invs.isEmpty();
        }
        if (invs.isEmpty()) {
            return false;
        }
        return inverse(cs.head(), invs.head(), q) && inverses(cs.tail(), invs.tail(), q);
    }

    static boolean isInfinity(byte[] encoded) {
        return Builtins.indexByteString(encoded, 0L) == 192L;
    }

    static boolean anyInfinity(JulcList<byte[]> points) {
        if (points.isEmpty()) {
            return false;
        }
        return isInfinity(points.head()) || anyInfinity(points.tail());
    }

    static byte[] concat(JulcList<byte[]> parts) {
        if (parts.isEmpty()) {
            return Builtins.emptyByteString();
        }
        return Builtins.appendByteString(parts.head(), concat(parts.tail()));
    }

    static boolean isIdentity(JulcG1 point) {
        return Builtins.equalsByteString(Builtins.bls12_381_G1_compress(point), identityEncoding());
    }

    static byte[] identityEncoding() {
        return Builtins.consByteString(192L, Builtins.replicateByte(47L, 0L));
    }

    /** δ(y, z) = (z − z²)·Σ_{i<n} y^i − z³·(2^n − 1). */
    static BigInteger delta(BigInteger y, BigInteger z, BigInteger z2, BigInteger n, BigInteger q) {
        BigInteger sumY = sumPowers(y, n, BigInteger.ONE, BigInteger.ZERO, q);
        BigInteger z3 = z2.multiply(z).mod(q);
        BigInteger twoN = sumPowers(BigInteger.TWO, n, BigInteger.ONE, BigInteger.ZERO, q);   // 2^n − 1
        return z.subtract(z2).multiply(sumY).subtract(z3.multiply(twoN)).mod(q);
    }

    static BigInteger sumPowers(BigInteger y, BigInteger left, BigInteger power, BigInteger acc, BigInteger q) {
        if (left.signum() == 0) {
            return acc;
        }
        return sumPowers(y, left.subtract(BigInteger.ONE), power.multiply(y).mod(q), acc.add(power).mod(q), q);
    }

    /** The s_i of spec §8.3, x_1 first: each round splits every entry into (·x⁻¹, ·x), in that order. */
    static JulcList<BigInteger> products(JulcList<BigInteger> xs, JulcList<BigInteger> xsInv, JulcList<BigInteger> acc,
                                         BigInteger q) {
        if (xs.isEmpty()) {
            return acc;
        }
        return products(xs.tail(), xsInv.tail(), split(acc, xsInv.head(), xs.head(), q, JulcList.empty()).reverse(), q);
    }

    static JulcList<BigInteger> split(JulcList<BigInteger> acc, BigInteger lo, BigInteger hi, BigInteger q,
                                      JulcList<BigInteger> out) {
        if (acc.isEmpty()) {
            return out;
        }
        BigInteger s = acc.head();
        return split(acc.tail(), lo, hi, q, out.prepend(s.multiply(lo).mod(q)).prepend(s.multiply(hi).mod(q)));
    }

    /** a·s_i + z, reversed. */
    static JulcList<BigInteger> gCoefficients(JulcList<BigInteger> s, BigInteger a, BigInteger z, BigInteger q,
                                              JulcList<BigInteger> out) {
        if (s.isEmpty()) {
            return out;
        }
        return gCoefficients(s.tail(), a, z, q, out.prepend(a.multiply(s.head()).add(z).mod(q)));
    }

    /** y^{−i}·(b·s_i⁻¹ − z²·2^i) − z, reversed. */
    static JulcList<BigInteger> hCoefficients(JulcList<BigInteger> sInv, BigInteger b, BigInteger z, BigInteger z2,
                                              BigInteger yInvPow, BigInteger yInv, BigInteger twoPow, BigInteger q,
                                              JulcList<BigInteger> out) {
        if (sInv.isEmpty()) {
            return out;
        }
        BigInteger c = yInvPow.multiply(b.multiply(sInv.head()).subtract(z2.multiply(twoPow))).subtract(z).mod(q);
        return hCoefficients(sInv.tail(), b, z, z2, yInvPow.multiply(yInv).mod(q), yInv, twoPow.add(twoPow), q,
                out.prepend(c));
    }

    /** −c², reversed. */
    static JulcList<BigInteger> negSquares(JulcList<BigInteger> cs, BigInteger q, JulcList<BigInteger> out) {
        if (cs.isEmpty()) {
            return out;
        }
        return negSquares(cs.tail(), q, out.prepend(q.subtract(cs.head().multiply(cs.head()).mod(q)).mod(q)));
    }
}
