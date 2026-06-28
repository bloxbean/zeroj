package com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;

import java.math.BigInteger;

/**
 * Cardano-profile BLS12-381 PlonK verifier for bounded multi-public-input circuits.
 *
 * <p>This verifier uses the {@code zeroj-plonk-bls12381-cardano-mpi-v1-json}
 * transcript profile. It binds the profile tag, exact public input count, and
 * ordered fixed-width public input scalars before the first challenge.</p>
 */
@SpendingValidator
public class PlonkBLS12381MultiInputVerifier {

    private static final BigInteger MAX_PUBLIC_INPUT_COUNT = BigInteger.valueOf(8);

    @Param static byte[] vkQm;
    @Param static byte[] vkQl;
    @Param static byte[] vkQr;
    @Param static byte[] vkQo;
    @Param static byte[] vkQc;
    @Param static byte[] vkS1;
    @Param static byte[] vkS2;
    @Param static byte[] vkS3;
    @Param static byte[] vkX2;

    @Param static BigInteger domainSize;
    @Param static BigInteger domainPower;
    @Param static BigInteger omega;
    @Param static BigInteger k1;
    @Param static BigInteger k2;
    @Param static BigInteger k1OverK2;
    @Param static BigInteger fr;
    @Param static BigInteger nInv;
    @Param static byte[] g1Gen;
    @Param static byte[] g2Gen;
    @Param static byte[] profileTag;
    @Param static BigInteger publicInputCount;

    record PlonkProof(
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            PlutusData publicInputInverses
    ) {}

    @Entrypoint
    static boolean validate(PlutusData datum, PlonkProof p, PlutusData ctx) {
        if (!validParams() || !validProofShapeAndScalars(p)) {
            return false;
        }

        PlutusData inputs = Builtins.unListData(datum);
        PlutusData inverses = Builtins.unListData(p.publicInputInverses());
        if (!exactLength(inputs, publicInputCount)
                || !exactLength(inverses, publicInputCount)
                || !validScalars(inputs)
                || !validScalars(inverses)) {
            return false;
        }

        BigInteger beta = challenge(cat(
                cat(cat(cat(vkQm, vkQl), cat(vkQr, vkQo)), cat(vkQc, cat(vkS1, vkS2))),
                cat(publicInputTranscript(inputs, cat(vkS3, cat(profileTag, i2bs(publicInputCount)))),
                        cat(p.cmA(), cat(p.cmB(), p.cmC())))));

        BigInteger gamma = challenge(i2bs(beta));
        BigInteger alpha = challenge(cat(cat(i2bs(beta), i2bs(gamma)), p.cmZ()));
        BigInteger xi = challenge(cat(i2bs(alpha), cat(p.cmT1(), cat(p.cmT2(), p.cmT3()))));
        BigInteger v = challenge(cat(
                cat(cat(i2bs(xi), i2bs(p.evalA())), cat(i2bs(p.evalB()), i2bs(p.evalC()))),
                cat(i2bs(p.evalS1()), cat(i2bs(p.evalS2()), i2bs(p.evalZw())))));
        BigInteger u = challenge(cat(p.wXi(), p.wXiw()));

        if (!validPublicInputInverses(inverses, xi, BigInteger.ONE)) {
            return false;
        }
        BigInteger xin = pow2PowerMod(xi, domainPower);
        BigInteger zh = xin.subtract(BigInteger.ONE).mod(fr);
        BigInteger l1 = lagrangeBasis(zh, BigInteger.ONE, Builtins.asInteger(Builtins.headList(inverses)));
        BigInteger pi = publicInputPolynomial(inputs, inverses, zh, BigInteger.ONE);

        BigInteger alpha2 = alpha.multiply(alpha).mod(fr);
        BigInteger e3a = p.evalA().add(beta.multiply(p.evalS1()).mod(fr)).add(gamma).mod(fr);
        BigInteger e3b = p.evalB().add(beta.multiply(p.evalS2()).mod(fr)).add(gamma).mod(fr);
        BigInteger e3c = p.evalC().add(gamma).mod(fr);
        BigInteger e3 = e3a.multiply(e3b).mod(fr).multiply(e3c).mod(fr)
                .multiply(p.evalZw()).mod(fr).multiply(alpha).mod(fr);
        BigInteger r0 = pi.subtract(l1.multiply(alpha2).mod(fr)).mod(fr).subtract(e3).mod(fr);

        byte[] qm = Builtins.bls12_381_G1_uncompress(vkQm);
        byte[] ql = Builtins.bls12_381_G1_uncompress(vkQl);
        byte[] qr = Builtins.bls12_381_G1_uncompress(vkQr);
        byte[] qo = Builtins.bls12_381_G1_uncompress(vkQo);
        byte[] qc = Builtins.bls12_381_G1_uncompress(vkQc);
        byte[] s1 = Builtins.bls12_381_G1_uncompress(vkS1);
        byte[] s2 = Builtins.bls12_381_G1_uncompress(vkS2);
        byte[] s3 = Builtins.bls12_381_G1_uncompress(vkS3);
        byte[] x2 = Builtins.bls12_381_G2_uncompress(vkX2);

        byte[] cA = Builtins.bls12_381_G1_uncompress(p.cmA());
        byte[] cB = Builtins.bls12_381_G1_uncompress(p.cmB());
        byte[] cC = Builtins.bls12_381_G1_uncompress(p.cmC());
        byte[] cZ = Builtins.bls12_381_G1_uncompress(p.cmZ());
        byte[] t1 = Builtins.bls12_381_G1_uncompress(p.cmT1());
        byte[] t2 = Builtins.bls12_381_G1_uncompress(p.cmT2());
        byte[] t3 = Builtins.bls12_381_G1_uncompress(p.cmT3());
        byte[] wXi = Builtins.bls12_381_G1_uncompress(p.wXi());
        byte[] wXiw = Builtins.bls12_381_G1_uncompress(p.wXiw());
        byte[] g1 = Builtins.bls12_381_G1_uncompress(g1Gen);
        byte[] g2 = Builtins.bls12_381_G2_uncompress(g2Gen);

        BigInteger v2 = v.multiply(v).mod(fr);
        BigInteger v3 = v2.multiply(v).mod(fr);
        BigInteger v4 = v3.multiply(v).mod(fr);
        BigInteger v5 = v4.multiply(v).mod(fr);

        byte[] d1 = g1Add(
                g1Add(g1Mul(p.evalA().multiply(p.evalB()).mod(fr), qm), g1Mul(p.evalA(), ql)),
                g1Add(g1Mul(p.evalB(), qr), g1Add(g1Mul(p.evalC(), qo), qc)));

        BigInteger betaXi = beta.multiply(xi).mod(fr);
        BigInteger d2a = p.evalA().add(betaXi).add(gamma).mod(fr)
                .multiply(p.evalB().add(betaXi.multiply(k1).mod(fr)).add(gamma).mod(fr)).mod(fr)
                .multiply(p.evalC().add(betaXi.multiply(k2).mod(fr)).add(gamma).mod(fr)).mod(fr)
                .multiply(alpha).mod(fr);
        BigInteger d2b = l1.multiply(alpha2).mod(fr);
        byte[] d2 = g1Mul(d2a.add(d2b).add(u).mod(fr), cZ);

        BigInteger d3s = p.evalA().add(beta.multiply(p.evalS1()).mod(fr)).add(gamma).mod(fr)
                .multiply(p.evalB().add(beta.multiply(p.evalS2()).mod(fr)).add(gamma).mod(fr)).mod(fr)
                .multiply(alpha.multiply(beta).mod(fr).multiply(p.evalZw()).mod(fr)).mod(fr);
        byte[] d3 = g1Mul(d3s, s3);

        byte[] d4 = g1Mul(zh, g1Add(t1,
                g1Add(g1Mul(xin, t2), g1Mul(xin.multiply(xin).mod(fr), t3))));

        byte[] d = g1Sub(g1Add(d1, d2), g1Add(d3, d4));
        byte[] f = g1Add(
                g1Add(g1Add(d, g1Mul(v, cA)), g1Add(g1Mul(v2, cB), g1Mul(v3, cC))),
                g1Add(g1Mul(v4, s1), g1Mul(v5, s2)));

        BigInteger eScalar = r0.negate().mod(fr)
                .add(v.multiply(p.evalA()).mod(fr))
                .add(v2.multiply(p.evalB()).mod(fr))
                .add(v3.multiply(p.evalC()).mod(fr))
                .add(v4.multiply(p.evalS1()).mod(fr))
                .add(v5.multiply(p.evalS2()).mod(fr))
                .add(u.multiply(p.evalZw()).mod(fr))
                .mod(fr);
        byte[] e = g1Mul(eScalar, g1);

        byte[] b1 = g1Add(
                g1Sub(f, e),
                g1Add(g1Mul(xi, wXi), g1Mul(u.multiply(xi).mod(fr).multiply(omega).mod(fr), wXiw)));
        byte[] a1 = g1Add(wXi, g1Mul(u, wXiw));

        return Builtins.bls12_381_finalVerify(
                Builtins.bls12_381_millerLoop(b1, g2),
                Builtins.bls12_381_millerLoop(a1, x2));
    }

    private static boolean validParams() {
        return fr.signum() > 0
                && publicInputCount.compareTo(BigInteger.ONE) >= 0
                && publicInputCount.compareTo(MAX_PUBLIC_INPUT_COUNT) <= 0
                && publicInputCount.compareTo(domainSize) <= 0
                && Builtins.lengthOfByteString(profileTag) == 40
                && domainPower.compareTo(BigInteger.valueOf(3)) >= 0
                && domainPower.compareTo(BigInteger.valueOf(24)) <= 0
                && domainSize.equals(pow2(domainPower))
                && domainSize.multiply(nInv).mod(fr).equals(BigInteger.ONE)
                && scalarInFr(omega)
                && !omega.equals(BigInteger.ZERO)
                && pow2PowerMod(omega, domainPower).equals(BigInteger.ONE)
                && !pow2PowerMod(omega, domainPower.subtract(BigInteger.ONE)).equals(BigInteger.ONE)
                && scalarInFr(k1)
                && scalarInFr(k2)
                && scalarInFr(k1OverK2)
                && !k1.equals(BigInteger.ZERO)
                && !k2.equals(BigInteger.ZERO)
                && !k1OverK2.equals(BigInteger.ZERO)
                && k1.equals(k1OverK2.multiply(k2).mod(fr))
                && !pow2PowerMod(k1, domainPower).equals(BigInteger.ONE)
                && !pow2PowerMod(k2, domainPower).equals(BigInteger.ONE)
                && !pow2PowerMod(k1OverK2, domainPower).equals(BigInteger.ONE)
                && isCanonicalG1(vkQm)
                && isCanonicalG1(vkQl)
                && isCanonicalG1(vkQr)
                && isCanonicalG1(vkQo)
                && isCanonicalG1(vkQc)
                && isCanonicalNonInfinityG1(vkS1)
                && isCanonicalNonInfinityG1(vkS2)
                && isCanonicalNonInfinityG1(vkS3)
                && isCanonicalNonInfinityG1(g1Gen)
                && isCanonicalNonInfinityG2(vkX2)
                && isCanonicalNonInfinityG2(g2Gen);
    }

    private static boolean validProofShapeAndScalars(PlonkProof p) {
        return scalarInFr(p.evalA())
                && scalarInFr(p.evalB())
                && scalarInFr(p.evalC())
                && scalarInFr(p.evalS1())
                && scalarInFr(p.evalS2())
                && scalarInFr(p.evalZw())
                && isCanonicalNonInfinityG1(p.cmA())
                && isCanonicalNonInfinityG1(p.cmB())
                && isCanonicalNonInfinityG1(p.cmC())
                && isCanonicalNonInfinityG1(p.cmZ())
                && isCanonicalNonInfinityG1(p.cmT1())
                && isCanonicalNonInfinityG1(p.cmT2())
                && isCanonicalNonInfinityG1(p.cmT3())
                && isCanonicalNonInfinityG1(p.wXi())
                && isCanonicalNonInfinityG1(p.wXiw());
    }

    private static boolean scalarInFr(BigInteger value) {
        return value.signum() >= 0 && value.compareTo(fr) < 0;
    }

    private static boolean exactLength(PlutusData cursor, BigInteger remaining) {
        if (remaining.equals(BigInteger.ZERO)) {
            return Builtins.nullList(cursor);
        } else if (Builtins.nullList(cursor)) {
            return false;
        } else {
            return exactLength(Builtins.tailList(cursor), remaining.subtract(BigInteger.ONE));
        }
    }

    private static boolean validScalars(PlutusData cursor) {
        if (Builtins.nullList(cursor)) {
            return true;
        } else {
            return scalarInFr(Builtins.asInteger(Builtins.headList(cursor)))
                    && validScalars(Builtins.tailList(cursor));
        }
    }

    private static byte[] publicInputTranscript(PlutusData inputs, byte[] acc) {
        if (Builtins.nullList(inputs)) {
            return acc;
        } else {
            BigInteger publicInput = Builtins.asInteger(Builtins.headList(inputs));
            return publicInputTranscript(Builtins.tailList(inputs), cat(acc, i2bs(publicInput)));
        }
    }

    private static boolean validPublicInputInverses(PlutusData inverses, BigInteger xi, BigInteger wPow) {
        if (Builtins.nullList(inverses)) {
            return true;
        } else {
            BigInteger inverse = Builtins.asInteger(Builtins.headList(inverses));
            BigInteger denominator = xi.subtract(wPow).mod(fr);
            return denominator.multiply(inverse).mod(fr).equals(BigInteger.ONE)
                    && validPublicInputInverses(Builtins.tailList(inverses), xi, wPow.multiply(omega).mod(fr));
        }
    }

    private static BigInteger lagrangeBasis(BigInteger zh, BigInteger wPow, BigInteger inverse) {
        return wPow.multiply(zh).mod(fr).multiply(nInv).mod(fr).multiply(inverse).mod(fr);
    }

    private static BigInteger publicInputPolynomial(PlutusData inputs, PlutusData inverses,
                                                    BigInteger zh, BigInteger wPow) {
        if (Builtins.nullList(inputs)) {
            return BigInteger.ZERO;
        } else {
            BigInteger publicInput = Builtins.asInteger(Builtins.headList(inputs));
            BigInteger inverse = Builtins.asInteger(Builtins.headList(inverses));
            BigInteger li = lagrangeBasis(zh, wPow, inverse);
            BigInteger tail = publicInputPolynomial(
                    Builtins.tailList(inputs),
                    Builtins.tailList(inverses),
                    zh,
                    wPow.multiply(omega).mod(fr));
            return tail.subtract(publicInput.multiply(li).mod(fr)).mod(fr);
        }
    }

    private static BigInteger challenge(byte[] input) {
        return Builtins.byteStringToInteger(true, Builtins.keccak_256(input)).mod(fr);
    }

    private static byte[] i2bs(BigInteger value) {
        return Builtins.integerToByteString(true, 32, value);
    }

    private static byte[] cat(byte[] a, byte[] b) {
        return Builtins.appendByteString(a, b);
    }

    private static BigInteger pow2(BigInteger power) {
        if (power.equals(BigInteger.ZERO)) {
            return BigInteger.ONE;
        } else {
            return BigInteger.TWO.multiply(pow2(power.subtract(BigInteger.ONE)));
        }
    }

    private static BigInteger pow2PowerMod(BigInteger value, BigInteger power) {
        if (power.equals(BigInteger.ZERO)) {
            return value.mod(fr);
        } else {
            BigInteger squared = value.multiply(value).mod(fr);
            return pow2PowerMod(squared, power.subtract(BigInteger.ONE));
        }
    }

    private static byte[] g1Mul(BigInteger scalar, byte[] point) {
        return Builtins.bls12_381_G1_scalarMul(scalar.mod(fr), point);
    }

    private static byte[] g1Add(byte[] a, byte[] b) {
        return Builtins.bls12_381_G1_add(a, b);
    }

    private static byte[] g1Sub(byte[] a, byte[] b) {
        return Builtins.bls12_381_G1_add(a, Builtins.bls12_381_G1_neg(b));
    }

    private static boolean isCanonicalG1(byte[] compressed) {
        return Builtins.lengthOfByteString(compressed) == 48
                && Builtins.equalsByteString(
                        Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_uncompress(compressed)),
                        compressed);
    }

    private static boolean isCanonicalNonInfinityG1(byte[] compressed) {
        return isCanonicalG1(compressed) && !isCompressedInfinityG1(compressed);
    }

    private static boolean isCanonicalNonInfinityG2(byte[] compressed) {
        return Builtins.lengthOfByteString(compressed) == 96
                && Builtins.equalsByteString(
                        Builtins.bls12_381_G2_compress(Builtins.bls12_381_G2_uncompress(compressed)),
                        compressed)
                && !isCompressedInfinityG2(compressed);
    }

    private static boolean isCompressedInfinityG1(byte[] compressed) {
        return Builtins.lengthOfByteString(compressed) == 48
                && Builtins.indexByteString(compressed, 0) == 192
                && Builtins.equalsByteString(Builtins.sliceByteString(1, 47, compressed), Builtins.replicateByte(47, 0));
    }

    private static boolean isCompressedInfinityG2(byte[] compressed) {
        return Builtins.lengthOfByteString(compressed) == 96
                && Builtins.indexByteString(compressed, 0) == 192
                && Builtins.equalsByteString(Builtins.sliceByteString(1, 95, compressed), Builtins.replicateByte(95, 0));
    }
}
