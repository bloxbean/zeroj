package com.bloxbean.cardano.zeroj.onchain.julc.plonk.lib;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.OnchainLibrary;

import java.math.BigInteger;

/**
 * Reusable on-chain PlonK verifier logic for ZeroJ BLS12-381 Cardano profiles.
 *
 * <p>The library verifies only the cryptographic proof statement. Custom spending
 * validators must still enforce application policy such as authorization,
 * nullifiers, replay protection, and ScriptContext binding.</p>
 */
@OnchainLibrary
public class PlonkBLS12381Lib {

    private static final BigInteger MAX_PUBLIC_INPUT_COUNT = BigInteger.valueOf(8);

    public static boolean verifyOneInput(
            PlutusData datum,
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            BigInteger xiMinusOneInv, BigInteger xiMinusOmegaInv,
            byte[] vkQm, byte[] vkQl, byte[] vkQr, byte[] vkQo, byte[] vkQc,
            byte[] vkS1, byte[] vkS2, byte[] vkS3, byte[] vkX2,
            BigInteger domainSize, BigInteger domainPower,
            BigInteger omega, BigInteger k1, BigInteger k2, BigInteger k1OverK2,
            BigInteger fr, BigInteger nInv,
            byte[] g1Gen, byte[] g2Gen) {
        if (!validParamsBase(vkQm, vkQl, vkQr, vkQo, vkQc, vkS1, vkS2, vkS3, vkX2,
                domainSize, domainPower, omega, k1, k2, k1OverK2, fr, nInv, g1Gen, g2Gen)
                || !validProofShapeAndScalars(cmA, cmB, cmC, cmZ, cmT1, cmT2, cmT3, wXi, wXiw,
                evalA, evalB, evalC, evalS1, evalS2, evalZw, fr)
                || !scalarInFr(xiMinusOneInv, fr)
                || !scalarInFr(xiMinusOmegaInv, fr)) {
            return false;
        }

        PlutusData inputs = Builtins.unListData(datum);
        if (Builtins.nullList(inputs) || !Builtins.nullList(Builtins.tailList(inputs))) {
            return false;
        }
        BigInteger pub0 = Builtins.asInteger(Builtins.headList(inputs));
        if (!scalarInFr(pub0, fr)) {
            return false;
        }

        BigInteger beta = challenge(cat(
                cat(cat(cat(vkQm, vkQl), cat(vkQr, vkQo)), cat(vkQc, cat(vkS1, vkS2))),
                cat(cat(vkS3, i2bs(pub0)), cat(cmA, cat(cmB, cmC)))), fr);

        BigInteger gamma = challenge(i2bs(beta), fr);
        BigInteger alpha = challenge(cat(cat(i2bs(beta), i2bs(gamma)), cmZ), fr);
        BigInteger xi = challenge(cat(i2bs(alpha), cat(cmT1, cat(cmT2, cmT3))), fr);
        BigInteger v = challenge(cat(
                cat(cat(i2bs(xi), i2bs(evalA)), cat(i2bs(evalB), i2bs(evalC))),
                cat(i2bs(evalS1), cat(i2bs(evalS2), i2bs(evalZw)))), fr);
        BigInteger u = challenge(cat(wXi, wXiw), fr);

        BigInteger xiMinusOne = xi.subtract(BigInteger.ONE).mod(fr);
        BigInteger xiMinusOmega = xi.subtract(omega).mod(fr);
        if (!xiMinusOne.multiply(xiMinusOneInv).mod(fr).equals(BigInteger.ONE)
                || !xiMinusOmega.multiply(xiMinusOmegaInv).mod(fr).equals(BigInteger.ONE)) {
            return false;
        }
        BigInteger xin = pow2PowerMod(xi, domainPower, fr);
        BigInteger zh = xin.subtract(BigInteger.ONE).mod(fr);
        BigInteger l1 = zh.multiply(nInv).mod(fr).multiply(xiMinusOneInv).mod(fr);
        BigInteger pi = pub0.multiply(l1).mod(fr).negate().mod(fr);

        return verifyKzg(cmA, cmB, cmC, cmZ, cmT1, cmT2, cmT3, wXi, wXiw,
                evalA, evalB, evalC, evalS1, evalS2, evalZw,
                vkQm, vkQl, vkQr, vkQo, vkQc, vkS1, vkS2, vkS3, vkX2,
                alpha, beta, gamma, xi, v, u, r0(pi, l1, alpha, beta, gamma,
                        evalA, evalB, evalC, evalS1, evalS2, evalZw, fr),
                l1, zh, xin, k1, k2, fr, omega, g1Gen, g2Gen);
    }

    public static boolean verifyMultiInputDatum(
            PlutusData datum,
            PlutusData publicInputInverses,
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            byte[] vkQm, byte[] vkQl, byte[] vkQr, byte[] vkQo, byte[] vkQc,
            byte[] vkS1, byte[] vkS2, byte[] vkS3, byte[] vkX2,
            BigInteger domainSize, BigInteger domainPower,
            BigInteger omega, BigInteger k1, BigInteger k2, BigInteger k1OverK2,
            BigInteger fr, BigInteger nInv,
            byte[] g1Gen, byte[] g2Gen,
            byte[] profileTag, BigInteger publicInputCount) {
        PlutusData inputs = Builtins.unListData(datum);
        return verifyMultiInputWithInputs(inputs, publicInputCount, publicInputInverses,
                cmA, cmB, cmC, cmZ, cmT1, cmT2, cmT3, wXi, wXiw,
                evalA, evalB, evalC, evalS1, evalS2, evalZw,
                vkQm, vkQl, vkQr, vkQo, vkQc, vkS1, vkS2, vkS3, vkX2,
                domainSize, domainPower, omega, k1, k2, k1OverK2, fr, nInv,
                g1Gen, g2Gen, profileTag);
    }

    public static boolean verifyMultiInputParams(
            PlutusData publicInputs,
            PlutusData publicInputInverses,
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            byte[] vkQm, byte[] vkQl, byte[] vkQr, byte[] vkQo, byte[] vkQc,
            byte[] vkS1, byte[] vkS2, byte[] vkS3, byte[] vkX2,
            BigInteger domainSize, BigInteger domainPower,
            BigInteger omega, BigInteger k1, BigInteger k2, BigInteger k1OverK2,
            BigInteger fr, BigInteger nInv,
            byte[] g1Gen, byte[] g2Gen,
            byte[] profileTag) {
        PlutusData inputs = Builtins.unListData(publicInputs);
        BigInteger publicInputCount = boundedLength(inputs, BigInteger.ZERO);
        return verifyMultiInputWithInputs(inputs, publicInputCount, publicInputInverses,
                cmA, cmB, cmC, cmZ, cmT1, cmT2, cmT3, wXi, wXiw,
                evalA, evalB, evalC, evalS1, evalS2, evalZw,
                vkQm, vkQl, vkQr, vkQo, vkQc, vkS1, vkS2, vkS3, vkX2,
                domainSize, domainPower, omega, k1, k2, k1OverK2, fr, nInv,
                g1Gen, g2Gen, profileTag);
    }

    private static boolean verifyMultiInputWithInputs(
            PlutusData inputs, BigInteger publicInputCount,
            PlutusData publicInputInverses,
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            byte[] vkQm, byte[] vkQl, byte[] vkQr, byte[] vkQo, byte[] vkQc,
            byte[] vkS1, byte[] vkS2, byte[] vkS3, byte[] vkX2,
            BigInteger domainSize, BigInteger domainPower,
            BigInteger omega, BigInteger k1, BigInteger k2, BigInteger k1OverK2,
            BigInteger fr, BigInteger nInv,
            byte[] g1Gen, byte[] g2Gen, byte[] profileTag) {
        if (!validParamsMpi(publicInputCount, profileTag, vkQm, vkQl, vkQr, vkQo, vkQc,
                vkS1, vkS2, vkS3, vkX2, domainSize, domainPower, omega, k1, k2,
                k1OverK2, fr, nInv, g1Gen, g2Gen)
                || !validProofShapeAndScalars(cmA, cmB, cmC, cmZ, cmT1, cmT2, cmT3, wXi, wXiw,
                evalA, evalB, evalC, evalS1, evalS2, evalZw, fr)) {
            return false;
        }

        PlutusData inverses = Builtins.unListData(publicInputInverses);
        if (!exactLength(inputs, publicInputCount)
                || !exactLength(inverses, publicInputCount)
                || !validScalars(inputs, fr)
                || !validScalars(inverses, fr)) {
            return false;
        }

        BigInteger beta = challenge(cat(
                cat(cat(cat(vkQm, vkQl), cat(vkQr, vkQo)), cat(vkQc, cat(vkS1, vkS2))),
                cat(publicInputTranscript(inputs, cat(vkS3, cat(profileTag, i2bs(publicInputCount)))),
                        cat(cmA, cat(cmB, cmC)))), fr);

        BigInteger gamma = challenge(i2bs(beta), fr);
        BigInteger alpha = challenge(cat(cat(i2bs(beta), i2bs(gamma)), cmZ), fr);
        BigInteger xi = challenge(cat(i2bs(alpha), cat(cmT1, cat(cmT2, cmT3))), fr);
        BigInteger v = challenge(cat(
                cat(cat(i2bs(xi), i2bs(evalA)), cat(i2bs(evalB), i2bs(evalC))),
                cat(i2bs(evalS1), cat(i2bs(evalS2), i2bs(evalZw)))), fr);
        BigInteger u = challenge(cat(wXi, wXiw), fr);

        if (!validPublicInputInverses(inverses, xi, BigInteger.ONE, omega, fr)) {
            return false;
        }
        BigInteger xin = pow2PowerMod(xi, domainPower, fr);
        BigInteger zh = xin.subtract(BigInteger.ONE).mod(fr);
        BigInteger l1 = lagrangeBasis(zh, BigInteger.ONE, Builtins.asInteger(Builtins.headList(inverses)), nInv, fr);
        BigInteger pi = publicInputPolynomial(inputs, inverses, zh, BigInteger.ONE, omega, nInv, fr);

        return verifyKzg(cmA, cmB, cmC, cmZ, cmT1, cmT2, cmT3, wXi, wXiw,
                evalA, evalB, evalC, evalS1, evalS2, evalZw,
                vkQm, vkQl, vkQr, vkQo, vkQc, vkS1, vkS2, vkS3, vkX2,
                alpha, beta, gamma, xi, v, u, r0(pi, l1, alpha, beta, gamma,
                        evalA, evalB, evalC, evalS1, evalS2, evalZw, fr),
                l1, zh, xin, k1, k2, fr, omega, g1Gen, g2Gen);
    }

    private static boolean verifyKzg(
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            byte[] vkQm, byte[] vkQl, byte[] vkQr, byte[] vkQo, byte[] vkQc,
            byte[] vkS1, byte[] vkS2, byte[] vkS3, byte[] vkX2,
            BigInteger alpha, BigInteger beta, BigInteger gamma,
            BigInteger xi, BigInteger v, BigInteger u, BigInteger r0,
            BigInteger l1, BigInteger zh, BigInteger xin,
            BigInteger k1, BigInteger k2,
            BigInteger fr, BigInteger omega,
            byte[] g1Gen, byte[] g2Gen) {
        byte[] qm = Builtins.bls12_381_G1_uncompress(vkQm);
        byte[] ql = Builtins.bls12_381_G1_uncompress(vkQl);
        byte[] qr = Builtins.bls12_381_G1_uncompress(vkQr);
        byte[] qo = Builtins.bls12_381_G1_uncompress(vkQo);
        byte[] qc = Builtins.bls12_381_G1_uncompress(vkQc);
        byte[] s1 = Builtins.bls12_381_G1_uncompress(vkS1);
        byte[] s2 = Builtins.bls12_381_G1_uncompress(vkS2);
        byte[] s3 = Builtins.bls12_381_G1_uncompress(vkS3);
        byte[] x2 = Builtins.bls12_381_G2_uncompress(vkX2);

        byte[] cA = Builtins.bls12_381_G1_uncompress(cmA);
        byte[] cB = Builtins.bls12_381_G1_uncompress(cmB);
        byte[] cC = Builtins.bls12_381_G1_uncompress(cmC);
        byte[] cZ = Builtins.bls12_381_G1_uncompress(cmZ);
        byte[] t1 = Builtins.bls12_381_G1_uncompress(cmT1);
        byte[] t2 = Builtins.bls12_381_G1_uncompress(cmT2);
        byte[] t3 = Builtins.bls12_381_G1_uncompress(cmT3);
        byte[] wXiG1 = Builtins.bls12_381_G1_uncompress(wXi);
        byte[] wXiwG1 = Builtins.bls12_381_G1_uncompress(wXiw);
        byte[] g1 = Builtins.bls12_381_G1_uncompress(g1Gen);
        byte[] g2 = Builtins.bls12_381_G2_uncompress(g2Gen);

        BigInteger v2 = v.multiply(v).mod(fr);
        BigInteger v3 = v2.multiply(v).mod(fr);
        BigInteger v4 = v3.multiply(v).mod(fr);
        BigInteger v5 = v4.multiply(v).mod(fr);

        byte[] d1 = g1Add(
                g1Add(g1Mul(evalA.multiply(evalB).mod(fr), qm, fr), g1Mul(evalA, ql, fr)),
                g1Add(g1Mul(evalB, qr, fr), g1Add(g1Mul(evalC, qo, fr), qc)));

        BigInteger betaXi = beta.multiply(xi).mod(fr);
        BigInteger d2a = evalA.add(betaXi).add(gamma).mod(fr)
                .multiply(evalB.add(betaXi.multiply(k1).mod(fr)).add(gamma).mod(fr)).mod(fr)
                .multiply(evalC.add(betaXi.multiply(k2).mod(fr)).add(gamma).mod(fr)).mod(fr)
                .multiply(alpha).mod(fr);
        BigInteger d2b = l1.multiply(alpha.multiply(alpha).mod(fr)).mod(fr);
        byte[] d2 = g1Mul(d2a.add(d2b).add(u).mod(fr), cZ, fr);

        BigInteger d3s = evalA.add(beta.multiply(evalS1).mod(fr)).add(gamma).mod(fr)
                .multiply(evalB.add(beta.multiply(evalS2).mod(fr)).add(gamma).mod(fr)).mod(fr)
                .multiply(alpha.multiply(beta).mod(fr).multiply(evalZw).mod(fr)).mod(fr);
        byte[] d3 = g1Mul(d3s, s3, fr);

        byte[] d4 = g1Mul(zh, g1Add(t1,
                g1Add(g1Mul(xin, t2, fr), g1Mul(xin.multiply(xin).mod(fr), t3, fr))), fr);

        byte[] d = g1Sub(g1Add(d1, d2), g1Add(d3, d4));
        byte[] f = g1Add(
                g1Add(g1Add(d, g1Mul(v, cA, fr)), g1Add(g1Mul(v2, cB, fr), g1Mul(v3, cC, fr))),
                g1Add(g1Mul(v4, s1, fr), g1Mul(v5, s2, fr)));

        BigInteger eScalar = r0.negate().mod(fr)
                .add(v.multiply(evalA).mod(fr))
                .add(v2.multiply(evalB).mod(fr))
                .add(v3.multiply(evalC).mod(fr))
                .add(v4.multiply(evalS1).mod(fr))
                .add(v5.multiply(evalS2).mod(fr))
                .add(u.multiply(evalZw).mod(fr))
                .mod(fr);
        byte[] e = g1Mul(eScalar, g1, fr);

        byte[] b1 = g1Add(
                g1Sub(f, e),
                g1Add(g1Mul(xi, wXiG1, fr), g1Mul(u.multiply(xi).mod(fr).multiply(omega).mod(fr), wXiwG1, fr)));
        byte[] a1 = g1Add(wXiG1, g1Mul(u, wXiwG1, fr));

        return Builtins.bls12_381_finalVerify(
                Builtins.bls12_381_millerLoop(b1, g2),
                Builtins.bls12_381_millerLoop(a1, x2));
    }

    private static BigInteger r0(BigInteger pi, BigInteger l1, BigInteger alpha, BigInteger beta, BigInteger gamma,
                                 BigInteger evalA, BigInteger evalB, BigInteger evalC,
                                 BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
                                 BigInteger fr) {
        BigInteger alpha2 = alpha.multiply(alpha).mod(fr);
        BigInteger e3a = evalA.add(beta.multiply(evalS1).mod(fr)).add(gamma).mod(fr);
        BigInteger e3b = evalB.add(beta.multiply(evalS2).mod(fr)).add(gamma).mod(fr);
        BigInteger e3c = evalC.add(gamma).mod(fr);
        BigInteger e3 = e3a.multiply(e3b).mod(fr).multiply(e3c).mod(fr)
                .multiply(evalZw).mod(fr).multiply(alpha).mod(fr);
        return pi.subtract(l1.multiply(alpha2).mod(fr)).mod(fr).subtract(e3).mod(fr);
    }

    private static boolean validParamsMpi(
            BigInteger publicInputCount, byte[] profileTag,
            byte[] vkQm, byte[] vkQl, byte[] vkQr, byte[] vkQo, byte[] vkQc,
            byte[] vkS1, byte[] vkS2, byte[] vkS3, byte[] vkX2,
            BigInteger domainSize, BigInteger domainPower,
            BigInteger omega, BigInteger k1, BigInteger k2, BigInteger k1OverK2,
            BigInteger fr, BigInteger nInv,
            byte[] g1Gen, byte[] g2Gen) {
        return publicInputCount.compareTo(BigInteger.ONE) >= 0
                && publicInputCount.compareTo(MAX_PUBLIC_INPUT_COUNT) <= 0
                && publicInputCount.compareTo(domainSize) <= 0
                && Builtins.lengthOfByteString(profileTag) == 40
                && validParamsBase(vkQm, vkQl, vkQr, vkQo, vkQc, vkS1, vkS2, vkS3, vkX2,
                domainSize, domainPower, omega, k1, k2, k1OverK2, fr, nInv, g1Gen, g2Gen);
    }

    private static boolean validParamsBase(
            byte[] vkQm, byte[] vkQl, byte[] vkQr, byte[] vkQo, byte[] vkQc,
            byte[] vkS1, byte[] vkS2, byte[] vkS3, byte[] vkX2,
            BigInteger domainSize, BigInteger domainPower,
            BigInteger omega, BigInteger k1, BigInteger k2, BigInteger k1OverK2,
            BigInteger fr, BigInteger nInv,
            byte[] g1Gen, byte[] g2Gen) {
        return fr.signum() > 0
                && domainPower.compareTo(BigInteger.valueOf(3)) >= 0
                && domainPower.compareTo(BigInteger.valueOf(24)) <= 0
                && domainSize.equals(pow2(domainPower))
                && domainSize.multiply(nInv).mod(fr).equals(BigInteger.ONE)
                && scalarInFr(omega, fr)
                && !omega.equals(BigInteger.ZERO)
                && pow2PowerMod(omega, domainPower, fr).equals(BigInteger.ONE)
                && !pow2PowerMod(omega, domainPower.subtract(BigInteger.ONE), fr).equals(BigInteger.ONE)
                && scalarInFr(k1, fr)
                && scalarInFr(k2, fr)
                && scalarInFr(k1OverK2, fr)
                && !k1.equals(BigInteger.ZERO)
                && !k2.equals(BigInteger.ZERO)
                && !k1OverK2.equals(BigInteger.ZERO)
                && k1.equals(k1OverK2.multiply(k2).mod(fr))
                && !pow2PowerMod(k1, domainPower, fr).equals(BigInteger.ONE)
                && !pow2PowerMod(k2, domainPower, fr).equals(BigInteger.ONE)
                && !pow2PowerMod(k1OverK2, domainPower, fr).equals(BigInteger.ONE)
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

    private static boolean validProofShapeAndScalars(
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            BigInteger fr) {
        return scalarInFr(evalA, fr)
                && scalarInFr(evalB, fr)
                && scalarInFr(evalC, fr)
                && scalarInFr(evalS1, fr)
                && scalarInFr(evalS2, fr)
                && scalarInFr(evalZw, fr)
                && isCanonicalNonInfinityG1(cmA)
                && isCanonicalNonInfinityG1(cmB)
                && isCanonicalNonInfinityG1(cmC)
                && isCanonicalNonInfinityG1(cmZ)
                && isCanonicalNonInfinityG1(cmT1)
                && isCanonicalNonInfinityG1(cmT2)
                && isCanonicalNonInfinityG1(cmT3)
                && isCanonicalNonInfinityG1(wXi)
                && isCanonicalNonInfinityG1(wXiw);
    }

    private static boolean scalarInFr(BigInteger value, BigInteger fr) {
        return value.signum() >= 0 && value.compareTo(fr) < 0;
    }

    private static BigInteger boundedLength(PlutusData cursor, BigInteger count) {
        if (Builtins.nullList(cursor)) {
            return count;
        } else if (count.equals(MAX_PUBLIC_INPUT_COUNT)) {
            return MAX_PUBLIC_INPUT_COUNT.add(BigInteger.ONE);
        } else {
            return boundedLength(Builtins.tailList(cursor), count.add(BigInteger.ONE));
        }
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

    private static boolean validScalars(PlutusData cursor, BigInteger fr) {
        if (Builtins.nullList(cursor)) {
            return true;
        } else {
            return scalarInFr(Builtins.asInteger(Builtins.headList(cursor)), fr)
                    && validScalars(Builtins.tailList(cursor), fr);
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

    private static boolean validPublicInputInverses(
            PlutusData inverses, BigInteger xi, BigInteger wPow, BigInteger omega, BigInteger fr) {
        if (Builtins.nullList(inverses)) {
            return true;
        } else {
            BigInteger inverse = Builtins.asInteger(Builtins.headList(inverses));
            BigInteger denominator = xi.subtract(wPow).mod(fr);
            return denominator.multiply(inverse).mod(fr).equals(BigInteger.ONE)
                    && validPublicInputInverses(Builtins.tailList(inverses), xi,
                    wPow.multiply(omega).mod(fr), omega, fr);
        }
    }

    private static BigInteger lagrangeBasis(BigInteger zh, BigInteger wPow,
                                            BigInteger inverse, BigInteger nInv, BigInteger fr) {
        return wPow.multiply(zh).mod(fr).multiply(nInv).mod(fr).multiply(inverse).mod(fr);
    }

    private static BigInteger publicInputPolynomial(
            PlutusData inputs, PlutusData inverses, BigInteger zh, BigInteger wPow,
            BigInteger omega, BigInteger nInv, BigInteger fr) {
        if (Builtins.nullList(inputs)) {
            return BigInteger.ZERO;
        } else {
            BigInteger publicInput = Builtins.asInteger(Builtins.headList(inputs));
            BigInteger inverse = Builtins.asInteger(Builtins.headList(inverses));
            BigInteger li = lagrangeBasis(zh, wPow, inverse, nInv, fr);
            BigInteger tail = publicInputPolynomial(
                    Builtins.tailList(inputs),
                    Builtins.tailList(inverses),
                    zh,
                    wPow.multiply(omega).mod(fr),
                    omega,
                    nInv,
                    fr);
            return tail.subtract(publicInput.multiply(li).mod(fr)).mod(fr);
        }
    }

    private static BigInteger challenge(byte[] input, BigInteger fr) {
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

    private static BigInteger pow2PowerMod(BigInteger value, BigInteger power, BigInteger fr) {
        if (power.equals(BigInteger.ZERO)) {
            return value.mod(fr);
        } else {
            BigInteger squared = value.multiply(value).mod(fr);
            return pow2PowerMod(squared, power.subtract(BigInteger.ONE), fr);
        }
    }

    private static byte[] g1Mul(BigInteger scalar, byte[] point, BigInteger fr) {
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
