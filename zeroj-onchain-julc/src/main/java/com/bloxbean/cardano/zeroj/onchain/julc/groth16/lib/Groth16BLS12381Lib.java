package com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.OnchainLibrary;

import java.math.BigInteger;

/**
 * Reusable on-chain Groth16 verifier logic for BLS12-381 proofs.
 */
@OnchainLibrary
public class Groth16BLS12381Lib {

    public static PlutusData publicInputs(BigInteger pub0) {
        return Builtins.listData(Builtins.mkCons(
                Builtins.iData(pub0),
                Builtins.mkNilData()));
    }

    public static PlutusData publicInputs(BigInteger pub0, BigInteger pub1) {
        return Builtins.listData(Builtins.mkCons(
                Builtins.iData(pub0),
                Builtins.mkCons(
                        Builtins.iData(pub1),
                        Builtins.mkNilData())));
    }

    public static PlutusData publicInputs(BigInteger pub0, BigInteger pub1, BigInteger pub2) {
        return Builtins.listData(Builtins.mkCons(
                Builtins.iData(pub0),
                Builtins.mkCons(
                        Builtins.iData(pub1),
                        Builtins.mkCons(
                                Builtins.iData(pub2),
                                Builtins.mkNilData()))));
    }

    public static PlutusData publicInputs(BigInteger pub0, BigInteger pub1, BigInteger pub2,
                                          BigInteger pub3) {
        return Builtins.listData(Builtins.mkCons(
                Builtins.iData(pub0),
                Builtins.mkCons(
                        Builtins.iData(pub1),
                        Builtins.mkCons(
                                Builtins.iData(pub2),
                                Builtins.mkCons(
                                        Builtins.iData(pub3),
                                        Builtins.mkNilData())))));
    }

    public static PlutusData publicInputs(BigInteger pub0, BigInteger pub1, BigInteger pub2,
                                          BigInteger pub3, BigInteger pub4) {
        return Builtins.listData(Builtins.mkCons(
                Builtins.iData(pub0),
                Builtins.mkCons(
                        Builtins.iData(pub1),
                        Builtins.mkCons(
                                Builtins.iData(pub2),
                                Builtins.mkCons(
                                        Builtins.iData(pub3),
                                        Builtins.mkCons(
                                                Builtins.iData(pub4),
                                                Builtins.mkNilData()))))));
    }

    public static PlutusData publicInputs(BigInteger pub0, BigInteger pub1, BigInteger pub2,
                                          BigInteger pub3, BigInteger pub4, BigInteger pub5) {
        return Builtins.listData(Builtins.mkCons(
                Builtins.iData(pub0),
                Builtins.mkCons(
                        Builtins.iData(pub1),
                        Builtins.mkCons(
                                Builtins.iData(pub2),
                                Builtins.mkCons(
                                        Builtins.iData(pub3),
                                        Builtins.mkCons(
                                                Builtins.iData(pub4),
                                                Builtins.mkCons(
                                                        Builtins.iData(pub5),
                                                        Builtins.mkNilData())))))));
    }

    public static boolean verify(PlutusData publicInputs,
                                 byte[] piA,
                                 byte[] piB,
                                 byte[] piC,
                                 byte[] vkAlpha,
                                 byte[] vkBeta,
                                 byte[] vkGamma,
                                 byte[] vkDelta,
                                 PlutusData vkIc) {
        PlutusData inputsCursor = Builtins.unListData(publicInputs);
        PlutusData icCursor = Builtins.unListData(vkIc);

        if (Builtins.nullList(icCursor)) {
            return false;
        }
        if (!validScalars(inputsCursor) || !validIcPoints(icCursor)) {
            return false;
        }

        byte[] vkX = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(icCursor)));
        return verifyWithPublicInputs(inputsCursor, Builtins.tailList(icCursor), vkX,
                piA, piB, piC, vkAlpha, vkBeta, vkGamma, vkDelta);
    }

    public static boolean verifyFour(BigInteger pub0,
                                     BigInteger pub1,
                                     BigInteger pub2,
                                     BigInteger pub3,
                                     byte[] piA,
                                     byte[] piB,
                                     byte[] piC,
                                     byte[] vkAlpha,
                                     byte[] vkBeta,
                                     byte[] vkGamma,
                                     byte[] vkDelta,
                                     PlutusData vkIc) {
        PlutusData ic0 = Builtins.unListData(vkIc);
        if (Builtins.nullList(ic0)) return false;

        PlutusData ic1 = Builtins.tailList(ic0);
        if (Builtins.nullList(ic1)) return false;

        PlutusData ic2 = Builtins.tailList(ic1);
        if (Builtins.nullList(ic2)) return false;

        PlutusData ic3 = Builtins.tailList(ic2);
        if (Builtins.nullList(ic3)) return false;

        PlutusData ic4 = Builtins.tailList(ic3);
        if (Builtins.nullList(ic4)) return false;

        if (!Builtins.nullList(Builtins.tailList(ic4))) return false;
        if (!scalarInFr(pub0) || !scalarInFr(pub1) || !scalarInFr(pub2) || !scalarInFr(pub3)) {
            return false;
        }
        if (!validIcPoints(ic0)) {
            return false;
        }

        byte[] vkX0 = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(ic0)));
        byte[] vkX1 = addPublicInput(vkX0, pub0, ic1);
        byte[] vkX2 = addPublicInput(vkX1, pub1, ic2);
        byte[] vkX3 = addPublicInput(vkX2, pub2, ic3);
        byte[] vkX4 = addPublicInput(vkX3, pub3, ic4);

        return verifyWithComputedVkX(vkX4, piA, piB, piC, vkAlpha, vkBeta, vkGamma, vkDelta);
    }

    private static boolean verifyWithPublicInputs(PlutusData inputsCursor,
                                                  PlutusData icCursor,
                                                  byte[] vkX,
                                                  byte[] piA,
                                                  byte[] piB,
                                                  byte[] piC,
                                                  byte[] vkAlpha,
                                                  byte[] vkBeta,
                                                  byte[] vkGamma,
                                                  byte[] vkDelta) {
        if (!matchingLengths(inputsCursor, icCursor)) {
            return false;
        }

        byte[] computedVkX = computeVkX(inputsCursor, icCursor, vkX);
        return verifyWithComputedVkX(computedVkX, piA, piB, piC,
                vkAlpha, vkBeta, vkGamma, vkDelta);
    }

    private static boolean verifyWithComputedVkX(byte[] computedVkX,
                                                 byte[] piA,
                                                 byte[] piB,
                                                 byte[] piC,
                                                 byte[] vkAlpha,
                                                 byte[] vkBeta,
                                                 byte[] vkGamma,
                                                 byte[] vkDelta) {
        if (!isCanonicalNonInfinityG1(piA)
                || !isCanonicalNonInfinityG2(piB)
                || !isCanonicalNonInfinityG1(piC)
                || !isCanonicalNonInfinityG1(vkAlpha)
                || !isCanonicalNonInfinityG2(vkBeta)
                || !isCanonicalNonInfinityG2(vkGamma)
                || !isCanonicalNonInfinityG2(vkDelta)) {
            return false;
        }

        byte[] a = Builtins.bls12_381_G1_uncompress(piA);
        byte[] b = Builtins.bls12_381_G2_uncompress(piB);
        byte[] c = Builtins.bls12_381_G1_uncompress(piC);

        byte[] alpha = Builtins.bls12_381_G1_uncompress(vkAlpha);
        byte[] beta  = Builtins.bls12_381_G2_uncompress(vkBeta);
        byte[] gamma = Builtins.bls12_381_G2_uncompress(vkGamma);
        byte[] delta = Builtins.bls12_381_G2_uncompress(vkDelta);

        byte[] negAlpha = Builtins.bls12_381_G1_neg(alpha);
        byte[] lhs = Builtins.bls12_381_mulMlResult(
                Builtins.bls12_381_millerLoop(a, b),
                Builtins.bls12_381_millerLoop(negAlpha, beta));
        byte[] rhs = Builtins.bls12_381_mulMlResult(
                Builtins.bls12_381_millerLoop(computedVkX, gamma),
                Builtins.bls12_381_millerLoop(c, delta));

        return Builtins.bls12_381_finalVerify(lhs, rhs);
    }

    private static byte[] addPublicInput(byte[] vkX, BigInteger publicInput, PlutusData icCursor) {
        byte[] ic = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(icCursor)));
        byte[] scaled = Builtins.bls12_381_G1_scalarMul(publicInput, ic);
        return Builtins.bls12_381_G1_add(vkX, scaled);
    }

    private static boolean matchingLengths(PlutusData inputsCursor, PlutusData icCursor) {
        if (Builtins.nullList(inputsCursor)) {
            return Builtins.nullList(icCursor);
        } else if (Builtins.nullList(icCursor)) {
            return false;
        } else {
            return matchingLengths(Builtins.tailList(inputsCursor), Builtins.tailList(icCursor));
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

    private static boolean scalarInFr(BigInteger value) {
        return value.signum() >= 0 && value.compareTo(fr()) < 0;
    }

    private static BigInteger fr() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        return BigInteger.valueOf(52435L).multiply(base)
                .add(BigInteger.valueOf(875175126190479447L)).multiply(base)
                .add(BigInteger.valueOf(740508185965837690L)).multiply(base)
                .add(BigInteger.valueOf(552500527637822603L)).multiply(base)
                .add(BigInteger.valueOf(658699938581184513L));
    }

    private static boolean validIcPoints(PlutusData cursor) {
        if (Builtins.nullList(cursor)) {
            return true;
        } else {
            return isCanonicalNonInfinityG1(Builtins.unBData(Builtins.headList(cursor)))
                    && validIcPoints(Builtins.tailList(cursor));
        }
    }

    private static byte[] computeVkX(PlutusData inputsCursor, PlutusData icCursor, byte[] vkX) {
        if (Builtins.nullList(inputsCursor)) {
            return vkX;
        } else {
            BigInteger publicInput = Builtins.asInteger(Builtins.headList(inputsCursor));
            byte[] ic = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(icCursor)));
            byte[] scaled = Builtins.bls12_381_G1_scalarMul(publicInput, ic);
            byte[] nextVkX = Builtins.bls12_381_G1_add(vkX, scaled);
            return computeVkX(Builtins.tailList(inputsCursor), Builtins.tailList(icCursor), nextVkX);
        }
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
