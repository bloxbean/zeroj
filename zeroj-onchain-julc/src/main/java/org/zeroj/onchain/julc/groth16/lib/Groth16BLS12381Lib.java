package org.zeroj.onchain.julc.groth16.lib;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcG1;
import org.julclang.core.types.JulcG2;
import org.julclang.core.types.JulcMlResult;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.OnchainLibrary;

import java.math.BigInteger;

/**
 * Reusable on-chain Groth16 verifier logic for BLS12-381 proofs.
 */
@OnchainLibrary
public class Groth16BLS12381Lib {

    /*
     * One builder per public-input count. Julc compiles overloads by name, not signature
     * (pre16 ran the last declaration for every call; pre17 rejects them, JULC0054), so the
     * arity is part of each name. See ADR-0050.
     */
    public static PlutusData publicInputs1(BigInteger pub0) {
        return Builtins.listData(Builtins.mkCons(
                Builtins.iData(pub0),
                Builtins.mkNilData()));
    }

    public static PlutusData publicInputs2(BigInteger pub0, BigInteger pub1) {
        return Builtins.listData(Builtins.mkCons(
                Builtins.iData(pub0),
                Builtins.mkCons(
                        Builtins.iData(pub1),
                        Builtins.mkNilData())));
    }

    public static PlutusData publicInputs3(BigInteger pub0, BigInteger pub1, BigInteger pub2) {
        return Builtins.listData(Builtins.mkCons(
                Builtins.iData(pub0),
                Builtins.mkCons(
                        Builtins.iData(pub1),
                        Builtins.mkCons(
                                Builtins.iData(pub2),
                                Builtins.mkNilData()))));
    }

    public static PlutusData publicInputs4(BigInteger pub0, BigInteger pub1, BigInteger pub2,
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

    public static PlutusData publicInputs5(BigInteger pub0, BigInteger pub1, BigInteger pub2,
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

    public static PlutusData publicInputs6(BigInteger pub0, BigInteger pub1, BigInteger pub2,
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

        JulcG1 vkX = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(icCursor)));
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

        JulcG1 vkX0 = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(ic0)));
        JulcG1 vkX1 = addPublicInput(vkX0, pub0, ic1);
        JulcG1 vkX2 = addPublicInput(vkX1, pub1, ic2);
        JulcG1 vkX3 = addPublicInput(vkX2, pub2, ic3);
        JulcG1 vkX4 = addPublicInput(vkX3, pub3, ic4);

        return verifyWithComputedVkX(vkX4, piA, piB, piC, vkAlpha, vkBeta, vkGamma, vkDelta);
    }

    private static boolean verifyWithPublicInputs(PlutusData inputsCursor,
                                                  PlutusData icCursor,
                                                  JulcG1 vkX,
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

        JulcG1 computedVkX = computeVkX(inputsCursor, icCursor, vkX);
        return verifyWithComputedVkX(computedVkX, piA, piB, piC,
                vkAlpha, vkBeta, vkGamma, vkDelta);
    }

    /**
     * Each proof and key point is checked in order (length, decompression, canonical non-infinity
     * encoding) and the decompressed point is then used in the pairing: one decompression per point
     * (issue #84), the same checks and the same order as before.
     */
    private static boolean verifyWithComputedVkX(JulcG1 computedVkX,
                                                 byte[] piA,
                                                 byte[] piB,
                                                 byte[] piC,
                                                 byte[] vkAlpha,
                                                 byte[] vkBeta,
                                                 byte[] vkGamma,
                                                 byte[] vkDelta) {
        if (Builtins.lengthOfByteString(piA) != 48) return false;
        JulcG1 a = Builtins.bls12_381_G1_uncompress(piA);
        if (!canonicalNonInfinityG1(piA, a)) return false;
        if (Builtins.lengthOfByteString(piB) != 96) return false;
        JulcG2 b = Builtins.bls12_381_G2_uncompress(piB);
        if (!canonicalNonInfinityG2(piB, b)) return false;
        if (Builtins.lengthOfByteString(piC) != 48) return false;
        JulcG1 c = Builtins.bls12_381_G1_uncompress(piC);
        if (!canonicalNonInfinityG1(piC, c)) return false;
        if (Builtins.lengthOfByteString(vkAlpha) != 48) return false;
        JulcG1 alpha = Builtins.bls12_381_G1_uncompress(vkAlpha);
        if (!canonicalNonInfinityG1(vkAlpha, alpha)) return false;
        if (Builtins.lengthOfByteString(vkBeta) != 96) return false;
        JulcG2 beta = Builtins.bls12_381_G2_uncompress(vkBeta);
        if (!canonicalNonInfinityG2(vkBeta, beta)) return false;
        if (Builtins.lengthOfByteString(vkGamma) != 96) return false;
        JulcG2 gamma = Builtins.bls12_381_G2_uncompress(vkGamma);
        if (!canonicalNonInfinityG2(vkGamma, gamma)) return false;
        if (Builtins.lengthOfByteString(vkDelta) != 96) return false;
        JulcG2 delta = Builtins.bls12_381_G2_uncompress(vkDelta);
        if (!canonicalNonInfinityG2(vkDelta, delta)) return false;

        JulcG1 negAlpha = Builtins.bls12_381_G1_neg(alpha);
        JulcMlResult lhs = Builtins.bls12_381_mulMlResult(
                Builtins.bls12_381_millerLoop(a, b),
                Builtins.bls12_381_millerLoop(negAlpha, beta));
        JulcMlResult rhs = Builtins.bls12_381_mulMlResult(
                Builtins.bls12_381_millerLoop(computedVkX, gamma),
                Builtins.bls12_381_millerLoop(c, delta));

        return Builtins.bls12_381_finalVerify(lhs, rhs);
    }

    private static JulcG1 addPublicInput(JulcG1 vkX, BigInteger publicInput, PlutusData icCursor) {
        JulcG1 ic = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(icCursor)));
        JulcG1 scaled = Builtins.bls12_381_G1_scalarMul(publicInput, ic);
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

    private static JulcG1 computeVkX(PlutusData inputsCursor, PlutusData icCursor, JulcG1 vkX) {
        if (Builtins.nullList(inputsCursor)) {
            return vkX;
        } else {
            BigInteger publicInput = Builtins.asInteger(Builtins.headList(inputsCursor));
            JulcG1 ic = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(icCursor)));
            JulcG1 scaled = Builtins.bls12_381_G1_scalarMul(publicInput, ic);
            JulcG1 nextVkX = Builtins.bls12_381_G1_add(vkX, scaled);
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

    /**
     * {@code encoded} is the canonical compressed encoding of {@code point} (it re-compresses to the
     * same bytes) and not the compressed point at infinity. {@code point} is
     * {@code uncompress(encoded)}, already computed by the caller.
     */
    private static boolean canonicalNonInfinityG1(byte[] encoded, JulcG1 point) {
        return Builtins.equalsByteString(Builtins.bls12_381_G1_compress(point), encoded)
                && !isCompressedInfinityG1(encoded);
    }

    private static boolean canonicalNonInfinityG2(byte[] encoded, JulcG2 point) {
        return Builtins.equalsByteString(Builtins.bls12_381_G2_compress(point), encoded)
                && !isCompressedInfinityG2(encoded);
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
