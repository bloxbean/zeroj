package org.zeroj.onchain.julc.groth16.lib;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcG1;
import org.julclang.core.types.JulcG1Points;
import org.julclang.core.types.JulcG2;
import org.julclang.core.types.JulcMlResult;
import org.julclang.core.types.JulcScalars;
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
        if (!validScalars(inputsCursor) || !icEncodingsWellFormed(icCursor)) {
            return false;
        }

        // ADR-0056: every IC entry is decompressed once and fully validated before any scalar
        // multiplication (ADR-0045 V1). The count comparison is a pure list walk (it cannot fail),
        // so it is evaluated first only to skip every multiplication when the counts disagree: the
        // walk still validates each entry, and the result is the same as before, false.
        boolean countsMatch = matchingLengths(inputsCursor, Builtins.tailList(icCursor));
        // From msmMinInputs() public inputs one multi-scalar multiplication is cheaper than one
        // scalar multiplication per input (ADR-0056 M2); the walk validates the same way either way.
        JulcG1 vkX = countsMatch && atLeast(inputsCursor, msmMinInputs())
                ? icSumMsm(inputsCursor, icCursor)
                : icSum(inputsCursor, icCursor, countsMatch);
        if (!countsMatch) {
            return false;
        }
        return verifyWithComputedVkX(vkX, piA, piB, piC, vkAlpha, vkBeta, vkGamma, vkDelta);
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
        // ADR-0056: the five IC entries are validated in order, each decompressed once, before
        // any scalar multiplication (ADR-0045 V1); the same points are then used for vk_x.
        byte[] e0 = Builtins.unBData(Builtins.headList(ic0));
        if (Builtins.lengthOfByteString(e0) != 48) return false;
        JulcG1 p0 = Builtins.bls12_381_G1_uncompress(e0);
        if (!canonicalNonInfinityG1(e0, p0)) return false;
        byte[] e1 = Builtins.unBData(Builtins.headList(ic1));
        if (Builtins.lengthOfByteString(e1) != 48) return false;
        JulcG1 p1 = Builtins.bls12_381_G1_uncompress(e1);
        if (!canonicalNonInfinityG1(e1, p1)) return false;
        byte[] e2 = Builtins.unBData(Builtins.headList(ic2));
        if (Builtins.lengthOfByteString(e2) != 48) return false;
        JulcG1 p2 = Builtins.bls12_381_G1_uncompress(e2);
        if (!canonicalNonInfinityG1(e2, p2)) return false;
        byte[] e3 = Builtins.unBData(Builtins.headList(ic3));
        if (Builtins.lengthOfByteString(e3) != 48) return false;
        JulcG1 p3 = Builtins.bls12_381_G1_uncompress(e3);
        if (!canonicalNonInfinityG1(e3, p3)) return false;
        byte[] e4 = Builtins.unBData(Builtins.headList(ic4));
        if (Builtins.lengthOfByteString(e4) != 48) return false;
        JulcG1 p4 = Builtins.bls12_381_G1_uncompress(e4);
        if (!canonicalNonInfinityG1(e4, p4)) return false;

        JulcG1 vkX1 = Builtins.bls12_381_G1_add(p0, Builtins.bls12_381_G1_scalarMul(pub0, p1));
        JulcG1 vkX2 = Builtins.bls12_381_G1_add(vkX1, Builtins.bls12_381_G1_scalarMul(pub1, p2));
        JulcG1 vkX3 = Builtins.bls12_381_G1_add(vkX2, Builtins.bls12_381_G1_scalarMul(pub2, p3));
        JulcG1 vkX4 = Builtins.bls12_381_G1_add(vkX3, Builtins.bls12_381_G1_scalarMul(pub3, p4));

        return verifyWithComputedVkX(vkX4, piA, piB, piC, vkAlpha, vkBeta, vkGamma, vkDelta);
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

    private static boolean matchingLengths(PlutusData inputsCursor, PlutusData icCursor) {
        if (Builtins.nullList(inputsCursor)) {
            return Builtins.nullList(icCursor);
        } else if (Builtins.nullList(icCursor)) {
            return false;
        } else {
            return matchingLengths(Builtins.tailList(inputsCursor), Builtins.tailList(icCursor));
        }
    }

    /**
     * Every IC entry is 48 bytes and not the compressed point at infinity. Byte checks only, so a
     * wrong-length or infinity entry returns {@code false} without decompressing anything.
     */
    private static boolean icEncodingsWellFormed(PlutusData cursor) {
        if (Builtins.nullList(cursor)) {
            return true;
        }
        byte[] encoded = Builtins.unBData(Builtins.headList(cursor));
        return Builtins.lengthOfByteString(encoded) == 48
                && !isCompressedInfinityG1(encoded)
                && icEncodingsWellFormed(Builtins.tailList(cursor));
    }

    /**
     * {@code IC[0] + Σ inputs[i] · IC[i+1]}, decompressing each IC entry once. Each entry is
     * validated (decompression: curve and subgroup; re-compression: canonical encoding) on the way
     * down, so every entry is validated before the first scalar multiplication, which happens on
     * the way back up (ADR-0045 V1). An entry that fails here fails the script; the byte checks of
     * {@link #icEncodingsWellFormed} have already returned {@code false} for length and infinity.
     * With {@code multiply} false (the counts disagree) every entry is still validated, but nothing
     * is multiplied; the caller then returns {@code false}.
     */
    private static JulcG1 icSum(PlutusData inputsCursor, PlutusData icCursor, boolean multiply) {
        JulcG1 base = validatedIcPoint(icCursor);
        PlutusData rest = Builtins.tailList(icCursor);
        if (Builtins.nullList(rest)) {
            return base;
        }
        return icTerms(inputsCursor, rest, base, multiply);
    }

    /**
     * {@code base + Σ inputs[i] · ic[i]} over the common prefix (nothing is added unless
     * {@code multiply}). The rest of {@code ic} is validated (by the recursive call) before this
     * entry's scalar multiplication. The call is not in tail position: each level keeps its point
     * until the levels below return, one pending level per IC entry.
     */
    private static JulcG1 icTerms(PlutusData inputsCursor, PlutusData icCursor, JulcG1 base, boolean multiply) {
        JulcG1 point = validatedIcPoint(icCursor);
        PlutusData rest = Builtins.tailList(icCursor);
        PlutusData nextInputs = Builtins.nullList(inputsCursor) ? inputsCursor : Builtins.tailList(inputsCursor);
        JulcG1 later = Builtins.nullList(rest) ? base : icTerms(nextInputs, rest, base, multiply);
        if (!multiply || Builtins.nullList(inputsCursor)) {
            return later;
        }
        return Builtins.bls12_381_G1_add(later,
                Builtins.bls12_381_G1_scalarMul(Builtins.asInteger(Builtins.headList(inputsCursor)), point));
    }

    /**
     * The smallest number of public inputs for which {@link #icSumMsm} is used. Measured (Julc VM,
     * PV11 cost model): one multi-scalar multiplication over n points costs about 52e6 steps less
     * per input than n scalar multiplications, against a higher fixed cost; it is 116e6 steps dearer
     * at 4 inputs and 145e6 cheaper at 9, so it pays from 7 (ADR-0056 M2).
     */
    private static int msmMinInputs() {
        return 7;
    }

    /** {@code cursor} has at least {@code k} elements. */
    private static boolean atLeast(PlutusData cursor, int k) {
        if (k <= 0) {
            return true;
        }
        return !Builtins.nullList(cursor) && atLeast(Builtins.tailList(cursor), k - 1);
    }

    /**
     * {@code IC[0] + Σ inputs[i] · IC[i+1]} with one multi-scalar multiplication. Each IC entry is
     * decompressed once and validated on the way down (as in {@link #icSum}); the validated points
     * are collected into a native list, and the multiplication runs only after the whole walk has
     * returned, so after every entry is validated (ADR-0045 V1). The counts are known to agree.
     */
    private static JulcG1 icSumMsm(PlutusData inputsCursor, PlutusData icCursor) {
        JulcG1 base = validatedIcPoint(icCursor);
        PlutusData rest = Builtins.tailList(icCursor);
        if (Builtins.nullList(rest)) {
            return base;
        }
        JulcG1Points points = icPoints(rest);
        JulcScalars scalars = scalarList(inputsCursor);
        return Builtins.bls12_381_G1_add(base, Builtins.bls12_381_G1_multiScalarMul(scalars, points));
    }

    /** The validated points of {@code icCursor}, in order: each entry is validated before the rest. */
    private static JulcG1Points icPoints(PlutusData icCursor) {
        JulcG1 point = validatedIcPoint(icCursor);
        PlutusData rest = Builtins.tailList(icCursor);
        JulcG1Points later = Builtins.nullList(rest) ? Builtins.g1PointsEmpty() : icPoints(rest);
        return Builtins.g1PointsCons(point, later);
    }

    /** The public inputs as a native scalar list, in order (validScalars has checked each one). */
    private static JulcScalars scalarList(PlutusData inputsCursor) {
        if (Builtins.nullList(inputsCursor)) {
            return Builtins.scalarsEmpty();
        }
        return Builtins.scalarsCons(Builtins.asInteger(Builtins.headList(inputsCursor)),
                scalarList(Builtins.tailList(inputsCursor)));
    }

    /**
     * The head IC entry, decompressed once and checked canonical and not infinity; otherwise the
     * script fails. Through {@code verify} the branch is defense in depth: the byte checks have
     * already refused infinity, and the evaluator's {@code uncompress} (blst) refuses the other
     * non-canonical encodings. CIP-0381 does not define those rejections normatively, so the check
     * stays (ADR-0056 I4).
     */
    private static JulcG1 validatedIcPoint(PlutusData icCursor) {
        byte[] encoded = Builtins.unBData(Builtins.headList(icCursor));
        JulcG1 point = Builtins.bls12_381_G1_uncompress(encoded);
        if (!canonicalNonInfinityG1(encoded, point)) {
            Builtins.error();
        }
        return point;
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
