package com.bloxbean.cardano.zeroj.onchain.julc;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.OnchainLibrary;

import java.math.BigInteger;

/**
 * Reusable on-chain Groth16 verifier logic for BLS12-381 proofs.
 */
@OnchainLibrary
public class Groth16BLS12381 {

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

        byte[] vkX = Builtins.bls12_381_G1_uncompress(Builtins.unBData(Builtins.headList(icCursor)));
        return verifyWithPublicInputs(inputsCursor, Builtins.tailList(icCursor), vkX,
                piA, piB, piC, vkAlpha, vkBeta, vkGamma, vkDelta);
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

    private static boolean matchingLengths(PlutusData inputsCursor, PlutusData icCursor) {
        if (Builtins.nullList(inputsCursor)) {
            return Builtins.nullList(icCursor);
        } else if (Builtins.nullList(icCursor)) {
            return false;
        } else {
            return matchingLengths(Builtins.tailList(inputsCursor), Builtins.tailList(icCursor));
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
}
