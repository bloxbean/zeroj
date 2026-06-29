package com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.lib.PlonkBLS12381Lib;

import java.math.BigInteger;

/**
 * Cardano-profile BLS12-381 PlonK verifier for one-public-input circuits.
 *
 * <p>The cryptographic verifier is implemented in {@link PlonkBLS12381Lib} so
 * application validators can reuse the same reviewed pairing-check logic while
 * adding their own ScriptContext policy.</p>
 */
@SpendingValidator
public class PlonkBLS12381Verifier {

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

    record PlonkProof(
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            BigInteger xiMinusOneInv, BigInteger xiMinusOmegaInv
    ) {}

    @Entrypoint
    static boolean validate(PlutusData datum, PlonkProof p, PlutusData ctx) {
        return PlonkBLS12381Lib.verifyOneInput(
                datum,
                p.cmA(), p.cmB(), p.cmC(), p.cmZ(),
                p.cmT1(), p.cmT2(), p.cmT3(),
                p.wXi(), p.wXiw(),
                p.evalA(), p.evalB(), p.evalC(),
                p.evalS1(), p.evalS2(), p.evalZw(),
                p.xiMinusOneInv(), p.xiMinusOmegaInv(),
                vkQm, vkQl, vkQr, vkQo, vkQc, vkS1, vkS2, vkS3, vkX2,
                domainSize, domainPower, omega, k1, k2, k1OverK2, fr, nInv,
                g1Gen, g2Gen);
    }
}
