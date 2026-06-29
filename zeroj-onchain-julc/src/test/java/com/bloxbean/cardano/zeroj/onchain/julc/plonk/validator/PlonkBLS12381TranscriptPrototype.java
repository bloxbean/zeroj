package com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;

import java.math.BigInteger;

/**
 * Experimental on-chain PlonK BLS12-381 verifier prototype (Plutus V3).
 *
 * <p>Performs Fiat-Shamir challenge re-derivation
 * matching gnark's exact transcript format:</p>
 * <ul>
 *   <li>SHA-256 hash with challenge name prefix and hash chain</li>
 *   <li>All G1 points serialized as uncompressed 96 bytes (gnark RawBytes)</li>
 *   <li>Challenge order: gamma → beta → alpha → zeta</li>
 * </ul>
 *
     * <p>The redeemer carries both compressed G1 points (for BLS operations)
     * and their uncompressed raw bytes (for Fiat-Shamir hashing). This prototype
     * rejects non-canonical compressed encodings and wrong-sized raw transcript
     * byte strings. A final production verifier must still pin a transcript profile
     * that can bind the hashed bytes to the group-operation bytes.</p>
 *
 * <p>This version is not a full trustless PlonK verifier yet: the KZG batch
 * opening pairing check is deferred. It is specialized for 1 public input
 * (multiplier circuit: Z=33) and currently validates the transcript and
 * precomputed inverse constraints.</p>
 */
@SpendingValidator
public class PlonkBLS12381TranscriptPrototype {

    // VK: uncompressed raw bytes for transcript (96 bytes each)
    @Param static byte[] vkS1Raw;
    @Param static byte[] vkS2Raw;
    @Param static byte[] vkS3Raw;
    @Param static byte[] vkQlRaw;
    @Param static byte[] vkQrRaw;
    @Param static byte[] vkQmRaw;
    @Param static byte[] vkQoRaw;
    @Param static byte[] vkQkRaw;

    // VK: compressed points for BLS operations (48 bytes G1, 96 bytes G2)
    @Param static byte[] vkS3;     // G1 compressed (for linearized commitment)
    @Param static byte[] vkS1;     // G1 compressed (for [F] computation)
    @Param static byte[] vkS2;     // G1 compressed
    @Param static byte[] vkQm;     // G1 compressed
    @Param static byte[] vkQl;
    @Param static byte[] vkQr;
    @Param static byte[] vkQo;
    @Param static byte[] vkQc;     // G1 compressed (Qk = Qc)
    @Param static byte[] vkX2;     // G2 compressed 96 bytes

    // Domain parameters
    @Param static BigInteger omega;
    @Param static BigInteger k1;
    @Param static BigInteger k2;
    @Param static BigInteger fr;
    @Param static BigInteger nInv;
    @Param static byte[] g1Gen;
    @Param static byte[] g2Gen;

    /**
     * PlonK proof with both compressed (for BLS) and uncompressed (for transcript) G1 bytes.
     */
    record PlonkProof(
            // Compressed G1 (48 bytes) — for BLS operations
            byte[] cmA, byte[] cmB, byte[] cmC, byte[] cmZ,
            byte[] cmT1, byte[] cmT2, byte[] cmT3,
            byte[] wXi, byte[] wXiw,
            // Uncompressed G1 (96 bytes) — for Fiat-Shamir transcript
            byte[] cmARaw, byte[] cmBRaw, byte[] cmCRaw, byte[] cmZRaw,
            byte[] cmT1Raw, byte[] cmT2Raw, byte[] cmT3Raw,
            // Scalar evaluations
            BigInteger evalA, BigInteger evalB, BigInteger evalC,
            BigInteger evalS1, BigInteger evalS2, BigInteger evalZw,
            // Pre-computed inverses (verified on-chain)
            BigInteger xiMinusOneInv, BigInteger xiMinusOmegaInv
    ) {}

    @Entrypoint
    static boolean validate(PlutusData datum, PlonkProof p, PlutusData ctx) {
        if (!validParams() || !validProofShapeAndScalars(p)) {
            return false;
        }

        // Extract exactly 1 public input from datum
        PlutusData inputs = Builtins.unListData(datum);
        if (Builtins.nullList(inputs) || !Builtins.nullList(Builtins.tailList(inputs))) {
            return false;
        }
        BigInteger pub0 = Builtins.asInteger(Builtins.headList(inputs));
        if (!scalarInFr(pub0)) {
            return false;
        }

        // ======== Fiat-Shamir (gnark format: SHA-256 with name prefix + hash chain) ========

        // gamma = SHA-256("gamma" || S1_raw || S2_raw || S3_raw || Ql_raw || Qr_raw || Qm_raw || Qo_raw || Qk_raw || pub0_fr || cmA_raw || cmB_raw || cmC_raw)
        byte[] gammaInput = Builtins.appendByteString(
                Builtins.appendByteString(
                        Builtins.appendByteString(
                                Builtins.appendByteString(
                                        Builtins.appendByteString(GAMMA_BYTES, vkS1Raw),
                                        Builtins.appendByteString(vkS2Raw, vkS3Raw)),
                                Builtins.appendByteString(
                                        Builtins.appendByteString(vkQlRaw, vkQrRaw),
                                        Builtins.appendByteString(vkQmRaw, vkQoRaw))),
                        Builtins.appendByteString(vkQkRaw, i2bs(pub0))),
                Builtins.appendByteString(p.cmARaw(),
                        Builtins.appendByteString(p.cmBRaw(), p.cmCRaw())));
        byte[] gammaHash = Builtins.sha2_256(gammaInput);
        BigInteger gamma = Builtins.byteStringToInteger(true, gammaHash).mod(fr);

        // beta = SHA-256("beta" || gammaHash)
        byte[] betaHash = Builtins.sha2_256(Builtins.appendByteString(BETA_BYTES, gammaHash));
        BigInteger beta = Builtins.byteStringToInteger(true, betaHash).mod(fr);

        // alpha = SHA-256("alpha" || betaHash || cmZ_raw)
        byte[] alphaHash = Builtins.sha2_256(
                Builtins.appendByteString(Builtins.appendByteString(ALPHA_BYTES, betaHash), p.cmZRaw()));
        BigInteger alpha = Builtins.byteStringToInteger(true, alphaHash).mod(fr);

        // zeta = SHA-256("zeta" || alphaHash || cmT1_raw || cmT2_raw || cmT3_raw)
        byte[] zetaHash = Builtins.sha2_256(
                Builtins.appendByteString(
                        Builtins.appendByteString(ZETA_BYTES, alphaHash),
                        Builtins.appendByteString(p.cmT1Raw(),
                                Builtins.appendByteString(p.cmT2Raw(), p.cmT3Raw()))));
        BigInteger xi = Builtins.byteStringToInteger(true, zetaHash).mod(fr);

        // ======== Verify pre-computed inverses ========
        BigInteger xiMinusOne = xi.subtract(BigInteger.ONE).mod(fr);
        boolean inv1Ok = xiMinusOne.multiply(p.xiMinusOneInv()).mod(fr).equals(BigInteger.ONE);
        BigInteger xiMinusOmega = xi.subtract(omega).mod(fr);
        boolean inv2Ok = xiMinusOmega.multiply(p.xiMinusOmegaInv()).mod(fr).equals(BigInteger.ONE);

        // ======== Polynomial evaluations ========
        BigInteger xi2 = xi.multiply(xi).mod(fr);
        BigInteger xi4 = xi2.multiply(xi2).mod(fr); // domain_size=4, so xi^4
        BigInteger zh = xi4.subtract(BigInteger.ONE).mod(fr);
        BigInteger l1 = zh.multiply(nInv).mod(fr).multiply(p.xiMinusOneInv()).mod(fr);

        // PI for 1 public input: pi = pub0 * L_0(xi) = pub0 * zh * nInv * (xi-1)^{-1}
        BigInteger pi = pub0.multiply(l1).mod(fr);

        // ======== r0 ========
        BigInteger alpha2 = alpha.multiply(alpha).mod(fr);
        BigInteger e3a = p.evalA().add(beta.multiply(p.evalS1()).mod(fr)).add(gamma).mod(fr);
        BigInteger e3b = p.evalB().add(beta.multiply(p.evalS2()).mod(fr)).add(gamma).mod(fr);
        BigInteger e3c = p.evalC().add(gamma).mod(fr);
        BigInteger e3 = e3a.multiply(e3b).mod(fr).multiply(e3c).mod(fr)
                .multiply(p.evalZw()).mod(fr).multiply(alpha).mod(fr);
        BigInteger r0 = pi.subtract(l1.multiply(alpha2).mod(fr)).mod(fr).subtract(e3).mod(fr);

        // ======== G1 operations ========
        byte[] qm = Builtins.bls12_381_G1_uncompress(vkQm);
        byte[] ql = Builtins.bls12_381_G1_uncompress(vkQl);
        byte[] qr = Builtins.bls12_381_G1_uncompress(vkQr);
        byte[] qo = Builtins.bls12_381_G1_uncompress(vkQo);
        byte[] qc = Builtins.bls12_381_G1_uncompress(vkQc);
        byte[] s3u = Builtins.bls12_381_G1_uncompress(vkS3);
        byte[] x2u = Builtins.bls12_381_G2_uncompress(vkX2);
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

        // ======== [D] ========
        BigInteger ab = p.evalA().multiply(p.evalB()).mod(fr);
        byte[] d1 = Builtins.bls12_381_G1_add(
                Builtins.bls12_381_G1_add(Builtins.bls12_381_G1_scalarMul(ab, qm), Builtins.bls12_381_G1_scalarMul(p.evalA(), ql)),
                Builtins.bls12_381_G1_add(Builtins.bls12_381_G1_scalarMul(p.evalB(), qr),
                        Builtins.bls12_381_G1_add(Builtins.bls12_381_G1_scalarMul(p.evalC(), qo), qc)));

        BigInteger betaxi = beta.multiply(xi).mod(fr);
        BigInteger d2c = p.evalA().add(betaxi).add(gamma).mod(fr)
                .multiply(p.evalB().add(betaxi.multiply(k1).mod(fr)).add(gamma).mod(fr)).mod(fr)
                .multiply(p.evalC().add(betaxi.multiply(k2).mod(fr)).add(gamma).mod(fr)).mod(fr)
                .multiply(alpha).mod(fr)
                .add(l1.multiply(alpha2).mod(fr)).mod(fr);
        byte[] d2 = Builtins.bls12_381_G1_scalarMul(d2c, cZ);

        BigInteger d3c = p.evalA().add(beta.multiply(p.evalS1()).mod(fr)).add(gamma).mod(fr)
                .multiply(p.evalB().add(beta.multiply(p.evalS2()).mod(fr)).add(gamma).mod(fr)).mod(fr)
                .multiply(alpha.multiply(beta).mod(fr).multiply(p.evalZw()).mod(fr)).mod(fr);
        byte[] d3 = Builtins.bls12_381_G1_scalarMul(d3c, s3u);

        BigInteger xi4sq = xi4.multiply(xi4).mod(fr);
        byte[] d4 = Builtins.bls12_381_G1_scalarMul(zh,
                Builtins.bls12_381_G1_add(t1, Builtins.bls12_381_G1_add(Builtins.bls12_381_G1_scalarMul(xi4, t2), Builtins.bls12_381_G1_scalarMul(xi4sq, t3))));

        byte[] dPt = Builtins.bls12_381_G1_add(Builtins.bls12_381_G1_add(d1, d2), Builtins.bls12_381_G1_neg(Builtins.bls12_381_G1_add(d3, d4)));

        // ======== [F], [E], pairing ========
        // (simplified — gnark's v/u challenges come from KZG fold, not PlonK transcript)
        // For the full implementation, the KZG fold produces additional challenges.
        // For now, verify the linearized commitment [D] is consistent with the proof.

        // The pairing check uses gnark's KZG batch verification which involves
        // additional transcript rounds (v, u) from the KZG fold step.
        // This requires more work to implement — saving for next iteration.

        // Prototype scope: verify Fiat-Shamir + inverse checks + return true if all pass.
        // This is not a production PlonK acceptance condition until the KZG
        // batch opening pairing check above is implemented.
        return inv1Ok && inv2Ok;
    }

    private static boolean validParams() {
        return fr.signum() > 0
                && scalarInFr(omega)
                && scalarInFr(k1)
                && scalarInFr(k2)
                && scalarInFr(nInv)
                && isCanonicalG1(vkS1)
                && isCanonicalG1(vkS2)
                && isCanonicalG1(vkS3)
                && isCanonicalG1(vkQm)
                && isCanonicalG1(vkQl)
                && isCanonicalG1(vkQr)
                && isCanonicalG1(vkQo)
                && isCanonicalG1(vkQc)
                && isCanonicalG1(g1Gen)
                && isCanonicalG2(vkX2)
                && isCanonicalG2(g2Gen)
                && isRawG1(vkS1Raw)
                && isRawG1(vkS2Raw)
                && isRawG1(vkS3Raw)
                && isRawG1(vkQlRaw)
                && isRawG1(vkQrRaw)
                && isRawG1(vkQmRaw)
                && isRawG1(vkQoRaw)
                && isRawG1(vkQkRaw);
    }

    private static boolean validProofShapeAndScalars(PlonkProof p) {
        return scalarInFr(p.evalA())
                && scalarInFr(p.evalB())
                && scalarInFr(p.evalC())
                && scalarInFr(p.evalS1())
                && scalarInFr(p.evalS2())
                && scalarInFr(p.evalZw())
                && scalarInFr(p.xiMinusOneInv())
                && scalarInFr(p.xiMinusOmegaInv())
                && isCanonicalG1(p.cmA())
                && isCanonicalG1(p.cmB())
                && isCanonicalG1(p.cmC())
                && isCanonicalG1(p.cmZ())
                && isCanonicalG1(p.cmT1())
                && isCanonicalG1(p.cmT2())
                && isCanonicalG1(p.cmT3())
                && isCanonicalG1(p.wXi())
                && isCanonicalG1(p.wXiw())
                && isRawG1(p.cmARaw())
                && isRawG1(p.cmBRaw())
                && isRawG1(p.cmCRaw())
                && isRawG1(p.cmZRaw())
                && isRawG1(p.cmT1Raw())
                && isRawG1(p.cmT2Raw())
                && isRawG1(p.cmT3Raw());
    }

    private static boolean scalarInFr(BigInteger value) {
        return value.signum() >= 0 && value.compareTo(fr) < 0;
    }

    private static boolean isCanonicalG1(byte[] compressed) {
        return Builtins.lengthOfByteString(compressed) == 48
                && Builtins.equalsByteString(
                        Builtins.bls12_381_G1_compress(Builtins.bls12_381_G1_uncompress(compressed)),
                        compressed);
    }

    private static boolean isCanonicalG2(byte[] compressed) {
        return Builtins.lengthOfByteString(compressed) == 96
                && Builtins.equalsByteString(
                        Builtins.bls12_381_G2_compress(Builtins.bls12_381_G2_uncompress(compressed)),
                        compressed);
    }

    private static boolean isRawG1(byte[] raw) {
        return Builtins.lengthOfByteString(raw) == 96
                && Builtins.lengthOfByteString(Builtins.sliceByteString(0, 48, raw)) == 48
                && Builtins.lengthOfByteString(Builtins.sliceByteString(48, 48, raw)) == 48;
    }

    // Challenge name bytes (hardcoded UTF-8 — avoids Builtins.encodeUtf8 which returns BytesData)
    // "gamma" = 67 61 6d 6d 61
    @Param static byte[] GAMMA_BYTES;
    // "beta"  = 62 65 74 61
    @Param static byte[] BETA_BYTES;
    // "alpha" = 61 6c 70 68 61
    @Param static byte[] ALPHA_BYTES;
    // "zeta"  = 7a 65 74 61
    @Param static byte[] ZETA_BYTES;

    /** BigInteger to 32-byte big-endian. */
    static byte[] i2bs(BigInteger value) {
        return Builtins.integerToByteString(true, 32, value);
    }
}
