package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;

/**
 * Explicit public-data boundary between fixed-limb signing and the existing public
 * {@link BigInteger} API. No method accepts or reads a secret key or nonce scalar.
 */
final class JubjubPublicAdapter {

    private JubjubPublicAdapter() {
    }

    static JubjubPoint normalizedPoint(long[] point, int po,
                                       byte[] bytes, int uo, int vo,
                                       long[] work, int wo) {
        CtJubjubFqOps.toCanonicalBytes(
                bytes, uo, point, po + CtJubjubPointOps.U, work, wo);
        CtJubjubFqOps.toCanonicalBytes(
                bytes, vo, point, po + CtJubjubPointOps.V, work, wo);
        return JubjubPoint.fromAffine(
                new BigInteger(1, slice32(bytes, uo)),
                new BigInteger(1, slice32(bytes, vo)));
    }

    static BigInteger scalar(long[] scalar, int so,
                             byte[] bytes, int bo,
                             long[] work, int wo) {
        CtJubjubFrOps.toCanonicalBytes(bytes, bo, scalar, so, work, wo);
        return new BigInteger(1, slice32(bytes, bo));
    }

    static void canonicalScalar(BigInteger scalar, byte[] output, int offset) {
        byte[] encoded = scalar.toByteArray();
        int source = encoded.length == 33 && encoded[0] == 0 ? 1 : 0;
        int length = encoded.length - source;
        if (length > 32) {
            throw new IllegalArgumentException("public scalar does not fit 32 bytes");
        }
        for (int i = 0; i < 32; i++) {
            output[offset + i] = 0;
        }
        System.arraycopy(encoded, source, output, offset + 32 - length, length);
    }

    static long challengeToScalar(long[] output, int oo,
                                  JubjubPoint rPoint,
                                  JubjubPoint publicKey,
                                  JubjubMessage message,
                                  byte[] bytes, int bo,
                                  long[] work, int wo) {
        BigInteger challenge = EdDSAJubjub.computeChallenge(
                rPoint, publicKey, message.toPublicFieldElement());
        canonicalScalar(challenge, bytes, bo);
        return CtJubjubFrOps.fromCanonicalBytes(
                output, oo, bytes, bo, work, wo);
    }

    static EdDSAJubjub.Signature signature(
            JubjubPoint rPoint,
            long[] signatureScalar, int so,
            byte[] bytes, int bo,
            long[] work, int wo) {
        return new EdDSAJubjub.Signature(
                rPoint, scalar(signatureScalar, so, bytes, bo, work, wo));
    }

    static EdDSAJubjub.Signature verifyBeforeRelease(
            JubjubPoint publicKey,
            JubjubMessage message,
            EdDSAJubjub.Signature candidate) {
        return EdDSAJubjub.verifyBeforeRelease(
                publicKey, message.toPublicFieldElement(), candidate);
    }

    private static byte[] slice32(byte[] source, int offset) {
        byte[] result = new byte[32];
        System.arraycopy(source, offset, result, 0, result.length);
        return result;
    }
}
