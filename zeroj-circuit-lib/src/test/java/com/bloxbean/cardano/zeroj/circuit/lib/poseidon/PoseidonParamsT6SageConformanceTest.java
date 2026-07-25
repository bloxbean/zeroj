package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Conformance gate for the BLS12-381 {@code t=6} Poseidon preset added by ADR-0037.
 *
 * <p>{@link PoseidonGrainLFSR} deliberately does <b>not</b> port the Poseidon paper's MDS
 * security algorithms 1/2/3. That is only safe when the <em>first</em> Cauchy matrix the
 * generator samples is already accepted by those algorithms, which cannot be checked in Java.
 * Each entry in {@code VETTED_PARAMS} therefore carries a claim that the authoritative
 * hadeshash Sage script confirmed first-pass acceptance for that tuple.
 *
 * <p>This test pins the {@code t=6} claim. The expected values were produced by running the
 * pinned reference script (hadeshash commit
 * {@code 208b5a164c6a252b137997694d90931b2bb851c5}) in the {@code sagemath/sagemath} image:
 *
 * <pre>
 * sage generate_parameters_grain.sage 1 0 255 6 8 60 \
 *     0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
 * </pre>
 *
 * which reported {@code Algorithm 1: [True, 0]}, {@code Algorithm 2: [True, None]},
 * {@code Algorithm 3: [True, None]} — first-pass acceptance — and emitted 408 round constants
 * plus a 6x6 MDS matrix. All 444 values were compared element-by-element against the
 * generated Java preset and matched exactly; the digest below is over that same sequence, so
 * any drift in the Grain LFSR, the parameter tuple, or the generated file fails here.
 */
class PoseidonParamsT6SageConformanceTest {

    private static final PoseidonParams T6 = PoseidonParamsBLS12_381T6.INSTANCE;

    @Test
    @DisplayName("t=6 preset shape: 68 rounds x 6 cells, alpha 5, 6x6 MDS")
    void shape() {
        assertEquals(6, T6.t());
        assertEquals(5, T6.alpha());
        assertEquals(8, T6.rf());
        assertEquals(60, T6.rp());
        assertEquals((8 + 60) * 6, T6.c().length, "408 round constants");
        assertEquals(6 * 6, T6.m().length, "36 MDS entries");
    }

    @Test
    @DisplayName("t=6 gives rate 5 — enough for the five-element EdDSA challenge in one permutation")
    void rateIsSufficientForTheChallenge() {
        // Sponge with capacity 1: rate = t - 1. The challenge absorbs
        // (R.u, R.v, pk.u, pk.v, msg) = 5 elements, so t must be at least 6.
        // t=5 (rate 4) cannot do it, which is why ADR-0037 corrected the earlier
        // "t=5/t=6" phrasing to t=6.
        int rate = T6.t() - 1;
        assertEquals(5, rate);
        assertTrue(rate >= 5, "rate must cover the 5-element challenge");
        assertEquals(4, PoseidonParamsBLS12_381T5.INSTANCE.t() - 1,
                "t=5 has rate 4 and is therefore insufficient — documented so the choice is not "
                        + "re-litigated");
    }

    @Test
    @DisplayName("t=6 round constants match the Sage reference (boundary values)")
    void roundConstantBoundaries() {
        assertEquals(hex("18ba13688329bee1d93fd39128f89ed425b23757a8c27cc96570dcbe9e8ad0c0"), T6.c()[0]);
        assertEquals(hex("4c885b226991acbb64b966e17f0aeb3185747c9530f952ecb817988216d7955c"), T6.c()[1]);
        assertEquals(hex("6660659cfdc88ecdf845015d228aa79d0e7fe3770dfd28309944d350912a4a36"),
                T6.c()[T6.c().length - 1]);
    }

    @Test
    @DisplayName("t=6 MDS matrix matches the Sage reference (boundary values)")
    void mdsBoundaries() {
        assertEquals(hex("28e8b9bd05b214da35df0e54417dccc3616a712a706504111e0911fd41f17d5c"), T6.m()[0]);
        assertEquals(hex("35d35d81949d8e08b542b97dbc71b8bd59481378c99fea86133f35aea9e89246"),
                T6.m()[T6.m().length - 1]);
    }

    @Test
    @DisplayName("t=6 parameters digest matches the Sage reference over all 444 values")
    void fullParameterDigest() throws Exception {
        // Boundary checks alone would miss a change in the middle of the sequence.
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        for (BigInteger v : T6.c()) sha256.update(toFixed32(v));
        for (BigInteger v : T6.m()) sha256.update(toFixed32(v));
        assertEquals("b8791aa751cb4b2d7fad4767f14561aff24c08a56ce52828ec3f8f6cd436a34f",
                toHex(sha256.digest()),
                "SHA-256 over the 408 round constants followed by the 36 MDS entries, each as "
                        + "a 32-byte big-endian value, drifted from the Sage reference output");
    }

    @Test
    @DisplayName("every t=6 parameter is a canonical field element")
    void parametersAreCanonical() {
        BigInteger p = T6.field().prime();
        for (BigInteger v : T6.c()) {
            assertTrue(v.signum() >= 0 && v.compareTo(p) < 0, "round constant out of range: " + v);
        }
        for (BigInteger v : T6.m()) {
            assertTrue(v.signum() >= 0 && v.compareTo(p) < 0, "MDS entry out of range: " + v);
        }
    }

    private static BigInteger hex(String s) {
        return new BigInteger(s, 16);
    }

    private static byte[] toFixed32(BigInteger v) {
        byte[] out = new byte[32];
        byte[] be = v.toByteArray();
        int start = (be.length > 32) ? be.length - 32 : 0;
        int len = Math.min(be.length, 32);
        System.arraycopy(be, start, out, 32 - len, len);
        return out;
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
