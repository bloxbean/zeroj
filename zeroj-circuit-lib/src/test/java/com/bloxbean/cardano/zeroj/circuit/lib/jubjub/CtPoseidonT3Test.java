package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0039 M3/M4 differential tests for the fixed-limb Poseidon permutation and nonce
 * transcripts. The references deliberately use the existing independent BigInteger path.
 */
class CtPoseidonT3Test {

    private static final PoseidonParams PARAMS = PoseidonParamsBLS12_381T3.INSTANCE;
    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final BigInteger NONCE_KEY_TAG =
            tag("ZeroJ-JubjubEdDSA-hedged-v1-nonce-key");
    private static final BigInteger HEDGED_NONCE_TAG =
            tag("ZeroJ-JubjubEdDSA-hedged-v1-nonce");
    private static final Random RANDOM = new Random(0x39_50_4f_53_45L);

    @Test
    @DisplayName("all embedded Poseidon constants equal the authoritative generated preset")
    void constantsMatchPreset() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long[] encoded = new long[4];
        for (int round = 0; round < PARAMS.totalRounds(); round++) {
            for (int cell = 0; cell < PARAMS.t(); cell++) {
                CtPoseidonT3Constants.copyRoundConstant(encoded, 0, round, cell);
                byte[] actual = fqBytes(encoded);
                assertEquals(PARAMS.cAt(round, cell), new BigInteger(1, actual),
                        "round=" + round + ", cell=" + cell);
                digest.update(actual);
            }
        }
        for (int row = 0; row < PARAMS.t(); row++) {
            for (int column = 0; column < PARAMS.t(); column++) {
                CtPoseidonT3Constants.copyMdsEntry(encoded, 0, row, column);
                byte[] actual = fqBytes(encoded);
                assertEquals(PARAMS.mAt(row, column), new BigInteger(1, actual),
                        "row=" + row + ", column=" + column);
                digest.update(actual);
            }
        }
        assertEquals("0f2b0f1a2bdef1fde256a8d2e60770e3a759b97e05f8cd66e18d149c5db727af",
                HexFormat.of().formatHex(digest.digest()));
    }

    @Test
    @DisplayName("fixed-limb Poseidon permutation agrees on boundaries and random states")
    void permutationMatchesReference() {
        BigInteger[] boundary = {
                BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                P.shiftRight(1), P.subtract(BigInteger.TWO), P.subtract(BigInteger.ONE)
        };
        for (BigInteger a : boundary) {
            for (BigInteger b : boundary) {
                assertPermutation(new BigInteger[]{a, b, a.add(b).mod(P)});
            }
        }
        for (int i = 0; i < 200; i++) {
            assertPermutation(new BigInteger[]{
                    randomBelow(P), randomBelow(P), randomBelow(P)
            });
        }
    }

    @Test
    @DisplayName("deterministic-v1 nonce is byte-identical to the legacy transcript")
    void deterministicNonceMatchesReference() {
        BigInteger[] scalars = {
                BigInteger.ONE, BigInteger.TWO, L.shiftRight(1),
                L.subtract(BigInteger.TWO), L.subtract(BigInteger.ONE)
        };
        BigInteger[] messages = {
                BigInteger.ZERO, BigInteger.ONE, P.shiftRight(1), P.subtract(BigInteger.ONE)
        };
        for (BigInteger sk : scalars) {
            for (BigInteger message : messages) {
                assertDeterministicNonce(sk, message);
            }
        }
        for (int i = 0; i < 100; i++) {
            assertDeterministicNonce(randomNonZeroBelow(L), randomBelow(P));
        }
    }

    @Test
    @DisplayName("hedged candidate transcript agrees with an independent BigInteger reference")
    void hedgedNonceMatchesReference() {
        for (int i = 0; i < 64; i++) {
            BigInteger sk = i == 0 ? BigInteger.ONE
                    : i == 1 ? L.subtract(BigInteger.ONE) : randomNonZeroBelow(L);
            BigInteger message = i == 0 ? BigInteger.ZERO
                    : i == 1 ? P.subtract(BigInteger.ONE) : randomBelow(P);
            byte[] auxiliary = new byte[32];
            RANDOM.nextBytes(auxiliary);

            long[] secret = fr(sk);
            long[] messageFq = fq(message);
            long[] nonceKey = new long[4];
            long[] point = new long[CtJubjubPointOps.POINT_LIMBS];
            long[] pointWork = new long[CtJubjubPointOps.SCALAR_MUL_WORK_LIMBS];
            CtJubjubNonce.deriveNonceKey(
                    nonceKey, 0, secret, 0, new long[CtJubjubNonce.WORK_LIMBS], 0);
            long[] generator = new long[CtJubjubPointOps.POINT_LIMBS];
            CtJubjubPointOps.generator(generator, 0);
            CtJubjubPointOps.scalarMul(
                    point, 0, generator, 0, secret, 0, pointWork, 0);
            long[] normalized = new long[CtJubjubPointOps.POINT_LIMBS];
            CtJubjubPointOps.normalize(normalized, 0, point, 0, new long[32], 0);

            long[] actual = new long[4];
            CtJubjubNonce.hedgedV1(
                    actual, 0, nonceKey, 0, normalized, 0, messageFq, 0,
                    auxiliary, 0, new long[CtJubjubNonce.WORK_LIMBS], 0);

            JubjubPoint publicKey = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(sk).normalized();
            BigInteger expectedNonceKey = PoseidonHash.permute(PARAMS, new BigInteger[]{
                    NONCE_KEY_TAG, sk, BigInteger.ZERO
            })[0];
            BigInteger[] state = PoseidonHash.permute(PARAMS, new BigInteger[]{
                    HEDGED_NONCE_TAG, expectedNonceKey, message
            });
            state = PoseidonHash.permute(PARAMS, new BigInteger[]{
                    state[0],
                    state[1].add(publicKey.affineU()).mod(P),
                    state[2].add(publicKey.affineV()).mod(P)
            });
            BigInteger auxHigh = new BigInteger(1, Arrays.copyOfRange(auxiliary, 0, 16));
            BigInteger auxLow = new BigInteger(1, Arrays.copyOfRange(auxiliary, 16, 32));
            state = PoseidonHash.permute(PARAMS, new BigInteger[]{
                    state[0],
                    state[1].add(auxHigh).mod(P),
                    state[2].add(auxLow).mod(P)
            });
            BigInteger expected = state[0].mod(L.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            assertEquals(expected, frValue(actual));
            assertTrue(expected.signum() > 0 && expected.compareTo(L) < 0);
        }
    }

    @Test
    @DisplayName("hedged transcript is deterministic per auxiliary input and binds every input")
    void hedgedTranscriptBindsInputs() {
        BigInteger sk = BigInteger.valueOf(42);
        BigInteger message = BigInteger.valueOf(99);
        byte[] auxiliary = new byte[32];
        Arrays.fill(auxiliary, (byte) 0xa5);

        BigInteger baseline = hedged(sk, message, auxiliary);
        assertEquals(baseline, hedged(sk, message, auxiliary.clone()));

        byte[] changedAux = auxiliary.clone();
        changedAux[31] ^= 1;
        assertNotEquals(baseline, hedged(sk, message, changedAux));
        assertNotEquals(baseline, hedged(sk, message.add(BigInteger.ONE), auxiliary));
        assertNotEquals(baseline, hedged(sk.add(BigInteger.ONE), message, auxiliary));
    }

    @Test
    @DisplayName("nonce domains are independently derived and pinned")
    void domainTagsArePinned() {
        assertEquals(JubjubEdDSASuite.NONCE_TAG,
                tag(JubjubEdDSASuite.NONCE_TAG_LABEL));
        assertEquals("28c87335b019e6e7ca819222776c84073ddfcc06b031d9fdbbafedbb65a0e991",
                NONCE_KEY_TAG.toString(16));
        assertEquals("6b9458c0423a2e488bcd71ca3b3ccd905536ded5996c97715b0885971d11f6b1",
                HEDGED_NONCE_TAG.toString(16));
        assertNotEquals(JubjubEdDSASuite.NONCE_TAG, NONCE_KEY_TAG);
        assertNotEquals(NONCE_KEY_TAG, HEDGED_NONCE_TAG);
        assertNotEquals(JubjubEdDSASuite.CHALLENGE_TAG, HEDGED_NONCE_TAG);
    }

    @Test
    @DisplayName("hedged-v1 candidate nonce vector is pinned independently of signing")
    void hedgedCandidateVector() {
        long[] secret = fr(BigInteger.ONE);
        long[] nonceKey = new long[4];
        CtJubjubNonce.deriveNonceKey(
                nonceKey, 0, secret, 0, new long[CtJubjubNonce.WORK_LIMBS], 0);
        long[] generator = new long[CtJubjubPointOps.POINT_LIMBS];
        long[] publicKey = new long[CtJubjubPointOps.POINT_LIMBS];
        CtJubjubPointOps.generator(generator, 0);
        CtJubjubPointOps.scalarMul(
                publicKey, 0, generator, 0, secret, 0,
                new long[CtJubjubPointOps.SCALAR_MUL_WORK_LIMBS], 0);
        long[] normalized = new long[CtJubjubPointOps.POINT_LIMBS];
        CtJubjubPointOps.normalize(normalized, 0, publicKey, 0, new long[32], 0);
        long[] nonce = new long[4];
        CtJubjubNonce.hedgedV1(
                nonce, 0, nonceKey, 0, normalized, 0, fq(BigInteger.ZERO), 0,
                new byte[32], 0, new long[CtJubjubNonce.WORK_LIMBS], 0);

        String vector = "nonceKey=" + fqValue(nonceKey).toString(16)
                + ";nonce=" + frValue(nonce).toString(16);
        assertEquals(
                "nonceKey=52c14c92d2f6eb95966adf00ac7290d81e760d596c21e0cd09cef989497fe3fa"
                        + ";nonce=23e724ba6d51119660d8509733cd24556685b635eb8b1fedaa52b0331cbc5c2",
                vector);
    }

    private static void assertPermutation(BigInteger[] input) {
        long[] state = new long[CtPoseidonT3.STATE_LIMBS];
        for (int i = 0; i < input.length; i++) {
            CtJubjubFqOps.copy(state, i * 4, fq(input[i]), 0);
        }
        CtPoseidonT3.permute(state, 0, new long[CtPoseidonT3.WORK_LIMBS], 0);
        BigInteger[] expected = PoseidonHash.permute(PARAMS, input);
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], fqValue(state, i * 4), "cell=" + i);
        }
    }

    private static void assertDeterministicNonce(BigInteger sk, BigInteger message) {
        long[] actual = new long[4];
        CtJubjubNonce.deterministicV1(
                actual, 0, fr(sk), 0, fq(message), 0,
                new long[CtJubjubNonce.WORK_LIMBS], 0);
        BigInteger expected = PoseidonHash.spongeHash(
                PARAMS, JubjubEdDSASuite.NONCE_TAG, sk, message).mod(L);
        assertEquals(expected, frValue(actual));
    }

    private static BigInteger hedged(BigInteger sk, BigInteger message, byte[] auxiliary) {
        long[] secret = fr(sk);
        long[] nonceKey = new long[4];
        CtJubjubNonce.deriveNonceKey(
                nonceKey, 0, secret, 0, new long[CtJubjubNonce.WORK_LIMBS], 0);
        long[] generator = new long[CtJubjubPointOps.POINT_LIMBS];
        long[] publicKey = new long[CtJubjubPointOps.POINT_LIMBS];
        CtJubjubPointOps.generator(generator, 0);
        CtJubjubPointOps.scalarMul(
                publicKey, 0, generator, 0, secret, 0,
                new long[CtJubjubPointOps.SCALAR_MUL_WORK_LIMBS], 0);
        long[] normalized = new long[CtJubjubPointOps.POINT_LIMBS];
        CtJubjubPointOps.normalize(normalized, 0, publicKey, 0, new long[32], 0);
        long[] nonce = new long[4];
        CtJubjubNonce.hedgedV1(
                nonce, 0, nonceKey, 0, normalized, 0, fq(message), 0,
                auxiliary, 0, new long[CtJubjubNonce.WORK_LIMBS], 0);
        return frValue(nonce);
    }

    private static BigInteger tag(String label) {
        try {
            return new BigInteger(1, MessageDigest.getInstance("SHA-512")
                    .digest(label.getBytes(StandardCharsets.US_ASCII))).mod(P);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static long[] fq(BigInteger value) {
        long[] out = new long[4];
        assertEquals(-1L, CtJubjubFqOps.fromCanonicalBytes(
                out, 0, fixed32(value), 0, new long[16], 0));
        return out;
    }

    private static long[] fr(BigInteger value) {
        long[] out = new long[4];
        assertEquals(-1L, CtJubjubFrOps.fromCanonicalBytes(
                out, 0, fixed32(value), 0, new long[16], 0));
        return out;
    }

    private static BigInteger fqValue(long[] value) {
        return fqValue(value, 0);
    }

    private static BigInteger fqValue(long[] value, int offset) {
        byte[] out = new byte[32];
        CtJubjubFqOps.toCanonicalBytes(out, 0, value, offset, new long[16], 0);
        return new BigInteger(1, out);
    }

    private static BigInteger frValue(long[] value) {
        byte[] out = new byte[32];
        CtJubjubFrOps.toCanonicalBytes(out, 0, value, 0, new long[16], 0);
        return new BigInteger(1, out);
    }

    private static byte[] fqBytes(long[] value) {
        byte[] out = new byte[32];
        CtJubjubFqOps.toCanonicalBytes(out, 0, value, 0, new long[16], 0);
        return out;
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int source = raw.length > 32 && raw[0] == 0 ? 1 : 0;
        int length = raw.length - source;
        System.arraycopy(raw, source, out, out.length - length, length);
        return out;
    }

    private static BigInteger randomBelow(BigInteger modulus) {
        BigInteger value;
        do {
            value = new BigInteger(modulus.bitLength(), RANDOM);
        } while (value.compareTo(modulus) >= 0);
        return value;
    }

    private static BigInteger randomNonZeroBelow(BigInteger modulus) {
        BigInteger value;
        do {
            value = randomBelow(modulus);
        } while (value.signum() == 0);
        return value;
    }
}
