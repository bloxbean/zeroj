package org.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The host BLAKE2b behind the threshold session id and transcript digest, against RFC 7693
 * Appendix A and two independent implementations (BouncyCastle and Cardano's
 * {@code Blake2bUtil}), across block boundaries.
 */
class Blake2bDigestTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    @DisplayName("RFC 7693 Appendix A: BLAKE2b-512(\"abc\")")
    void rfcVector() {
        assertArrayEquals(HEX.parseHex("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                        + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
                Blake2bDigest.digest("abc".getBytes(StandardCharsets.US_ASCII), 64));
    }

    @Test
    @DisplayName("Agrees with BouncyCastle (256 and 512 bits) and Cardano's Blake2bUtil, lengths 0..300")
    void differential() {
        Random rnd = new Random(62);
        for (int length = 0; length <= 300; length++) {
            byte[] input = new byte[length];
            rnd.nextBytes(input);
            assertArrayEquals(bouncyCastle(input, 256), Blake2bDigest.blake2b256(input), "len " + length);
            assertArrayEquals(bouncyCastle(input, 512), Blake2bDigest.digest(input, 64), "len " + length);
            assertArrayEquals(Blake2bUtil.blake2bHash256(input), Blake2bDigest.blake2b256(input), "len " + length);
        }
    }

    @Test
    @DisplayName("Output length is 1..64 bytes")
    void lengths() {
        assertThrows(IllegalArgumentException.class, () -> Blake2bDigest.digest(new byte[0], 0));
        assertThrows(IllegalArgumentException.class, () -> Blake2bDigest.digest(new byte[0], 65));
        assertArrayEquals(Blake2bUtil.blake2bHash224("x".getBytes(StandardCharsets.US_ASCII)),
                Blake2bDigest.digest("x".getBytes(StandardCharsets.US_ASCII), 28));
    }

    @Test
    @DisplayName("Block count is ⌈length / 128⌉ (one for empty input) up to Integer.MAX_VALUE, without overflow (review F9)")
    void blockCountBoundaries() {
        assertEquals(1, Blake2bDigest.blockCount(0));
        assertEquals(1, Blake2bDigest.blockCount(1));
        assertEquals(1, Blake2bDigest.blockCount(128));
        assertEquals(2, Blake2bDigest.blockCount(129));
        assertEquals(16_777_215, Blake2bDigest.blockCount(2_147_483_520));
        // From 2^31 − 127 on, the old int sum (length + 127) overflowed and gave one block.
        assertEquals(16_777_216, Blake2bDigest.blockCount(2_147_483_521));
        assertEquals(16_777_216, Blake2bDigest.blockCount(Integer.MAX_VALUE - 126));
        assertEquals(16_777_216, Blake2bDigest.blockCount(Integer.MAX_VALUE));
        assertThrows(IllegalArgumentException.class, () -> Blake2bDigest.blockCount(-1));
    }

    /**
     * Review F9's counterexample, end to end: a 2^31 − 127-byte input, against BouncyCastle, and
     * a change in its last byte changes the digest. About 2 GiB; run with
     * {@code ./gradlew :zeroj-circuit-lib:heavyGadgetTest --tests '*Blake2bDigestTest*'}.
     */
    @Test
    @EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    @DisplayName("Heavy: a 2^31 − 127-byte input is hashed in full and agrees with BouncyCastle (review F9)")
    void largeInput() {
        byte[] input = new byte[Integer.MAX_VALUE - 126];
        byte[] zero = Blake2bDigest.blake2b256(input);
        assertArrayEquals(bouncyCastle(input, 256), zero);
        input[input.length - 1] = 1;
        byte[] one = Blake2bDigest.blake2b256(input);
        assertArrayEquals(bouncyCastle(input, 256), one);
        assertFalse(Arrays.equals(zero, one), "the last byte must affect the digest");
    }

    @Test
    @DisplayName("Personalization: agrees with BouncyCastle's personalised BLAKE2b, lengths 0..300 and several personalizations (ADR-0055 M1)")
    void personalisedDifferential() {
        Random rnd = new Random(55);
        byte[][] personalizations = {
                "ZeroJ_NoteKDF_v1".getBytes(StandardCharsets.US_ASCII),
                "Zcash_SaplingKDF".getBytes(StandardCharsets.US_ASCII),
                new byte[16],
                HEX.parseHex("000102030405060708090a0b0c0d0e0f"),
                HEX.parseHex("ffffffffffffffffffffffffffffffff"),
        };
        for (byte[] pers : personalizations) {
            for (int length = 0; length <= 300; length++) {
                byte[] input = new byte[length];
                rnd.nextBytes(input);
                for (int outLength : new int[]{32, 64, 1, 17}) {
                    assertArrayEquals(bouncyCastle(input, outLength, pers), Blake2bDigest.digest(input, outLength, pers),
                            "length " + length + ", out " + outLength + ", pers " + HEX.formatHex(pers));
                }
            }
        }
    }

    @Test
    @DisplayName("An all-zero personalization equals none; any other changes the digest; a wrong length is refused")
    void personalizationRules() {
        byte[] input = "abc".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(Blake2bDigest.digest(input, 32), Blake2bDigest.digest(input, 32, new byte[16]));
        byte[] pers = "ZeroJ_NoteKDF_v1".getBytes(StandardCharsets.US_ASCII);
        assertFalse(Arrays.equals(Blake2bDigest.digest(input, 32), Blake2bDigest.digest(input, 32, pers)));
        byte[] flipped = pers.clone();
        flipped[15] ^= 1;
        assertFalse(Arrays.equals(Blake2bDigest.digest(input, 32, pers), Blake2bDigest.digest(input, 32, flipped)),
                "every personalization byte is used");
        assertThrows(IllegalArgumentException.class, () -> Blake2bDigest.digest(input, 32, new byte[15]));
        assertThrows(IllegalArgumentException.class, () -> Blake2bDigest.digest(input, 32, new byte[17]));
    }

    private static byte[] bouncyCastle(byte[] input, int outLength, byte[] personalization) {
        var digest = new org.bouncycastle.crypto.digests.Blake2bDigest(null, outLength, null, personalization);
        digest.update(input, 0, input.length);
        byte[] out = new byte[outLength];
        digest.doFinal(out, 0);
        return out;
    }

    private static byte[] bouncyCastle(byte[] input, int bits) {
        var digest = new org.bouncycastle.crypto.digests.Blake2bDigest(bits);
        digest.update(input, 0, input.length);
        byte[] out = new byte[bits / 8];
        digest.doFinal(out, 0);
        return out;
    }
}
