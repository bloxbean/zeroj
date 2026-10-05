package org.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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

    private static byte[] bouncyCastle(byte[] input, int bits) {
        var digest = new org.bouncycastle.crypto.digests.Blake2bDigest(bits);
        digest.update(input, 0, input.length);
        byte[] out = new byte[bits / 8];
        digest.doFinal(out, 0);
        return out;
    }
}
