package com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Groth16VerificationKeyCodecTest {
    @Test
    void canonicalEncodingRoundTripsAndRejectsNonCanonicalLengths() {
        var key = new SnarkjsToCardano.VkCompressed(
                filled(48, 1), filled(96, 2), filled(96, 3), filled(96, 4),
                List.of(filled(48, 5), filled(48, 6)));
        byte[] encoded = Groth16VerificationKeyCodec.encode(key);
        var decoded = Groth16VerificationKeyCodec.decode(encoded);

        assertEquals(8 + 4 + 48 + 3 * 96 + 2 * 48, encoded.length);
        assertArrayEquals(key.alpha(), decoded.alpha());
        assertArrayEquals(key.beta(), decoded.beta());
        assertArrayEquals(key.gamma(), decoded.gamma());
        assertArrayEquals(key.delta(), decoded.delta());
        assertArrayEquals(key.ic().get(0), decoded.ic().get(0));
        assertArrayEquals(key.ic().get(1), decoded.ic().get(1));

        assertThrows(IllegalArgumentException.class,
                () -> Groth16VerificationKeyCodec.decode(Arrays.copyOf(encoded, encoded.length - 1)));
        byte[] trailing = Arrays.copyOf(encoded, encoded.length + 1);
        assertThrows(IllegalArgumentException.class,
                () -> Groth16VerificationKeyCodec.decode(trailing));
        byte[] wrongMagic = encoded.clone();
        wrongMagic[0] ^= 1;
        assertThrows(IllegalArgumentException.class,
                () -> Groth16VerificationKeyCodec.decode(wrongMagic));
        byte[] hostileCount = encoded.clone();
        ByteBuffer.wrap(hostileCount, 8, 4).putInt(Integer.MAX_VALUE);
        assertThrows(IllegalArgumentException.class,
                () -> Groth16VerificationKeyCodec.decode(hostileCount));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16VerificationKeyCodec.encode(new SnarkjsToCardano.VkCompressed(
                        new byte[47], key.beta(), key.gamma(), key.delta(), key.ic())));
    }

    private static byte[] filled(int length, int value) {
        byte[] output = new byte[length];
        Arrays.fill(output, (byte) value);
        return output;
    }
}
