package org.zeroj.onchain.julc.groth16.codec;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Groth16VerificationKeyCodecTest {
    @Test
    void canonicalEncodingRoundTripsAndRejectsNonCanonicalLengths() {
        var key = validKey();
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

    @Test
    void decodeRejectsInfinityAndInvalidCompressedPoints() {
        var valid = validKey();
        byte[] g1Inf = Bls12381Codecs.g1ToCompressed(G1Point.INFINITY);
        byte[] g2Inf = Bls12381Codecs.g2ToCompressed(G2Point.INFINITY);

        var infAlpha = new SnarkjsToCardano.VkCompressed(g1Inf, valid.beta(), valid.gamma(), valid.delta(), valid.ic());
        assertThrows(IllegalArgumentException.class,
                () -> Groth16VerificationKeyCodec.decode(Groth16VerificationKeyCodec.encode(infAlpha)));

        var infBeta = new SnarkjsToCardano.VkCompressed(valid.alpha(), g2Inf, valid.gamma(), valid.delta(), valid.ic());
        assertThrows(IllegalArgumentException.class,
                () -> Groth16VerificationKeyCodec.decode(Groth16VerificationKeyCodec.encode(infBeta)));

        var infIc = new SnarkjsToCardano.VkCompressed(
                valid.alpha(), valid.beta(), valid.gamma(), valid.delta(), List.of(valid.ic().get(0), g1Inf));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16VerificationKeyCodec.decode(Groth16VerificationKeyCodec.encode(infIc)));

        var garbage = new SnarkjsToCardano.VkCompressed(
                filled(48, 1), valid.beta(), valid.gamma(), valid.delta(), valid.ic());
        assertThrows(IllegalArgumentException.class,
                () -> Groth16VerificationKeyCodec.decode(Groth16VerificationKeyCodec.encode(garbage)));
    }

    private static SnarkjsToCardano.VkCompressed validKey() {
        G1Point g1 = Bls12381Generators.G1;
        G2Point g2 = Bls12381Generators.G2;
        return new SnarkjsToCardano.VkCompressed(
                Bls12381Codecs.g1ToCompressed(g1.scalarMul(BigInteger.valueOf(2))),
                Bls12381Codecs.g2ToCompressed(g2.scalarMul(BigInteger.valueOf(3))),
                Bls12381Codecs.g2ToCompressed(g2.scalarMul(BigInteger.valueOf(5))),
                Bls12381Codecs.g2ToCompressed(g2.scalarMul(BigInteger.valueOf(7))),
                List.of(
                        Bls12381Codecs.g1ToCompressed(g1.scalarMul(BigInteger.valueOf(11))),
                        Bls12381Codecs.g1ToCompressed(g1.scalarMul(BigInteger.valueOf(13)))));
    }

    private static byte[] filled(int length, int value) {
        byte[] output = new byte[length];
        Arrays.fill(output, (byte) value);
        return output;
    }
}
