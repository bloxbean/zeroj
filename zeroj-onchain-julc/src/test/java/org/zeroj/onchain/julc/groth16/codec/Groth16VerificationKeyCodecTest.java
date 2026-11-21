package org.zeroj.onchain.julc.groth16.codec;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    void encodeAndDecodeRejectInfinityOffSubgroupAndInvalidCompressedPoints() {
        var valid = validKey();
        byte[] g1Inf = Bls12381Codecs.g1ToCompressed(G1Point.INFINITY);
        byte[] g2Inf = Bls12381Codecs.g2ToCompressed(G2Point.INFINITY);

        G1Point g1Torsion = new G1Point(Fp.ZERO, Fp.of(2));
        assertTrue(g1Torsion.isOnCurve());
        assertFalse(g1Torsion.isInSubgroup());
        byte[] g1OffSubgroup = Bls12381Codecs.g1ToCompressed(g1Torsion);

        Fp2 x2 = Fp2.of(Fp.ZERO, Fp.ONE);
        Fp2 y2 = x2.square().mul(x2).add(Fp2.of(Fp.of(4), Fp.of(4))).sqrt().orElseThrow();
        G2Point g2Torsion = new G2Point(x2, y2);
        assertTrue(g2Torsion.isOnCurve());
        assertFalse(g2Torsion.isInSubgroup());
        byte[] g2OffSubgroup = Bls12381Codecs.g2ToCompressed(g2Torsion);

        List<SnarkjsToCardano.VkCompressed> badKeys = List.of(
                new SnarkjsToCardano.VkCompressed(g1Inf, valid.beta(), valid.gamma(), valid.delta(), valid.ic()),
                new SnarkjsToCardano.VkCompressed(valid.alpha(), g2Inf, valid.gamma(), valid.delta(), valid.ic()),
                new SnarkjsToCardano.VkCompressed(valid.alpha(), valid.beta(), valid.gamma(), valid.delta(),
                        List.of(valid.ic().get(0), g1Inf)),
                new SnarkjsToCardano.VkCompressed(filled(48, 1), valid.beta(), valid.gamma(), valid.delta(), valid.ic()),
                new SnarkjsToCardano.VkCompressed(g1OffSubgroup, valid.beta(), valid.gamma(), valid.delta(), valid.ic()),
                new SnarkjsToCardano.VkCompressed(valid.alpha(), g2OffSubgroup, valid.gamma(), valid.delta(), valid.ic())
        );

        for (var bad : badKeys) {
            assertThrows(IllegalArgumentException.class, () -> Groth16VerificationKeyCodec.encode(bad));
            byte[] rawWire = rawEncodeUnchecked(bad);
            IllegalArgumentException decodeEx = assertThrows(
                    IllegalArgumentException.class, () -> Groth16VerificationKeyCodec.decode(rawWire));
            assertFalse(decodeEx.getMessage().contains("magic"),
                    "raw wire test must exercise point validation, got: " + decodeEx.getMessage());
        }
    }

    private static byte[] rawEncodeUnchecked(SnarkjsToCardano.VkCompressed key) {
        byte[] magic = "ZJG16VK1".getBytes(StandardCharsets.US_ASCII);
        int size = magic.length + 4 + 48 + 3 * 96 + key.ic().size() * 48;
        ByteBuffer buf = ByteBuffer.allocate(size);
        buf.put(magic);
        buf.putInt(key.ic().size());
        buf.put(key.alpha());
        buf.put(key.beta());
        buf.put(key.gamma());
        buf.put(key.delta());
        for (byte[] p : key.ic()) {
            buf.put(p);
        }
        return buf.array();
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
