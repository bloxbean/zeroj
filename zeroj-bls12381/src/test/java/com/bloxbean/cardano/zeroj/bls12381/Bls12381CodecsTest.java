package com.bloxbean.cardano.zeroj.bls12381;

import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class Bls12381CodecsTest {

    @Test
    void g1Uncompressed_roundTripsGenerator() {
        byte[] encoded = Bls12381Codecs.g1ToUncompressed(Bls12381Generators.G1);
        assertEquals(Bls12381Codecs.G1_UNCOMPRESSED_BYTES, encoded.length);
        assertEquals(Bls12381Generators.G1, Bls12381Codecs.g1FromUncompressed(encoded));
    }

    @Test
    void g1Compressed_roundTripsGenerator() {
        byte[] encoded = Bls12381Codecs.g1ToCompressed(Bls12381Generators.G1);
        assertEquals(Bls12381Codecs.G1_COMPRESSED_BYTES, encoded.length);
        assertEquals(Bls12381Generators.G1, Bls12381Codecs.g1FromCompressed(encoded));
    }

    @Test
    void g1Compressed_generatorMatchesZcashEncoding() {
        assertArrayEquals(
                hexToBytes("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"),
                Bls12381Codecs.g1ToCompressed(Bls12381Generators.G1));
    }

    @Test
    void g2Uncompressed_roundTripsGenerator() {
        byte[] encoded = Bls12381Codecs.g2ToUncompressed(Bls12381Generators.G2);
        assertEquals(Bls12381Codecs.G2_UNCOMPRESSED_BYTES, encoded.length);
        assertEquals(Bls12381Generators.G2, Bls12381Codecs.g2FromUncompressed(encoded));
    }

    @Test
    void g2Compressed_roundTripsGenerator() {
        byte[] encoded = Bls12381Codecs.g2ToCompressed(Bls12381Generators.G2);
        assertEquals(Bls12381Codecs.G2_COMPRESSED_BYTES, encoded.length);
        assertEquals(Bls12381Generators.G2, Bls12381Codecs.g2FromCompressed(encoded));
    }

    @Test
    void g2Compressed_generatorMatchesZcashEncoding() {
        assertArrayEquals(
                hexToBytes("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"),
                Bls12381Codecs.g2ToCompressed(Bls12381Generators.G2));
    }

    @Test
    void infinity_roundTrips() {
        assertEquals(G1Point.INFINITY, Bls12381Codecs.g1FromUncompressed(Bls12381Codecs.g1ToUncompressed(G1Point.INFINITY)));
        assertEquals(G2Point.INFINITY, Bls12381Codecs.g2FromUncompressed(Bls12381Codecs.g2ToUncompressed(G2Point.INFINITY)));
        assertEquals(G1Point.INFINITY, Bls12381Codecs.g1FromCompressed(Bls12381Codecs.g1ToCompressed(G1Point.INFINITY)));
        assertEquals(G2Point.INFINITY, Bls12381Codecs.g2FromCompressed(Bls12381Codecs.g2ToCompressed(G2Point.INFINITY)));
    }

    @Test
    void scalarToLittleEndian32_encodesOne() {
        byte[] scalar = Bls12381Codecs.scalarToLittleEndian32(BigInteger.ONE);
        assertEquals(1, scalar[0]);
        for (int i = 1; i < scalar.length; i++) {
            assertEquals(0, scalar[i]);
        }
    }

    @Test
    void scalarToLittleEndian32Reduced_reducesSignedScalars() {
        assertArrayEquals(
                Bls12381Codecs.scalarToLittleEndian32(BigInteger.ZERO),
                Bls12381Codecs.scalarToLittleEndian32Reduced(Bls12381Generators.SCALAR_FIELD_ORDER));
        assertArrayEquals(
                Bls12381Codecs.scalarToLittleEndian32(Bls12381Generators.SCALAR_FIELD_ORDER.subtract(BigInteger.ONE)),
                Bls12381Codecs.scalarToLittleEndian32Reduced(BigInteger.valueOf(-1)));
    }

    @Test
    void g1Uncompressed_rejectsOffCurvePoint() {
        byte[] encoded = Bls12381Codecs.g1ToUncompressed(Bls12381Generators.G1);
        encoded[encoded.length - 1] ^= 1;

        assertThrows(IllegalArgumentException.class, () -> Bls12381Codecs.g1FromUncompressed(encoded));
        assertFalse(Bls12381Codecs.g1FromUncompressedUnchecked(encoded).isOnCurve());
    }

    @Test
    void g1Codecs_rejectPrimeFieldTorsionPoint() {
        var torsion = new G1Point(Fp.ZERO, Fp.of(2));
        assertTrue(torsion.isOnCurve());
        assertFalse(torsion.isInSubgroup());

        assertThrows(IllegalArgumentException.class,
                () -> Bls12381Codecs.g1FromUncompressed(Bls12381Codecs.g1ToUncompressed(torsion)));
        assertThrows(IllegalArgumentException.class,
                () -> Bls12381Codecs.g1FromCompressed(Bls12381Codecs.g1ToCompressed(torsion)));
    }

    @Test
    void g2Uncompressed_rejectsOffCurvePoint() {
        byte[] encoded = Bls12381Codecs.g2ToUncompressed(Bls12381Generators.G2);
        encoded[encoded.length - 1] ^= 1;

        assertThrows(IllegalArgumentException.class, () -> Bls12381Codecs.g2FromUncompressed(encoded));
        assertFalse(Bls12381Codecs.g2FromUncompressedUnchecked(encoded).isOnCurve());
    }

    @Test
    void g2Codecs_rejectTwistTorsionPoint() {
        var x = Fp2.of(Fp.ZERO, Fp.ONE);
        var y = x.square().mul(x).add(Fp2.of(Fp.of(4), Fp.of(4))).sqrt().orElseThrow();
        var torsion = new G2Point(x, y);
        assertTrue(torsion.isOnCurve());
        assertFalse(torsion.isInSubgroup());

        assertThrows(IllegalArgumentException.class,
                () -> Bls12381Codecs.g2FromUncompressed(Bls12381Codecs.g2ToUncompressed(torsion)));
        assertThrows(IllegalArgumentException.class,
                () -> Bls12381Codecs.g2FromCompressed(Bls12381Codecs.g2ToCompressed(torsion)));
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
