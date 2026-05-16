package com.bloxbean.cardano.zeroj.blst;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Generators;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Providers;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BlstBls12381ProviderTest {
    private static final Bls12381Provider PURE = Bls12381Providers.pureJava();
    private static final Bls12381Provider BLST = BlstBls12381Provider.createDefault();
    private static final List<BigInteger> SCALARS = List.of(
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger.TWO,
            BigInteger.valueOf(17),
            Bls12381Generators.SCALAR_FIELD_ORDER.subtract(BigInteger.ONE),
            Bls12381Generators.SCALAR_FIELD_ORDER,
            Bls12381Generators.SCALAR_FIELD_ORDER.add(BigInteger.ONE),
            BigInteger.valueOf(-1));

    @Test
    void generatorsMatchPureJavaBytes() {
        assertEquals("zeroj-bls12381-blst", BLST.id());
        assertArrayEquals(
                Bls12381Codecs.g1ToUncompressed(PURE.g1Generator()),
                Bls12381Codecs.g1ToUncompressed(BLST.g1Generator()));
        assertArrayEquals(
                Bls12381Codecs.g2ToUncompressed(PURE.g2Generator()),
                Bls12381Codecs.g2ToUncompressed(BLST.g2Generator()));
        assertArrayEquals(
                Bls12381Codecs.g1ToCompressed(PURE.g1Generator()),
                BLST.g1ToCompressed(BLST.g1Generator()));
        assertArrayEquals(
                Bls12381Codecs.g2ToCompressed(PURE.g2Generator()),
                BLST.g2ToCompressed(BLST.g2Generator()));
    }

    @Test
    void g1ArithmeticMatchesPureJava() {
        G1Point g = BLST.g1Generator();
        G1Point hashed = BLST.g1HashToCurve(
                "blst-g1-provider-test".getBytes(StandardCharsets.US_ASCII),
                "ZEROJ-BLS12381-BLST-G1-TEST".getBytes(StandardCharsets.US_ASCII));

        assertEquals(PURE.g1Add(PURE.g1Generator(), hashed), BLST.g1Add(g, hashed));
        assertEquals(PURE.g1Negate(hashed), BLST.g1Negate(hashed));
        assertEquals(hashed, BLST.g1Add(hashed, BLST.g1Identity()));
        assertEquals(BLST.g1Identity(), BLST.g1Add(hashed, BLST.g1Negate(hashed)));
        for (BigInteger scalar : SCALARS) {
            assertEquals(PURE.g1ScalarMul(hashed, scalar), BLST.g1ScalarMul(hashed, scalar), scalar.toString());
            assertEquals(BLST.g1ScalarMul(hashed, scalar), BLST.g1SecretScalarMul(hashed, scalar), scalar.toString());
        }
    }

    @Test
    void g2ArithmeticMatchesPureJava() {
        G2Point g = BLST.g2Generator();
        G2Point hashed = BLST.g2HashToCurve(
                "blst-g2-provider-test".getBytes(StandardCharsets.US_ASCII),
                "ZEROJ-BLS12381-BLST-G2-TEST".getBytes(StandardCharsets.US_ASCII));

        assertEquals(PURE.g2Add(PURE.g2Generator(), hashed), BLST.g2Add(g, hashed));
        assertEquals(PURE.g2Negate(hashed), BLST.g2Negate(hashed));
        assertEquals(hashed, BLST.g2Add(hashed, BLST.g2Identity()));
        assertEquals(BLST.g2Identity(), BLST.g2Add(hashed, BLST.g2Negate(hashed)));
        for (BigInteger scalar : SCALARS) {
            assertEquals(PURE.g2ScalarMul(hashed, scalar), BLST.g2ScalarMul(hashed, scalar), scalar.toString());
            assertEquals(BLST.g2ScalarMul(hashed, scalar), BLST.g2SecretScalarMul(hashed, scalar), scalar.toString());
        }
    }

    @Test
    void pairingProductMatchesPureJava() {
        G1Point g1 = BLST.g1Generator();
        G2Point g2 = BLST.g2Generator();
        G1Point negG1 = BLST.g1Negate(g1);

        assertTrue(BLST.pairingProductIsIdentity(new G1Point[]{g1, negG1}, new G2Point[]{g2, g2}));
        assertFalse(BLST.pairingProductIsIdentity(new G1Point[]{g1}, new G2Point[]{g2}));
        assertTrue(BLST.pairingProductIsIdentity(new G1Point[]{BLST.g1Identity()}, new G2Point[]{g2}));
        assertEquals(
                PURE.pairingProductIsIdentity(new G1Point[]{g1, negG1}, new G2Point[]{g2, g2}),
                BLST.pairingProductIsIdentity(new G1Point[]{g1, negG1}, new G2Point[]{g2, g2}));
    }

    @Test
    void pairingProductRejectsMismatchedArrayLengths() {
        assertThrows(IllegalArgumentException.class,
                () -> BLST.pairingProductIsIdentity(new G1Point[]{BLST.g1Generator()}, new G2Point[0]));
    }
}
