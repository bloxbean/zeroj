package com.bloxbean.cardano.zeroj.bls12381.spi;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Generators;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class PureJavaBls12381ProviderTest {

    private final Bls12381Provider provider = Bls12381Providers.pureJava();

    @Test
    void exposesStandardGenerators() {
        assertEquals(Bls12381Generators.G1, provider.g1Generator());
        assertEquals(Bls12381Generators.G2, provider.g2Generator());
    }

    @Test
    void exposesGroupOperationsAndCodecs() {
        assertEquals(G1Point.INFINITY, provider.g1Identity());
        assertEquals(G2Point.INFINITY, provider.g2Identity());
        assertEquals(Bls12381Generators.G1.add(Bls12381Generators.G1), provider.g1Add(Bls12381Generators.G1, Bls12381Generators.G1));
        assertEquals(Bls12381Generators.G2.add(Bls12381Generators.G2), provider.g2Add(Bls12381Generators.G2, Bls12381Generators.G2));
        assertEquals(Bls12381Generators.G1.negate(), provider.g1Negate(Bls12381Generators.G1));
        assertEquals(Bls12381Generators.G2.negate(), provider.g2Negate(Bls12381Generators.G2));
        assertEquals(Bls12381Generators.G1, provider.g1FromCompressed(provider.g1ToCompressed(Bls12381Generators.G1)));
        assertEquals(Bls12381Generators.G2, provider.g2FromCompressed(provider.g2ToCompressed(Bls12381Generators.G2)));
        assertEquals(Bls12381Generators.G1, provider.g1FromUncompressed(provider.g1ToUncompressed(Bls12381Generators.G1)));
        assertEquals(Bls12381Generators.G2, provider.g2FromUncompressed(provider.g2ToUncompressed(Bls12381Generators.G2)));
    }

    @Test
    void scalarMul_matchesAffineImplementation() {
        assertEquals(
                Bls12381Generators.G1.scalarMul(BigInteger.valueOf(42)),
                provider.g1ScalarMulGenerator(BigInteger.valueOf(42)));
        assertEquals(
                Bls12381Generators.G2.scalarMul(BigInteger.valueOf(42)),
                provider.g2ScalarMulGenerator(BigInteger.valueOf(42)));
    }

    @Test
    void scalarMul_reducesScalarsModuloGroupOrder() {
        var r = Bls12381Generators.SCALAR_FIELD_ORDER;

        assertEquals(G1Point.INFINITY, provider.g1ScalarMulGenerator(r));
        assertEquals(G2Point.INFINITY, provider.g2ScalarMulGenerator(r));
        assertEquals(Bls12381Generators.G1, provider.g1ScalarMulGenerator(r.add(BigInteger.ONE)));
        assertEquals(Bls12381Generators.G2, provider.g2ScalarMulGenerator(r.add(BigInteger.ONE)));
        assertEquals(Bls12381Generators.G1.negate(), provider.g1ScalarMulGenerator(BigInteger.valueOf(-1)));
        assertEquals(Bls12381Generators.G2.negate(), provider.g2ScalarMulGenerator(BigInteger.valueOf(-1)));
    }

    @Test
    void secretScalarMul_matchesPublicScalarMul() {
        var scalar = new BigInteger("12345678901234567890123456789012345678901234567890");

        assertEquals(provider.g1ScalarMulGenerator(scalar), provider.g1SecretScalarMulGenerator(scalar));
        assertEquals(provider.g2ScalarMulGenerator(scalar), provider.g2SecretScalarMulGenerator(scalar));
    }

    @Test
    void rejectsInvalidPoints() {
        assertThrows(IllegalArgumentException.class,
                () -> provider.g1ScalarMul(new G1Point(Fp.ZERO, Fp.ZERO), BigInteger.ONE));
        assertThrows(IllegalArgumentException.class,
                () -> provider.g2ScalarMul(new G2Point(Fp2.ZERO, Fp2.ZERO), BigInteger.ONE));
        assertThrows(IllegalArgumentException.class,
                () -> provider.g1SecretScalarMul(new G1Point(Fp.ZERO, Fp.ZERO), BigInteger.ONE));
        assertThrows(IllegalArgumentException.class,
                () -> provider.g2SecretScalarMul(new G2Point(Fp2.ZERO, Fp2.ZERO), BigInteger.ONE));
    }

    @Test
    void hashToScalar_isDeterministicAndInRange() {
        byte[] msg = "abc".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] dst = "ZEROJ-BLS12381-SCALAR".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        BigInteger scalar = provider.hashToScalar(msg, dst);
        assertEquals(scalar, provider.hashToScalar(msg, dst));
        assertTrue(scalar.signum() >= 0);
        assertTrue(scalar.compareTo(Bls12381Generators.SCALAR_FIELD_ORDER) < 0);
    }

    @Test
    void hashToCurve_returnsValidSubgroupPoints() {
        byte[] msg = "abc".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] g1Dst = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] g2Dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        assertTrue(provider.g1HashToCurve(msg, g1Dst).isValid());
        assertTrue(provider.g2HashToCurve(msg, g2Dst).isValid());
    }

    @Test
    void pairingProductIdentityForGeneratorAndNegation() {
        assertTrue(provider.pairingProductIsIdentity(
                new G1Point[]{Bls12381Generators.G1, Bls12381Generators.G1.negate()},
                new G2Point[]{Bls12381Generators.G2, Bls12381Generators.G2}));
    }
}
