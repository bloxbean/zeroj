package com.bloxbean.cardano.zeroj.crypto.ec;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for BN254 G1 Jacobian point arithmetic.
 *
 * <p>Test vectors computed using Python with the BN254 base field prime.
 * Cross-validated against EIP-197 and the existing zeroj BigInteger-based G1Point.</p>
 */
class JacobianG1BN254Test {

    static final BigInteger P = MontFp254.modulus();

    // --- Generator and curve ---

    @Test
    void generator_isOnCurve() {
        var g = JacobianG1BN254.GENERATOR.toAffine();
        assertTrue(g.isOnCurve(), "Generator (1,2) must be on curve y^2 = x^3 + 3");
        assertEquals(BigInteger.ONE, g.xBigInt());
        assertEquals(BigInteger.TWO, g.yBigInt());
    }

    @Test
    void infinity_isInfinity() {
        assertTrue(JacobianG1BN254.INFINITY.isInfinity());
    }

    // --- Identity ---

    @Test
    void addInfinity_identity() {
        var g = JacobianG1BN254.GENERATOR;
        var sum = g.add(JacobianG1BN254.INFINITY);
        var aff = sum.toAffine();
        assertEquals(BigInteger.ONE, aff.xBigInt());
        assertEquals(BigInteger.TWO, aff.yBigInt());
    }

    @Test
    void infinityAdd_identity() {
        var g = JacobianG1BN254.GENERATOR;
        var sum = JacobianG1BN254.INFINITY.add(g);
        var aff = sum.toAffine();
        assertEquals(BigInteger.ONE, aff.xBigInt());
        assertEquals(BigInteger.TWO, aff.yBigInt());
    }

    // --- Negation ---

    @Test
    void negate_generator() {
        var g = JacobianG1BN254.GENERATOR;
        var neg = g.negate().toAffine();
        assertEquals(BigInteger.ONE, neg.xBigInt());
        assertEquals(P.subtract(BigInteger.TWO), neg.yBigInt(), "-G has y = p - 2");
        assertTrue(neg.isOnCurve());
    }

    @Test
    void addNegation_isInfinity() {
        var g = JacobianG1BN254.GENERATOR;
        assertTrue(g.add(g.negate()).isInfinity(), "G + (-G) = infinity");
    }

    // --- Doubling ---

    @Test
    void doubleGenerator() {
        // 2*G = (1368015179489954701390400359078579693043519447331113978918064868415326638035,
        //        9918110051302171585080402603319702774565515993150576347155970296011118125764)
        var twoG = JacobianG1BN254.GENERATOR.doublePoint().toAffine();
        assertTrue(twoG.isOnCurve(), "2G must be on curve");
        assertEquals(
                new BigInteger("1368015179489954701390400359078579693043519447331113978918064868415326638035"),
                twoG.xBigInt());
        assertEquals(
                new BigInteger("9918110051302171585080402603319702774565515993150576347155970296011118125764"),
                twoG.yBigInt());
    }

    // --- Addition ---

    @Test
    void tripleGenerator() {
        // 3*G = G + 2G
        var twoG = JacobianG1BN254.GENERATOR.doublePoint();
        var threeG = JacobianG1BN254.GENERATOR.add(twoG).toAffine();
        assertTrue(threeG.isOnCurve(), "3G must be on curve");
        assertEquals(
                new BigInteger("3353031288059533942658390886683067124040920775575537747144343083137631628272"),
                threeG.xBigInt());
        assertEquals(
                new BigInteger("19321533766552368860946552437480515441416830039777911637913418824951667761761"),
                threeG.yBigInt());
    }

    @Test
    void additionIsCommutative() {
        var g = JacobianG1BN254.GENERATOR;
        var twoG = g.doublePoint();
        var threeG = g.add(twoG);

        // Also compute as 2G + G
        var threeG2 = twoG.add(g);

        var aff1 = threeG.toAffine();
        var aff2 = threeG2.toAffine();
        assertEquals(aff1.xBigInt(), aff2.xBigInt());
        assertEquals(aff1.yBigInt(), aff2.yBigInt());
    }

    @Test
    void doubleViaAdd_matchesDoublePoint() {
        var g = JacobianG1BN254.GENERATOR;
        var dbl = g.doublePoint().toAffine();
        var addSelf = g.add(g).toAffine();
        assertEquals(dbl.xBigInt(), addSelf.xBigInt());
        assertEquals(dbl.yBigInt(), addSelf.yBigInt());
    }

    // --- Scalar multiplication ---

    @Test
    void scalarMul_zero() {
        assertTrue(JacobianG1BN254.GENERATOR.scalarMul(BigInteger.ZERO).isInfinity());
    }

    @Test
    void scalarMul_one() {
        var result = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.ONE).toAffine();
        assertEquals(BigInteger.ONE, result.xBigInt());
        assertEquals(BigInteger.TWO, result.yBigInt());
    }

    @Test
    void scalarMul_two() {
        var result = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.TWO).toAffine();
        var expected = JacobianG1BN254.GENERATOR.doublePoint().toAffine();
        assertEquals(expected.xBigInt(), result.xBigInt());
        assertEquals(expected.yBigInt(), result.yBigInt());
    }

    @Test
    void scalarMul_three() {
        var result = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.valueOf(3)).toAffine();
        assertTrue(result.isOnCurve());
        assertEquals(
                new BigInteger("3353031288059533942658390886683067124040920775575537747144343083137631628272"),
                result.xBigInt());
    }

    @Test
    void scalarMul_seven() {
        var result = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.valueOf(7)).toAffine();
        assertTrue(result.isOnCurve());

        // Verify by step-by-step addition
        var g = JacobianG1BN254.GENERATOR;
        var accumulated = g;
        for (int i = 1; i < 7; i++) {
            accumulated = accumulated.add(g);
        }
        var expected = accumulated.toAffine();
        assertEquals(expected.xBigInt(), result.xBigInt());
        assertEquals(expected.yBigInt(), result.yBigInt());
    }

    @Test
    void scalarMul_largeScalar() {
        // Use a large scalar and verify the result is on the curve
        BigInteger scalar = new BigInteger("123456789012345678901234567890");
        var result = JacobianG1BN254.GENERATOR.scalarMul(scalar).toAffine();
        assertTrue(result.isOnCurve(), "Large scalar mul result must be on curve");
        assertFalse(result.isInfinity());
    }

    @Test
    void scalarMul_negativeScalar() {
        BigInteger scalar = BigInteger.valueOf(5);
        var pos = JacobianG1BN254.GENERATOR.scalarMul(scalar).toAffine();
        var neg = JacobianG1BN254.GENERATOR.scalarMul(scalar.negate()).toAffine();

        assertEquals(pos.xBigInt(), neg.xBigInt(), "x coordinates should match");
        assertEquals(P.subtract(pos.yBigInt()), neg.yBigInt(), "y should be negated");
    }

    // --- EIP-197 test vector ---
    // From Ethereum precompile ecMul: 1*G = (1,2)
    // This validates our generator is correct for EVM compatibility.

    @Test
    void eip197_ecMul_scalarOne() {
        var result = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.ONE).toAffine();
        assertEquals(BigInteger.ONE, result.xBigInt());
        assertEquals(BigInteger.TWO, result.yBigInt());
    }

    // --- Mixed addition ---

    @Test
    void addAffine_matchesGeneralAdd() {
        var g = JacobianG1BN254.GENERATOR;
        var twoG = g.doublePoint();

        // General add
        var threeG1 = twoG.add(g).toAffine();
        // Mixed add
        var threeG2 = twoG.addAffine(MontFp254.ONE, MontFp254.TWO).toAffine();

        assertEquals(threeG1.xBigInt(), threeG2.xBigInt());
        assertEquals(threeG1.yBigInt(), threeG2.yBigInt());
    }

    // --- Associativity ---

    @Test
    void additionIsAssociative() {
        var g = JacobianG1BN254.GENERATOR;
        var twoG = g.doublePoint();
        var threeG = g.add(twoG);

        // (G + 2G) + G vs G + (2G + G)
        var fourG_1 = threeG.add(g).toAffine();
        var fourG_2 = g.add(twoG.add(g)).toAffine();

        assertEquals(fourG_1.xBigInt(), fourG_2.xBigInt());
        assertEquals(fourG_1.yBigInt(), fourG_2.yBigInt());
    }

    // --- Order ---

    @Test
    void scalarMul_byOrder_isInfinity() {
        // The order of BN254 G1 is the scalar field r
        BigInteger r = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        // r*G = infinity
        assertTrue(JacobianG1BN254.GENERATOR.scalarMul(r).isInfinity(),
                "Generator times the group order must be infinity");
    }

    @Test
    void scalarMul_byOrderMinusOne_isNegGenerator() {
        BigInteger r = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        var result = JacobianG1BN254.GENERATOR.scalarMul(r.subtract(BigInteger.ONE)).toAffine();
        // (r-1)*G = -G
        assertEquals(BigInteger.ONE, result.xBigInt());
        assertEquals(P.subtract(BigInteger.TWO), result.yBigInt(), "(r-1)*G should be -G");
    }

    // --- Consistency: multiple paths to same result ---

    @Test
    void tenG_threeWays() {
        var g = JacobianG1BN254.GENERATOR;

        // Way 1: scalar mul
        var tenG_1 = g.scalarMul(BigInteger.TEN).toAffine();

        // Way 2: 5G + 5G
        var fiveG = g.scalarMul(BigInteger.valueOf(5));
        var tenG_2 = fiveG.doublePoint().toAffine();

        // Way 3: 7G + 3G
        var sevenG = g.scalarMul(BigInteger.valueOf(7));
        var threeG = g.scalarMul(BigInteger.valueOf(3));
        var tenG_3 = sevenG.add(threeG).toAffine();

        assertTrue(tenG_1.isOnCurve());
        assertEquals(tenG_1.xBigInt(), tenG_2.xBigInt());
        assertEquals(tenG_1.yBigInt(), tenG_2.yBigInt());
        assertEquals(tenG_1.xBigInt(), tenG_3.xBigInt());
        assertEquals(tenG_1.yBigInt(), tenG_3.yBigInt());
    }
}
