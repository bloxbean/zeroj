package com.bloxbean.cardano.zeroj.crypto.ec;

import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class JacobianG2BN254Test {

    static final BigInteger FR = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");

    @Test
    void generator_isOnCurve() {
        assertTrue(JacobianG2BN254.GENERATOR.toAffine().isOnCurve());
    }

    @Test
    void infinity_isInfinity() {
        assertTrue(JacobianG2BN254.INFINITY.isInfinity());
    }

    @Test
    void addInfinity_identity() {
        var g = JacobianG2BN254.GENERATOR;
        var sum = g.add(JacobianG2BN254.INFINITY);
        assertFalse(sum.isInfinity());
        assertTrue(sum.toAffine().isOnCurve());
    }

    @Test
    void addNegation_isInfinity() {
        var g = JacobianG2BN254.GENERATOR;
        assertTrue(g.add(g.negate()).isInfinity());
    }

    @Test
    void doubleGenerator_isOnCurve() {
        var twoG = JacobianG2BN254.GENERATOR.doublePoint();
        assertFalse(twoG.isInfinity());
        assertTrue(twoG.toAffine().isOnCurve());
    }

    @Test
    void doubleViaAdd_matchesDoublePoint() {
        var g = JacobianG2BN254.GENERATOR;
        var dbl = g.doublePoint().toAffine();
        var addSelf = g.add(g).toAffine();
        assertEquals(dbl.x().reBigInt(), addSelf.x().reBigInt());
        assertEquals(dbl.x().imBigInt(), addSelf.x().imBigInt());
        assertEquals(dbl.y().reBigInt(), addSelf.y().reBigInt());
        assertEquals(dbl.y().imBigInt(), addSelf.y().imBigInt());
    }

    @Test
    void scalarMul_byOrder_isInfinity() {
        assertTrue(JacobianG2BN254.GENERATOR.scalarMul(FR).isInfinity(),
                "G2 generator times group order should be infinity");
    }

    @Test
    void scalarMul_seven_isOnCurve() {
        var result = JacobianG2BN254.GENERATOR.scalarMul(BigInteger.valueOf(7));
        assertFalse(result.isInfinity());
        assertTrue(result.toAffine().isOnCurve());
    }

    @Test
    void scalarMul_consistency() {
        var g = JacobianG2BN254.GENERATOR;
        // 5*G via scalarMul
        var fiveG1 = g.scalarMul(BigInteger.valueOf(5)).toAffine();
        // 5*G via addition: G + G + G + G + G
        var fiveG2 = g.add(g).add(g).add(g).add(g).toAffine();

        assertEquals(fiveG1.x().reBigInt(), fiveG2.x().reBigInt());
        assertEquals(fiveG1.x().imBigInt(), fiveG2.x().imBigInt());
        assertEquals(fiveG1.y().reBigInt(), fiveG2.y().reBigInt());
        assertEquals(fiveG1.y().imBigInt(), fiveG2.y().imBigInt());
    }

    @Test
    void additionIsCommutative() {
        var g = JacobianG2BN254.GENERATOR;
        var twoG = g.doublePoint();
        var a = g.add(twoG).toAffine();
        var b = twoG.add(g).toAffine();
        assertEquals(a.x().reBigInt(), b.x().reBigInt());
        assertEquals(a.y().reBigInt(), b.y().reBigInt());
    }
}
