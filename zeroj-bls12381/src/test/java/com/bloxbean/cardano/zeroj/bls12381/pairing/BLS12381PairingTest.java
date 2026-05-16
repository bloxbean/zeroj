package com.bloxbean.cardano.zeroj.bls12381.pairing;

import com.bloxbean.cardano.zeroj.bls12381.ec.*;
import com.bloxbean.cardano.zeroj.bls12381.field.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class BLS12381PairingTest {

    private static final G1Point G1 = new G1Point(
            Fp.of(new BigInteger("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", 16)),
            Fp.of(new BigInteger("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", 16)));
    private static final G2Point G2 = new G2Point(
            Fp2.of(Fp.of(new BigInteger("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8", 16)),
                    Fp.of(new BigInteger("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e", 16))),
            Fp2.of(Fp.of(new BigInteger("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801", 16)),
                    Fp.of(new BigInteger("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be", 16))));

    @Test
    void cyclotomicPolynomialDivisibleByR() {
        var p = Fp.P;
        var r = G1Point.R;
        var p2 = p.multiply(p);
        var p4 = p2.multiply(p2);
        var cyclotomic = p4.subtract(p2).add(BigInteger.ONE);
        assertEquals(BigInteger.ZERO, cyclotomic.mod(r));
    }

    @Test
    void fp12_oneToAnyPower_isOne() {
        assertTrue(Fp12.ONE.pow(new BigInteger("123456789")).isOne());
    }

    @Test
    void fp12_mulByInverse_isOne() {
        var a = new Fp12(
                new Fp6(Fp2.of(Fp.of(42), Fp.of(7)), Fp2.ONE, Fp2.ZERO),
                new Fp6(Fp2.of(Fp.of(3), Fp.of(5)), Fp2.ZERO, Fp2.ZERO));
        assertTrue(a.mul(a.inv()).isOne());
    }

    @Test
    void fp12_conjugateMul_hasClearC1() {
        var a = new Fp12(
                new Fp6(Fp2.of(Fp.of(42), Fp.of(7)), Fp2.ONE, Fp2.ZERO),
                new Fp6(Fp2.of(Fp.of(3), Fp.of(5)), Fp2.ZERO, Fp2.ZERO));
        assertTrue(a.mul(a.conjugate()).c1().isZero());
    }

    @Test
    void finalExpOfOne_isOne() {
        assertTrue(BLS12381Pairing.finalExponentiation(Fp12.ONE).isOne());
    }

    @Test
    void millerLoopNeg_isConjugate() {
        var f1 = BLS12381Pairing.millerLoop(G1, G2);
        var f2 = BLS12381Pairing.millerLoop(G1.negate(), G2);
        var product = f1.mul(f2);
        assertTrue(product.c1().isZero(),
                "ml(P,Q)*ml(-P,Q) must have zero w-component (conjugate pair)");
    }

    @Test
    void pairingCheck_ePlusNegE_isOne() {
        boolean result = BLS12381Pairing.pairingCheck(
                new G1Point[]{G1, G1.negate()},
                new G2Point[]{G2, G2});
        assertTrue(result, "e(P,Q)*e(-P,Q) must be 1");
    }
}
