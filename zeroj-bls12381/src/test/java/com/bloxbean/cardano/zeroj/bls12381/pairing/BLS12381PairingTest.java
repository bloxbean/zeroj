package com.bloxbean.cardano.zeroj.bls12381.pairing;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Generators;
import com.bloxbean.cardano.zeroj.bls12381.ec.*;
import com.bloxbean.cardano.zeroj.bls12381.field.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class BLS12381PairingTest {

    private static final G1Point G1 = Bls12381Generators.G1;
    private static final G2Point G2 = Bls12381Generators.G2;

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

    @Test
    void generatorPairing_isNonDegenerateAndHasOrderR() {
        var e = generatorPairing();

        assertFalse(e.isOne(), "e(G1,G2) must not be 1");
        assertTrue(e.pow(G1Point.R).isOne(), "e(G1,G2)^r must be 1");
    }

    @Test
    void generatorPairing_matchesKnownAnswer() {
        assertEquals(generatorPairingKat(), generatorPairing());
    }

    @Test
    void pairing_isBilinearForNonTrivialScalars() {
        var e = generatorPairing();
        var a = BigInteger.valueOf(5);
        var b = BigInteger.valueOf(7);

        var eAg2 = pair(G1.scalarMul(a), G2);
        var eG1b = pair(G1, G2.scalarMul(b));
        var eAg1b = pair(G1.scalarMul(a), G2.scalarMul(b));

        assertEquals(e.pow(a), eAg2, "e([a]G1,G2) must equal e(G1,G2)^a");
        assertEquals(e.pow(b), eG1b, "e(G1,[b]G2) must equal e(G1,G2)^b");
        assertEquals(e.pow(a.multiply(b)), eAg1b, "e([a]G1,[b]G2) must equal e(G1,G2)^(ab)");
    }

    private static Fp12 generatorPairing() {
        return pair(G1, G2);
    }

    private static Fp12 pair(G1Point p, G2Point q) {
        return BLS12381Pairing.finalExponentiation(BLS12381Pairing.millerLoop(p, q));
    }

    // Self-pinned regression vector in ZeroJ's Fp12 tower layout. Bilinearity,
    // non-degeneracy, and e^r checks above provide the independent correctness gates.
    // Replace or corroborate this with an external coefficient vector when a compatible
    // blst/zkcrypto Fp12 serialization is available.
    private static Fp12 generatorPairingKat() {
        return fp12(
                "11619b45f61edfe3b47a15fac19442526ff489dcda25e59121d9931438907dfd448299a87dde3a649bdba96e84d54558",
                "153ce14a76a53e205ba8f275ef1137c56a566f638b52d34ba3bf3bf22f277d70f76316218c0dfd583a394b8448d2be7f",
                "95668fb4a02fe930ed44767834c915b283b1c6ca98c047bd4c272e9ac3f3ba6ff0b05a93e59c71fba77bce995f04692",
                "16deedaa683124fe7260085184d88f7d036b86f53bb5b7f1fc5e248814782065413e7d958d17960109ea006b2afdeb5f",
                "9c92cf02f3cd3d2f9d34bc44eee0dd50314ed44ca5d30ce6a9ec0539be7a86b121edc61839ccc908c4bdde256cd6048",
                "111061f398efc2a97ff825b04d21089e24fd8b93a47e41e60eae7e9b2a38d54fa4dedced0811c34ce528781ab9e929c7",
                "1ecfcf31c86257ab00b4709c33f1c9c4e007659dd5ffc4a735192167ce197058cfb4c94225e7f1b6c26ad9ba68f63bc",
                "8890726743a1f94a8193a166800b7787744a8ad8e2f9365db76863e894b7a11d83f90d873567e9d645ccf725b32d26f",
                "e61c752414ca5dfd258e9606bac08daec29b3e2c57062669556954fb227d3f1260eedf25446a086b0844bcd43646c10",
                "fe63f185f56dd29150fc498bbeea78969e7e783043620db33f75a05a0a2ce5c442beaff9da195ff15164c00ab66bdde",
                "10900338a92ed0b47af211636f7cfdec717b7ee43900eee9b5fc24f0000c5874d4801372db478987691c566a8c474978",
                "1454814f3085f0e6602247671bc408bbce2007201536818c901dbd4d2095dd86c1ec8b888e59611f60a301af7776be3d");
    }

    private static Fp12 fp12(String... c) {
        return new Fp12(
                new Fp6(fp2(c[0], c[1]), fp2(c[2], c[3]), fp2(c[4], c[5])),
                new Fp6(fp2(c[6], c[7]), fp2(c[8], c[9]), fp2(c[10], c[11])));
    }

    private static Fp2 fp2(String c0, String c1) {
        return Fp2.of(fp(c0), fp(c1));
    }

    private static Fp fp(String hex) {
        return Fp.of(new BigInteger(hex, 16));
    }
}
