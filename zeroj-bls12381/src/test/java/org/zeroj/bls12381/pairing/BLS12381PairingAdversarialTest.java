package org.zeroj.bls12381.pairing;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp12;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.bls12381.field.Fp6;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0062 D9 (pairing). Negative pairing products, identity and length edge cases, bilinearity
 * over several random scalar pairs, and an external GT known-answer test.
 *
 * <p>The GT vectors come from py_ecc 8.0.0 via
 * {@code src/test/resources/bls12381-reference/pyecc_gt_kat.py}, which maps py_ecc's orientation
 * (ZeroJ = py_ecc⁻¹) and Fp12 basis to ZeroJ's layout. The {@code e(G1, G2)} value equals the
 * self-pinned vector in {@link BLS12381PairingTest} and the ffjavascript-corroborated one in
 * {@code zeroj-crypto}, so three independent sources agree.</p>
 *
 * <p>The checks are written against an injectable pairing so that {@link #mutantsAreDetected} can
 * show they fail for a constant-1 pairing and for {@code e⁻¹} (the request in ADR-0021).</p>
 */
class BLS12381PairingAdversarialTest {
    private static final G1Point G1 = Bls12381Generators.G1;
    private static final G2Point G2 = Bls12381Generators.G2;
    private static final BigInteger R = G1Point.R;

    private static final BigInteger KAT_A =
            new BigInteger("2a5e3c6f1b0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f", 16);
    private static final BigInteger KAT_B =
            new BigInteger("1f2e3d4c5b6a79881726354453627180fedcba9876543210f0e1d2c3b4a59687", 16);

    private static final BiFunction<G1Point, G2Point, Fp12> REAL =
            (p, q) -> BLS12381Pairing.finalExponentiation(BLS12381Pairing.millerLoop(p, q));

    // ---- the checks, against the real pairing ----

    @Test
    void realPairingPassesEveryCheck() {
        assertEquals(List.of(), failedChecks(REAL));
    }

    /** ADR-0021 / ADR-0062: the suite must not pass for a constant-1 pairing or for e⁻¹. */
    @Test
    void mutantsAreDetected() {
        BiFunction<G1Point, G2Point, Fp12> constantOne = (p, q) -> Fp12.ONE;
        BiFunction<G1Point, G2Point, Fp12> inverse = (p, q) -> REAL.apply(p, q).inv();

        assertFalse(failedChecks(constantOne).isEmpty(), "a constant-1 pairing must fail the suite");
        assertFalse(failedChecks(inverse).isEmpty(), "e^-1 must fail the suite");
    }

    private static List<String> failedChecks(BiFunction<G1Point, G2Point, Fp12> e) {
        List<String> failed = new ArrayList<>();
        check(failed, "positive: e(G1,G2)·e(−G1,G2) = 1",
                product(e, new G1Point[]{G1, G1.negate()}, new G2Point[]{G2, G2}).isOne());
        check(failed, "negative: e(G1,G2) ≠ 1", !e.apply(G1, G2).isOne());
        BigInteger a = BigInteger.valueOf(11);
        BigInteger b = BigInteger.valueOf(13);
        check(failed, "negative: e(aG1,bG2)·e(−G1,(ab+1)G2) ≠ 1",
                !product(e, new G1Point[]{G1.scalarMul(a), G1.negate()},
                        new G2Point[]{G2.scalarMul(b), G2.scalarMul(a.multiply(b).add(BigInteger.ONE))}).isOne());
        check(failed, "positive: e(aG1,bG2)·e(−G1,(ab)G2) = 1",
                product(e, new G1Point[]{G1.scalarMul(a), G1.negate()},
                        new G2Point[]{G2.scalarMul(b), G2.scalarMul(a.multiply(b))}).isOne());
        check(failed, "external KAT e(G1,G2) (py_ecc 8.0.0)", e.apply(G1, G2).equals(pyEccGeneratorPairing()));
        check(failed, "external KAT e([a]G1,[b]G2) (py_ecc 8.0.0)",
                e.apply(G1.scalarMul(KAT_A), G2.scalarMul(KAT_B)).equals(pyEccScaledPairing()));
        return failed;
    }

    private static void check(List<String> failed, String name, boolean ok) {
        if (!ok) {
            failed.add(name);
        }
    }

    private static Fp12 product(BiFunction<G1Point, G2Point, Fp12> e, G1Point[] ps, G2Point[] qs) {
        Fp12 acc = Fp12.ONE;
        for (int i = 0; i < ps.length; i++) {
            acc = acc.mul(e.apply(ps[i], qs[i]));
        }
        return acc;
    }

    // ---- the production entry point: pairingCheck ----

    @Test
    void pairingCheck_rejectsANonIdentityProduct() {
        assertFalse(BLS12381Pairing.pairingCheck(new G1Point[]{G1}, new G2Point[]{G2}));
        BigInteger a = BigInteger.valueOf(5);
        BigInteger b = BigInteger.valueOf(9);
        assertFalse(BLS12381Pairing.pairingCheck(
                new G1Point[]{G1.scalarMul(a), G1.negate()},
                new G2Point[]{G2.scalarMul(b), G2.scalarMul(a.multiply(b).add(BigInteger.ONE))}));
        assertTrue(BLS12381Pairing.pairingCheck(
                new G1Point[]{G1.scalarMul(a), G1.negate()},
                new G2Point[]{G2.scalarMul(b), G2.scalarMul(a.multiply(b))}));
    }

    @Test
    void pairingCheck_identityInputsContributeOne() {
        assertTrue(BLS12381Pairing.pairingCheck(new G1Point[]{G1Point.INFINITY}, new G2Point[]{G2}));
        assertTrue(BLS12381Pairing.pairingCheck(new G1Point[]{G1}, new G2Point[]{G2Point.INFINITY}));
        // An identity pair does not mask a non-identity one.
        assertFalse(BLS12381Pairing.pairingCheck(
                new G1Point[]{G1Point.INFINITY, G1}, new G2Point[]{G2, G2}));
        assertTrue(BLS12381Pairing.millerLoop(G1Point.INFINITY, G2).isOne());
        assertTrue(BLS12381Pairing.millerLoop(G1, G2Point.INFINITY).isOne());
    }

    @Test
    void pairingCheck_rejectsLengthMismatch() {
        assertThrows(IllegalArgumentException.class,
                () -> BLS12381Pairing.pairingCheck(new G1Point[]{G1, G1}, new G2Point[]{G2}));
        assertThrows(IllegalArgumentException.class,
                () -> BLS12381Pairing.pairingCheck(new G1Point[]{}, new G2Point[]{G2}));
    }

    @Test
    void bilinearityOverRandomScalarPairs() {
        Random random = new Random(0x0062_0009L);
        for (int i = 0; i < 8; i++) {
            BigInteger a = new BigInteger(255, random).mod(R);
            BigInteger b = new BigInteger(255, random).mod(R);
            Fp12 eab = REAL.apply(G1.scalarMul(a), G2.scalarMul(b));
            assertEquals(REAL.apply(G1.scalarMul(a.multiply(b).mod(R)), G2), eab, "pair " + i);
            assertEquals(REAL.apply(G1, G2.scalarMul(a.multiply(b).mod(R))), eab, "pair " + i);
            assertTrue(BLS12381Pairing.pairingCheck(
                    new G1Point[]{G1.scalarMul(a), G1.scalarMul(a.multiply(b).mod(R)).negate()},
                    new G2Point[]{G2.scalarMul(b), G2}), "pair " + i);
        }
    }

    /**
     * ADR-0062 D7: the former vertical-line branch of {@code lineFuncAdd} silently computed a wrong
     * line for {@code T = Q}. With an order-13 twist point the loop reaches {@code T = 12Q = −Q} at
     * the third addition step; that must now fail instead of returning a value.
     */
    @Test
    void millerLoop_rejectsAPointThatReachesTEqualsMinusQ() {
        G2Point q = twistPointOfOrder13();
        assertTrue(q.isOnCurve());
        assertFalse(q.isInSubgroup());
        assertThrows(IllegalArgumentException.class, () -> BLS12381Pairing.millerLoop(G1, q));
        assertThrows(IllegalArgumentException.class,
                () -> BLS12381Pairing.pairingCheck(new G1Point[]{G1}, new G2Point[]{q}));
    }

    /** A point of order 13 on the G2 twist (13² divides the twist cofactor h2). */
    private static G2Point twistPointOfOrder13() {
        BigInteger h2 = new BigInteger("5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef2"
                + "1537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5", 16);
        BigInteger groupOrder = h2.multiply(R);
        BigInteger thirteen = BigInteger.valueOf(13);
        Fp2 b = Fp2.of(Fp.of(4), Fp.of(4));
        for (int x0 = 1; x0 < 1000; x0++) {
            Fp2 x = Fp2.of(Fp.of(x0), Fp.ZERO);
            var y = x.square().mul(x).add(b).sqrt();
            if (y.isEmpty()) {
                continue;
            }
            G2Point t = new G2Point(x, y.get()).scalarMul(groupOrder.divide(thirteen.pow(2)));
            G2Point q = t.scalarMul(thirteen).isInfinity() ? t : t.scalarMul(thirteen);
            if (!q.isInfinity() && q.scalarMul(thirteen).isInfinity()) {
                return q;
            }
        }
        throw new AssertionError("no order-13 twist point found");
    }

    // ---- py_ecc 8.0.0 vectors, ZeroJ layout (see pyecc_gt_kat.py) ----

    private static Fp12 pyEccGeneratorPairing() {
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

    private static Fp12 pyEccScaledPairing() {
        return fp12(
                "167ad8b3aa3b070f897fe02118408e92af2543131c5d6dcc59e1b8c104ca9a8a72e889347600f037b6485f1dcdc8f131",
                "9df0874da8a7758c3f1193a5febc3015bc8389a1bba07bce3fdff4334dddc16145f7065eccb5f931e358e209dcdcccd",
                "891299dba71bf64d45c56f827b172ec36157d7d44cedfb82579fb910cdaf3211dcaed80406f07fec5a3561fbcd6c76e",
                "137f1e35ba528b0ba2426dde63a9080554ee06a8652b6790fb5c3a91448ef71f4c1e2fe28d1c420cdfd9f405b0d65887",
                "e9c877da5fbd96cce0ac7994d0f1d6bf7e93deb8d42ce97d10da531d40f6d9f86734ff8570716edacb078a9fd428615",
                "1730dd51776750735f653c2f23e3663e91e9b171d24ed3bd41918fcf1acf67c5ded3cc6a48a501a61294a51ae9c85dd4",
                "103ac57af2d2a05f705e97e805efb515d68a9407a8e8e170a2f293d17e7c8f3049cf7a74c76c686b20ab7857005b2213",
                "cddf27edb46082d1eb95f400f1a82a8075b7e11d4968b5f76517c1b6b847482b1e806b735c9e39a62463233c0973155",
                "43b59e922885a36a296446311edd9cd4b1c5a875c1fdd5939bbc88d543518f118d30ca04f926554f5a83ae3f8fa0847",
                "e5ebac62a1c2e6f6b23eb1bf2d8541b928a8f2e15a96840a2ded7a296bb33db4b0d12ca7efbe2f0e3805450f1ecb0a6",
                "cb3f72316d66240a69ba4448b4d9a838d1c460ed1cb960193136c97f73040a8fa96d4218170c15993d4011d1849e4af",
                "c053f87d604bb53ae900b06f6d2562e4be43c8b2316985c8f227cdf0b56478c338752734ad2d0059d767d2d6eafb3ea");
    }

    private static Fp12 fp12(String... c) {
        return new Fp12(
                new Fp6(fp2(c[0], c[1]), fp2(c[2], c[3]), fp2(c[4], c[5])),
                new Fp6(fp2(c[6], c[7]), fp2(c[8], c[9]), fp2(c[10], c[11])));
    }

    private static Fp2 fp2(String c0, String c1) {
        return Fp2.of(Fp.of(new BigInteger(c0, 16)), Fp.of(new BigInteger(c1, 16)));
    }
}
