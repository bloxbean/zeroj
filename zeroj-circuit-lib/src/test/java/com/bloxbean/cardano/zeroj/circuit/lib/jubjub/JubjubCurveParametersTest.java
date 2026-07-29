package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the Jubjub curve parameters and the assumptions the gadgets rely on.
 *
 * <p>ADR-0016 Risk 4 named a {@code JubjubCurveTest.assertParameterSquareness} gate as the
 * mitigation for the completeness assumption behind the unified addition formula. That gate
 * was never written, so the assumption sat unchecked for the life of the module. This is it,
 * plus the rest of the constants the scheme depends on.
 *
 * <p>Every value is <b>re-derived</b> here rather than compared against a copy of itself:
 * {@code d} is recomputed from its defining rational, the subgroup generator from cofactor
 * clearing, and the squareness properties by Euler's criterion. A test that only compared
 * constants to hard-coded twins would pass even if both were wrong.
 */
class JubjubCurveParametersTest {

    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;

    // ------------------------------------------------------------------
    //  ADR-0016 Risk 4: the completeness assumption
    // ------------------------------------------------------------------

    /**
     * The unified Hisil–Wong–Carter–Dawson addition formula is complete — no exceptional
     * input pairs — precisely when {@code a} is a square and {@code d} is a non-square in the
     * base field. Every gadget in this package assumes that; nothing checked it until now.
     */
    @Test
    @DisplayName("a = -1 is a quadratic residue and d is a non-residue (unified-addition completeness)")
    void assertParameterSquareness() {
        assertTrue(isQuadraticResidue(JubjubCurve.A),
                "a = -1 must be a square in Fq, else the unified addition formula has "
                        + "exceptional inputs and every gadget here is unsound at those points");
        assertFalse(isQuadraticResidue(JubjubCurve.D),
                "d must be a NON-square in Fq for the same reason");
    }

    @Test
    @DisplayName("a = -1 is a square because p = 1 mod 4")
    void minusOneIsSquareBecauseOfPMod4() {
        assertEquals(BigInteger.ONE, P.mod(BigInteger.valueOf(4)),
                "-1 is a square in Fq iff p = 1 (mod 4)");
    }

    // ------------------------------------------------------------------
    //  Constants, re-derived rather than restated
    // ------------------------------------------------------------------

    @Test
    @DisplayName("d equals its defining rational -10240/10241")
    void dMatchesItsDefiningRational() {
        BigInteger expected = BigInteger.valueOf(-10240)
                .multiply(BigInteger.valueOf(10241).modInverse(P)).mod(P);
        assertEquals(expected, JubjubCurve.D);
    }

    @Test
    @DisplayName("a is -1 mod p and TWO_D is 2d mod p")
    void derivedConstants() {
        assertEquals(P.subtract(BigInteger.ONE), JubjubCurve.A);
        assertEquals(JubjubCurve.D.shiftLeft(1).mod(P), JubjubCurve.TWO_D);
    }

    @Test
    @DisplayName("p and l are prime, with the expected bit lengths")
    void moduliArePrime() {
        assertTrue(P.isProbablePrime(64), "base field prime");
        assertTrue(L.isProbablePrime(64), "subgroup order");
        assertEquals(255, P.bitLength());
        assertEquals(252, L.bitLength());
    }

    @Test
    @DisplayName("delta = p - 8l is 126 bits, which is what makes the nonce bias negligible")
    void deltaIsSmall() {
        BigInteger delta = P.subtract(L.shiftLeft(3));
        assertEquals(JubjubCurve.P_MINUS_EIGHT_L, delta);
        assertTrue(delta.signum() > 0, "p must exceed 8l");
        assertEquals(126, delta.bitLength(),
                "the statistical distance of `Poseidon mod l` from uniform is about delta/p, "
                        + "so 126 bits against a 255-bit p gives ~2^-129 -- not the ~2^-3 an "
                        + "earlier comment in this package claimed");
        assertTrue(delta.compareTo(L) < 0, "delta must be smaller than l for q <= 8 to hold");
    }

    @Test
    @DisplayName("group order is exactly 8·l: cofactor clearing yields the subgroup generator")
    void cofactorStructure() {
        assertEquals(8, JubjubCurve.COFACTOR);
        JubjubPoint full = JubjubPoint.FULL_GENERATOR;

        assertTrue(JubjubPoint.SUBGROUP_GENERATOR.projectiveEquals(full.mulByCofactor()),
                "SUBGROUP_GENERATOR must be [8]*FULL_GENERATOR");
        assertTrue(full.scalarMul(L.multiply(BigInteger.valueOf(8))).isIdentity(),
                "[8l]*FULL_GENERATOR == O");
        assertFalse(full.scalarMul(L).isIdentity(),
                "[l]*FULL_GENERATOR != O, i.e. the full generator really has order 8l");
        assertTrue(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(L).isIdentity(),
                "[l]*G == O");
        assertFalse(JubjubPoint.SUBGROUP_GENERATOR.isIdentity());
    }

    @Test
    @DisplayName("both generators are on the curve")
    void generatorsOnCurve() {
        assertTrue(onCurve(JubjubCurve.FULL_GENERATOR_U, JubjubCurve.FULL_GENERATOR_V));
        assertTrue(onCurve(JubjubPoint.SUBGROUP_GENERATOR.affineU(),
                JubjubPoint.SUBGROUP_GENERATOR.affineV()));
        assertEquals(BigInteger.valueOf(11), JubjubCurve.FULL_GENERATOR_V);
    }

    @Test
    @DisplayName("subgroup generator affine coordinates match the values pinned in the spec")
    void subgroupGeneratorMatchesSpec() {
        assertEquals(new BigInteger(
                        "3ea5c4673a121ca35ed37ee3b172f5ee04315c657fbe375f512dfea318d56fe5", 16),
                JubjubPoint.SUBGROUP_GENERATOR.affineU());
        assertEquals(new BigInteger(
                        "57137b83ea6edb4f78f7d30d3f616cb3b9aa6e8e40808413c10cea38d50c55cb", 16),
                JubjubPoint.SUBGROUP_GENERATOR.affineV());
    }

    // ------------------------------------------------------------------
    //  Torsion structure the verifier's key checks depend on
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the small-order points the verifier must reject really are small-order")
    void smallOrderPointsAreSmallOrder() {
        // (0, -1): order 2. Used by the M3 tests as an attacker-supplied public key.
        JubjubPoint o2 = JubjubPoint.fromAffine(BigInteger.ZERO, P.subtract(BigInteger.ONE));
        assertTrue(o2.doubled().isIdentity(), "(0,-1) must have order 2");
        assertFalse(o2.isInSubgroup());

        // [l]*FULL_GENERATOR: order 8.
        JubjubPoint o8 = JubjubPoint.FULL_GENERATOR.scalarMul(L);
        assertFalse(o8.isIdentity());
        assertTrue(o8.mulByCofactor().isIdentity(), "[l]*FULL_GEN must have order dividing 8");
        assertFalse(o8.isInSubgroup());

        // The identity passes the subgroup check, which is exactly why it needed its own
        // rejection rather than being covered by one.
        assertTrue(JubjubPoint.IDENTITY.isInSubgroup());
    }

    @Test
    @DisplayName("a mixed-order key survives [8]·pk != O, which is why verifyStrict exists")
    void mixedOrderKeySurvivesTheBackstop() {
        JubjubPoint pkPrime = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(12345));
        JubjubPoint mixed = pkPrime.add(JubjubPoint.FULL_GENERATOR.scalarMul(L));
        assertFalse(mixed.isInSubgroup(), "pk' + T is outside the prime-order subgroup");
        assertFalse(mixed.mulByCofactor().isIdentity(),
                "[8]*(pk' + T) = [8]*pk' != O, so the cheap backstop cannot detect it");
    }

    // ------------------------------------------------------------------

    private static boolean isQuadraticResidue(BigInteger x) {
        return x.modPow(P.subtract(BigInteger.ONE).shiftRight(1), P).equals(BigInteger.ONE);
    }

    private static boolean onCurve(BigInteger u, BigInteger v) {
        BigInteger uu = u.multiply(u).mod(P);
        BigInteger vv = v.multiply(v).mod(P);
        return vv.subtract(uu).mod(P).equals(
                BigInteger.ONE.add(JubjubCurve.D.multiply(uu).multiply(vv)).mod(P));
    }
}
