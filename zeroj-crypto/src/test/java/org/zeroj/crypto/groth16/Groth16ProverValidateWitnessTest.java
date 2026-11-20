package org.zeroj.crypto.groth16;

import org.junit.jupiter.api.Test;
import org.zeroj.api.LegacyCurvePolicy;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.crypto.field.MontFr254;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0068: Groth16Prover.validateWitness legacy BN254 gating, wire-0, canonical, and bounds checks.
 */
class Groth16ProverValidateWitnessTest {

    @Test
    @SuppressWarnings("removal")
    void validateWitnessFailsClosedWhenLegacyBn254Disabled() {
        String prev = System.getProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY);
        try {
            System.clearProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY);
            List<R1CSConstraint> constraints = List.of(
                    new R1CSConstraint(Map.of(1, BigInteger.ONE), Map.of(2, BigInteger.ONE), Map.of(3, BigInteger.ONE)));
            BigInteger[] witness = {BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(3), BigInteger.valueOf(6)};
            assertThrows(IllegalStateException.class,
                    () -> Groth16Prover.validateWitness(constraints, witness, 1));
        } finally {
            if (prev == null) {
                System.clearProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY);
            } else {
                System.setProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY, prev);
            }
        }
    }

    @Test
    @SuppressWarnings("removal")
    void validateWitnessEnforcesWireZeroCanonicalScalarsAndBoundsWhenEnabled() {
        String prev = System.getProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY);
        try {
            System.setProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY, "true");
            List<R1CSConstraint> constraints = List.of(
                    new R1CSConstraint(Map.of(1, BigInteger.ONE), Map.of(2, BigInteger.ONE), Map.of(3, BigInteger.ONE)));
            BigInteger[] valid = {BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(3), BigInteger.valueOf(6)};
            assertDoesNotThrow(() -> Groth16Prover.validateWitness(constraints, valid, 1));

            // witness[0] != 1 rejected without leaking value
            BigInteger sentinel = new BigInteger("777666555444333222111");
            BigInteger[] badWire0 = {sentinel, BigInteger.TWO, BigInteger.valueOf(3), BigInteger.valueOf(6)};
            IllegalArgumentException wire0Ex = assertThrows(IllegalArgumentException.class,
                    () -> Groth16Prover.validateWitness(constraints, badWire0, 1));
            assertFalse(wire0Ex.getMessage().contains(sentinel.toString()));

            // Violated constraint rejected without leaking witness-derived lhs/cVal
            BigInteger[] badConstraint = {BigInteger.ONE, sentinel, BigInteger.ONE, BigInteger.ZERO};
            IllegalArgumentException constrEx = assertThrows(IllegalArgumentException.class,
                    () -> Groth16Prover.validateWitness(constraints, badConstraint, 1));
            assertFalse(constrEx.getMessage().contains(sentinel.toString()));

            // Non-canonical scalar >= BN254 r rejected
            BigInteger[] nonCanonical = {BigInteger.ONE, MontFr254.modulus(), BigInteger.ZERO, BigInteger.ZERO};
            assertThrows(IllegalArgumentException.class,
                    () -> Groth16Prover.validateWitness(constraints, nonCanonical, 1));

            // Negative numConstraints or > size rejected
            assertThrows(IllegalArgumentException.class,
                    () -> Groth16Prover.validateWitness(constraints, valid, -1));
            assertThrows(IllegalArgumentException.class,
                    () -> Groth16Prover.validateWitness(constraints, valid, 2));

            // Negative wire index rejected
            List<R1CSConstraint> negWire = List.of(
                    new R1CSConstraint(Map.of(-1, BigInteger.ONE), Map.of(0, BigInteger.ONE), Map.of()));
            assertThrows(IllegalArgumentException.class,
                    () -> Groth16Prover.validateWitness(negWire, valid, 1));
        } finally {
            if (prev == null) {
                System.clearProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY);
            } else {
                System.setProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY, prev);
            }
        }
    }
}
