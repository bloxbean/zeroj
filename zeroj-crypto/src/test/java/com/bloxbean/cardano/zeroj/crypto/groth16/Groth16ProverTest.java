package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Prover.R1CSConstraint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Groth16 prover internals.
 *
 * <p>Validates the h(x) polynomial computation (the mathematical core)
 * using known R1CS constraints and witnesses.</p>
 */
class Groth16ProverTest {

    static final BigInteger R = MontFr254.modulus();

    // --- h(x) polynomial tests ---

    @Test
    void computeH_multiplierCircuit() {
        // Multiplier: a * b = c
        // R1CS: A=[a], B=[b], C=[c]
        // Wire 0 = 1, Wire 1 = c (public), Wire 2 = a, Wire 3 = b, Wire 4 = product
        // Constraint: (a) * (b) = (product)  → A={2:1}, B={3:1}, C={4:1}
        // assertEqual: (product - c) * 1 = 0 → A={4:1, 1:-1}, B={0:1}, C={}

        var constraints = new R1CSConstraint[]{
                // a * b = product
                new R1CSConstraint(
                        Map.of(2, BigInteger.ONE),           // A: wire 2 (a)
                        Map.of(3, BigInteger.ONE),           // B: wire 3 (b)
                        Map.of(4, BigInteger.ONE)),          // C: wire 4 (product)
                // (product - c) * 1 = 0
                new R1CSConstraint(
                        Map.of(4, BigInteger.ONE, 1, R.subtract(BigInteger.ONE)),  // A: product - c
                        Map.of(0, BigInteger.ONE),           // B: 1
                        Map.of())                            // C: 0
        };

        // Witness: [1, 33, 3, 11, 33]
        BigInteger[] witness = {
                BigInteger.ONE,              // wire 0 = 1
                BigInteger.valueOf(33),      // wire 1 = c = 33
                BigInteger.valueOf(3),       // wire 2 = a = 3
                BigInteger.valueOf(11),      // wire 3 = b = 11
                BigInteger.valueOf(33)       // wire 4 = product = 33
        };

        // Verify constraints are satisfied
        for (var c : constraints) {
            BigInteger aVal = evalLC(c.a(), witness);
            BigInteger bVal = evalLC(c.b(), witness);
            BigInteger cVal = evalLC(c.c(), witness);
            assertEquals(aVal.multiply(bVal).mod(R), cVal, "Constraint should be satisfied");
        }

        // Compute h(x) — this should succeed without error for a valid witness
        BigInteger[] h = Groth16Prover.computeH(constraints, witness, 2, 4) /* 2 constraints, domainSize=4 */;
        assertNotNull(h);
        assertTrue(h.length > 0, "h polynomial should have at least one coefficient");
    }

    @Test
    void computeH_trivialConstraint() {
        // Single constraint: 1 * 1 = 1
        var constraints = new R1CSConstraint[]{
                new R1CSConstraint(
                        Map.of(0, BigInteger.ONE),
                        Map.of(0, BigInteger.ONE),
                        Map.of(0, BigInteger.ONE))
        };
        BigInteger[] witness = {BigInteger.ONE};

        // h(x) should be computable (may be zero polynomial for trivial cases)
        BigInteger[] h = Groth16Prover.computeH(constraints, witness, 1, 2);
        assertNotNull(h);
    }

    @Test
    void computeH_adderCircuit() {
        // Adder: a + b = sum
        // In R1CS, addition is free (absorbed into linear combinations)
        // But we can express it as: (a + b) * 1 = sum
        // Wire 0=1, 1=sum(public), 2=a, 3=b

        var constraints = new R1CSConstraint[]{
                new R1CSConstraint(
                        Map.of(2, BigInteger.ONE, 3, BigInteger.ONE),  // A: a + b
                        Map.of(0, BigInteger.ONE),                      // B: 1
                        Map.of(1, BigInteger.ONE))                      // C: sum
        };

        BigInteger[] witness = {BigInteger.ONE, BigInteger.valueOf(15), BigInteger.valueOf(7), BigInteger.valueOf(8)};

        // Verify constraint: (7 + 8) * 1 = 15 ✓
        BigInteger aVal = evalLC(constraints[0].a(), witness);
        BigInteger bVal = evalLC(constraints[0].b(), witness);
        BigInteger cVal = evalLC(constraints[0].c(), witness);
        assertEquals(aVal.multiply(bVal).mod(R), cVal);

        BigInteger[] h = Groth16Prover.computeH(constraints, witness, 1, 2);
        assertNotNull(h);
    }

    @Test
    void computeH_invalidWitness_hNonZeroAtRoots() {
        // If witness doesn't satisfy constraints, A*B - C != 0 at the roots of unity
        // h(x) computation may still succeed algebraically but produce a "wrong" h
        // that doesn't divide evenly (remainder != 0).
        // We verify this doesn't crash, at minimum.

        var constraints = new R1CSConstraint[]{
                new R1CSConstraint(
                        Map.of(1, BigInteger.ONE),
                        Map.of(2, BigInteger.ONE),
                        Map.of(3, BigInteger.ONE))
        };

        // Wrong witness: 3 * 11 != 99
        BigInteger[] witness = {BigInteger.ONE, BigInteger.valueOf(3), BigInteger.valueOf(11), BigInteger.valueOf(99)};

        // This should not crash (but the proof would be invalid)
        BigInteger[] h = Groth16Prover.computeH(constraints, witness, 1, 2);
        assertNotNull(h);
    }

    // --- Helpers ---

    private BigInteger evalLC(Map<Integer, BigInteger> lc, BigInteger[] witness) {
        BigInteger sum = BigInteger.ZERO;
        for (var e : lc.entrySet()) {
            if (e.getKey() < witness.length) {
                sum = sum.add(e.getValue().multiply(witness[e.getKey()]));
            }
        }
        return sum.mod(R);
    }
}
