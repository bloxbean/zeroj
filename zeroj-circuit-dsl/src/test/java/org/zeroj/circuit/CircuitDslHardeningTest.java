package org.zeroj.circuit;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0068: raw CircuitAPI boolean enforcement, fromBinary width guard, strict canonical
 * WitnessCalculator, and curve-generic R1CSConstraintSystem.verifyWitness.
 */
class CircuitDslHardeningTest {

    @Test
    void rawBooleanOpsRejectNonBooleanWitnessesEvenWhenBypassingWitnessCalculator() {
        List<CircuitBuilder> circuits = List.of(
                CircuitBuilder.create("raw-xor").secretVar("a").secretVar("b").publicVar("out")
                        .define(api -> api.assertEqual(api.xor(api.var("a"), api.var("b")), api.var("out"))),
                CircuitBuilder.create("raw-and").secretVar("a").secretVar("b").publicVar("out")
                        .define(api -> api.assertEqual(api.and(api.var("a"), api.var("b")), api.var("out"))),
                CircuitBuilder.create("raw-or").secretVar("a").secretVar("b").publicVar("out")
                        .define(api -> api.assertEqual(api.or(api.var("a"), api.var("b")), api.var("out"))),
                CircuitBuilder.create("raw-not").secretVar("a").publicVar("out")
                        .define(api -> api.assertEqual(api.not(api.var("a")), api.var("out")))
        );

        for (CurveId curve : List.of(CurveId.BLS12_381, CurveId.BN254)) {
            FieldConfig field = FieldConfig.forCurve(curve);
            BigInteger p = field.prime();
            for (CircuitBuilder circuit : circuits) {
                R1CSConstraintSystem r1cs = circuit.compileR1CS(curve);
                boolean binaryOp = circuit.constraintGraph().secretInputs().size() == 2;

                // Honest boolean witness satisfies both WitnessCalculator and verifyWitness
                Map<String, List<BigInteger>> honestInputs = binaryOp
                        ? Map.of("a", List.of(BigInteger.ONE), "b", List.of(BigInteger.ZERO),
                                "out", List.of(circuit.constraintGraph().name().equals("raw-and")
                                        ? BigInteger.ZERO : BigInteger.ONE))
                        : Map.of("a", List.of(BigInteger.ONE), "out", List.of(BigInteger.ZERO));
                BigInteger[] honestWitness = circuit.calculateWitness(honestInputs, curve);
                assertDoesNotThrow(() -> r1cs.verifyWitness(honestWitness));

                // Non-boolean input a = 2 must be rejected by WitnessCalculator
                Map<String, List<BigInteger>> badInputs = binaryOp
                        ? Map.of("a", List.of(BigInteger.TWO), "b", List.of(BigInteger.ZERO),
                                "out", List.of(BigInteger.TWO))
                        : Map.of("a", List.of(BigInteger.TWO), "out", List.of(p.subtract(BigInteger.ONE)));
                assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(badInputs, curve));

                // Adversarial raw witness bypassing WitnessCalculator with a = 2 (matching algebraic formula)
                BigInteger[] forged = honestWitness.clone();
                int aId = circuit.constraintGraph().secretInputs().getFirst().id();
                int outId = circuit.constraintGraph().publicInputs().getFirst().id();
                forged[aId] = BigInteger.TWO;
                if (circuit.constraintGraph().name().equals("raw-not")) {
                    forged[outId] = p.subtract(BigInteger.ONE);
                } else if (circuit.constraintGraph().name().equals("raw-and")) {
                    forged[outId] = BigInteger.ZERO;
                } else {
                    forged[outId] = BigInteger.TWO;
                }
                assertThrows(IllegalArgumentException.class, () -> r1cs.verifyWitness(forged));
            }
        }
    }

    @Test
    void derivedBooleansDoNotEmitRedundantAssertBooleanGates() {
        var graph = CircuitBuilder.create("derived-bools")
                .secretVar("x").secretVar("y")
                .define(api -> {
                    var z = api.isZero(api.var("x"));
                    var eq = api.isEqual(api.var("x"), api.var("y"));
                    var c0 = api.constant(0);
                    var c1 = api.constant(1);
                    var combined = api.not(api.or(api.and(z, eq), api.xor(c0, c1)));
                    api.assertBoolean(combined);
                    api.select(combined, api.var("x"), api.var("y"));
                }).constraintGraph();

        long assertBoolCount = graph.gates().stream()
                .filter(Gate.AssertBoolean.class::isInstance)
                .count();
        assertEquals(0, assertBoolCount,
                "provably-boolean outputs (0, 1, isZero, isEqual, xor/and/or/not) must not re-emit AssertBoolean");
    }

    @Test
    void fromBinaryEnforcesWidthBoundsAndNonNullBits() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("empty-bits")
                .define(api -> api.fromBinary(new Variable[0])));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("too-wide-bits")
                .define(api -> {
                    Variable[] bits = new Variable[254];
                    Variable zero = api.constant(0);
                    for (int i = 0; i < bits.length; i++) bits[i] = zero;
                    api.fromBinary(bits);
                }));

        assertThrows(NullPointerException.class, () -> CircuitBuilder.create("null-bit-entry")
                .define(api -> api.fromBinary(new Variable[]{api.constant(1), null})));

        // Boundary 1 bit and 253 bits succeed
        assertDoesNotThrow(() -> CircuitBuilder.create("max-253-bits")
                .define(api -> {
                    Variable[] bits = new Variable[253];
                    Variable zero = api.constant(0);
                    for (int i = 0; i < bits.length; i++) bits[i] = zero;
                    api.fromBinary(bits);
                }));
    }

    @Test
    void witnessCalculatorRejectsUnknownKeysMultiValueListsNullAndNonCanonicalInputs() {
        var circuit = CircuitBuilder.create("mul")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));
        var graph = circuit.constraintGraph();
        FieldConfig bls = FieldConfig.BLS12_381;
        BigInteger p = bls.prime();

        // Null map
        assertThrows(NullPointerException.class, () -> WitnessCalculator.calculate(graph, null, bls));

        // Unknown extra key
        Map<String, List<BigInteger>> unknownKey = Map.of(
                "c", List.of(BigInteger.valueOf(6)),
                "a", List.of(BigInteger.TWO),
                "b", List.of(BigInteger.valueOf(3)),
                "extra", List.of(BigInteger.ZERO));
        assertThrows(IllegalArgumentException.class, () -> WitnessCalculator.calculate(graph, unknownKey, bls));
        assertThrows(IllegalArgumentException.class, () -> WitnessCalculator.calculateFlat(graph, unknownKey, bls));

        // Multi-value list
        Map<String, List<BigInteger>> multiVal = Map.of(
                "c", List.of(BigInteger.valueOf(6)),
                "a", List.of(BigInteger.TWO, BigInteger.ONE),
                "b", List.of(BigInteger.valueOf(3)));
        assertThrows(IllegalArgumentException.class, () -> WitnessCalculator.calculate(graph, multiVal, bls));

        // Null element inside list
        Map<String, List<BigInteger>> nullElem = new HashMap<>();
        nullElem.put("c", List.of(BigInteger.valueOf(6)));
        nullElem.put("a", Collections.singletonList(null));
        nullElem.put("b", List.of(BigInteger.valueOf(3)));
        assertThrows(IllegalArgumentException.class, () -> WitnessCalculator.calculate(graph, nullElem, bls));

        // Negative value (no silent mod p)
        Map<String, List<BigInteger>> negative = Map.of(
                "c", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.ONE.negate()),
                "b", List.of(BigInteger.ONE.negate()));
        assertThrows(IllegalArgumentException.class, () -> WitnessCalculator.calculate(graph, negative, bls));

        // Value >= p (no silent mod p)
        Map<String, List<BigInteger>> gePrime = Map.of(
                "c", List.of(BigInteger.ZERO),
                "a", List.of(p),
                "b", List.of(BigInteger.ONE));
        assertThrows(IllegalArgumentException.class, () -> WitnessCalculator.calculate(graph, gePrime, bls));
        assertThrows(IllegalArgumentException.class, () -> WitnessCalculator.calculateFlat(graph, gePrime, bls));
    }

    @Test
    void curveGenericVerifyWitnessValidatesBothCurvesAndRejectsMalformedWitnesses() {
        var circuit = CircuitBuilder.create("mul-generic")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));

        for (CurveId curve : List.of(CurveId.BLS12_381, CurveId.BN254)) {
            R1CSConstraintSystem r1cs = circuit.compileR1CS(curve);
            BigInteger p = r1cs.prime();
            BigInteger a = p.subtract(BigInteger.TWO);
            BigInteger b = BigInteger.valueOf(3);
            BigInteger c = a.multiply(b).mod(p);

            BigInteger[] witness = circuit.calculateWitness(Map.of(
                    "c", List.of(c), "a", List.of(a), "b", List.of(b)), curve);
            assertDoesNotThrow(() -> r1cs.verifyWitness(witness));
            assertDoesNotThrow(() -> R1CSConstraintSystem.verifyWitness(
                    r1cs.constraints(), witness, r1cs.fieldConfig()));

            // Wrong length
            BigInteger[] shortW = Arrays.copyOf(witness, witness.length - 1);
            assertThrows(IllegalArgumentException.class, () -> r1cs.verifyWitness(shortW));

            // witness[0] != 1
            BigInteger[] badWire0 = witness.clone();
            badWire0[0] = BigInteger.TWO;
            assertThrows(IllegalArgumentException.class, () -> r1cs.verifyWitness(badWire0));

            // Non-canonical entry >= p
            BigInteger[] geP = witness.clone();
            geP[1] = p;
            assertThrows(IllegalArgumentException.class, () -> r1cs.verifyWitness(geP));

            // Negative entry
            BigInteger[] negW = witness.clone();
            negW[1] = BigInteger.ONE.negate();
            assertThrows(IllegalArgumentException.class, () -> r1cs.verifyWitness(negW));

            // Null entry
            BigInteger[] nullW = witness.clone();
            nullW[1] = null;
            assertThrows(IllegalArgumentException.class, () -> r1cs.verifyWitness(nullW));

            // Violated constraint
            BigInteger[] badC = witness.clone();
            badC[1] = c.add(BigInteger.ONE).mod(p);
            assertThrows(IllegalArgumentException.class, () -> r1cs.verifyWitness(badC));

            // Out-of-bounds wire reference in explicit constraint list
            R1CSConstraint oobConstraint = new R1CSConstraint(Map.of(99, BigInteger.ONE), Map.of(0, BigInteger.ONE), Map.of());
            assertThrows(IllegalArgumentException.class, () -> R1CSConstraintSystem.verifyWitness(
                    List.of(oobConstraint), witness, r1cs.fieldConfig()));
        }
    }
}
