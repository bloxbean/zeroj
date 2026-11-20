package org.zeroj.circuit.annotation;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ADR-0068: ZkUInt.sub 252-bit cap & ZkInputMap canonical/range validation. */
class ZkUIntSubAndInputMapHardeningTest {

    @Test
    void zkUIntSubRejects253BitOperands() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("sub-253")
                .secretVar("a").secretVar("b")
                .defineSignals(c -> {
                    var a = ZkUInt.secret(c, "a", 253);
                    var b = ZkUInt.secret(c, "b", 253);
                    a.sub(b);
                }));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("sub-253-mixed-left")
                .secretVar("a").secretVar("b")
                .defineSignals(c -> {
                    var a = ZkUInt.secret(c, "a", 253);
                    var b = ZkUInt.secret(c, "b", 8);
                    a.sub(b);
                }));

        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("sub-253-mixed-right")
                .secretVar("a").secretVar("b")
                .defineSignals(c -> {
                    var a = ZkUInt.secret(c, "a", 8);
                    var b = ZkUInt.secret(c, "b", 253);
                    a.sub(b);
                }));
    }

    @Test
    void zkUIntSubAt252BitsAcceptsValidAndRejectsUnderflowOnBn254AndBls12381() {
        CircuitBuilder circuit = CircuitBuilder.create("sub-252")
                .publicVar("diff")
                .secretVar("a")
                .secretVar("b")
                .defineSignals(c -> {
                    var a = ZkUInt.secret(c, "a", 252);
                    var b = ZkUInt.secret(c, "b", 252);
                    var diff = ZkUInt.publicInput(c, "diff", 252);
                    a.sub(b).assertEqual(diff);
                });

        BigInteger max252 = BigInteger.ONE.shiftLeft(252).subtract(BigInteger.ONE);

        for (CurveId curve : List.of(CurveId.BN254, CurveId.BLS12_381)) {
            R1CSConstraintSystem r1cs = circuit.compileR1CS(curve);

            // Valid boundary cases: max252 - 0 = max252, max252 - max252 = 0
            BigInteger[] w1 = circuit.calculateWitness(Map.of(
                    "a", List.of(max252),
                    "b", List.of(BigInteger.ZERO),
                    "diff", List.of(max252)), curve);
            assertDoesNotThrow(() -> r1cs.verifyWitness(w1));

            BigInteger[] w2 = circuit.calculateWitness(Map.of(
                    "a", List.of(max252),
                    "b", List.of(max252),
                    "diff", List.of(BigInteger.ZERO)), curve);
            assertDoesNotThrow(() -> r1cs.verifyWitness(w2));

            // Underflow cases: 0 - 1 and 0 - (2^252 - 1) must fail (p - (2^252 - 1) >= 2^252)
            BigInteger p = FieldConfig.forCurve(curve).prime();
            BigInteger wrapped = p.subtract(max252);
            assertTrue(wrapped.bitLength() > 252,
                    "2^253 <= p must hold so underflow wraps above 2^252 on " + curve);

            assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                    "a", List.of(BigInteger.ZERO),
                    "b", List.of(BigInteger.ONE),
                    "diff", List.of(BigInteger.ZERO)), curve));

            assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                    "a", List.of(BigInteger.ZERO),
                    "b", List.of(max252),
                    "diff", List.of(BigInteger.ZERO)), curve));
        }
    }

    @Test
    void zkInputMapRejectsNegativeOutOfTypeUnknownAndNonCanonicalInputs() {
        var schema = ZkCircuitSchema.of(
                "typed-inputs",
                List.of(),
                List.of(
                        ZkCircuitSchema.Input.scalar("f", ZkCircuitSchema.Visibility.PUBLIC,
                                ZkCircuitSchema.Kind.FIELD, -1),
                        ZkCircuitSchema.Input.scalar("flag", ZkCircuitSchema.Visibility.PUBLIC,
                                ZkCircuitSchema.Kind.BOOL, 1)),
                List.of(
                        ZkCircuitSchema.Input.scalar("amt", ZkCircuitSchema.Visibility.SECRET,
                                ZkCircuitSchema.Kind.UINT, 8),
                        ZkCircuitSchema.Input.array("data", ZkCircuitSchema.Visibility.SECRET,
                                ZkCircuitSchema.Kind.BYTES, 8, 2),
                        ZkCircuitSchema.Input.array("bits", ZkCircuitSchema.Visibility.SECRET,
                                ZkCircuitSchema.Kind.BITS, 1, 2)));

        // Direct put rejects negative values
        assertThrows(IllegalArgumentException.class, () -> new ZkInputMap().put("f", -1));

        // Checked puts enforce type bounds
        assertThrows(IllegalArgumentException.class, () -> new ZkInputMap()
                .putChecked(schema.input("flag"), "flag", BigInteger.TWO));
        assertThrows(IllegalArgumentException.class, () -> new ZkInputMap()
                .putChecked(schema.input("amt"), "amt", BigInteger.valueOf(256)));
        assertThrows(IllegalArgumentException.class, () -> new ZkInputMap()
                .putArrayChecked(schema.input("data"), List.of(BigInteger.ZERO, BigInteger.valueOf(256))));
        assertThrows(IllegalArgumentException.class, () -> new ZkInputMap()
                .putArrayChecked(schema.input("bits"), List.of(BigInteger.ZERO, BigInteger.TWO)));

        // Valid inputs pass validate on both curves
        var valid = new ZkInputMap()
                .putChecked(schema.input("f"), "f", BigInteger.valueOf(42))
                .putChecked(schema.input("flag"), "flag", BigInteger.ONE)
                .putChecked(schema.input("amt"), "amt", BigInteger.valueOf(255))
                .putArrayChecked(schema.input("data"), List.of(BigInteger.ZERO, BigInteger.valueOf(255)))
                .putArrayChecked(schema.input("bits"), List.of(BigInteger.ONE, BigInteger.ZERO));
        assertDoesNotThrow(() -> valid.validate(schema, CurveId.BLS12_381));
        assertDoesNotThrow(() -> valid.validate(schema, CurveId.BN254));
        assertEquals(List.of(BigInteger.valueOf(42), BigInteger.ONE), valid.publicValues(schema));

        // Unknown key rejected by validate
        valid.put("extra", 1);
        assertThrows(IllegalArgumentException.class, () -> valid.validate(schema, CurveId.BLS12_381));

        // Non-canonical field value (>= p) rejected by validate
        var nonCanonical = new ZkInputMap()
                .put("f", FieldConfig.BLS12_381.prime())
                .put("flag", 1)
                .put("amt", 1)
                .putArray("data", List.of(BigInteger.ZERO, BigInteger.ONE))
                .putArray("bits", List.of(BigInteger.ZERO, BigInteger.ONE));
        assertThrows(IllegalArgumentException.class, () -> nonCanonical.validate(schema, CurveId.BLS12_381));
    }
}
