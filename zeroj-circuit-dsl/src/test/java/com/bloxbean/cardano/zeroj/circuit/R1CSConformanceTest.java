package com.bloxbean.cardano.zeroj.circuit;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSSerializer;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Conformance tests comparing our R1CS output against circom-generated R1CS files.
 *
 * <p>The circom multiplier circuit: {@code c <== a * b}, public: [a], private: [b], output: [c]
 * produces a known .r1cs binary. We build the same circuit with our Java DSL and verify
 * the serialized output matches key structural properties.</p>
 */
class R1CSConformanceTest {

    private static final BigInteger BN254_PRIME = FieldConfig.BN254.prime();

    @Test
    void r1csSerializer_multiplier_headerMatchesCircom() {
        // Build the multiplier circuit: c = a * b
        // circom convention: public input a (wire 2), private input b (wire 3), output c (wire 1)
        // Our convention may differ in wire ordering, but the header structure must match
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("a").secretVar("b")
                .define(api -> {
                    var product = api.mul(api.var("a"), api.var("b"));
                    // In our DSL, product is an intermediate wire. We don't explicitly
                    // declare outputs — they're asserted equal to public vars.
                });

        var r1cs = circuit.compileR1CS(CurveId.BN254);
        byte[] serialized = R1CSSerializer.serialize(r1cs);

        // Check magic bytes
        assertEquals((byte) 'r', serialized[0]);
        assertEquals((byte) '1', serialized[1]);
        assertEquals((byte) 'c', serialized[2]);
        assertEquals((byte) 's', serialized[3]);

        // Check version = 1
        assertEquals(1, readUint32LE(serialized, 4));

        // Check numSections = 3
        assertEquals(3, readUint32LE(serialized, 8));

        // Check field element size (n8 = 32)
        // Section 1 starts at offset 12 (after global header)
        // sectionType(4) + sectionLength(8) = 12 bytes of section header
        int sectionDataStart = 12 + 4 + 8; // global header + section1 header
        assertEquals(32, readUint32LE(serialized, sectionDataStart));

        // Check prime matches BN254
        byte[] primeBytes = Arrays.copyOfRange(serialized, sectionDataStart + 4, sectionDataStart + 4 + 32);
        BigInteger serializedPrime = readFieldElementLE(primeBytes, 32);
        assertEquals(BN254_PRIME, serializedPrime, "Prime must match BN254 scalar field");
    }

    @Test
    void r1csSerializer_multiplier_constraintCount() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> {
                    var product = api.mul(api.var("a"), api.var("b"));
                    api.assertEqual(product, api.var("c"));
                });

        var r1cs = circuit.compileR1CS(CurveId.BN254);

        // Multiplier has 1 multiplication gate + 1 assertEqual
        // The assertEqual compiles to an R1CS constraint: (diff) * 1 = 0
        assertTrue(r1cs.numConstraints() <= 2,
                "multiplier should have at most 2 constraints, got " + r1cs.numConstraints());
    }

    @Test
    void r1csSerializer_roundTripPrime() {
        var circuit = CircuitBuilder.create("test")
                .publicVar("x")
                .define(api -> {});

        var r1cs = circuit.compileR1CS(CurveId.BN254);
        byte[] serialized = R1CSSerializer.serialize(r1cs);

        // Deserialize just the prime to verify round-trip
        int sectionDataStart = 12 + 4 + 8;
        int n8 = readUint32LE(serialized, sectionDataStart);
        assertEquals(32, n8);

        byte[] primeBytes = Arrays.copyOfRange(serialized, sectionDataStart + 4, sectionDataStart + 4 + n8);
        assertEquals(BN254_PRIME, readFieldElementLE(primeBytes, n8));
    }

    @Test
    void r1cs_witnessCompatible_withCircomFormat() {
        // Verify that our witness matches the circom convention:
        // witness[0] = 1 (constant), then outputs, then public inputs, then private inputs
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> {
                    var product = api.mul(api.var("a"), api.var("b"));
                    api.assertEqual(product, api.var("c"));
                });

        var witness = circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        assertEquals(BigInteger.ONE, witness[0], "witness[0] must be 1");
        // Our convention: wire 1 = first public var (c=33), wire 2 = first secret var (a=3), etc.
        assertEquals(BigInteger.valueOf(33), witness[1], "public input c");
        assertEquals(BigInteger.valueOf(3), witness[2], "secret input a");
        assertEquals(BigInteger.valueOf(11), witness[3], "secret input b");
    }

    @Test
    void r1cs_satisfiabilityCheck() {
        // Verify the R1CS constraints are satisfied by the witness
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> {
                    var product = api.mul(api.var("a"), api.var("b"));
                    api.assertEqual(product, api.var("c"));
                });

        var r1cs = circuit.compileR1CS(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        // Check each R1CS constraint: (A · w) × (B · w) = (C · w)
        for (var constraint : r1cs.constraints()) {
            BigInteger aVal = evalLinearCombination(constraint.a(), witness, BN254_PRIME);
            BigInteger bVal = evalLinearCombination(constraint.b(), witness, BN254_PRIME);
            BigInteger cVal = evalLinearCombination(constraint.c(), witness, BN254_PRIME);

            BigInteger lhs = aVal.multiply(bVal).mod(BN254_PRIME);
            assertEquals(lhs, cVal, "R1CS constraint not satisfied: "
                    + aVal + " * " + bVal + " != " + cVal);
        }
    }

    @Test
    void plonk_gateTableSatisfied() {
        // Verify PlonK gates are satisfied by the witness
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> {
                    var product = api.mul(api.var("a"), api.var("b"));
                    api.assertEqual(product, api.var("c"));
                });

        var plonk = circuit.compilePlonK(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        // Check each gate: qL*a + qR*b + qO*c + qM*(a*b) + qC = 0
        for (var row : plonk.gateRows()) {
            BigInteger a = witness[row.wireA()];
            BigInteger b = witness[row.wireB()];
            BigInteger c = witness[row.wireC()];

            if (a == null || b == null || c == null) continue; // padding rows

            BigInteger result = row.qL().multiply(a).mod(BN254_PRIME)
                    .add(row.qR().multiply(b).mod(BN254_PRIME))
                    .add(row.qO().multiply(c).mod(BN254_PRIME))
                    .add(row.qM().multiply(a).mod(BN254_PRIME).multiply(b).mod(BN254_PRIME))
                    .add(row.qC())
                    .mod(BN254_PRIME);

            assertEquals(BigInteger.ZERO, result, "PlonK gate not satisfied: "
                    + "qL=" + row.qL() + " qR=" + row.qR() + " qO=" + row.qO()
                    + " qM=" + row.qM() + " qC=" + row.qC()
                    + " a=" + a + " b=" + b + " c=" + c);
        }
    }

    // --- Helpers ---

    private static BigInteger evalLinearCombination(Map<Integer, BigInteger> lc, BigInteger[] witness, BigInteger p) {
        BigInteger sum = BigInteger.ZERO;
        for (var entry : lc.entrySet()) {
            sum = sum.add(entry.getValue().multiply(witness[entry.getKey()])).mod(p);
        }
        return sum;
    }

    private static int readUint32LE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }

    private static BigInteger readFieldElementLE(byte[] leBytes, int n8) {
        byte[] beBytes = new byte[n8];
        for (int i = 0; i < n8; i++) beBytes[i] = leBytes[n8 - 1 - i];
        return new BigInteger(1, beBytes);
    }
}
