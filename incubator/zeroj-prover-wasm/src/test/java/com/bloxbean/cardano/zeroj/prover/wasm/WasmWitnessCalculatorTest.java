package com.bloxbean.cardano.zeroj.prover.wasm;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the GraalWasm-based circom witness calculator.
 * Uses the multiplier circuit: a * b = c, public inputs: [c, a], private: b.
 */
class WasmWitnessCalculatorTest {

    /** BN254 scalar field order. */
    private static final BigInteger BN254_R = new BigInteger(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617");

    private byte[] loadWasm() {
        try (var in = getClass().getResourceAsStream("/test-vectors/circom-wasm-bn254/multiplier.wasm")) {
            if (in == null) fail("multiplier.wasm not found in test resources");
            return in.readAllBytes();
        } catch (Exception e) {
            return fail("Failed to load WASM: " + e.getMessage());
        }
    }

    @Test
    void fnvHash_knownValues() {
        // Test the FNV-1a hash implementation against known values
        // The hash of "a" and "b" must be deterministic
        long hashA = WasmWitnessCalculator.fnvHash("a");
        long hashB = WasmWitnessCalculator.fnvHash("b");
        assertNotEquals(hashA, hashB, "different signal names must have different hashes");
        // FNV-1a of "a": hash = 0xCBF29CE484222325 ^ 0x61 * 0x100000001B3
        // Verify it's deterministic
        assertEquals(hashA, WasmWitnessCalculator.fnvHash("a"));
    }

    @Test
    void bigIntToLimbs_roundTrip() {
        BigInteger value = BigInteger.valueOf(33);
        int[] limbs = WasmWitnessCalculator.bigIntToLimbs(value, 8);
        assertEquals(8, limbs.length);
        assertEquals(33, limbs[7]); // LSB
        assertEquals(0, limbs[0]);  // MSB

        BigInteger recovered = WasmWitnessCalculator.limbsToBigInt(limbs);
        assertEquals(value, recovered);
    }

    @Test
    void bigIntToLimbs_largeValue() {
        BigInteger value = BN254_R.subtract(BigInteger.ONE);
        int[] limbs = WasmWitnessCalculator.bigIntToLimbs(value, 8);
        BigInteger recovered = WasmWitnessCalculator.limbsToBigInt(limbs);
        assertEquals(value, recovered);
    }

    @Test
    void calculateWitness_multiplier3x11() {
        try (var calc = new WasmWitnessCalculator(loadWasm())) {
            // Circuit: a * b = c, inputs: a=3, b=11
            var inputs = Map.of(
                    "a", List.of(BigInteger.valueOf(3)),
                    "b", List.of(BigInteger.valueOf(11)));

            BigInteger[] witness = calc.calculateWitness(inputs);

            assertNotNull(witness);
            assertTrue(witness.length >= 4, "multiplier witness should have at least 4 elements");

            // witness[0] = 1 (constant signal, always 1)
            assertEquals(BigInteger.ONE, witness[0], "witness[0] must be 1");

            // The witness should contain the output c=33 and inputs a=3, b=11
            // Order: [1, c, a, b] = [1, 33, 3, 11]
            assertEquals(BigInteger.valueOf(33), witness[1], "output c must be 33");
            assertEquals(BigInteger.valueOf(3), witness[2], "input a must be 3");
            assertEquals(BigInteger.valueOf(11), witness[3], "input b must be 11");
        }
    }

    @Test
    void calculateWitness_differentInputs() {
        try (var calc = new WasmWitnessCalculator(loadWasm())) {
            var inputs = Map.of(
                    "a", List.of(BigInteger.valueOf(7)),
                    "b", List.of(BigInteger.valueOf(13)));

            BigInteger[] witness = calc.calculateWitness(inputs);

            assertEquals(BigInteger.ONE, witness[0]);
            assertEquals(BigInteger.valueOf(91), witness[1], "7 * 13 = 91");
            assertEquals(BigInteger.valueOf(7), witness[2]);
            assertEquals(BigInteger.valueOf(13), witness[3]);
        }
    }

    @Test
    void calculateWitness_largeValues() {
        try (var calc = new WasmWitnessCalculator(loadWasm())) {
            BigInteger a = new BigInteger("123456789012345678901234567890");
            BigInteger b = new BigInteger("987654321098765432109876543210");
            BigInteger expectedC = a.multiply(b).mod(BN254_R);

            var inputs = Map.of(
                    "a", List.of(a),
                    "b", List.of(b));

            BigInteger[] witness = calc.calculateWitness(inputs);

            assertEquals(BigInteger.ONE, witness[0]);
            assertEquals(expectedC, witness[1], "large multiplication should work in field");
        }
    }

    @Test
    void getPrime_isBN254() {
        try (var calc = new WasmWitnessCalculator(loadWasm())) {
            assertEquals(BN254_R, calc.getPrime(), "circom BN254 circuit should use BN254 prime");
        }
    }

    @Test
    void getWitnessSize_multiplier() {
        try (var calc = new WasmWitnessCalculator(loadWasm())) {
            assertEquals(4, calc.getWitnessSize(), "multiplier circuit has 4 witness elements");
        }
    }

    @Test
    void calculateWtns_producesValidBinary() {
        try (var calc = new WasmWitnessCalculator(loadWasm())) {
            var inputs = Map.of(
                    "a", List.of(BigInteger.valueOf(3)),
                    "b", List.of(BigInteger.valueOf(11)));

            byte[] wtns = calc.calculateWtns(inputs);

            // Check .wtns header
            assertEquals(0x77, wtns[0] & 0xFF); // 'w'
            assertEquals(0x74, wtns[1] & 0xFF); // 't'
            assertEquals(0x6e, wtns[2] & 0xFF); // 'n'
            assertEquals(0x73, wtns[3] & 0xFF); // 's'
            assertEquals(2, wtns[4] & 0xFF);    // version = 2

            // The file should have reasonable size: header + metadata + 4 witness * 32 bytes
            assertTrue(wtns.length > 100, "wtns should have reasonable size");
        }
    }
}
