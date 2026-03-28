package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the Signal-based stdlib — all using the OO (Signal chaining) style.
 */
class SignalStyleTest {

    // ========================================================================
    // Comparators
    // ========================================================================

    @Test
    void comparators_lessThan() {
        var circuit = CircuitBuilder.create("lt")
                .publicVar("result").secretVar("a").secretVar("b")
                .defineSignals(c -> {
                    Signal a = c.privateInput("a");
                    Signal b = c.privateInput("b");
                    Signal result = c.publicOutput("result");
                    c.assertEqual(SignalComparators.lessThan(c, a, b, 8), result);
                });

        // 3 < 11 → 1
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254));

        // 11 < 3 → 0
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ZERO),
                "a", List.of(BigInteger.valueOf(11)),
                "b", List.of(BigInteger.valueOf(3))), CurveId.BN254));

        // 5 < 5 → 0 (strict)
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ZERO),
                "a", List.of(BigInteger.valueOf(5)),
                "b", List.of(BigInteger.valueOf(5))), CurveId.BN254));
    }

    @Test
    void comparators_greaterOrEqual() {
        var circuit = CircuitBuilder.create("gte")
                .publicVar("result").secretVar("age").secretVar("threshold")
                .defineSignals(c -> {
                    Signal age = c.privateInput("age");
                    Signal threshold = c.privateInput("threshold");
                    c.assertEqual(SignalComparators.greaterOrEqual(c, age, threshold, 8),
                            c.publicOutput("result"));
                });

        // 25 >= 18 → 1
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ONE),
                "age", List.of(BigInteger.valueOf(25)),
                "threshold", List.of(BigInteger.valueOf(18))), CurveId.BN254));

        // 15 >= 18 → 0
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ZERO),
                "age", List.of(BigInteger.valueOf(15)),
                "threshold", List.of(BigInteger.valueOf(18))), CurveId.BN254));
    }

    @Test
    void comparators_inRange() {
        var circuit = CircuitBuilder.create("range")
                .publicVar("ok").secretVar("val").secretVar("lo").secretVar("hi")
                .defineSignals(c -> {
                    Signal val = c.privateInput("val");
                    Signal lo = c.privateInput("lo");
                    Signal hi = c.privateInput("hi");
                    c.assertEqual(SignalComparators.inRange(c, val, lo, hi, 16),
                            c.publicOutput("ok"));
                });

        // 500 in [100, 1000] → 1
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "ok", List.of(BigInteger.ONE),
                "val", List.of(BigInteger.valueOf(500)),
                "lo", List.of(BigInteger.valueOf(100)),
                "hi", List.of(BigInteger.valueOf(1000))), CurveId.BN254));
    }

    @Test
    void comparators_minMax() {
        var circuit = CircuitBuilder.create("minmax")
                .publicVar("minVal").publicVar("maxVal").secretVar("a").secretVar("b")
                .defineSignals(c -> {
                    Signal a = c.privateInput("a");
                    Signal b = c.privateInput("b");
                    c.assertEqual(SignalComparators.min(c, a, b, 8), c.publicOutput("minVal"));
                    c.assertEqual(SignalComparators.max(c, a, b, 8), c.publicOutput("maxVal"));
                });

        // min(3,11)=3, max(3,11)=11
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "minVal", List.of(BigInteger.valueOf(3)),
                "maxVal", List.of(BigInteger.valueOf(11)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254));
    }

    // ========================================================================
    // MiMC hash
    // ========================================================================

    @Test
    void mimc_signalStyle_deterministic() {
        var circuit = CircuitBuilder.create("mimc")
                .secretVar("left").secretVar("right")
                .defineSignals(c -> SignalMiMC.hash(c, c.privateInput("left"), c.privateInput("right")));

        var w1 = circuit.calculateWitness(Map.of(
                "left", List.of(BigInteger.valueOf(3)),
                "right", List.of(BigInteger.valueOf(11))), CurveId.BN254);
        var w2 = circuit.calculateWitness(Map.of(
                "left", List.of(BigInteger.valueOf(3)),
                "right", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        assertArrayEquals(w1, w2, "MiMC must be deterministic");
    }

    @Test
    void mimc_signalStyle_differentInputs() {
        var circuit = CircuitBuilder.create("mimc")
                .secretVar("left").secretVar("right")
                .defineSignals(c -> SignalMiMC.hash(c, c.privateInput("left"), c.privateInput("right")));

        var w1 = circuit.calculateWitness(Map.of(
                "left", List.of(BigInteger.ONE),
                "right", List.of(BigInteger.TWO)), CurveId.BN254);
        var w2 = circuit.calculateWitness(Map.of(
                "left", List.of(BigInteger.valueOf(3)),
                "right", List.of(BigInteger.valueOf(4))), CurveId.BN254);

        assertFalse(java.util.Arrays.equals(w1, w2));
    }

    // ========================================================================
    // Merkle proof
    // ========================================================================

    @Test
    void merkle_signalStyle_computeRoot() {
        var circuit = CircuitBuilder.create("merkle")
                .secretVar("leaf").secretVar("sib0").secretVar("sib1")
                .secretVar("path0").secretVar("path1")
                .defineSignals(c -> {
                    Signal leaf = c.privateInput("leaf");
                    Signal[] siblings = {c.privateInput("sib0"), c.privateInput("sib1")};
                    Signal[] pathBits = {c.privateInput("path0"), c.privateInput("path1")};
                    SignalMerkle.computeRoot(c, leaf, siblings, pathBits, SignalMiMC::hash);
                });

        var witness = circuit.calculateWitness(Map.of(
                "leaf", List.of(BigInteger.TEN),
                "sib0", List.of(BigInteger.valueOf(20)),
                "sib1", List.of(BigInteger.valueOf(30)),
                "path0", List.of(BigInteger.ZERO),
                "path1", List.of(BigInteger.ZERO)), CurveId.BN254);

        assertNotNull(witness);
        assertEquals(BigInteger.ONE, witness[0]);
    }

    // ========================================================================
    // Binary
    // ========================================================================

    @Test
    void binary_signalStyle_roundTrip() {
        var circuit = CircuitBuilder.create("bits")
                .publicVar("value")
                .defineSignals(c -> {
                    Signal v = c.publicInput("value");
                    Signal[] bits = SignalBinary.num2Bits(c, v, 8);
                    Signal reconstructed = SignalBinary.bits2Num(c, bits);
                    c.assertEqual(reconstructed, v);
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "value", List.of(BigInteger.valueOf(170))), CurveId.BN254));
    }

    @Test
    void binary_signalStyle_bitwiseXor() {
        var circuit = CircuitBuilder.create("xor")
                .secretVar("a").secretVar("b")
                .defineSignals(c -> {
                    Signal a = c.privateInput("a");
                    Signal b = c.privateInput("b");
                    Signal[] bitsA = SignalBinary.num2Bits(c, a, 8);
                    Signal[] bitsB = SignalBinary.num2Bits(c, b, 8);
                    SignalBinary.bitXor(bitsA, bitsB); // just compute, don't assert
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.valueOf(0b10101010)),
                "b", List.of(BigInteger.valueOf(0b11001100))), CurveId.BN254));
    }

    // ========================================================================
    // Real-world circuits using Signal API
    // ========================================================================

    /** Age verification: prove age >= threshold without revealing age. */
    static class AgeVerificationCircuit implements CircuitSpec {
        @Override
        public void define(SignalBuilder c) {
            Signal age = c.privateInput("age");
            Signal threshold = c.publicInput("threshold");
            Signal result = c.publicOutput("result");
            c.assertEqual(SignalComparators.greaterOrEqual(c, age, threshold, 8), result);
        }
    }

    @Test
    void realWorld_ageVerification() {
        var circuit = CircuitBuilder.create("age-check")
                .publicVar("threshold").publicVar("result").secretVar("age")
                .defineSignals(new AgeVerificationCircuit());

        // 25 >= 18 → 1
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "threshold", List.of(BigInteger.valueOf(18)),
                "result", List.of(BigInteger.ONE),
                "age", List.of(BigInteger.valueOf(25))), CurveId.BN254));

        // False claim: 15 >= 18 but says result=1 → constraint violation
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "threshold", List.of(BigInteger.valueOf(18)),
                "result", List.of(BigInteger.ONE),
                "age", List.of(BigInteger.valueOf(15))), CurveId.BN254));
    }

    /** Voting: boolean vote + hash commitment. */
    static class VotingCircuit implements CircuitSpec {
        @Override
        public void define(SignalBuilder c) {
            Signal vote = c.privateInput("vote");
            Signal nullifier = c.privateInput("nullifier");
            Signal commitment = c.publicOutput("commitment");

            vote.assertBoolean();
            c.assertEqual(SignalMiMC.hash(c, vote, nullifier), commitment);
        }
    }

    @Test
    void realWorld_voting() {
        var circuit = CircuitBuilder.create("vote")
                .publicVar("commitment").secretVar("vote").secretVar("nullifier")
                .defineSignals(new VotingCircuit());

        // Compiles to all 3 backends
        assertNotNull(circuit.compileR1CS(CurveId.BN254));
        assertNotNull(circuit.compilePlonK(CurveId.BN254));
        assertNotNull(circuit.compileHalo2(CurveId.BN254));
    }

    /** Private balance transfer with range proof. */
    static class TransferCircuit implements CircuitSpec {
        @Override
        public void define(SignalBuilder c) {
            Signal senderBalance = c.privateInput("senderBalance");
            Signal amount = c.privateInput("amount");
            Signal newBalance = c.privateInput("newBalance");
            Signal amountPublic = c.publicOutput("amountPublic");

            // newBalance = senderBalance - amount
            c.assertEqual(senderBalance.sub(amount), newBalance);

            // amount must be positive (fits in 64 bits)
            amount.assertInRange(64);

            // newBalance must be non-negative (fits in 64 bits)
            newBalance.assertInRange(64);

            // Public output: the transfer amount
            c.assertEqual(amount, amountPublic);
        }
    }

    @Test
    void realWorld_privateTransfer() {
        var circuit = CircuitBuilder.create("transfer")
                .publicVar("amountPublic")
                .secretVar("senderBalance").secretVar("amount").secretVar("newBalance")
                .defineSignals(new TransferCircuit());

        // Valid: 100 - 30 = 70
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "amountPublic", List.of(BigInteger.valueOf(30)),
                "senderBalance", List.of(BigInteger.valueOf(100)),
                "amount", List.of(BigInteger.valueOf(30)),
                "newBalance", List.of(BigInteger.valueOf(70))), CurveId.BN254));

        // Invalid: 100 - 30 ≠ 50
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "amountPublic", List.of(BigInteger.valueOf(30)),
                "senderBalance", List.of(BigInteger.valueOf(100)),
                "amount", List.of(BigInteger.valueOf(30)),
                "newBalance", List.of(BigInteger.valueOf(50))), CurveId.BN254));
    }
}
