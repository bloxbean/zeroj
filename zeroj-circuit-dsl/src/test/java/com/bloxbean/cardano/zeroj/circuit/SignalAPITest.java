package com.bloxbean.cardano.zeroj.circuit;

import com.bloxbean.cardano.zeroj.api.CurveId;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the Signal-based (OO) circuit API.
 * Each test shows both API styles producing the same result.
 */
class SignalAPITest {

    // ========================================================================
    // Example circuit: multiplier as a CircuitSpec class
    // ========================================================================

    static class MulCircuit implements CircuitSpec {
        @Override
        public void define(SignalBuilder c) {
            Signal a = c.privateInput("a");
            Signal b = c.privateInput("b");
            Signal out = c.publicOutput("out");
            c.assertEqual(a.mul(b), out);
        }
    }

    @Test
    void mulCircuit_specStyle() {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("out").secretVar("a").secretVar("b")
                .defineSignals(new MulCircuit());

        var witness = circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        assertEquals(BigInteger.ONE, witness[0]);
        assertEquals(BigInteger.valueOf(33), witness[1]);
    }

    @Test
    void mulCircuit_lambdaStyle_sameResult() {
        // Same circuit, functional API
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("out")));

        var witness = circuit.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        assertEquals(BigInteger.valueOf(33), witness[1]);
    }

    // ========================================================================
    // Signal arithmetic
    // ========================================================================

    @Test
    void signal_chainedArithmetic() {
        // d = (a + b) * c using Signal chaining
        var circuit = CircuitBuilder.create("chain")
                .publicVar("d").secretVar("a").secretVar("b").secretVar("c")
                .defineSignals(cb -> {
                    Signal a = cb.privateInput("a");
                    Signal b = cb.privateInput("b");
                    Signal c = cb.privateInput("c");
                    Signal d = cb.publicOutput("d");
                    cb.assertEqual(a.add(b).mul(c), d);
                });

        // (3 + 11) * 2 = 28
        var witness = circuit.calculateWitness(Map.of(
                "d", List.of(BigInteger.valueOf(28)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11)),
                "c", List.of(BigInteger.TWO)), CurveId.BN254);

        assertEquals(BigInteger.valueOf(28), witness[1]);
    }

    @Test
    void signal_divAndNeg() {
        // out = -a / b
        var circuit = CircuitBuilder.create("divneg")
                .publicVar("out").secretVar("a").secretVar("b")
                .defineSignals(cb -> {
                    Signal a = cb.privateInput("a");
                    Signal b = cb.privateInput("b");
                    Signal out = cb.publicOutput("out");
                    cb.assertEqual(a.neg().div(b), out);
                });

        // -33 / 3 = -11 mod p
        BigInteger p = FieldConfig.BN254.prime();
        BigInteger expected = p.subtract(BigInteger.valueOf(11)); // -11 mod p

        var witness = circuit.calculateWitness(Map.of(
                "out", List.of(expected),
                "a", List.of(BigInteger.valueOf(33)),
                "b", List.of(BigInteger.valueOf(3))), CurveId.BN254);

        assertEquals(expected, witness[1]);
    }

    // ========================================================================
    // Signal comparison and selection
    // ========================================================================

    @Test
    void signal_selectAndIsZero() {
        var circuit = CircuitBuilder.create("sel")
                .publicVar("result").secretVar("flag").secretVar("a").secretVar("b")
                .defineSignals(cb -> {
                    Signal flag = cb.privateInput("flag");
                    Signal a = cb.privateInput("a");
                    Signal b = cb.privateInput("b");
                    Signal result = cb.publicOutput("result");
                    // if flag==1 → a, else → b
                    cb.assertEqual(flag.select(a, b), result);
                });

        // flag=1 → select a=10
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.TEN),
                "flag", List.of(BigInteger.ONE),
                "a", List.of(BigInteger.TEN),
                "b", List.of(BigInteger.valueOf(20))), CurveId.BN254));

        // flag=0 → select b=20
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.valueOf(20)),
                "flag", List.of(BigInteger.ZERO),
                "a", List.of(BigInteger.TEN),
                "b", List.of(BigInteger.valueOf(20))), CurveId.BN254));
    }

    @Test
    void signal_isZero() {
        var circuit = CircuitBuilder.create("iszero")
                .publicVar("result").secretVar("x")
                .defineSignals(cb -> {
                    Signal x = cb.privateInput("x");
                    Signal result = cb.publicOutput("result");
                    cb.assertEqual(x.isZero(), result);
                });

        // x=0 → result=1
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ONE),
                "x", List.of(BigInteger.ZERO)), CurveId.BN254));

        // x=42 → result=0
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "result", List.of(BigInteger.ZERO),
                "x", List.of(BigInteger.valueOf(42))), CurveId.BN254));
    }

    // ========================================================================
    // Signal binary ops
    // ========================================================================

    @Test
    void signal_toBinaryAndAssert() {
        var circuit = CircuitBuilder.create("bits")
                .secretVar("x")
                .defineSignals(cb -> {
                    Signal x = cb.privateInput("x");
                    x.assertInRange(8); // prove x fits in 8 bits
                });

        // 170 fits in 8 bits
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "x", List.of(BigInteger.valueOf(170))), CurveId.BN254));
    }

    // ========================================================================
    // Compile to all 3 backends
    // ========================================================================

    @Test
    void signal_compilesToAllBackends() {
        var circuit = CircuitBuilder.create("mul")
                .publicVar("out").secretVar("a").secretVar("b")
                .defineSignals(new MulCircuit());

        assertNotNull(circuit.compileR1CS(CurveId.BN254));
        assertNotNull(circuit.compilePlonK(CurveId.BN254));
        assertNotNull(circuit.compileHalo2(CurveId.BN254));
    }

    // ========================================================================
    // Real-world: voting circuit with Signal API
    // ========================================================================

    static class VoteCircuit implements CircuitSpec {
        @Override
        public void define(SignalBuilder c) {
            Signal vote = c.privateInput("vote");
            Signal nullifier = c.privateInput("nullifier");
            Signal commitment = c.publicOutput("commitment");

            // Vote must be 0 or 1
            vote.assertBoolean();

            // commitment = vote * nullifier (simplified hash for demo)
            c.assertEqual(vote.mul(nullifier), commitment);
        }
    }

    @Test
    void voteCircuit() {
        var circuit = CircuitBuilder.create("vote")
                .publicVar("commitment").secretVar("vote").secretVar("nullifier")
                .defineSignals(new VoteCircuit());

        // vote=1, nullifier=42 → commitment=42
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "commitment", List.of(BigInteger.valueOf(42)),
                "vote", List.of(BigInteger.ONE),
                "nullifier", List.of(BigInteger.valueOf(42))), CurveId.BN254));

        // vote=2 → assertBoolean fails
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "commitment", List.of(BigInteger.valueOf(84)),
                "vote", List.of(BigInteger.TWO),
                "nullifier", List.of(BigInteger.valueOf(42))), CurveId.BN254));
    }
}
