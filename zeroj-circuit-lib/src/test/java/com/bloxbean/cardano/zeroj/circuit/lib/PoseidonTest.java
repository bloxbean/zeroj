package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Poseidon hash tests verified against circomlibjs reference implementation.
 */
class PoseidonTest {

    // Test vectors from circomlibjs (verified via npm circomlibjs buildPoseidon)
    private static final BigInteger POSEIDON_0_0 = new BigInteger(
            "14744269619966411208579211824598458697587494354926760081771325075741142829156");
    private static final BigInteger POSEIDON_1_2 = new BigInteger(
            "7853200120776062878684798364095072458815029376092732009249414926327459813530");
    private static final BigInteger POSEIDON_123_456 = new BigInteger(
            "19620391833206800292073497099357851348339828238212863168390691880932172496143");

    @Test
    void poseidon_0_0_matchesCircomlib() {
        var circuit = CircuitBuilder.create("poseidon")
                .publicVar("hash").secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, api.var("a"), api.var("b"));
                    api.assertEqual(h, api.var("hash"));
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "hash", List.of(POSEIDON_0_0),
                "a", List.of(BigInteger.ZERO),
                "b", List.of(BigInteger.ZERO)), CurveId.BN254));
    }

    @Test
    void poseidon_1_2_matchesCircomlib() {
        var circuit = CircuitBuilder.create("poseidon")
                .publicVar("hash").secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, api.var("a"), api.var("b"));
                    api.assertEqual(h, api.var("hash"));
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "hash", List.of(POSEIDON_1_2),
                "a", List.of(BigInteger.ONE),
                "b", List.of(BigInteger.TWO)), CurveId.BN254));
    }

    @Test
    void poseidon_123_456_matchesCircomlib() {
        var circuit = CircuitBuilder.create("poseidon")
                .publicVar("hash").secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, api.var("a"), api.var("b"));
                    api.assertEqual(h, api.var("hash"));
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "hash", List.of(POSEIDON_123_456),
                "a", List.of(BigInteger.valueOf(123)),
                "b", List.of(BigInteger.valueOf(456))), CurveId.BN254));
    }

    @Test
    void poseidon_wrongHash_fails() {
        var circuit = CircuitBuilder.create("poseidon")
                .publicVar("hash").secretVar("a").secretVar("b")
                .define(api -> {
                    var h = Poseidon.hash(api, api.var("a"), api.var("b"));
                    api.assertEqual(h, api.var("hash"));
                });

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "hash", List.of(BigInteger.valueOf(999)), // wrong hash
                "a", List.of(BigInteger.ONE),
                "b", List.of(BigInteger.TWO)), CurveId.BN254));
    }

    @Test
    void poseidon_signalApi() {
        var circuit = CircuitBuilder.create("poseidon")
                .publicVar("hash").secretVar("a").secretVar("b")
                .defineSignals(c -> {
                    Signal h = Poseidon.hash(c, c.privateInput("a"), c.privateInput("b"));
                    c.assertEqual(h, c.publicOutput("hash"));
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "hash", List.of(POSEIDON_1_2),
                "a", List.of(BigInteger.ONE),
                "b", List.of(BigInteger.TWO)), CurveId.BN254));
    }

    @Test
    void poseidon_deterministic() {
        var circuit = CircuitBuilder.create("poseidon")
                .secretVar("a").secretVar("b")
                .define(api -> Poseidon.hash(api, api.var("a"), api.var("b")));

        var w1 = circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.valueOf(42)),
                "b", List.of(BigInteger.valueOf(7))), CurveId.BN254);
        var w2 = circuit.calculateWitness(Map.of(
                "a", List.of(BigInteger.valueOf(42)),
                "b", List.of(BigInteger.valueOf(7))), CurveId.BN254);

        assertArrayEquals(w1, w2);
    }
}
