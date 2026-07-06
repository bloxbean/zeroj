package com.bloxbean.cardano.zeroj.circuit.lib.hash;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Correctness tests for the in-circuit {@link Sha512} gadget.
 *
 * <p>The gadget's output is cross-checked, byte-for-byte, against the JCA
 * {@code MessageDigest("SHA-512")} reference across message lengths chosen to exercise the
 * padding boundaries (single block, the 112-byte overflow case, exact-block, multi-block).
 * A message length passes iff {@code calculateWitness} satisfies every in-circuit
 * {@code assertEqual(output, expected)} — so a valid witness <i>is</i> the proof of equality.
 */
class Sha512Test {

    private static byte[] jca(byte[] msg) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(msg);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static BigInteger u(long v) {
        return new BigInteger(Long.toUnsignedString(v));
    }

    /** Build a circuit that hashes {@code msg} and asserts each output byte equals JCA's digest. */
    private static void assertMatchesJca(byte[] msg, CurveId curve) {
        int n = msg.length;
        byte[] expected = jca(msg);

        var builder = CircuitBuilder.create("sha512-" + n);
        for (int i = 0; i < n; i++) builder.secretVar("b" + i);
        for (int i = 0; i < 64; i++) builder.publicVar("e" + i);

        builder.define(api -> {
            Variable[] bytes = new Variable[n];
            for (int i = 0; i < n; i++) bytes[i] = api.var("b" + i);
            Variable[] out = Sha512.hashBytes(api, bytes);
            assertEquals(64, out.length, "digest must be 64 bytes");
            for (int i = 0; i < 64; i++) api.assertEqual(out[i], api.var("e" + i));
        });

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        for (int i = 0; i < n; i++) inputs.put("b" + i, List.of(BigInteger.valueOf(msg[i] & 0xff)));
        for (int i = 0; i < 64; i++) inputs.put("e" + i, List.of(BigInteger.valueOf(expected[i] & 0xff)));

        assertDoesNotThrow(() -> builder.calculateWitness(inputs, curve),
                "SHA-512 gadget disagreed with JCA for message length " + n);
    }

    // ------------------------------------------------------------------
    // End-to-end vs JCA across padding boundaries and multi-block
    // ------------------------------------------------------------------

    @Test
    void emptyMessage_matchesJca() {
        assertMatchesJca(new byte[0], CurveId.BN254);
    }

    @Test
    void abc_matchesJca() {
        assertMatchesJca("abc".getBytes(StandardCharsets.US_ASCII), CurveId.BN254);
    }

    @Test
    void paddingBoundaries_matchJca() {
        // 111 -> single block (fits length field); 112 -> overflows to a second block;
        // 128 -> exact one-block message then a full pad block.
        for (int len : new int[]{55, 56, 111, 112, 127, 128}) {
            byte[] msg = new byte[len];
            new Random(0xC0FFEE + len).nextBytes(msg);
            assertMatchesJca(msg, CurveId.BN254);
        }
    }

    @Test
    void multiBlock_matchesJca() {
        byte[] msg = new byte[200];
        new Random(42).nextBytes(msg);
        assertMatchesJca(msg, CurveId.BN254);
    }

    @Test
    void fieldAgnostic_worksOnBls12381() {
        // The gadget declares no field dependency; the same logic must verify on BLS12-381.
        assertMatchesJca("abc".getBytes(StandardCharsets.US_ASCII), CurveId.BLS12_381);
        assertMatchesJca(new byte[112], CurveId.BLS12_381);
    }

    // ------------------------------------------------------------------
    // Negative: tampered expected digest must fail
    // ------------------------------------------------------------------

    @Test
    void wrongDigest_fails() {
        byte[] msg = "abc".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = jca(msg);
        expected[0] ^= 0x01; // flip one bit of the claimed digest

        var builder = CircuitBuilder.create("sha512-neg");
        for (int i = 0; i < msg.length; i++) builder.secretVar("b" + i);
        for (int i = 0; i < 64; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Variable[] bytes = new Variable[msg.length];
            for (int i = 0; i < msg.length; i++) bytes[i] = api.var("b" + i);
            Variable[] out = Sha512.hashBytes(api, bytes);
            for (int i = 0; i < 64; i++) api.assertEqual(out[i], api.var("e" + i));
        });

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        for (int i = 0; i < msg.length; i++) inputs.put("b" + i, List.of(BigInteger.valueOf(msg[i] & 0xff)));
        for (int i = 0; i < 64; i++) inputs.put("e" + i, List.of(BigInteger.valueOf(expected[i] & 0xff)));

        assertThrows(ArithmeticException.class, () -> builder.calculateWitness(inputs, CurveId.BN254));
    }

    // ------------------------------------------------------------------
    // Focused helper checks: rotr / shr vs Java's Long operations
    // ------------------------------------------------------------------

    @Test
    void rotr_matchesLongRotateRight() {
        long[] samples = {0x0123456789abcdefL, 0xffffffffffffffffL, 1L, 0x8000000000000000L, 0xdeadbeefcafebabeL};
        int[] shifts = {1, 7, 8, 14, 28, 39, 63};
        for (long x : samples) {
            for (int n : shifts) {
                var builder = CircuitBuilder.create("rotr");
                builder.secretVar("x").publicVar("y");
                builder.define(api -> {
                    Variable[] bits = api.toBinary(api.var("x"), 64);
                    Variable rotated = api.fromBinary(Sha512.rotr(bits, n));
                    api.assertEqual(rotated, api.var("y"));
                });
                BigInteger expected = u(Long.rotateRight(x, n));
                assertDoesNotThrow(() -> builder.calculateWitness(
                        Map.of("x", List.of(u(x)), "y", List.of(expected)), CurveId.BN254),
                        "rotr mismatch x=" + Long.toHexString(x) + " n=" + n);
            }
        }
    }

    @Test
    void shr_matchesLongUnsignedShiftRight() {
        long[] samples = {0x0123456789abcdefL, 0xffffffffffffffffL, 0x8000000000000000L, 0xdeadbeefcafebabeL};
        int[] shifts = {1, 6, 7, 32, 63};
        for (long x : samples) {
            for (int n : shifts) {
                var builder = CircuitBuilder.create("shr");
                builder.secretVar("x").publicVar("y");
                builder.define(api -> {
                    Variable[] bits = api.toBinary(api.var("x"), 64);
                    Variable shifted = api.fromBinary(Sha512.shr(api, bits, n));
                    api.assertEqual(shifted, api.var("y"));
                });
                BigInteger expected = u(x >>> n);
                assertDoesNotThrow(() -> builder.calculateWitness(
                        Map.of("x", List.of(u(x)), "y", List.of(expected)), CurveId.BN254),
                        "shr mismatch x=" + Long.toHexString(x) + " n=" + n);
            }
        }
    }

    // ------------------------------------------------------------------
    // Constraint-count report (ADR-0027 acceptance benchmark)
    // ------------------------------------------------------------------

    @Test
    void constraintCount_singleBlock_reported() {
        // "abc" -> one 1024-bit block.
        int n = 3;
        var builder = CircuitBuilder.create("sha512-cost");
        for (int i = 0; i < n; i++) builder.secretVar("b" + i);
        builder.define(api -> {
            Variable[] bytes = new Variable[n];
            for (int i = 0; i < n; i++) bytes[i] = api.var("b" + i);
            Sha512.hashBytes(api, bytes);
        });
        int constraints = builder.compileR1CS(CurveId.BN254).numConstraints();
        System.out.println("[ADR-0027 M1] SHA-512 single-block constraints = " + constraints);
        assertTrue(constraints > 20_000, "unexpectedly low: " + constraints);
        assertTrue(constraints < 200_000, "over budget for one block: " + constraints);
    }
}
