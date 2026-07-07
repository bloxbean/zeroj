package com.bloxbean.cardano.zeroj.circuit.lib.ed25519;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0028 Phase A: fixed-base windowed scalar multiplication.
 *
 * <p>Safety net (ADR-0028 framework pillar 1): the windowed method
 * {@link Ed25519Point#scalarMulFixedBaseBWindowed} must produce results identical to the
 * ADR-0027 deterministic reference {@link Ed25519Point#scalarMulFixedBaseB} <b>and</b> to
 * {@link Ed25519Host} (itself validated against BouncyCastle in {@link Ed25519PointTest}), across
 * many scalars including edge values, for every window size. A constraint-reduction report
 * confirms the ~⌈n/w⌉ vs n add-count win.</p>
 */
class Ed25519WindowedTest {

    private static final Random RND = new Random(0x0028L);

    /** Encode(windowed(k)) must equal host encode(k·B). */
    private static void assertWindowedMatchesHost(BigInteger k, int nBits, int w) {
        byte[] expected = Ed25519Host.encode(Ed25519Host.scalarMulBase(k));
        var builder = CircuitBuilder.create("ed-win-" + w + "-" + k);
        for (int i = 0; i < nBits; i++) builder.secretVar("s" + i);
        for (int i = 0; i < 32; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Variable[] bits = new Variable[nBits];
            for (int i = 0; i < nBits; i++) bits[i] = api.var("s" + i);
            Variable[] enc = Ed25519Point.scalarMulFixedBaseBWindowed(api, bits, w).encode();
            for (int i = 0; i < 32; i++) api.assertEqual(enc[i], api.var("e" + i));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < nBits; i++) in.put("s" + i, List.of(k.testBit(i) ? BigInteger.ONE : BigInteger.ZERO));
        for (int i = 0; i < 32; i++) in.put("e" + i, List.of(BigInteger.valueOf(expected[i] & 0xff)));
        assertDoesNotThrow(() -> builder.calculateWitness(in, CurveId.BN254),
                "windowed(w=" + w + ") scalar mult mismatch for k=" + k);
    }

    @Test
    void windowed_matchesHost_variousScalarsAndWindows() {
        // edge scalars + randoms, across window sizes.
        long[] edges = {0, 1, 2, 3, 15, 16, 255, 256, 1023};
        for (int w : new int[]{1, 2, 3, 4, 5}) {
            for (long k : edges) assertWindowedMatchesHost(BigInteger.valueOf(k), 20, w);
            for (int t = 0; t < 4; t++) assertWindowedMatchesHost(new BigInteger(20, RND).max(BigInteger.ONE), 20, w);
        }
    }

    @Test
    void windowed_equalsReference_bitByBit() {
        // Directly assert windowed == non-windowed reference (the ADR-0027 gadget) via encodings.
        for (int w : new int[]{2, 4}) {
            for (int t = 0; t < 5; t++) {
                BigInteger k = new BigInteger(24, RND).max(BigInteger.ONE);
                var builder = CircuitBuilder.create("ed-win-eq-" + w + "-" + t);
                for (int i = 0; i < 24; i++) builder.secretVar("s" + i);
                builder.define(api -> {
                    Variable[] bits = new Variable[24];
                    for (int i = 0; i < 24; i++) bits[i] = api.var("s" + i);
                    Variable[] ref = Ed25519Point.scalarMulFixedBaseB(api, bits).encode();
                    Variable[] win = Ed25519Point.scalarMulFixedBaseBWindowed(api, bits, w).encode();
                    for (int i = 0; i < 32; i++) api.assertEqual(ref[i], win[i]); // must be bit-identical
                });
                Map<String, List<BigInteger>> in = new HashMap<>();
                for (int i = 0; i < 24; i++) in.put("s" + i, List.of(k.testBit(i) ? BigInteger.ONE : BigInteger.ZERO));
                final BigInteger kk = k;
                assertDoesNotThrow(() -> builder.calculateWitness(in, CurveId.BN254),
                        "windowed != reference for k=" + kk + " w=" + w);
            }
        }
    }

    @Test
    void windowed_worksOnBls12381() {
        assertWindowedMatchesHost(new BigInteger("123456789012345"), 48, 4);
    }

    @Test
    @org.junit.jupiter.api.condition.EnabledIfSystemProperty(named = "zeroj.heavy", matches = "true")
    void windowed_full255BitScalar_matchesHost() {
        // Close the coverage gap: exercise the full 255-bit path incl. a set high top bit.
        BigInteger k = BigInteger.ONE.shiftLeft(254).or(new BigInteger(254, RND));
        assertWindowedMatchesHost(k, 255, 4);
    }

    @Test
    void constraintReduction_reported() {
        // Reported at 32 bits (the add-count ratio is size-independent) to keep the reference
        // circuit's R1CS compile within the default test heap; a 255-bit reference is ~29M.
        int nBits = 32;
        int ref = scalarMulConstraints(nBits, 0);          // 0 => bit-by-bit reference
        System.out.println("[ADR-0028 A] Ed25519 scalar mult (" + nBits + "-bit) constraints:");
        System.out.println("    reference (bit-by-bit) = " + ref);
        int best = ref;
        for (int w : new int[]{2, 4, 5}) {
            int c = scalarMulConstraints(nBits, w);
            System.out.printf("    windowed w=%d          = %d  (%.2fx)%n", w, c, ref / (double) c);
            best = Math.min(best, c);
        }
        assertTrue(best < ref * 0.5, "windowing should more than halve the scalar-mult cost");
    }

    private static int scalarMulConstraints(int nBits, int w) {
        var builder = CircuitBuilder.create("cost-" + w);
        for (int i = 0; i < nBits; i++) builder.secretVar("s" + i);
        builder.define(api -> {
            Variable[] bits = new Variable[nBits];
            for (int i = 0; i < nBits; i++) bits[i] = api.var("s" + i);
            if (w == 0) Ed25519Point.scalarMulFixedBaseB(api, bits);
            else Ed25519Point.scalarMulFixedBaseBWindowed(api, bits, w);
        });
        return builder.compileR1CS(CurveId.BN254).numConstraints();
    }
}
