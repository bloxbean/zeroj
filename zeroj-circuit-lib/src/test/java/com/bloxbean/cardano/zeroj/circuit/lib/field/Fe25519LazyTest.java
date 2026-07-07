package com.bloxbean.cardano.zeroj.circuit.lib.field;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0028 Phase B: lazy reduction for {@link Fe25519}.
 *
 * <p>Validates the lazy operations ({@code addLazy}/{@code subLazy} + loose-operand {@code mul})
 * against {@link BigInteger} — the permanent oracle — including <b>high-overflow chains</b> that
 * deliberately push the operand overflow past {@link Fe25519#MAX_MUL_OVERFLOW} to exercise the
 * mul reduce-backstop, and boundary cases around it. Because reduction is deterministic and each
 * carry-reduce asserts a zero residual carry, an under-provisioned width/pass count would fail
 * loudly here rather than produce a wrong result.</p>
 */
class Fe25519LazyTest {

    private static final BigInteger P = Fe25519.P;
    private static final Random RND = new Random(0x1a2b3cL);

    private static BigInteger randFe() { return new BigInteger(255, RND).mod(P); }

    /** Build a circuit that computes `fn` over lazy ops and asserts canonical == expected (mod p). */
    private interface Body { Fe25519 run(Fe25519[] in); }

    private static void assertLazy(String name, int nInputs, BigInteger[] vals, BigInteger expected, Body body) {
        var builder = CircuitBuilder.create(name);
        for (int k = 0; k < nInputs; k++) for (int i = 0; i < 5; i++) builder.secretVar("x" + k + "_" + i);
        for (int i = 0; i < 5; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Fe25519[] in = new Fe25519[nInputs];
            for (int k = 0; k < nInputs; k++) {
                Variable[] lv = new Variable[5];
                for (int i = 0; i < 5; i++) lv[i] = api.var("x" + k + "_" + i);
                in[k] = Fe25519.ofLimbsChecked(api, lv);
            }
            Fe25519 r = body.run(in).canonical();
            Variable[] rl = r.limbs();
            for (int i = 0; i < 5; i++) api.assertEqual(rl[i], api.var("e" + i));
        });
        Map<String, List<BigInteger>> inMap = new HashMap<>();
        for (int k = 0; k < nInputs; k++) {
            BigInteger[] limbs = Fe25519.toLimbValues(vals[k]);
            for (int i = 0; i < 5; i++) inMap.put("x" + k + "_" + i, List.of(limbs[i]));
        }
        BigInteger[] el = Fe25519.toLimbValues(expected);
        for (int i = 0; i < 5; i++) inMap.put("e" + i, List.of(el[i]));
        assertDoesNotThrow(() -> builder.calculateWitness(inMap, CurveId.BN254), name + " mismatch");
    }

    @Test
    void addLazyThenMul_matchesBigInteger() {
        for (int t = 0; t < 30; t++) {
            BigInteger a = randFe(), b = randFe(), c = randFe(), d = randFe();
            BigInteger expected = a.add(b).multiply(c.add(d)).mod(P);
            assertLazy("lazy-add-mul", 4, new BigInteger[]{a, b, c, d}, expected,
                    in -> in[0].addLazy(in[1]).mul(in[2].addLazy(in[3])));
        }
    }

    @Test
    void subLazyThenMul_matchesBigInteger() {
        for (int t = 0; t < 30; t++) {
            BigInteger a = randFe(), b = randFe(), c = randFe(), d = randFe();
            BigInteger expected = a.subtract(b).multiply(c.subtract(d)).mod(P);
            assertLazy("lazy-sub-mul", 4, new BigInteger[]{a, b, c, d}, expected,
                    in -> in[0].subLazy(in[1]).mul(in[2].subLazy(in[3])));
        }
    }

    @Test
    void lazyEqualsEager() {
        for (int t = 0; t < 20; t++) {
            BigInteger a = randFe(), b = randFe();
            assertLazy("lazy=eager-add", 2, new BigInteger[]{a, b}, a.add(b).mod(P),
                    in -> in[0].addLazy(in[1]));       // addLazy().canonical() must equal a+b
            assertLazy("lazy=eager-sub", 2, new BigInteger[]{a, b}, a.subtract(b).mod(P),
                    in -> in[0].subLazy(in[1]));
        }
    }

    @Test
    void highOverflowChain_pastMulBackstop_matchesBigInteger() {
        // Chain N lazy adds (overflow grows to N), then mul — N>6 forces mul's reduce backstop.
        for (int n : new int[]{2, 6, 7, 8, 10}) {
            BigInteger[] vals = new BigInteger[n + 1];
            BigInteger sum = BigInteger.ZERO;
            for (int k = 0; k < n; k++) { vals[k] = randFe(); sum = sum.add(vals[k]); }
            vals[n] = randFe();                        // multiplier
            BigInteger expected = sum.multiply(vals[n]).mod(P);
            final int nn = n;
            assertLazy("lazy-chain-" + n, n + 1, vals, expected, in -> {
                Fe25519 acc = in[0];
                for (int k = 1; k < nn; k++) acc = acc.addLazy(in[k]);   // overflow -> ~n
                return acc.mul(in[nn]);                                  // reduces if overflow > MAX_MUL_OVERFLOW
            });
        }
    }

    @Test
    void highOverflowChain_thenCanonical_matchesBigInteger() {
        // Reduce/canonical directly on a high-overflow accumulator (no mul).
        int n = 9;
        BigInteger[] vals = new BigInteger[n];
        BigInteger sum = BigInteger.ZERO;
        for (int k = 0; k < n; k++) { vals[k] = randFe(); sum = sum.add(vals[k]); }
        assertLazy("lazy-chain-canon", n, vals, sum.mod(P), in -> {
            Fe25519 acc = in[0];
            for (int k = 1; k < n; k++) acc = acc.addLazy(in[k]);
            return acc;
        });
    }

    @Test
    void worksOnBls12381() {
        BigInteger a = randFe(), b = randFe(), c = randFe();
        assertLazyBls("lazy-bls", 3, new BigInteger[]{a, b, c},
                a.add(b).multiply(c).mod(P), in -> in[0].addLazy(in[1]).mul(in[2]));
    }

    private static void assertLazyBls(String name, int nInputs, BigInteger[] vals, BigInteger expected, Body body) {
        var builder = CircuitBuilder.create(name);
        for (int k = 0; k < nInputs; k++) for (int i = 0; i < 5; i++) builder.secretVar("x" + k + "_" + i);
        for (int i = 0; i < 5; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Fe25519[] in = new Fe25519[nInputs];
            for (int k = 0; k < nInputs; k++) {
                Variable[] lv = new Variable[5];
                for (int i = 0; i < 5; i++) lv[i] = api.var("x" + k + "_" + i);
                in[k] = Fe25519.ofLimbsChecked(api, lv);
            }
            Variable[] rl = body.run(in).canonical().limbs();
            for (int i = 0; i < 5; i++) api.assertEqual(rl[i], api.var("e" + i));
        });
        Map<String, List<BigInteger>> inMap = new HashMap<>();
        for (int k = 0; k < nInputs; k++) {
            BigInteger[] limbs = Fe25519.toLimbValues(vals[k]);
            for (int i = 0; i < 5; i++) inMap.put("x" + k + "_" + i, List.of(limbs[i]));
        }
        BigInteger[] el = Fe25519.toLimbValues(expected);
        for (int i = 0; i < 5; i++) inMap.put("e" + i, List.of(el[i]));
        assertDoesNotThrow(() -> builder.calculateWitness(inMap, CurveId.BLS12_381), name + " mismatch");
    }
}
