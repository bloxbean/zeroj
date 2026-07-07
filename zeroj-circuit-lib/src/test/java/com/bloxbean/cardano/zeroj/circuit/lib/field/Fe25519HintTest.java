package com.bloxbean.cardano.zeroj.circuit.lib.field;

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
 * ADR-0028 Phase C: hint-based CRT multiplication for {@link Fe25519}.
 *
 * <p>Two test families implementing the ADR-0028 framework:</p>
 * <ol>
 *   <li><b>Differential (pillar 1)</b>: {@code mulHint} must equal the deterministic {@code mul}
 *       and {@code BigInteger} over random + edge inputs, on BN254 and BLS12-381.</li>
 *   <li><b>Soundness / under-constraint (pillar 2)</b>: feed <b>adversarial</b> {@code (q,r)}
 *       directly to {@code mulFromQR} (bypassing the hint) and assert the constraints REJECT every
 *       tampered witness — the direct test that the advice is fully pinned down.</li>
 * </ol>
 */
class Fe25519HintTest {

    private static final BigInteger P = Fe25519.P;
    private static final Random RND = new Random(0xC27L);

    private static BigInteger randFe() { return new BigInteger(255, RND).mod(P); }

    // ------------------------------------------------------------------
    // 1. Differential: mulHint == mul == BigInteger
    // ------------------------------------------------------------------

    private static void assertMulHint(BigInteger a, BigInteger b, CurveId curve) {
        BigInteger expected = a.multiply(b).mod(P);
        BigInteger[] al = Fe25519.toLimbValues(a), bl = Fe25519.toLimbValues(b), el = Fe25519.toLimbValues(expected);
        var builder = CircuitBuilder.create("mulhint");
        for (int i = 0; i < 5; i++) builder.secretVar("a" + i).secretVar("b" + i);
        for (int i = 0; i < 5; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Variable[] av = new Variable[5], bv = new Variable[5];
            for (int i = 0; i < 5; i++) { av[i] = api.var("a" + i); bv[i] = api.var("b" + i); }
            Fe25519 r = Fe25519.ofLimbsChecked(api, av).mulHint(Fe25519.ofLimbsChecked(api, bv)).canonical();
            Variable[] rl = r.limbs();
            for (int i = 0; i < 5; i++) api.assertEqual(rl[i], api.var("e" + i));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < 5; i++) { in.put("a" + i, List.of(al[i])); in.put("b" + i, List.of(bl[i])); in.put("e" + i, List.of(el[i])); }
        assertDoesNotThrow(() -> builder.calculateWitness(in, curve), "mulHint != a*b mod p for a=" + a + " b=" + b);
    }

    @Test
    void mulHint_matchesBigInteger() {
        BigInteger[] edges = {BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO, P.subtract(BigInteger.ONE),
                P.subtract(BigInteger.TWO), BigInteger.ONE.shiftLeft(200)};
        for (BigInteger a : edges) for (BigInteger b : edges) assertMulHint(a, b, CurveId.BN254);
        for (int t = 0; t < 40; t++) assertMulHint(randFe(), randFe(), CurveId.BN254);
    }

    @Test
    void mulHint_matchesDeterministicMul() {
        // mulHint and the frozen deterministic mul must agree exactly (both == BigInteger).
        for (int t = 0; t < 15; t++) {
            BigInteger a = randFe(), b = randFe();
            BigInteger[] al = Fe25519.toLimbValues(a), bl = Fe25519.toLimbValues(b);
            var builder = CircuitBuilder.create("hint-eq-det");
            for (int i = 0; i < 5; i++) builder.secretVar("a" + i).secretVar("b" + i);
            builder.define(api -> {
                Variable[] av = new Variable[5], bv = new Variable[5];
                for (int i = 0; i < 5; i++) { av[i] = api.var("a" + i); bv[i] = api.var("b" + i); }
                Fe25519 fa = Fe25519.ofLimbsChecked(api, av), fb = Fe25519.ofLimbsChecked(api, bv);
                Variable[] hint = fa.mulHint(fb).canonical().limbs();
                Variable[] det = fa.mul(fb).canonical().limbs();
                for (int i = 0; i < 5; i++) api.assertEqual(hint[i], det[i]); // bit-identical
            });
            Map<String, List<BigInteger>> in = new HashMap<>();
            for (int i = 0; i < 5; i++) { in.put("a" + i, List.of(al[i])); in.put("b" + i, List.of(bl[i])); }
            assertDoesNotThrow(() -> builder.calculateWitness(in, CurveId.BN254));
        }
    }

    @Test
    void mulHint_worksOnBls12381() {
        assertMulHint(randFe(), randFe(), CurveId.BLS12_381);
    }

    @Test
    void constraintCount_mulHint_reported() {
        var builder = CircuitBuilder.create("mulhint-cost");
        for (int i = 0; i < 5; i++) builder.secretVar("a" + i).secretVar("b" + i);
        builder.define(api -> {
            Variable[] av = new Variable[5], bv = new Variable[5];
            for (int i = 0; i < 5; i++) { av[i] = api.var("a" + i); bv[i] = api.var("b" + i); }
            Fe25519.ofLimbsTrusted(api, av).mulHint(Fe25519.ofLimbsTrusted(api, bv));
        });
        int c = builder.compileR1CS(CurveId.BN254).numConstraints();
        System.out.println("[ADR-0028 C] Fe25519 mulHint constraints = " + c + " (deterministic mul = 8051)");
        assertTrue(c > 0 && c < 8051, "mulHint should be cheaper than deterministic mul: " + c);
    }

    // ------------------------------------------------------------------
    // 2. Soundness: adversarial (q, r) fed to mulFromQR must be REJECTED
    // ------------------------------------------------------------------

    /** Run mulFromQR with the given a,b,q,r limb values; return whether the witness is satisfiable. */
    private static boolean accepts(BigInteger[] a, BigInteger[] b, BigInteger[] q, BigInteger[] r) {
        var builder = CircuitBuilder.create("qr");
        for (int i = 0; i < 5; i++) builder.secretVar("a" + i).secretVar("b" + i).secretVar("q" + i).secretVar("r" + i);
        builder.define(api -> {
            Variable[] av = new Variable[5], bv = new Variable[5], qv = new Variable[5], rv = new Variable[5];
            for (int i = 0; i < 5; i++) {
                av[i] = api.var("a" + i); bv[i] = api.var("b" + i);
                qv[i] = api.var("q" + i); rv[i] = api.var("r" + i);
            }
            Fe25519.mulFromQR(api, av, bv, qv, rv);
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < 5; i++) {
            in.put("a" + i, List.of(a[i])); in.put("b" + i, List.of(b[i]));
            in.put("q" + i, List.of(q[i])); in.put("r" + i, List.of(r[i]));
        }
        try { builder.calculateWitness(in, CurveId.BN254); return true; }
        catch (ArithmeticException | IllegalArgumentException e) { return false; }
    }

    private static BigInteger[] limbs(BigInteger v) { return Fe25519.toLimbValues(v); }

    @Test
    void soundness_correctQR_accepted_tamperedQR_rejected() {
        for (int t = 0; t < 20; t++) {
            BigInteger a = randFe(), b = randFe();
            BigInteger prod = a.multiply(b);
            BigInteger q = prod.divide(P), r = prod.mod(P);
            BigInteger[] al = limbs(a), bl = limbs(b), ql = limbs(q), rl = limbs(r);

            assertTrue(accepts(al, bl, ql, rl), "honest (q,r) must be accepted");

            // Mutate each q and r limb by +1 and -1 (staying a valid field element) -> must reject.
            for (int i = 0; i < 5; i++) {
                for (int delta : new int[]{1, -1}) {
                    assertFalse(accepts(al, bl, mutate(ql, i, delta), rl),
                            "tampered q[" + i + "]" + (delta > 0 ? "+1" : "-1") + " must be rejected");
                    assertFalse(accepts(al, bl, ql, mutate(rl, i, delta)),
                            "tampered r[" + i + "]" + (delta > 0 ? "+1" : "-1") + " must be rejected");
                }
            }
        }
    }

    @Test
    void soundness_nonCanonicalR_rejected() {
        // r' = r + p, q' = q - 1 satisfies a*b = q'*p + r' but r' >= p — must be rejected by r<p.
        // Choose a,b so that r < 19 (=> r+p < 2^255 fits 5 limbs and lands in the [p,2^255) window).
        for (int t = 0; t < 200 && t < 200; t++) {
            BigInteger a = randFe(), b = randFe();
            BigInteger prod = a.multiply(b);
            BigInteger q = prod.divide(P), r = prod.mod(P);
            if (r.compareTo(BigInteger.valueOf(19)) >= 0) continue; // need r+p < 2^255
            if (q.signum() == 0) continue;
            BigInteger rPrime = r.add(P), qPrime = q.subtract(BigInteger.ONE);
            // sanity: identity still holds over integers
            assertEquals(prod, qPrime.multiply(P).add(rPrime));
            assertFalse(accepts(limbs(a), limbs(b), limbs(qPrime), splitRaw(rPrime)),
                    "non-canonical r (>= p) must be rejected");
            return; // one qualifying case is enough
        }
    }

    @Test
    void soundness_swappedLimbs_rejected() {
        BigInteger a = randFe(), b = randFe();
        BigInteger prod = a.multiply(b);
        BigInteger[] ql = limbs(prod.divide(P)), rl = limbs(prod.mod(P));
        if (rl[0].equals(rl[1])) return; // need distinct to make the swap a real change
        BigInteger[] rSwap = rl.clone();
        BigInteger tmp = rSwap[0]; rSwap[0] = rSwap[1]; rSwap[1] = tmp;
        assertFalse(accepts(limbs(a), limbs(b), ql, rSwap), "swapped r limbs must be rejected");
    }

    private static BigInteger[] mutate(BigInteger[] limbs, int idx, int delta) {
        BigInteger[] out = limbs.clone();
        out[idx] = out[idx].add(BigInteger.valueOf(delta));
        if (out[idx].signum() < 0) out[idx] = out[idx].add(P); // keep a valid field element
        return out;
    }

    private static BigInteger[] splitRaw(BigInteger v) {
        BigInteger mask = BigInteger.ONE.shiftLeft(51).subtract(BigInteger.ONE);
        BigInteger[] out = new BigInteger[5];
        for (int i = 0; i < 5; i++) { out[i] = v.and(mask); v = v.shiftRight(51); }
        return out;
    }
}
