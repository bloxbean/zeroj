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
 * ADR-0028: hint-based Fe25519 inverse. Differential (pillar 1): {@code inverseHint} equals the
 * Fermat {@link Fe25519#inverse} and {@link BigInteger#modInverse}. Soundness (pillar 2): an
 * adversarial candidate fed to {@code inverseFromCandidate} must be REJECTED — the check
 * {@code a·cand == 1} fully pins the inverse.
 */
class Fe25519InverseHintTest {

    private static final BigInteger P = Fe25519.P;
    private static final Random RND = new Random(0x1_0FFL);

    private static BigInteger randNonZero() {
        BigInteger v;
        do { v = new BigInteger(255, RND).mod(P); } while (v.signum() == 0);
        return v;
    }

    // ------------------------------------------------------------------
    // Differential: inverseHint == modInverse (and == Fermat inverse)
    // ------------------------------------------------------------------

    private static void assertInverseHint(BigInteger a, CurveId curve) {
        BigInteger expected = a.modInverse(P);
        BigInteger[] al = Fe25519.toLimbValues(a), el = Fe25519.toLimbValues(expected);
        var builder = CircuitBuilder.create("fe-inv-hint");
        for (int i = 0; i < 5; i++) builder.secretVar("a" + i);
        for (int i = 0; i < 5; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Variable[] av = new Variable[5];
            for (int i = 0; i < 5; i++) av[i] = api.var("a" + i);
            Variable[] rl = Fe25519.ofLimbsChecked(api, av).inverseHint().canonical().limbs();
            for (int i = 0; i < 5; i++) api.assertEqual(rl[i], api.var("e" + i));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < 5; i++) { in.put("a" + i, List.of(al[i])); in.put("e" + i, List.of(el[i])); }
        assertDoesNotThrow(() -> builder.calculateWitness(in, curve), "inverseHint != a^-1 for a=" + a);
    }

    @Test
    void inverseHint_matchesBigInteger() {
        for (BigInteger a : new BigInteger[]{BigInteger.ONE, BigInteger.TWO, P.subtract(BigInteger.ONE)})
            assertInverseHint(a, CurveId.BN254);
        for (int t = 0; t < 30; t++) assertInverseHint(randNonZero(), CurveId.BN254);
    }

    @Test
    void inverseHint_worksOnBls12381() {
        assertInverseHint(randNonZero(), CurveId.BLS12_381);
    }

    @Test
    void inverseHint_zeroIsUnsatisfiable() {
        // 0 has no inverse: a·cand == 1 with a==0 can never hold -> witness generation fails.
        var builder = CircuitBuilder.create("fe-inv-zero");
        for (int i = 0; i < 5; i++) builder.secretVar("a" + i);
        builder.define(api -> {
            Variable[] av = new Variable[5];
            for (int i = 0; i < 5; i++) av[i] = api.var("a" + i);
            Fe25519.ofLimbsChecked(api, av).inverseHint();
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < 5; i++) in.put("a" + i, List.of(BigInteger.ZERO));
        assertThrows(ArithmeticException.class, () -> builder.calculateWitness(in, CurveId.BN254));
    }

    @Test
    void constraintCount_inverseHint_vsFermat() {
        int hint = invConstraints(true);
        int fermat = invConstraints(false);
        System.out.println("[ADR-0028] Fe25519 inverse: hint=" + hint + "  Fermat=" + fermat
                + "  (" + (fermat / hint) + "x)");
        assertTrue(hint * 50L < fermat, "hint inverse must be far cheaper than Fermat");
    }

    private static int invConstraints(boolean useHint) {
        var builder = CircuitBuilder.create("fe-inv-cost-" + useHint);
        for (int i = 0; i < 5; i++) builder.secretVar("a" + i);
        builder.define(api -> {
            Variable[] av = new Variable[5];
            for (int i = 0; i < 5; i++) av[i] = api.var("a" + i);
            Fe25519 a = Fe25519.ofLimbsTrusted(api, av);
            if (useHint) a.inverseHint(); else a.inverse();
        });
        return builder.compileR1CS(CurveId.BN254).numConstraints();
    }

    // ------------------------------------------------------------------
    // Soundness: adversarial candidate must be rejected
    // ------------------------------------------------------------------

    private static boolean accepts(BigInteger a, BigInteger cand) {
        var builder = CircuitBuilder.create("fe-inv-qr");
        for (int i = 0; i < 5; i++) builder.secretVar("a" + i).secretVar("c" + i);
        builder.define(api -> {
            Variable[] av = new Variable[5], cv = new Variable[5];
            for (int i = 0; i < 5; i++) { av[i] = api.var("a" + i); cv[i] = api.var("c" + i); }
            Fe25519.inverseFromCandidate(api, av, cv);
        });
        BigInteger[] al = Fe25519.toLimbValues(a), cl = Fe25519.toLimbValues(cand.mod(P));
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < 5; i++) { in.put("a" + i, List.of(al[i])); in.put("c" + i, List.of(cl[i])); }
        try { builder.calculateWitness(in, CurveId.BN254); return true; }
        catch (ArithmeticException | IllegalArgumentException e) { return false; }
    }

    @Test
    void soundness_correctInverseAccepted_wrongRejected() {
        for (int t = 0; t < 20; t++) {
            BigInteger a = randNonZero();
            BigInteger inv = a.modInverse(P);
            assertTrue(accepts(a, inv), "the true inverse must be accepted");
            // Any other candidate (inv+1, inv-1, a random one, 0) must be rejected.
            assertFalse(accepts(a, inv.add(BigInteger.ONE).mod(P)), "inv+1 must be rejected");
            assertFalse(accepts(a, inv.subtract(BigInteger.ONE).mod(P)), "inv-1 must be rejected");
            assertFalse(accepts(a, randNonZero()), "a random candidate must be rejected");
            assertFalse(accepts(a, BigInteger.ZERO), "zero candidate must be rejected");
        }
    }
}
