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
import java.util.function.BinaryOperator;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exhaustive correctness tests for the {@link Fe25519} non-native field gadget.
 *
 * <p>Every operation is cross-checked, over many random operands plus boundary values, against
 * {@link BigInteger} arithmetic mod {@code p = 2^255 - 19}. The circuit computes the op, takes
 * the canonical representative, and asserts its 5 limbs equal the BigInteger result's limbs — so
 * a satisfied witness is a proof of equality. This is the audit-critical gadget; the harness is
 * deliberately broad (random + edge + the [p, 2^255) canonicalization window + negative tests).
 */
class Fe25519Test {

    private static final BigInteger P = Fe25519.P;
    private static final Random RND = new Random(0xED25519L);

    /** Interesting field values to always include. */
    private static List<BigInteger> edgeValues() {
        List<BigInteger> v = new ArrayList<>();
        v.add(BigInteger.ZERO);
        v.add(BigInteger.ONE);
        v.add(BigInteger.TWO);
        v.add(P.subtract(BigInteger.ONE));      // p-1
        v.add(P.subtract(BigInteger.TWO));      // p-2
        v.add(BigInteger.ONE.shiftLeft(51));    // limb boundary
        v.add(BigInteger.ONE.shiftLeft(51).subtract(BigInteger.ONE));
        v.add(BigInteger.ONE.shiftLeft(204));   // top-limb boundary
        v.add(BigInteger.valueOf(19));
        v.add(P.subtract(BigInteger.valueOf(19)));
        return v;
    }

    private static BigInteger randFe() {
        return new BigInteger(255, RND).mod(P);
    }

    // ------------------------------------------------------------------
    // Binary-op harness: assert op(a,b) == expected (mod p) via canonical limbs
    // ------------------------------------------------------------------

    private interface FeBin { Fe25519 apply(Fe25519 a, Fe25519 b); }

    private static void checkBinary(String name, FeBin circuitOp, BinaryOperator<BigInteger> ref,
                                    BigInteger a, BigInteger b, CurveId curve) {
        BigInteger expected = ref.apply(a, b).mod(P);
        BigInteger[] al = Fe25519.toLimbValues(a);
        BigInteger[] bl = Fe25519.toLimbValues(b);
        BigInteger[] el = Fe25519.toLimbValues(expected);

        var builder = CircuitBuilder.create(name);
        for (int i = 0; i < 5; i++) builder.secretVar("a" + i);
        for (int i = 0; i < 5; i++) builder.secretVar("b" + i);
        for (int i = 0; i < 5; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Variable[] av = new Variable[5], bv = new Variable[5];
            for (int i = 0; i < 5; i++) av[i] = api.var("a" + i);
            for (int i = 0; i < 5; i++) bv[i] = api.var("b" + i);
            Fe25519 fa = Fe25519.ofLimbsChecked(api, av);
            Fe25519 fb = Fe25519.ofLimbsChecked(api, bv);
            Fe25519 r = circuitOp.apply(fa, fb).canonical();
            Variable[] rl = r.limbs();
            for (int i = 0; i < 5; i++) api.assertEqual(rl[i], api.var("e" + i));
        });

        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < 5; i++) in.put("a" + i, List.of(al[i]));
        for (int i = 0; i < 5; i++) in.put("b" + i, List.of(bl[i]));
        for (int i = 0; i < 5; i++) in.put("e" + i, List.of(el[i]));
        assertDoesNotThrow(() -> builder.calculateWitness(in, curve),
                name + " mismatch: a=" + a + " b=" + b);
    }

    @Test
    void add_matchesBigInteger() {
        for (BigInteger a : edgeValues())
            for (BigInteger b : edgeValues())
                checkBinary("fe-add", Fe25519::add, BigInteger::add, a, b, CurveId.BN254);
        for (int t = 0; t < 40; t++)
            checkBinary("fe-add", Fe25519::add, BigInteger::add, randFe(), randFe(), CurveId.BN254);
    }

    @Test
    void sub_matchesBigInteger() {
        for (BigInteger a : edgeValues())
            for (BigInteger b : edgeValues())
                checkBinary("fe-sub", Fe25519::sub, BigInteger::subtract, a, b, CurveId.BN254);
        for (int t = 0; t < 40; t++)
            checkBinary("fe-sub", Fe25519::sub, BigInteger::subtract, randFe(), randFe(), CurveId.BN254);
    }

    @Test
    void mul_matchesBigInteger() {
        for (BigInteger a : edgeValues())
            for (BigInteger b : edgeValues())
                checkBinary("fe-mul", Fe25519::mul, BigInteger::multiply, a, b, CurveId.BN254);
        for (int t = 0; t < 40; t++)
            checkBinary("fe-mul", Fe25519::mul, BigInteger::multiply, randFe(), randFe(), CurveId.BN254);
    }

    @Test
    void square_matchesBigInteger() {
        for (BigInteger a : edgeValues())
            checkBinary("fe-sq", (x, y) -> x.square(), (x, y) -> x.multiply(x), a, a, CurveId.BN254);
        for (int t = 0; t < 20; t++) {
            BigInteger a = randFe();
            checkBinary("fe-sq", (x, y) -> x.square(), (x, y) -> x.multiply(x), a, a, CurveId.BN254);
        }
    }

    @Test
    void inverse_matchesBigInteger() {
        // a^-1 == a.modInverse(p). One in-circuit Fermat inverse is ~3M constraints (255 squarings),
        // so keep this to a couple of values — it exercises mul/square composition end-to-end.
        for (BigInteger a : new BigInteger[]{BigInteger.TWO, randFe().max(BigInteger.ONE)}) {
            checkBinary("fe-inv", (x, y) -> x.inverse(), (x, y) -> x.modInverse(P), a, a, CurveId.BN254);
        }
    }

    // ------------------------------------------------------------------
    // Canonicalization: values in [p, 2^255) must reduce to [0, p)
    // ------------------------------------------------------------------

    @Test
    void canonical_reducesAboveP() {
        // Feed limbs encoding a value v in [p, 2^255) directly and check canonical == v - p.
        for (int k = 0; k < 19; k++) {
            BigInteger v = P.add(BigInteger.valueOf(k)); // p .. p+18  (all < 2^255)
            BigInteger expected = v.mod(P);              // == k
            BigInteger[] vl = splitRaw(v);               // raw 5×51 limbs (v < 2^255, limbs < 2^51)
            BigInteger[] el = Fe25519.toLimbValues(expected);

            var builder = CircuitBuilder.create("fe-canon-" + k);
            for (int i = 0; i < 5; i++) builder.secretVar("v" + i);
            for (int i = 0; i < 5; i++) builder.publicVar("e" + i);
            builder.define(api -> {
                Variable[] vv = new Variable[5];
                for (int i = 0; i < 5; i++) vv[i] = api.var("v" + i);
                Fe25519 r = Fe25519.ofLimbsChecked(api, vv).canonical();
                Variable[] rl = r.limbs();
                for (int i = 0; i < 5; i++) api.assertEqual(rl[i], api.var("e" + i));
            });
            Map<String, List<BigInteger>> in = new HashMap<>();
            for (int i = 0; i < 5; i++) in.put("v" + i, List.of(vl[i]));
            for (int i = 0; i < 5; i++) in.put("e" + i, List.of(el[i]));
            assertDoesNotThrow(() -> builder.calculateWitness(in, CurveId.BN254), "canonical failed for v=p+" + k);
        }
    }

    // ------------------------------------------------------------------
    // Field-agnostic + negative
    // ------------------------------------------------------------------

    @Test
    void worksOnBls12381() {
        BigInteger a = randFe(), b = randFe();
        checkBinary("fe-mul-bls", Fe25519::mul, BigInteger::multiply, a, b, CurveId.BLS12_381);
        checkBinary("fe-sub-bls", Fe25519::sub, BigInteger::subtract, a, b, CurveId.BLS12_381);
    }

    @Test
    void wrongResult_fails() {
        BigInteger a = BigInteger.valueOf(123456789), b = BigInteger.valueOf(987654321);
        BigInteger wrong = a.multiply(b).mod(P).add(BigInteger.ONE).mod(P);
        BigInteger[] al = Fe25519.toLimbValues(a), bl = Fe25519.toLimbValues(b), el = Fe25519.toLimbValues(wrong);

        var builder = CircuitBuilder.create("fe-neg");
        for (int i = 0; i < 5; i++) builder.secretVar("a" + i);
        for (int i = 0; i < 5; i++) builder.secretVar("b" + i);
        for (int i = 0; i < 5; i++) builder.publicVar("e" + i);
        builder.define(api -> {
            Variable[] av = new Variable[5], bv = new Variable[5];
            for (int i = 0; i < 5; i++) av[i] = api.var("a" + i);
            for (int i = 0; i < 5; i++) bv[i] = api.var("b" + i);
            Fe25519 r = Fe25519.ofLimbsChecked(api, av).mul(Fe25519.ofLimbsChecked(api, bv)).canonical();
            Variable[] rl = r.limbs();
            for (int i = 0; i < 5; i++) api.assertEqual(rl[i], api.var("e" + i));
        });
        Map<String, List<BigInteger>> in = new HashMap<>();
        for (int i = 0; i < 5; i++) in.put("a" + i, List.of(al[i]));
        for (int i = 0; i < 5; i++) in.put("b" + i, List.of(bl[i]));
        for (int i = 0; i < 5; i++) in.put("e" + i, List.of(el[i]));
        assertThrows(ArithmeticException.class, () -> builder.calculateWitness(in, CurveId.BN254));
    }

    @Test
    void constraintCount_mul_reported() {
        var builder = CircuitBuilder.create("fe-mul-cost");
        for (int i = 0; i < 5; i++) builder.secretVar("a" + i);
        for (int i = 0; i < 5; i++) builder.secretVar("b" + i);
        builder.define(api -> {
            Variable[] av = new Variable[5], bv = new Variable[5];
            for (int i = 0; i < 5; i++) av[i] = api.var("a" + i);
            for (int i = 0; i < 5; i++) bv[i] = api.var("b" + i);
            Fe25519.ofLimbsTrusted(api, av).mul(Fe25519.ofLimbsTrusted(api, bv));
        });
        int c = builder.compileR1CS(CurveId.BN254).numConstraints();
        System.out.println("[ADR-0027 M4] Fe25519 mul constraints = " + c);
        assertTrue(c > 0 && c < 20_000, "unexpected mul cost: " + c);
    }

    // raw split of a value < 2^255 into 5 limbs of 51 bits (no mod-p reduction)
    private static BigInteger[] splitRaw(BigInteger v) {
        BigInteger mask = BigInteger.ONE.shiftLeft(51).subtract(BigInteger.ONE);
        BigInteger[] out = new BigInteger[5];
        for (int i = 0; i < 5; i++) { out[i] = v.and(mask); v = v.shiftRight(51); }
        return out;
    }
}
