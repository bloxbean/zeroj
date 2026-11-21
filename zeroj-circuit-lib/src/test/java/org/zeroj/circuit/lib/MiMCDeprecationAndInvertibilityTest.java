package org.zeroj.circuit.lib;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.lib.zk.ZkMerkle;
import org.zeroj.circuit.lib.zk.ZkMiMC;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the entire legacy MiMC gadget family is marked
 * {@code @Deprecated(forRemoval = true)} and documents the exact algebraic
 * invertibility / collision-forgery property that motivates removal.
 */
@SuppressWarnings("removal")
class MiMCDeprecationAndInvertibilityTest {

    private static final BigInteger BN254_FR = FieldConfig.BN254.prime();
    private static final BigInteger INV_SEVEN =
            BigInteger.valueOf(7).modInverse(BN254_FR.subtract(BigInteger.ONE));

    @Test
    void allLegacyMiMCSymbolsAreDeprecatedForRemoval() throws Exception {
        assertDeprecatedForRemoval(MiMC.class);
        assertDeprecatedForRemoval(SignalMiMC.class);
        assertDeprecatedForRemoval(MiMCSponge.class);
        assertDeprecatedForRemoval(ZkMiMC.class);

        Field mimcEnum = ZkMerkle.HashType.class.getField("MIMC");
        Deprecated dep = mimcEnum.getAnnotation(Deprecated.class);
        assertNotNull(dep, "ZkMerkle.HashType.MIMC must be @Deprecated");
        assertTrue(dep.forRemoval(), "ZkMerkle.HashType.MIMC must have forRemoval = true");
    }

    @Test
    void mimcHashIsTriviallyInvertibleAndCollisionForgeableInR1cs() {
        var circuit = CircuitBuilder.create("mimc-invertibility-proof")
                .publicVar("out")
                .secretVar("left")
                .secretVar("right")
                .define(api -> {
                    var h = MiMC.hash(api, api.var("left"), api.var("right"));
                    api.assertEqual(h, api.var("out"));
                });

        var r1cs = circuit.compileR1CS(CurveId.BN254);

        BigInteger target = new BigInteger("123456789012345678901234567890");
        BigInteger right1 = BigInteger.valueOf(17);
        BigInteger right2 = BigInteger.valueOf(42);

        BigInteger forgedLeft1 = invertMiMC(target, right1);
        BigInteger forgedLeft2 = invertMiMC(target, right2);

        assertNotEquals(forgedLeft1, forgedLeft2,
                "Distinct keys must yield distinct forged preimages for the same target");

        BigInteger[] w1 = circuit.calculateWitness(Map.of(
                "out", List.of(target),
                "left", List.of(forgedLeft1),
                "right", List.of(right1)
        ), CurveId.BN254);
        BigInteger[] w2 = circuit.calculateWitness(Map.of(
                "out", List.of(target),
                "left", List.of(forgedLeft2),
                "right", List.of(right2)
        ), CurveId.BN254);

        assertAllConstraintsSatisfied(r1cs, w1);
        assertAllConstraintsSatisfied(r1cs, w2);
        assertEquals(target, w1[1]);
        assertEquals(target, w2[1]);
    }

    private static void assertAllConstraintsSatisfied(R1CSConstraintSystem r1cs, BigInteger[] w) {
        BigInteger p = r1cs.prime();
        for (R1CSConstraint c : r1cs.constraints()) {
            BigInteger a = dot(c.a(), w, p);
            BigInteger b = dot(c.b(), w, p);
            BigInteger rhs = dot(c.c(), w, p);
            assertEquals(rhs, a.multiply(b).mod(p), "Every R1CS constraint must hold");
        }
    }

    private static BigInteger dot(Map<Integer, BigInteger> vec, BigInteger[] w, BigInteger p) {
        BigInteger sum = BigInteger.ZERO;
        for (Map.Entry<Integer, BigInteger> e : vec.entrySet()) {
            sum = sum.add(e.getValue().multiply(w[e.getKey()])).mod(p);
        }
        return sum;
    }

    private static BigInteger invertMiMC(BigInteger target, BigInteger key) {
        BigInteger state = target.subtract(key).mod(BN254_FR);
        for (int i = 90; i >= 0; i--) {
            BigInteger t = state.modPow(INV_SEVEN, BN254_FR);
            BigInteger rc = MiMC.roundConstant(i).mod(BN254_FR);
            state = t.subtract(rc).subtract(key).mod(BN254_FR);
        }
        return state;
    }

    private static void assertDeprecatedForRemoval(Class<?> type) {
        Deprecated dep = type.getAnnotation(Deprecated.class);
        assertNotNull(dep, type.getName() + " must be @Deprecated");
        assertTrue(dep.forRemoval(), type.getName() + " must have forRemoval = true");
    }
}
