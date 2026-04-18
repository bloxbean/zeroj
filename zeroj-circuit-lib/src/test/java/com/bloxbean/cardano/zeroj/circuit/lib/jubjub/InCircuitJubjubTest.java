package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Self-consistency tests for {@link InCircuitJubjub}.
 *
 * <p>Strategy: for each operation (add, double, fixed-base scalar-mul), compute
 * the expected output via the already-verified off-circuit {@link JubjubPoint}
 * (which matches zkcrypto byte-for-byte), build a circuit that computes the
 * same operation in-gadget, assert the circuit output equals the expected
 * output via {@code api.assertEqual}. If in-circuit and off-circuit disagree,
 * {@code calculateWitness} throws.
 *
 * <p>This closes the spec-to-circuit gap: the off-circuit implementation is
 * anchored to the zkcrypto/Zcash spec; the circuit is anchored to the off-
 * circuit implementation.
 */
class InCircuitJubjubTest {

    @Test
    @DisplayName("In-circuit add(P, Q) matches off-circuit JubjubPoint.add for random scalars")
    void inCircuit_add_matchesOffCircuit() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        for (int i = 1; i <= 5; i++) {
            JubjubPoint p = g.scalarMul(BigInteger.valueOf(i * 13L));
            JubjubPoint q = g.scalarMul(BigInteger.valueOf(i * 27L));
            JubjubPoint expected = p.add(q);

            BigInteger expectedU = expected.affineU();
            BigInteger expectedV = expected.affineV();

            var circuit = CircuitBuilder.create("jubjub_add_" + i)
                    .publicVar("outU").publicVar("outV")
                    .secretVar("pu").secretVar("pv").secretVar("pz").secretVar("pt")
                    .secretVar("qu").secretVar("qv").secretVar("qz").secretVar("qt")
                    .define(api -> {
                        var pIn = new InCircuitJubjub.Point(
                                api.var("pu"), api.var("pv"), api.var("pz"), api.var("pt"));
                        var qIn = new InCircuitJubjub.Point(
                                api.var("qu"), api.var("qv"), api.var("qz"), api.var("qt"));
                        var sum = InCircuitJubjub.add(api, pIn, qIn);
                        // Extract affine: outU · sum.z == sum.u and outV · sum.z == sum.v
                        var outU = api.var("outU");
                        var outV = api.var("outV");
                        api.assertEqual(api.mul(outU, sum.z()), sum.u());
                        api.assertEqual(api.mul(outV, sum.z()), sum.v());
                    });

            final int iter = i;
            assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                    "outU", List.of(expectedU),
                    "outV", List.of(expectedV),
                    "pu", List.of(p.u()), "pv", List.of(p.v()), "pz", List.of(p.z()), "pt", List.of(p.t()),
                    "qu", List.of(q.u()), "qv", List.of(q.v()), "qz", List.of(q.z()), "qt", List.of(q.t())
            ), CurveId.BLS12_381), () -> "Iter " + iter);
        }
    }

    @Test
    @DisplayName("In-circuit doubled(P) matches off-circuit JubjubPoint.doubled for random scalars")
    void inCircuit_doubled_matchesOffCircuit() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        for (int i = 1; i <= 5; i++) {
            JubjubPoint p = g.scalarMul(BigInteger.valueOf(i * 101L));
            JubjubPoint expected = p.doubled();

            BigInteger expectedU = expected.affineU();
            BigInteger expectedV = expected.affineV();

            var circuit = CircuitBuilder.create("jubjub_double_" + i)
                    .publicVar("outU").publicVar("outV")
                    .secretVar("pu").secretVar("pv").secretVar("pz").secretVar("pt")
                    .define(api -> {
                        var pIn = new InCircuitJubjub.Point(
                                api.var("pu"), api.var("pv"), api.var("pz"), api.var("pt"));
                        var dbl = InCircuitJubjub.doubled(api, pIn);
                        api.assertEqual(api.mul(api.var("outU"), dbl.z()), dbl.u());
                        api.assertEqual(api.mul(api.var("outV"), dbl.z()), dbl.v());
                    });

            final int iter = i;
            assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                    "outU", List.of(expectedU),
                    "outV", List.of(expectedV),
                    "pu", List.of(p.u()), "pv", List.of(p.v()),
                    "pz", List.of(p.z()), "pt", List.of(p.t())
            ), CurveId.BLS12_381), () -> "Iter " + iter);
        }
    }

    @Test
    @DisplayName("In-circuit fixed-base scalarMul matches off-circuit [k]·G for small scalars")
    void inCircuit_scalarMulFixedBase_matchesOffCircuit_small() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        BigInteger[] scalars = {
                BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(7),
                BigInteger.valueOf(42), BigInteger.valueOf(1000),
                BigInteger.valueOf(123456789L)
        };
        for (BigInteger k : scalars) {
            JubjubPoint expected = g.scalarMul(k);
            BigInteger expectedU = expected.affineU();
            BigInteger expectedV = expected.affineV();

            var circuit = CircuitBuilder.create("jubjub_smul_" + k)
                    .publicVar("outU").publicVar("outV").secretVar("k")
                    .define(api -> {
                        // 32-bit is plenty for these small test scalars.
                        var res = InCircuitJubjub.scalarMulFixedBase(api, g, api.var("k"), 32);
                        api.assertEqual(api.mul(api.var("outU"), res.z()), res.u());
                        api.assertEqual(api.mul(api.var("outV"), res.z()), res.v());
                    });

            assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                    "outU", List.of(expectedU),
                    "outV", List.of(expectedV),
                    "k", List.of(k)
            ), CurveId.BLS12_381), () -> "[k]·G for k=" + k);
        }
    }

    @Test
    @DisplayName("In-circuit fixed-base scalarMul requires correct expected output (wrong hash fails)")
    void inCircuit_scalarMulFixedBase_rejectsWrongOutput() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        var circuit = CircuitBuilder.create("jubjub_smul_neg")
                .publicVar("outU").publicVar("outV").secretVar("k")
                .define(api -> {
                    var res = InCircuitJubjub.scalarMulFixedBase(api, g, api.var("k"), 16);
                    api.assertEqual(api.mul(api.var("outU"), res.z()), res.u());
                    api.assertEqual(api.mul(api.var("outV"), res.z()), res.v());
                });

        // Wrong expected output — calculation should fail.
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "outU", List.of(BigInteger.valueOf(999)),
                "outV", List.of(BigInteger.valueOf(888)),
                "k", List.of(BigInteger.valueOf(5))
        ), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("In-circuit fixed-base scalarMul: k=0 returns identity")
    void inCircuit_scalarMulFixedBase_kZero() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        var circuit = CircuitBuilder.create("jubjub_smul_zero")
                .publicVar("outU").publicVar("outV").secretVar("k")
                .define(api -> {
                    var res = InCircuitJubjub.scalarMulFixedBase(api, g, api.var("k"), 16);
                    api.assertEqual(api.mul(api.var("outU"), res.z()), res.u());
                    api.assertEqual(api.mul(api.var("outV"), res.z()), res.v());
                });
        // [0]·G = IDENTITY = affine (0, 1).
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(BigInteger.ZERO),
                "outV", List.of(BigInteger.ONE),
                "k", List.of(BigInteger.ZERO)
        ), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("In-circuit fixed-base scalarMul: full 252-bit scalar matches off-circuit")
    void inCircuit_scalarMulFixedBase_fullWidth() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        // A scalar with the top 252-bit set to exercise the highest bit.
        BigInteger k = JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE);
        JubjubPoint expected = g.scalarMul(k);

        var circuit = CircuitBuilder.create("jubjub_smul_252bit")
                .publicVar("outU").publicVar("outV").secretVar("k")
                .define(api -> {
                    var res = InCircuitJubjub.scalarMulFixedBase(api, g, api.var("k"), 252);
                    api.assertEqual(api.mul(api.var("outU"), res.z()), res.u());
                    api.assertEqual(api.mul(api.var("outV"), res.z()), res.v());
                });
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(expected.affineU()),
                "outV", List.of(expected.affineV()),
                "k", List.of(k)
        ), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("In-circuit variable-base scalarMul [k]·P matches off-circuit for random k, P")
    void inCircuit_scalarMulVariableBase_matchesOffCircuit() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        // Use P = [37]·G (a non-trivial subgroup point) as the variable base.
        JubjubPoint p = g.scalarMul(BigInteger.valueOf(37));
        for (BigInteger k : new BigInteger[]{
                BigInteger.ONE, BigInteger.TWO, BigInteger.valueOf(99),
                BigInteger.valueOf(1234567L)
        }) {
            JubjubPoint expected = p.scalarMul(k);

            var circuit = CircuitBuilder.create("jubjub_varsmul_" + k)
                    .publicVar("outU").publicVar("outV")
                    .secretVar("pu").secretVar("pv").secretVar("pz").secretVar("pt")
                    .secretVar("k")
                    .define(api -> {
                        var pIn = new InCircuitJubjub.Point(
                                api.var("pu"), api.var("pv"), api.var("pz"), api.var("pt"));
                        var res = InCircuitJubjub.scalarMulVariableBase(api, pIn, api.var("k"), 32);
                        api.assertEqual(api.mul(api.var("outU"), res.z()), res.u());
                        api.assertEqual(api.mul(api.var("outV"), res.z()), res.v());
                    });
            assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                    "outU", List.of(expected.affineU()),
                    "outV", List.of(expected.affineV()),
                    "pu", List.of(p.u()), "pv", List.of(p.v()),
                    "pz", List.of(p.z()), "pt", List.of(p.t()),
                    "k", List.of(k)
            ), CurveId.BLS12_381), () -> "Variable-base [" + k + "]·P");
        }
    }

    @Test
    @DisplayName("In-circuit variable-base scalarMul: full 252-bit scalar matches off-circuit")
    void inCircuit_scalarMulVariableBase_fullWidth() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        JubjubPoint p = g.scalarMul(BigInteger.valueOf(37));
        BigInteger k = JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE);
        JubjubPoint expected = p.scalarMul(k);

        var circuit = CircuitBuilder.create("jubjub_varsmul_252")
                .publicVar("outU").publicVar("outV")
                .secretVar("pu").secretVar("pv").secretVar("pz").secretVar("pt")
                .secretVar("k")
                .define(api -> {
                    var pIn = new InCircuitJubjub.Point(
                            api.var("pu"), api.var("pv"), api.var("pz"), api.var("pt"));
                    var res = InCircuitJubjub.scalarMulVariableBase(api, pIn, api.var("k"), 252);
                    api.assertEqual(api.mul(api.var("outU"), res.z()), res.u());
                    api.assertEqual(api.mul(api.var("outV"), res.z()), res.v());
                });
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(expected.affineU()),
                "outV", List.of(expected.affineV()),
                "pu", List.of(p.u()), "pv", List.of(p.v()),
                "pz", List.of(p.z()), "pt", List.of(p.t()),
                "k", List.of(k)
        ), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("In-circuit P + (-P) = IDENTITY (unified add handles identity boundary)")
    void inCircuit_pointPlusNegation_isIdentity() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        JubjubPoint p = g.scalarMul(BigInteger.valueOf(42));
        JubjubPoint negP = p.negate();

        var circuit = CircuitBuilder.create("jubjub_pMinusP")
                .publicVar("outU").publicVar("outV")
                .secretVar("pu").secretVar("pv").secretVar("pz").secretVar("pt")
                .secretVar("nu").secretVar("nv").secretVar("nz").secretVar("nt")
                .define(api -> {
                    var pIn = new InCircuitJubjub.Point(
                            api.var("pu"), api.var("pv"), api.var("pz"), api.var("pt"));
                    var nIn = new InCircuitJubjub.Point(
                            api.var("nu"), api.var("nv"), api.var("nz"), api.var("nt"));
                    var sum = InCircuitJubjub.add(api, pIn, nIn);
                    // Assert affine (outU, outV) == (0, 1).
                    api.assertEqual(api.mul(api.var("outU"), sum.z()), sum.u());
                    api.assertEqual(api.mul(api.var("outV"), sum.z()), sum.v());
                });
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(BigInteger.ZERO),
                "outV", List.of(BigInteger.ONE),
                "pu", List.of(p.u()), "pv", List.of(p.v()),
                "pz", List.of(p.z()), "pt", List.of(p.t()),
                "nu", List.of(negP.u()), "nv", List.of(negP.v()),
                "nz", List.of(negP.z()), "nt", List.of(negP.t())
        ), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("Field guard: Jubjub gadget called under BN254 compile throws")
    void fieldGuard_jubjubUnderBn254_throws() {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        var circuit = CircuitBuilder.create("jubjub_field_guard")
                .publicVar("outU").publicVar("outV").secretVar("k")
                .define(api -> {
                    var res = InCircuitJubjub.scalarMulFixedBase(api, g, api.var("k"), 8);
                    api.assertEqual(api.var("outU"), res.u());
                    api.assertEqual(api.var("outV"), res.v());
                });

        // Jubjub only makes sense over BLS12-381 scalar field. Guard must fire.
        assertThrows(IllegalStateException.class, () -> circuit.calculateWitness(Map.of(
                "outU", List.of(BigInteger.ZERO),
                "outV", List.of(BigInteger.ONE),
                "k", List.of(BigInteger.ZERO)
        ), CurveId.BN254));
    }
}
