package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
class TempWin {
    static int c(CircuitBuilder b){ return b.compileR1CS(CurveId.BLS12_381).constraints().size(); }
    @Test void w() {
        var g = JubjubPoint.SUBGROUP_GENERATOR;
        System.out.println("WIN bitwise 252  = " + c(CircuitBuilder.create("bw").secretVar("k")
            .define(api -> InCircuitJubjub.scalarMulFixedBase(api, g, api.var("k"), 252))));
        System.out.println("WIN windowed 252 = " + c(CircuitBuilder.create("ww").secretVar("k")
            .define(api -> InCircuitJubjub.scalarMulFixedBaseWindowed(api, g, api.decompose(api.var("k"), 252).bits()))));
        // correctness: windowed must equal off-circuit for several scalars
        for (BigInteger k : new BigInteger[]{BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(7),
                BigInteger.valueOf(8), BigInteger.valueOf(123456789L),
                JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE)}) {
            var exp = g.scalarMul(k);
            var circ = CircuitBuilder.create("wc"+k).publicVar("ou").publicVar("ov").secretVar("k")
                .define(api -> { var r = InCircuitJubjub.scalarMulFixedBaseWindowed(api, g,
                        api.decompose(api.var("k"), 252).bits());
                    api.assertEqual(api.mul(api.var("ou"), r.z()), r.u());
                    api.assertEqual(api.mul(api.var("ov"), r.z()), r.v()); });
            try { circ.calculateWitness(Map.of("ou", List.of(exp.affineU()),
                    "ov", List.of(exp.affineV()), "k", List.of(k)), CurveId.BLS12_381);
                System.out.println("WIN ok k=" + k);
            } catch (Exception e) { System.out.println("WIN FAIL k=" + k + " " + e); }
        }
    }
}
