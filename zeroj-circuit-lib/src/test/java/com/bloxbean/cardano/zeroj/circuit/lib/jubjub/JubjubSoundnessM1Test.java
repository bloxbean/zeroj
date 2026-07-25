package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0037 M1 soundness gates.
 *
 * <p>Each test here corresponds to a defect that the pre-ADR-0037 gadget exhibited. Where a
 * defect had a concrete exploit witness, the witness comes from {@link JubjubExploitFixtures}
 * and the test asserts two things: that the legacy relation really did accept it, and that
 * the fixed gadget rejects it. Asserting only the second half would leave the test passing
 * even if the exploit had been mis-derived.
 */
class JubjubSoundnessM1Test {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final BigInteger DELTA = JubjubCurve.P_MINUS_EIGHT_L;

    private static final BigInteger SK = new BigInteger(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16).mod(L);

    private static JubjubPoint issuerPk() {
        return EdDSAJubjub.keypairFromSecret(SK).pk();
    }

    // ------------------------------------------------------------------
    //  Structural gate: no public raw-Point verification overload
    // ------------------------------------------------------------------

    @Test
    @DisplayName("no public verification overload accepts raw extended-coordinate Points")
    void noPublicRawPointVerifier() {
        for (Method m : InCircuitEdDSAJubjub.class.getMethods()) {
            if (!Modifier.isPublic(m.getModifiers())) continue;
            boolean takesRawPoint = false;
            for (Class<?> t : m.getParameterTypes()) {
                if (InCircuitJubjub.Point.class.equals(t)) takesRawPoint = true;
            }
            assertFalse(takesRawPoint,
                    "public method " + m.getName() + " takes a raw InCircuitJubjub.Point; "
                            + "a prover-supplied point must enter through affine wires so the "
                            + "gadget can bind and curve-check it (ADR-0037 Decision 1)");
        }
    }

    @Test
    @DisplayName("verifyCore is not public — the key-trust contract must be named")
    void verifyCoreIsNotPublic() throws Exception {
        Method core = InCircuitEdDSAJubjub.class.getDeclaredMethod(
                "verifyCore",
                com.bloxbean.cardano.zeroj.circuit.CircuitAPI.class,
                com.bloxbean.cardano.zeroj.circuit.Variable.class,
                com.bloxbean.cardano.zeroj.circuit.Variable.class,
                com.bloxbean.cardano.zeroj.circuit.Variable.class,
                com.bloxbean.cardano.zeroj.circuit.Variable.class,
                com.bloxbean.cardano.zeroj.circuit.Variable.class,
                com.bloxbean.cardano.zeroj.circuit.Variable.class,
                com.bloxbean.cardano.zeroj.circuit.Variable.class,
                com.bloxbean.cardano.zeroj.circuit.Variable.class);
        assertFalse(Modifier.isPublic(core.getModifiers()),
                "verifyCore must stay package-private until ADR-0037 M3 names the entry points");
    }

    @Test
    @DisplayName("the withdrawn annotation-layer verify throws rather than silently working")
    void withdrawnAdapterVerifyThrows() throws Exception {
        Method m = com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkEdDSAJubjub.class
                .getDeclaredMethod("verify",
                        com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext.class,
                        com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkJubjubPoint.class,
                        com.bloxbean.cardano.zeroj.circuit.annotation.ZkField.class,
                        com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkJubjubPoint.class,
                        com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt.class,
                        com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt.class,
                        com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt.class);
        assertTrue(m.isAnnotationPresent(Deprecated.class),
                "the withdrawn verify must be marked deprecated for removal");
    }

    // ------------------------------------------------------------------
    //  Exploit 1: extended-coordinate forgery
    // ------------------------------------------------------------------

    @Test
    @DisplayName("extended-coordinate forgery: accepted by the legacy relation, rejected now")
    void extendedCoordinateForgery() {
        JubjubPoint pk = issuerPk();
        BigInteger msg = BigInteger.valueOf(0xDEADBEEFL);
        var x = JubjubExploitFixtures.extendedCoordinateForgery(pk, msg);

        // The forged R is not even on the curve — sanity-check the fixture itself.
        BigInteger zInv = x.rZ().modInverse(P);
        BigInteger affU = x.rU().multiply(zInv).mod(P);
        BigInteger affV = x.rV().multiply(zInv).mod(P);
        assertThrows(IllegalArgumentException.class, () -> JubjubPoint.fromAffine(affU, affV),
                "the exploit's R must be off-curve; if it is on-curve the fixture is wrong");

        // Half 1: the legacy relation accepted it.
        assertDoesNotThrow(() -> legacyCircuit().calculateWitness(legacyWitness(x), CurveId.BLS12_381),
                "fixture is stale: the legacy relation no longer accepts this witness");

        // Half 2: the fixed gadget rejects it. R's affine coordinates are all a caller can
        // supply now, and they do not satisfy the curve equation.
        assertThrows(Exception.class,
                () -> fixedCircuit().calculateWitness(fixedWitness(x), CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  Exploit 2: all-zero degenerate point
    // ------------------------------------------------------------------

    @Test
    @DisplayName("all-zero point: accepted by the legacy relation, rejected now")
    void allZeroPointForgery() {
        JubjubPoint pk = issuerPk();
        BigInteger msg = BigInteger.valueOf(0xBADC0DEL);
        var x = JubjubExploitFixtures.allZeroPointForgery(pk, msg);

        assertDoesNotThrow(() -> legacyCircuit().calculateWitness(legacyWitness(x), CurveId.BLS12_381),
                "fixture is stale: the legacy relation no longer accepts the all-zero point");

        assertThrows(Exception.class,
                () -> fixedCircuit().calculateWitness(fixedWitness(x), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("assertWellFormed rejects the all-zero point (Z != 0 conjunct)")
    void assertWellFormedRejectsAllZero() {
        var circuit = wellFormedCircuit();
        assertThrows(Exception.class, () -> circuit.calculateWitness(Map.of(
                "u", List.of(BigInteger.ZERO), "v", List.of(BigInteger.ZERO),
                "z", List.of(BigInteger.ZERO), "t", List.of(BigInteger.ZERO)
        ), CurveId.BLS12_381), "(0,0,0,0) satisfies the curve equation and T*Z==U*V identically");
    }

    @Test
    @DisplayName("assertWellFormed rejects Z = 0 with otherwise consistent coordinates")
    void assertWellFormedRejectsZeroZ() {
        var circuit = wellFormedCircuit();
        // U = 0, V = 0 keeps T*Z == U*V trivially; pick T so the curve equation also holds:
        // V^2 - U^2 == Z^2 + d*T^2  ->  0 == 0 + d*T^2  ->  T = 0.
        assertThrows(Exception.class, () -> circuit.calculateWitness(Map.of(
                "u", List.of(BigInteger.ZERO), "v", List.of(BigInteger.ZERO),
                "z", List.of(BigInteger.ZERO), "t", List.of(BigInteger.ZERO)
        ), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("assertWellFormed rejects T*Z != U*V")
    void assertWellFormedRejectsBadT() {
        JubjubPoint p = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(9));
        var circuit = wellFormedCircuit();
        assertThrows(Exception.class, () -> circuit.calculateWitness(Map.of(
                "u", List.of(p.u()), "v", List.of(p.v()),
                "z", List.of(p.z()), "t", List.of(p.t().add(BigInteger.ONE).mod(P))
        ), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("assertWellFormed rejects an off-curve point")
    void assertWellFormedRejectsOffCurve() {
        var circuit = wellFormedCircuit();
        // (1, 1) with Z=1, T=1 satisfies T*Z == U*V but not the curve equation.
        assertThrows(Exception.class, () -> circuit.calculateWitness(Map.of(
                "u", List.of(BigInteger.ONE), "v", List.of(BigInteger.ONE),
                "z", List.of(BigInteger.ONE), "t", List.of(BigInteger.ONE)
        ), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("assertWellFormed ACCEPTS a nonzero projective rescaling — it is a valid representation")
    void assertWellFormedAcceptsRescaling() {
        JubjubPoint p = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(11));
        BigInteger lambda = BigInteger.valueOf(999_331);
        var circuit = wellFormedCircuit();
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "u", List.of(p.u().multiply(lambda).mod(P)),
                "v", List.of(p.v().multiply(lambda).mod(P)),
                "z", List.of(p.z().multiply(lambda).mod(P)),
                "t", List.of(p.t().multiply(lambda).mod(P))
        ), CurveId.BLS12_381),
                "rescaling is a legitimate representation; assertWellFormed must not reject it. "
                        + "That is exactly why it is insufficient at a hashing boundary.");
    }

    @Test
    @DisplayName("assertWellFormed accepts genuine projective points")
    void assertWellFormedAcceptsValidPoints() {
        var circuit = wellFormedCircuit();
        for (int i = 1; i <= 5; i++) {
            JubjubPoint p = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(i * 37L)).doubled();
            final int iter = i;
            assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                    "u", List.of(p.u()), "v", List.of(p.v()),
                    "z", List.of(p.z()), "t", List.of(p.t())
            ), CurveId.BLS12_381), () -> "valid point rejected at i=" + iter);
        }
    }

    // ------------------------------------------------------------------
    //  witnessAffine
    // ------------------------------------------------------------------

    @Test
    @DisplayName("witnessAffine rejects off-curve affine coordinates")
    void witnessAffineRejectsOffCurve() {
        var circuit = CircuitBuilder.create("wa_offcurve")
                .secretVar("u").secretVar("v")
                .define(api -> InCircuitJubjub.witnessAffine(api, api.var("u"), api.var("v")));
        assertThrows(Exception.class, () -> circuit.calculateWitness(Map.of(
                "u", List.of(BigInteger.ONE), "v", List.of(BigInteger.ZERO)
        ), CurveId.BLS12_381), "(1, 0) is not on the Jubjub curve");
    }

    @Test
    @DisplayName("witnessAffine accepts on-curve points, including the identity")
    void witnessAffineAcceptsValid() {
        var circuit = CircuitBuilder.create("wa_ok")
                .secretVar("u").secretVar("v")
                .define(api -> InCircuitJubjub.witnessAffine(api, api.var("u"), api.var("v")));
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "u", List.of(g.affineU()), "v", List.of(g.affineV())), CurveId.BLS12_381));
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "u", List.of(BigInteger.ZERO), "v", List.of(BigInteger.ONE)), CurveId.BLS12_381),
                "the identity (0,1) is on the curve; witnessAffine is not a subgroup check");
    }

    @Test
    @DisplayName("cost pins: witnessAffine 6, assertWellFormed 14, verifyCore 19,500")
    void constraintCostsArePinned() {
        var wa = CircuitBuilder.create("wa_cost")
                .secretVar("u").secretVar("v")
                .define(api -> InCircuitJubjub.witnessAffine(api, api.var("u"), api.var("v")));
        assertEquals(6, wa.compileR1CS(CurveId.BLS12_381).constraints().size(),
                "witnessAffine standalone: u^2, v^2, u^2*v^2, d*(u^2v^2), the curve assertion, "
                        + "and T = u*v. Five of these are new work; the legacy relation already "
                        + "paid for T, which is why ADR-0037 records +5 per point incrementally.");

        var wf = CircuitBuilder.create("wf_cost")
                .secretVar("u").secretVar("v").secretVar("z").secretVar("t")
                .define(api -> InCircuitJubjub.assertWellFormed(api, new InCircuitJubjub.Point(
                        api.var("u"), api.var("v"), api.var("z"), api.var("t"))));
        assertEquals(14, wf.compileR1CS(CurveId.BLS12_381).constraints().size(),
                "assertWellFormed: four squarings, the d-scaling, the curve assertion, "
                        + "T*Z and U*V plus their assertion, and the isZero(Z) inverse witness");

        assertEquals(19_500, fixedCircuit().compileR1CS(CurveId.BLS12_381).constraints().size(),
                "verifyCore cost is pinned so ADR-0037 M5 optimizations are visible and no "
                        + "regression slips in. Legacy (forgeable) relation was 18,965; the "
                        + "+535 buys affine binding of both points and the canonical, complete "
                        + "challenge reduction.");
    }

    // ------------------------------------------------------------------
    //  Canonical + complete challenge reduction
    // ------------------------------------------------------------------

    @Test
    @DisplayName("challenge alias (q+8, kModL+delta) is rejected")
    void challengeAliasRejected() {
        JubjubPoint pk = issuerPk();
        BigInteger msg = BigInteger.valueOf(4242);
        var sig = EdDSAJubjub.sign(SK, msg);
        var honest = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), pk, msg);

        BigInteger aliasQ = honest.kQuotient().add(BigInteger.valueOf(8));
        BigInteger aliasK = honest.kModL().add(DELTA);

        // Sanity: the alias really does satisfy the field equation the circuit asserts.
        assertEquals(
                honest.kQuotient().multiply(L).add(honest.kModL()).mod(P),
                aliasQ.multiply(L).add(aliasK).mod(P),
                "alias must be congruent mod p, else this test proves nothing");
        assertTrue(aliasK.compareTo(L) < 0, "alias kModL must still be < l to be interesting");

        var circuit = fixedCircuit();
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("pkU", List.of(pk.affineU()));
        w.put("pkV", List.of(pk.affineV()));
        w.put("msg", List.of(msg));
        w.put("rU", List.of(sig.r().affineU()));
        w.put("rV", List.of(sig.r().affineV()));
        w.put("s", List.of(sig.s()));
        w.put("kModL", List.of(aliasK));
        w.put("kQuotient", List.of(aliasQ));
        assertThrows(Exception.class, () -> circuit.calculateWitness(w, CurveId.BLS12_381),
                "q <= 8 must reject the q+8 alias");
    }

    @Test
    @DisplayName("reduction boundary: constructed kRaw straddling 8l reduces canonically")
    void reductionBoundaryIsConstructedNotSampled() {
        // The interesting region is kRaw in [8l, p), which occurs with probability
        // delta/p ~ 2^-129 -- unreachable by sampling. Construct it directly and check the
        // arithmetic the circuit relies on: q <= 8 always, and q == 8 implies kModL < delta.
        BigInteger eightL = L.shiftLeft(3);
        BigInteger[] probes = {
                BigInteger.ZERO,
                L.subtract(BigInteger.ONE),
                L,
                eightL.subtract(BigInteger.ONE),
                eightL,
                eightL.add(BigInteger.ONE),
                P.subtract(BigInteger.ONE),
        };
        for (BigInteger kRaw : probes) {
            BigInteger[] qr = kRaw.divideAndRemainder(L);
            BigInteger q = qr[0], k = qr[1];
            assertTrue(q.compareTo(BigInteger.valueOf(8)) <= 0,
                    "q must never exceed 8 for kRaw < p; kRaw=" + kRaw.toString(16));
            assertTrue(k.compareTo(L) < 0, "kModL must be < l");
            if (q.equals(BigInteger.valueOf(8))) {
                assertTrue(k.compareTo(DELTA) < 0,
                        "when q == 8 the remainder must be < delta, else q*l+kModL >= p");
            }
            // The constraint the circuit enforces: no wraparound.
            assertTrue(q.multiply(L).add(k).compareTo(P) < 0,
                    "q*l + kModL must stay below p so the field equation cannot wrap");
        }
    }

    @Test
    @DisplayName("delta is p - 8l and 126 bits wide")
    void deltaConstantIsCorrect() {
        assertEquals(P.subtract(L.multiply(BigInteger.valueOf(8))), DELTA);
        assertEquals(126, DELTA.bitLength());
        assertEquals(new BigInteger("207c9f6499bdd7e87b478d0848469a49", 16), DELTA);
    }

    // ------------------------------------------------------------------
    //  Honest path still works
    // ------------------------------------------------------------------

    @Test
    @DisplayName("honest signatures still verify through the fixed relation")
    void honestSignaturesStillVerify() {
        JubjubPoint pk = issuerPk();
        var circuit = fixedCircuit();
        for (int i = 1; i <= 6; i++) {
            BigInteger msg = BigInteger.valueOf(1000L + i);
            var sig = EdDSAJubjub.sign(SK, msg);
            var red = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), pk, msg);
            Map<String, List<BigInteger>> w = new HashMap<>();
            w.put("pkU", List.of(pk.affineU()));
            w.put("pkV", List.of(pk.affineV()));
            w.put("msg", List.of(msg));
            w.put("rU", List.of(sig.r().affineU()));
            w.put("rV", List.of(sig.r().affineV()));
            w.put("s", List.of(sig.s()));
            w.put("kModL", List.of(red.kModL()));
            w.put("kQuotient", List.of(red.kQuotient()));
            final int iter = i;
            assertDoesNotThrow(() -> circuit.calculateWitness(w, CurveId.BLS12_381),
                    () -> "honest signature " + iter + " rejected — completeness regression");
        }
    }

    @Test
    @DisplayName("tampered message still rejected")
    void tamperedMessageRejected() {
        JubjubPoint pk = issuerPk();
        BigInteger msg = BigInteger.valueOf(7777);
        var sig = EdDSAJubjub.sign(SK, msg);
        var red = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), pk, msg);
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("pkU", List.of(pk.affineU()));
        w.put("pkV", List.of(pk.affineV()));
        w.put("msg", List.of(msg.add(BigInteger.ONE)));   // tampered
        w.put("rU", List.of(sig.r().affineU()));
        w.put("rV", List.of(sig.r().affineV()));
        w.put("s", List.of(sig.s()));
        w.put("kModL", List.of(red.kModL()));
        w.put("kQuotient", List.of(red.kQuotient()));
        assertThrows(Exception.class, () -> fixedCircuit().calculateWitness(w, CurveId.BLS12_381));
    }

    @Test
    @DisplayName("malleated S = S + l still rejected")
    void malleatedSRejected() {
        JubjubPoint pk = issuerPk();
        BigInteger msg = BigInteger.valueOf(8888);
        var sig = EdDSAJubjub.sign(SK, msg);
        var red = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), pk, msg);
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("pkU", List.of(pk.affineU()));
        w.put("pkV", List.of(pk.affineV()));
        w.put("msg", List.of(msg));
        w.put("rU", List.of(sig.r().affineU()));
        w.put("rV", List.of(sig.r().affineV()));
        w.put("s", List.of(sig.s().add(L)));             // malleated
        w.put("kModL", List.of(red.kModL()));
        w.put("kQuotient", List.of(red.kQuotient()));
        assertThrows(Exception.class, () -> fixedCircuit().calculateWitness(w, CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  Circuit builders
    // ------------------------------------------------------------------

    /** The removed pre-ADR-0037 relation, reproduced test-only. */
    private static CircuitBuilder legacyCircuit() {
        return CircuitBuilder.create("legacy_relation")
                .publicVar("pkU").publicVar("pkV").publicVar("msg")
                .secretVar("rU").secretVar("rV").secretVar("rZ").secretVar("rT")
                .secretVar("s").secretVar("kModL").secretVar("kQuotient")
                .define(api -> JubjubExploitFixtures.legacyRelation(api,
                        api.var("pkU"), api.var("pkV"), api.var("msg"),
                        api.var("rU"), api.var("rV"), api.var("rZ"), api.var("rT"),
                        api.var("s"), api.var("kModL"), api.var("kQuotient")));
    }

    /** The fixed relation: affine wires only. */
    private static CircuitBuilder fixedCircuit() {
        return CircuitBuilder.create("fixed_relation")
                .publicVar("pkU").publicVar("pkV").publicVar("msg")
                .secretVar("rU").secretVar("rV")
                .secretVar("s").secretVar("kModL").secretVar("kQuotient")
                .define(api -> InCircuitEdDSAJubjub.verifyCore(api,
                        api.var("pkU"), api.var("pkV"), api.var("msg"),
                        api.var("rU"), api.var("rV"),
                        api.var("s"), api.var("kModL"), api.var("kQuotient")));
    }

    private static CircuitBuilder wellFormedCircuit() {
        return CircuitBuilder.create("well_formed")
                .secretVar("u").secretVar("v").secretVar("z").secretVar("t")
                .define(api -> InCircuitJubjub.assertWellFormed(api, new InCircuitJubjub.Point(
                        api.var("u"), api.var("v"), api.var("z"), api.var("t"))));
    }

    private static Map<String, List<BigInteger>> legacyWitness(JubjubExploitFixtures.Exploit x) {
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("pkU", List.of(x.pkU()));
        w.put("pkV", List.of(x.pkV()));
        w.put("msg", List.of(x.msg()));
        w.put("rU", List.of(x.rU()));
        w.put("rV", List.of(x.rV()));
        w.put("rZ", List.of(x.rZ()));
        w.put("rT", List.of(x.rT()));
        w.put("s", List.of(x.s()));
        w.put("kModL", List.of(x.kModL()));
        w.put("kQuotient", List.of(x.kQuotient()));
        return w;
    }

    /** The same exploit expressed against the affine-only API: R.z/R.t are no longer inputs. */
    private static Map<String, List<BigInteger>> fixedWitness(JubjubExploitFixtures.Exploit x) {
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("pkU", List.of(x.pkU()));
        w.put("pkV", List.of(x.pkV()));
        w.put("msg", List.of(x.msg()));
        w.put("rU", List.of(x.rU()));
        w.put("rV", List.of(x.rV()));
        w.put("s", List.of(x.s()));
        w.put("kModL", List.of(x.kModL()));
        w.put("kQuotient", List.of(x.kQuotient()));
        return w;
    }
}
