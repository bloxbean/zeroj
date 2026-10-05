package org.zeroj.circuit.lib.zk;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.InCircuitJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0051 D3, D3a, D4 / milestone M2: homomorphic building blocks, the I4 constructors, safe
 * decoding, and the no-wraparound balance helper.
 */
class PedersenHomomorphicApiTest {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final int FULL = ZkPedersen.BLINDING_BITS;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final JubjubPoint T8 = JubjubPoint.fromAffine(
            new BigInteger("71d4df38ba9e7973eaaae086a16618d17aa41ac43dae8582d92e6a7927200d43", 16),
            new BigInteger("4958bdb21966982e16a13035ad4d72669106ee90f384a4a1ff0d2068eff496dd", 16));

    // ------------------------------------------------------------------
    //  ZkJubjubPoint.assertInPrimeOrderSubgroup
    // ------------------------------------------------------------------

    @Test
    @DisplayName("ZkJubjubPoint subgroup assertion accepts subgroup points, rejects torsion shifts")
    void zkSubgroupAssertion_affine() {
        var circuit = CircuitBuilder.create("zk-subgroup")
                .secretVar("u").secretVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkJubjubPoint.witnessAffine(zk, ZkField.secret(c, "u"), ZkField.secret(c, "v"))
                            .assertInPrimeOrderSubgroup(zk);
                });
        JubjubPoint good = PedersenCommitment.commit(BigInteger.TEN, randomBlinding());
        assertDoesNotThrow(() -> circuit.calculateWitness(affineWitness("u", "v", good), CurveId.BLS12_381));
        assertDoesNotThrow(() -> circuit.calculateWitness(
                affineWitness("u", "v", JubjubPoint.IDENTITY), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                affineWitness("u", "v", good.add(T8)), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                affineWitness("u", "v", T8), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("ZkJubjubPoint subgroup assertion validates an unestablished projective point first")
    void zkSubgroupAssertion_projectiveRequiresWellFormedness() {
        var circuit = CircuitBuilder.create("zk-subgroup-projective")
                .secretVar("U").secretVar("V").secretVar("Z").secretVar("T")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var api = c.api();
                    ZkJubjubPoint raw = ZkJubjubPoint.wrap(zk, new InCircuitJubjub.Point(
                            api.var("U"), api.var("V"), api.var("Z"), api.var("T")));
                    raw.assertInPrimeOrderSubgroup(zk);
                });
        BigInteger zero = BigInteger.ZERO;
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                projective(zero, zero, zero, zero), CurveId.BLS12_381), "all-zero tuple");
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        BigInteger lambda = BigInteger.valueOf(987_654_321);
        BigInteger u = g.affineU().multiply(lambda).mod(P);
        BigInteger v = g.affineV().multiply(lambda).mod(P);
        BigInteger t = g.affineU().multiply(g.affineV()).multiply(lambda).mod(P);
        assertDoesNotThrow(() -> circuit.calculateWitness(
                projective(u, v, lambda, t), CurveId.BLS12_381), "rescaled valid point");
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                projective(u, v, lambda, t.add(BigInteger.ONE).mod(P)), CurveId.BLS12_381),
                "inconsistent T");
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                projective(u, v, zero, t), CurveId.BLS12_381), "Z = 0");
    }

    // ------------------------------------------------------------------
    //  ZkPedersenCommitment constructors (I4)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("witnessInSubgroup accepts a real commitment and rejects torsion-shifted or off-curve points")
    void witnessInSubgroup() {
        var circuit = CircuitBuilder.create("witness-in-subgroup")
                .secretVar("u").secretVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var commitment = ZkPedersenCommitment.witnessInSubgroup(
                            zk, ZkField.secret(c, "u"), ZkField.secret(c, "v"));
                    assertEquals(ZkPedersenCommitment.Origin.WITNESSED_IN_SUBGROUP, commitment.origin());
                    assertFalse(commitment.hasKnownValue());
                });
        JubjubPoint c = PedersenCommitment.commit(BigInteger.valueOf(5), randomBlinding());
        assertDoesNotThrow(() -> circuit.calculateWitness(affineWitness("u", "v", c), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                affineWitness("u", "v", c.add(T8)), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "u", List.of(BigInteger.ONE), "v", List.of(BigInteger.ONE)), CurveId.BLS12_381));
        // The affine binder pins Z = 1 and T = u·v, so the all-zero projective tuple cannot even be
        // expressed; its affine shadow (0, 0) is off-curve and rejected.
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "u", List.of(BigInteger.ZERO), "v", List.of(BigInteger.ZERO)), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("fromVerifierCheckedPublic rejects secret and derived coordinates at definition time")
    void fromVerifierCheckedPublic_requiresPublicCoordinates() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("secret-coords")
                .secretVar("u").secretVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPedersenCommitment.fromVerifierCheckedPublic(
                            zk, ZkField.secret(c, "u"), ZkField.secret(c, "v"));
                }));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("derived-coords")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var u = ZkField.publicInput(c, "u");
                    ZkPedersenCommitment.fromVerifierCheckedPublic(
                            zk, u.add(zk.constant(0)), ZkField.publicInput(c, "v"));
                }));
        JubjubPoint h = PedersenCommitment.H;
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("constant-coords")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPedersenCommitment.fromVerifierCheckedPublic(
                            zk, zk.constant(h.affineU()), zk.constant(h.affineV()));
                }), "a constant is not in the public statement, so no verifier can check its subgroup");
    }

    /**
     * Documents case (c): the circuit checks the curve, not the subgroup. A torsion-shifted
     * public commitment proves fine, and the verifier's {@code PedersenCommitment.decode} is what
     * rejects it.
     */
    @Test
    @DisplayName("fromVerifierCheckedPublic leaves the subgroup to the verifier, and decode enforces it")
    void fromVerifierCheckedPublic_subgroupIsTheVerifiersJob() {
        var circuit = CircuitBuilder.create("public-commitment")
                .publicVar("u").publicVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPedersenCommitment.fromVerifierCheckedPublic(
                            zk, ZkField.publicInput(c, "u"), ZkField.publicInput(c, "v"));
                });
        JubjubPoint good = PedersenCommitment.commit(BigInteger.ONE, randomBlinding());
        JubjubPoint shifted = good.add(T8);
        assertDoesNotThrow(() -> circuit.calculateWitness(affineWitness("u", "v", good), CurveId.BLS12_381));
        assertDoesNotThrow(() -> circuit.calculateWitness(affineWitness("u", "v", shifted), CurveId.BLS12_381),
                "the circuit does not check the subgroup in case c");
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "u", List.of(BigInteger.ONE), "v", List.of(BigInteger.ONE)), CurveId.BLS12_381),
                "the curve equation is still enforced");

        assertTrue(PedersenCommitment.decode(good.toBytes()).projectiveEquals(good));
        assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.decode(shifted.toBytes()));
    }

    // ------------------------------------------------------------------
    //  Homomorphic combination
    // ------------------------------------------------------------------

    @Test
    @DisplayName("C(a, r) + C(b, s) − C(c, t) equals C(a + b − c, r + s − t), and carries no known value")
    void homomorphicCombination() {
        BigInteger a = BigInteger.valueOf(700), b = BigInteger.valueOf(300), c = BigInteger.valueOf(250);
        BigInteger r = randomBlinding(), s = randomBlinding(), t = randomBlinding();
        BigInteger sumValue = a.add(b).subtract(c);
        BigInteger sumBlinding = r.add(s).subtract(t).mod(L);

        var circuit = CircuitBuilder.create("homomorphic")
                .secretVar("a").secretVar("b").secretVar("c").secretVar("d")
                .secretVar("r").secretVar("s").secretVar("t").secretVar("w")
                .defineSignals(cs -> {
                    var zk = new ZkContext(cs);
                    var ca = ZkPedersenCommitment.commit(zk, ZkUInt.secret(cs, "a", 64), ZkUInt.secret(cs, "r", FULL));
                    var cb = ZkPedersenCommitment.commit(zk, ZkUInt.secret(cs, "b", 64), ZkUInt.secret(cs, "s", FULL));
                    var cc = ZkPedersenCommitment.commit(zk, ZkUInt.secret(cs, "c", 64), ZkUInt.secret(cs, "t", FULL));
                    var combined = ca.add(zk, cb).subtract(zk, cc);
                    assertEquals(ZkPedersenCommitment.Origin.COMBINED, combined.origin());
                    assertFalse(combined.hasKnownValue());
                    combined.assertEqual(zk, ZkPedersenCommitment.commit(
                            zk, ZkUInt.secret(cs, "d", 64), ZkUInt.secret(cs, "w", FULL)));
                });

        Map<String, List<BigInteger>> ok = new HashMap<>(Map.of(
                "a", List.of(a), "b", List.of(b), "c", List.of(c), "d", List.of(sumValue),
                "r", List.of(r), "s", List.of(s), "t", List.of(t), "w", List.of(sumBlinding)));
        assertDoesNotThrow(() -> circuit.calculateWitness(ok, CurveId.BLS12_381));
        ok.put("d", List.of(sumValue.add(BigInteger.ONE)));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(ok, CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  decode
    // ------------------------------------------------------------------

    @Test
    @DisplayName("decode accepts subgroup points including the identity, and rejects torsion")
    void decode() {
        JubjubPoint c = PedersenCommitment.commit(BigInteger.valueOf(3), randomBlinding());
        assertTrue(PedersenCommitment.decode(c.toBytes()).projectiveEquals(c));
        assertTrue(PedersenCommitment.decode(PedersenCommitment.H.toBytes()).projectiveEquals(PedersenCommitment.H));
        assertTrue(PedersenCommitment.decode(JubjubPoint.IDENTITY.toBytes()).isIdentity(),
                "the identity is a valid commitment (spec §4.1)");
        assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.decode(T8.toBytes()));
        assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.decode(c.add(T8).toBytes()));
        assertThrows(IllegalArgumentException.class, () -> PedersenCommitment.decode(new byte[31]));
    }

    // ------------------------------------------------------------------
    //  assertBalanced (D3a)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("A bounded transfer balances; an off-by-one does not")
    void balancedTransfer() {
        var circuit = transferCircuit();
        assertDoesNotThrow(() -> circuit.calculateWitness(
                transferWitness(1000, 500, 1400, 100), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                transferWitness(1000, 500, 1400, 99), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                transferWitness(1000, 500, 1401, 100), CurveId.BLS12_381));
    }

    /**
     * The review counterexample {@code C(l−1, 17) + C(1, 23) = C(0, 40)}: with 252-bit inputs
     * the helper refuses the layout at definition time, even though the output is one bit.
     */
    @Test
    @DisplayName("Wraparound counterexample: 252-bit inputs with a one-bit total are refused at definition time")
    void counterexample_wideInputsRefused() {
        assertTrue(PedersenCommitment.commit(L.subtract(BigInteger.ONE), BigInteger.valueOf(17))
                .add(PedersenCommitment.commit(BigInteger.ONE, BigInteger.valueOf(23)))
                .projectiveEquals(PedersenCommitment.commit(BigInteger.ZERO, BigInteger.valueOf(40))),
                "the counterexample holds as a point identity");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("wrap")
                        .secretVar("x").secretVar("y").secretVar("z")
                        .secretVar("rx").secretVar("ry").secretVar("rz")
                        .defineSignals(c -> {
                            var zk = new ZkContext(c);
                            var cx = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "x", 252), ZkUInt.secret(c, "rx", FULL));
                            var cy = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "y", 252), ZkUInt.secret(c, "ry", FULL));
                            var cz = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "z", 1), ZkUInt.secret(c, "rz", FULL));
                            ZkPedersen.assertBalanced(zk,
                                    List.of(ZkPedersen.Term.of(cx), ZkPedersen.Term.of(cy)),
                                    List.of(ZkPedersen.Term.of(cz)));
                        }));
        assertTrue(e.getMessage().contains("left side"), e.getMessage());
    }

    /** With widths that pass the bound, the counterexample's witness cannot even be expressed. */
    @Test
    @DisplayName("Wraparound counterexample: under safe widths the l − 1 witness is unrepresentable")
    void counterexample_safeWidthsRejectWitness() {
        var circuit = transferCircuit();
        Map<String, List<BigInteger>> w = transferWitness(0, 1, 0, 0);
        w.put("in1", List.of(L.subtract(BigInteger.ONE)));
        w.put("in1R", List.of(BigInteger.valueOf(17)));
        w.put("in2R", List.of(BigInteger.valueOf(23)));
        w.put("outR", List.of(BigInteger.valueOf(40)));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(w, CurveId.BLS12_381));
    }

    @Test
    @DisplayName("Side bound boundary: maximum l − 1 is accepted, l is refused")
    void sideBoundBoundary() {
        BigInteger lMinusOne = L.subtract(BigInteger.ONE);
        assertDoesNotThrow(() -> defineCoefficientBalance(lMinusOne, lMinusOne));
        assertThrows(IllegalArgumentException.class, () -> defineCoefficientBalance(L, lMinusOne));
        assertThrows(IllegalArgumentException.class, () -> defineCoefficientBalance(lMinusOne, L));
    }

    @Test
    @DisplayName("Coefficients: zero and negative are refused; a valid coefficient is enforced in the witness")
    void coefficients() {
        assertThrows(IllegalArgumentException.class, () -> defineCoefficientBalance(BigInteger.ZERO, BigInteger.ONE));
        assertThrows(IllegalArgumentException.class, () -> defineCoefficientBalance(BigInteger.valueOf(-3), BigInteger.ONE));

        var circuit = CircuitBuilder.create("coeff")
                .secretVar("x").secretVar("y").secretVar("rx").secretVar("ry")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var cx = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "x", 32), ZkUInt.secret(c, "rx", FULL));
                    var cy = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "y", 34), ZkUInt.secret(c, "ry", FULL));
                    ZkPedersen.assertBalanced(zk,
                            List.of(ZkPedersen.Term.of(BigInteger.valueOf(3), cx)),
                            List.of(ZkPedersen.Term.of(cy)));
                });
        Map<String, List<BigInteger>> w = new HashMap<>(Map.of(
                "x", List.of(BigInteger.valueOf(41)), "y", List.of(BigInteger.valueOf(123)),
                "rx", List.of(randomBlinding()), "ry", List.of(randomBlinding())));
        assertDoesNotThrow(() -> circuit.calculateWitness(w, CurveId.BLS12_381));
        w.put("y", List.of(BigInteger.valueOf(124)));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(w, CurveId.BLS12_381));
    }

    @Test
    @DisplayName("Commitments without a known value cannot enter a balance")
    void unknownValueRefused() {
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("unknown")
                .secretVar("u").secretVar("v").secretVar("x").secretVar("rx")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var external = ZkPedersenCommitment.witnessInSubgroup(zk, ZkField.secret(c, "u"), ZkField.secret(c, "v"));
                    var known = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "x", 32), ZkUInt.secret(c, "rx", FULL));
                    ZkPedersen.assertBalanced(zk, List.of(ZkPedersen.Term.of(external)), List.of(ZkPedersen.Term.of(known)));
                }));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("combined")
                .secretVar("x").secretVar("y").secretVar("rx").secretVar("ry")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var cx = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "x", 32), ZkUInt.secret(c, "rx", FULL));
                    var cy = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "y", 32), ZkUInt.secret(c, "ry", FULL));
                    ZkPedersen.assertBalanced(zk, List.of(ZkPedersen.Term.of(cx.add(zk, cy))), List.of(ZkPedersen.Term.of(cy)));
                }));
        assertThrows(IllegalArgumentException.class, () -> CircuitBuilder.create("empty")
                .secretVar("x").secretVar("rx")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var cx = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "x", 32), ZkUInt.secret(c, "rx", FULL));
                    ZkPedersen.assertBalanced(zk, List.of(ZkPedersen.Term.of(cx)), List.of());
                }));
    }

    // ------------------------------------------------------------------
    //  Cost pins (ADR-0051 performance gates)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("M2 cost pins: subgroup assertion, witnessInSubgroup, balanced transfer")
    void costPins() {
        R1CSConstraintSystem subgroupOnEstablished = CircuitBuilder.create("pin-subgroup")
                .secretVar("u").secretVar("v")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkJubjubPoint.witnessAffine(zk, ZkField.secret(c, "u"), ZkField.secret(c, "v"))
                            .assertInPrimeOrderSubgroup(zk);
                })
                .compileR1CS(CurveId.BLS12_381);
        R1CSConstraintSystem witnessed = CircuitBuilder.create("pin-witness")
                .secretVar("u").secretVar("v")
                .defineSignals(c -> ZkPedersenCommitment.witnessInSubgroup(
                        new ZkContext(c), ZkField.secret(c, "u"), ZkField.secret(c, "v")))
                .compileR1CS(CurveId.BLS12_381);
        R1CSConstraintSystem transfer = transferCircuit().compileR1CS(CurveId.BLS12_381);

        // witnessAffine (5 rows) + [l]·P (EdDSA's verifyStrict − verifyWithRegisteredKey gap)
        // + the local Z ≠ 0 guard of isIdentity. The low-level, self-validating entry point on
        // raw coordinates is pinned at 5,556 in InCircuitJubjubSubgroupTest.
        assertAll(
                () -> assertEquals(5_547, subgroupOnEstablished.constraints().size(), "subgroup assertion rows"),
                () -> assertEquals(341_190, nnz(subgroupOnEstablished), "subgroup assertion nonzeros"),
                () -> assertEquals(5_547, witnessed.constraints().size(), "witnessInSubgroup rows"),
                () -> assertEquals(7_284, transfer.constraints().size(), "2-in/1-out + fee transfer rows"),
                () -> assertEquals(35_244, nnz(transfer), "2-in/1-out + fee transfer nonzeros"));
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    /** in1 + in2 = out + fee: three 64-bit committed amounts and a 32-bit public fee. */
    private static CircuitBuilder transferCircuit() {
        return CircuitBuilder.create("transfer")
                .publicVar("fee").publicVar("outU").publicVar("outV")
                .secretVar("in1").secretVar("in2").secretVar("out")
                .secretVar("in1R").secretVar("in2R").secretVar("outR")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    var in1 = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "in1", 64), ZkUInt.secret(c, "in1R", FULL));
                    var in2 = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "in2", 64), ZkUInt.secret(c, "in2R", FULL));
                    var out = ZkPedersenCommitment.commit(zk, ZkUInt.secret(c, "out", 64), ZkUInt.secret(c, "outR", FULL));
                    out.assertAffineEquals(zk, ZkField.publicInput(c, "outU"), ZkField.publicInput(c, "outV"));
                    ZkPedersen.assertBalanced(zk,
                            List.of(ZkPedersen.Term.of(in1), ZkPedersen.Term.of(in2)),
                            List.of(ZkPedersen.Term.of(out), ZkPedersen.Term.amount(ZkUInt.publicInput(c, "fee", 32))));
                });
    }

    private static Map<String, List<BigInteger>> transferWitness(long in1, long in2, long out, long fee) {
        BigInteger outR = randomBlinding();
        JubjubPoint outC = PedersenCommitment.commit(BigInteger.valueOf(out), outR);
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("fee", List.of(BigInteger.valueOf(fee)));
        w.put("outU", List.of(outC.affineU()));
        w.put("outV", List.of(outC.affineV()));
        w.put("in1", List.of(BigInteger.valueOf(in1)));
        w.put("in2", List.of(BigInteger.valueOf(in2)));
        w.put("out", List.of(BigInteger.valueOf(out)));
        w.put("in1R", List.of(randomBlinding()));
        w.put("in2R", List.of(randomBlinding()));
        w.put("outR", List.of(outR));
        return w;
    }

    /** left = leftCoefficient · (1-bit amount), right = rightCoefficient · (1-bit amount). */
    private static void defineCoefficientBalance(BigInteger leftCoefficient, BigInteger rightCoefficient) {
        CircuitBuilder.create("bound")
                .secretVar("a").secretVar("b")
                .defineSignals(c -> {
                    var zk = new ZkContext(c);
                    ZkPedersen.assertBalanced(zk,
                            List.of(ZkPedersen.Term.amount(leftCoefficient, ZkUInt.secret(c, "a", 1))),
                            List.of(ZkPedersen.Term.amount(rightCoefficient, ZkUInt.secret(c, "b", 1))));
                });
    }

    private static BigInteger randomBlinding() {
        return PedersenCommitment.randomBlinding(RANDOM);
    }

    private static Map<String, List<BigInteger>> affineWitness(String uName, String vName, JubjubPoint p) {
        JubjubPoint n = p.normalized();
        return Map.of(uName, List.of(n.affineU()), vName, List.of(n.affineV()));
    }

    private static Map<String, List<BigInteger>> projective(BigInteger u, BigInteger v, BigInteger z, BigInteger t) {
        return Map.of("U", List.of(u), "V", List.of(v), "Z", List.of(z), "T", List.of(t));
    }

    private static long nnz(R1CSConstraintSystem system) {
        return system.constraints().stream()
                .mapToLong(c -> (long) c.a().size() + c.b().size() + c.c().size())
                .sum();
    }
}
