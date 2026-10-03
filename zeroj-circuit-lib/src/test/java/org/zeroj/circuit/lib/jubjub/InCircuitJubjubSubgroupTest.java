package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0051 D3 / M2: low-level negation, subtraction and the public, self-validating
 * {@link InCircuitJubjub#assertInPrimeOrderSubgroup}.
 *
 * <p>The subgroup assertion is fed raw extended coordinates straight from the witness — the
 * worst case for a public helper — and must reject every malformed representation the review
 * of ADR-0051 r1 named, as well as torsion-shifted points, while accepting valid subgroup
 * points in any projective scaling and the well-formed identity.
 */
class InCircuitJubjubSubgroupTest {

    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;

    /** Small-order points, from the independent reference output (decode_neg.*). */
    private static final JubjubPoint T2 = JubjubPoint.fromAffine(BigInteger.ZERO, P.subtract(BigInteger.ONE));
    private static final JubjubPoint T4 = JubjubPoint.fromAffine(
            new BigInteger("00000000000000008d51ccce760304d0ec030002760300000001000000000000", 16),
            BigInteger.ZERO);
    private static final JubjubPoint T8 = JubjubPoint.fromAffine(
            new BigInteger("71d4df38ba9e7973eaaae086a16618d17aa41ac43dae8582d92e6a7927200d43", 16),
            new BigInteger("4958bdb21966982e16a13035ad4d72669106ee90f384a4a1ff0d2068eff496dd", 16));

    // ------------------------------------------------------------------
    //  assertInPrimeOrderSubgroup — accepted
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Accepts subgroup points in affine and rescaled projective form, and the identity")
    void acceptsValidSubgroupPoints() {
        var circuit = subgroupCircuit();
        JubjubPoint c = PedersenCommitment.commit(BigInteger.valueOf(42), BigInteger.valueOf(7));
        BigInteger lambda = new BigInteger("1234567890abcdef1234567890abcdef", 16);

        assertAccepted(circuit, affine(G));
        assertAccepted(circuit, affine(c));
        assertAccepted(circuit, scaled(c, lambda));
        assertAccepted(circuit, affine(JubjubPoint.IDENTITY));
        assertAccepted(circuit, scaled(JubjubPoint.IDENTITY, lambda));
    }

    // ------------------------------------------------------------------
    //  assertInPrimeOrderSubgroup — rejected
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Rejects the all-zero tuple that the bare [l]P = O check would accept")
    void rejectsAllZero() {
        assertRejected(subgroupCircuit(), new BigInteger[]{BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO});
    }

    @Test
    @DisplayName("Rejects Z = 0 with the other coordinates non-zero")
    void rejectsZeroZ() {
        BigInteger[] g = affine(G);
        assertRejected(subgroupCircuit(), new BigInteger[]{g[0], g[1], BigInteger.ZERO, g[3]});
        assertRejected(subgroupCircuit(), new BigInteger[]{BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO});
    }

    @Test
    @DisplayName("Rejects an inconsistent T")
    void rejectsInconsistentT() {
        BigInteger[] g = affine(G);
        assertRejected(subgroupCircuit(), new BigInteger[]{g[0], g[1], g[2], g[3].add(BigInteger.ONE).mod(P)});
    }

    @Test
    @DisplayName("Rejects off-curve points")
    void rejectsOffCurve() {
        assertRejected(subgroupCircuit(), new BigInteger[]{BigInteger.ONE, BigInteger.ONE, BigInteger.ONE, BigInteger.ONE});
        BigInteger[] g = affine(G);
        BigInteger u = g[0].add(BigInteger.ONE).mod(P);
        assertRejected(subgroupCircuit(), new BigInteger[]{u, g[1], BigInteger.ONE, u.multiply(g[1]).mod(P)});
    }

    @Test
    @DisplayName("Rejects small-order points and subgroup points shifted by torsion (orders 2, 4, 8)")
    void rejectsTorsion() {
        var circuit = subgroupCircuit();
        for (JubjubPoint t : List.of(T2, T4, T8)) {
            assertTrue(!t.isInSubgroup() && !t.isIdentity(), "fixture must be a non-trivial torsion point");
            assertRejected(circuit, affine(t));
            assertRejected(circuit, affine(G.add(t)));
            assertRejected(circuit, affine(PedersenCommitment.H.add(t)));
        }
    }

    // ------------------------------------------------------------------
    //  negate / subtract
    // ------------------------------------------------------------------

    @Test
    @DisplayName("negate and subtract match off-circuit arithmetic")
    void negateAndSubtractMatchOffCircuit() {
        JubjubPoint a = PedersenCommitment.commit(BigInteger.valueOf(100), BigInteger.valueOf(55));
        JubjubPoint b = PedersenCommitment.commit(BigInteger.valueOf(30), BigInteger.valueOf(21));
        JubjubPoint expectedNeg = a.negate().normalized();
        JubjubPoint expectedDiff = a.add(b.negate()).normalized();

        var circuit = CircuitBuilder.create("neg-sub")
                .publicVar("negU").publicVar("negV").publicVar("diffU").publicVar("diffV")
                .secretVar("aU").secretVar("aV").secretVar("bU").secretVar("bV")
                .define(api -> {
                    var pa = InCircuitJubjub.witnessAffine(api, api.var("aU"), api.var("aV"));
                    var pb = InCircuitJubjub.witnessAffine(api, api.var("bU"), api.var("bV"));
                    var neg = InCircuitJubjub.negate(api, pa);
                    var diff = InCircuitJubjub.subtract(api, pa, pb);
                    api.assertEqual(api.mul(api.var("negU"), neg.z()), neg.u());
                    api.assertEqual(api.mul(api.var("negV"), neg.z()), neg.v());
                    api.assertEqual(api.mul(api.var("diffU"), diff.z()), diff.u());
                    api.assertEqual(api.mul(api.var("diffV"), diff.z()), diff.v());
                });

        JubjubPoint an = a.normalized();
        JubjubPoint bn = b.normalized();
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "negU", List.of(expectedNeg.affineU()), "negV", List.of(expectedNeg.affineV()),
                "diffU", List.of(expectedDiff.affineU()), "diffV", List.of(expectedDiff.affineV()),
                "aU", List.of(an.affineU()), "aV", List.of(an.affineV()),
                "bU", List.of(bn.affineU()), "bV", List.of(bn.affineV())), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "negU", List.of(an.affineU()), "negV", List.of(an.affineV()),
                "diffU", List.of(expectedDiff.affineU()), "diffV", List.of(expectedDiff.affineV()),
                "aU", List.of(an.affineU()), "aV", List.of(an.affineV()),
                "bU", List.of(bn.affineU()), "bV", List.of(bn.affineV())), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("negate costs zero constraints; subtract costs exactly one addition")
    void negateAndSubtractCosts() {
        int base = rows("none");
        assertEquals(base, rows("negate"), "negate must add no constraints");
        assertEquals(rows("add"), rows("subtract"), "subtract must cost exactly one addition");
    }

    // ------------------------------------------------------------------
    //  Cost pin
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Public subgroup assertion cost is pinned")
    void subgroupAssertionCost() {
        var circuit = subgroupCircuit();
        var system = circuit.compileR1CS(CurveId.BLS12_381);
        assertEquals(5_556, system.constraints().size(), "well-formedness + [l]P = O rows");
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private static CircuitBuilder subgroupCircuit() {
        return CircuitBuilder.create("subgroup")
                .secretVar("U").secretVar("V").secretVar("Z").secretVar("T")
                .define(api -> InCircuitJubjub.assertInPrimeOrderSubgroup(api,
                        new InCircuitJubjub.Point(api.var("U"), api.var("V"), api.var("Z"), api.var("T"))));
    }

    private static int rows(String op) {
        return CircuitBuilder.create("cost-" + op)
                .secretVar("aU").secretVar("aV").secretVar("bU").secretVar("bV")
                .define(api -> {
                    var pa = InCircuitJubjub.witnessAffine(api, api.var("aU"), api.var("aV"));
                    var pb = InCircuitJubjub.witnessAffine(api, api.var("bU"), api.var("bV"));
                    switch (op) {
                        case "negate" -> InCircuitJubjub.negate(api, pa);
                        case "add" -> InCircuitJubjub.add(api, pa, pb);
                        case "subtract" -> InCircuitJubjub.subtract(api, pa, pb);
                        default -> { }
                    }
                })
                .compileR1CS(CurveId.BLS12_381)
                .constraints().size();
    }

    private static BigInteger[] affine(JubjubPoint p) {
        BigInteger u = p.affineU();
        BigInteger v = p.affineV();
        return new BigInteger[]{u, v, BigInteger.ONE, u.multiply(v).mod(P)};
    }

    private static BigInteger[] scaled(JubjubPoint p, BigInteger lambda) {
        BigInteger[] a = affine(p);
        BigInteger[] out = new BigInteger[4];
        for (int i = 0; i < 4; i++) out[i] = a[i].multiply(lambda).mod(P);
        return out;
    }

    private static Map<String, List<BigInteger>> witness(BigInteger[] coords) {
        return Map.of("U", List.of(coords[0]), "V", List.of(coords[1]),
                "Z", List.of(coords[2]), "T", List.of(coords[3]));
    }

    private static void assertAccepted(CircuitBuilder circuit, BigInteger[] coords) {
        assertDoesNotThrow(() -> circuit.calculateWitness(witness(coords), CurveId.BLS12_381));
    }

    private static void assertRejected(CircuitBuilder circuit, BigInteger[] coords) {
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(witness(coords), CurveId.BLS12_381));
    }
}
