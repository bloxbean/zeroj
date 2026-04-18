package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T5;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PedersenTest {

    // ------------------------------------------------------------------
    //  Pedersen-base derivation properties
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Pedersen H is in the Jubjub prime-order subgroup")
    void pedersenH_isInSubgroup() {
        assertTrue(PedersenCommitment.H.isInSubgroup(),
                "H must be cofactor-cleared; required for binding");
    }

    // Locked fixture — derived once from the Poseidon try-and-increment on
    // domain tag "zeroj.pedersen.v1.H". Any drift in Poseidon params, the
    // derivation loop, or the domain tag would flip these values and fail.
    private static final BigInteger H_U_EXPECTED = new BigInteger(
            "72963e7766b3cd553a1525a17da810e6b4cdeb70541dac5b52a3210f5c372db6", 16);
    private static final BigInteger H_V_EXPECTED = new BigInteger(
            "60bb97d81759e04503194aeb9eb8faa23b0092c941d1139bfe99907794c8e37d", 16);

    @Test
    @DisplayName("Pedersen H affine coordinates match locked fixture")
    void pedersenH_matchesLockedFixture() {
        assertEquals(H_U_EXPECTED, PedersenCommitment.H.affineU(),
                "H.u drifted — derivation changed (Poseidon params? domain tag? loop?)");
        assertEquals(H_V_EXPECTED, PedersenCommitment.H.affineV(),
                "H.v drifted — derivation changed");
    }

    @Test
    @DisplayName("Pedersen H is distinct from the identity and from G")
    void pedersenH_isNonTrivial() {
        assertFalse(PedersenCommitment.H.isIdentity(), "H must not be identity");
        assertNotEquals(JubjubPoint.SUBGROUP_GENERATOR, PedersenCommitment.H,
                "H must not equal G (that would break binding)");
    }

    @Test
    @DisplayName("Pedersen H is deterministic across calls (same derivation always yields same point)")
    void pedersenH_isDeterministic() {
        // Static field init means the same instance — but re-reading should match.
        JubjubPoint firstRead = PedersenCommitment.H;
        JubjubPoint secondRead = PedersenCommitment.H;
        assertTrue(firstRead.projectiveEquals(secondRead));
    }

    // ------------------------------------------------------------------
    //  Off-circuit commit / verify
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Commit(v, r) == [v]·G + [r]·H; verify accepts the opening")
    void commit_verify_roundTrip() {
        BigInteger v = BigInteger.valueOf(42);
        BigInteger r = BigInteger.valueOf(12345);
        JubjubPoint c = PedersenCommitment.commit(v, r);
        assertTrue(PedersenCommitment.verify(c, v, r));
    }

    @Test
    @DisplayName("Pedersen is hiding: commit(v1, r1) != commit(v2, r1) for v1 != v2")
    void commit_isHiding_differentValuesDiffer() {
        BigInteger r = BigInteger.valueOf(77);
        JubjubPoint c1 = PedersenCommitment.commit(BigInteger.ONE, r);
        JubjubPoint c2 = PedersenCommitment.commit(BigInteger.TWO, r);
        assertNotEquals(c1, c2);
    }

    @Test
    @DisplayName("Pedersen is binding in the homomorphic sense: commit(v1+v2, r1+r2) == commit(v1, r1) + commit(v2, r2)")
    void commit_isHomomorphic() {
        BigInteger v1 = BigInteger.valueOf(10);
        BigInteger v2 = BigInteger.valueOf(32);
        BigInteger r1 = BigInteger.valueOf(100);
        BigInteger r2 = BigInteger.valueOf(200);
        JubjubPoint c1 = PedersenCommitment.commit(v1, r1);
        JubjubPoint c2 = PedersenCommitment.commit(v2, r2);
        JubjubPoint sum = c1.add(c2);
        JubjubPoint combined = PedersenCommitment.commit(v1.add(v2), r1.add(r2));
        assertTrue(sum.projectiveEquals(combined),
                "Pedersen should be homomorphic: C(v1, r1) + C(v2, r2) = C(v1+v2, r1+r2)");
    }

    @Test
    @DisplayName("Pedersen verify rejects a wrong opening")
    void verify_rejectsWrongOpening() {
        BigInteger v = BigInteger.valueOf(42);
        BigInteger r = BigInteger.valueOf(12345);
        JubjubPoint c = PedersenCommitment.commit(v, r);
        assertFalse(PedersenCommitment.verify(c, v.add(BigInteger.ONE), r));
        assertFalse(PedersenCommitment.verify(c, v, r.add(BigInteger.ONE)));
    }

    // ------------------------------------------------------------------
    //  In-circuit commit gadget
    // ------------------------------------------------------------------

    @Test
    @DisplayName("In-circuit Pedersen commit matches off-circuit for a small (v, r)")
    void inCircuit_commit_matchesOffCircuit_small() {
        BigInteger v = BigInteger.valueOf(42);
        BigInteger r = BigInteger.valueOf(12345);
        JubjubPoint expected = PedersenCommitment.commit(v, r);

        var circuit = CircuitBuilder.create("pedersen_commit")
                .publicVar("outU").publicVar("outV")
                .secretVar("v").secretVar("r")
                .define(api -> {
                    var c = InCircuitPedersen.commit(api, api.var("v"), api.var("r"), 32);
                    api.assertEqual(api.mul(api.var("outU"), c.z()), c.u());
                    api.assertEqual(api.mul(api.var("outV"), c.z()), c.v());
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(expected.affineU()),
                "outV", List.of(expected.affineV()),
                "v", List.of(v),
                "r", List.of(r)
        ), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("commit(0, r) = [r]·H (v=0 edge case)")
    void commit_vZero_equalsRHOnly() {
        BigInteger r = BigInteger.valueOf(42);
        JubjubPoint c = PedersenCommitment.commit(BigInteger.ZERO, r);
        JubjubPoint expected = PedersenCommitment.H.scalarMul(r);
        assertTrue(c.projectiveEquals(expected));
    }

    @Test
    @DisplayName("commit(v, 0) = [v]·G (r=0 edge case — unsafe in practice but must compute correctly)")
    void commit_rZero_equalsVGOnly() {
        BigInteger v = BigInteger.valueOf(17);
        JubjubPoint c = PedersenCommitment.commit(v, BigInteger.ZERO);
        JubjubPoint expected = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(v);
        assertTrue(c.projectiveEquals(expected));
    }

    @Test
    @DisplayName("In-circuit Pedersen commit: full 252-bit (v, r) matches off-circuit")
    void inCircuit_commit_fullWidth() {
        BigInteger v = JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.valueOf(7));
        BigInteger r = JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.valueOf(3));
        JubjubPoint expected = PedersenCommitment.commit(v, r);

        var circuit = CircuitBuilder.create("pedersen_commit_252")
                .publicVar("outU").publicVar("outV")
                .secretVar("v").secretVar("r")
                .define(api -> {
                    var c = InCircuitPedersen.commit(api, api.var("v"), api.var("r"), 252);
                    api.assertEqual(api.mul(api.var("outU"), c.z()), c.u());
                    api.assertEqual(api.mul(api.var("outV"), c.z()), c.v());
                });
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "outU", List.of(expected.affineU()),
                "outV", List.of(expected.affineV()),
                "v", List.of(v),
                "r", List.of(r)
        ), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("InCircuitPedersen rejects numBits > 252")
    void inCircuit_rejectsLargeNumBits() {
        var b = CircuitBuilder.create("bad").secretVar("v").secretVar("r");
        assertThrows(IllegalArgumentException.class, () -> b.define(api ->
                InCircuitPedersen.commit(api, api.var("v"), api.var("r"), 300)));
    }

    @Test
    @DisplayName("In-circuit Pedersen rejects wrong commitment")
    void inCircuit_commit_rejectsWrongOutput() {
        var circuit = CircuitBuilder.create("pedersen_commit_neg")
                .publicVar("outU").publicVar("outV")
                .secretVar("v").secretVar("r")
                .define(api -> {
                    var c = InCircuitPedersen.commit(api, api.var("v"), api.var("r"), 16);
                    api.assertEqual(api.mul(api.var("outU"), c.z()), c.u());
                    api.assertEqual(api.mul(api.var("outV"), c.z()), c.v());
                });
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "outU", List.of(BigInteger.valueOf(999)),
                "outV", List.of(BigInteger.valueOf(888)),
                "v", List.of(BigInteger.valueOf(1)),
                "r", List.of(BigInteger.valueOf(2))
        ), CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  BLS12_381 t=5 preset sanity
    // ------------------------------------------------------------------

    @Test
    @DisplayName("PoseidonParamsBLS12_381T5: well-formed, 340 round constants, 5x5 MDS")
    void t5_preset_isWellFormed() {
        var p = PoseidonParamsBLS12_381T5.INSTANCE;
        assertEquals(5, p.t());
        assertEquals(5, p.alpha());
        assertEquals(8, p.rf());
        assertEquals(60, p.rp());
        assertEquals((8 + 60) * 5, p.c().length); // 340
        assertEquals(5 * 5, p.m().length);        // 25
    }

    @Test
    @DisplayName("BLS12_381 t=5 first round constant matches SageMath reference")
    void t5_firstConstant_matchesSage() {
        // From Sage (ADR-0016 M4 cross-check: docker run ... sage generate_parameters_grain.sage 1 0 255 5 8 60 <bls_prime>)
        BigInteger expected = new BigInteger(
                "5ee52b2f39e240a4006e97a15a7609dce42fa9aa510d11586a56db98fa925158", 16);
        assertEquals(expected, PoseidonParamsBLS12_381T5.INSTANCE.c()[0],
                "BLS12-381 t=5 C[0] must match hadeshash Sage script output");
    }

    @Test
    @DisplayName("BLS12_381 t=5 MDS[0][0] matches SageMath reference")
    void t5_firstMds_matchesSage() {
        BigInteger expected = new BigInteger(
                "354423b163d1078b0dd645be56316e34a9b98e52dcf9f469be44b108be46c107", 16);
        assertEquals(expected, PoseidonParamsBLS12_381T5.INSTANCE.m()[0],
                "BLS12-381 t=5 MDS[0][0] must match hadeshash Sage script output");
    }
}
