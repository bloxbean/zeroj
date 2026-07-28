package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

/** ADR-0038 Decision 5: low-severity cleanup. */
class JubjubCleanupP5Test {

    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;
    private static final JubjubPoint PK =
            EdDSAJubjub.keypairFromSecret(BigInteger.valueOf(1234567)).pk();

    // ------------------------------------------------------------------
    //  msg ∈ [0, p) — reject, don't reduce
    // ------------------------------------------------------------------

    /**
     * {@code computeChallenge} is public so gadgets can reproduce sign/verify's challenge
     * exactly. Poseidon reduces its inputs internally, so without an explicit range check the
     * challenge for {@code msg} and {@code msg + p} would be identical — while {@code sign}
     * and {@code verify} reject the latter outright. Diverging on the accepted domain is what
     * makes the two implementations disagree.
     */
    @Test
    void computeChallenge_rejectsMessageAtOrAboveP() {
        for (BigInteger bad : new BigInteger[]{P, P.add(BigInteger.ONE), P.multiply(BigInteger.TWO)}) {
            var ex = assertThrows(IllegalArgumentException.class,
                    () -> EdDSAJubjub.computeChallenge(G, PK, bad),
                    "msg = " + bad.bitLength() + " bits must be rejected");
            assertTrue(ex.getMessage().contains("[0, p)"), "got: " + ex.getMessage());
        }
    }

    @Test
    void computeChallenge_rejectsNegativeMessage() {
        assertThrows(IllegalArgumentException.class,
                () -> EdDSAJubjub.computeChallenge(G, PK, BigInteger.valueOf(-1)));
    }

    @Test
    void computeChallenge_acceptsBoundaryValues() {
        assertDoesNotThrow(() -> EdDSAJubjub.computeChallenge(G, PK, BigInteger.ZERO));
        assertDoesNotThrow(() -> EdDSAJubjub.computeChallenge(G, PK, P.subtract(BigInteger.ONE)));
    }

    /** The aliasing this closes: msg and msg + p must not share a challenge. */
    @Test
    void computeChallenge_wouldHaveAliasedMsgAndMsgPlusP() {
        BigInteger msg = BigInteger.valueOf(42);
        BigInteger alias = msg.add(P);

        assertDoesNotThrow(() -> EdDSAJubjub.computeChallenge(G, PK, msg));
        assertThrows(IllegalArgumentException.class,
                () -> EdDSAJubjub.computeChallenge(G, PK, alias),
                "the alias must be rejected rather than silently reduced to the same challenge");
    }

    @Test
    void witnessComputeKReduction_rejectsOutOfRangeMessage() {
        assertThrows(IllegalArgumentException.class,
                () -> InCircuitEdDSAJubjub.witnessComputeKReduction(G, PK, P));
        assertThrows(IllegalArgumentException.class,
                () -> InCircuitEdDSAJubjub.witnessComputeKReduction(G, PK, BigInteger.valueOf(-5)));
    }

    @Test
    void witnessComputeKReduction_acceptsBoundaryValues() {
        assertDoesNotThrow(
                () -> InCircuitEdDSAJubjub.witnessComputeKReduction(G, PK, BigInteger.ZERO));
        assertDoesNotThrow(() -> InCircuitEdDSAJubjub.witnessComputeKReduction(
                G, PK, P.subtract(BigInteger.ONE)));
    }

    /** The witness helper and the scheme must agree on the accepted domain, exactly. */
    @Test
    void witnessComputeKReduction_domainMatchesSignAndVerify() {
        BigInteger sk = BigInteger.valueOf(99);
        var keypair = EdDSAJubjub.keypairFromSecret(sk);

        for (BigInteger msg : new BigInteger[]{
                BigInteger.ZERO, BigInteger.ONE, P.subtract(BigInteger.ONE)}) {
            assertDoesNotThrow(() -> EdDSAJubjub.sign(sk, msg));
            assertDoesNotThrow(
                    () -> InCircuitEdDSAJubjub.witnessComputeKReduction(G, keypair.pk(), msg));
        }
        for (BigInteger msg : new BigInteger[]{P, P.add(BigInteger.ONE)}) {
            assertThrows(IllegalArgumentException.class, () -> EdDSAJubjub.sign(sk, msg));
            assertThrows(IllegalArgumentException.class,
                    () -> InCircuitEdDSAJubjub.witnessComputeKReduction(G, keypair.pk(), msg));
        }
    }

    /** The reduction itself must be unchanged by the added guard. */
    @Test
    void witnessComputeKReduction_stillProducesCanonicalPair() {
        BigInteger msg = BigInteger.valueOf(777);
        var reduction = InCircuitEdDSAJubjub.witnessComputeKReduction(G, PK, msg);

        assertTrue(reduction.kModL().signum() >= 0);
        assertTrue(reduction.kModL().compareTo(JubjubCurve.SUBGROUP_ORDER) < 0, "kModL < l");
        assertTrue(reduction.kQuotient().compareTo(BigInteger.valueOf(8)) <= 0, "q <= 8");
        assertEquals(EdDSAJubjub.computeChallenge(G, PK, msg), reduction.kModL(),
                "kModL must equal the challenge scalar sign/verify computes");
    }

    // ------------------------------------------------------------------
    //  The dead doubling table
    // ------------------------------------------------------------------

    /**
     * The removed table was 252 off-circuit point doublings computed and discarded on every
     * call. Its removal must not change a single constraint — it never fed the windowed path.
     */
    @Test
    void fixedBaseScalarMul_constraintCountUnchangedByDeadTableRemoval() {
        var circuit = com.bloxbean.cardano.zeroj.circuit.CircuitBuilder.create("fixed-base-pin")
                .publicVar("out").secretVar("k")
                .define(api -> InCircuitJubjub.scalarMulFixedBase(
                        api, JubjubPoint.SUBGROUP_GENERATOR, api.var("k"), 252))
                .compileR1CS(com.bloxbean.cardano.zeroj.api.CurveId.BLS12_381);

        // Measured: 1,506 rows for the whole circuit — the 252-bit decomposition the Variable
        // overload emits plus the windowed multiplication. Matches the figure pinned by
        // WindowedFixedBaseTest and quoted in scalarMulFixedBase's Javadoc.
        assertEquals(1506, circuit.constraints().size(),
                "fixed-base 252-bit scalar multiplication constraint count");
    }

    /** And it must still compute the right point. */
    @Test
    void fixedBaseScalarMul_stillCorrect() {
        BigInteger k = BigInteger.valueOf(12345);
        JubjubPoint expected = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(k);

        var circuit = com.bloxbean.cardano.zeroj.circuit.CircuitBuilder.create("fixed-base-value")
                .publicVar("outU").secretVar("k")
                .define(api -> {
                    var p = InCircuitJubjub.scalarMulFixedBase(
                            api, JubjubPoint.SUBGROUP_GENERATOR, api.var("k"), 32);
                    api.assertEqual(api.mul(api.var("outU"), p.z()), p.u());
                });

        assertDoesNotThrow(() -> circuit.calculateWitness(java.util.Map.of(
                "outU", java.util.List.of(expected.affineU()),
                "k", java.util.List.of(k)), com.bloxbean.cardano.zeroj.api.CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  The corrected constraint figure
    // ------------------------------------------------------------------

    /**
     * {@code JubjubEdDSASuite}'s Javadoc quoted 2,772 constraints for the tagged {@code t=6}
     * challenge; {@code JubjubEdDSASuiteTest} pins 321. This asserts the pinned value so the
     * Javadoc and the measurement cannot drift apart again.
     */
    @Test
    void taggedT6Challenge_costsThePinnedConstraintCount() {
        var circuit = com.bloxbean.cardano.zeroj.circuit.CircuitBuilder.create("t6-challenge")
                .publicVar("out")
                .secretVar("a").secretVar("b").secretVar("c").secretVar("d").secretVar("e")
                .define(api -> {
                    var k = com.bloxbean.cardano.zeroj.circuit.lib.Poseidon.spongeHash(
                            api, JubjubEdDSASuite.challengeParams(),
                            api.constant(JubjubEdDSASuite.CHALLENGE_TAG),
                            api.var("a"), api.var("b"), api.var("c"), api.var("d"), api.var("e"));
                    api.assertEqual(k, api.var("out"));
                })
                .compileR1CS(com.bloxbean.cardano.zeroj.api.CurveId.BLS12_381);

        // JubjubEdDSASuiteTest pins the bare permutation at 321; this circuit adds one row for
        // the assertEqual binding the digest to a public output. The Javadoc figure that used
        // to read 2,772 is the one being corrected here.
        assertEquals(322, circuit.constraints().size(),
                "tagged t=6 challenge (321) plus one output binding");
        assertEquals(9_194, circuit.constraints().stream()
                        .mapToLong(c -> (long) c.a().size() + c.b().size() + c.c().size()).sum(),
                "tagged t=6 sparse-matrix nonzeros");
        assertEquals(512, Integer.highestOneBit(circuit.constraints().size() - 1) << 1,
                "row-derived padded proving domain");
    }
}
