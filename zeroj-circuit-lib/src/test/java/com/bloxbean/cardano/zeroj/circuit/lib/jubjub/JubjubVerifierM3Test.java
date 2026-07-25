package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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
 * ADR-0037 M3 gates: the two named verification entry points and their key-trust models.
 *
 * <p>The central question these tests answer is not "does a valid signature verify" but
 * "what exactly does each entry point promise about {@code pk}". {@code verifyStrict} proves
 * subgroup membership in-circuit; {@code verifyWithRegisteredKey} proves only that the key is
 * verifier-visible and leaves membership to the protocol. Both must reject small-order keys.
 * The mixed-order case is where they legitimately differ, and that difference is asserted
 * rather than left implicit.
 */
class JubjubVerifierM3Test {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final BigInteger SK = new BigInteger(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16).mod(L);

    /** [l]·FULL_GENERATOR has order 8: FULL_GENERATOR has order 8l. */
    private static JubjubPoint torsion8() {
        return JubjubPoint.FULL_GENERATOR.scalarMul(L);
    }

    /** (0, -1) is on the curve and has order 2. */
    private static JubjubPoint order2() {
        return JubjubPoint.fromAffine(BigInteger.ZERO, P.subtract(BigInteger.ONE));
    }

    // ------------------------------------------------------------------
    //  Small-order public keys — rejected by BOTH entry points
    // ------------------------------------------------------------------

    @Test
    @DisplayName("identity pk is rejected by both entry points (was a universal forgery)")
    void identityPkRejectedByBoth() {
        // [k]*O = O collapses the equation to [S]*G == R, so R = [S]*G forges for any message
        // with no secret key at all. The identity is on the curve, so witnessAffine passes it.
        BigInteger s = BigInteger.valueOf(987_654_321L);
        JubjubPoint pk = JubjubPoint.IDENTITY;
        JubjubPoint r = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(s);
        BigInteger msg = BigInteger.valueOf(0xFEED);

        assertThrows(Exception.class,
                () -> strictCircuit().calculateWitness(witness(pk, r, s, msg), CurveId.BLS12_381),
                "verifyStrict must reject the identity");
        assertThrows(Exception.class,
                () -> registeredCircuit().calculateWitness(witness(pk, r, s, msg), CurveId.BLS12_381),
                "verifyWithRegisteredKey must reject the identity via [8]pk != O");
    }

    @Test
    @DisplayName("order-2 pk (0,-1) is rejected by both entry points")
    void order2PkRejectedByBoth() {
        JubjubPoint pk = order2();
        assertTrue(pk.mulByCofactor().isIdentity(), "sanity: [8]*(0,-1) == O");
        BigInteger s = BigInteger.valueOf(555_777L);
        JubjubPoint r = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(s);
        BigInteger msg = BigInteger.valueOf(1234);

        assertThrows(Exception.class,
                () -> strictCircuit().calculateWitness(witness(pk, r, s, msg), CurveId.BLS12_381));
        assertThrows(Exception.class,
                () -> registeredCircuit().calculateWitness(witness(pk, r, s, msg), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("order-8 pk is rejected by both entry points")
    void order8PkRejectedByBoth() {
        JubjubPoint pk = torsion8();
        assertTrue(pk.mulByCofactor().isIdentity(), "sanity: [8]*T == O");
        assertFalse(pk.isIdentity(), "sanity: T != O");
        BigInteger s = BigInteger.valueOf(31337);
        JubjubPoint r = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(s);
        BigInteger msg = BigInteger.valueOf(4242);

        assertThrows(Exception.class,
                () -> strictCircuit().calculateWitness(witness(pk, r, s, msg), CurveId.BLS12_381));
        assertThrows(Exception.class,
                () -> registeredCircuit().calculateWitness(witness(pk, r, s, msg), CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  Mixed-order pk — where the two entry points legitimately differ
    // ------------------------------------------------------------------

    /**
     * A mixed-order key {@code pk = pk' + T} passes {@code [8]·pk != O} but is not in the
     * prime-order subgroup.
     *
     * <p>This needs a <b>deterministic constructed transcript, not a random signature</b>.
     * Under cofactorless verification the torsion term cancels only when {@code 8 | k}: the
     * equation is {@code [S]·G == R + [k]·(pk' + T) = R + [k]·pk' + [k]·T}, and {@code [k]·T}
     * vanishes exactly when {@code k ≡ 0 (mod 8)}. Measured on random transcripts that holds
     * 51 times in 400 — about one in eight — so a random vector would flake ~7/8 of the time.
     * We therefore search for a message whose challenge satisfies {@code 8 | k} and pin it.
     */
    @Test
    @DisplayName("mixed-order pk: verifyStrict rejects, verifyWithRegisteredKey accepts")
    void mixedOrderPkDistinguishesTheEntryPoints() {
        JubjubPoint pkPrime = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(SK);
        JubjubPoint pkMixed = pkPrime.add(torsion8());

        assertFalse(pkMixed.isInSubgroup(), "sanity: mixed-order key is outside the subgroup");
        assertFalse(pkMixed.mulByCofactor().isIdentity(),
                "sanity: [8]*pkMixed != O, so the cheap backstop does NOT catch it");

        // Deterministic search for a transcript with 8 | k.
        BigInteger msg = null, s = null;
        JubjubPoint r = null;
        for (int i = 0; i < 200; i++) {
            BigInteger candidate = BigInteger.valueOf(1000L + i);
            var sig = EdDSAJubjub.sign(SK, candidate);
            BigInteger k = EdDSAJubjub.computeChallenge(sig.r(), pkMixed, candidate);
            if (k.mod(BigInteger.valueOf(8)).signum() == 0) {
                // Recompute S against the mixed key's challenge.
                BigInteger nonce = nonceFor(SK, candidate);
                msg = candidate;
                r = sig.r();
                s = nonce.add(k.multiply(SK)).mod(L);
                break;
            }
        }
        org.junit.jupiter.api.Assertions.assertNotNull(msg,
                "no transcript with 8 | k found in 200 tries; expected ~25");

        final BigInteger fMsg = msg, fS = s;
        final JubjubPoint fR = r;

        assertDoesNotThrow(
                () -> registeredCircuit().calculateWitness(
                        witness(pkMixed, fR, fS, fMsg), CurveId.BLS12_381),
                "verifyWithRegisteredKey accepts a mixed-order key: [8]pk != O passes and it "
                        + "does not prove subgroup membership. This is the residual obligation "
                        + "on the registry, asserted here rather than left implicit.");

        assertThrows(Exception.class,
                () -> strictCircuit().calculateWitness(
                        witness(pkMixed, fR, fS, fMsg), CurveId.BLS12_381),
                "verifyStrict must reject a key outside the prime-order subgroup");
    }

    // ------------------------------------------------------------------
    //  DSL provenance enforcement
    // ------------------------------------------------------------------

    @Test
    @DisplayName("verifyWithRegisteredKey throws at define time for a secret pk wire")
    void registeredKeyRejectsSecretWitnessPk() {
        var ex = assertThrows(IllegalArgumentException.class, () ->
                CircuitBuilder.create("reg_secret_pk")
                        .publicVar("msg")
                        .secretVar("pkU").secretVar("pkV")     // secret, not public
                        .secretVar("rU").secretVar("rV")
                        .secretVar("s").secretVar("kModL").secretVar("kQuotient")
                        .define(api -> InCircuitEdDSAJubjub.verifyWithRegisteredKey(api,
                                api.var("pkU"), api.var("pkV"), api.var("msg"),
                                api.var("rU"), api.var("rV"),
                                api.var("s"), api.var("kModL"), api.var("kQuotient"))));
        assertTrue(ex.getMessage().contains("public input or a circuit constant"), ex.getMessage());
    }

    @Test
    @DisplayName("verifyWithRegisteredKey accepts a constant pk")
    void registeredKeyAcceptsConstantPk() {
        JubjubPoint pk = EdDSAJubjub.keypairFromSecret(SK).pk();
        assertDoesNotThrow(() -> CircuitBuilder.create("reg_const_pk")
                .publicVar("msg")
                .secretVar("rU").secretVar("rV")
                .secretVar("s").secretVar("kModL").secretVar("kQuotient")
                .define(api -> InCircuitEdDSAJubjub.verifyWithRegisteredKey(api,
                        api.constant(pk.affineU()), api.constant(pk.affineV()), api.var("msg"),
                        api.var("rU"), api.var("rV"),
                        api.var("s"), api.var("kModL"), api.var("kQuotient"))));
    }

    // ------------------------------------------------------------------
    //  Honest path and verifier-relation equivalence
    // ------------------------------------------------------------------

    @Test
    @DisplayName("honest signatures verify through both entry points")
    void honestSignaturesVerifyThroughBoth() {
        JubjubPoint pk = EdDSAJubjub.keypairFromSecret(SK).pk();
        for (int i = 1; i <= 5; i++) {
            BigInteger msg = BigInteger.valueOf(7000L + i);
            var sig = EdDSAJubjub.sign(SK, msg);
            var w = witness(pk, sig.r(), sig.s(), msg);
            final int iter = i;
            assertDoesNotThrow(() -> strictCircuit().calculateWitness(w, CurveId.BLS12_381),
                    () -> "verifyStrict rejected honest signature " + iter);
            assertDoesNotThrow(() -> registeredCircuit().calculateWitness(w, CurveId.BLS12_381),
                    () -> "verifyWithRegisteredKey rejected honest signature " + iter);
        }
    }

    /**
     * Off-circuit acceptance must imply in-circuit acceptance, and for {@code verifyStrict}
     * the converse holds too: both apply the same cofactorless equation with the same
     * subgroup requirements. Divergences would show up here as an assertion failure rather
     * than being discovered in production.
     */
    @Test
    @DisplayName("verifier relation: off-circuit and verifyStrict agree over a randomized corpus")
    void verifierRelationAgreesOverCorpus() {
        JubjubPoint pk = EdDSAJubjub.keypairFromSecret(SK).pk();
        int checked = 0;
        for (int i = 0; i < 25; i++) {
            BigInteger msg = BigInteger.valueOf(900_000L + i * 7919L);
            var sig = EdDSAJubjub.sign(SK, msg);

            boolean offCircuitAccepts = EdDSAJubjub.verify(pk, msg, sig);
            boolean inCircuitAccepts;
            try {
                strictCircuit().calculateWitness(witness(pk, sig.r(), sig.s(), msg),
                        CurveId.BLS12_381);
                inCircuitAccepts = true;
            } catch (Exception e) {
                inCircuitAccepts = false;
            }
            assertEquals(offCircuitAccepts, inCircuitAccepts,
                    "off-circuit and verifyStrict disagreed on a valid transcript at i=" + i);

            // And a tampered variant must be rejected by both.
            BigInteger badMsg = msg.add(BigInteger.ONE);
            assertFalse(EdDSAJubjub.verify(pk, badMsg, sig));
            assertThrows(Exception.class, () -> strictCircuit().calculateWitness(
                    witness(pk, sig.r(), sig.s(), badMsg), CurveId.BLS12_381));
            checked++;
        }
        assertEquals(25, checked);
    }

    // ------------------------------------------------------------------
    //  Cost pins
    // ------------------------------------------------------------------

    @Test
    @DisplayName("cost pins for the two entry points")
    void entryPointCosts() {
        int registered = registeredCircuit().compileR1CS(CurveId.BLS12_381).constraints().size();
        int strict = strictCircuit().compileR1CS(CurveId.BLS12_381).constraints().size();
        assertEquals(8_962, registered,
                "verifyWithRegisteredKey = verifyCore (8,929) + [8]pk != O (33). Down from "
                        + "19,000 before the M5 work; the ADR target was ~8k.");
        assertEquals(14_500, strict,
                "verifyStrict adds the in-circuit [l]pk == O subgroup check. Down from 27,569; "
                        + "the ADR target was ~14k.");
        assertTrue(strict - registered > 5_000,
                "the variable-base subgroup check should dominate the difference");
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private static BigInteger nonceFor(BigInteger sk, BigInteger msg) {
        return com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash.spongeHash(
                JubjubEdDSASuite.nonceParams(), JubjubEdDSASuite.NONCE_TAG, sk, msg).mod(L);
    }

    private static CircuitBuilder strictCircuit() {
        return CircuitBuilder.create("eddsa_strict")
                .publicVar("pkU").publicVar("pkV").publicVar("msg")
                .secretVar("rU").secretVar("rV")
                .secretVar("s").secretVar("kModL").secretVar("kQuotient")
                .define(api -> InCircuitEdDSAJubjub.verifyStrict(api,
                        api.var("pkU"), api.var("pkV"), api.var("msg"),
                        api.var("rU"), api.var("rV"),
                        api.var("s"), api.var("kModL"), api.var("kQuotient")));
    }

    private static CircuitBuilder registeredCircuit() {
        return CircuitBuilder.create("eddsa_registered")
                .publicVar("pkU").publicVar("pkV").publicVar("msg")
                .secretVar("rU").secretVar("rV")
                .secretVar("s").secretVar("kModL").secretVar("kQuotient")
                .define(api -> InCircuitEdDSAJubjub.verifyWithRegisteredKey(api,
                        api.var("pkU"), api.var("pkV"), api.var("msg"),
                        api.var("rU"), api.var("rV"),
                        api.var("s"), api.var("kModL"), api.var("kQuotient")));
    }

    private static Map<String, List<BigInteger>> witness(
            JubjubPoint pk, JubjubPoint r, BigInteger s, BigInteger msg) {
        var red = InCircuitEdDSAJubjub.witnessComputeKReduction(r, pk, msg);
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("pkU", List.of(pk.affineU()));
        w.put("pkV", List.of(pk.affineV()));
        w.put("msg", List.of(msg));
        w.put("rU", List.of(r.affineU()));
        w.put("rV", List.of(r.affineV()));
        w.put("s", List.of(s));
        w.put("kModL", List.of(red.kModL()));
        w.put("kQuotient", List.of(red.kQuotient()));
        return w;
    }
}
