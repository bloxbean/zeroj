package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.Poseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T6;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Conformance of the implementation to {@code docs/specs/jubjub-eddsa-v1.md}.
 *
 * <p>The spec is normative; these tests are what stop it from drifting away from the code.
 * They check the pinned constants, that the tags really are derived the way the spec says,
 * that domain separation actually separates, and — the one that matters most for a proof
 * system — that the off-circuit and in-circuit challenge computations agree exactly.
 */
class JubjubEdDSASuiteTest {

    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;

    // ------------------------------------------------------------------
    //  Pinned constants and their derivation
    // ------------------------------------------------------------------

    @Test
    @DisplayName("suite identifier and labels match the spec")
    void suiteIdentifiers() {
        assertEquals("ZeroJ-JubjubEdDSA-v1", JubjubEdDSASuite.SUITE_ID);
        assertEquals("ZeroJ-JubjubEdDSA-v1-challenge", JubjubEdDSASuite.CHALLENGE_TAG_LABEL);
        assertEquals("ZeroJ-JubjubEdDSA-v1-nonce", JubjubEdDSASuite.NONCE_TAG_LABEL);
    }

    @Test
    @DisplayName("tags equal OS2IP(SHA-512(label)) mod p, recomputed independently")
    void tagsMatchTheirDocumentedDerivation() throws Exception {
        // The literals are what the implementation uses; this asserts they are the values the
        // documented recipe produces, so the recipe in the spec is auditable rather than
        // decorative.
        assertEquals(deriveTag(JubjubEdDSASuite.CHALLENGE_TAG_LABEL), JubjubEdDSASuite.CHALLENGE_TAG);
        assertEquals(deriveTag(JubjubEdDSASuite.NONCE_TAG_LABEL), JubjubEdDSASuite.NONCE_TAG);
    }

    @Test
    @DisplayName("pinned tag literals match the spec table")
    void tagLiterals() {
        assertEquals(new BigInteger(
                        "00eddbdea8f7a5571d7ba19cab887f55f5225616ae1a827da58198fec59f999b", 16),
                JubjubEdDSASuite.CHALLENGE_TAG);
        assertEquals(new BigInteger(
                        "6737a0f0a6c1453e3776d8f7f0ab0181b254d79b0d450d72c46803ed651ae865", 16),
                JubjubEdDSASuite.NONCE_TAG);
    }

    @Test
    @DisplayName("tags are distinct, non-zero, canonical field elements")
    void tagsAreWellFormed() {
        for (BigInteger tag : List.of(JubjubEdDSASuite.CHALLENGE_TAG, JubjubEdDSASuite.NONCE_TAG)) {
            assertTrue(tag.signum() > 0, "a zero tag would be no separation at all");
            assertTrue(tag.compareTo(P) < 0, "tag must be a canonical field element");
        }
        assertNotEquals(JubjubEdDSASuite.CHALLENGE_TAG, JubjubEdDSASuite.NONCE_TAG);
    }

    @Test
    @DisplayName("presets: challenge is t=6 (rate 5), nonce is t=3 (rate 2)")
    void presets() {
        assertEquals(6, JubjubEdDSASuite.challengeParams().t());
        assertEquals(3, JubjubEdDSASuite.nonceParams().t());
        assertEquals(PoseidonParamsBLS12_381T6.INSTANCE, JubjubEdDSASuite.challengeParams());
        assertEquals(PoseidonParamsBLS12_381T3.INSTANCE, JubjubEdDSASuite.nonceParams());
    }

    // ------------------------------------------------------------------
    //  Domain separation actually separates
    // ------------------------------------------------------------------

    @Test
    @DisplayName("the domain tag changes the sponge output — separation is real, not decorative")
    void tagChangesOutput() {
        BigInteger a = BigInteger.valueOf(11), b = BigInteger.valueOf(22);
        BigInteger untagged = PoseidonHash.spongeHash(
                JubjubEdDSASuite.nonceParams(), BigInteger.ZERO, a, b);
        BigInteger tagged = PoseidonHash.spongeHash(
                JubjubEdDSASuite.nonceParams(), JubjubEdDSASuite.NONCE_TAG, a, b);
        assertNotEquals(untagged, tagged);
    }

    @Test
    @DisplayName("a nonce value cannot be reinterpreted as a challenge, or vice versa")
    void nonceAndChallengeAreSeparated() {
        // Different tag AND different width, so there is no input assignment under which one
        // construction reproduces the other's output for the same data.
        BigInteger x = BigInteger.valueOf(7), y = BigInteger.valueOf(9);
        BigInteger nonce = PoseidonHash.spongeHash(
                JubjubEdDSASuite.nonceParams(), JubjubEdDSASuite.NONCE_TAG, x, y);
        BigInteger challengeLike = PoseidonHash.spongeHash(
                JubjubEdDSASuite.challengeParams(), JubjubEdDSASuite.CHALLENGE_TAG, x, y);
        assertNotEquals(nonce, challengeLike);
    }

    // ------------------------------------------------------------------
    //  Off-circuit and in-circuit agreement
    // ------------------------------------------------------------------

    @Test
    @DisplayName("off-circuit and in-circuit challenge agree exactly")
    void challengeAgreesAcrossTheBoundary() {
        // If these ever diverge, honest provers fail and the failure is opaque. Assert it
        // directly rather than inferring it from an end-to-end test.
        BigInteger sk = new BigInteger("abcdef0123456789", 16).mod(L);
        JubjubPoint pk = EdDSAJubjub.keypairFromSecret(sk).pk();

        for (int i = 0; i < 5; i++) {
            BigInteger msg = BigInteger.valueOf(500L + i);
            var sig = EdDSAJubjub.sign(sk, msg);

            BigInteger offCircuitRaw = PoseidonHash.spongeHash(
                    JubjubEdDSASuite.challengeParams(), JubjubEdDSASuite.CHALLENGE_TAG,
                    sig.r().affineU(), sig.r().affineV(), pk.affineU(), pk.affineV(), msg);

            var circuit = CircuitBuilder.create("challenge_oracle_" + i)
                    .publicVar("out")
                    .secretVar("rU").secretVar("rV").secretVar("pkU").secretVar("pkV")
                    .secretVar("msg")
                    .define(api -> api.assertEqual(
                            Poseidon.spongeHash(api, JubjubEdDSASuite.challengeParams(),
                                    api.constant(JubjubEdDSASuite.CHALLENGE_TAG),
                                    api.var("rU"), api.var("rV"),
                                    api.var("pkU"), api.var("pkV"), api.var("msg")),
                            api.var("out")));

            final int iter = i;
            assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                    "out", List.of(offCircuitRaw),
                    "rU", List.of(sig.r().affineU()),
                    "rV", List.of(sig.r().affineV()),
                    "pkU", List.of(pk.affineU()),
                    "pkV", List.of(pk.affineV()),
                    "msg", List.of(msg)
            ), CurveId.BLS12_381), () -> "challenge diverged across the boundary at i=" + iter);
        }
    }

    @Test
    @DisplayName("witnessComputeKReduction matches computeChallenge, so honest provers succeed")
    void witnessHelperMatchesTheChallenge() {
        BigInteger sk = new BigInteger("1122334455667788", 16).mod(L);
        JubjubPoint pk = EdDSAJubjub.keypairFromSecret(sk).pk();
        for (int i = 0; i < 5; i++) {
            BigInteger msg = BigInteger.valueOf(90_000L + i);
            var sig = EdDSAJubjub.sign(sk, msg);
            var red = InCircuitEdDSAJubjub.witnessComputeKReduction(sig.r(), pk, msg);
            assertEquals(EdDSAJubjub.computeChallenge(sig.r(), pk, msg), red.kModL(),
                    "the witness helper and the signer must derive the same challenge");
            assertTrue(red.kQuotient().compareTo(BigInteger.valueOf(8)) <= 0);
        }
    }

    @Test
    @DisplayName("off-circuit and in-circuit t=6 permutations agree on random states")
    void permutationsAgree() {
        var params = PoseidonParamsBLS12_381T6.INSTANCE;
        BigInteger[] state = new BigInteger[6];
        for (int i = 0; i < 6; i++) state[i] = BigInteger.valueOf(1000L + i * 37L);
        BigInteger expected = PoseidonHash.permute(params, state)[0];

        var circuit = CircuitBuilder.create("t6_permute")
                .publicVar("out")
                .secretVar("s0").secretVar("s1").secretVar("s2")
                .secretVar("s3").secretVar("s4").secretVar("s5")
                .define(api -> {
                    var in = new com.bloxbean.cardano.zeroj.circuit.Variable[]{
                            api.var("s0"), api.var("s1"), api.var("s2"),
                            api.var("s3"), api.var("s4"), api.var("s5")};
                    api.assertEqual(Poseidon.permute(api, params, in)[0], api.var("out"));
                });
        assertDoesNotThrow(() -> circuit.calculateWitness(Map.of(
                "out", List.of(expected),
                "s0", List.of(state[0]), "s1", List.of(state[1]), "s2", List.of(state[2]),
                "s3", List.of(state[3]), "s4", List.of(state[4]), "s5", List.of(state[5])
        ), CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  Cost claim in the spec
    // ------------------------------------------------------------------

    @Test
    @DisplayName("spec cost claim: t=6 tagged challenge is cheaper than the t=3 folded one")
    void t6IsCheaperThanFolding() {
        int t6 = CircuitBuilder.create("cost_t6")
                .secretVar("a").secretVar("b").secretVar("c").secretVar("d").secretVar("e")
                .define(api -> Poseidon.spongeHash(api, JubjubEdDSASuite.challengeParams(),
                        api.constant(JubjubEdDSASuite.CHALLENGE_TAG),
                        api.var("a"), api.var("b"), api.var("c"), api.var("d"), api.var("e")))
                .compileR1CS(CurveId.BLS12_381).constraints().size();

        int t3fold = CircuitBuilder.create("cost_t3fold")
                .secretVar("a").secretVar("b").secretVar("c").secretVar("d").secretVar("e")
                .define(api -> com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN.hash(api,
                        PoseidonParamsBLS12_381T3.INSTANCE,
                        api.var("a"), api.var("b"), api.var("c"), api.var("d"), api.var("e")))
                .compileR1CS(CurveId.BLS12_381).constraints().size();

        assertEquals(321, t6, "tagged t=6 challenge, after constant-multiplication folding");
        assertEquals(960, t3fold, "the untagged four-fold t=3 chain, same compiler");
        assertTrue(t6 < t3fold,
                "the wide permutation must be cheaper AND domain-separated, which is why no "
                        + "folded interim was shipped");
    }

    private static BigInteger deriveTag(String label) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-512")
                .digest(label.getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, digest).mod(P);
    }
}
