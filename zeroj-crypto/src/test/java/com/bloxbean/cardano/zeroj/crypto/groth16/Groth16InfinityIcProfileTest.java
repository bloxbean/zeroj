package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.api.VerificationResult;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.Groth16BLS12381Verifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Issue #52 / ADR-0045 — the native setup must never emit a verification key that the ADR-0025
 * verifier profile rejects, and every provider must reject the same keys the same way.
 *
 * <p>Before the fix the relation below ({@code a * b = c}, {@code 1 * 1 = 1} over wires
 * {@code [1, c, p, a, b]} with public {@code c, p}) set up "successfully" with
 * {@code IC[2] = infinity}, and both JSON verifiers then rejected the key with
 * {@code vk.IC[2] must not be point at infinity}. Setup now rejects the relation at ingress on
 * every entry point (S1); the exact scalar check (S2) is forced independently below.</p>
 */
class Groth16InfinityIcProfileTest {

    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger FR = MontFr381.modulus();
    private static final R1CSConstraint ONE_ROW =
            new R1CSConstraint(Map.of(0, ONE), Map.of(0, ONE), Map.of(0, ONE));

    /** Wires {@code [1, c, p, a, b]}, public {@code c, p}. */
    private static final int NUM_WIRES = 5;
    private static final int NUM_PUBLIC = 2;
    private static final BigInteger[] WITNESS = {
            ONE, BigInteger.valueOf(33), BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(11)};

    /** {@code a * b = c}; public wire 2 ({@code p}) appears in no row. */
    private static final List<R1CSConstraint> UNBOUND_P = List.of(
            new R1CSConstraint(Map.of(3, ONE), Map.of(4, ONE), Map.of(1, ONE)), ONE_ROW);
    /** {@code UNBOUND_P} plus the trivially satisfied binding row {@code p * 1 = p}. */
    private static final List<R1CSConstraint> BOUND = List.of(
            new R1CSConstraint(Map.of(3, ONE), Map.of(4, ONE), Map.of(1, ONE)), ONE_ROW,
            new R1CSConstraint(Map.of(2, ONE), Map.of(0, ONE), Map.of(2, ONE)));
    /** {@code a * b = c} alone over {@code [1, c, a, b]}: no row references the constant wire. */
    private static final List<R1CSConstraint> NO_CONSTANT_TERM = List.of(
            new R1CSConstraint(Map.of(2, ONE), Map.of(3, ONE), Map.of(1, ONE)));

    private static BigInteger tau;

    @BeforeAll
    static void setUp() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
        tau = PowersOfTauBLS381.generate(4).tauScalar();
    }

    private static R1CSFlat flatOf(List<R1CSConstraint> cons) {
        var b = R1CSFlat.builder();
        for (var c : cons) b.add(c.a(), c.b(), c.c());
        return b.build();
    }

    // ---- S1: structural rejection on every setup entry point ---------------------------------

    @Test
    void heapSetup_rejectsUnboundPublicWire_namingIt() {
        var ex = assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setup(UNBOUND_P, NUM_WIRES, NUM_PUBLIC, tau));
        assertTrue(ex.getMessage().contains("public wire 2"), ex.getMessage());
        assertTrue(ex.getMessage().contains("IC[2]"), ex.getMessage());
    }

    @Test
    void streamingSetup_rejectsUnboundPublicWire_beforeWritingAnything(@TempDir Path tmp) {
        Path dir = tmp.resolve("keys");
        var flat = flatOf(UNBOUND_P);
        for (boolean sparse : new boolean[]{true, false}) {
            var ex = assertThrows(IllegalArgumentException.class,
                    () -> Groth16SetupBLS381.setupToStore(flat, NUM_WIRES, NUM_PUBLIC, tau, dir, sparse));
            assertTrue(ex.getMessage().contains("public wire 2"), ex.getMessage());
        }
        assertFalse(Files.exists(dir), "setup must fail before the key store directory is created");
    }

    @Test
    void facadeAndPipeline_rejectUnboundPublicWire(@TempDir Path tmp) {
        assertThrows(IllegalArgumentException.class,
                () -> Groth16Keys.setupInMemory(UNBOUND_P, NUM_WIRES, NUM_PUBLIC, tau));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16Keys.setupToStore(flatOf(UNBOUND_P), NUM_WIRES, NUM_PUBLIC, tau, tmp.resolve("k"), true));
        assertFalse(Files.exists(tmp.resolve("k")));
        // Compiled itself stays generic (imported ceremony keys prove the original relation plus
        // snarkjs binding rows through the same pipeline); the native pipeline setup rejects the
        // relation before creating the bundle directory, the r1cs.bin cache, or any store file.
        var cc = new Groth16Pipeline.Compiled(flatOf(UNBOUND_P), UNBOUND_P.size(), NUM_WIRES, NUM_PUBLIC);
        Path bundle = tmp.resolve("bundle");
        for (boolean sparse : new boolean[]{true, false}) {
            var ex = assertThrows(IllegalArgumentException.class,
                    () -> Groth16Pipeline.setup(cc, tau, bundle, sparse, new Groth16Pipeline.Progress() {}));
            assertTrue(ex.getMessage().contains("public wire 2"), ex.getMessage());
        }
        assertFalse(Files.exists(bundle), "pipeline setup must fail before creating the bundle directory");
    }

    @Test
    void setup_rejectsRelationWithoutConstantTerm(@TempDir Path tmp) {
        var heap = assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setup(NO_CONSTANT_TERM, 4, 1, tau));
        assertTrue(heap.getMessage().contains("constant wire 0"), heap.getMessage());
        Path dir = tmp.resolve("keys");
        var streaming = assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setupToStore(flatOf(NO_CONSTANT_TERM), 4, 1, tau, dir, true));
        assertEquals(heap.getMessage(), streaming.getMessage(), "heap and streaming setup must agree");
        assertFalse(Files.exists(dir));
    }

    @Test
    void setup_treatsCoefficientZeroModuloFieldAsAbsent() {
        // p is "referenced", but only with a coefficient ≡ 0 (mod r): still unbound
        var zeroCoefficient = new ArrayList<>(UNBOUND_P);
        zeroCoefficient.add(new R1CSConstraint(Map.of(2, FR), Map.of(0, ONE), Map.of()));
        var ex = assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setup(zeroCoefficient, NUM_WIRES, NUM_PUBLIC, tau));
        assertTrue(ex.getMessage().contains("public wire 2"), ex.getMessage());
    }

    // ---- S2: the exact scalar check, forced with crafted randomness -----------------------------

    /**
     * Relation over {@code [1, p, x, y]} (public {@code p}): {@code x * y = p} and
     * {@code p * 1 = x}. Wire {@code p} is bound (S1 passes) and appears only in A (row 1) and
     * C (row 0), so its public-query scalar is {@code (beta * L_1(tau) + L_0(tau)) / gamma}.
     * Choosing {@code beta = -L_0(tau) / L_1(tau)} makes it exactly zero; the setup must then
     * fail closed instead of writing {@code IC[1] = infinity}.
     */
    @Test
    void exactCheck_zeroPublicQueryScalar_failsClosedOnHeapAndStreaming(@TempDir Path tmp) {
        var cons = List.of(
                new R1CSConstraint(Map.of(2, ONE), Map.of(3, ONE), Map.of(1, ONE)),
                new R1CSConstraint(Map.of(1, ONE), Map.of(0, ONE), Map.of(2, ONE)));
        BigInteger[] lagrange = lagrangeAt(tau, 4);
        BigInteger betaStar = lagrange[0].negate().multiply(lagrange[1].modInverse(FR)).mod(FR);
        var rng = new SecureRandom();
        BigInteger alpha = nonzeroScalar(rng), gamma = nonzeroScalar(rng), delta = nonzeroScalar(rng);

        var heap = assertThrows(IllegalStateException.class,
                () -> Groth16SetupBLS381.setup(cons, 4, 1, tau, alpha, betaStar, gamma, delta));
        assertTrue(heap.getMessage().contains("public wire 1"), heap.getMessage());
        assertTrue(heap.getMessage().contains("IC[1]"), heap.getMessage());

        Path dir = tmp.resolve("keys");
        for (boolean sparse : new boolean[]{true, false}) {
            var streaming = assertThrows(IllegalStateException.class,
                    () -> Groth16SetupBLS381.setupToStore(flatOf(cons), 4, 1, tau, alpha, betaStar, gamma, delta,
                            dir, sparse));
            assertEquals(heap.getMessage(), streaming.getMessage(), "heap and streaming setup must agree");
        }
        assertFalse(Files.exists(dir), "setup must fail before the key store directory is created");

        // control: any other beta produces a key whose IC entries are all finite
        BigInteger betaOther = betaStar.add(ONE).mod(FR);
        var ok = Groth16SetupBLS381.setup(cons, 4, 1, tau, alpha, betaOther, gamma, delta);
        for (AffineG1 ic : ok.ic()) assertFalse(ic.isInfinity());
    }

    // ---- The bound sibling relation: sets up, proves, verifies identically on both providers ----

    @Test
    void boundRelation_verifiesOnBothProviders_andBothRejectInfinityIcTheSameWay() {
        var setup = Groth16SetupBLS381.setup(BOUND, NUM_WIRES, NUM_PUBLIC, tau);
        for (int i = 0; i < setup.ic().length; i++) assertFalse(setup.ic()[i].isInfinity(), "IC[" + i + "]");
        var proof = Groth16ProverBLS381.prove(setup.provingKey(), WITNESS, BOUND, NUM_WIRES);

        String vkJson = vkJson(setup, NUM_PUBLIC, Map.of());
        String proofJson = proofJson(proof);
        var pureJava = new Groth16BLS12381PureJavaVerifier();
        var blst = new Groth16BLS12381Verifier();

        var honest = envelope(proofJson, vkJson, List.of(WITNESS[1], WITNESS[2]));
        assertTrue(pureJava.verify(honest, material(vkJson)).proofValid());
        assertTrue(blst.verify(honest, material(vkJson)).proofValid());

        // the bound public input p is now part of the verification equation: another value fails
        var wrongP = envelope(proofJson, vkJson, List.of(WITNESS[1], WITNESS[2].add(ONE)));
        assertFalse(pureJava.verify(wrongP, material(vkJson)).proofValid());
        assertFalse(blst.verify(wrongP, material(vkJson)).proofValid());

        // V1/V3: an infinity IC entry, in the canonical projective JSON form [0, 1, 0], is rejected
        // for IC[0] and for IC[i > 0] with the same reason and message on both providers
        for (int i : new int[]{0, 2}) {
            String tampered = vkJson(setup, NUM_PUBLIC, Map.of(i, List.of(BigInteger.ZERO, ONE, BigInteger.ZERO)));
            var env = envelope(proofJson, tampered, List.of(WITNESS[1], WITNESS[2]));
            var pj = pureJava.verify(env, material(tampered));
            var bl = blst.verify(env, material(tampered));
            assertFalse(pj.proofValid(), "pure Java IC[" + i + "]");
            assertFalse(bl.proofValid(), "blst IC[" + i + "]");
            assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, pj.reasonCode().orElseThrow());
            assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, bl.reasonCode().orElseThrow());
            assertTrue(pj.message().orElseThrow().contains("vk.IC[" + i + "] must not be point at infinity"),
                    pj.message().orElseThrow());
            assertEquals(pj.message(), bl.message(), "providers must report the same rejection");
        }
    }

    // ---- helpers -----------------------------------------------------------------------------

    /**
     * Independent Lagrange basis {@code L_i(tau)} on the size-{@code n} multiplicative subgroup:
     * {@code L_i(tau) = omega^i (tau^n - 1) / (n (tau - omega^i))}. Uses the same generator
     * constant as the setup (a fixed domain convention), but not its evaluation code.
     */
    static BigInteger[] lagrangeAt(BigInteger tau, int n) {
        int logN = Integer.numberOfTrailingZeros(n);
        BigInteger omega = FieldFFTBLS381.rootOfUnity(logN).toBigInteger();
        BigInteger zh = tau.modPow(BigInteger.valueOf(n), FR).subtract(ONE).mod(FR);
        BigInteger nInv = BigInteger.valueOf(n).modInverse(FR);
        BigInteger[] out = new BigInteger[n];
        BigInteger omegaI = ONE;
        for (int i = 0; i < n; i++) {
            BigInteger denominator = tau.subtract(omegaI).mod(FR);
            assertTrue(denominator.signum() != 0, "tau must not be a domain element");
            out[i] = omegaI.multiply(zh).mod(FR).multiply(nInv).mod(FR)
                    .multiply(denominator.modInverse(FR)).mod(FR);
            omegaI = omegaI.multiply(omega).mod(FR);
        }
        return out;
    }

    static BigInteger nonzeroScalar(SecureRandom rng) {
        while (true) {
            BigInteger x = new BigInteger(1, rng.generateSeed(64)).mod(FR);
            if (x.signum() != 0) return x;
        }
    }

    static List<BigInteger> g1(AffineG1 p) {
        if (p.isInfinity()) return List.of(BigInteger.ZERO, ONE, BigInteger.ZERO);
        return List.of(p.xBigInt(), p.yBigInt(), ONE);
    }

    static List<List<BigInteger>> g2(AffineG2 p) {
        return List.of(List.of(p.x().reBigInt(), p.x().imBigInt()),
                List.of(p.y().reBigInt(), p.y().imBigInt()), List.of(ONE, BigInteger.ZERO));
    }

    static String q(List<BigInteger> v) {
        var sb = new StringBuilder("[");
        for (int i = 0; i < v.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(v.get(i)).append('"');
        }
        return sb.append(']').toString();
    }

    static String q2(List<List<BigInteger>> v) {
        var sb = new StringBuilder("[");
        for (int i = 0; i < v.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(q(v.get(i)));
        }
        return sb.append(']').toString();
    }

    /** snarkjs-format verification_key.json from a native setup, with optional IC overrides. */
    static String vkJson(Groth16SetupBLS381.SetupResult s, int numPublic, Map<Integer, List<BigInteger>> icOverride) {
        var pk = s.provingKey();
        var sb = new StringBuilder("{\"protocol\":\"groth16\",\"curve\":\"bls12381\",\"nPublic\":").append(numPublic);
        sb.append(",\"vk_alpha_1\":").append(q(g1(pk.alphaG1())));
        sb.append(",\"vk_beta_2\":").append(q2(g2(pk.betaG2())));
        sb.append(",\"vk_gamma_2\":").append(q2(g2(s.gammaG2())));
        sb.append(",\"vk_delta_2\":").append(q2(g2(pk.deltaG2())));
        sb.append(",\"vk_alphabeta_12\":[[[\"0\",\"0\"],[\"0\",\"0\"],[\"0\",\"0\"]],[[\"0\",\"0\"],[\"0\",\"0\"],[\"0\",\"0\"]]]");
        sb.append(",\"IC\":[");
        for (int i = 0; i < s.ic().length; i++) {
            if (i > 0) sb.append(',');
            sb.append(q(icOverride.getOrDefault(i, g1(s.ic()[i]))));
        }
        return sb.append("]}").toString();
    }

    static String proofJson(Groth16ProofBLS381 proof) {
        return "{\"pi_a\":" + q(g1(proof.a())) + ",\"pi_b\":" + q2(g2(proof.b())) + ",\"pi_c\":" + q(g1(proof.c()))
                + ",\"protocol\":\"groth16\",\"curve\":\"bls12381\"}";
    }

    static ZkProofEnvelope envelope(String proofJson, String vkJson, List<BigInteger> publicInputs) {
        var sb = new StringBuilder("[");
        for (int i = 0; i < publicInputs.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(publicInputs.get(i)).append('"');
        }
        return SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, sb.append(']').toString(), new CircuitId("adr-0045"));
    }

    static VerificationMaterial material(String vkJson) {
        return VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("adr-0045"));
    }
}
