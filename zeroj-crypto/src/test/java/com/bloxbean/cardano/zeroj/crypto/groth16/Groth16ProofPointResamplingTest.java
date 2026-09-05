package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.crypto.msm.FlatScalars;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0045 P1/P2 — the prover never returns a proof point at infinity. The event has
 * probability on the order of {@code 1/r} with random blinders, so it is forced here: with the
 * explicit-randomness setup and an independent Lagrange evaluation the test computes the exact
 * {@code r*} (or {@code s*}) that cancels {@code A} (or {@code B}), feeds it through the
 * package-private blinder seam, and checks that the randomized path resamples while the
 * deterministic unblinded path fails closed.
 *
 * <p>Relation: {@code a * b = c} and {@code 1 * 1 = 1} over wires {@code [1, c, a, b]},
 * witness {@code [1, 33, 3, 11]}. With {@code L_i = L_i(tau)} on the size-4 domain:
 * {@code A_unblinded = alpha + L_1 + 3 L_0}, {@code B_unblinded = beta + L_1 + 11 L_0}
 * (as scalars of the respective generators), and {@code A = A_unblinded + r * delta}.</p>
 */
class Groth16ProofPointResamplingTest {

    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger FR = MontFr381.modulus();
    private static final int NUM_WIRES = 4;
    private static final int NUM_PUBLIC = 1;
    private static final List<R1CSConstraint> RELATION = List.of(
            new R1CSConstraint(Map.of(2, ONE), Map.of(3, ONE), Map.of(1, ONE)),
            new R1CSConstraint(Map.of(0, ONE), Map.of(0, ONE), Map.of(0, ONE)));
    private static final BigInteger[] WITNESS = {ONE, BigInteger.valueOf(33), BigInteger.valueOf(3), BigInteger.valueOf(11)};

    private static BigInteger tau, alpha, beta, gamma, delta, aUnblinded, bUnblinded;
    private static Groth16SetupBLS381.SetupResult setup;

    @BeforeAll
    static void setUp() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
        tau = PowersOfTauBLS381.generate(4).tauScalar();
        var rng = new SecureRandom();
        alpha = Groth16InfinityIcProfileTest.nonzeroScalar(rng);
        beta = Groth16InfinityIcProfileTest.nonzeroScalar(rng);
        gamma = Groth16InfinityIcProfileTest.nonzeroScalar(rng);
        delta = Groth16InfinityIcProfileTest.nonzeroScalar(rng);
        setup = Groth16SetupBLS381.setup(RELATION, NUM_WIRES, NUM_PUBLIC, tau, alpha, beta, gamma, delta);

        BigInteger[] l = Groth16InfinityIcProfileTest.lagrangeAt(tau, 4);
        // sum_i w_i u_i(tau): u_0 = L_1 (row 1 A), u_2 = L_0 (row 0 A); w_0 = 1, w_2 = 3
        aUnblinded = alpha.add(l[1]).add(l[0].multiply(WITNESS[2])).mod(FR);
        // sum_i w_i v_i(tau): v_0 = L_1 (row 1 B), v_3 = L_0 (row 0 B); w_0 = 1, w_3 = 11
        bUnblinded = beta.add(l[1]).add(l[0].multiply(WITNESS[3])).mod(FR);
    }

    private static FlatScalars packedWitness() {
        return FlatScalars.pack(WITNESS, WITNESS.length);
    }

    private static FlatScalars packedH() {
        int domain = Groth16ProvingKeyBLS381.count(setup.provingKey().pointsH());
        BigInteger[] h = Groth16ProverBLS381.computeH(RELATION, WITNESS, RELATION.size(), domain);
        return FlatScalars.pack(h, h.length);
    }

    private static BigInteger cancelling(BigInteger unblinded) {
        return unblinded.negate().multiply(delta.modInverse(FR)).mod(FR);
    }

    /** {@code {r, s}} pairs: the first {@code poisoned} draws cancel a point, later ones are random. */
    private static Groth16ProverBLS381.BlinderSource poisonedThenRandom(BigInteger[] poison, int poisoned,
                                                                       AtomicInteger draws) {
        var rng = new SecureRandom();
        return () -> {
            int n = draws.getAndIncrement();
            if (n < poisoned) return poison.clone();
            return new BigInteger[]{Groth16InfinityIcProfileTest.nonzeroScalar(rng),
                    Groth16InfinityIcProfileTest.nonzeroScalar(rng)};
        };
    }

    @Test
    void randomizedProve_resamplesWhenAWouldBeInfinity() {
        BigInteger rStar = cancelling(aUnblinded);
        BigInteger[] poison = {rStar, BigInteger.valueOf(7)};
        var draws = new AtomicInteger();
        var proof = Groth16ProverBLS381.proveBlinded(setup.provingKey(),
                Groth16ProverBLS381.heapReaders(setup.provingKey()), ProverBackend.PURE_JAVA,
                packedWitness(), packedH(), poisonedThenRandom(poison, 1, draws));
        assertEquals(2, draws.get(), "the cancelling (r, s) must be discarded and one fresh pair drawn");
        assertFalse(proof.a().isInfinity());
        assertFalse(proof.b().isInfinity());
        assertFalse(proof.c().isInfinity());
        assertTrue(pairingVerify(proof, WITNESS[1]), "the resampled proof must verify");
    }

    @Test
    void randomizedProve_resamplesWhenBWouldBeInfinity() {
        BigInteger sStar = cancelling(bUnblinded);
        BigInteger[] poison = {BigInteger.valueOf(5), sStar};
        var draws = new AtomicInteger();
        var proof = Groth16ProverBLS381.proveBlinded(setup.provingKey(),
                Groth16ProverBLS381.heapReaders(setup.provingKey()), ProverBackend.PURE_JAVA,
                packedWitness(), packedH(), poisonedThenRandom(poison, 3, draws));
        assertEquals(4, draws.get(), "three cancelling pairs discarded, then one fresh pair");
        assertTrue(pairingVerify(proof, WITNESS[1]));
    }

    /** Also validates {@code r*} itself: a wrong {@code r*} would not trigger the bound. */
    @Test
    void randomizedProve_failsClosedWhenEverySampleCancelsAPoint() {
        BigInteger[] poison = {cancelling(aUnblinded), BigInteger.valueOf(9)};
        var draws = new AtomicInteger();
        var ex = assertThrows(IllegalStateException.class,
                () -> Groth16ProverBLS381.proveBlinded(setup.provingKey(),
                        Groth16ProverBLS381.heapReaders(setup.provingKey()), ProverBackend.PURE_JAVA,
                        packedWitness(), packedH(), poisonedThenRandom(poison, Integer.MAX_VALUE, draws)));
        assertEquals(Groth16ProverBLS381.MAX_BLINDER_RESAMPLES, draws.get());
        assertTrue(ex.getMessage().contains("point at infinity"), ex.getMessage());
    }

    @Test
    void randomizedProve_rejectsMalformedBlinderSource() {
        assertThrows(IllegalStateException.class,
                () -> Groth16ProverBLS381.proveBlinded(setup.provingKey(),
                        Groth16ProverBLS381.heapReaders(setup.provingKey()), ProverBackend.PURE_JAVA,
                        packedWitness(), packedH(), () -> null));
        assertThrows(IllegalStateException.class,
                () -> Groth16ProverBLS381.proveBlinded(setup.provingKey(),
                        Groth16ProverBLS381.heapReaders(setup.provingKey()), ProverBackend.PURE_JAVA,
                        packedWitness(), packedH(), () -> new BigInteger[]{ONE}));
    }

    /**
     * P2: with {@code alpha* = -(L_1 + 3 L_0)} the unblinded {@code A} is exactly the identity.
     * The deterministic path cannot resample and must throw; the randomized path on the same
     * key still proves (its {@code r * delta} term is nonzero with overwhelming probability).
     */
    @Test
    void unblindedProve_failsClosedInsteadOfReturningInfinity() {
        BigInteger[] l = Groth16InfinityIcProfileTest.lagrangeAt(tau, 4);
        BigInteger alphaStar = l[1].add(l[0].multiply(WITNESS[2])).negate().mod(FR);
        var cancelled = Groth16SetupBLS381.setup(RELATION, NUM_WIRES, NUM_PUBLIC, tau, alphaStar, beta, gamma, delta);
        var pk = cancelled.provingKey();
        int domain = Groth16ProvingKeyBLS381.count(pk.pointsH());
        var ex = assertThrows(IllegalStateException.class,
                () -> Groth16ProverBLS381.proveUnblindedWithReaders(pk, Groth16ProverBLS381.heapReaders(pk),
                        ProverBackend.PURE_JAVA, WITNESS, RELATION, domain));
        assertTrue(ex.getMessage().contains("point at infinity"), ex.getMessage());

        var proof = Groth16ProverBLS381.prove(pk, WITNESS, RELATION, NUM_WIRES);
        assertFalse(proof.a().isInfinity());
        assertTrue(pairingVerify(cancelled, proof, WITNESS[1]));
    }

    @Test
    void publicProveEntryPoints_stillProduceVerifyingProofs() {
        var pk = setup.provingKey();
        int domain = Groth16ProvingKeyBLS381.count(pk.pointsH());
        var readers = Groth16ProverBLS381.heapReaders(pk);
        assertTrue(pairingVerify(Groth16ProverBLS381.prove(pk, WITNESS, RELATION, NUM_WIRES), WITNESS[1]));
        assertTrue(pairingVerify(Groth16ProverBLS381.proveWithReaders(pk, readers, WITNESS, RELATION, NUM_WIRES, domain),
                WITNESS[1]));
        BigInteger[] h = Groth16ProverBLS381.computeH(RELATION, WITNESS, RELATION.size(), domain);
        assertTrue(pairingVerify(Groth16ProverBLS381.proveWithHCoeffs(pk, readers, ProverBackend.PURE_JAVA, WITNESS, h),
                WITNESS[1]));
        try (var keys = Groth16Keys.of(setup)) {
            assertTrue(pairingVerify(keys.prove(WITNESS, RELATION), WITNESS[1]));
        }
    }

    // ---- pairing verification from the setup's VK components ----

    private static boolean pairingVerify(Groth16ProofBLS381 proof, BigInteger pub) {
        return pairingVerify(setup, proof, pub);
    }

    private static boolean pairingVerify(Groth16SetupBLS381.SetupResult s, Groth16ProofBLS381 proof, BigInteger pub) {
        G1Point vkX = toG1(s.ic()[0]).add(toG1(s.ic()[1]).scalarMul(pub));
        return BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(proof.a()), toG1(s.provingKey().alphaG1()).negate(), vkX.negate(), toG1(proof.c()).negate()},
                new G2Point[]{toG2(proof.b()), toG2(s.provingKey().betaG2()), toG2(s.gammaG2()), toG2(s.provingKey().deltaG2())});
    }

    private static G1Point toG1(JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2(JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
