package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.crypto.msm.FlatScalars;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Issue #46 — a relation whose wire indices fall outside {@code [0, numWires)} must be rejected
 * at every public setup and prove ingress, never silently weakened.
 *
 * <p>Before the fix, the heap and streaming setups and every prover path skipped such terms.
 * Because setup and prover skipped the same terms, the proof <em>verified</em> — against a
 * relation the circuit author never wrote. These tests pin the fail-closed behaviour on the
 * A, B and C matrices independently, at {@code numWires}, above it, at the {@code int} extremes
 * (where {@code wire * 4} used to overflow onto a valid slot), and for negative indices, across
 * the heap, streaming, list, flat, {@code Groth16Keys} and {@code Groth16Pipeline} paths.</p>
 */
class Groth16RelationValidationTest {

    private static final BigInteger ONE = BigInteger.ONE;

    /** Multiplier {@code a * b = c} over wires {@code [1, c, a, b]}. */
    private static final int NUM_WIRES = 4;
    private static final int NUM_PUBLIC = 1;
    private static final BigInteger[] WITNESS = {
            ONE, BigInteger.valueOf(33), BigInteger.valueOf(3), BigInteger.valueOf(11)};

    private static BigInteger tau;

    @BeforeAll
    static void setUp() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
        tau = PowersOfTauBLS381.generate(4).tauScalar();
    }

    private static List<R1CSConstraint> multiplier() {
        return List.of(new R1CSConstraint(Map.of(2, ONE), Map.of(3, ONE), Map.of(1, ONE)));
    }

    /** The multiplier with matrix {@code m}'s single term moved to {@code wire}. */
    private static List<R1CSConstraint> withWire(String m, int wire) {
        Map<Integer, BigInteger> a = m.equals("A") ? Map.of(wire, ONE) : Map.of(2, ONE);
        Map<Integer, BigInteger> b = m.equals("B") ? Map.of(wire, ONE) : Map.of(3, ONE);
        Map<Integer, BigInteger> c = m.equals("C") ? Map.of(wire, ONE) : Map.of(1, ONE);
        return List.of(new R1CSConstraint(a, b, c));
    }

    private static R1CSFlat flatOf(List<R1CSConstraint> cons) {
        var b = R1CSFlat.builder();
        for (var c : cons) b.add(c.a(), c.b(), c.c());
        return b.build();
    }

    /** Every matrix × every out-of-range index class named in the issue's acceptance criteria. */
    static Stream<Arguments> outOfRangeTerms() {
        int[] wires = {NUM_WIRES, NUM_WIRES + 1, 1 << 30, Integer.MAX_VALUE, -1, Integer.MIN_VALUE};
        return Stream.of("A", "B", "C")
                .flatMap(m -> IntStream.of(wires).mapToObj(w -> Arguments.of(m, w)));
    }

    // ---- setup -----------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}[{1}]")
    @MethodSource("outOfRangeTerms")
    void heapSetup_rejectsOutOfRangeWire(String m, int wire) {
        var ex = assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setup(withWire(m, wire), NUM_WIRES, NUM_PUBLIC, tau));
        assertTrue(ex.getMessage().contains("wire " + wire), ex.getMessage());
        assertTrue(ex.getMessage().contains("R1CS " + m), ex.getMessage());
    }

    @ParameterizedTest(name = "{0}[{1}]")
    @MethodSource("outOfRangeTerms")
    void streamingSetup_rejectsOutOfRangeWire_beforeWritingAnything(String m, int wire, @TempDir Path tmp) {
        Path dir = tmp.resolve("keys");
        var flat = flatOf(withWire(m, wire));
        for (boolean sparse : new boolean[]{true, false}) {
            var ex = assertThrows(IllegalArgumentException.class,
                    () -> Groth16SetupBLS381.setupToStore(flat, NUM_WIRES, NUM_PUBLIC, tau, dir, sparse));
            assertTrue(ex.getMessage().contains("wire " + wire), ex.getMessage());
        }
        assertFalse(Files.exists(dir), "setup must fail before the key store directory is created");
    }

    @ParameterizedTest(name = "{0}[{1}]")
    @MethodSource("outOfRangeTerms")
    void facadeAndPipeline_rejectOutOfRangeWire(String m, int wire, @TempDir Path tmp) {
        var bad = withWire(m, wire);
        assertThrows(IllegalArgumentException.class,
                () -> Groth16Keys.setupInMemory(bad, NUM_WIRES, NUM_PUBLIC, tau));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16Keys.setupToStore(flatOf(bad), NUM_WIRES, NUM_PUBLIC, tau, tmp.resolve("k"), true));
        // the canonical pipeline path already rejected this; it must keep doing so
        assertThrows(IllegalArgumentException.class,
                () -> new Groth16Pipeline.Compiled(flatOf(bad), 1, NUM_WIRES, NUM_PUBLIC));
    }

    @Test
    void setup_rejectsInconsistentDimensions(@TempDir Path tmp) {
        var cons = multiplier();
        var flat = flatOf(cons);
        assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setup(cons, 0, 0, tau), "numWires 0");
        assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setup(cons, NUM_WIRES, -1, tau), "negative numPublic");
        assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setup(cons, NUM_WIRES, NUM_WIRES, tau), "numPublic == numWires");
        assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setup(cons, NUM_WIRES, NUM_WIRES + 1, tau), "numPublic > numWires");
        // the undersized-numWires mistake: the relation reaches wire 3, the caller declares 3 wires
        assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setup(cons, NUM_WIRES - 1, NUM_PUBLIC, tau), "numWires too small");
        assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setupToStore(flat, NUM_WIRES - 1, NUM_PUBLIC, tau, tmp.resolve("a"), false));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setupToStore(flat, NUM_WIRES, NUM_WIRES, tau, tmp.resolve("b"), true));
        assertFalse(Files.exists(tmp.resolve("a")));
        assertFalse(Files.exists(tmp.resolve("b")));
    }

    // ---- prove -----------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}[{1}]")
    @MethodSource("outOfRangeTerms")
    void prover_rejectsOutOfRangeWire_onEveryEntryPoint(String m, int wire) {
        var sr = Groth16SetupBLS381.setup(multiplier(), NUM_WIRES, NUM_PUBLIC, tau);
        var pk = sr.provingKey();
        int domain = Groth16ProvingKeyBLS381.count(pk.pointsH());
        var readers = Groth16ProverBLS381.heapReaders(pk);
        var bad = withWire(m, wire);
        var badFlat = flatOf(bad);
        var packed = FlatScalars.pack(WITNESS, WITNESS.length);

        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.prove(pk, WITNESS, bad, NUM_WIRES));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.prove(pk, WITNESS, bad, NUM_WIRES, domain));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.proveWithReaders(pk, readers, WITNESS, bad, NUM_WIRES, domain));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.proveWithReaders(pk, readers, ProverBackend.PURE_JAVA,
                        WITNESS, bad, NUM_WIRES, domain));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.proveUnblindedWithReaders(pk, readers, ProverBackend.PURE_JAVA,
                        WITNESS, bad, domain));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.computeH(bad, WITNESS, bad.size(), domain));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.computeH(badFlat, WITNESS, 0, domain));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.computeHFlat(badFlat, packed, 0, domain));
        try (var keys = Groth16Keys.of(sr)) {
            assertThrows(IllegalArgumentException.class, () -> keys.prove(WITNESS, bad));
            assertThrows(IllegalArgumentException.class,
                    () -> keys.prove(ProverBackend.PURE_JAVA, packed, badFlat, 0));
        }
    }

    @Test
    void prover_rejectsWitnessAndKeyDimensionMismatches() {
        var sr = Groth16SetupBLS381.setup(multiplier(), NUM_WIRES, NUM_PUBLIC, tau);
        var pk = sr.provingKey();
        int domain = Groth16ProvingKeyBLS381.count(pk.pointsH());
        var readers = Groth16ProverBLS381.heapReaders(pk);
        var cons = multiplier();
        var flat = flatOf(cons);
        var packed = FlatScalars.pack(WITNESS, WITNESS.length);

        // witness length disagrees with the declared numWires
        BigInteger[] shortWitness = {ONE, BigInteger.valueOf(33), BigInteger.valueOf(3)};
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.proveWithReaders(pk, readers, shortWitness, cons, NUM_WIRES, domain));
        // length agrees with an undersized numWires, but the relation reaches beyond it
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.proveWithReaders(pk, readers, shortWitness, cons, 3, domain));
        // the relation validates against a longer witness, but the witness does not fit the key
        BigInteger[] longWitness = Arrays.copyOf(WITNESS, NUM_WIRES + 1);
        longWitness[NUM_WIRES] = BigInteger.ZERO;
        var ex = assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.proveWithReaders(pk, readers, longWitness, cons, NUM_WIRES + 1, domain));
        assertTrue(ex.getMessage().contains("proving key"), ex.getMessage());
        // an H vector that does not match the key's H points
        BigInteger[] hWrong = new BigInteger[domain + 1];
        Arrays.fill(hWrong, ONE);
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.proveWithHCoeffs(pk, readers, ProverBackend.PURE_JAVA, WITNESS, hWrong));
        // binding rows outside the witness, or pushing the relation past the FFT domain
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.computeHFlat(flat, packed, -1, domain));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.computeHFlat(flat, packed, NUM_WIRES + 1, domain));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.computeHFlat(flat, packed, NUM_WIRES, domain), "1 + 4 rows > domain 4");
        // an FFT domain that is not a power of two
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.computeH(cons, WITNESS, cons.size(), 3));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.computeH(flat, WITNESS, 0, 6));
        // the empty witness
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.computeH(cons, new BigInteger[0], cons.size(), domain));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.proveWithReaders(pk, readers, new BigInteger[0], cons, 0, domain));
    }

    // ---- positive boundary + the closed failure mode ------------------------------------------

    /** Wire {@code numWires - 1} is the last valid index: the multiplier's B term sits there. */
    @Test
    void boundaryWire_numWiresMinusOne_isAcceptedAndVerifies() {
        var cons = multiplier();
        try (var keys = Groth16Keys.setupInMemory(cons, NUM_WIRES, NUM_PUBLIC, tau)) {
            var proof = keys.prove(WITNESS, cons);
            assertTrue(pairingVerify(keys, proof, WITNESS[1]), "honest proof must verify");
            assertFalse(pairingVerify(keys, proof, WITNESS[1].add(ONE)), "wrong public input must fail");

            var flatProof = keys.prove(ProverBackend.PURE_JAVA,
                    FlatScalars.pack(WITNESS, NUM_WIRES), flatOf(cons), 0);
            assertTrue(pairingVerify(keys, flatProof, WITNESS[1]), "flat prove path must verify");
        }
    }

    /**
     * The failure mode this issue closes. Before the fix, {@code (a + junk) * b = c} with
     * {@code junk} on wire {@code numWires} lost the {@code junk} term in both setup and prover,
     * so the honest {@code a * b = c} witness produced a verifying proof for a relation the
     * author never wrote. Setup and prover now both refuse the relation.
     */
    @Test
    void silentlyWeakenedRelation_isRejectedInsteadOfProved() {
        var weakened = List.of(new R1CSConstraint(
                Map.of(2, ONE, NUM_WIRES, ONE), Map.of(3, ONE), Map.of(1, ONE)));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16SetupBLS381.setup(weakened, NUM_WIRES, NUM_PUBLIC, tau));

        var honest = Groth16SetupBLS381.setup(multiplier(), NUM_WIRES, NUM_PUBLIC, tau);
        assertThrows(IllegalArgumentException.class,
                () -> Groth16ProverBLS381.prove(honest.provingKey(), WITNESS, weakened, NUM_WIRES));
    }

    // ---- Groth16 pairing verification from the handle's VK components ----

    private static boolean pairingVerify(Groth16Keys keys, Groth16ProofBLS381 proof, BigInteger pub) {
        G1Point vkX = toG1(keys.ic()[0]).add(toG1(keys.ic()[1]).scalarMul(pub));
        return BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(proof.a()), toG1(keys.pk().alphaG1()).negate(), vkX.negate(),
                        toG1(proof.c()).negate()},
                new G2Point[]{toG2(proof.b()), toG2(keys.pk().betaG2()), toG2(keys.gammaG2()),
                        toG2(keys.pk().deltaG2())});
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
