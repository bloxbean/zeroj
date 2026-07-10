package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.cryptoblst.BlstProverBackend;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0033 M3: proving from a {@link Groth16PkStore}-loaded key — where the G2 key is read through
 * the mmap'd {@code SegmentG2Reader} raw-byte path — must produce the same proof as the in-RAM
 * heap-reader path, on both backends. The squaring-chain circuit's wires 1 and n+1 never appear in
 * any B row, so its {@code pointsB2} contains <b>infinity</b> points — this exercises the all-zero
 * coord convention through {@code readBE} (blst 0x40 encoding) and {@code get} (pure Java) too.
 */
class BlstStoreProveDifferentialTest {

    private static final BigInteger FR = MontFr381.modulus();
    private static final ProverBackend BLST = BlstProverBackend.create();

    @BeforeAll
    static void allowDevSetup() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
    }

    private static List<R1CSConstraint> squaringChain(int n) {
        List<R1CSConstraint> cons = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++)
            cons.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        cons.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return cons;
    }

    private static BigInteger[] witness(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE;
        BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) { w[2 + i] = a; a = a.multiply(a).mod(FR); }
        w[1] = w[n + 1];
        return w;
    }

    @Test
    void storeLoadedProof_segmentG2Reader_equalsInRam_bothBackends(@TempDir Path dir) throws Exception {
        int n = 1024;
        var cons = squaringChain(n);
        var w = witness(n);
        BigInteger tau = PowersOfTauBLS381.generate(4).tauScalar();
        var sr = Groth16SetupBLS381.setup(cons, n + 2, 1, tau);
        var pk = sr.provingKey();

        Groth16PkStore.save(sr, dir);
        try (var loaded = Groth16PkStore.load(dir)) {
            // The fixture must actually exercise the infinity path: wires 1 and n+1 are in no B row.
            assertTrue(loaded.readers().b2().get(1).isInfinity(), "pointsB2[1] should be infinity");
            assertTrue(loaded.readers().b2().get(n + 1).isInfinity(), "pointsB2[n+1] should be infinity");
            assertFalse(loaded.readers().b2().get(2).isInfinity(), "pointsB2[2] should be a real point");

            int domain = loaded.domain();
            var inRam = Groth16ProverBLS381.proveUnblindedWithReaders(
                    pk, Groth16ProverBLS381.heapReaders(pk), ProverBackend.PURE_JAVA, w, cons, domain);
            var storeJava = Groth16ProverBLS381.proveUnblindedWithReaders(
                    loaded.pk(), loaded.readers(), ProverBackend.PURE_JAVA, w, cons, domain);
            var storeBlst = Groth16ProverBLS381.proveUnblindedWithReaders(
                    loaded.pk(), loaded.readers(), BLST, w, cons, domain);

            assertProofEquals(inRam, storeJava, "store/pure-java");
            assertProofEquals(inRam, storeBlst, "store/blst");
        }
    }

    private static void assertProofEquals(Groth16ProofBLS381 expected, Groth16ProofBLS381 actual, String label) {
        assertEquals(expected.a().x().toBigInteger(), actual.a().x().toBigInteger(), label + " piA.x");
        assertEquals(expected.a().y().toBigInteger(), actual.a().y().toBigInteger(), label + " piA.y");
        assertEquals(expected.b().x().re().toBigInteger(), actual.b().x().re().toBigInteger(), label + " piB.x.c0");
        assertEquals(expected.b().x().im().toBigInteger(), actual.b().x().im().toBigInteger(), label + " piB.x.c1");
        assertEquals(expected.b().y().re().toBigInteger(), actual.b().y().re().toBigInteger(), label + " piB.y.c0");
        assertEquals(expected.b().y().im().toBigInteger(), actual.b().y().im().toBigInteger(), label + " piB.y.c1");
        assertEquals(expected.c().x().toBigInteger(), actual.c().x().toBigInteger(), label + " piC.x");
        assertEquals(expected.c().y().toBigInteger(), actual.c().y().toBigInteger(), label + " piC.y");
    }
}
