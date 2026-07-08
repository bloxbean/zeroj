package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
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
 * ADR-0029 M5: a proof from a {@link Groth16PkStore}-persisted key (saved then loaded, G1 mmap'd)
 * must be bit-identical to a proof from the fresh in-heap setup — i.e. the store round-trips the PK
 * exactly, so setup can be run once and reused.
 */
class Groth16PkStoreTest {

    private static final BigInteger FR = MontFr381.modulus();

    @BeforeAll
    static void allow() { System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true"); }

    private static List<R1CSConstraint> chain(int n) {
        List<R1CSConstraint> c = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++) c.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        c.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return c;
    }

    private static BigInteger[] wit(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE; BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) { w[2 + i] = a; a = a.multiply(a).mod(FR); }
        w[1] = w[n + 1]; return w;
    }

    @Test
    void saveLoad_roundTrips_proofBitIdentical(@TempDir Path dir) throws Exception {
        int n = 128;
        var cons = chain(n);
        var w = wit(n);
        BigInteger tau = PowersOfTauBLS381.generate(9).tauScalar();
        var sr = Groth16SetupBLS381.setup(cons, n + 2, 1, tau);
        int domain = Groth16ProvingKeyBLS381.count(sr.provingKey().pointsH());

        var fresh = Groth16ProverBLS381.proveUnblindedWithReaders(sr.provingKey(),
                Groth16ProverBLS381.heapReaders(sr.provingKey()), ProverBackend.PURE_JAVA, w, cons, domain);

        Groth16PkStore.save(sr, dir);
        assertTrue(Groth16PkStore.exists(dir), "store should exist after save");

        try (var loaded = Groth16PkStore.load(dir)) {
            var fromStore = Groth16ProverBLS381.proveUnblindedWithReaders(loaded.pk(),
                    loaded.readers(), ProverBackend.PURE_JAVA, w, cons, domain);

            assertEquals(fresh.a().x().toBigInteger(), fromStore.a().x().toBigInteger(), "piA.x");
            assertEquals(fresh.a().y().toBigInteger(), fromStore.a().y().toBigInteger(), "piA.y");
            assertEquals(fresh.b().x().re().toBigInteger(), fromStore.b().x().re().toBigInteger(), "piB.x.c0");
            assertEquals(fresh.b().y().im().toBigInteger(), fromStore.b().y().im().toBigInteger(), "piB.y.c1");
            assertEquals(fresh.c().x().toBigInteger(), fromStore.c().x().toBigInteger(), "piC.x");
            assertEquals(fresh.c().y().toBigInteger(), fromStore.c().y().toBigInteger(), "piC.y");
            // VK round-trips too
            assertEquals(sr.gammaG2().x().re().toBigInteger(), loaded.gammaG2().x().re().toBigInteger(), "gammaG2");
            assertEquals(sr.ic().length, loaded.ic().length, "ic count");
            assertEquals(sr.ic()[0].x().toBigInteger(), loaded.ic()[0].x().toBigInteger(), "ic[0].x");
        }
    }
}
