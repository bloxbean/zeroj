package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M5b: the {@link ParallelMsm} chunked multi-core MSM must equal the serial backend
 * (point addition is associative ⇒ same affine result), at the MSM level and for whole proofs.
 */
class ParallelMsmTest {

    private static final BigInteger R = MontFr381.modulus();

    @BeforeAll
    static void allow() { System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true"); }

    @Test
    void parallelG1Msm_equalsSerial_aboveThreshold() {
        int n = 40_000; // > MIN_PARALLEL so the parallel path actually engages
        Random rnd = new Random(42);
        long[] flat = new long[n * 12];
        BigInteger[] scalars = new BigInteger[n];
        var g = JacobianG1BLS381.GENERATOR;
        // a few distinct points repeated — cheap to build, still exercises all chunks
        long[][] pts = new long[8][];
        for (int j = 0; j < 8; j++) {
            var p = g.scalarMul(BigInteger.valueOf(2 + j)).toAffine();
            long[] one = new long[12];
            Groth16ProvingKeyBLS381.writeG1(flat, 0, p); // reuse the codec once to grab limbs
            System.arraycopy(flat, 0, one, 0, 12);
            pts[j] = one;
        }
        for (int i = 0; i < n; i++) {
            System.arraycopy(pts[i % 8], 0, flat, i * 12, 12);
            scalars[i] = new BigInteger(255, rnd).mod(R);
        }
        var reader = new PippengerFlatBLS381.HeapG1Reader(flat);

        var serial = G1MsmBackend.PURE_JAVA.msm(reader, n, scalars).toAffine();
        var parallel = ParallelMsm.parallel(G1MsmBackend.PURE_JAVA).msm(reader, n, scalars).toAffine();

        assertEquals(serial.x().toBigInteger(), parallel.x().toBigInteger(), "x");
        assertEquals(serial.y().toBigInteger(), parallel.y().toBigInteger(), "y");
    }

    @Test
    void parallelProof_bitIdentical_toSerial() {
        int n = 1024;
        List<R1CSConstraint> cons = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++)
            cons.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        cons.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = one; BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) { w[2 + i] = a; a = a.multiply(a).mod(R); }
        w[1] = w[n + 1];

        BigInteger tau = PowersOfTauBLS381.generate(4).tauScalar();
        var pk = Groth16SetupBLS381.setup(cons, n + 2, 1, tau).provingKey();
        int domain = Groth16ProvingKeyBLS381.count(pk.pointsH());
        var readers = Groth16ProverBLS381.heapReaders(pk);

        var serial = Groth16ProverBLS381.proveUnblindedWithReaders(pk, readers, ProverBackend.PURE_JAVA_SERIAL, w, cons, domain);
        var parallel = Groth16ProverBLS381.proveUnblindedWithReaders(pk, readers, ProverBackend.PURE_JAVA, w, cons, domain);

        assertEquals(serial.a().x().toBigInteger(), parallel.a().x().toBigInteger(), "piA.x");
        assertEquals(serial.b().x().re().toBigInteger(), parallel.b().x().re().toBigInteger(), "piB.x.c0");
        assertEquals(serial.c().x().toBigInteger(), parallel.c().x().toBigInteger(), "piC.x");
        assertEquals(serial.c().y().toBigInteger(), parallel.c().y().toBigInteger(), "piC.y");
    }
}
