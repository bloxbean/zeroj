package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.msm.MmapG1File;
import com.bloxbean.cardano.zeroj.crypto.msm.PippengerFlatBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M4 end-to-end: proving with the G1 proving key read from mmap'd files produces the
 * <b>bit-identical</b> proof to proving from the on-heap key (unblinded, so deterministic). Confirms
 * the whole prover runs correctly with the PK off-heap / file-backed.
 */
class MmapProveBLS381Test {

    private static final BigInteger FR = MontFr381.modulus();

    @BeforeAll
    static void allowDevSetup() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
    }

    @Test
    void mmapProof_equalsHeapProof() throws Exception {
        int n = 4096; // 2^12 squaring chain
        List<R1CSConstraint> constraints = squaringChain(n);
        int numWires = n + 2;
        BigInteger[] witness = squaringWitness(n);
        int domainSize = Integer.highestOneBit(Math.max(2, n - 1)) << 1;

        BigInteger tau = PowersOfTauBLS381.generate(4).tauScalar();
        var pk = Groth16SetupBLS381.setup(constraints, numWires, 1, tau).provingKey();

        // Heap prove (unblinded → deterministic)
        var heap = Groth16ProverBLS381.proveUnblindedWithReaders(
                pk, Groth16ProverBLS381.heapReaders(pk), witness, constraints, domainSize);

        // Write the 4 G1 key arrays to files, mmap, prove reading from the segments
        Path dir = Files.createTempDirectory("zeroj-pk-mmap");
        Path fa = dir.resolve("a.bin"), fb1 = dir.resolve("b1.bin"), fh = dir.resolve("h.bin"), fl = dir.resolve("l.bin");
        MmapG1File.write(pk.pointsA(), fa);
        MmapG1File.write(pk.pointsB1(), fb1);
        MmapG1File.write(pk.pointsH(), fh);
        MmapG1File.write(pk.pointsL(), fl);

        try (Arena arena = Arena.ofShared()) {
            var readers = new Groth16ProverBLS381.G1Readers(
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(fa, arena)),
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(fb1, arena)),
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(fh, arena)),
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(fl, arena)));
            var mmap = Groth16ProverBLS381.proveUnblindedWithReaders(pk, readers, witness, constraints, domainSize);

            assertProofEquals(heap, mmap);
        } finally {
            for (Path p : List.of(fa, fb1, fh, fl)) Files.deleteIfExists(p);
            Files.deleteIfExists(dir);
        }
    }

    private static void assertProofEquals(Groth16ProofBLS381 a, Groth16ProofBLS381 b) {
        // piA uses the G1 A-reader; piC uses the H- and L-readers (unblinded). Both must match
        // bit-for-bit. (The B1-reader uses the identical SegmentG1Reader path, proven separately by
        // MmapMsmBLS381Test; in an unblinded proof its contribution is multiplied by r=0.)
        assertEquals(a.a().x().toBigInteger(), b.a().x().toBigInteger(), "piA.x");
        assertEquals(a.a().y().toBigInteger(), b.a().y().toBigInteger(), "piA.y");
        assertEquals(a.c().x().toBigInteger(), b.c().x().toBigInteger(), "piC.x");
        assertEquals(a.c().y().toBigInteger(), b.c().y().toBigInteger(), "piC.y");
    }

    private static List<R1CSConstraint> squaringChain(int n) {
        List<R1CSConstraint> cons = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++)
            cons.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        cons.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return cons;
    }

    private static BigInteger[] squaringWitness(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE;
        BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) { w[2 + i] = a; a = a.multiply(a).mod(FR); }
        w[1] = w[n + 1];
        return w;
    }
}
