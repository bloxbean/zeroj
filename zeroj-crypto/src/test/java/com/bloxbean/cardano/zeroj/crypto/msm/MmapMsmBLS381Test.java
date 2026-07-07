package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M4: MSM reading the proving key from an mmap'd {@link MemorySegment} must produce the
 * same result as reading from the on-heap {@code long[]}. Proves the prover can run with the PK
 * file-backed (off-heap) with no change to the arithmetic.
 */
class MmapMsmBLS381Test {

    private static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final Random RND = new Random(0x44AA2F01L);

    private static BigInteger[] affinePointsAndScalars(int n, long[] flatOut) {
        BigInteger[] scalars = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            var a = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(i + 2L)).toAffine();
            System.arraycopy(a.x().toLimbs(), 0, flatOut, i * 12, 6);
            System.arraycopy(a.y().toLimbs(), 0, flatOut, i * 12 + 6, 6);
            scalars[i] = new BigInteger(255, RND).mod(R);
        }
        return scalars;
    }

    private static BigInteger[] affine(JacobianG1BLS381 j) {
        if (j.isInfinity()) return null;
        var a = j.toAffine();
        return new BigInteger[]{ a.x().toBigInteger(), a.y().toBigInteger() };
    }

    @Test
    void segmentMsm_matchesHeapMsm() throws Exception {
        for (int n : new int[]{1, 5, 64, 300}) {
            long[] flat = new long[n * 12];
            BigInteger[] scalars = affinePointsAndScalars(n, flat);

            JacobianG1BLS381 heap = PippengerFlatBLS381.msmFlat(flat, n, scalars);

            Path f = Files.createTempFile("zeroj-pk-", ".bin");
            try {
                MmapG1File.write(flat, f);
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment seg = MmapG1File.map(f, arena);
                    assertEquals(n, new PippengerFlatBLS381.SegmentG1Reader(seg).count(), "point count from segment");
                    JacobianG1BLS381 mmap = PippengerFlatBLS381.msmSegment(seg, n, scalars);
                    assertArrayEquals(affine(heap), affine(mmap), "mmap MSM != heap MSM at n=" + n);
                }
            } finally {
                Files.deleteIfExists(f);
            }
        }
    }

    @Test
    void mmapRoundTrip_preservesLimbs() throws Exception {
        long[] flat = new long[24];
        for (int i = 0; i < 24; i++) flat[i] = RND.nextLong();
        Path f = Files.createTempFile("zeroj-rt-", ".bin");
        try {
            MmapG1File.write(flat, f);
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment seg = MmapG1File.map(f, arena);
                long[] buf = new long[12];
                var reader = new PippengerFlatBLS381.SegmentG1Reader(seg);
                for (int i = 0; i < 2; i++) {
                    reader.readInto(i, buf);
                    for (int k = 0; k < 12; k++) assertEquals(flat[i * 12 + k], buf[k], "limb " + i + "," + k);
                }
            }
        } finally {
            Files.deleteIfExists(f);
        }
    }
}
