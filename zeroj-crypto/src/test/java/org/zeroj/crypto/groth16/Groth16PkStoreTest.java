package org.zeroj.crypto.groth16;

import org.zeroj.api.R1CSConstraint;
import org.zeroj.api.TrustedSetupPolicy;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
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

        var fresh = Groth16UnblindedTestProver.proveUnblinded(sr.provingKey(),
                Groth16ProverBLS381.heapReaders(sr.provingKey()), ProverBackend.PURE_JAVA, w, cons, domain);

        Groth16PkStore.save(sr, dir);
        assertTrue(Groth16PkStore.exists(dir), "store should exist after save");

        try (var loaded = Groth16PkStore.load(dir)) {
            var fromStore = Groth16UnblindedTestProver.proveUnblinded(loaded.pk(),
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

    @Test
    void loadRejectsOffSubgroupOffCurveInfinityAndNonCanonicalAuxPoints(@TempDir Path dir) throws Exception {
        var cons = chain(8);
        BigInteger tau = PowersOfTauBLS381.generate(5).tauScalar();
        var sr = Groth16SetupBLS381.setup(cons, 10, 1, tau);
        Groth16PkStore.save(sr, dir);
        Path auxPath = dir.resolve("aux.bin");
        byte[] validAux = Files.readAllBytes(auxPath);

        // Positive control: untouched store loads cleanly.
        try (var ok = Groth16PkStore.load(dir)) {
            assertEquals(sr.ic().length, ok.ic().length);
        }

        // 1. G1 off-subgroup torsion point (0, 2) in alphaG1 (offset 0).
        G1Point g1Torsion = new G1Point(Fp.ZERO, Fp.of(2));
        assertTrue(g1Torsion.isOnCurve());
        assertFalse(g1Torsion.isInSubgroup());
        byte[] g1SubgroupBad = validAux.clone();
        writeBe48(g1SubgroupBad, 0, BigInteger.ZERO);
        writeBe48(g1SubgroupBad, 48, BigInteger.TWO);
        Files.write(auxPath, g1SubgroupBad);
        assertThrows(IOException.class, () -> Groth16PkStore.load(dir));

        // 2. G2 off-subgroup torsion point in gammaG2 (offset 672 = 3*96 + 2*192).
        Fp2 x2 = Fp2.of(Fp.ZERO, Fp.ONE);
        Fp2 y2 = x2.square().mul(x2).add(Fp2.of(Fp.of(4), Fp.of(4))).sqrt().orElseThrow();
        G2Point g2Torsion = new G2Point(x2, y2);
        assertTrue(g2Torsion.isOnCurve());
        assertFalse(g2Torsion.isInSubgroup());
        byte[] g2SubgroupBad = validAux.clone();
        writeBe48(g2SubgroupBad, 672, x2.c0().value());
        writeBe48(g2SubgroupBad, 720, x2.c1().value());
        writeBe48(g2SubgroupBad, 768, y2.c0().value());
        writeBe48(g2SubgroupBad, 816, y2.c1().value());
        Files.write(auxPath, g2SubgroupBad);
        assertThrows(IOException.class, () -> Groth16PkStore.load(dir));

        // 3. Infinity IC[0] (96 zero bytes at offset 864 = 3*96 + 3*192).
        byte[] infIc = validAux.clone();
        Arrays.fill(infIc, 864, 960, (byte) 0);
        Files.write(auxPath, infIc);
        assertThrows(IOException.class, () -> Groth16PkStore.load(dir));

        // 4. Off-curve G1 (1, 1) in betaG1 (offset 96).
        byte[] offCurve = validAux.clone();
        writeBe48(offCurve, 96, BigInteger.ONE);
        writeBe48(offCurve, 144, BigInteger.ONE);
        Files.write(auxPath, offCurve);
        assertThrows(IOException.class, () -> Groth16PkStore.load(dir));

        // 5. Non-canonical Fp coordinate (x + p) in alphaG1 (offset 0).
        byte[] nonCanonical = validAux.clone();
        BigInteger canonicalX = new BigInteger(1, Arrays.copyOfRange(validAux, 0, 48));
        writeBe48(nonCanonical, 0, canonicalX.add(Fp.P));
        Files.write(auxPath, nonCanonical);
        assertThrows(IOException.class, () -> Groth16PkStore.load(dir));
    }

    @Test
    void sparsePointFileIndexValidatesMultiBlockBitmapAndRanks() {
        int count = 1200; // 3 blocks (512 + 512 + 176), 19 bitmap words with 48 trailing bits in last word
        int words = (count + 63) >>> 6;
        long[] bitmap = new long[words];
        long nnz = 0;
        for (int i = 0; i < count; i += 3) {
            bitmap[i >>> 6] |= 1L << (i & 63);
            nnz++;
        }
        long fileSize = SparsePointFile.fileSize(count, nnz, 96);
        long rankOff = 32L + (long) words * 8L;
        var leInt = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
        var leLong = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment valid = arena.allocate(fileSize);
            SparsePointFile.writeIndex(valid, bitmap, count, nnz, 96);

            // Positive control: valid multi-block index passes validation and returns exact ranks.
            var idx = new SparsePointFile.Index(valid);
            assertEquals(count, idx.count());
            long expectedRank = 0;
            for (int i = 0; i < count; i++) {
                boolean present = (i % 3) == 0;
                assertEquals(present, idx.present(i), "present(" + i + ")");
                if (present) {
                    assertEquals(expectedRank++, idx.rank(i), "rank(" + i + ")");
                }
            }

            // Negative 1: same-length tampered block rank (block 1 rank incremented by 1).
            MemorySegment badRank = arena.allocate(fileSize);
            MemorySegment.copy(valid, 0, badRank, 0, fileSize);
            badRank.set(leInt, rankOff + 4L, badRank.get(leInt, rankOff + 4L) + 1);
            assertThrows(IllegalArgumentException.class, () -> new SparsePointFile.Index(badRank));

            // Negative 2: same-length tampered bitmap bit (popcount != header nnz).
            MemorySegment badPopcount = arena.allocate(fileSize);
            MemorySegment.copy(valid, 0, badPopcount, 0, fileSize);
            long lastWordOff = 32L + (long) (words - 1) * 8L;
            badPopcount.set(leLong, lastWordOff, badPopcount.get(leLong, lastWordOff) ^ 1L);
            assertThrows(IllegalArgumentException.class, () -> new SparsePointFile.Index(badPopcount));

            // Negative 3: trailing bitmap bit >= count set while clearing an in-range bit in the same
            // final word so total popcount still equals nnz and all earlier block ranks still match.
            MemorySegment badTrailingBit = arena.allocate(fileSize);
            MemorySegment.copy(valid, 0, badTrailingBit, 0, fileSize);
            long lastWord = badTrailingBit.get(leLong, lastWordOff);
            long clearedBit = Long.lowestOneBit(lastWord);
            assertTrue(clearedBit != 0L, "final word must have at least one set in-range bit");
            long trailingBit = 1L << (count & 63);
            badTrailingBit.set(leLong, lastWordOff, (lastWord ^ clearedBit) | trailingBit);
            assertThrows(IllegalArgumentException.class, () -> new SparsePointFile.Index(badTrailingBit));
        }
    }

    private static void writeBe48(byte[] dst, int offset, BigInteger value) {
        byte[] raw = value.toByteArray();
        Arrays.fill(dst, offset, offset + 48, (byte) 0);
        int srcPos = raw.length > 48 ? raw.length - 48 : 0;
        int len = Math.min(raw.length, 48);
        System.arraycopy(raw, srcPos, dst, offset + 48 - len, len);
    }
}
