package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.crypto.msm.G2AffineReader;
import com.bloxbean.cardano.zeroj.crypto.msm.MmapG1File;
import com.bloxbean.cardano.zeroj.crypto.msm.PippengerFlatBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381.SetupResult;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Persists a Groth16 proving key + verification key to disk and loads it back (ADR-0029 M5).
 *
 * <p>The trusted setup is a one-time, expensive step (for a ~19M-constraint circuit, ~50 min); the
 * proving key it produces is then reused for <em>every</em> proof. This store writes that key once
 * so subsequent proofs just load it — no re-setup. The four flat G1 arrays are written in the
 * {@link MmapG1File} format so the prover reads them <b>memory-mapped, off-heap</b> (small prove
 * heap, and keys larger than RAM). G2 ({@code pointsB2}), the single points, and the VK are written
 * as fixed 48-byte big-endian field elements; {@code pointsB2.bin} (192 B/point) is also
 * memory-mapped on load and read through a {@link G2AffineReader} (ADR-0033 M3), so the G2 key
 * stays off-heap too.</p>
 *
 * <p>This is the persistent analogue of an snarkjs {@code .zkey}: setup → {@link #save} once,
 * then {@link #load} + prove many times.</p>
 */
public final class Groth16PkStore {

    private Groth16PkStore() {}

    private static final int FP_BYTES = 48;
    private static final String MANIFEST = "manifest.properties";

    /** Everything the prover needs, with the G1 key memory-mapped. Close to unmap. */
    public record Loaded(Groth16ProvingKeyBLS381 pk, Groth16ProverBLS381.G1Readers readers,
                         AffineG2 gammaG2, AffineG1[] ic, int domain, Arena arena) implements AutoCloseable {
        @Override public void close() { arena.close(); }
    }

    /** True if {@code dir} holds a previously-saved key. */
    public static boolean exists(Path dir) {
        return Files.isRegularFile(dir.resolve(MANIFEST));
    }

    /** Write the setup output to {@code dir}. One-time; overwrites any existing store. */
    public static void save(SetupResult sr, Path dir) throws IOException {
        Files.createDirectories(dir);
        var pk = sr.provingKey();
        MmapG1File.write(pk.pointsA(), dir.resolve("pointsA.bin"));
        MmapG1File.write(pk.pointsB1(), dir.resolve("pointsB1.bin"));
        MmapG1File.write(pk.pointsH(), dir.resolve("pointsH.bin"));
        MmapG1File.write(pk.pointsL(), dir.resolve("pointsL.bin"));

        try (var g2 = dos(dir.resolve("pointsB2.bin"))) {
            for (AffineG2 p : pk.pointsB2()) putG2(g2, p);
        }
        writeAuxAndManifest(dir, pk.alphaG1(), pk.betaG1(), pk.deltaG1(),
                pk.betaG2(), pk.deltaG2(), sr.gammaG2(), sr.ic(),
                pk.numPublic(), pk.pointsB2().length, Groth16ProvingKeyBLS381.count(pk.pointsH()));
    }

    /**
     * Write the single points + VK (aux.bin) and the manifest — shared by {@link #save} and the
     * streaming {@code .zkey} importer (ADR-0031 M2), so the store format lives in one place.
     */
    static void writeAuxAndManifest(Path dir, AffineG1 alphaG1, AffineG1 betaG1, AffineG1 deltaG1,
                                    AffineG2 betaG2, AffineG2 deltaG2, AffineG2 gammaG2, AffineG1[] ic,
                                    int numPublic, int numB2, int domain) throws IOException {
        try (var aux = dos(dir.resolve("aux.bin"))) {
            putG1(aux, alphaG1); putG1(aux, betaG1); putG1(aux, deltaG1);
            putG2(aux, betaG2); putG2(aux, deltaG2); putG2(aux, gammaG2);
            for (AffineG1 p : ic) putG1(aux, p);
        }
        var m = new Properties();
        m.setProperty("numPublic", Integer.toString(numPublic));
        m.setProperty("numB2", Integer.toString(numB2));
        m.setProperty("numIc", Integer.toString(ic.length));
        m.setProperty("domain", Integer.toString(domain));
        try (var out = Files.newOutputStream(dir.resolve(MANIFEST))) {
            m.store(out, "ADR-0029 Groth16 proving key store");
        }
    }

    /** Load a saved key from {@code dir}, memory-mapping the G1 arrays into a fresh shared arena. */
    public static Loaded load(Path dir) throws IOException {
        var m = new Properties();
        try (var in = Files.newInputStream(dir.resolve(MANIFEST))) { m.load(in); }
        int numPublic = Integer.parseInt(m.getProperty("numPublic"));
        int numB2 = Integer.parseInt(m.getProperty("numB2"));
        int numIc = Integer.parseInt(m.getProperty("numIc"));
        int domain = Integer.parseInt(m.getProperty("domain"));

        AffineG1 alphaG1, betaG1, deltaG1; AffineG2 betaG2, deltaG2, gammaG2; AffineG1[] ic = new AffineG1[numIc];
        try (var aux = dis(dir.resolve("aux.bin"))) {
            alphaG1 = getG1(aux); betaG1 = getG1(aux); deltaG1 = getG1(aux);
            betaG2 = getG2(aux); deltaG2 = getG2(aux); gammaG2 = getG2(aux);
            for (int i = 0; i < numIc; i++) ic[i] = getG1(aux);
        }

        Arena arena = Arena.ofShared();
        try {
            // ADR-0033 M3: pointsB2.bin (fixed 192 B/point) is mmap'd like the G1 files — the G2
            // key (~15.7 GB on-heap at 19M constraints) now stays file-backed/off-heap too.
            var b2 = new G2AffineReader.SegmentG2Reader(MmapG1File.map(dir.resolve("pointsB2.bin"), arena));
            if (b2.count() != numB2)
                throw new IOException("pointsB2.bin holds " + b2.count() + " points but manifest says " + numB2);
            var readers = new Groth16ProverBLS381.G1Readers(
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(dir.resolve("pointsA.bin"), arena)),
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(dir.resolve("pointsB1.bin"), arena)),
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(dir.resolve("pointsH.bin"), arena)),
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(dir.resolve("pointsL.bin"), arena)),
                    b2);
            // G1 + G2 key arrays are read via the mmap readers, so the PK holds empty arrays.
            long[] empty = new long[0];
            var pk = new Groth16ProvingKeyBLS381(alphaG1, betaG1, betaG2, deltaG1, deltaG2,
                    empty, empty, new AffineG2[0], empty, empty, numPublic);
            return new Loaded(pk, readers, gammaG2, ic, domain, arena);
        } catch (RuntimeException | IOException e) {
            arena.close();
            throw e;
        }
    }

    // ---- fixed 48-byte big-endian field elements ----

    private static DataOutputStream dos(Path p) throws IOException {
        return new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(p), 1 << 20));
    }

    private static DataInputStream dis(Path p) throws IOException {
        return new DataInputStream(new BufferedInputStream(Files.newInputStream(p), 1 << 20));
    }

    private static void putFp(DataOutputStream o, MontFp381 v) throws IOException {
        byte[] be = v.toBigInteger().toByteArray();
        byte[] b = new byte[FP_BYTES];
        int src = Math.max(0, be.length - FP_BYTES), len = be.length - src;
        System.arraycopy(be, src, b, FP_BYTES - len, len);
        o.write(b);
    }

    private static MontFp381 getFp(DataInputStream in) throws IOException {
        byte[] b = new byte[FP_BYTES];
        in.readFully(b);
        return MontFp381.fromBigInteger(new BigInteger(1, b));
    }

    private static void putG1(DataOutputStream o, AffineG1 p) throws IOException { putFp(o, p.x()); putFp(o, p.y()); }

    private static AffineG1 getG1(DataInputStream in) throws IOException { return new AffineG1(getFp(in), getFp(in)); }

    private static void putG2(DataOutputStream o, AffineG2 p) throws IOException {
        putFp(o, p.x().re()); putFp(o, p.x().im()); putFp(o, p.y().re()); putFp(o, p.y().im());
    }

    private static AffineG2 getG2(DataInputStream in) throws IOException {
        BigInteger xr = getFp(in).toBigInteger(), xi = getFp(in).toBigInteger();
        BigInteger yr = getFp(in).toBigInteger(), yi = getFp(in).toBigInteger();
        return new AffineG2(MontFp2_381.of(xr, xi), MontFp2_381.of(yr, yi));
    }
}
