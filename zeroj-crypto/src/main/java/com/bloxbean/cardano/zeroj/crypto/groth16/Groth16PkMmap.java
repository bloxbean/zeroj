package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.msm.MmapG1File;
import com.bloxbean.cardano.zeroj.crypto.msm.PippengerFlatBLS381;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Materializes a Groth16 proving key's flat G1 arrays to files and maps them read-only, so the
 * prover can run with the key <b>off the JVM heap</b> (ADR-0029 M4) — resident RAM becomes the OS
 * page-cache working set, not the whole key.
 *
 * <pre>{@code
 * try (var mmap = Groth16PkMmap.materialize(pk, dir)) {
 *     proof = Groth16ProverBLS381.proveWithReaders(pk, mmap.readers(), witness, cons, numWires, domain);
 * } // unmaps and deletes the temp files
 * }</pre>
 *
 * <p>{@link #shouldEngage} implements the ADR-0029 auto-engage policy: use mmap when the flat G1 key
 * would not comfortably fit the JVM's max heap (keyed on detected {@code -Xmx}).</p>
 */
public final class Groth16PkMmap implements AutoCloseable {

    private final Arena arena;
    private final Groth16ProverBLS381.G1Readers readers;
    private final Path[] files;
    private final boolean deleteOnClose;

    private Groth16PkMmap(Arena arena, Groth16ProverBLS381.G1Readers readers, Path[] files, boolean deleteOnClose) {
        this.arena = arena;
        this.readers = readers;
        this.files = files;
        this.deleteOnClose = deleteOnClose;
    }

    /** mmap-backed readers over the key's G1 arrays. Valid until {@link #close()}. */
    public Groth16ProverBLS381.G1Readers readers() { return readers; }

    /** Total on-disk bytes of the mapped G1 key. */
    public long fileBytes() {
        long b = 0;
        try { for (Path f : files) b += Files.size(f); } catch (IOException e) { throw new UncheckedIOException(e); }
        return b;
    }

    /**
     * Write the key's G1 arrays under {@code dir} and map them. Files are named a/b1/h/l.bin and are
     * deleted on {@link #close()}.
     */
    public static Groth16PkMmap materialize(Groth16ProvingKeyBLS381 pk, Path dir) throws IOException {
        Files.createDirectories(dir);
        Path fa = dir.resolve("pointsA.bin"), fb1 = dir.resolve("pointsB1.bin"),
                fh = dir.resolve("pointsH.bin"), fl = dir.resolve("pointsL.bin");
        MmapG1File.write(pk.pointsA(), fa);
        MmapG1File.write(pk.pointsB1(), fb1);
        MmapG1File.write(pk.pointsH(), fh);
        MmapG1File.write(pk.pointsL(), fl);

        Arena arena = Arena.ofShared();
        try {
            var readers = new Groth16ProverBLS381.G1Readers(
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(fa, arena)),
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(fb1, arena)),
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(fh, arena)),
                    new PippengerFlatBLS381.SegmentG1Reader(MmapG1File.map(fl, arena)));
            return new Groth16PkMmap(arena, readers, new Path[]{fa, fb1, fh, fl}, true);
        } catch (RuntimeException | IOException e) {
            arena.close();
            throw e;
        }
    }

    /**
     * Auto-engage policy: mmap when the flat G1 key ({@code 12 longs/point × the four arrays}) would
     * take more than {@code headroomFraction} of the JVM max heap — i.e. when keeping it on-heap
     * risks OOM / heavy GC. Native (mmap) memory is not counted against {@code -Xmx}.
     */
    public static boolean shouldEngage(Groth16ProvingKeyBLS381 pk, double headroomFraction) {
        long g1Bytes = (long) (pk.pointsA().length + pk.pointsB1().length
                + pk.pointsH().length + pk.pointsL().length) * Long.BYTES;
        long maxHeap = Runtime.getRuntime().maxMemory();
        return g1Bytes > headroomFraction * maxHeap;
    }

    @Override
    public void close() {
        arena.close(); // unmaps all segments
        if (deleteOnClose) {
            for (Path f : files) {
                try { Files.deleteIfExists(f); } catch (IOException ignored) { /* best-effort */ }
            }
        }
    }
}
