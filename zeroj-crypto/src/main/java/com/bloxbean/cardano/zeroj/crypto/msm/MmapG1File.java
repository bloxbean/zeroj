package com.bloxbean.cardano.zeroj.crypto.msm;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * File-backed storage for flat G1 proving-key arrays (ADR-0029 M4).
 *
 * <p>Writes a flat {@code long[]} (12 Montgomery longs per affine point) to a file and maps it back
 * read-only as an off-heap {@link MemorySegment}. The prover reads points from the segment via
 * {@link PippengerFlatBLS381.SegmentG1Reader}, so the proving key lives on disk / in the OS page
 * cache rather than the JVM heap — the resident RAM is the working set, not the whole PK. Native
 * byte order throughout (matches {@link ValueLayout#JAVA_LONG} reads).</p>
 */
public final class MmapG1File {

    private MmapG1File() {}

    /** Write a flat G1 {@code long[]} to {@code path} (truncating any existing file). */
    public static void write(long[] flat, Path path) throws IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.READ,
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
             Arena arena = Arena.ofConfined()) {
            MemorySegment seg = ch.map(FileChannel.MapMode.READ_WRITE, 0, (long) flat.length * Long.BYTES, arena);
            MemorySegment.copy(flat, 0, seg, ValueLayout.JAVA_LONG, 0, flat.length);
            seg.force();
        }
    }

    /**
     * Map {@code path} read-only into {@code arena} as a {@link MemorySegment}. The segment is valid
     * for the lifetime of {@code arena}; close the arena (or use try-with-resources) to unmap.
     */
    public static MemorySegment map(Path path, Arena arena) throws IOException {
        try (FileChannel ch = FileChannel.open(path, StandardOpenOption.READ)) {
            return ch.map(FileChannel.MapMode.READ_ONLY, 0, ch.size(), arena);
        }
    }
}
