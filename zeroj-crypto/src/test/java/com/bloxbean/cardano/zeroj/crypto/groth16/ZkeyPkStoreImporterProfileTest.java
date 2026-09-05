package com.bloxbean.cardano.zeroj.crypto.groth16;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0045 I1 — the streaming zkey importer applies the same infinity rule as the verifiers:
 * a {@code .zkey} whose {@code IC} section (or a single VK point) is the point at infinity is
 * rejected at import, instead of becoming a store every verifier rejects. Works on the checked-in
 * snarkjs BLS12-381 multiplier zkey; no external tooling.
 */
class ZkeyPkStoreImporterProfileTest {

    private static final String ZKEY = "/test-circuits/multiplier-bls381/multiplier.zkey";

    @Test
    void unmodifiedCeremonyZkey_importsAndHasFiniteIc(@TempDir Path tmp) throws IOException {
        Path zkey = copyZkey(tmp);
        var dims = ZkeyPkStoreImporter.importToPkStore(zkey, tmp.resolve("store"));
        assertTrue(dims.numPublic() >= 1);
        try (var loaded = Groth16PkStore.load(tmp.resolve("store"))) {
            for (var ic : loaded.ic()) assertFalse(ic.isInfinity());
        }
    }

    @Test
    void zkeyWithInfinityIcEntry_isRejectedAtImport(@TempDir Path tmp) throws IOException {
        for (int entry : new int[]{0, 1}) {
            Path zkey = copyZkey(tmp);
            long icSection = sectionOffset(zkey, 3);
            zero(zkey, icSection + entry * 96L, 96);
            Path store = tmp.resolve("store-" + entry);
            var ex = assertThrows(IOException.class, () -> ZkeyPkStoreImporter.importToPkStore(zkey, store));
            assertTrue(ex.getMessage().contains("IC[" + entry + "]"), ex.getMessage());
            assertTrue(ex.getMessage().contains("infinity"), ex.getMessage());
        }
    }

    @Test
    void zkeyWithInfinityAlpha_isRejectedAtImport(@TempDir Path tmp) throws IOException {
        Path zkey = copyZkey(tmp);
        long header = sectionOffset(zkey, 2);
        zero(zkey, header + 100, 96); // alphaG1 sits right after the two field primes and dims
        var ex = assertThrows(IOException.class, () -> ZkeyPkStoreImporter.importToPkStore(zkey, tmp.resolve("s")));
        assertTrue(ex.getMessage().contains("alphaG1"), ex.getMessage());
        assertTrue(ex.getMessage().contains("infinity"), ex.getMessage());
    }

    // ---- helpers ----

    private static Path copyZkey(Path tmp) throws IOException {
        try (var in = ZkeyPkStoreImporterProfileTest.class.getResourceAsStream(ZKEY)) {
            if (in == null) throw new IOException("missing test resource " + ZKEY);
            Path out = Files.createTempFile(tmp, "key", ".zkey");
            Files.write(out, in.readAllBytes());
            return out;
        }
    }

    /** Offset of the payload of the first section with {@code type} ("zkey" | u32 version | u32 count | sections). */
    private static long sectionOffset(Path zkey, int type) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(Files.readAllBytes(zkey)).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals("zkey", new String(new byte[]{buf.get(0), buf.get(1), buf.get(2), buf.get(3)}));
        int nSections = buf.getInt(8);
        long pos = 12;
        for (int i = 0; i < nSections; i++) {
            int t = buf.getInt((int) pos);
            long size = buf.getLong((int) pos + 4);
            pos += 12;
            if (t == type) return pos;
            pos += size;
        }
        throw new IOException("no section " + type);
    }

    private static void zero(Path file, long offset, int length) throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        Arrays.fill(bytes, (int) offset, (int) offset + length, (byte) 0);
        Files.write(file, bytes);
    }
}
