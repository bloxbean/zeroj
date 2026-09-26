package org.zeroj.crypto.groth16;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;

class ZkeyStreamingBoundaryTest {
    @TempDir Path tmp;
    static byte[] fixture() throws IOException {
        try (var in = ZkeyStreamingBoundaryTest.class.getResourceAsStream(
                "/test-circuits/multiplier-bls381/multiplier.zkey")) {
            return in.readAllBytes();
        }
    }
    static int section(byte[] bytes, int wanted) {
        var b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        int offset = 12;
        for (int i = 0; i < b.getInt(8); i++) {
            int type = b.getInt(offset);
            int size = Math.toIntExact(b.getLong(offset + 4));
            if (type == wanted) return offset + 12;
            offset += 12 + size;
        }
        throw new AssertionError("Missing section " + wanted);
    }
    static void put(byte[] bytes, int offset, BigInteger value) {
        Arrays.fill(bytes, offset, offset + 48, (byte) 0);
        byte[] be = value.toByteArray();
        for (int i = 0; i < Math.min(48, be.length); i++) bytes[offset + i] = be[be.length - 1 - i];
    }
    static void point(byte[] bytes, int offset, BigInteger... values) {
        for (int i = 0; i < values.length; i++)
            put(bytes, offset + i * 48, values[i].shiftLeft(384).mod(Fp.P));
    }
    void rejected(byte[] bytes) throws IOException {
        Path input = Files.createTempFile(tmp, "mutated", ".zkey");
        Files.write(input, bytes);
        Path out = tmp.resolve(input.getFileName() + "-store");
        assertThrows(IOException.class, () -> ZkeyPkStoreImporter.importUnpinnedToPkStore(input, out));
        assertFalse(Files.exists(out), "failed import must not publish any store");
    }
    @Test void rejectsG1TorsionInEveryPointSection() throws IOException {
        var torsion = new G1Point(Fp.ZERO, Fp.of(2));
        assertTrue(torsion.isOnCurve());
        assertFalse(torsion.isInSubgroup());
        byte[] original = fixture();
        int h = section(original, 2);
        int[] offsets = {h + 100, h + 196, h + 676, section(original, 3),
                section(original, 5), section(original, 6), section(original, 8), section(original, 9)};
        for (int offset : offsets) {
            byte[] b = original.clone();
            point(b, offset, BigInteger.ZERO, BigInteger.TWO);
            rejected(b);
        }
    }
    @Test void rejectsG2TorsionInEveryPointSection() throws IOException {
        Fp2 x = Fp2.of(Fp.ZERO, Fp.ONE);
        Fp2 y = x.square().mul(x).add(Fp2.of(Fp.of(4), Fp.of(4))).sqrt().orElseThrow();
        var torsion = new G2Point(x, y);
        assertTrue(torsion.isOnCurve());
        assertFalse(torsion.isInSubgroup());
        byte[] original = fixture();
        int h = section(original, 2);
        for (int offset : new int[]{h + 292, h + 484, h + 772, section(original, 7)}) {
            byte[] b = original.clone();
            point(b, offset, x.c0().value(), x.c1().value(), y.c0().value(), y.c1().value());
            rejected(b);
        }
    }
    @Test void rejectsNoncanonicalResiduesAndMalformedStructure() throws IOException {
        byte[] original = fixture();
        for (int sec : new int[]{2, 3, 5, 6, 7, 8, 9}) {
            byte[] b = original.clone();
            put(b, section(b, sec) + (sec == 2 ? 100 : 0), Fp.P);
            rejected(b);
        }
        for (int length : new int[]{0, 4, 11, 15, original.length - 1})
            rejected(Arrays.copyOf(original, length));
        byte[] b = original.clone();
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(4, 0);
        rejected(b);
        b = Arrays.copyOf(original, original.length + 1);
        rejected(b);
        b = original.clone();
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putLong(16, Long.MAX_VALUE);
        rejected(b);
    }

    @Test void pinsSourceAndStoreAndRejectsTampering() throws Exception {
        byte[] bytes = fixture();
        Path input = tmp.resolve("key.zkey");
        Files.write(input, bytes);
        String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        Path store = tmp.resolve("pinned");
        assertThrows(IOException.class, () -> ZkeyPkStoreImporter.importToPkStore(input, store, "00".repeat(32)));
        assertFalse(Files.exists(store));
        var imported = ZkeyPkStoreImporter.importToPkStore(input, store, expected);
        assertEquals(expected, imported.sourceSha256());
        var repeat = ZkeyPkStoreImporter.importToPkStore(input, tmp.resolve("repeat"), expected);
        assertEquals(imported.manifestSha256(), repeat.manifestSha256(), "deterministic manifest");
        try (var keys = Groth16Keys.load(store, imported.manifestSha256())) {
            assertEquals(imported.numWires(), keys.numWires());
        }
        assertThrows(IOException.class, () -> Groth16Keys.load(store, "00".repeat(32)));
        for (String payload : new String[]{"aux.bin", "pointsA.bin", "pointsB1.bin", "pointsB2.bin", "pointsH.bin", "pointsL.bin"}) {
            Path file = store.resolve(payload);
            byte[] valid = Files.readAllBytes(file);
            byte[] changed = valid.clone();
            changed[0] ^= 1;
            Files.write(file, changed);
            assertThrows(IOException.class, () -> Groth16Keys.load(store, imported.manifestSha256()), payload);
            Files.write(file, valid);
        }
        // Refuse overwrite before touching an existing valid bundle.
        byte[] manifest = Files.readAllBytes(store.resolve("manifest.properties"));
        assertThrows(IOException.class, () -> ZkeyPkStoreImporter.importToPkStore(input, store, expected));
        assertArrayEquals(manifest, Files.readAllBytes(store.resolve("manifest.properties")));
        assertThrows(IOException.class, () -> ZkeyPkStoreImporter.importToPkStore(input, tmp.resolve("implicit")));
    }

    @Test void rejectsDuplicateSectionsAndBadCoefficients() throws IOException {
        byte[] original = fixture();
        byte[] b = original.clone();
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(section(b, 2) - 12, 1);
        rejected(b);
        b = original.clone();
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(section(b, 4) + 4, 3);
        rejected(b);
        b = original.clone();
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(section(b, 4) + 8, Integer.MAX_VALUE);
        rejected(b);
        b = original.clone();
        ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(section(b, 4) + 12, Integer.MAX_VALUE);
        rejected(b);
    }
}
