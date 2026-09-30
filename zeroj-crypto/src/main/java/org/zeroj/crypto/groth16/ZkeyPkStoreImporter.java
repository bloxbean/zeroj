package org.zeroj.crypto.groth16;

import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.MontFp2_381;
import org.zeroj.bls12381.field.MontFp381;
import org.zeroj.bls12381.field.MontFr381;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Comparator;
import java.util.HexFormat;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

/**
 * Streaming importer for <b>large</b> snarkjs Groth16 {@code .zkey} files (ADR-0031 M2): converts a
 * ceremony proving key directly into a {@link Groth16PkStore} directory without materializing point
 * object arrays — the path for MPC ceremony keys at real scale (a 19M-constraint key is ~30 GB,
 * far past {@link ZkeyImporterBLS381}'s strict in-memory limits).
 *
 * <p>The {@code .zkey} stores points as little-endian <b>Montgomery</b> residues — byte-identical
 * to the flat-limb layout of the ZeroJ proving-key store on little-endian platforms — so the four
 * G1 sections (A, B1, L, H) are <b>raw-copied</b> and then curve/subgroup-validated in parallel. The G2
 * section is converted (Montgomery → canonical big-endian, the store's G2 encoding) and validated
 * in the same parallel pass. VK parts (alpha/beta/gamma/delta, IC) land in the store's
 * {@code aux.bin}/manifest via the shared {@link Groth16PkStore} writer.</p>
 *
 * <p>After import: {@code Groth16PkStore.load(dir, imported.manifestSha256())}, then prove
 * as with a ZeroJ-generated key.
 * Note snarkjs setup appends public-input binding rows to the constraint list — use
 * {@link #snarkjsConstraints(java.util.List, int)} when proving under a ceremony key.</p>
 */
public final class ZkeyPkStoreImporter {

    private ZkeyPkStoreImporter() {}

    private static final long MAX_ZKEY_FILE = 64L << 30;   // 64 GB
    private static final int MAX_WIRES = 1 << 27;          // 134M
    private static final int MAX_DOMAIN_POWER = 27;

    private static final ValueLayout.OfInt U32 = ValueLayout.JAVA_INT_UNALIGNED.withOrder(java.nio.ByteOrder.LITTLE_ENDIAN);
    private static final ValueLayout.OfLong U64 = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(java.nio.ByteOrder.LITTLE_ENDIAN);

    private static final BigInteger FP = MontFp381.modulus();
    private static final BigInteger FR = MontFr381.modulus();
    private static final BigInteger FP_R_INV = BigInteger.ONE.shiftLeft(384).mod(FP).modInverse(FP);

    /** Parsed dimensions, for logging/validation by the caller. */
    public record Imported(int numWires, int numPublic, int domainSize,
                           String sourceSha256, String manifestSha256) {}

    /**
     * Import structurally and point-validated bytes matching a trusted external hash.
     * The sealed store is unbound; use the fingerprint overload for circuit-aware cache hits.
     * This does not verify key consistency with the R1CS or ceremony transcript.
     */
    public static Imported importToPkStore(Path zkeyFile, Path dir, String expectedSha256) throws IOException {
        Groth16StoreIntegrity.requireDigest(expectedSha256);
        return stageImport(zkeyFile, dir, expectedSha256, null);
    }

    /**
     * Import with an exact circuit fingerprint included before the manifest is sealed.
     * The caller must independently establish the key/circuit association; this checks only
     * fingerprint syntax and dimensions, not the relation or ceremony transcript.
     */
    public static Imported importToPkStore(Path zkeyFile, Path dir, String expectedSha256,
                                           String expectedCircuitFingerprint) throws IOException {
        Groth16StoreIntegrity.requireDigest(expectedSha256);
        requireFingerprint(expectedCircuitFingerprint);
        return stageImport(zkeyFile, dir, expectedSha256, expectedCircuitFingerprint);
    }

    /**
     * Explicit local/test opt-in: validates structure and points but cannot authenticate ceremony origin.
     * This never bypasses curve, subgroup, canonicality or structural checks.
     */
    public static Imported importUnpinnedToPkStore(Path zkeyFile, Path dir) throws IOException {
        return stageImport(zkeyFile, dir, null, null);
    }

    /** Explicit local/test import with caller-asserted circuit metadata sealed into the manifest. */
    public static Imported importUnpinnedToPkStore(Path zkeyFile, Path dir,
                                                   String expectedCircuitFingerprint) throws IOException {
        requireFingerprint(expectedCircuitFingerprint);
        return stageImport(zkeyFile, dir, null, expectedCircuitFingerprint);
    }

    private static void requireFingerprint(String fingerprint) {
        if (!Groth16Pipeline.isExactFingerprint(fingerprint))
            throw new IllegalArgumentException("exact circuit fingerprint is required");
    }

    private static Imported stageImport(Path source, Path destination, String expectedHash,
                                        String circuitFingerprint) throws IOException {
        Path target = destination.toAbsolutePath();
        if (Files.exists(target)) throw new IOException("Output directory already exists: " + target);
        Files.createDirectories(target.getParent());
        Path staging = Files.createTempDirectory(target.getParent(), ".zeroj-import-");
        try {
            Path snapshot = staging.resolve("source.zkey");
            MessageDigest hash;
            try { hash = MessageDigest.getInstance("SHA-256"); }
            catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
            long total = 0;
            try (var in = Files.newInputStream(source); var out = Files.newOutputStream(snapshot)) {
                byte[] buffer = new byte[1 << 20];
                int count;
                while ((count = in.read(buffer)) != -1) {
                    total += count;
                    if (total > MAX_ZKEY_FILE) throw new IOException(".zkey exceeds 64 GB limit");
                    hash.update(buffer, 0, count);
                    out.write(buffer, 0, count);
                }
            }
            String sourceHash = HexFormat.of().formatHex(hash.digest());
            if (expectedHash != null && !sourceHash.equalsIgnoreCase(expectedHash))
                throw new IOException(".zkey SHA-256 mismatch");
            Imported dimensions;
            try {
                dimensions = importSnapshot(snapshot, staging);
            } catch (IllegalArgumentException | IndexOutOfBoundsException malformed) {
                throw new IOException("Malformed .zkey", malformed);
            }
            Files.delete(snapshot);
            if (circuitFingerprint != null)
                Groth16PkStore.bindCircuitFingerprint(staging, circuitFingerprint);
            String manifestHash = Groth16StoreIntegrity.seal(staging, sourceHash);
            // No REPLACE_EXISTING: an existing store is never partially overwritten.
            Files.move(staging, target);
            return new Imported(dimensions.numWires(), dimensions.numPublic(), dimensions.domainSize(),
                    sourceHash, manifestHash);
        } finally {
            if (Files.exists(staging)) {
                try (var files = Files.walk(staging)) {
                    for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
                }
            }
        }
    }

    private static Imported importSnapshot(Path zkeyFile, Path dir) throws IOException {
        long fileSize = Files.size(zkeyFile);
        if (fileSize < 12) throw new IOException("Truncated .zkey header");
        try (FileChannel ch = FileChannel.open(zkeyFile, StandardOpenOption.READ);
             Arena arena = Arena.ofShared()) {
            MemorySegment z = ch.map(FileChannel.MapMode.READ_ONLY, 0, fileSize, arena);

            // global header
            if (z.get(U32, 0) != 0x79656b7a) throw new IOException("Invalid .zkey magic"); // "zkey" LE
            int version = z.get(U32, 4);
            if (version != 1 && version != 2) throw new IOException("Unsupported .zkey version: " + version);
            int nSections = z.get(U32, 8);
            if (nSections <= 0 || nSections > 64) throw new IOException("Invalid .zkey section count");

            Map<Integer, long[]> sections = new HashMap<>();
            long pos = 12;
            for (int i = 0; i < nSections; i++) {
                if (fileSize - pos < 12) throw new IOException("Truncated .zkey section header");
                int type = z.get(U32, pos);
                if (type < 1 || type > 10) throw new IOException("Unknown .zkey section " + type);
                long size = z.get(U64, pos + 4);
                pos += 12;
                if (size < 0 || size > fileSize - pos) throw new IOException("Invalid .zkey section " + type);
                if (sections.put(type, new long[]{pos, size}) != null)
                    throw new IOException("Duplicate .zkey section " + type);
                pos += size;
            }
            if (pos != fileSize) throw new IOException("Trailing bytes after .zkey sections");
            for (int s : new int[]{1, 2, 3, 4, 5, 6, 7, 8, 9}) {
                if (!sections.containsKey(s)) throw new IOException("Missing .zkey section " + s);
            }

            requireSize(sections.get(1), 4, "protocol");
            requireSize(sections.get(2), 964, "Groth16 header");
            if (z.get(U32, sections.get(1)[0]) != 1) throw new IOException("Not a Groth16 .zkey");

            // section 2: Groth16 header
            long h = sections.get(2)[0];
            if (z.get(U32, h) != 48) throw new IOException("Not a BLS12-381 .zkey (n8q)");
            if (!FP.equals(fieldLE(z, h + 4, 48))) throw new IOException("Wrong base-field prime");
            if (z.get(U32, h + 52) != 32) throw new IOException("Not a BLS12-381 .zkey (n8r)");
            if (!FR.equals(fieldLE(z, h + 56, 32))) throw new IOException("Wrong scalar-field prime");
            int nVars = z.get(U32, h + 88);
            int nPublic = z.get(U32, h + 92);
            int domainSize = z.get(U32, h + 96);
            validateDims(nVars, nPublic, domainSize);
            validateCoefficients(z, sections.get(4), nVars, domainSize);

            long p = h + 100;
            AffineG1 alphaG1 = g1(z, p);            p += 96;
            AffineG1 betaG1 = g1(z, p);             p += 96;
            AffineG2 betaG2 = g2(z, p);             p += 192;
            AffineG2 gammaG2 = g2(z, p);            p += 192;
            AffineG1 deltaG1 = g1(z, p);            p += 96;
            AffineG2 deltaG2 = g2(z, p);
            // ADR-0025/ADR-0045 profile: single VK points and every IC entry must be on-curve and
            // not the point at infinity; an infinity IC[i] would leave public input i unbound.
            requireValid(alphaG1, false, "alphaG1");
            requireValid(betaG1, false, "betaG1");
            requireValid(betaG2, false, "betaG2");
            requireValid(gammaG2, false, "gammaG2");
            requireValid(deltaG1, false, "deltaG1");
            requireValid(deltaG2, false, "deltaG2");

            // section 3: IC (nPublic + 1 points)
            long[] ic3 = sections.get(3)[0] == 0 ? null : sections.get(3);
            requireSize(ic3, (nPublic + 1) * 96L, "IC");
            AffineG1[] ic = new AffineG1[nPublic + 1];
            for (int i = 0; i <= nPublic; i++) {
                ic[i] = g1(z, ic3[0] + i * 96L);
                requireValid(ic[i], false, "IC[" + i + "]");
            }

            int nPrivate = nVars - nPublic - 1;
            // G1 sections: raw copy (Montgomery LE bytes == flat-limb layout) + parallel validation
            copyAndValidateG1(z, sections.get(5), nVars, dir.resolve("pointsA.bin"), "pointsA");
            copyAndValidateG1(z, sections.get(6), nVars, dir.resolve("pointsB1.bin"), "pointsB1");
            copyAndValidateG1(z, sections.get(8), nPrivate, dir.resolve("pointsL.bin"), "pointsL");
            copyAndValidateG1(z, sections.get(9), domainSize, dir.resolve("pointsH.bin"), "pointsH");

            // G2 section: Montgomery LE → canonical BE (store encoding), parallel, validated
            convertG2Section(z, sections.get(7), nVars, dir.resolve("pointsB2.bin"));

            Groth16PkStore.writeAuxAndManifest(dir, alphaG1, betaG1, deltaG1,
                    betaG2, deltaG2, gammaG2, ic, nPublic, nVars, domainSize);
            return new Imported(nVars, nPublic, domainSize, null, null);
        }
    }

    /**
     * The constraint list to prove with under a snarkjs ceremony key: snarkjs's Groth16 setup
     * appends one binding row per public signal s (including the ONE wire): {@code A={s:1}, B={},
     * C={}} — without them the witness would not satisfy the key's QAP. Asserted equal to the
     * zkey's own coefficient section in the round-trip test.
     */
    public static java.util.List<org.zeroj.api.R1CSConstraint> snarkjsConstraints(
            java.util.List<org.zeroj.api.R1CSConstraint> original, int numPublic) {
        var out = new java.util.ArrayList<>(original);
        for (int s = 0; s <= numPublic; s++) {
            out.add(new org.zeroj.api.R1CSConstraint(
                    Map.of(s, BigInteger.ONE), Map.of(), Map.of()));
        }
        return out;
    }

    // ---- G1/G2 bulk ----

    private static void copyAndValidateG1(MemorySegment z, long[] sec, int count, Path outFile, String label)
            throws IOException {
        long bytes = count * 96L;
        requireSize(sec, bytes, label);
        MemorySegment src = z.asSlice(sec[0], bytes);
        try (FileChannel out = FileChannel.open(outFile, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.READ, StandardOpenOption.TRUNCATE_EXISTING);
             Arena a = Arena.ofShared()) {
            MemorySegment dst = out.map(FileChannel.MapMode.READ_WRITE, 0, bytes, a);
            dst.copyFrom(src);

            // parallel canonicality, curve and subgroup validation (reads the Montgomery limbs straight from the copy)
            AtomicInteger bad = new AtomicInteger(-1);
            int t = Math.max(1, Math.min(Runtime.getRuntime().availableProcessors(), count));
            int per = (count + t - 1) / t;
            IntStream.range(0, t).parallel().forEach(c -> {
                long[] buf = new long[12];
                for (int i = c * per; i < Math.min(count, (c + 1) * per); i++) {
                    if (bad.get() >= 0) return;
                    MemorySegment.copy(dst, ValueLayout.JAVA_LONG_UNALIGNED, i * 96L, buf, 0, 12);
                    boolean inf = true;
                    for (long l : buf) if (l != 0) { inf = false; break; }
                    if (inf) continue;
                    var pt = new AffineG1(
                            MontFp381.fromMontLimbs(buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]),
                            MontFp381.fromMontLimbs(buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]));
                    if (!pt.isOnCurve() || !JacobianG1BLS381.fromAffine(pt.x(), pt.y())
                            .scalarMul(FR).isInfinity()) bad.compareAndSet(-1, i);
                }
            });
            if (bad.get() >= 0)
                throw new IOException(".zkey " + label + "[" + bad.get() + "] is not on the curve or in the prime-order subgroup");
        }
    }

    private static void convertG2Section(MemorySegment z, long[] sec, int count, Path outFile) throws IOException {
        long inBytes = count * 192L;
        requireSize(sec, inBytes, "pointsB2");
        long srcOff = sec[0];
        try (FileChannel out = FileChannel.open(outFile, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.READ, StandardOpenOption.TRUNCATE_EXISTING);
             Arena a = Arena.ofShared()) {
            MemorySegment dst = out.map(FileChannel.MapMode.READ_WRITE, 0, count * 192L, a);

            AtomicInteger bad = new AtomicInteger(-1);
            int t = Math.max(1, Math.min(Runtime.getRuntime().availableProcessors(), count));
            int per = (count + t - 1) / t;
            IntStream.range(0, t).parallel().forEach(c -> {
                byte[] coord = new byte[48];
                for (int i = c * per; i < Math.min(count, (c + 1) * per); i++) {
                    if (bad.get() >= 0) return;
                    long in = srcOff + i * 192L;
                    // zkey layout: x.re, x.im, y.re, y.im (each 48B LE Montgomery)
                    BigInteger xr = mont(z, in, coord), xi = mont(z, in + 48, coord);
                    BigInteger yr = mont(z, in + 96, coord), yi = mont(z, in + 144, coord);
                    var pt = new AffineG2(MontFp2_381.of(xr, xi), MontFp2_381.of(yr, yi));
                    boolean inf = xr.signum() == 0 && xi.signum() == 0 && yr.signum() == 0 && yi.signum() == 0;
                    if (!inf && (!pt.isOnCurve() || !JacobianG2BLS381.fromAffine(pt.x(), pt.y())
                            .scalarMul(FR).isInfinity())) { bad.compareAndSet(-1, i); return; }
                    long o = i * 192L;
                    putBE(dst, o, xr, coord); putBE(dst, o + 48, xi, coord);
                    putBE(dst, o + 96, yr, coord); putBE(dst, o + 144, yi, coord);
                }
            });
            if (bad.get() >= 0)
                throw new IOException(".zkey pointsB2[" + bad.get() + "] is not on the curve or in the prime-order subgroup");
        }
    }

    // ---- field/point helpers ----

    /** 48-byte LE Montgomery at {@code off} → canonical BigInteger. */
    private static BigInteger mont(MemorySegment z, long off, byte[] scratch48) {
        MemorySegment.copy(z, off, MemorySegment.ofArray(scratch48), 0, 48);
        byte[] be = new byte[48];
        for (int i = 0; i < 48; i++) be[i] = scratch48[47 - i];
        BigInteger raw = new BigInteger(1, be);
        if (raw.compareTo(FP) >= 0) throw new IllegalArgumentException("Noncanonical Montgomery residue");
        return raw.multiply(FP_R_INV).mod(FP);
    }

    /** canonical BigInteger → 48-byte BE at {@code off} (the PkStore G2 coordinate encoding). */
    private static void putBE(MemorySegment dst, long off, BigInteger v, byte[] scratch48) {
        java.util.Arrays.fill(scratch48, (byte) 0);
        byte[] be = v.toByteArray();
        int s = Math.max(0, be.length - 48), len = be.length - s;
        System.arraycopy(be, s, scratch48, 48 - len, len);
        MemorySegment.copy(MemorySegment.ofArray(scratch48), 0, dst, off, 48);
    }

    private static BigInteger fieldLE(MemorySegment z, long off, int n) {
        byte[] le = new byte[n];
        MemorySegment.copy(z, off, MemorySegment.ofArray(le), 0, n);
        byte[] be = new byte[n];
        for (int i = 0; i < n; i++) be[i] = le[n - 1 - i];
        return new BigInteger(1, be);
    }

    private static AffineG1 g1(MemorySegment z, long off) {
        byte[] scratch = new byte[48];
        BigInteger x = mont(z, off, scratch), y = mont(z, off + 48, scratch);
        if (x.signum() == 0 && y.signum() == 0) return AffineG1.INFINITY;
        return new AffineG1(MontFp381.fromBigInteger(x), MontFp381.fromBigInteger(y));
    }

    private static AffineG2 g2(MemorySegment z, long off) {
        byte[] scratch = new byte[48];
        BigInteger xr = mont(z, off, scratch), xi = mont(z, off + 48, scratch);
        BigInteger yr = mont(z, off + 96, scratch), yi = mont(z, off + 144, scratch);
        return new AffineG2(MontFp2_381.of(xr, xi), MontFp2_381.of(yr, yi));
    }

    private static void validateDims(int nVars, int nPublic, int domainSize) throws IOException {
        if (nVars <= 1 || nVars > MAX_WIRES) throw new IOException("Invalid .zkey nVars: " + nVars);
        if (nPublic < 0 || nPublic > (1 << 20) || nPublic >= nVars) throw new IOException("Invalid .zkey nPublic: " + nPublic);
        if (domainSize < 4 || Integer.bitCount(domainSize) != 1
                || Integer.numberOfTrailingZeros(domainSize) > MAX_DOMAIN_POWER)
            throw new IOException("Invalid .zkey domainSize: " + domainSize);
    }

    private static void requireSize(long[] sec, long needed, String label) throws IOException {
        if (sec == null || sec[1] != needed) throw new IOException(".zkey section has incorrect size for " + label);
    }

    private static void requireValid(AffineG1 point, boolean allowInfinity, String label) throws IOException {
        if (point.isInfinity()) {
            if (allowInfinity) return;
            throw new IOException(label + " must not be infinity");
        }
        if (!point.isOnCurve() || !JacobianG1BLS381.fromAffine(point.x(), point.y()).scalarMul(FR).isInfinity())
            throw new IOException(label + " is not on curve and in the prime-order subgroup");
    }

    private static void requireValid(AffineG2 point, boolean allowInfinity, String label) throws IOException {
        if (point.isInfinity()) {
            if (allowInfinity) return;
            throw new IOException(label + " must not be infinity");
        }
        if (!point.isOnCurve() || !JacobianG2BLS381.fromAffine(point.x(), point.y()).scalarMul(FR).isInfinity())
            throw new IOException(label + " is not on curve and in the prime-order subgroup");
    }

    private static void validateCoefficients(MemorySegment z, long[] section, int wires, int domain)
            throws IOException {
        if (section[1] < 4) throw new IOException("Truncated coefficient section");
        int count = z.get(U32, section[0]);
        if (count < 0) throw new IOException("Invalid coefficient count");
        requireSize(section, 4L + count * 44L, "coefficients");
        for (int i = 0; i < count; i++) {
            long offset = section[0] + 4L + i * 44L;
            int matrix = z.get(U32, offset), row = z.get(U32, offset + 4), wire = z.get(U32, offset + 8);
            if (matrix < 0 || matrix > 2 || row < 0 || row >= domain || wire < 0 || wire >= wires)
                throw new IOException("Invalid coefficient index");
            if (fieldLE(z, offset + 12, 32).compareTo(FR) >= 0)
                throw new IOException("Noncanonical coefficient");
        }
    }
}
