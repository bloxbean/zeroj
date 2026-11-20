package org.zeroj.tools.zkey;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.bls12381.field.MontFp2_381;
import org.zeroj.bls12381.field.MontFp381;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.bls12381.pairing.BLS12381Pairing;
import org.zeroj.crypto.poly.FrFFTFlat;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * ZeroJ-native Groth16 phase-2 contributor (ADR-0031 M5 &amp; 2026-11-20 R3 hardening amendment) —
 * a bit-compatible reimplementation of {@code snarkjs zkey contribute}: validates untrusted input
 * {@code .zkey} structure and group elements, applies a fresh secret {@code k} via ADR-0062
 * {@code ctScalarMul} (delta &larr; k&middot;delta in the header; every non-infinity L- and
 * H-section point &larr; k&supmin;&sup1;&middot;point, multi-core), and appends the BGM17
 * proof-of-knowledge record to the contributions section — in the exact snarkjs 0.7.6 byte format,
 * so the resulting transcript still verifies with stock {@code snarkjs zkey verify} and further
 * snarkjs contributions can stack on top.
 *
 * <p><b>Side-channel contract (ADR-0062 I3):</b> All multiplications by secret scalars ({@code k},
 * {@code k⁻¹}, {@code s}) use {@link JacobianG1BLS381#ctScalarMul} /
 * {@link JacobianG2BLS381#ctScalarMul} (additive scalar splitting + fixed-schedule Montgomery
 * ladder). This is <b>not</b> a JVM constant-time guarantee; ceremony contributions must still run
 * on an offline, isolated host.</p>
 *
 * <p>The challenge point is derived via {@link SnarkjsHashToG2} over the blake2b-512 transcript
 * ({@code csHash ‖ prior contributions ‖ s-pair}), mirroring snarkjs 0.7.6 exactly. The
 * contributor's secret {@code k} and the s-pair base come from {@link SecureRandom}.</p>
 */
public final class ZkeyContributor {

    private ZkeyContributor() {}

    private static final ValueLayout.OfInt U32 = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    private static final ValueLayout.OfLong U64 = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    private static final int ZKEY_MAGIC = 0x79656b7a; // "zkey" little-endian
    private static final int GROTH16_PROTOCOL = 1;
    private static final int REQUIRED_SECTIONS = 10;
    private static final long MIN_CONTRIBUTION_BYTES = 96 + 96 + 96 + 192 + 64 + 4 + 4; // 552

    private static final BigInteger P = MontFp381.modulus();
    private static final BigInteger R_FR = MontFr381.modulus();
    private static final G1Point G1_GENERATOR = toG1Point(JacobianG1BLS381.GENERATOR.toAffine());
    private static final G2Point G2_GENERATOR = toG2Point(JacobianG2BLS381.GENERATOR.toAffine());

    // Section-2 Groth16 BLS12-381 header offsets (fixed layout, validated on read)
    private static final long H_N8Q = 0;
    private static final long H_Q = 4;
    private static final long H_N8R = 52;
    private static final long H_R = 56;
    private static final long H_NVARS = 88;
    private static final long H_NPUBLIC = 92;
    private static final long H_DOMAIN_SIZE = 96;
    private static final long H_ALPHA1 = 100;
    private static final long H_BETA1 = 196;
    private static final long H_BETA2 = 292;
    private static final long H_GAMMA2 = 484;
    private static final long H_DELTA1 = 676;
    private static final long H_DELTA2 = 772;
    private static final long HEADER_LEN = 964;

    private record PriorContribution(
            AffineG1 deltaAfter,
            AffineG1 g1s,
            AffineG1 g1sx,
            AffineG2 g2spx,
            byte[] transcript,
            byte[] rawBytes) {}

    /**
     * Contribute to {@code in} and atomically write the updated {@code .zkey} to {@code out}.
     * Fails if {@code out} already exists or resolves to {@code in}.
     *
     * @return the contribution hash (blake2b-512 of the new record's public key) — publish it.
     */
    public static byte[] contribute(Path in, Path out, String name) throws IOException {
        return contribute(in, out, name, false);
    }

    /**
     * Contribute to {@code in} and atomically write the updated {@code .zkey} to {@code out}.
     *
     * @param overwrite if {@code false}, fails when {@code out} already exists. In-place overwrite
     *                  ({@code in} and {@code out} resolving to the same file) is always rejected.
     * @return the contribution hash (blake2b-512 of the new record's public key) — publish it.
     */
    public static byte[] contribute(Path in, Path out, String name, boolean overwrite) throws IOException {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");

        Path inAbs = in.toAbsolutePath().normalize();
        Path outAbs = out.toAbsolutePath().normalize();
        Path outDir = outAbs.getParent();
        if (outDir == null || !Files.isDirectory(outDir)) {
            throw new IOException("Output parent directory does not exist: " + outDir);
        }
        if (Files.isDirectory(outAbs)) {
            throw new IOException("Output path is a directory: " + out);
        }
        boolean outExists = Files.exists(outAbs, LinkOption.NOFOLLOW_LINKS);
        if (outExists) {
            if (Files.exists(inAbs) && Files.isSameFile(inAbs, outAbs)) {
                throw new IOException("Refusing in-place overwrite: --in and --out refer to the same file: " + out);
            }
            if (!overwrite) {
                throw new IOException("Output file already exists (pass --overwrite / overwrite=true to replace): " + out);
            }
        } else if (inAbs.equals(outAbs)) {
            throw new IOException("Refusing in-place overwrite: --in and --out refer to the same path: " + out);
        }

        try (FileChannel inCh = FileChannel.open(inAbs, StandardOpenOption.READ);
             Arena inArena = Arena.ofShared()) {
            long inSize = inCh.size();
            if (inSize < 12) {
                throw new IOException("Truncated .zkey file: " + inSize + " bytes");
            }
            MemorySegment z = inCh.map(FileChannel.MapMode.READ_ONLY, 0, inSize, inArena);

            // ---- S1: file header and section table framing ----
            if (z.get(U32, 0) != ZKEY_MAGIC) {
                throw new IOException("Invalid .zkey magic");
            }
            int version = z.get(U32, 4);
            if (version != 1 && version != 2) {
                throw new IOException("Unsupported .zkey version: " + version);
            }
            long nSectionsLong = Integer.toUnsignedLong(z.get(U32, 8));
            if (nSectionsLong != REQUIRED_SECTIONS) {
                throw new IOException("Expected " + REQUIRED_SECTIONS + " Groth16 .zkey sections, got " + nSectionsLong);
            }

            Map<Integer, long[]> sec = new HashMap<>();
            long pos = 12;
            for (int i = 0; i < REQUIRED_SECTIONS; i++) {
                if (pos > inSize - 12) {
                    throw new IOException("Truncated .zkey section header at index " + i);
                }
                int type = z.get(U32, pos);
                long size = z.get(U64, pos + 4);
                pos += 12;
                if (size < 0 || size > inSize - pos) {
                    throw new IOException("Out-of-bounds .zkey section " + type + " size: " + size);
                }
                if (type < 1 || type > REQUIRED_SECTIONS) {
                    throw new IOException("Unsupported .zkey section type: " + type);
                }
                if (sec.put(type, new long[]{pos, size}) != null) {
                    throw new IOException("Duplicate .zkey section " + type);
                }
                pos += size;
            }
            if (pos != inSize) {
                throw new IOException("Trailing bytes after .zkey sections: " + (inSize - pos) + " extra bytes");
            }
            for (int s = 1; s <= REQUIRED_SECTIONS; s++) {
                if (!sec.containsKey(s)) {
                    throw new IOException("Missing .zkey section " + s);
                }
            }

            if (sec.get(1)[1] != 4 || z.get(U32, sec.get(1)[0]) != GROTH16_PROTOCOL) {
                throw new IOException("Not a Groth16 .zkey");
            }
            if (sec.get(2)[1] != HEADER_LEN) {
                throw new IOException("Unexpected Groth16 header length: " + sec.get(2)[1]);
            }

            // ---- S2: exact BLS12-381 primes and section dimensions ----
            long h = sec.get(2)[0];
            if (z.get(U32, h + H_N8Q) != 48 || z.get(U32, h + H_N8R) != 32) {
                throw new IOException("Not a BLS12-381 .zkey (unexpected prime byte lengths)");
            }
            if (!P.equals(readUnsignedLE(z, h + H_Q, 48))) {
                throw new IOException("Not a BLS12-381 .zkey (base field prime q mismatch)");
            }
            if (!R_FR.equals(readUnsignedLE(z, h + H_R, 32))) {
                throw new IOException("Not a BLS12-381 .zkey (scalar field prime r mismatch)");
            }

            long nVars = Integer.toUnsignedLong(z.get(U32, h + H_NVARS));
            long nPublic = Integer.toUnsignedLong(z.get(U32, h + H_NPUBLIC));
            long domainSize = Integer.toUnsignedLong(z.get(U32, h + H_DOMAIN_SIZE));
            if (nVars < 1 || nVars < nPublic + 1) {
                throw new IOException("Invalid Groth16 header dimensions: nVars=" + nVars + ", nPublic=" + nPublic);
            }
            if (domainSize == 0 || (domainSize & (domainSize - 1)) != 0 || domainSize > Integer.MAX_VALUE) {
                throw new IOException("Invalid Groth16 domainSize: " + domainSize);
            }
            long nL = nVars - nPublic - 1;
            if (nL > Integer.MAX_VALUE) {
                throw new IOException("L section point count exceeds int range: " + nL);
            }

            validateSectionSize(sec, 3, (nPublic + 1L) * 96L, "IC");
            validateCoeffsSection(z, sec.get(4));
            validateSectionSize(sec, 5, nVars * 96L, "A");
            validateSectionSize(sec, 6, nVars * 96L, "B1");
            validateSectionSize(sec, 7, nVars * 192L, "B2");
            validateSectionSize(sec, 8, nL * 96L, "L");
            validateSectionSize(sec, 9, domainSize * 96L, "H");

            // ---- S3 & S4: pre-secret header, delta pairing, and contribution chain validation ----
            requireNonIdentitySubgroupG1(z, h + H_ALPHA1, "header.alpha1");
            requireNonIdentitySubgroupG1(z, h + H_BETA1, "header.beta1");
            requireNonIdentitySubgroupG2(z, h + H_BETA2, "header.beta2");
            requireNonIdentitySubgroupG2(z, h + H_GAMMA2, "header.gamma2");
            AffineG1 delta1 = requireNonIdentitySubgroupG1(z, h + H_DELTA1, "header.delta1");
            AffineG2 delta2 = requireNonIdentitySubgroupG2(z, h + H_DELTA2, "header.delta2");

            if (!BLS12381Pairing.pairingCheck(
                    new G1Point[]{toG1Point(delta1), G1_GENERATOR.negate()},
                    new G2Point[]{G2_GENERATOR, toG2Point(delta2)})) {
                throw new IOException("Header delta1 and delta2 fail pairing check e(delta1, G2) == e(G1, delta2)");
            }

            long s10 = sec.get(10)[0];
            long s10Size = sec.get(10)[1];
            long s10End = s10 + s10Size;
            if (s10Size < 68) {
                throw new IOException("Truncated .zkey contributions section: " + s10Size + " bytes");
            }
            byte[] csHash = bytes(z, s10, 64);
            long nContribLong = Integer.toUnsignedLong(z.get(U32, s10 + 64));
            long maxContribs = (s10Size - 68) / MIN_CONTRIBUTION_BYTES;
            if (nContribLong > maxContribs) {
                throw new IOException("Invalid prior contribution count " + nContribLong
                        + " for section size " + s10Size);
            }
            int nContrib = (int) nContribLong;
            long rp = s10 + 68;
            List<PriorContribution> priors = new ArrayList<>(nContrib);
            long priorRawTotal = 0;
            for (int i = 0; i < nContrib; i++) {
                if (rp > s10End - MIN_CONTRIBUTION_BYTES) {
                    throw new IOException("Truncated contribution record at index " + i);
                }
                long start = rp;
                String prefix = "contributions[" + i + "]";
                AffineG1 deltaAfter = requireNonIdentitySubgroupG1(z, rp, prefix + ".deltaAfter");
                AffineG1 pG1s = requireNonIdentitySubgroupG1(z, rp + 96, prefix + ".g1_s");
                AffineG1 pG1sx = requireNonIdentitySubgroupG1(z, rp + 192, prefix + ".g1_sx");
                AffineG2 pG2spx = requireNonIdentitySubgroupG2(z, rp + 288, prefix + ".g2_spx");
                byte[] pTranscript = bytes(z, rp + 480, 64);
                int type = z.get(U32, rp + 544);
                if (type != 0 && type != 1) {
                    throw new IOException("Unsupported contribution type " + type + " at index " + i);
                }
                long paramLen = Integer.toUnsignedLong(z.get(U32, rp + 548));
                long paramStart = rp + 552;
                if (paramLen > s10End - paramStart) {
                    throw new IOException("Out-of-bounds contribution params length " + paramLen + " at index " + i);
                }
                validateContributionParams(z, paramStart, paramLen);
                rp = paramStart + paramLen;
                byte[] raw = bytes(z, start, rp - start);
                priorRawTotal += raw.length;
                priors.add(new PriorContribution(deltaAfter, pG1s, pG1sx, pG2spx, pTranscript, raw));
            }
            if (rp != s10End) {
                throw new IOException("Trailing bytes in .zkey contributions section: " + (s10End - rp));
            }

            AffineG1 expectedDelta1 = priors.isEmpty()
                    ? JacobianG1BLS381.GENERATOR.toAffine()
                    : priors.get(priors.size() - 1).deltaAfter();
            if (!delta1.equals(expectedDelta1)) {
                throw new IOException("Header delta1 does not match "
                        + (priors.isEmpty() ? "G1 generator (0 prior contributions)" : "last contribution deltaAfter"));
            }

            // ---- S6: draw fresh secrets ONLY after all pre-secret checks succeed ----
            SecureRandom rnd = new SecureRandom();
            BigInteger k = randScalar(rnd);
            BigInteger s = randScalar(rnd);
            AffineG1 g1s = JacobianG1BLS381.GENERATOR.ctScalarMul(s).toAffine();
            AffineG1 g1sx = JacobianG1BLS381.fromAffine(g1s.x(), g1s.y()).ctScalarMul(k).toAffine();

            // transcript = blake2b512(csHash ‖ RAW fields of every prior record ‖ unc(g1_s) ‖ unc(g1_sx))
            // — snarkjs streams each prior's components into ONE running hasher (hashPubKey(hasher, c)),
            // NOT the priors' sub-hashes. (The two coincide only with zero priors.)
            Blake2bDigest th = new Blake2bDigest(512);
            update(th, csHash);
            for (PriorContribution c : priors) {
                hashPubKeyInto(th, c.deltaAfter(), c.g1s(), c.g1sx(), c.g2spx(), c.transcript());
            }
            update(th, g1Unc(g1s));
            update(th, g1Unc(g1sx));
            byte[] transcript = digest(th);

            AffineG2 g2sp = SnarkjsHashToG2.hashToG2(transcript);
            if (g2sp.isInfinity()) {
                throw new IOException("Hash-to-G2 challenge unexpectedly produced identity point");
            }
            AffineG2 g2spx = JacobianG2BLS381.fromAffine(g2sp.x(), g2sp.y()).ctScalarMul(k).toAffine();

            AffineG1 delta1New = JacobianG1BLS381.fromAffine(delta1.x(), delta1.y()).ctScalarMul(k).toAffine();
            AffineG2 delta2New = JacobianG2BLS381.fromAffine(delta2.x(), delta2.y()).ctScalarMul(k).toAffine();
            BigInteger kInv = k.modInverse(R_FR);

            // new contribution record
            byte[] nameBytes = encodeName(name);
            byte[] params = nameBytes.length == 0
                    ? new byte[0]
                    : concat(new byte[]{1, (byte) nameBytes.length}, nameBytes);
            byte[] record = concat(
                    g1Lem(delta1New), g1Lem(g1s), g1Lem(g1sx), g2Lem(g2spx), transcript,
                    u32(0), u32(params.length), params);

            // ---- S7: write the new .zkey into a sibling temp file, then publish atomically ----
            long s10NewSize = 64L + 4L + priorRawTotal + record.length;
            long total = 12L
                    + 12L + sec.get(1)[1] + 12L + sec.get(2)[1]
                    + 12L + sec.get(3)[1] + 12L + sec.get(4)[1] + 12L + sec.get(5)[1]
                    + 12L + sec.get(6)[1] + 12L + sec.get(7)[1] + 12L + sec.get(8)[1]
                    + 12L + sec.get(9)[1] + 12L + s10NewSize;

            Path tmp = Files.createTempFile(outDir, ".zeroj-zkey-", ".tmp");
            boolean published = false;
            try {
                try (FileChannel outCh = FileChannel.open(tmp,
                        StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                    try (Arena outArena = Arena.ofShared()) {
                        MemorySegment o = outCh.map(FileChannel.MapMode.READ_WRITE, 0, total, outArena);
                        o.set(U32, 0, ZKEY_MAGIC);
                        o.set(U32, 4, 1);
                        o.set(U32, 8, REQUIRED_SECTIONS);
                        long w = 12;

                        w = section(o, w, 1, sec.get(1)[1]);
                        o.set(U32, w, GROTH16_PROTOCOL);
                        w += sec.get(1)[1];

                        w = section(o, w, 2, sec.get(2)[1]);
                        MemorySegment.copy(z, sec.get(2)[0], o, w, sec.get(2)[1]);
                        put(o, w + H_DELTA1, g1Lem(delta1New));
                        put(o, w + H_DELTA2, g2Lem(delta2New));
                        w += sec.get(2)[1];

                        for (int t : new int[]{3, 4, 5, 6, 7}) {
                            w = section(o, w, t, sec.get(t)[1]);
                            MemorySegment.copy(z, sec.get(t)[0], o, w, sec.get(t)[1]);
                            w += sec.get(t)[1];
                        }

                        w = section(o, w, 8, sec.get(8)[1]);
                        rescaleG1Section(z, sec.get(8)[0], o, w, (int) nL, kInv, "L (section 8)");
                        w += sec.get(8)[1];

                        w = section(o, w, 9, sec.get(9)[1]);
                        rescaleG1Section(z, sec.get(9)[0], o, w, (int) domainSize, kInv, "H (section 9)");
                        w += sec.get(9)[1];

                        w = section(o, w, 10, s10NewSize);
                        put(o, w, csHash);
                        o.set(U32, w + 64, nContrib + 1);
                        long q = w + 68;
                        for (PriorContribution prior : priors) {
                            put(o, q, prior.rawBytes());
                            q += prior.rawBytes().length;
                        }
                        put(o, q, record);
                    }
                    outCh.force(true);
                }

                publishTempFile(tmp, inAbs, outAbs, overwrite);
                published = true;
            } finally {
                if (!published) {
                    Files.deleteIfExists(tmp);
                }
            }

            Blake2bDigest ch = new Blake2bDigest(512);
            hashPubKeyInto(ch, delta1New, g1s, g1sx, g2spx, transcript);
            return digest(ch);
        }
    }

    private static void publishTempFile(Path tmp, Path inAbs, Path outAbs, boolean overwrite) throws IOException {
        if (Files.exists(outAbs, LinkOption.NOFOLLOW_LINKS)
                && Files.exists(inAbs)
                && Files.isSameFile(inAbs, outAbs)) {
            throw new IOException("Refusing in-place overwrite: --in and --out refer to the same file: " + outAbs);
        }
        if (!overwrite) {
            try {
                // Atomic non-clobbering publish on POSIX/NTFS filesystems supporting hard links.
                Files.createLink(outAbs, tmp);
                Files.deleteIfExists(tmp);
                return;
            } catch (FileAlreadyExistsException e) {
                throw new IOException("Output file already exists (pass --overwrite / overwrite=true to replace): " + outAbs, e);
            } catch (UnsupportedOperationException | SecurityException | IOException ignored) {
                // Fall back to move on filesystems without hard-link support.
                if (Files.exists(outAbs, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("Output file already exists (pass --overwrite / overwrite=true to replace): " + outAbs);
                }
                try {
                    Files.move(tmp, outAbs, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, outAbs);
                }
                return;
            }
        }
        try {
            Files.move(tmp, outAbs, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, outAbs, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    // ---- L/H rescale (multi-core, ADR-0062 ctScalarMul) ----

    /**
     * Rescales every point in section 8 (L) or section 9 (H) by {@code kInv}.
     *
     * <p>Per snarkjs 0.7.6 ({@code zkey_new.js:460-466}, {@code mpc_applykey.js:44},
     * {@code ffjavascript} 0.3.1 {@code wasm_curve.js}), infinity (96 zero bytes) is legal in L
     * (e.g. unused private wires) and preserved unchanged ({@code kInv · O = O}, leaking zero bits
     * of {@code kInv}). Every non-infinity point is canonical-checked ({@code < p}) in
     * {@link #g1FromLem} and on-curve + prime-order subgroup validated inside
     * {@link JacobianG1BLS381#ctScalarMul} (checked once per point).</p>
     */
    private static void rescaleG1Section(MemorySegment in, long inOff, MemorySegment out, long outOff,
                                         int count, BigInteger kInv, String sectionName) throws IOException {
        if (count == 0) return;
        AtomicReference<IOException> failure = new AtomicReference<>();
        FrFFTFlat.parallelRange(count, (lo, hi) -> {
            for (int i = lo; i < hi; i++) {
                if (failure.get() != null) return;
                try {
                    AffineG1 p = g1FromLem(in, inOff + i * 96L);
                    AffineG1 r = p.isInfinity()
                            ? AffineG1.INFINITY
                            : JacobianG1BLS381.fromAffine(p.x(), p.y()).ctScalarMul(kInv).toAffine();
                    put(out, outOff + i * 96L, g1Lem(r));
                } catch (IllegalArgumentException e) {
                    failure.compareAndSet(null, new IOException(
                            "Invalid G1 point in " + sectionName + " at index " + i + ": " + e.getMessage(), e));
                    return;
                }
            }
        });
        IOException err = failure.get();
        if (err != null) throw err;
    }

    // ---- validation helpers ----

    private static void validateSectionSize(Map<Integer, long[]> sec, int type, long expected, String label)
            throws IOException {
        long actual = sec.get(type)[1];
        if (actual != expected) {
            throw new IOException("Section " + type + " (" + label + ") size mismatch: expected "
                    + expected + " bytes, got " + actual);
        }
    }

    private static void validateCoeffsSection(MemorySegment z, long[] sec4) throws IOException {
        long off = sec4[0];
        long size = sec4[1];
        if (size < 4) {
            throw new IOException("Truncated .zkey coefficients section (section 4): " + size + " bytes");
        }
        long nCoeffs = Integer.toUnsignedLong(z.get(U32, off));
        long expected = 4L + nCoeffs * 44L;
        if (size != expected) {
            throw new IOException("Section 4 (coeffs) size mismatch: header declares " + nCoeffs
                    + " entries (" + expected + " bytes), got " + size);
        }
    }

    private static void validateContributionParams(MemorySegment z, long paramStart, long paramLen) throws IOException {
        long pos = paramStart;
        long end = paramStart + paramLen;
        int lastTag = 0;
        while (pos < end) {
            int tag = z.get(ValueLayout.JAVA_BYTE, pos++) & 0xFF;
            if (tag <= lastTag) {
                throw new IOException("Contribution parameters must be strictly sorted by tag");
            }
            lastTag = tag;
            if (tag == 1 || tag == 3) {
                if (pos >= end) {
                    throw new IOException("Truncated contribution parameter length for tag " + tag);
                }
                int len = z.get(ValueLayout.JAVA_BYTE, pos++) & 0xFF;
                if (len > end - pos) {
                    throw new IOException("Truncated contribution parameter payload for tag " + tag);
                }
                pos += len;
            } else if (tag == 2) {
                if (pos >= end) {
                    throw new IOException("Truncated contribution parameter payload for tag 2");
                }
                pos += 1;
            } else {
                throw new IOException("Unrecognized contribution parameter tag: " + tag);
            }
        }
        if (pos != end) {
            throw new IOException("Contribution parameter length mismatch");
        }
    }

    private static AffineG1 requireNonIdentitySubgroupG1(MemorySegment z, long off, String label) throws IOException {
        AffineG1 p;
        try {
            p = g1FromLem(z, off);
        } catch (IllegalArgumentException e) {
            throw new IOException("Non-canonical G1 coordinate in " + label + ": " + e.getMessage(), e);
        }
        if (p.isInfinity()) {
            throw new IOException("Identity G1 point is forbidden for " + label);
        }
        if (!p.isOnCurve()) {
            throw new IOException("Off-curve G1 point for " + label);
        }
        if (!JacobianG1BLS381.fromAffine(p.x(), p.y()).scalarMul(R_FR).isInfinity()) {
            throw new IOException("Non-subgroup G1 point for " + label);
        }
        return p;
    }

    private static AffineG2 requireNonIdentitySubgroupG2(MemorySegment z, long off, String label) throws IOException {
        AffineG2 p;
        try {
            p = g2FromLem(z, off);
        } catch (IllegalArgumentException e) {
            throw new IOException("Non-canonical G2 coordinate in " + label + ": " + e.getMessage(), e);
        }
        if (p.isInfinity()) {
            throw new IOException("Identity G2 point is forbidden for " + label);
        }
        if (!p.isOnCurve()) {
            throw new IOException("Off-curve G2 point for " + label);
        }
        if (!JacobianG2BLS381.fromAffine(p.x(), p.y()).scalarMul(R_FR).isInfinity()) {
            throw new IOException("Non-subgroup G2 point for " + label);
        }
        return p;
    }

    private static G1Point toG1Point(AffineG1 p) {
        return p.isInfinity() ? G1Point.INFINITY : new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2Point(AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }

    // ---- point codecs (LEM = little-endian Montgomery; Unc = canonical big-endian) ----

    private static MontFp381 montFpFromLem(MemorySegment z, long off) {
        return MontFp381.fromMontLimbs(
                z.get(U64, off),
                z.get(U64, off + 8),
                z.get(U64, off + 16),
                z.get(U64, off + 24),
                z.get(U64, off + 32),
                z.get(U64, off + 40));
    }

    private static AffineG1 g1FromLem(MemorySegment z, long off) {
        MontFp381 x = montFpFromLem(z, off);
        MontFp381 y = montFpFromLem(z, off + 48);
        if (x.isZero() && y.isZero()) return AffineG1.INFINITY;
        return new AffineG1(x, y);
    }

    private static AffineG2 g2FromLem(MemorySegment z, long off) {
        MontFp381 x0 = montFpFromLem(z, off);
        MontFp381 x1 = montFpFromLem(z, off + 48);
        MontFp381 y0 = montFpFromLem(z, off + 96);
        MontFp381 y1 = montFpFromLem(z, off + 144);
        if (x0.isZero() && x1.isZero() && y0.isZero() && y1.isZero()) {
            return AffineG2.INFINITY;
        }
        return new AffineG2(MontFp2_381.of(x0, x1), MontFp2_381.of(y0, y1));
    }

    private static byte[] g1Lem(AffineG1 p) {
        byte[] b = new byte[96];
        if (p.isInfinity()) return b;
        putMontFpLE(p.x(), b, 0);
        putMontFpLE(p.y(), b, 48);
        return b;
    }

    private static byte[] g2Lem(AffineG2 p) {
        byte[] b = new byte[192];
        if (p.isInfinity()) return b;
        putMontFpLE(p.x().re(), b, 0);
        putMontFpLE(p.x().im(), b, 48);
        putMontFpLE(p.y().re(), b, 96);
        putMontFpLE(p.y().im(), b, 144);
        return b;
    }

    private static byte[] g1Unc(AffineG1 p) {
        byte[] b = new byte[96];
        if (p.isInfinity()) return b;
        be48(p.xBigInt(), b, 0);
        be48(p.yBigInt(), b, 48);
        return b;
    }

    private static byte[] g2Unc(AffineG2 p) {
        byte[] b = new byte[192];
        if (p.isInfinity()) return b;
        be48(p.x().imBigInt(), b, 0);    // c1 first (byte-reverse of the LE c0‖c1 block)
        be48(p.x().reBigInt(), b, 48);
        be48(p.y().imBigInt(), b, 96);
        be48(p.y().reBigInt(), b, 144);
        return b;
    }

    /** snarkjs {@code hashPubKey(hasher, curve, c)}: stream the record's raw components into {@code d}. */
    private static void hashPubKeyInto(Blake2bDigest d, AffineG1 deltaAfter, AffineG1 g1s, AffineG1 g1sx,
                                       AffineG2 g2spx, byte[] transcript) {
        update(d, g1Unc(deltaAfter));
        update(d, g1Unc(g1s));
        update(d, g1Unc(g1sx));
        update(d, g2Unc(g2spx));
        update(d, transcript);
    }

    // ---- low-level helpers ----

    private static BigInteger readUnsignedLE(MemorySegment z, long off, int len) {
        byte[] be = new byte[len];
        for (int i = 0; i < len; i++) {
            be[len - 1 - i] = z.get(ValueLayout.JAVA_BYTE, off + i);
        }
        return new BigInteger(1, be);
    }

    private static void putMontFpLE(MontFp381 v, byte[] out, int off) {
        long[] limbs = v.toLimbs();
        for (int i = 0; i < 6; i++) {
            long limb = limbs[i];
            int base = off + i * 8;
            out[base] = (byte) limb;
            out[base + 1] = (byte) (limb >>> 8);
            out[base + 2] = (byte) (limb >>> 16);
            out[base + 3] = (byte) (limb >>> 24);
            out[base + 4] = (byte) (limb >>> 32);
            out[base + 5] = (byte) (limb >>> 40);
            out[base + 6] = (byte) (limb >>> 48);
            out[base + 7] = (byte) (limb >>> 56);
        }
    }

    private static void be48(BigInteger v, byte[] out, int off) {
        byte[] be = v.toByteArray();
        int s = Math.max(0, be.length - 48), len = be.length - s;
        System.arraycopy(be, s, out, off + 48 - len, len);
    }

    /**
     * Truncates contributor name matching snarkjs 0.7.6 ({@code name.substring(0, 64)} in UTF-8)
     * while preventing surrogate splitting and 1-byte TLV length overflow ({@code <= 255} UTF-8 bytes).
     */
    private static byte[] encodeName(String name) {
        if (name == null || name.isEmpty()) return new byte[0];
        int maxCodePoints = 64;
        int endIndex = 0;
        int utf8Bytes = 0;
        int codePoints = 0;
        while (endIndex < name.length() && codePoints < maxCodePoints) {
            int cp = name.codePointAt(endIndex);
            int charCount = Character.charCount(cp);
            int cpUtf8Len = cp <= 0x7F ? 1 : (cp <= 0x7FF ? 2 : (cp <= 0xFFFF ? 3 : 4));
            if (utf8Bytes + cpUtf8Len > 255) break;
            utf8Bytes += cpUtf8Len;
            endIndex += charCount;
            codePoints++;
        }
        return name.substring(0, endIndex).getBytes(StandardCharsets.UTF_8);
    }

    private static BigInteger randScalar(SecureRandom rnd) {
        BigInteger v;
        do {
            v = new BigInteger(512, rnd).mod(R_FR);
        } while (v.signum() == 0);
        return v;
    }

    private static byte[] bytes(MemorySegment z, long off, long len) {
        byte[] b = new byte[(int) len];
        MemorySegment.copy(z, off, MemorySegment.ofArray(b), 0, len);
        return b;
    }

    private static void put(MemorySegment o, long off, byte[] b) {
        MemorySegment.copy(MemorySegment.ofArray(b), 0, o, off, b.length);
    }

    private static long section(MemorySegment o, long w, int type, long size) {
        o.set(U32, w, type);
        o.set(U64, w + 4, size);
        return w + 12;
    }

    private static byte[] u32(int v) {
        return new byte[]{(byte) v, (byte) (v >>> 8), (byte) (v >>> 16), (byte) (v >>> 24)};
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) len += p.length;
        byte[] r = new byte[len];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, r, o, p.length);
            o += p.length;
        }
        return r;
    }

    private static void update(Blake2bDigest d, byte[] b) {
        d.update(b, 0, b.length);
    }

    private static byte[] digest(Blake2bDigest d) {
        byte[] out = new byte[64];
        d.doFinal(out, 0);
        return out;
    }
}
