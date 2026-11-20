package org.zeroj.crypto.plonk;

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
import org.zeroj.bls12381.pairing.BLS12381Pairing;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Streaming importer for BLS12-381 Powers of Tau ({@code .ptau}) SRS files produced by
 * {@code snarkjs} 0.7.6 (ADR-0066).
 *
 * <p>Format summary ({@code snarkjs@0.7.6} {@code powersoftau_utils.js} / {@code powersoftau_new.js}):
 * <ul>
 *   <li>Global header (12 bytes): magic {@code "ptau"}, {@code version = 1}, {@code numSections}</li>
 *   <li>Section 1 (60 bytes): {@code n8 = 48}, raw unsigned LE base prime {@code q = FP},
 *       {@code power}, {@code ceremonyPower}</li>
 *   <li>Section 2 ({@code (2^(power+1) - 1) * 96} bytes): {@code tau^i * G1} in affine LEM format</li>
 *   <li>Section 3 ({@code 2^power * 192} bytes): {@code tau^i * G2} in affine LEM format</li>
 * </ul>
 *
 * <p>The stream is read sequentially without buffering the full file in RAM, so multi-GB ceremony
 * files can load {@code maxPoints} powers in {@code O(maxPoints)} memory while still computing
 * and verifying the full-stream SHA-256 when {@code expectedSha256} is provided. Only bounded
 * framing and raw point bytes are read during the streaming pass; all elliptic-curve decoding,
 * subgroup checks, and pairing checks are deferred until after {@code expectedSha256} matches.</p>
 */
public final class PtauImporterBLS381 {

    private PtauImporterBLS381() {}

    private static final byte[] PTAU_MAGIC = {0x70, 0x74, 0x61, 0x75}; // "ptau"
    private static final int MAX_SECTIONS = 64;
    private static final int MAX_POWER = 32;
    /**
     * Maximum G1 SRS points loaded in one call: aligned with PlonK's maximum supported domain
     * ({@code 2^24}) plus the 6 blinding powers required by {@code T3} ({@code 2^24 + 6}).
     */
    static final int MAX_IMPORT_POINTS = (1 << 24) + 6;
    private static final int SECTION1_LEN = 4 + 48 + 4 + 4; // n8 + prime(48) + power + ceremonyPower
    private static final int G1_LEM_BYTES = 96;
    private static final int G2_LEM_BYTES = 192;
    private static final BigInteger FP = MontFp381.modulus();

    /** Parsed SRS for BLS12-381. */
    public record SRS(
            AffineG1[] tauG1,
            AffineG2[] tauG2,
            int power,
            BigInteger tauScalar
    ) {
        public SRS(AffineG1[] tauG1, AffineG2[] tauG2, int power) {
            this(tauG1, tauG2, power, null);
        }

        public AffineG2 x2() { return tauG2[1]; }
    }

    /**
     * Import SRS from a BLS12-381 {@code .ptau} stream, loading up to {@code maxPoints} G1 powers.
     *
     * @param maxPoints maximum number of G1 powers to load (for PlonK, {@code domainSize + 6} suffices)
     */
    public static SRS importPtau(InputStream input, int maxPoints) throws IOException {
        return importPtau(input, maxPoints, null);
    }

    /**
     * Import SRS from a BLS12-381 {@code .ptau} stream and require an exact full-stream SHA-256
     * match before decoding or validating elliptic-curve points (ADR-0066).
     *
     * @param maxPoints      maximum number of G1 powers to load (capped at {@value #MAX_IMPORT_POINTS})
     * @param expectedSha256 expected 32-byte SHA-256 digest of the entire {@code .ptau} stream, or
     *                       {@code null} for dev/test callers that intentionally skip pinning
     */
    public static SRS importPtau(InputStream input, int maxPoints, byte[] expectedSha256) throws IOException {
        if (input == null) {
            throw new IOException(".ptau input is null");
        }
        if (maxPoints <= 0) {
            throw new IOException("maxPoints must be positive");
        }
        if (expectedSha256 != null && expectedSha256.length != 32) {
            throw new IOException(".ptau expected SHA-256 hash must be 32 bytes");
        }

        MessageDigest sha256 = null;
        InputStream stream = new BufferedInputStream(input, 65536);
        if (expectedSha256 != null) {
            sha256 = newSha256();
            stream = new DigestInputStream(stream, sha256);
        }

        byte[] headerBuf = readExact(stream, 12, ".ptau header");
        if (!Arrays.equals(headerBuf, 0, 4, PTAU_MAGIC, 0, 4)) {
            throw new IOException("Invalid .ptau magic");
        }
        ByteBuffer hdr = ByteBuffer.wrap(headerBuf).order(ByteOrder.LITTLE_ENDIAN);
        hdr.position(4);
        int version = hdr.getInt();
        int numSections = hdr.getInt();
        if (version != 1) {
            throw new IOException("Unsupported .ptau version: " + version);
        }
        if (numSections <= 0 || numSections > MAX_SECTIONS) {
            throw new IOException("Invalid .ptau section count: " + numSections);
        }

        Set<Integer> seenSections = new HashSet<>();
        boolean hasHeader = false;
        int power = -1;
        int nG1 = -1;
        byte[] rawG1 = null;
        byte[] rawG2 = null;
        byte[] skipScratch = new byte[8192];

        for (int s = 0; s < numSections; s++) {
            byte[] secHdrBytes = readExact(stream, 12, ".ptau section header");
            ByteBuffer secHdr = ByteBuffer.wrap(secHdrBytes).order(ByteOrder.LITTLE_ENDIAN);
            int stype = secHdr.getInt();
            long ssize = secHdr.getLong();
            if (!seenSections.add(stype)) {
                throw new IOException("Duplicate .ptau section: " + stype);
            }
            if (ssize < 0) {
                throw new IOException("Invalid .ptau section size for section " + stype + ": " + ssize);
            }

            if (stype == 1) {
                if (ssize != SECTION1_LEN) {
                    throw new IOException("Invalid BLS12-381 .ptau header section size: expected "
                            + SECTION1_LEN + " bytes, got " + ssize);
                }
                byte[] sec1 = readExact(stream, SECTION1_LEN, "BLS12-381 .ptau header section");
                ByteBuffer s1 = ByteBuffer.wrap(sec1).order(ByteOrder.LITTLE_ENDIAN);
                int n8 = s1.getInt();
                if (n8 != 48) {
                    throw new IOException("Not a BLS12-381 .ptau (n8=" + n8 + ", expected 48)");
                }
                BigInteger prime = readUnsignedLE(sec1, 4, 48);
                if (!FP.equals(prime)) {
                    throw new IOException("Wrong BLS12-381 .ptau base-field prime");
                }
                s1.position(52);
                power = s1.getInt();
                int ceremonyPower = s1.getInt();
                if (power < 1 || power > MAX_POWER) {
                    throw new IOException("Invalid BLS12-381 .ptau power: " + power);
                }
                if (ceremonyPower < power || ceremonyPower > MAX_POWER) {
                    throw new IOException("Invalid BLS12-381 .ptau ceremonyPower: " + ceremonyPower
                            + " (power=" + power + ")");
                }
                hasHeader = true;
            } else if (stype == 2) {
                if (!hasHeader) {
                    throw new IOException("BLS12-381 .ptau section 2 appeared before header section 1");
                }
                long availableG1 = (1L << (power + 1)) - 1L;
                long expectedSize = availableG1 * G1_LEM_BYTES;
                if (ssize != expectedSize) {
                    throw new IOException("Invalid BLS12-381 .ptau G1 section size: expected "
                            + expectedSize + " bytes for power " + power + ", got " + ssize);
                }
                nG1 = resolvedG1Count(availableG1, maxPoints);
                rawG1 = readExact(stream, nG1 * G1_LEM_BYTES, "BLS12-381 .ptau G1 points");
                long remainingBytes = (availableG1 - nG1) * G1_LEM_BYTES;
                skipExact(stream, remainingBytes, skipScratch, ".ptau section 2 trailing G1 points");
            } else if (stype == 3) {
                if (!hasHeader) {
                    throw new IOException("BLS12-381 .ptau section 3 appeared before header section 1");
                }
                long availableG2 = 1L << power;
                long expectedSize = availableG2 * G2_LEM_BYTES;
                if (ssize != expectedSize) {
                    throw new IOException("Invalid BLS12-381 .ptau G2 section size: expected "
                            + expectedSize + " bytes for power " + power + ", got " + ssize);
                }
                if (availableG2 < 2) {
                    throw new IOException("BLS12-381 .ptau must contain at least two G2 powers");
                }
                rawG2 = readExact(stream, 2 * G2_LEM_BYTES, "BLS12-381 .ptau G2 points");
                long remainingBytes = (availableG2 - 2L) * G2_LEM_BYTES;
                skipExact(stream, remainingBytes, skipScratch, ".ptau section 3 trailing G2 points");
            } else {
                skipExact(stream, ssize, skipScratch, ".ptau section " + stype);
            }
        }

        if (!hasHeader) {
            throw new IOException("Missing .ptau section: 1");
        }
        if (rawG1 == null) {
            throw new IOException("Missing .ptau section: 2");
        }
        if (rawG2 == null) {
            throw new IOException("Missing .ptau section: 3");
        }
        if (stream.read() != -1) {
            throw new IOException("Trailing bytes after .ptau sections");
        }

        // Verify SHA-256 BEFORE any expensive elliptic-curve decoding, subgroup checks, or pairings.
        if (expectedSha256 != null && !MessageDigest.isEqual(sha256.digest(), expectedSha256)) {
            throw new IOException(".ptau SHA-256 hash mismatch");
        }

        AffineG1[] tauG1 = new AffineG1[nG1];
        for (int i = 0; i < nG1; i++) {
            tauG1[i] = decodeSrsG1(rawG1, i * G1_LEM_BYTES, i);
        }
        AffineG2[] tauG2 = new AffineG2[2];
        for (int i = 0; i < 2; i++) {
            tauG2[i] = decodeSrsG2(rawG2, i * G2_LEM_BYTES, i);
        }

        validateSrsConsistency(tauG1, tauG2, tauG1.length);
        return new SRS(tauG1, tauG2, power);
    }

    /**
     * Import all G1 powers (up to {@value #MAX_IMPORT_POINTS}) from a BLS12-381 {@code .ptau} stream.
     * For large ceremony files, prefer {@link #importPtau(InputStream, int, byte[])} with an explicit
     * {@code maxPoints} (e.g. {@code domainSize + 6}).
     */
    public static SRS importPtau(InputStream input) throws IOException {
        return importPtau(input, Integer.MAX_VALUE);
    }

    /**
     * Import SRS from a BLS12-381 {@code .ptau} stream and require an exact full-stream SHA-256
     * match before decoding or validating elliptic-curve points.
     */
    public static SRS importPtau(InputStream input, byte[] expectedSha256) throws IOException {
        return importPtau(input, Integer.MAX_VALUE, expectedSha256);
    }

    static int resolvedG1Count(long availableG1, int maxPoints) throws IOException {
        long nG1Long = Math.min(availableG1, (long) maxPoints);
        if (nG1Long > MAX_IMPORT_POINTS) {
            throw new IOException("Requested G1 power count " + nG1Long + " exceeds maximum "
                    + MAX_IMPORT_POINTS + " (pass an explicit maxPoints bound <= " + MAX_IMPORT_POINTS + ")");
        }
        return (int) nG1Long;
    }

    private static AffineG1 decodeSrsG1(byte[] ptBuf, int off, int index) throws IOException {
        MontFp381 x = decodeMontFp(ptBuf, off, "BLS12-381 .ptau G1[" + index + "].x");
        MontFp381 y = decodeMontFp(ptBuf, off + 48, "BLS12-381 .ptau G1[" + index + "].y");
        if (x.isZero() && y.isZero()) {
            throw new IOException("BLS12-381 .ptau G1[" + index + "] must not be the point at infinity");
        }
        AffineG1 point = new AffineG1(x, y);
        if (!point.isOnCurve()) {
            throw new IOException("BLS12-381 .ptau G1[" + index + "] is not on curve");
        }
        if (!toG1(point).isValid()) {
            throw new IOException("BLS12-381 .ptau G1[" + index + "] is not in subgroup");
        }
        return point;
    }

    private static AffineG2 decodeSrsG2(byte[] ptBuf, int off, int index) throws IOException {
        MontFp381 x0 = decodeMontFp(ptBuf, off, "BLS12-381 .ptau G2[" + index + "].x.c0");
        MontFp381 x1 = decodeMontFp(ptBuf, off + 48, "BLS12-381 .ptau G2[" + index + "].x.c1");
        MontFp381 y0 = decodeMontFp(ptBuf, off + 96, "BLS12-381 .ptau G2[" + index + "].y.c0");
        MontFp381 y1 = decodeMontFp(ptBuf, off + 144, "BLS12-381 .ptau G2[" + index + "].y.c1");
        if (x0.isZero() && x1.isZero() && y0.isZero() && y1.isZero()) {
            throw new IOException("BLS12-381 .ptau G2[" + index + "] must not be the point at infinity");
        }
        AffineG2 point = new AffineG2(MontFp2_381.of(x0, x1), MontFp2_381.of(y0, y1));
        if (!point.isOnCurve()) {
            throw new IOException("BLS12-381 .ptau G2[" + index + "] is not on curve");
        }
        if (!toG2(point).isValid()) {
            throw new IOException("BLS12-381 .ptau G2[" + index + "] is not in subgroup");
        }
        return point;
    }

    private static MontFp381 decodeMontFp(byte[] buf, int off, String label) throws IOException {
        ByteBuffer bb = ByteBuffer.wrap(buf, off, 48).order(ByteOrder.LITTLE_ENDIAN);
        try {
            return MontFp381.fromMontLimbs(
                    bb.getLong(), bb.getLong(), bb.getLong(),
                    bb.getLong(), bb.getLong(), bb.getLong());
        } catch (IllegalArgumentException e) {
            throw new IOException(label + " is not canonical (< p)", e);
        }
    }

    private static void validateSrsConsistency(AffineG1[] tauG1, AffineG2[] tauG2, int count) throws IOException {
        if (!tauG1[0].equals(JacobianG1BLS381.GENERATOR.toAffine())) {
            throw new IOException("BLS12-381 .ptau G1 generator anchor mismatch");
        }
        if (!tauG2[0].equals(JacobianG2BLS381.GENERATOR.toAffine())) {
            throw new IOException("BLS12-381 .ptau G2 generator anchor mismatch");
        }
        G2Point g2 = toG2(tauG2[0]);
        G2Point tauG2Point = toG2(tauG2[1]);
        for (int i = 1; i < count; i++) {
            boolean consistent = BLS12381Pairing.pairingCheck(
                    new G1Point[]{toG1(tauG1[i]), toG1(tauG1[i - 1]).negate()},
                    new G2Point[]{g2, tauG2Point});
            if (!consistent) {
                throw new IOException("BLS12-381 .ptau SRS powers are inconsistent at G1 index " + i);
            }
        }
    }

    private static G1Point toG1(AffineG1 point) {
        if (point.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(point.xBigInt()), Fp.of(point.yBigInt()));
    }

    private static G2Point toG2(AffineG2 point) {
        if (point.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(point.x().reBigInt()), Fp.of(point.x().imBigInt())),
                Fp2.of(Fp.of(point.y().reBigInt()), Fp.of(point.y().imBigInt())));
    }

    private static BigInteger readUnsignedLE(byte[] buf, int off, int len) {
        byte[] be = new byte[len];
        for (int i = 0; i < len; i++) {
            be[len - 1 - i] = buf[off + i];
        }
        return new BigInteger(1, be);
    }

    private static byte[] readExact(InputStream stream, int len, String label) throws IOException {
        byte[] out = new byte[len];
        readExactInto(stream, out, label);
        return out;
    }

    private static void readExactInto(InputStream stream, byte[] buf, String label) throws IOException {
        int offset = 0;
        while (offset < buf.length) {
            int n = stream.read(buf, offset, buf.length - offset);
            if (n < 0) {
                throw new IOException("Truncated " + label);
            }
            offset += n;
        }
    }

    private static void skipExact(InputStream stream, long bytes, byte[] scratch, String label) throws IOException {
        long remaining = bytes;
        while (remaining > 0) {
            int toRead = (int) Math.min(remaining, scratch.length);
            int n = stream.read(scratch, 0, toRead);
            if (n < 0) {
                throw new IOException("Truncated " + label);
            }
            remaining -= n;
        }
    }

    private static MessageDigest newSha256() throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is not available", e);
        }
    }
}
