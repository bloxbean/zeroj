package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Imports SRS (Structured Reference String) from Powers of Tau .ptau files for BLS12-381.
 *
 * <p>Key differences from BN254 ({@link PtauImporter}):
 * <ul>
 *   <li>n8 = 48 (BLS12-381 Fp is 48 bytes)</li>
 *   <li>Montgomery R = 2^384 mod p</li>
 *   <li>G1 points: 96 bytes, G2 points: 192 bytes</li>
 * </ul>
 */
public final class PtauImporterBLS381 {

    private PtauImporterBLS381() {}

    private static final byte[] PTAU_MAGIC = {0x70, 0x74, 0x61, 0x75}; // "ptau"
    private static final int MAX_PTAU_BYTES = 64 * 1024 * 1024;
    private static final int MAX_SECTIONS = 64;
    private static final int MAX_POWER = 32;
    private static final BigInteger FP = MontFp381.modulus();
    // Montgomery R^{-1} for Fp: (2^384 mod p)^{-1} mod p
    private static final BigInteger FP_R_INV = BigInteger.ONE.shiftLeft(384).mod(FP).modInverse(FP);

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
     * Import SRS from a BLS12-381 .ptau file.
     *
     * @param maxPoints maximum number of G1 points to load
     */
    public static SRS importPtau(InputStream input, int maxPoints) throws IOException {
        return importPtau(input, maxPoints, null);
    }

    /**
     * Import SRS from a BLS12-381 .ptau file and require an exact SHA-256
     * content-hash match before parsing.
     *
     * @param maxPoints maximum number of G1 points to load
     * @param expectedSha256 expected SHA-256 hash, or {@code null} for dev/test
     *                       callers that intentionally skip artifact pinning
     */
    public static SRS importPtau(InputStream input, int maxPoints, byte[] expectedSha256) throws IOException {
        if (maxPoints <= 0) {
            throw new IOException("maxPoints must be positive");
        }
        byte[] data = readBounded(input, ".ptau input");
        requireExpectedSha256(data, expectedSha256, ".ptau");
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (buf.remaining() < 12) {
            throw new IOException("Truncated .ptau header");
        }

        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, PTAU_MAGIC))
            throw new IOException("Invalid .ptau magic");
        int version = buf.getInt();
        int numSections = buf.getInt();
        if (version <= 0) {
            throw new IOException("Invalid .ptau version: " + version);
        }
        if (numSections <= 0 || numSections > MAX_SECTIONS) {
            throw new IOException("Invalid .ptau section count: " + numSections);
        }

        Map<Integer, long[]> sections = new LinkedHashMap<>();
        for (int i = 0; i < numSections; i++) {
            requireRemaining(buf, 12, ".ptau section header");
            int stype = buf.getInt();
            long ssize = buf.getLong();
            if (sections.containsKey(stype)) {
                throw new IOException("Duplicate .ptau section: " + stype);
            }
            if (ssize < 0 || ssize > buf.remaining() || ssize > Integer.MAX_VALUE) {
                throw new IOException("Invalid .ptau section size for section " + stype);
            }
            sections.put(stype, new long[]{buf.position(), ssize});
            buf.position(buf.position() + (int) ssize);
        }
        requireSection(sections, 1);
        requireSection(sections, 2);
        requireSection(sections, 3);

        // Section 1: Header
        buf.position((int) sections.get(1)[0]);
        requireSectionSize(sections, 1, 4 + 48 + 4);
        int n8 = buf.getInt();
        if (n8 != 48)
            throw new IOException("Not a BLS12-381 .ptau (n8=" + n8 + ", expected 48)");
        BigInteger prime = readFieldLE(buf, n8, FP, "BLS12-381 .ptau prime");
        if (!FP.equals(prime)) {
            throw new IOException("Wrong BLS12-381 .ptau base-field prime");
        }
        int power = buf.getInt();
        if (power < 1 || power > MAX_POWER) {
            throw new IOException("Invalid BLS12-381 .ptau power: " + power);
        }

        // Section 2: tau^i * G1 (affine, LE, Montgomery)
        if (sections.get(2)[1] % (2L * n8) != 0) {
            throw new IOException("Invalid BLS12-381 .ptau G1 section size");
        }
        buf.position((int) sections.get(2)[0]);
        int availableG1 = (int) (sections.get(2)[1] / (2 * n8));
        int nG1 = Math.min(availableG1, maxPoints);
        if (nG1 == 0) {
            throw new IOException("BLS12-381 .ptau contains no G1 powers");
        }
        AffineG1[] tauG1 = new AffineG1[nG1];
        for (int i = 0; i < nG1; i++) {
            tauG1[i] = readG1Mont(buf, n8);
        }

        // Section 3: tau^i * G2 (only need first 2)
        if (sections.get(3)[1] % (4L * n8) != 0) {
            throw new IOException("Invalid BLS12-381 .ptau G2 section size");
        }
        buf.position((int) sections.get(3)[0]);
        int nG2 = Math.min((int) (sections.get(3)[1] / (4 * n8)), 2);
        if (nG2 < 2) {
            throw new IOException("BLS12-381 .ptau must contain at least two G2 powers");
        }
        AffineG2[] tauG2 = new AffineG2[nG2];
        for (int i = 0; i < nG2; i++) {
            tauG2[i] = readG2Mont(buf, n8);
        }
        validateSrsConsistency(tauG1, tauG2, nG1);

        return new SRS(tauG1, tauG2, power);
    }

    public static SRS importPtau(InputStream input) throws IOException {
        return importPtau(input, Integer.MAX_VALUE);
    }

    /**
     * Import SRS from a BLS12-381 .ptau file and require an exact SHA-256
     * content-hash match before parsing.
     */
    public static SRS importPtau(InputStream input, byte[] expectedSha256) throws IOException {
        return importPtau(input, Integer.MAX_VALUE, expectedSha256);
    }

    private static AffineG1 readG1Mont(ByteBuffer buf, int n8) throws IOException {
        BigInteger x = readFieldLE(buf, n8, FP, "BLS12-381 G1 x").multiply(FP_R_INV).mod(FP);
        BigInteger y = readFieldLE(buf, n8, FP, "BLS12-381 G1 y").multiply(FP_R_INV).mod(FP);
        if (x.signum() == 0 && y.signum() == 0) return AffineG1.INFINITY;
        AffineG1 point = new AffineG1(MontFp381.fromBigInteger(x), MontFp381.fromBigInteger(y));
        if (!point.isOnCurve()) {
            throw new IOException("BLS12-381 .ptau G1 point is not on curve");
        }
        G1Point subgroupPoint = new G1Point(Fp.of(point.xBigInt()), Fp.of(point.yBigInt()));
        if (!subgroupPoint.isValid()) {
            throw new IOException("BLS12-381 .ptau G1 point is not in subgroup");
        }
        return point;
    }

    private static AffineG2 readG2Mont(ByteBuffer buf, int n8) throws IOException {
        BigInteger x0 = readFieldLE(buf, n8, FP, "BLS12-381 G2 x0").multiply(FP_R_INV).mod(FP);
        BigInteger x1 = readFieldLE(buf, n8, FP, "BLS12-381 G2 x1").multiply(FP_R_INV).mod(FP);
        BigInteger y0 = readFieldLE(buf, n8, FP, "BLS12-381 G2 y0").multiply(FP_R_INV).mod(FP);
        BigInteger y1 = readFieldLE(buf, n8, FP, "BLS12-381 G2 y1").multiply(FP_R_INV).mod(FP);
        if (x0.signum() == 0 && x1.signum() == 0 && y0.signum() == 0 && y1.signum() == 0)
            return AffineG2.INFINITY;
        AffineG2 point = new AffineG2(MontFp2_381.of(x0, x1), MontFp2_381.of(y0, y1));
        if (!point.isOnCurve()) {
            throw new IOException("BLS12-381 .ptau G2 point is not on curve");
        }
        G2Point subgroupPoint = new G2Point(
                Fp2.of(Fp.of(point.x().reBigInt()), Fp.of(point.x().imBigInt())),
                Fp2.of(Fp.of(point.y().reBigInt()), Fp.of(point.y().imBigInt())));
        if (!subgroupPoint.isValid()) {
            throw new IOException("BLS12-381 .ptau G2 point is not in subgroup");
        }
        return point;
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
        return new G1Point(Fp.of(point.xBigInt()), Fp.of(point.yBigInt()));
    }

    private static G2Point toG2(AffineG2 point) {
        return new G2Point(
                Fp2.of(Fp.of(point.x().reBigInt()), Fp.of(point.x().imBigInt())),
                Fp2.of(Fp.of(point.y().reBigInt()), Fp.of(point.y().imBigInt())));
    }

    private static BigInteger readFieldLE(ByteBuffer buf, int n8, BigInteger modulus, String label) throws IOException {
        requireRemaining(buf, n8, label);
        byte[] bytes = new byte[n8];
        buf.get(bytes);
        for (int i = 0; i < n8 / 2; i++) {
            byte tmp = bytes[i]; bytes[i] = bytes[n8 - 1 - i]; bytes[n8 - 1 - i] = tmp;
        }
        BigInteger value = new BigInteger(1, bytes);
        if (value.compareTo(modulus) >= 0) {
            throw new IOException(label + " is not canonical");
        }
        return value;
    }

    private static void requireSection(Map<Integer, long[]> sections, int sectionId) throws IOException {
        if (!sections.containsKey(sectionId)) {
            throw new IOException("Missing .ptau section: " + sectionId);
        }
    }

    private static void requireSectionSize(Map<Integer, long[]> sections, int sectionId, long minSize) throws IOException {
        if (sections.get(sectionId)[1] < minSize) {
            throw new IOException("Truncated .ptau section: " + sectionId);
        }
    }

    private static void requireRemaining(ByteBuffer buf, int bytes, String label) throws IOException {
        if (bytes < 0 || buf.remaining() < bytes) {
            throw new IOException("Truncated " + label);
        }
    }

    private static byte[] readBounded(InputStream input, String label) throws IOException {
        if (input == null) {
            throw new IOException(label + " is null");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > MAX_PTAU_BYTES) {
                throw new IOException(label + " exceeds " + MAX_PTAU_BYTES + " bytes");
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static void requireExpectedSha256(byte[] data, byte[] expectedSha256, String label) throws IOException {
        if (expectedSha256 == null) {
            return;
        }
        if (expectedSha256.length != 32) {
            throw new IOException(label + " expected SHA-256 hash must be 32 bytes");
        }
        if (!MessageDigest.isEqual(sha256(data), expectedSha256)) {
            throw new IOException(label + " SHA-256 hash mismatch");
        }
    }

    private static byte[] sha256(byte[] data) throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is not available", e);
        }
    }
}
