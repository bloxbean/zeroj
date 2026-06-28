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
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;

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
 * Imports PlonK proving keys from snarkjs PlonK .zkey binary format (BLS12-381 curve).
 *
 * <p>PlonK .zkey (protocol ID = 2) has 14 sections:
 * <ul>
 *   <li>1: Protocol (= 2 for PlonK)</li>
 *   <li>2: Header (dimensions, k1/k2, selector/permutation commitments, X_2)</li>
 *   <li>3: Additions (circuit optimization — wire additions before constraints)</li>
 *   <li>4-6: A/B/C wire maps (constraint → wire mapping)</li>
 *   <li>7-11: Ql/Qr/Qm/Qo/Qc selector polynomials (Lagrange evaluations on domain)</li>
 *   <li>12: Sigma permutation polynomials S1/S2/S3 (Lagrange evaluations)</li>
 *   <li>13: Lagrange-basis SRS points</li>
 *   <li>14: Powers-of-tau SRS points (monomial basis)</li>
 * </ul>
 */
public final class PlonKZkeyImporterBLS381 {

    private PlonKZkeyImporterBLS381() {}

    private static final byte[] ZKEY_MAGIC = {0x7a, 0x6b, 0x65, 0x79};
    private static final int MAX_ZKEY_BYTES = 64 * 1024 * 1024;
    private static final int MAX_SECTIONS = 64;
    private static final int MIN_DOMAIN_SIZE = 8;
    private static final int MAX_DOMAIN_POWER = 24;

    // Montgomery R for Fp (base field) — for converting points from .zkey
    private static final BigInteger FP = MontFp381.modulus();
    private static final BigInteger FR = MontFr381.modulus();
    private static final BigInteger FP_R = BigInteger.ONE.shiftLeft(384).mod(FP);
    private static final BigInteger FP_R_INV = FP_R.modInverse(FP);

    // Montgomery R for Fr (scalar field) — for converting polynomial evaluations
    private static final BigInteger FR_R = BigInteger.ONE.shiftLeft(256).mod(FR);
    private static final BigInteger FR_R_INV = FR_R.modInverse(FR);

    /**
     * Import a PlonK proving key from a snarkjs PlonK .zkey file (BLS12-381).
     */
    public static PlonKProvingKeyBLS381 importZkey(InputStream input) throws IOException {
        return importZkey(input, null);
    }

    /**
     * Import a PlonK proving key from a snarkjs PlonK .zkey file (BLS12-381)
     * and require an exact SHA-256 content-hash match before parsing.
     *
     * @param expectedSha256 expected SHA-256 hash, or {@code null} for dev/test
     *                       callers that intentionally skip artifact pinning
     */
    public static PlonKProvingKeyBLS381 importZkey(InputStream input, byte[] expectedSha256) throws IOException {
        byte[] data = readBounded(input, ".zkey input");
        requireExpectedSha256(data, expectedSha256, ".zkey");
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (buf.remaining() < 12) {
            throw new IOException("Truncated .zkey header");
        }

        // Global header
        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, ZKEY_MAGIC))
            throw new IOException("Invalid .zkey magic");
        int version = buf.getInt();
        int numSections = buf.getInt();
        if (version <= 0) {
            throw new IOException("Invalid .zkey version: " + version);
        }
        if (numSections <= 0 || numSections > MAX_SECTIONS) {
            throw new IOException("Invalid .zkey section count: " + numSections);
        }

        // Read section directory
        Map<Integer, long[]> sections = new LinkedHashMap<>();
        for (int i = 0; i < numSections; i++) {
            requireRemaining(buf, 12, ".zkey section header");
            int stype = buf.getInt();
            long ssize = buf.getLong();
            if (sections.containsKey(stype)) {
                throw new IOException("Duplicate .zkey section: " + stype);
            }
            if (ssize < 0 || ssize > buf.remaining() || ssize > Integer.MAX_VALUE) {
                throw new IOException("Invalid .zkey section size for section " + stype);
            }
            sections.put(stype, new long[]{buf.position(), ssize});
            buf.position(buf.position() + (int) ssize);
        }
        for (int sectionId : new int[]{1, 2, 7, 8, 9, 10, 11, 12, 13, 14}) {
            requireSection(sections, sectionId);
        }

        // Section 1: Protocol (must be 2 for PlonK)
        buf.position((int) sections.get(1)[0]);
        requireSectionSize(sections, 1, 4);
        int protocol = buf.getInt();
        if (protocol != 2)
            throw new IOException("Not a PlonK .zkey (protocol=" + protocol + ")");

        // Section 2: Header
        buf.position((int) sections.get(2)[0]);
        requireSectionSize(sections, 2, 4 + 48 + 4 + 32 + 5 * 4L + 2 * 32L + 8 * 96L + 192L);
        int n8q = buf.getInt();
        if (n8q != 48) throw new IOException("Only BLS12-381 (n8q=48) supported");
        BigInteger q = readFieldLE(buf, n8q, FP, "BLS12-381 .zkey base-field prime");
        if (!FP.equals(q)) {
            throw new IOException("Wrong BLS12-381 .zkey base-field prime");
        }

        int n8r = buf.getInt();
        if (n8r != 32) throw new IOException("Only BLS12-381 (n8r=32) supported");
        BigInteger r = readFieldLE(buf, n8r, FR, "BLS12-381 .zkey scalar-field prime");
        if (!FR.equals(r)) {
            throw new IOException("Wrong BLS12-381 .zkey scalar-field prime");
        }

        int nVars = buf.getInt();
        int nPublic = buf.getInt();
        int domainSize = buf.getInt();
        int nAdditions = buf.getInt();
        int nConstraints = buf.getInt();
        validateHeaderDimensions(nVars, nPublic, domainSize, nAdditions, nConstraints);

        BigInteger k1 = readFieldLE(buf, n8r, r, "BLS12-381 k1").multiply(FR_R_INV).mod(r);
        BigInteger k2 = readFieldLE(buf, n8r, r, "BLS12-381 k2").multiply(FR_R_INV).mod(r);

        // Read committed selector/permutation points (8 G1 + 1 G2) from header
        AffineG1 qmCommit = readG1Mont(buf, n8q, q, true, "Qm");
        AffineG1 qlCommit = readG1Mont(buf, n8q, q, true, "Ql");
        AffineG1 qrCommit = readG1Mont(buf, n8q, q, true, "Qr");
        AffineG1 qoCommit = readG1Mont(buf, n8q, q, true, "Qo");
        AffineG1 qcCommit = readG1Mont(buf, n8q, q, true, "Qc");
        AffineG1 s1Commit = readG1Mont(buf, n8q, q, false, "S1");
        AffineG1 s2Commit = readG1Mont(buf, n8q, q, false, "S2");
        AffineG1 s3Commit = readG1Mont(buf, n8q, q, false, "S3");
        AffineG2 x2 = readG2Mont(buf, n8q, q, false, "X_2");

        // Section 7-11: Selector polynomial evaluations on the domain
        // Each section has domainSize * n8r bytes of Fr evaluations in Montgomery form
        // BUT: snarkjs stores these as buffers of size (domainSize * 5 * n8r) across sections
        // Actually looking at section sizes: section 7 has 1280 bytes = 40 Fr elements
        // With domainSize=8, that's 5*8 = 40, meaning each section has domainSize Fr evals
        // Wait, 1280 / 32 = 40 elements, but domainSize = 8... This is because snarkjs
        // stores the polynomial in evaluation form over a LARGER domain for the quotient computation

        MontFr381[] ql = readFrArrayMont(buf, sections, 7, n8r, r, domainSize);
        MontFr381[] qr = readFrArrayMont(buf, sections, 8, n8r, r, domainSize);
        MontFr381[] qm = readFrArrayMont(buf, sections, 9, n8r, r, domainSize);
        MontFr381[] qo = readFrArrayMont(buf, sections, 10, n8r, r, domainSize);
        MontFr381[] qc = readFrArrayMont(buf, sections, 11, n8r, r, domainSize);

        // Section 12: Sigma permutation evaluations (3 * domainSize Fr elements)
        buf.position((int) sections.get(12)[0]);
        if (sections.get(12)[1] % n8r != 0) {
            throw new IOException("Invalid BLS12-381 .zkey sigma section size");
        }
        int sigmaTotal = (int) (sections.get(12)[1] / n8r);
        if (sigmaTotal % 3 != 0) {
            throw new IOException("BLS12-381 .zkey sigma section is not divisible into 3 polynomials");
        }
        int sigmaPerPoly = sigmaTotal / 3;
        if (sigmaPerPoly < domainSize) {
            throw new IOException("BLS12-381 .zkey sigma section is too short");
        }
        // Read only domainSize elements per polynomial
        MontFr381[] s1Eval = new MontFr381[domainSize];
        MontFr381[] s2Eval = new MontFr381[domainSize];
        MontFr381[] s3Eval = new MontFr381[domainSize];
        buf.position((int) sections.get(12)[0]);
        for (int i = 0; i < domainSize; i++) s1Eval[i] = readFrMont(buf, n8r, r);
        // Skip to s2 start (skip remaining s1 entries beyond domainSize)
        buf.position((int) sections.get(12)[0] + sigmaPerPoly * n8r);
        for (int i = 0; i < domainSize; i++) s2Eval[i] = readFrMont(buf, n8r, r);
        buf.position((int) sections.get(12)[0] + 2 * sigmaPerPoly * n8r);
        for (int i = 0; i < domainSize; i++) s3Eval[i] = readFrMont(buf, n8r, r);

        // Section 13: Lagrange-basis SRS points
        buf.position((int) sections.get(13)[0]);
        if (sections.get(13)[1] % (2L * n8q) != 0) {
            throw new IOException("Invalid BLS12-381 .zkey Lagrange SRS section size");
        }
        int nLagrangeSRS = (int) (sections.get(13)[1] / (2 * n8q));
        if (nLagrangeSRS < domainSize) {
            throw new IOException("BLS12-381 .zkey Lagrange SRS is too short");
        }
        AffineG1[] srsG1Lagrange = readG1Array(buf, nLagrangeSRS, n8q, q, "lagrangeSrsG1");

        // Section 14: Powers-of-tau SRS points (monomial basis)
        buf.position((int) sections.get(14)[0]);
        if (sections.get(14)[1] % (2L * n8q) != 0) {
            throw new IOException("Invalid BLS12-381 .zkey monomial SRS section size");
        }
        int nPtauSRS = (int) (sections.get(14)[1] / (2 * n8q));
        if (nPtauSRS < 2 * domainSize) {
            throw new IOException("BLS12-381 .zkey monomial SRS is too short");
        }
        AffineG1[] srsG1 = readG1Array(buf, nPtauSRS, n8q, q, "monomialSrsG1");
        validateMonomialSrsConsistency(srsG1, x2, 2 * domainSize);

        // Compute omega (primitive domainSize-th root of unity)
        int logN = Integer.numberOfTrailingZeros(domainSize);
        MontFr381 omega = FieldFFTBLS381.rootOfUnity(logN);

        return new PlonKProvingKeyBLS381(
                domainSize, nPublic, nConstraints, k1, k2, omega,
                ql, qr, qm, qo, qc, s1Eval, s2Eval, s3Eval,
                srsG1, srsG1Lagrange, x2,
                qmCommit, qlCommit, qrCommit, qoCommit, qcCommit,
                s1Commit, s2Commit, s3Commit);
    }

    // --- Reading helpers ---

    private static MontFr381[] readFrArrayMont(ByteBuffer buf, Map<Integer, long[]> sections,
                                                int sectionId, int n8r, BigInteger rField, int count) throws IOException {
        if (sections.get(sectionId)[1] % n8r != 0 || sections.get(sectionId)[1] < (long) count * n8r) {
            throw new IOException("Invalid BLS12-381 .zkey Fr section size: " + sectionId);
        }
        buf.position((int) sections.get(sectionId)[0]);
        MontFr381[] result = new MontFr381[count];
        for (int i = 0; i < count; i++) {
            result[i] = readFrMont(buf, n8r, rField);
        }
        return result;
    }

    private static MontFr381 readFrMont(ByteBuffer buf, int n8r, BigInteger rField) throws IOException {
        BigInteger val = readFieldLE(buf, n8r, rField, "BLS12-381 Fr element");
        // Convert from Montgomery form
        BigInteger normal = val.multiply(FR_R_INV).mod(rField);
        return MontFr381.fromBigInteger(normal);
    }

    private static AffineG1 readG1Mont(ByteBuffer buf, int n8q, BigInteger q,
                                       boolean allowInfinity, String label) throws IOException {
        BigInteger x = readFieldLE(buf, n8q, q, label + " x").multiply(FP_R_INV).mod(q);
        BigInteger y = readFieldLE(buf, n8q, q, label + " y").multiply(FP_R_INV).mod(q);
        if (x.signum() == 0 && y.signum() == 0) {
            if (allowInfinity) return AffineG1.INFINITY;
            throw new IOException(label + " must not be infinity");
        }
        AffineG1 point = new AffineG1(MontFp381.fromBigInteger(x), MontFp381.fromBigInteger(y));
        if (!point.isOnCurve()) {
            throw new IOException(label + " is not on BLS12-381 G1");
        }
        G1Point subgroupPoint = new G1Point(Fp.of(point.xBigInt()), Fp.of(point.yBigInt()));
        if (!subgroupPoint.isValid()) {
            throw new IOException(label + " is not in BLS12-381 G1 subgroup");
        }
        return point;
    }

    private static AffineG2 readG2Mont(ByteBuffer buf, int n8q, BigInteger q,
                                       boolean allowInfinity, String label) throws IOException {
        BigInteger x0 = readFieldLE(buf, n8q, q, label + " x0").multiply(FP_R_INV).mod(q);
        BigInteger x1 = readFieldLE(buf, n8q, q, label + " x1").multiply(FP_R_INV).mod(q);
        BigInteger y0 = readFieldLE(buf, n8q, q, label + " y0").multiply(FP_R_INV).mod(q);
        BigInteger y1 = readFieldLE(buf, n8q, q, label + " y1").multiply(FP_R_INV).mod(q);
        if (x0.signum() == 0 && x1.signum() == 0 && y0.signum() == 0 && y1.signum() == 0) {
            if (allowInfinity) return AffineG2.INFINITY;
            throw new IOException(label + " must not be infinity");
        }
        AffineG2 point = new AffineG2(MontFp2_381.of(x0, x1), MontFp2_381.of(y0, y1));
        if (!point.isOnCurve()) {
            throw new IOException(label + " is not on BLS12-381 G2");
        }
        G2Point subgroupPoint = new G2Point(
                Fp2.of(Fp.of(point.x().reBigInt()), Fp.of(point.x().imBigInt())),
                Fp2.of(Fp.of(point.y().reBigInt()), Fp.of(point.y().imBigInt())));
        if (!subgroupPoint.isValid()) {
            throw new IOException(label + " is not in BLS12-381 G2 subgroup");
        }
        return point;
    }

    private static AffineG1[] readG1Array(ByteBuffer buf, int count, int n8q, BigInteger q,
                                          String label) throws IOException {
        AffineG1[] points = new AffineG1[count];
        for (int i = 0; i < count; i++) points[i] = readG1Mont(buf, n8q, q, false, label + "[" + i + "]");
        return points;
    }

    private static void validateMonomialSrsConsistency(AffineG1[] srsG1, AffineG2 x2, int count) throws IOException {
        if (!srsG1[0].equals(JacobianG1BLS381.GENERATOR.toAffine())) {
            throw new IOException("BLS12-381 .zkey monomial SRS G1 generator anchor mismatch");
        }
        G2Point g2 = toG2(JacobianG2BLS381.GENERATOR.toAffine());
        G2Point tauG2Point = toG2(x2);
        for (int i = 1; i < count; i++) {
            boolean consistent = BLS12381Pairing.pairingCheck(
                    new G1Point[]{toG1(srsG1[i]), toG1(srsG1[i - 1]).negate()},
                    new G2Point[]{g2, tauG2Point});
            if (!consistent) {
                throw new IOException("BLS12-381 .zkey monomial SRS powers are inconsistent at G1 index " + i);
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

    private static void validateHeaderDimensions(
            int nVars,
            int nPublic,
            int domainSize,
            int nAdditions,
            int nConstraints) throws IOException {
        if (nVars <= 0) {
            throw new IOException("Invalid BLS12-381 .zkey variable count");
        }
        if (domainSize < MIN_DOMAIN_SIZE || (domainSize & (domainSize - 1)) != 0) {
            throw new IOException("BLS12-381 .zkey domainSize must be a power of two >= " + MIN_DOMAIN_SIZE);
        }
        int logN = Integer.numberOfTrailingZeros(domainSize);
        if (logN > MAX_DOMAIN_POWER) {
            throw new IOException("BLS12-381 .zkey domainSize exceeds 2^" + MAX_DOMAIN_POWER);
        }
        if (nPublic < 0 || nPublic > domainSize) {
            throw new IOException("Invalid BLS12-381 .zkey public input count");
        }
        if (nAdditions < 0 || nConstraints < 0 || nConstraints > domainSize) {
            throw new IOException("Invalid BLS12-381 .zkey constraint dimensions");
        }
    }

    private static void requireSection(Map<Integer, long[]> sections, int sectionId) throws IOException {
        if (!sections.containsKey(sectionId)) {
            throw new IOException("Missing .zkey section: " + sectionId);
        }
    }

    private static void requireSectionSize(Map<Integer, long[]> sections, int sectionId, long minSize) throws IOException {
        if (sections.get(sectionId)[1] < minSize) {
            throw new IOException("Truncated .zkey section: " + sectionId);
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
            if (total > MAX_ZKEY_BYTES) {
                throw new IOException(label + " exceeds " + MAX_ZKEY_BYTES + " bytes");
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
