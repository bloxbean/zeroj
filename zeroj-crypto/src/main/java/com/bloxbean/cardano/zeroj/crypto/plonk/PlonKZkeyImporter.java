package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BN254.AffineG2;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp2_254;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFT;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * Imports PlonK proving keys from snarkjs PlonK .zkey binary format.
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
public final class PlonKZkeyImporter {

    private PlonKZkeyImporter() {}

    private static final byte[] ZKEY_MAGIC = {0x7a, 0x6b, 0x65, 0x79};

    // Montgomery R for Fp (base field) — for converting points from .zkey
    private static final BigInteger FP_R = BigInteger.ONE.shiftLeft(256).mod(MontFp254.modulus());
    private static final BigInteger FP_R_INV = FP_R.modInverse(MontFp254.modulus());

    // Montgomery R for Fr (scalar field) — for converting polynomial evaluations
    private static final BigInteger FR_R = BigInteger.ONE.shiftLeft(256).mod(MontFr254.modulus());
    private static final BigInteger FR_R_INV = FR_R.modInverse(MontFr254.modulus());

    /**
     * Import a PlonK proving key from a snarkjs PlonK .zkey file.
     */
    public static PlonKProvingKey importZkey(InputStream input) throws IOException {
        byte[] data = input.readAllBytes();
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        // Global header
        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, ZKEY_MAGIC))
            throw new IOException("Invalid .zkey magic");
        int version = buf.getInt();
        int numSections = buf.getInt();

        // Read section directory
        Map<Integer, long[]> sections = new LinkedHashMap<>();
        for (int i = 0; i < numSections; i++) {
            int stype = buf.getInt();
            long ssize = buf.getLong();
            sections.put(stype, new long[]{buf.position(), ssize});
            buf.position(buf.position() + (int) ssize);
        }

        // Section 1: Protocol (must be 2 for PlonK)
        buf.position((int) sections.get(1)[0]);
        int protocol = buf.getInt();
        if (protocol != 2)
            throw new IOException("Not a PlonK .zkey (protocol=" + protocol + ")");

        // Section 2: Header
        buf.position((int) sections.get(2)[0]);
        int n8q = buf.getInt();
        if (n8q != 32) throw new IOException("Only BN254 (n8q=32) supported");
        BigInteger q = readFieldLE(buf, n8q);

        int n8r = buf.getInt();
        BigInteger r = readFieldLE(buf, n8r);

        int nVars = buf.getInt();
        int nPublic = buf.getInt();
        int domainSize = buf.getInt();
        int nAdditions = buf.getInt();
        int nConstraints = buf.getInt();

        BigInteger k1 = readFieldLE(buf, n8r).multiply(FR_R_INV).mod(r);
        BigInteger k2 = readFieldLE(buf, n8r).multiply(FR_R_INV).mod(r);

        // Read committed selector/permutation points (8 G1 + 1 G2) from header
        AffineG1 qmCommit = readG1Mont(buf, n8q, q);
        AffineG1 qlCommit = readG1Mont(buf, n8q, q);
        AffineG1 qrCommit = readG1Mont(buf, n8q, q);
        AffineG1 qoCommit = readG1Mont(buf, n8q, q);
        AffineG1 qcCommit = readG1Mont(buf, n8q, q);
        AffineG1 s1Commit = readG1Mont(buf, n8q, q);
        AffineG1 s2Commit = readG1Mont(buf, n8q, q);
        AffineG1 s3Commit = readG1Mont(buf, n8q, q);
        AffineG2 x2 = readG2Mont(buf, n8q, q);

        // Section 7-11: Selector polynomial evaluations on the domain
        // Each section has domainSize * n8r bytes of Fr evaluations in Montgomery form
        // BUT: snarkjs stores these as buffers of size (domainSize * 5 * n8r) across sections
        // Actually looking at section sizes: section 7 has 1280 bytes = 40 Fr elements
        // With domainSize=8, that's 5*8 = 40, meaning each section has domainSize Fr evals
        // Wait, 1280 / 32 = 40 elements, but domainSize = 8... This is because snarkjs
        // stores the polynomial in evaluation form over a LARGER domain for the quotient computation

        MontFr254[] ql = readFrArrayMont(buf, sections, 7, n8r, r, domainSize);
        MontFr254[] qr = readFrArrayMont(buf, sections, 8, n8r, r, domainSize);
        MontFr254[] qm = readFrArrayMont(buf, sections, 9, n8r, r, domainSize);
        MontFr254[] qo = readFrArrayMont(buf, sections, 10, n8r, r, domainSize);
        MontFr254[] qc = readFrArrayMont(buf, sections, 11, n8r, r, domainSize);

        // Section 12: Sigma permutation evaluations (3 * domainSize Fr elements)
        buf.position((int) sections.get(12)[0]);
        int sigmaTotal = (int) (sections.get(12)[1] / n8r);
        int sigmaPerPoly = sigmaTotal / 3;
        // Read only domainSize elements per polynomial
        MontFr254[] s1Eval = new MontFr254[domainSize];
        MontFr254[] s2Eval = new MontFr254[domainSize];
        MontFr254[] s3Eval = new MontFr254[domainSize];
        buf.position((int) sections.get(12)[0]);
        for (int i = 0; i < domainSize; i++) s1Eval[i] = readFrMont(buf, n8r, r);
        // Skip to s2 start (skip remaining s1 entries beyond domainSize)
        buf.position((int) sections.get(12)[0] + sigmaPerPoly * n8r);
        for (int i = 0; i < domainSize; i++) s2Eval[i] = readFrMont(buf, n8r, r);
        buf.position((int) sections.get(12)[0] + 2 * sigmaPerPoly * n8r);
        for (int i = 0; i < domainSize; i++) s3Eval[i] = readFrMont(buf, n8r, r);

        // Section 13: Lagrange-basis SRS points
        buf.position((int) sections.get(13)[0]);
        int nLagrangeSRS = (int) (sections.get(13)[1] / (2 * n8q));
        AffineG1[] srsG1Lagrange = readG1Array(buf, nLagrangeSRS, n8q, q);

        // Section 14: Powers-of-tau SRS points (monomial basis)
        buf.position((int) sections.get(14)[0]);
        int nPtauSRS = (int) (sections.get(14)[1] / (2 * n8q));
        AffineG1[] srsG1 = readG1Array(buf, nPtauSRS, n8q, q);

        // Compute omega (primitive domainSize-th root of unity)
        int logN = Integer.numberOfTrailingZeros(domainSize);
        MontFr254 omega = FieldFFT.rootOfUnity(logN);

        return new PlonKProvingKey(
                domainSize, nPublic, nConstraints, k1, k2, omega,
                ql, qr, qm, qo, qc, s1Eval, s2Eval, s3Eval,
                srsG1, srsG1Lagrange, x2,
                qmCommit, qlCommit, qrCommit, qoCommit, qcCommit,
                s1Commit, s2Commit, s3Commit);
    }

    // --- Reading helpers ---

    private static MontFr254[] readFrArrayMont(ByteBuffer buf, Map<Integer, long[]> sections,
                                                int sectionId, int n8r, BigInteger rField, int count) {
        buf.position((int) sections.get(sectionId)[0]);
        MontFr254[] result = new MontFr254[count];
        for (int i = 0; i < count; i++) {
            result[i] = readFrMont(buf, n8r, rField);
        }
        return result;
    }

    private static MontFr254 readFrMont(ByteBuffer buf, int n8r, BigInteger rField) {
        BigInteger val = readFieldLE(buf, n8r);
        // Convert from Montgomery form
        BigInteger normal = val.multiply(FR_R_INV).mod(rField);
        return MontFr254.fromBigInteger(normal);
    }

    private static AffineG1 readG1Mont(ByteBuffer buf, int n8q, BigInteger q) {
        BigInteger x = readFieldLE(buf, n8q).multiply(FP_R_INV).mod(q);
        BigInteger y = readFieldLE(buf, n8q).multiply(FP_R_INV).mod(q);
        if (x.signum() == 0 && y.signum() == 0) return AffineG1.INFINITY;
        return new AffineG1(MontFp254.fromBigInteger(x), MontFp254.fromBigInteger(y));
    }

    private static AffineG2 readG2Mont(ByteBuffer buf, int n8q, BigInteger q) {
        BigInteger x0 = readFieldLE(buf, n8q).multiply(FP_R_INV).mod(q);
        BigInteger x1 = readFieldLE(buf, n8q).multiply(FP_R_INV).mod(q);
        BigInteger y0 = readFieldLE(buf, n8q).multiply(FP_R_INV).mod(q);
        BigInteger y1 = readFieldLE(buf, n8q).multiply(FP_R_INV).mod(q);
        if (x0.signum() == 0 && x1.signum() == 0 && y0.signum() == 0 && y1.signum() == 0)
            return AffineG2.INFINITY;
        return new AffineG2(MontFp2_254.of(x0, x1), MontFp2_254.of(y0, y1));
    }

    private static AffineG1[] readG1Array(ByteBuffer buf, int count, int n8q, BigInteger q) {
        AffineG1[] points = new AffineG1[count];
        for (int i = 0; i < count; i++) points[i] = readG1Mont(buf, n8q, q);
        return points;
    }

    private static BigInteger readFieldLE(ByteBuffer buf, int n8) {
        byte[] bytes = new byte[n8];
        buf.get(bytes);
        for (int i = 0; i < n8 / 2; i++) {
            byte tmp = bytes[i]; bytes[i] = bytes[n8 - 1 - i]; bytes[n8 - 1 - i] = tmp;
        }
        return new BigInteger(1, bytes);
    }
}
