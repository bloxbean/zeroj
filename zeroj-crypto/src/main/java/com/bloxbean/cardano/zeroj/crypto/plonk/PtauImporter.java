package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.api.LegacyCurvePolicy;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BN254.AffineG2;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp2_254;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * Imports SRS (Structured Reference String) from Powers of Tau .ptau files.
 *
 * <p>The .ptau format is the standard output of snarkjs Powers of Tau ceremony.
 * It contains tau^i * G1 and tau^i * G2 points needed for KZG commitments.</p>
 */
public final class PtauImporter {

    private PtauImporter() {}

    private static final byte[] PTAU_MAGIC = {0x70, 0x74, 0x61, 0x75}; // "ptau"
    private static final BigInteger FP = MontFp254.modulus();
    private static final BigInteger FP_R_INV = BigInteger.ONE.shiftLeft(256).mod(FP).modInverse(FP);

    /** Parsed SRS from a .ptau file. */
    public record SRS(
            AffineG1[] tauG1,    // [tau^0*G1, tau^1*G1, ..., tau^n*G1]
            AffineG2[] tauG2,    // [tau^0*G2, tau^1*G2]  (only first 2 needed for KZG)
            int power,            // log2 of ceremony size
            BigInteger tauScalar // tau as scalar (only available for dev/test generators, null for imported .ptau)
    ) {
        /** Construct without tau scalar (for imported .ptau files). */
        public SRS(AffineG1[] tauG1, AffineG2[] tauG2, int power) {
            this(tauG1, tauG2, power, null);
        }

        /** The SRS second point in G2: [tau]_2. */
        public AffineG2 x2() { return tauG2[1]; }
    }

    /**
     * Import SRS from a .ptau file.
     *
     * @param maxPoints maximum number of G1 points to load (for memory efficiency)
     */
    public static SRS importPtau(InputStream input, int maxPoints) throws IOException {
        LegacyCurvePolicy.requireLegacyBn254Enabled();
        byte[] data = input.readAllBytes();
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, PTAU_MAGIC))
            throw new IOException("Invalid .ptau magic");
        int version = buf.getInt();
        int numSections = buf.getInt();

        Map<Integer, long[]> sections = new LinkedHashMap<>();
        for (int i = 0; i < numSections; i++) {
            int stype = buf.getInt();
            long ssize = buf.getLong();
            sections.put(stype, new long[]{buf.position(), ssize});
            buf.position(buf.position() + (int) ssize);
        }

        // Section 1: Header
        buf.position((int) sections.get(1)[0]);
        int n8 = buf.getInt();
        readFieldLE(buf, n8); // prime (skip)
        int power = buf.getInt();

        // Section 2: tau^i * G1 (affine, LE, Montgomery)
        buf.position((int) sections.get(2)[0]);
        int availableG1 = (int) (sections.get(2)[1] / (2 * n8));
        int nG1 = Math.min(availableG1, maxPoints);
        AffineG1[] tauG1 = new AffineG1[nG1];
        for (int i = 0; i < nG1; i++) {
            tauG1[i] = readG1Mont(buf, n8);
        }

        // Section 3: tau^i * G2 (only need first 2: G2 and tau*G2)
        buf.position((int) sections.get(3)[0]);
        int nG2 = Math.min((int) (sections.get(3)[1] / (4 * n8)), 2);
        AffineG2[] tauG2 = new AffineG2[nG2];
        for (int i = 0; i < nG2; i++) {
            tauG2[i] = readG2Mont(buf, n8);
        }

        return new SRS(tauG1, tauG2, power);
    }

    /** Import with default max points. */
    public static SRS importPtau(InputStream input) throws IOException {
        return importPtau(input, Integer.MAX_VALUE);
    }

    private static AffineG1 readG1Mont(ByteBuffer buf, int n8) {
        BigInteger x = readFieldLE(buf, n8).multiply(FP_R_INV).mod(FP);
        BigInteger y = readFieldLE(buf, n8).multiply(FP_R_INV).mod(FP);
        if (x.signum() == 0 && y.signum() == 0) return AffineG1.INFINITY;
        return new AffineG1(MontFp254.fromBigInteger(x), MontFp254.fromBigInteger(y));
    }

    private static AffineG2 readG2Mont(ByteBuffer buf, int n8) {
        BigInteger x0 = readFieldLE(buf, n8).multiply(FP_R_INV).mod(FP);
        BigInteger x1 = readFieldLE(buf, n8).multiply(FP_R_INV).mod(FP);
        BigInteger y0 = readFieldLE(buf, n8).multiply(FP_R_INV).mod(FP);
        BigInteger y1 = readFieldLE(buf, n8).multiply(FP_R_INV).mod(FP);
        if (x0.signum() == 0 && x1.signum() == 0 && y0.signum() == 0 && y1.signum() == 0)
            return AffineG2.INFINITY;
        return new AffineG2(MontFp2_254.of(x0, x1), MontFp2_254.of(y0, y1));
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
