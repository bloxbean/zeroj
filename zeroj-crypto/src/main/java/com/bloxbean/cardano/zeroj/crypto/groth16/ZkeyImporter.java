package com.bloxbean.cardano.zeroj.crypto.groth16;

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

// Also provides .wtns witness file parsing

/**
 * Imports Groth16 proving keys from snarkjs .zkey binary format (iden3 binfile).
 *
 * <p>The .zkey format is the standard output of snarkjs Groth16 trusted setup:
 * {@code snarkjs groth16 setup circuit.r1cs pot_final.ptau circuit.zkey}</p>
 *
 * <h3>File layout</h3>
 * <pre>
 * [Global header: magic "zkey" + version + numSections]
 * [Section 1: Protocol ID (1 = Groth16)]
 * [Section 2: Header — primes, dimensions, alpha/beta/gamma/delta]
 * [Section 3: IC — public input commitments]
 * [Section 4: Coefficients — R1CS coefficient mappings]
 * [Section 5: A points in G1]
 * [Section 6: B points in G1]
 * [Section 7: B points in G2]
 * [Section 8: L (private wire) points in G1]
 * [Section 9: H (quotient polynomial) points in G1]
 * [Section 10: MPC contributions]
 * </pre>
 *
 * <p>Points are stored as affine coordinates in little-endian Montgomery form.
 * The importer converts from Montgomery to standard form during parsing.</p>
 */
public final class ZkeyImporter {

    private ZkeyImporter() {}

    private static final byte[] ZKEY_MAGIC = {0x7a, 0x6b, 0x65, 0x79}; // "zkey"
    private static final BigInteger FP_MONT_R;
    static {
        // R = 2^256 mod p (Montgomery R for BN254 Fq)
        FP_MONT_R = BigInteger.ONE.shiftLeft(256).mod(MontFp254.modulus());
    }
    private static final BigInteger FP_MONT_R_INV = FP_MONT_R.modInverse(MontFp254.modulus());

    /**
     * Import a Groth16 proving key from a snarkjs .zkey binary stream.
     *
     * @param input the .zkey file contents
     * @return parsed proving key ready for Groth16Prover
     * @throws IOException if the file format is invalid
     */
    public static Groth16ProvingKey importZkey(InputStream input) throws IOException {
        return importZkeyFull(input.readAllBytes()).provingKey();
    }

    /**
     * Import the complete .zkey data: proving key + R1CS constraints.
     * The constraints are needed for h(x) polynomial computation in the prover.
     */
    public static ZkeyData importZkeyFull(byte[] data) throws IOException {
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        // Global header
        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, ZKEY_MAGIC))
            throw new IOException("Invalid .zkey magic: expected 'zkey'");

        int version = buf.getInt();
        if (version != 1)
            throw new IOException("Unsupported .zkey version: " + version);

        int numSections = buf.getInt();

        // Read section directory: sectionType → (offset, size)
        Map<Integer, long[]> sections = new LinkedHashMap<>();
        for (int i = 0; i < numSections; i++) {
            int sectionType = buf.getInt();
            long sectionSize = buf.getLong();
            sections.put(sectionType, new long[]{buf.position(), sectionSize});
            buf.position(buf.position() + (int) sectionSize);
        }

        // Section 1: Protocol (must be Groth16 = 1)
        buf.position((int) sections.get(1)[0]);
        int protocol = buf.getInt();
        if (protocol != 1)
            throw new IOException("Not a Groth16 .zkey (protocol=" + protocol + ")");

        // Section 2: Header
        buf.position((int) sections.get(2)[0]);
        int n8q = buf.getInt();
        if (n8q != 32)
            throw new IOException("Only BN254 (n8q=32) supported, got " + n8q);
        BigInteger q = readFieldElementLE(buf, n8q); // base field prime

        int n8r = buf.getInt();
        BigInteger rField = readFieldElementLE(buf, n8r); // scalar field prime

        int nVars = buf.getInt();
        int nPublic = buf.getInt();
        int domainSize = buf.getInt();

        var alphaG1 = readG1Montgomery(buf, n8q, q);
        var betaG1 = readG1Montgomery(buf, n8q, q);
        var betaG2 = readG2Montgomery(buf, n8q, q);
        var gammaG2 = readG2Montgomery(buf, n8q, q); // read to advance position
        var deltaG1 = readG1Montgomery(buf, n8q, q);
        var deltaG2 = readG2Montgomery(buf, n8q, q);

        // On-curve validation for critical proving key points
        if (!alphaG1.isOnCurve())
            throw new IOException("alphaG1 is not on BN254 G1 curve — .zkey may be corrupted");
        if (!betaG1.isOnCurve())
            throw new IOException("betaG1 is not on BN254 G1 curve — .zkey may be corrupted");
        if (!betaG2.isOnCurve())
            throw new IOException("betaG2 is not on BN254 G2 twist curve — .zkey may be corrupted");
        if (!deltaG1.isOnCurve())
            throw new IOException("deltaG1 is not on BN254 G1 curve — .zkey may be corrupted");
        if (!deltaG2.isOnCurve())
            throw new IOException("deltaG2 is not on BN254 G2 twist curve — .zkey may be corrupted");

        // Section 4: Coefficients — reconstruct R1CS constraints
        // R^2 mod r (double Montgomery for coefficients)
        BigInteger FR_R = BigInteger.ONE.shiftLeft(256).mod(rField);
        BigInteger FR_R_INV = FR_R.modInverse(rField);
        // Coefficients are stored in R^2 Montgomery form
        BigInteger FR_R2_INV = FR_R_INV.multiply(FR_R_INV).mod(rField);

        buf.position((int) sections.get(4)[0]);
        int numCoeffs = buf.getInt();
        // Build constraints from coefficient entries
        // Each: matrix(u32), constraint(u32), signal(u32), value(n8r bytes, R^2 Montgomery)
        int numConstraints = domainSize; // snarkjs pads to domainSize
        Map<Integer, BigInteger>[] aMap = new Map[numConstraints];
        Map<Integer, BigInteger>[] bMap = new Map[numConstraints];
        Map<Integer, BigInteger>[] cMap = new Map[numConstraints];
        for (int i = 0; i < numConstraints; i++) {
            aMap[i] = new HashMap<>();
            bMap[i] = new HashMap<>();
            cMap[i] = new HashMap<>();
        }
        for (int i = 0; i < numCoeffs; i++) {
            int matrix = buf.getInt(); // 0=A, 1=B, 2=C
            int constraint = buf.getInt();
            int signal = buf.getInt();
            BigInteger valueMont = readFieldElementLE(buf, n8r);
            // Convert from R^2 Montgomery: value = valueMont * R^{-2} mod r
            BigInteger value = valueMont.multiply(FR_R2_INV).mod(rField);
            if (constraint < numConstraints && value.signum() != 0) {
                switch (matrix) {
                    case 0 -> aMap[constraint].merge(signal, value, (a, b) -> a.add(b).mod(rField));
                    case 1 -> bMap[constraint].merge(signal, value, (a, b) -> a.add(b).mod(rField));
                    case 2 -> cMap[constraint].merge(signal, value, (a, b) -> a.add(b).mod(rField));
                }
            }
        }
        // Find actual number of non-empty constraints
        int actualConstraints = 0;
        for (int i = 0; i < numConstraints; i++) {
            if (!aMap[i].isEmpty() || !bMap[i].isEmpty() || !cMap[i].isEmpty()) {
                actualConstraints = i + 1;
            }
        }
        var constraints = new Groth16Prover.R1CSConstraint[numConstraints];
        for (int i = 0; i < numConstraints; i++) {
            constraints[i] = new Groth16Prover.R1CSConstraint(aMap[i], bMap[i], cMap[i]);
        }

        // Section 5: A points in G1
        buf.position((int) sections.get(5)[0]);
        AffineG1[] pointsA = readG1Array(buf, nVars, n8q, q);

        // Section 6: B points in G1
        buf.position((int) sections.get(6)[0]);
        AffineG1[] pointsB1 = readG1Array(buf, nVars, n8q, q);

        // Section 7: B points in G2
        buf.position((int) sections.get(7)[0]);
        AffineG2[] pointsB2 = readG2Array(buf, nVars, n8q, q);

        // Section 8: L (C/private) points in G1
        int nPrivate = nVars - nPublic - 1;
        buf.position((int) sections.get(8)[0]);
        AffineG1[] pointsL = readG1Array(buf, nPrivate, n8q, q);

        // Section 9: H points in G1
        buf.position((int) sections.get(9)[0]);
        AffineG1[] pointsH = readG1Array(buf, domainSize, n8q, q);

        var pk = new Groth16ProvingKey(
                alphaG1, betaG1, betaG2, deltaG1, deltaG2,
                pointsA, pointsB1, pointsB2, pointsH, pointsL, nPublic);

        return new ZkeyData(pk, constraints, actualConstraints, nVars, domainSize);
    }

    // --- Point reading ---

    private static AffineG1 readG1Montgomery(ByteBuffer buf, int n8q, BigInteger q) {
        BigInteger x = fromMontgomery(readFieldElementLE(buf, n8q), q);
        BigInteger y = fromMontgomery(readFieldElementLE(buf, n8q), q);
        if (x.signum() == 0 && y.signum() == 0) return AffineG1.INFINITY;
        return new AffineG1(MontFp254.fromBigInteger(x), MontFp254.fromBigInteger(y));
    }

    private static AffineG2 readG2Montgomery(ByteBuffer buf, int n8q, BigInteger q) {
        BigInteger x0 = fromMontgomery(readFieldElementLE(buf, n8q), q);
        BigInteger x1 = fromMontgomery(readFieldElementLE(buf, n8q), q);
        BigInteger y0 = fromMontgomery(readFieldElementLE(buf, n8q), q);
        BigInteger y1 = fromMontgomery(readFieldElementLE(buf, n8q), q);
        if (x0.signum() == 0 && x1.signum() == 0 && y0.signum() == 0 && y1.signum() == 0)
            return AffineG2.INFINITY;
        return new AffineG2(
                MontFp2_254.of(x0, x1),
                MontFp2_254.of(y0, y1));
    }

    private static AffineG1[] readG1Array(ByteBuffer buf, int count, int n8q, BigInteger q) {
        var points = new AffineG1[count];
        for (int i = 0; i < count; i++) {
            points[i] = readG1Montgomery(buf, n8q, q);
        }
        return points;
    }

    private static AffineG2[] readG2Array(ByteBuffer buf, int count, int n8q, BigInteger q) {
        var points = new AffineG2[count];
        for (int i = 0; i < count; i++) {
            points[i] = readG2Montgomery(buf, n8q, q);
        }
        return points;
    }

    // --- Field element reading ---

    /** Read n8 bytes in little-endian as an unsigned BigInteger. */
    private static BigInteger readFieldElementLE(ByteBuffer buf, int n8) {
        byte[] bytes = new byte[n8];
        buf.get(bytes);
        // Reverse to big-endian for BigInteger
        for (int i = 0; i < n8 / 2; i++) {
            byte tmp = bytes[i];
            bytes[i] = bytes[n8 - 1 - i];
            bytes[n8 - 1 - i] = tmp;
        }
        return new BigInteger(1, bytes);
    }

    /** Convert from Montgomery form: value * R^{-1} mod q. */
    private static BigInteger fromMontgomery(BigInteger montValue, BigInteger q) {
        return montValue.multiply(FP_MONT_R_INV).mod(q);
    }

    // --- .wtns witness file parsing ---

    private static final byte[] WTNS_MAGIC = {0x77, 0x74, 0x6e, 0x73}; // "wtns"

    /**
     * Parse a snarkjs .wtns binary witness file.
     *
     * @param input the .wtns file contents
     * @return witness vector as BigInteger array
     */
    public static BigInteger[] importWtns(InputStream input) throws IOException {
        byte[] data = input.readAllBytes();
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        // Global header
        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, WTNS_MAGIC))
            throw new IOException("Invalid .wtns magic: expected 'wtns'");

        int version = buf.getInt();
        int numSections = buf.getInt();

        // Section 1: Header
        int sType = buf.getInt();
        long sSize = buf.getLong();
        int n8 = buf.getInt();
        BigInteger prime = readFieldElementLE(buf, n8);
        int nWitness = buf.getInt();

        // Section 2: Witness values
        sType = buf.getInt();
        sSize = buf.getLong();
        BigInteger[] witness = new BigInteger[nWitness];
        for (int i = 0; i < nWitness; i++) {
            witness[i] = readFieldElementLE(buf, n8);
        }
        return witness;
    }
}
