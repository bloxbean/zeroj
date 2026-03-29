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
        byte[] data = input.readAllBytes();
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
        int pos = buf.position();
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
        BigInteger r = readFieldElementLE(buf, n8r); // scalar field prime

        int nVars = buf.getInt();
        int nPublic = buf.getInt();
        int domainSize = buf.getInt();

        var alphaG1 = readG1Montgomery(buf, n8q, q);
        var betaG1 = readG1Montgomery(buf, n8q, q);
        var betaG2 = readG2Montgomery(buf, n8q, q);
        var gammaG2 = readG2Montgomery(buf, n8q, q); // not stored in proving key but read to advance
        var deltaG1 = readG1Montgomery(buf, n8q, q);
        var deltaG2 = readG2Montgomery(buf, n8q, q);

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

        return new Groth16ProvingKey(
                alphaG1, betaG1, betaG2, deltaG1, deltaG2,
                pointsA, pointsB1, pointsB2, pointsH, pointsL, nPublic);
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
}
