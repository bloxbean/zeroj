package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Imports Groth16 proving keys from snarkjs .zkey binary format for BLS12-381.
 */
public final class ZkeyImporterBLS381 {

    private ZkeyImporterBLS381() {}

    private static final byte[] ZKEY_MAGIC = {0x7a, 0x6b, 0x65, 0x79}; // "zkey"
    private static final byte[] WTNS_MAGIC = {0x77, 0x74, 0x6e, 0x73}; // "wtns"

    private static final int MAX_ZKEY_BYTES = 128 * 1024 * 1024;
    private static final int MAX_WTNS_BYTES = 128 * 1024 * 1024;
    private static final int MAX_SECTIONS = 64;
    private static final int MIN_DOMAIN_SIZE = 4;
    private static final int MAX_DOMAIN_POWER = 24;
    private static final int MAX_WIRES = 1 << 24;
    private static final int MAX_COEFFICIENTS = 1 << 26;
    private static final int MAX_WITNESS_VALUES = 1 << 24;

    private static final BigInteger FP = MontFp381.modulus();
    private static final BigInteger FR = MontFr381.modulus();
    private static final BigInteger FP_R_INV = BigInteger.ONE.shiftLeft(384).mod(FP).modInverse(FP);
    private static final BigInteger FR_R = BigInteger.ONE.shiftLeft(256).mod(FR);
    private static final BigInteger FR_R_INV = FR_R.modInverse(FR);
    private static final BigInteger FR_R2_INV = FR_R_INV.multiply(FR_R_INV).mod(FR);

    public static Groth16ProvingKeyBLS381 importZkey(InputStream input) throws IOException {
        return importZkey(input, null);
    }

    /**
     * Import a BLS12-381 Groth16 proving key and require an exact SHA-256
     * content-hash match before parsing when {@code expectedSha256} is non-null.
     */
    public static Groth16ProvingKeyBLS381 importZkey(InputStream input, byte[] expectedSha256) throws IOException {
        return importZkeyFull(readBounded(input, MAX_ZKEY_BYTES, ".zkey input"), expectedSha256).provingKey();
    }

    public static ZkeyDataBLS381 importZkeyFull(byte[] data) throws IOException {
        return importZkeyFull(data, null);
    }

    public static ZkeyDataBLS381 importZkeyFull(byte[] data, byte[] expectedSha256) throws IOException {
        if (data == null) {
            throw new IOException(".zkey input must not be null");
        }
        if (data.length > MAX_ZKEY_BYTES) {
            throw new IOException(".zkey input exceeds supported size limit");
        }
        requireExpectedSha256(data, expectedSha256, ".zkey");

        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (buf.remaining() < 12) {
            throw new IOException("Truncated .zkey header");
        }

        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, ZKEY_MAGIC)) {
            throw new IOException("Invalid .zkey magic: expected 'zkey'");
        }
        int version = buf.getInt();
        int numSections = buf.getInt();
        if (version <= 0) {
            throw new IOException("Invalid .zkey version: " + version);
        }
        if (numSections <= 0 || numSections > MAX_SECTIONS) {
            throw new IOException("Invalid .zkey section count: " + numSections);
        }

        Map<Integer, long[]> sections = readSections(buf, numSections, ".zkey");
        for (int sectionId : new int[]{1, 2, 4, 5, 6, 7, 8, 9}) {
            requireSection(sections, sectionId, ".zkey");
        }

        buf.position((int) sections.get(1)[0]);
        requireSectionSize(sections, 1, 4, ".zkey");
        int protocol = buf.getInt();
        if (protocol != 1) {
            throw new IOException("Not a Groth16 .zkey (protocol=" + protocol + ")");
        }

        buf.position((int) sections.get(2)[0]);
        requireSectionSize(sections, 2, 4 + 48 + 4 + 32 + 3 * 4L + 3 * 96L + 3 * 192L, ".zkey");
        int n8q = buf.getInt();
        if (n8q != 48) {
            throw new IOException("Not a BLS12-381 .zkey (n8q=" + n8q + ", expected 48)");
        }
        BigInteger q = readFieldLE(buf, n8q, null, "BLS12-381 .zkey base-field prime");
        if (!FP.equals(q)) {
            throw new IOException("Wrong BLS12-381 .zkey base-field prime");
        }

        int n8r = buf.getInt();
        if (n8r != 32) {
            throw new IOException("Not a BLS12-381 .zkey (n8r=" + n8r + ", expected 32)");
        }
        BigInteger rField = readFieldLE(buf, n8r, null, "BLS12-381 .zkey scalar-field prime");
        if (!FR.equals(rField)) {
            throw new IOException("Wrong BLS12-381 .zkey scalar-field prime");
        }

        int nVars = buf.getInt();
        int nPublic = buf.getInt();
        int domainSize = buf.getInt();
        validateHeaderDimensions(nVars, nPublic, domainSize);

        var alphaG1 = readG1Montgomery(buf, n8q, q, false, "alphaG1");
        var betaG1 = readG1Montgomery(buf, n8q, q, false, "betaG1");
        var betaG2 = readG2Montgomery(buf, n8q, q, false, "betaG2");
        readG2Montgomery(buf, n8q, q, false, "gammaG2");
        var deltaG1 = readG1Montgomery(buf, n8q, q, false, "deltaG1");
        var deltaG2 = readG2Montgomery(buf, n8q, q, false, "deltaG2");

        buf.position((int) sections.get(4)[0]);
        requireRemaining(buf, 4, "Groth16 coefficient count");
        int numCoeffs = buf.getInt();
        validateCoefficientSection(sections, 4, numCoeffs, n8r);

        @SuppressWarnings("unchecked")
        Map<Integer, BigInteger>[] aMap = new Map[domainSize];
        @SuppressWarnings("unchecked")
        Map<Integer, BigInteger>[] bMap = new Map[domainSize];
        @SuppressWarnings("unchecked")
        Map<Integer, BigInteger>[] cMap = new Map[domainSize];
        for (int i = 0; i < domainSize; i++) {
            aMap[i] = new HashMap<>();
            bMap[i] = new HashMap<>();
            cMap[i] = new HashMap<>();
        }

        for (int i = 0; i < numCoeffs; i++) {
            requireRemaining(buf, 12 + n8r, "Groth16 coefficient entry");
            int matrix = buf.getInt();
            int constraint = buf.getInt();
            int signal = buf.getInt();
            if (matrix < 0 || matrix > 2) {
                throw new IOException("Invalid Groth16 coefficient matrix id: " + matrix);
            }
            if (constraint < 0 || constraint >= domainSize) {
                throw new IOException("Invalid Groth16 coefficient constraint index: " + constraint);
            }
            if (signal < 0 || signal >= nVars) {
                throw new IOException("Invalid Groth16 coefficient signal index: " + signal);
            }
            BigInteger valueMont = readFieldLE(buf, n8r, rField, "Groth16 coefficient");
            BigInteger value = valueMont.multiply(FR_R2_INV).mod(rField);
            if (value.signum() == 0) {
                continue;
            }
            switch (matrix) {
                case 0 -> aMap[constraint].merge(signal, value, (a, b) -> a.add(b).mod(rField));
                case 1 -> bMap[constraint].merge(signal, value, (a, b) -> a.add(b).mod(rField));
                case 2 -> cMap[constraint].merge(signal, value, (a, b) -> a.add(b).mod(rField));
                default -> throw new IOException("Invalid Groth16 coefficient matrix id: " + matrix);
            }
        }
        requireSectionConsumed(buf, sections, 4, ".zkey coefficient section");

        int actualConstraints = 0;
        List<R1CSConstraint> constraints = new ArrayList<>(domainSize);
        for (int i = 0; i < domainSize; i++) {
            if (!aMap[i].isEmpty() || !bMap[i].isEmpty() || !cMap[i].isEmpty()) {
                actualConstraints = i + 1;
            }
            constraints.add(new R1CSConstraint(aMap[i], bMap[i], cMap[i]));
        }

        AffineG1[] pointsA = readG1Section(buf, sections, 5, nVars, n8q, q, "pointsA");
        AffineG1[] pointsB1 = readG1Section(buf, sections, 6, nVars, n8q, q, "pointsB1");
        AffineG2[] pointsB2 = readG2Section(buf, sections, 7, nVars, n8q, q, "pointsB2");

        int nPrivate = nVars - nPublic - 1;
        AffineG1[] pointsL = readG1Section(buf, sections, 8, nPrivate, n8q, q, "pointsL");
        AffineG1[] pointsH = readG1Section(buf, sections, 9, domainSize, n8q, q, "pointsH");

        var pk = new Groth16ProvingKeyBLS381(
                alphaG1, betaG1, betaG2, deltaG1, deltaG2,
                Groth16ProvingKeyBLS381.flattenG1(pointsA), Groth16ProvingKeyBLS381.flattenG1(pointsB1),
                pointsB2, Groth16ProvingKeyBLS381.flattenG1(pointsH), Groth16ProvingKeyBLS381.flattenG1(pointsL),
                nPublic);

        return new ZkeyDataBLS381(pk, constraints, actualConstraints, nVars, domainSize);
    }

    public static BigInteger[] importWtns(InputStream input) throws IOException {
        byte[] data = readBounded(input, MAX_WTNS_BYTES, ".wtns input");
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (buf.remaining() < 12) {
            throw new IOException("Truncated .wtns header");
        }

        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, WTNS_MAGIC)) {
            throw new IOException("Invalid .wtns magic: expected 'wtns'");
        }
        int version = buf.getInt();
        int numSections = buf.getInt();
        if (version <= 0) {
            throw new IOException("Invalid .wtns version: " + version);
        }
        if (numSections <= 0 || numSections > MAX_SECTIONS) {
            throw new IOException("Invalid .wtns section count: " + numSections);
        }

        Map<Integer, long[]> sections = readSections(buf, numSections, ".wtns");
        requireSection(sections, 1, ".wtns");
        requireSection(sections, 2, ".wtns");

        buf.position((int) sections.get(1)[0]);
        requireSectionSize(sections, 1, 4 + 32 + 4, ".wtns");
        int n8 = buf.getInt();
        if (n8 != 32) {
            throw new IOException("Not a BLS12-381 witness (n8=" + n8 + ", expected 32)");
        }
        BigInteger prime = readFieldLE(buf, n8, null, "BLS12-381 witness field prime");
        if (!FR.equals(prime)) {
            throw new IOException("Wrong BLS12-381 witness scalar-field prime");
        }
        int nWitness = buf.getInt();
        if (nWitness < 0 || nWitness > MAX_WITNESS_VALUES) {
            throw new IOException("Invalid .wtns witness count: " + nWitness);
        }
        requireSectionConsumed(buf, sections, 1, ".wtns header section");

        long expectedWitnessBytes = (long) nWitness * n8;
        if (sections.get(2)[1] != expectedWitnessBytes) {
            throw new IOException("Invalid .wtns witness section size");
        }
        buf.position((int) sections.get(2)[0]);
        BigInteger[] witness = new BigInteger[nWitness];
        for (int i = 0; i < nWitness; i++) {
            witness[i] = readFieldLE(buf, n8, prime, "witness[" + i + "]");
        }
        requireSectionConsumed(buf, sections, 2, ".wtns witness section");
        return witness;
    }

    private static Map<Integer, long[]> readSections(ByteBuffer buf, int numSections, String fileType)
            throws IOException {
        Map<Integer, long[]> sections = new LinkedHashMap<>();
        for (int i = 0; i < numSections; i++) {
            requireRemaining(buf, 12, fileType + " section header");
            int sectionType = buf.getInt();
            long sectionSize = buf.getLong();
            if (sections.containsKey(sectionType)) {
                throw new IOException("Duplicate " + fileType + " section: " + sectionType);
            }
            if (sectionSize < 0 || sectionSize > buf.remaining() || sectionSize > Integer.MAX_VALUE) {
                throw new IOException("Invalid " + fileType + " section size for section " + sectionType);
            }
            sections.put(sectionType, new long[]{buf.position(), sectionSize});
            buf.position(buf.position() + (int) sectionSize);
        }
        return sections;
    }

    private static AffineG1[] readG1Section(ByteBuffer buf, Map<Integer, long[]> sections,
                                            int sectionId, int count, int n8q, BigInteger q,
                                            String label) throws IOException {
        long expectedSize = (long) count * 2L * n8q;
        if (sections.get(sectionId)[1] != expectedSize) {
            throw new IOException("Invalid BLS12-381 .zkey " + label + " section size");
        }
        buf.position((int) sections.get(sectionId)[0]);
        AffineG1[] points = new AffineG1[count];
        for (int i = 0; i < count; i++) {
            points[i] = readG1Montgomery(buf, n8q, q, true, label + "[" + i + "]");
        }
        requireSectionConsumed(buf, sections, sectionId, label + " section");
        return points;
    }

    private static AffineG2[] readG2Section(ByteBuffer buf, Map<Integer, long[]> sections,
                                            int sectionId, int count, int n8q, BigInteger q,
                                            String label) throws IOException {
        long expectedSize = (long) count * 4L * n8q;
        if (sections.get(sectionId)[1] != expectedSize) {
            throw new IOException("Invalid BLS12-381 .zkey " + label + " section size");
        }
        buf.position((int) sections.get(sectionId)[0]);
        AffineG2[] points = new AffineG2[count];
        for (int i = 0; i < count; i++) {
            points[i] = readG2Montgomery(buf, n8q, q, true, label + "[" + i + "]");
        }
        requireSectionConsumed(buf, sections, sectionId, label + " section");
        return points;
    }

    private static AffineG1 readG1Montgomery(ByteBuffer buf, int n8q, BigInteger q,
                                             boolean allowInfinity, String label) throws IOException {
        BigInteger x = readFieldLE(buf, n8q, q, label + " x").multiply(FP_R_INV).mod(q);
        BigInteger y = readFieldLE(buf, n8q, q, label + " y").multiply(FP_R_INV).mod(q);
        if (x.signum() == 0 && y.signum() == 0) {
            if (allowInfinity) {
                return AffineG1.INFINITY;
            }
            throw new IOException(label + " must not be infinity");
        }
        AffineG1 point = new AffineG1(MontFp381.fromBigInteger(x), MontFp381.fromBigInteger(y));
        if (!point.isOnCurve()) {
            throw new IOException(label + " is not on BLS12-381 G1");
        }
        if (!toG1(point).isValid()) {
            throw new IOException(label + " is not in BLS12-381 G1 subgroup");
        }
        return point;
    }

    private static AffineG2 readG2Montgomery(ByteBuffer buf, int n8q, BigInteger q,
                                             boolean allowInfinity, String label) throws IOException {
        BigInteger x0 = readFieldLE(buf, n8q, q, label + " x0").multiply(FP_R_INV).mod(q);
        BigInteger x1 = readFieldLE(buf, n8q, q, label + " x1").multiply(FP_R_INV).mod(q);
        BigInteger y0 = readFieldLE(buf, n8q, q, label + " y0").multiply(FP_R_INV).mod(q);
        BigInteger y1 = readFieldLE(buf, n8q, q, label + " y1").multiply(FP_R_INV).mod(q);
        if (x0.signum() == 0 && x1.signum() == 0 && y0.signum() == 0 && y1.signum() == 0) {
            if (allowInfinity) {
                return AffineG2.INFINITY;
            }
            throw new IOException(label + " must not be infinity");
        }
        AffineG2 point = new AffineG2(MontFp2_381.of(x0, x1), MontFp2_381.of(y0, y1));
        if (!point.isOnCurve()) {
            throw new IOException(label + " is not on BLS12-381 G2");
        }
        if (!toG2(point).isValid()) {
            throw new IOException(label + " is not in BLS12-381 G2 subgroup");
        }
        return point;
    }

    private static BigInteger readFieldLE(ByteBuffer buf, int n8, BigInteger modulus, String label)
            throws IOException {
        requireRemaining(buf, n8, label);
        byte[] bytes = new byte[n8];
        buf.get(bytes);
        for (int i = 0; i < n8 / 2; i++) {
            byte tmp = bytes[i];
            bytes[i] = bytes[n8 - 1 - i];
            bytes[n8 - 1 - i] = tmp;
        }
        BigInteger value = new BigInteger(1, bytes);
        if (modulus != null && value.compareTo(modulus) >= 0) {
            throw new IOException(label + " is not canonical");
        }
        return value;
    }

    private static void validateHeaderDimensions(int nVars, int nPublic, int domainSize) throws IOException {
        if (nVars <= 1 || nVars > MAX_WIRES) {
            throw new IOException("Invalid BLS12-381 .zkey variable count: " + nVars);
        }
        if (nPublic < 0 || nPublic >= nVars) {
            throw new IOException("Invalid BLS12-381 .zkey public input count: " + nPublic);
        }
        if (domainSize < MIN_DOMAIN_SIZE || Integer.bitCount(domainSize) != 1) {
            throw new IOException("Invalid BLS12-381 .zkey domain size: " + domainSize);
        }
        if (Integer.numberOfTrailingZeros(domainSize) > MAX_DOMAIN_POWER) {
            throw new IOException("BLS12-381 .zkey domain size exceeds supported limit: " + domainSize);
        }
    }

    private static void validateCoefficientSection(Map<Integer, long[]> sections, int sectionId,
                                                   int numCoeffs, int n8r) throws IOException {
        if (numCoeffs < 0 || numCoeffs > MAX_COEFFICIENTS) {
            throw new IOException("Invalid Groth16 coefficient count: " + numCoeffs);
        }
        long expectedSize = 4L + (long) numCoeffs * (12L + n8r);
        if (sections.get(sectionId)[1] != expectedSize) {
            throw new IOException("Invalid Groth16 coefficient section size");
        }
    }

    private static byte[] readBounded(InputStream input, int maxBytes, String label) throws IOException {
        if (input == null) {
            throw new IOException(label + " must not be null");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > maxBytes) {
                throw new IOException(label + " exceeds supported size limit");
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
            throw new IOException(label + " expected SHA-256 must be 32 bytes");
        }
        byte[] actual;
        try {
            actual = MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is not available", e);
        }
        if (!MessageDigest.isEqual(actual, expectedSha256)) {
            throw new IOException(label + " SHA-256 mismatch");
        }
    }

    private static void requireSection(Map<Integer, long[]> sections, int sectionId, String fileType)
            throws IOException {
        if (!sections.containsKey(sectionId)) {
            throw new IOException("Missing " + fileType + " section: " + sectionId);
        }
    }

    private static void requireSectionSize(Map<Integer, long[]> sections, int sectionId, long minimumSize,
                                           String fileType) throws IOException {
        long size = sections.get(sectionId)[1];
        if (size < minimumSize || size > Integer.MAX_VALUE) {
            throw new IOException("Invalid " + fileType + " section size: " + sectionId);
        }
    }

    private static void requireSectionConsumed(ByteBuffer buf, Map<Integer, long[]> sections,
                                               int sectionId, String label) throws IOException {
        int end = (int) (sections.get(sectionId)[0] + sections.get(sectionId)[1]);
        if (buf.position() != end) {
            throw new IOException(label + " has trailing bytes");
        }
    }

    private static void requireRemaining(ByteBuffer buf, int needed, String label) throws IOException {
        if (needed < 0 || buf.remaining() < needed) {
            throw new IOException("Truncated " + label);
        }
    }

    private static G1Point toG1(AffineG1 point) {
        if (point.isInfinity()) {
            return G1Point.INFINITY;
        }
        return new G1Point(Fp.of(point.xBigInt()), Fp.of(point.yBigInt()));
    }

    private static G2Point toG2(AffineG2 point) {
        if (point.isInfinity()) {
            return G2Point.INFINITY;
        }
        return new G2Point(
                Fp2.of(Fp.of(point.x().reBigInt()), Fp.of(point.x().imBigInt())),
                Fp2.of(Fp.of(point.y().reBigInt()), Fp.of(point.y().imBigInt())));
    }
}
