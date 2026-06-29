package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * Imports R1CS constraint systems from iden3 .r1cs binary format.
 *
 * <p>This is the standard format output by circom and consumed by snarkjs-compatible tooling.
 * The constraints parsed here are in the exact form used by the trusted setup,
 * ensuring compatibility with the .zkey proving key.</p>
 */
public final class R1CSImporter {

    private R1CSImporter() {}

    private static final byte[] R1CS_MAGIC = {0x72, 0x31, 0x63, 0x73}; // "r1cs"
    private static final int MAX_R1CS_BYTES = 256 * 1024 * 1024;
    private static final int MAX_SECTIONS = 64;
    private static final int MAX_FIELD_BYTES = 64;
    private static final int MAX_CONSTRAINTS = 1 << 24;
    private static final int MAX_WIRES = 1 << 24;
    private static final int MAX_TERMS_PER_LC = 1 << 20;
    private static final long MAX_TOTAL_TERMS = 1L << 26;

    /**
     * Parse an iden3 .r1cs binary file and extract R1CS constraints.
     */
    public static R1CSData importR1CS(InputStream input) throws IOException {
        byte[] data = readBounded(input, ".r1cs input");
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (buf.remaining() < 12) {
            throw new IOException("Truncated .r1cs header");
        }

        // Global header
        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, R1CS_MAGIC))
            throw new IOException("Invalid .r1cs magic");
        int version = buf.getInt();
        int numSections = buf.getInt();
        if (version <= 0) {
            throw new IOException("Invalid .r1cs version: " + version);
        }
        if (numSections <= 0 || numSections > MAX_SECTIONS) {
            throw new IOException("Invalid .r1cs section count: " + numSections);
        }

        // Read sections
        Map<Integer, long[]> sections = new LinkedHashMap<>();
        for (int i = 0; i < numSections; i++) {
            requireRemaining(buf, 12, ".r1cs section header");
            int stype = buf.getInt();
            long ssize = buf.getLong();
            if (sections.containsKey(stype)) {
                throw new IOException("Duplicate .r1cs section: " + stype);
            }
            if (ssize < 0 || ssize > buf.remaining() || ssize > Integer.MAX_VALUE) {
                throw new IOException("Invalid .r1cs section size for section " + stype);
            }
            sections.put(stype, new long[]{buf.position(), ssize});
            buf.position(buf.position() + (int) ssize);
        }
        requireSection(sections, 1);
        requireSection(sections, 2);

        // Section 1: Header
        buf.position((int) sections.get(1)[0]);
        requireRemainingInSection(buf, sections, 1, 4, ".r1cs field byte length");
        int n8 = buf.getInt();
        if (n8 <= 0 || n8 > MAX_FIELD_BYTES) {
            throw new IOException("Invalid .r1cs field byte length: " + n8);
        }
        requireRemainingInSection(buf, sections, 1, n8 + 28, ".r1cs header");
        BigInteger prime = readFieldElementLE(buf, n8, null, ".r1cs field prime");
        if (prime.signum() <= 0) {
            throw new IOException("Invalid .r1cs field prime");
        }

        int nWires = buf.getInt();
        int nPubOut = buf.getInt();
        int nPubIn = buf.getInt();
        int nPrvIn = buf.getInt();
        long nLabels = buf.getLong();
        int nConstraints = buf.getInt();
        validateHeader(nWires, nPubOut, nPubIn, nPrvIn, nLabels, nConstraints);
        int nPublic = checkedAdd(nPubOut, nPubIn, ".r1cs public input count");

        // Section 2: Constraints
        buf.position((int) sections.get(2)[0]);
        List<R1CSConstraint> constraints = new ArrayList<>(nConstraints);
        long totalTerms = 0;
        for (int i = 0; i < nConstraints; i++) {
            LcRead a = readLC(buf, n8, prime, nWires, "constraint[" + i + "].A");
            LcRead b = readLC(buf, n8, prime, nWires, "constraint[" + i + "].B");
            LcRead c = readLC(buf, n8, prime, nWires, "constraint[" + i + "].C");
            totalTerms += a.terms() + b.terms() + c.terms();
            if (totalTerms > MAX_TOTAL_TERMS) {
                throw new IOException(".r1cs has too many linear-combination terms");
            }
            constraints.add(new R1CSConstraint(a.termsMap(), b.termsMap(), c.termsMap()));
        }
        int section2End = (int) (sections.get(2)[0] + sections.get(2)[1]);
        if (buf.position() != section2End) {
            throw new IOException(".r1cs constraints section has trailing bytes");
        }

        return new R1CSData(prime, nWires, nPublic, nConstraints, constraints);
    }

    private static LcRead readLC(ByteBuffer buf, int n8, BigInteger prime, int nWires, String label) throws IOException {
        requireRemaining(buf, 4, label + " term count");
        int numTerms = buf.getInt();
        if (numTerms < 0 || numTerms > MAX_TERMS_PER_LC) {
            throw new IOException("Invalid " + label + " term count: " + numTerms);
        }
        Map<Integer, BigInteger> lc = new HashMap<>();
        for (int j = 0; j < numTerms; j++) {
            requireRemaining(buf, 4, label + " wire id");
            int wireId = buf.getInt();
            if (wireId < 0 || wireId >= nWires) {
                throw new IOException(label + " references invalid wire id: " + wireId);
            }
            BigInteger val = readFieldElementLE(buf, n8, prime, label + " value");
            if (val.signum() != 0) {
                lc.merge(wireId, val, (a, b) -> a.add(b).mod(prime));
            }
        }
        return new LcRead(lc, numTerms);
    }

    private static BigInteger readFieldElementLE(ByteBuffer buf, int n8, BigInteger modulus, String label)
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

    private static byte[] readBounded(InputStream input, String label) throws IOException {
        if (input == null) {
            throw new IOException(label + " must not be null");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > MAX_R1CS_BYTES) {
                throw new IOException(label + " exceeds supported size limit");
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static void validateHeader(int nWires, int nPubOut, int nPubIn, int nPrvIn,
                                       long nLabels, int nConstraints) throws IOException {
        if (nWires <= 0 || nWires > MAX_WIRES) {
            throw new IOException("Invalid .r1cs wire count: " + nWires);
        }
        if (nPubOut < 0 || nPubIn < 0 || nPrvIn < 0) {
            throw new IOException(".r1cs input counts must be non-negative");
        }
        int nPublic = checkedAdd(nPubOut, nPubIn, ".r1cs public input count");
        if (nPublic >= nWires) {
            throw new IOException(".r1cs public input count exceeds wire count");
        }
        if (nLabels < 0) {
            throw new IOException("Invalid .r1cs label count: " + nLabels);
        }
        if (nConstraints < 0 || nConstraints > MAX_CONSTRAINTS) {
            throw new IOException("Invalid .r1cs constraint count: " + nConstraints);
        }
    }

    private static int checkedAdd(int a, int b, String label) throws IOException {
        long sum = (long) a + b;
        if (sum > Integer.MAX_VALUE) {
            throw new IOException(label + " overflows int");
        }
        return (int) sum;
    }

    private static void requireSection(Map<Integer, long[]> sections, int sectionId) throws IOException {
        if (!sections.containsKey(sectionId)) {
            throw new IOException("Missing .r1cs section: " + sectionId);
        }
    }

    private static void requireRemainingInSection(ByteBuffer buf, Map<Integer, long[]> sections,
                                                  int sectionId, long needed, String label) throws IOException {
        long end = sections.get(sectionId)[0] + sections.get(sectionId)[1];
        if (needed < 0 || buf.position() + needed > end) {
            throw new IOException("Truncated " + label);
        }
    }

    private static void requireRemaining(ByteBuffer buf, int needed, String label) throws IOException {
        if (needed < 0 || buf.remaining() < needed) {
            throw new IOException("Truncated " + label);
        }
    }

    private record LcRead(Map<Integer, BigInteger> termsMap, int terms) {}

    /** Parsed R1CS data. */
    public record R1CSData(
            BigInteger prime,
            int numWires,
            int numPublic,
            int numConstraints,
            List<R1CSConstraint> constraints
    ) {}
}
