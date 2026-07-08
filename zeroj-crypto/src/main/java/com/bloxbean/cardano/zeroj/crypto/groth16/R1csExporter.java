package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Exports a ZeroJ R1CS constraint system to the iden3 {@code .r1cs} binary format (ADR-0031 M1) —
 * the format circom emits and snarkjs-compatible tooling consumes.
 *
 * <p>This is the bridge that lets a ZeroJ-authored circuit go through a standard <b>snarkjs Groth16
 * MPC ceremony</b>: export the R1CS, run {@code snarkjs groth16 setup} + {@code zkey contribute}
 * (phase 2), then import the final {@code .zkey} back with {@link ZkeyImporterBLS381} and prove
 * with ZeroJ as usual. Byte-exact inverse of {@link R1CSImporter}; the round trip is asserted in
 * tests, and a gated integration test drives real snarkjs over an exported file.</p>
 *
 * <p>Conventions (matching ZeroJ's wire layout): wire 0 is the constant ONE, wires
 * {@code 1..numPublic} are the public inputs — exported as {@code nPubOut=0, nPubIn=numPublic},
 * so snarkjs builds the IC over exactly the same wires the ZeroJ verifier/datum order uses.
 * Coefficients are written canonically (mod Fr, little-endian, 32 bytes — <em>not</em> Montgomery).</p>
 */
public final class R1csExporter {

    private R1csExporter() {}

    private static final byte[] R1CS_MAGIC = {0x72, 0x31, 0x63, 0x73}; // "r1cs"
    private static final int N8 = 32; // BLS12-381 Fr
    private static final BigInteger FR = MontFr381.modulus();

    /** Export to a file. */
    public static void export(List<R1CSConstraint> constraints, int numWires, int numPublic, Path path)
            throws IOException {
        try (OutputStream os = new BufferedOutputStream(Files.newOutputStream(path), 1 << 20)) {
            export(constraints, numWires, numPublic, os);
        }
    }

    /**
     * Export to a stream: global header + section 1 (header), section 2 (constraints),
     * section 3 (wire→label identity map).
     */
    public static void export(List<R1CSConstraint> constraints, int numWires, int numPublic, OutputStream os)
            throws IOException {
        if (numWires <= 0) throw new IllegalArgumentException("numWires must be positive");
        if (numPublic < 0 || numPublic >= numWires)
            throw new IllegalArgumentException("numPublic out of range: " + numPublic + " (wires " + numWires + ")");

        DataOutputStream out = new DataOutputStream(os);

        long headerSize = 4L + N8 + 4 + 4 + 4 + 4 + 8 + 4;
        long constraintsSize = constraintsSectionSize(constraints);
        long labelsSize = 8L * numWires;

        // global header
        out.write(R1CS_MAGIC);
        writeU32(out, 1); // version
        writeU32(out, 3); // sections

        // section 1: header
        writeU32(out, 1);
        writeU64(out, headerSize);
        writeU32(out, N8);
        writeFieldLE(out, FR);
        writeU32(out, numWires);
        writeU32(out, 0);                          // nPubOut (ZeroJ has no output/input split)
        writeU32(out, numPublic);                  // nPubIn
        writeU32(out, numWires - numPublic - 1);   // nPrvIn
        writeU64(out, numWires);                   // nLabels
        writeU32(out, constraints.size());

        // section 2: constraints
        writeU32(out, 2);
        writeU64(out, constraintsSize);
        for (R1CSConstraint c : constraints) {
            writeLc(out, c.a(), numWires);
            writeLc(out, c.b(), numWires);
            writeLc(out, c.c(), numWires);
        }

        // section 3: wire2label (identity)
        writeU32(out, 3);
        writeU64(out, labelsSize);
        for (int i = 0; i < numWires; i++) writeU64(out, i);

        out.flush();
    }

    private static long constraintsSectionSize(List<R1CSConstraint> constraints) {
        long size = 0;
        for (R1CSConstraint c : constraints) {
            size += 4L + (long) nonZeroTerms(c.a()) * (4 + N8);
            size += 4L + (long) nonZeroTerms(c.b()) * (4 + N8);
            size += 4L + (long) nonZeroTerms(c.c()) * (4 + N8);
        }
        return size;
    }

    private static int nonZeroTerms(Map<Integer, BigInteger> lc) {
        int n = 0;
        for (BigInteger v : lc.values()) if (v.mod(FR).signum() != 0) n++;
        return n;
    }

    private static void writeLc(DataOutputStream out, Map<Integer, BigInteger> lc, int numWires) throws IOException {
        // deterministic order (ascending wire id), canonical non-zero coefficients only
        TreeMap<Integer, BigInteger> sorted = new TreeMap<>();
        for (var e : lc.entrySet()) {
            int wire = e.getKey();
            if (wire < 0 || wire >= numWires)
                throw new IllegalArgumentException("LC references invalid wire id: " + wire);
            BigInteger v = e.getValue().mod(FR);
            if (v.signum() != 0) sorted.put(wire, v);
        }
        writeU32(out, sorted.size());
        for (var e : sorted.entrySet()) {
            writeU32(out, e.getKey());
            writeFieldLE(out, e.getValue());
        }
    }

    private static void writeFieldLE(DataOutputStream out, BigInteger value) throws IOException {
        byte[] be = value.toByteArray();
        byte[] le = new byte[N8];
        int start = (be.length > 0 && be[0] == 0) ? 1 : 0; // strip sign byte
        int len = be.length - start;
        if (len > N8) throw new IllegalArgumentException("field element exceeds " + N8 + " bytes");
        for (int i = 0; i < len; i++) le[i] = be[be.length - 1 - i];
        out.write(le);
    }

    private static void writeU32(DataOutputStream out, int v) throws IOException {
        out.write(v & 0xFF);
        out.write((v >>> 8) & 0xFF);
        out.write((v >>> 16) & 0xFF);
        out.write((v >>> 24) & 0xFF);
    }

    private static void writeU64(DataOutputStream out, long v) throws IOException {
        for (int i = 0; i < 8; i++) out.write((int) ((v >>> (8 * i)) & 0xFF));
    }
}
