package com.bloxbean.cardano.zeroj.circuit.r1cs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;

/**
 * Serializes an {@link R1CSConstraintSystem} to the iden3 {@code .r1cs} binary format.
 *
 * <p>This is the standard format consumed by snarkjs and rapidsnark. The format is
 * specified at <a href="https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md">iden3/r1csfile</a>.</p>
 */
public final class R1CSSerializer {

    private R1CSSerializer() {}

    private static final byte[] MAGIC = {0x72, 0x31, 0x63, 0x73}; // "r1cs"

    /**
     * Serialize to iden3 .r1cs binary format.
     */
    public static byte[] serialize(R1CSConstraintSystem r1cs) {
        int n8 = r1cs.fieldConfig().n8(); // field element byte size
        try {
            var out = new ByteArrayOutputStream();

            // Global header
            out.write(MAGIC);
            writeUint32LE(out, 1); // version
            writeUint32LE(out, 3); // numSections

            // Section 1: Header (type=2)
            byte[] headerSection = buildHeaderSection(r1cs, n8);
            writeUint32LE(out, 2); // sectionType = Header
            writeUint64LE(out, headerSection.length);
            out.write(headerSection);

            // Section 2: Constraints (type=1)
            byte[] constraintSection = buildConstraintSection(r1cs, n8);
            writeUint32LE(out, 1); // sectionType = Constraints
            writeUint64LE(out, constraintSection.length);
            out.write(constraintSection);

            // Section 3: Wire2Label (type=3)
            byte[] wire2labelSection = buildWire2LabelSection(r1cs);
            writeUint32LE(out, 3); // sectionType = Wire2Label
            writeUint64LE(out, wire2labelSection.length);
            out.write(wire2labelSection);

            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize R1CS", e);
        }
    }

    private static byte[] buildHeaderSection(R1CSConstraintSystem r1cs, int n8) throws IOException {
        var out = new ByteArrayOutputStream();
        writeUint32LE(out, n8); // field element size
        writeFieldElementLE(out, r1cs.prime(), n8); // prime
        writeUint32LE(out, r1cs.numWires()); // nWires
        writeUint32LE(out, 0); // nPubOut (public outputs — we treat all public vars as inputs for now)
        writeUint32LE(out, r1cs.numPublicInputs()); // nPubIn
        writeUint32LE(out, r1cs.numPrivateInputs()); // nPrvIn
        writeUint64LE(out, r1cs.numWires()); // nLabels
        writeUint32LE(out, r1cs.numConstraints()); // nConstraints
        return out.toByteArray();
    }

    private static byte[] buildConstraintSection(R1CSConstraintSystem r1cs, int n8) throws IOException {
        var out = new ByteArrayOutputStream();
        for (var constraint : r1cs.constraints()) {
            writeLinearCombination(out, constraint.a(), n8);
            writeLinearCombination(out, constraint.b(), n8);
            writeLinearCombination(out, constraint.c(), n8);
        }
        return out.toByteArray();
    }

    private static void writeLinearCombination(ByteArrayOutputStream out, Map<Integer, BigInteger> lc, int n8)
            throws IOException {
        // Filter out zero coefficients
        var nonZero = lc.entrySet().stream()
                .filter(e -> e.getValue().signum() != 0)
                .toList();
        writeUint32LE(out, nonZero.size());
        for (var entry : nonZero) {
            writeUint32LE(out, entry.getKey()); // wireId
            writeFieldElementLE(out, entry.getValue(), n8); // coefficient
        }
    }

    private static byte[] buildWire2LabelSection(R1CSConstraintSystem r1cs) throws IOException {
        var out = new ByteArrayOutputStream();
        // Simple 1:1 mapping: wire i → label i
        for (int i = 0; i < r1cs.numWires(); i++) {
            writeUint64LE(out, i);
        }
        return out.toByteArray();
    }

    private static void writeFieldElementLE(ByteArrayOutputStream out, BigInteger value, int n8) {
        byte[] beBytes = value.toByteArray();
        byte[] leBytes = new byte[n8];
        int srcLen = Math.min(beBytes.length, n8);
        for (int i = 0; i < srcLen; i++) {
            leBytes[i] = beBytes[beBytes.length - 1 - i];
        }
        out.writeBytes(leBytes);
    }

    private static void writeUint32LE(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 24) & 0xFF);
    }

    private static void writeUint64LE(ByteArrayOutputStream out, long value) {
        for (int i = 0; i < 8; i++) {
            out.write((int) ((value >> (i * 8)) & 0xFF));
        }
    }
}
