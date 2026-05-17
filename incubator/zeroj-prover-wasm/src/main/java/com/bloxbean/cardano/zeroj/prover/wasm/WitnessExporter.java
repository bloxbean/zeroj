package com.bloxbean.cardano.zeroj.prover.wasm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Exports witness values to standard formats (.wtns and gnark binary).
 *
 * <p>The .wtns format is the standard circom witness file format used by snarkjs-compatible tooling.</p>
 */
public final class WitnessExporter {

    private WitnessExporter() {}

    /** .wtns file magic bytes. */
    private static final byte[] WTNS_MAGIC = {0x77, 0x74, 0x6e, 0x73}; // "wtns"

    /**
     * Convert witness to .wtns binary format.
     *
     * <p>Format:
     * <pre>
     * Header:
     *   4 bytes  magic "wtns"
     *   4 bytes  version (uint32 LE) = 2
     *   4 bytes  numSections (uint32 LE) = 2
     *
     * Section 1 (Metadata):
     *   4 bytes  sectionId (uint32 LE) = 1
     *   8 bytes  sectionLength (uint64 LE)
     *   4 bytes  n8 (field element byte size, uint32 LE)
     *   n8 bytes field prime (little-endian)
     *   4 bytes  witnessSize (uint32 LE)
     *
     * Section 2 (Witness data):
     *   4 bytes  sectionId (uint32 LE) = 2
     *   8 bytes  sectionLength (uint64 LE) = witnessSize * n8
     *   witnessSize * n8 bytes  witness values (each n8 bytes, little-endian)
     * </pre>
     *
     * @param witness  the witness values
     * @param prime    the field prime
     * @param n32      number of 32-bit limbs per field element
     * @return .wtns binary bytes
     */
    public static byte[] toWtns(BigInteger[] witness, BigInteger prime, int n32) {
        int n8 = n32 * 4;
        try {
            var out = new ByteArrayOutputStream();

            // Header
            out.write(WTNS_MAGIC);
            writeUint32LE(out, 2);  // version
            writeUint32LE(out, 2);  // numSections

            // Section 1: Metadata
            writeUint32LE(out, 1);  // sectionId
            long section1Len = 4 + n8 + 4; // n8 field + prime bytes + witnessSize
            writeUint64LE(out, section1Len);
            writeUint32LE(out, n8); // field element byte size
            writeFieldElement(out, prime, n8); // prime in little-endian
            writeUint32LE(out, witness.length); // witness size

            // Section 2: Witness data
            writeUint32LE(out, 2);  // sectionId
            long section2Len = (long) witness.length * n8;
            writeUint64LE(out, section2Len);
            for (BigInteger w : witness) {
                writeFieldElement(out, w, n8);
            }

            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize witness", e);
        }
    }

    /**
     * Write .wtns to a file.
     */
    public static Path writeWtns(BigInteger[] witness, BigInteger prime, int n32, Path directory) throws IOException {
        byte[] wtnsBytes = toWtns(witness, prime, n32);
        Path path = directory.resolve("witness.wtns");
        Files.write(path, wtnsBytes);
        return path;
    }

    /**
     * Write a field element as n8 bytes in little-endian format.
     */
    private static void writeFieldElement(ByteArrayOutputStream out, BigInteger value, int n8) {
        byte[] beBytes = value.toByteArray();
        byte[] leBytes = new byte[n8];

        // BigInteger.toByteArray() is big-endian and may have a leading zero byte
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
