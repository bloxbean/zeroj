package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
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

    /**
     * Parse an iden3 .r1cs binary file and extract R1CS constraints.
     */
    public static R1CSData importR1CS(InputStream input) throws IOException {
        byte[] data = input.readAllBytes();
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        // Global header
        byte[] magic = new byte[4];
        buf.get(magic);
        if (!Arrays.equals(magic, R1CS_MAGIC))
            throw new IOException("Invalid .r1cs magic");
        int version = buf.getInt();
        int numSections = buf.getInt();

        // Read sections
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
        byte[] primeBytes = new byte[n8];
        buf.get(primeBytes);
        // LE to BE
        for (int i = 0; i < n8 / 2; i++) {
            byte tmp = primeBytes[i];
            primeBytes[i] = primeBytes[n8 - 1 - i];
            primeBytes[n8 - 1 - i] = tmp;
        }
        BigInteger prime = new BigInteger(1, primeBytes);

        int nWires = buf.getInt();
        int nPubOut = buf.getInt();
        int nPubIn = buf.getInt();
        int nPrvIn = buf.getInt();
        long nLabels = buf.getLong();
        int nConstraints = buf.getInt();

        // Section 2: Constraints
        buf.position((int) sections.get(2)[0]);
        List<R1CSConstraint> constraints = new ArrayList<>(nConstraints);
        for (int i = 0; i < nConstraints; i++) {
            var a = readLC(buf, n8);
            var b = readLC(buf, n8);
            var c = readLC(buf, n8);
            constraints.add(new R1CSConstraint(a, b, c));
        }

        return new R1CSData(prime, nWires, nPubOut + nPubIn, nConstraints, constraints);
    }

    private static Map<Integer, BigInteger> readLC(ByteBuffer buf, int n8) {
        int numTerms = buf.getInt();
        Map<Integer, BigInteger> lc = new HashMap<>();
        for (int j = 0; j < numTerms; j++) {
            int wireId = buf.getInt();
            byte[] valBytes = new byte[n8];
            buf.get(valBytes);
            // LE to BE
            for (int i = 0; i < n8 / 2; i++) {
                byte tmp = valBytes[i];
                valBytes[i] = valBytes[n8 - 1 - i];
                valBytes[n8 - 1 - i] = tmp;
            }
            BigInteger val = new BigInteger(1, valBytes);
            if (val.signum() != 0) lc.put(wireId, val);
        }
        return lc;
    }

    /** Parsed R1CS data. */
    public record R1CSData(
            BigInteger prime,
            int numWires,
            int numPublic,
            int numConstraints,
            List<R1CSConstraint> constraints
    ) {}
}
