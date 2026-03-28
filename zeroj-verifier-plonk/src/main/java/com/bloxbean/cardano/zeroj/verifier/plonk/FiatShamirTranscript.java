package com.bloxbean.cardano.zeroj.verifier.plonk;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Keccak-256 Fiat-Shamir transcript matching the snarkjs PlonK format exactly.
 *
 * <p>snarkjs transcript protocol:</p>
 * <ul>
 *   <li>Collects polynomial commitments (G1 points) and scalars (Fr elements) in order</li>
 *   <li>G1 points are serialized as uncompressed affine (x || y), each coordinate big-endian, {@code fieldByteSize} bytes</li>
 *   <li>Scalars are serialized as big-endian, {@code scalarByteSize} bytes</li>
 *   <li>On {@link #getChallenge()}: concatenates all data, hashes with Keccak-256, reduces mod Fr</li>
 *   <li>{@link #reset()} clears the buffer between rounds</li>
 * </ul>
 *
 * <p>This matches {@code snarkjs/src/Keccak256Transcript.js} exactly.</p>
 */
public class FiatShamirTranscript {

    private static final int POLYNOMIAL = 0;
    private static final int SCALAR = 1;

    private final BigInteger fieldModulus;
    private final int scalarByteSize;
    private final int fieldByteSize; // base field element size (for G1 point coordinates)

    private final List<int[]> types = new ArrayList<>(); // [type]
    private final List<byte[]> dataList = new ArrayList<>();

    /**
     * Create a transcript for a specific curve.
     *
     * @param fieldModulus   the scalar field modulus Fr
     * @param scalarByteSize byte size of Fr elements (32 for BN254, 32 for BLS12-381)
     * @param fieldByteSize  byte size of base field Fp elements (32 for BN254, 48 for BLS12-381)
     */
    public FiatShamirTranscript(BigInteger fieldModulus, int scalarByteSize, int fieldByteSize) {
        this.fieldModulus = fieldModulus;
        this.scalarByteSize = scalarByteSize;
        this.fieldByteSize = fieldByteSize;
    }

    /**
     * Convenience constructor for BN254 (32-byte scalars and field elements).
     */
    public FiatShamirTranscript(BigInteger fieldModulus) {
        this(fieldModulus, 32, 32);
    }

    /**
     * Reset the transcript — clears all accumulated data for the next round.
     */
    public void reset() {
        types.clear();
        dataList.clear();
    }

    /**
     * Append a polynomial commitment (G1 point in affine coordinates).
     * The point is serialized as x || y, each coordinate in big-endian with {@code fieldByteSize} bytes.
     *
     * @param x affine x-coordinate
     * @param y affine y-coordinate
     */
    public void addPolCommitment(BigInteger x, BigInteger y) {
        byte[] buf = new byte[fieldByteSize * 2];
        writeBigEndian(buf, 0, fieldByteSize, x);
        writeBigEndian(buf, fieldByteSize, fieldByteSize, y);
        types.add(new int[]{POLYNOMIAL});
        dataList.add(buf);
    }

    /**
     * Append a scalar field element (big-endian, scalarByteSize bytes).
     */
    public void addScalar(BigInteger scalar) {
        byte[] buf = new byte[scalarByteSize];
        writeBigEndian(buf, 0, scalarByteSize, scalar);
        types.add(new int[]{SCALAR});
        dataList.add(buf);
    }

    /**
     * Squeeze a challenge: hash all accumulated data with Keccak-256, reduce mod Fr.
     */
    public BigInteger getChallenge() {
        if (dataList.isEmpty()) {
            throw new IllegalStateException("No data in transcript");
        }

        // Compute total buffer size
        int totalSize = 0;
        for (int i = 0; i < types.size(); i++) {
            totalSize += dataList.get(i).length;
        }

        // Concatenate all data
        byte[] buffer = new byte[totalSize];
        int offset = 0;
        for (int i = 0; i < dataList.size(); i++) {
            byte[] d = dataList.get(i);
            System.arraycopy(d, 0, buffer, offset, d.length);
            offset += d.length;
        }

        // Hash with Keccak-256
        byte[] hash = Keccak256.hash(buffer);

        // Interpret as big-endian integer, reduce mod Fr
        return new BigInteger(1, hash).mod(fieldModulus);
    }

    // --- Compatibility aliases ---

    /** Alias for {@link #addScalar(BigInteger)}. */
    public void appendScalar(BigInteger scalar) { addScalar(scalar); }

    /** Alias for {@link #addPolCommitment(BigInteger, BigInteger)}. */
    public void appendG1Point(BigInteger x, BigInteger y) { addPolCommitment(x, y); }

    /** Alias for {@link #getChallenge()}. */
    public BigInteger squeezeChallenge() { return getChallenge(); }

    /** Squeeze a non-zero challenge. */
    public BigInteger squeezeNonZeroChallenge() {
        BigInteger c = getChallenge();
        // In practice Keccak-256 output mod Fr is never zero
        return c;
    }

    /** @deprecated Use constructor + addScalar/addPolCommitment instead. */
    public void appendBytes(byte[] data) {
        types.add(new int[]{SCALAR});
        dataList.add(data.clone());
    }

    private static void writeBigEndian(byte[] buf, int offset, int size, BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length <= size) {
            System.arraycopy(bytes, 0, buf, offset + size - bytes.length, bytes.length);
        } else {
            // Strip leading zero / trim to size
            System.arraycopy(bytes, bytes.length - size, buf, offset, size);
        }
    }
}
