package com.bloxbean.cardano.zeroj.crypto.transcript;

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
        writeBigEndian(buf, 0, fieldByteSize, x, "G1 x-coordinate");
        writeBigEndian(buf, fieldByteSize, fieldByteSize, y, "G1 y-coordinate");
        types.add(new int[]{POLYNOMIAL});
        dataList.add(buf);
    }

    /**
     * Append a scalar field element (big-endian, scalarByteSize bytes).
     */
    public void addScalar(BigInteger scalar) {
        if (scalar == null || scalar.signum() < 0 || scalar.compareTo(fieldModulus) >= 0) {
            throw new IllegalArgumentException("Scalar is outside the transcript field");
        }
        byte[] buf = new byte[scalarByteSize];
        writeBigEndian(buf, 0, scalarByteSize, scalar, "scalar");
        types.add(new int[]{SCALAR});
        dataList.add(buf);
    }

    /**
     * Append already-canonical transcript bytes.
     */
    public void addBytes(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Transcript bytes must not be null");
        }
        types.add(new int[]{SCALAR});
        dataList.add(data.clone());
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
    @Deprecated
    public void appendBytes(byte[] data) {
        addBytes(data);
    }

    private static void writeBigEndian(byte[] buf, int offset, int size, BigInteger value, String label) {
        if (value == null || value.signum() < 0) {
            throw new IllegalArgumentException(label + " must be a non-negative integer");
        }
        byte[] bytes = value.toByteArray();
        int sourceOffset = 0;
        int length = bytes.length;
        if (bytes.length == size + 1 && bytes[0] == 0) {
            sourceOffset = 1;
            length = size;
        }
        if (length > size) {
            throw new IllegalArgumentException(label + " exceeds fixed-width transcript encoding");
        }
        System.arraycopy(bytes, sourceOffset, buf, offset + size - length, length);
    }
}
