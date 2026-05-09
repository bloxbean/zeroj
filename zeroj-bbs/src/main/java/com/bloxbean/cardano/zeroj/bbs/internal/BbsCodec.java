package com.bloxbean.cardano.zeroj.bbs.internal;

import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Generators;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Draft-10 BBS octet serialization helpers.
 */
public final class BbsCodec {
    public static final BigInteger R = Bls12381Generators.SCALAR_FIELD_ORDER;

    private BbsCodec() {}

    public record SignatureParts(G1Point a, BigInteger e) {
        public SignatureParts {
            requireNonIdentity(a, "signature A");
            e = requireNonZeroScalar(e, "signature e");
        }
    }

    public record ProofParts(
            G1Point aBar,
            G1Point bBar,
            G1Point d,
            BigInteger eHat,
            BigInteger r1Hat,
            BigInteger r3Hat,
            List<BigInteger> mHats,
            BigInteger challenge
    ) {
        public ProofParts {
            requireNonIdentity(aBar, "proof Abar");
            requireNonIdentity(bBar, "proof Bbar");
            requireNonIdentity(d, "proof D");
            eHat = requireScalar(eHat, "proof eHat");
            r1Hat = requireScalar(r1Hat, "proof r1Hat");
            r3Hat = requireScalar(r3Hat, "proof r3Hat");
            mHats = List.copyOf(Objects.requireNonNull(mHats, "proof commitments required"));
            for (BigInteger mHat : mHats) {
                requireScalar(mHat, "proof hidden message commitment");
            }
            challenge = requireScalar(challenge, "proof challenge");
        }
    }

    public static byte[] scalarToBytes(BigInteger scalar) {
        return fixedBigEndian(requireNonZeroScalar(scalar, "scalar"), Bls12381Codecs.SCALAR_BYTES);
    }

    public static byte[] scalarToBytesAllowZero(BigInteger scalar) {
        return fixedBigEndian(requireScalar(scalar, "scalar"), Bls12381Codecs.SCALAR_BYTES);
    }

    public static BigInteger scalarFromBytes(byte[] bytes, String label) {
        requireLength(bytes, Bls12381Codecs.SCALAR_BYTES, label);
        BigInteger scalar = new BigInteger(1, bytes);
        if (scalar.compareTo(R) >= 0) {
            throw new IllegalArgumentException(label + " is outside BLS12-381 Fr");
        }
        return scalar;
    }

    public static BigInteger nonZeroScalarFromBytes(byte[] bytes, String label) {
        return requireNonZeroScalar(scalarFromBytes(bytes, label), label);
    }

    public static byte[] publicKeyToOctets(G2Point point) {
        requireNonIdentity(point, "public key");
        return Bls12381Codecs.g2ToCompressed(Bls12381Codecs.requireValid(point));
    }

    public static G2Point octetsToPublicKey(byte[] bytes) {
        requireLength(bytes, Bls12381Codecs.G2_COMPRESSED_BYTES, "public key");
        G2Point point = Bls12381Codecs.g2FromCompressed(bytes);
        if (point.isInfinity()) {
            throw new IllegalArgumentException("BBS public key must not be identity");
        }
        return point;
    }

    public static byte[] signatureToOctets(SignatureParts signature) {
        Objects.requireNonNull(signature, "signature required");
        return concat(
                Bls12381Codecs.g1ToCompressed(signature.a()),
                scalarToBytes(signature.e()));
    }

    public static SignatureParts octetsToSignature(byte[] bytes, BbsCiphersuite ciphersuite) {
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        requireLength(bytes, ciphersuite.g1Bytes() + ciphersuite.scalarBytes(), "signature");
        G1Point a = Bls12381Codecs.g1FromCompressed(Arrays.copyOfRange(bytes, 0, ciphersuite.g1Bytes()));
        if (a.isInfinity()) {
            throw new IllegalArgumentException("BBS signature A must not be identity");
        }
        BigInteger e = nonZeroScalarFromBytes(
                Arrays.copyOfRange(bytes, ciphersuite.g1Bytes(), bytes.length), "signature e");
        return new SignatureParts(a, e);
    }

    public static byte[] proofToOctets(ProofParts proof) {
        Objects.requireNonNull(proof, "proof required");
        List<byte[]> parts = new ArrayList<>();
        parts.add(Bls12381Codecs.g1ToCompressed(proof.aBar()));
        parts.add(Bls12381Codecs.g1ToCompressed(proof.bBar()));
        parts.add(Bls12381Codecs.g1ToCompressed(proof.d()));
        parts.add(scalarToBytesAllowZero(proof.eHat()));
        parts.add(scalarToBytesAllowZero(proof.r1Hat()));
        parts.add(scalarToBytesAllowZero(proof.r3Hat()));
        for (BigInteger mHat : proof.mHats()) {
            parts.add(scalarToBytesAllowZero(mHat));
        }
        parts.add(scalarToBytesAllowZero(proof.challenge()));
        return concat(parts.toArray(byte[][]::new));
    }

    public static ProofParts octetsToProof(byte[] bytes, BbsCiphersuite ciphersuite) {
        Objects.requireNonNull(bytes, "proof bytes required");
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        int floor = 3 * ciphersuite.g1Bytes() + 4 * ciphersuite.scalarBytes();
        if (bytes.length < floor) {
            throw new IllegalArgumentException("BBS proof must be at least " + floor + " bytes, got " + bytes.length);
        }
        int scalarBytesLen = bytes.length - 3 * ciphersuite.g1Bytes();
        if (scalarBytesLen % ciphersuite.scalarBytes() != 0) {
            throw new IllegalArgumentException("BBS proof scalar section is not aligned to 32-byte scalars");
        }
        int scalarCount = scalarBytesLen / ciphersuite.scalarBytes();
        if (scalarCount < 4) {
            throw new IllegalArgumentException("BBS proof must contain at least 4 scalars");
        }

        int offset = 0;
        G1Point aBar = readNonIdentityG1(bytes, offset, "proof Abar");
        offset += ciphersuite.g1Bytes();
        G1Point bBar = readNonIdentityG1(bytes, offset, "proof Bbar");
        offset += ciphersuite.g1Bytes();
        G1Point d = readNonIdentityG1(bytes, offset, "proof D");
        offset += ciphersuite.g1Bytes();

        List<BigInteger> scalars = new ArrayList<>(scalarCount);
        while (offset < bytes.length) {
            scalars.add(scalarFromBytes(Arrays.copyOfRange(bytes, offset, offset + ciphersuite.scalarBytes()),
                    "proof scalar"));
            offset += ciphersuite.scalarBytes();
        }

        List<BigInteger> commitments = scalarCount > 4
                ? scalars.subList(3, scalarCount - 1)
                : List.of();
        return new ProofParts(
                aBar,
                bBar,
                d,
                scalars.get(0),
                scalars.get(1),
                scalars.get(2),
                commitments,
                scalars.get(scalarCount - 1));
    }

    public static byte[] serialize(Object... values) {
        List<byte[]> parts = new ArrayList<>(values.length);
        for (Object value : values) {
            if (value instanceof G1Point point) {
                parts.add(Bls12381Codecs.g1ToCompressed(Bls12381Codecs.requireValid(point)));
            } else if (value instanceof G2Point point) {
                parts.add(Bls12381Codecs.g2ToCompressed(Bls12381Codecs.requireValid(point)));
            } else if (value instanceof BigInteger scalar) {
                parts.add(scalarToBytesAllowZero(scalar));
            } else if (value instanceof Integer integer) {
                parts.add(i2osp(integer.longValue(), 8));
            } else if (value instanceof Long longValue) {
                parts.add(i2osp(longValue, 8));
            } else if (value instanceof String string) {
                parts.add(string.getBytes(StandardCharsets.US_ASCII));
            } else {
                throw new IllegalArgumentException("Unsupported BBS serialization type: " + value);
            }
        }
        return concat(parts.toArray(byte[][]::new));
    }

    public static byte[] i2osp(long value, int length) {
        if (value < 0) {
            throw new IllegalArgumentException("I2OSP value must be non-negative");
        }
        if (length <= 0 || length > 8) {
            throw new IllegalArgumentException("I2OSP length must be between 1 and 8");
        }
        byte[] out = new byte[length];
        long v = value;
        for (int i = length - 1; i >= 0; i--) {
            out[i] = (byte) v;
            v >>>= 8;
        }
        if (v != 0) {
            throw new IllegalArgumentException("I2OSP value does not fit in " + length + " bytes");
        }
        return out;
    }

    public static byte[] concat(byte[]... chunks) {
        int len = 0;
        for (byte[] chunk : chunks) {
            len += chunk.length;
        }
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, out, offset, chunk.length);
            offset += chunk.length;
        }
        return out;
    }

    public static byte[] copy(byte[] bytes) {
        return bytes != null ? bytes.clone() : new byte[0];
    }

    public static List<byte[]> copyMessages(List<byte[]> messages) {
        Objects.requireNonNull(messages, "messages required");
        List<byte[]> copy = new ArrayList<>(messages.size());
        for (byte[] message : messages) {
            copy.add(copy(message));
        }
        return List.copyOf(copy);
    }

    static BigInteger requireScalar(BigInteger scalar, String label) {
        Objects.requireNonNull(scalar, label + " required");
        if (scalar.signum() < 0 || scalar.compareTo(R) >= 0) {
            throw new IllegalArgumentException(label + " must be in [0, r)");
        }
        return scalar;
    }

    static BigInteger requireNonZeroScalar(BigInteger scalar, String label) {
        requireScalar(scalar, label);
        if (scalar.signum() == 0) {
            throw new IllegalArgumentException(label + " must be non-zero");
        }
        return scalar;
    }

    static G1Point requireNonIdentity(G1Point point, String label) {
        Bls12381Codecs.requireValid(point);
        if (point.isInfinity()) {
            throw new IllegalArgumentException(label + " must not be identity");
        }
        return point;
    }

    static G2Point requireNonIdentity(G2Point point, String label) {
        Bls12381Codecs.requireValid(point);
        if (point.isInfinity()) {
            throw new IllegalArgumentException(label + " must not be identity");
        }
        return point;
    }

    private static G1Point readNonIdentityG1(byte[] bytes, int offset, String label) {
        G1Point point = Bls12381Codecs.g1FromCompressed(
                Arrays.copyOfRange(bytes, offset, offset + Bls12381Codecs.G1_COMPRESSED_BYTES));
        if (point.isInfinity()) {
            throw new IllegalArgumentException(label + " must not be identity");
        }
        return point;
    }

    private static void requireLength(byte[] bytes, int expected, String label) {
        Objects.requireNonNull(bytes, label + " bytes required");
        if (bytes.length != expected) {
            throw new IllegalArgumentException(label + " must be " + expected + " bytes, got " + bytes.length);
        }
    }

    private static byte[] fixedBigEndian(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        int rawStart = raw.length > 1 && raw[0] == 0 ? 1 : 0;
        int rawLen = raw.length - rawStart;
        if (rawLen > length) {
            throw new IllegalArgumentException("Value does not fit in " + length + " bytes");
        }
        byte[] out = new byte[length];
        System.arraycopy(raw, rawStart, out, length - rawLen, rawLen);
        return out;
    }
}
