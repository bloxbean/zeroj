package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

final class SetupCacheIO {
    static final int MAGIC = 0x5A534332; // "ZSC2"
    static final int VERSION = 2;
    static final int TYPE_BLS12381_SRS = 0;
    static final int TYPE_GROTH16_BLS12381_SETUP = 1;
    static final int TYPE_PLONK_BLS12381_PROVING_KEY = 2;
    static final int MAX_PLONK_DOMAIN_SIZE = 1 << 24;
    static final int MAX_CACHE_ARRAY_LENGTH = 1 << 25;
    static final int MAX_CACHE_PAYLOAD_BYTES = 256 * 1024 * 1024;
    private static final int SHA256_BYTES = 32;

    private SetupCacheIO() {
    }

    @FunctionalInterface
    interface PayloadWriter {
        void write(DataOutputStream out) throws IOException;
    }

    @FunctionalInterface
    interface PayloadReader<T> {
        T read(DataInputStream in) throws IOException;
    }

    static void writeCacheFile(Path path, int type, PayloadWriter writer) throws IOException {
        createParentDirectories(path);

        var payloadBuffer = new ByteArrayOutputStream();
        try (var payloadOut = new DataOutputStream(payloadBuffer)) {
            writer.write(payloadOut);
        }
        byte[] payload = payloadBuffer.toByteArray();
        if (payload.length > MAX_CACHE_PAYLOAD_BYTES) {
            throw new IOException("Cache payload exceeds supported limit: " + payload.length);
        }
        byte[] digest = sha256(payload);

        try (var out = new DataOutputStream(Files.newOutputStream(path))) {
            writeHeader(out, type);
            out.writeInt(payload.length);
            out.writeInt(digest.length);
            out.write(digest);
            out.write(payload);
        }
    }

    static <T> T readCacheFile(Path path, int expectedType, PayloadReader<T> reader) throws IOException {
        long size = Files.size(path);
        if (size > MAX_CACHE_PAYLOAD_BYTES + 64L) {
            throw new IOException("Cache file exceeds supported limit: " + size);
        }
        byte[] data = Files.readAllBytes(path);
        try (var in = new DataInputStream(new ByteArrayInputStream(data))) {
            checkHeader(in, expectedType);
            int payloadLength = readArrayLength(in, "cache payload", MAX_CACHE_PAYLOAD_BYTES);
            int digestLength = readArrayLength(in, "cache digest", SHA256_BYTES);
            if (digestLength != SHA256_BYTES) {
                throw new IOException("Unsupported cache digest length: " + digestLength);
            }
            byte[] expectedDigest = new byte[digestLength];
            in.readFully(expectedDigest);
            byte[] payload = new byte[payloadLength];
            in.readFully(payload);
            if (in.read() != -1) {
                throw new IOException("Cache file has trailing bytes");
            }
            byte[] actualDigest = sha256(payload);
            if (!MessageDigest.isEqual(expectedDigest, actualDigest)) {
                throw new IOException("Cache payload SHA-256 mismatch");
            }
            try (var payloadIn = new DataInputStream(new ByteArrayInputStream(payload))) {
                T result = reader.read(payloadIn);
                if (payloadIn.read() != -1) {
                    throw new IOException("Cache payload has trailing bytes");
                }
                return result;
            }
        }
    }

    private static void writeHeader(DataOutputStream out, int type) throws IOException {
        out.writeInt(MAGIC);
        out.writeInt(VERSION);
        out.writeInt(type);
    }

    private static void checkHeader(DataInputStream in, int expectedType) throws IOException {
        int magic = in.readInt();
        if (magic != MAGIC) {
            throw new IOException("Invalid cache file (bad magic: " + Integer.toHexString(magic) + ")");
        }
        int version = in.readInt();
        if (version != VERSION) {
            throw new IOException("Unsupported cache version: " + version);
        }
        int type = in.readInt();
        if (type != expectedType) {
            throw new IOException("Wrong content type: expected " + expectedType + ", got " + type);
        }
    }

    static void createParentDirectories(Path path) throws IOException {
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
    }

    static void writeG1(DataOutputStream out, AffineG1 p) throws IOException {
        validateG1(p, true, "G1 point");
        writeFp(out, p.x());
        writeFp(out, p.y());
    }

    static AffineG1 readG1(DataInputStream in) throws IOException {
        var x = readFp(in);
        var y = readFp(in);
        return new AffineG1(x, y);
    }

    static void writeG2(DataOutputStream out, AffineG2 p) throws IOException {
        validateG2(p, true, "G2 point");
        writeFp(out, p.x().re());
        writeFp(out, p.x().im());
        writeFp(out, p.y().re());
        writeFp(out, p.y().im());
    }

    static AffineG2 readG2(DataInputStream in) throws IOException {
        var xRe = readFp(in);
        var xIm = readFp(in);
        var yRe = readFp(in);
        var yIm = readFp(in);
        return new AffineG2(new MontFp2_381(xRe, xIm), new MontFp2_381(yRe, yIm));
    }

    static void writeG1Array(DataOutputStream out, AffineG1[] arr) throws IOException {
        out.writeInt(arr.length);
        for (var p : arr) {
            writeG1(out, p);
        }
    }

    static AffineG1[] readG1Array(DataInputStream in) throws IOException {
        int len = readArrayLength(in, "G1 array", MAX_CACHE_ARRAY_LENGTH);
        var arr = new AffineG1[len];
        for (int i = 0; i < len; i++) {
            arr[i] = readG1(in);
        }
        return arr;
    }

    static void writeG2Array(DataOutputStream out, AffineG2[] arr) throws IOException {
        out.writeInt(arr.length);
        for (var p : arr) {
            writeG2(out, p);
        }
    }

    static AffineG2[] readG2Array(DataInputStream in) throws IOException {
        int len = readArrayLength(in, "G2 array", MAX_CACHE_ARRAY_LENGTH);
        var arr = new AffineG2[len];
        for (int i = 0; i < len; i++) {
            arr[i] = readG2(in);
        }
        return arr;
    }

    static void writeFr(DataOutputStream out, MontFr381 value) throws IOException {
        writeScalar(out, value.toBigInteger(), "Fr");
    }

    static MontFr381 readFr(DataInputStream in) throws IOException {
        return MontFr381.fromBigInteger(readScalar(in, "Fr"));
    }

    static void writeFrArray(DataOutputStream out, MontFr381[] arr) throws IOException {
        out.writeInt(arr.length);
        for (var value : arr) {
            writeFr(out, value);
        }
    }

    static MontFr381[] readFrArray(DataInputStream in) throws IOException {
        int len = readArrayLength(in, "Fr array", MAX_CACHE_ARRAY_LENGTH);
        var arr = new MontFr381[len];
        for (int i = 0; i < len; i++) {
            arr[i] = readFr(in);
        }
        return arr;
    }

    static void writeScalar(DataOutputStream out, BigInteger value, String label) throws IOException {
        if (value == null || value.signum() < 0 || value.compareTo(MontFr381.modulus()) >= 0) {
            throw new IOException(label + " must be a canonical BLS12-381 scalar");
        }
        byte[] bytes = value.toByteArray();
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    static BigInteger readScalar(DataInputStream in, String label) throws IOException {
        int len = readArrayLength(in, label, 33);
        if (len == 0) {
            throw new IOException(label + " scalar must not be empty");
        }
        byte[] bytes = new byte[len];
        in.readFully(bytes);
        BigInteger value = new BigInteger(bytes);
        if (value.signum() < 0 || value.compareTo(MontFr381.modulus()) >= 0) {
            throw new IOException(label + " must be a canonical BLS12-381 scalar");
        }
        return value;
    }

    static int readArrayLength(DataInputStream in, String label, int max) throws IOException {
        int len = in.readInt();
        if (len < 0 || len > max) {
            throw new IOException("Invalid " + label + " length: " + len);
        }
        return len;
    }

    private static void writeFp(DataOutputStream out, MontFp381 fp) throws IOException {
        long[] limbs = fp.toLimbs();
        for (long limb : limbs) {
            out.writeLong(limb);
        }
    }

    private static MontFp381 readFp(DataInputStream in) throws IOException {
        try {
            return MontFp381.fromMontLimbs(
                    in.readLong(), in.readLong(), in.readLong(),
                    in.readLong(), in.readLong(), in.readLong());
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid canonical BLS12-381 Fp cache limb", e);
        }
    }

    static void validateG1(AffineG1 point, boolean allowInfinity, String label) throws IOException {
        if (point == null) {
            throw new IOException(label + " is null");
        }
        if (point.isInfinity()) {
            if (allowInfinity) return;
            throw new IOException(label + " must not be infinity");
        }
        if (!point.isOnCurve()) {
            throw new IOException(label + " is not on BLS12-381 G1");
        }
        if (!JacobianG1BLS381.fromAffine(point.x(), point.y()).scalarMul(G1Point.R).isInfinity()) {
            throw new IOException(label + " is not in BLS12-381 G1 subgroup");
        }
    }

    static void validateG2(AffineG2 point, boolean allowInfinity, String label) throws IOException {
        if (point == null) {
            throw new IOException(label + " is null");
        }
        if (point.isInfinity()) {
            if (allowInfinity) return;
            throw new IOException(label + " must not be infinity");
        }
        if (!point.isOnCurve()) {
            throw new IOException(label + " is not on BLS12-381 G2");
        }
        if (!JacobianG2BLS381.fromAffine(point.x(), point.y()).scalarMul(G1Point.R).isInfinity()) {
            throw new IOException(label + " is not in BLS12-381 G2 subgroup");
        }
    }

    static void validateG1Array(AffineG1[] points, boolean allowInfinity, String label) throws IOException {
        if (points == null) {
            throw new IOException(label + " is null");
        }
        for (int i = 0; i < points.length; i++) {
            validateG1(points[i], allowInfinity, label + "[" + i + "]");
        }
    }

    static void validateG2Array(AffineG2[] points, boolean allowInfinity, String label) throws IOException {
        if (points == null) {
            throw new IOException(label + " is null");
        }
        for (int i = 0; i < points.length; i++) {
            validateG2(points[i], allowInfinity, label + "[" + i + "]");
        }
    }

    static void validateBls12381Srs(AffineG1[] tauG1, AffineG2[] tauG2, int power) throws IOException {
        if (power < 1 || power > 32) {
            throw new IOException("Invalid BLS12-381 SRS power: " + power);
        }
        if (tauG1.length == 0) {
            throw new IOException("BLS12-381 SRS contains no G1 powers");
        }
        if (tauG2.length < 2) {
            throw new IOException("BLS12-381 SRS must contain at least two G2 powers");
        }
        validateG1Array(tauG1, false, "BLS12-381 SRS G1");
        validateG2Array(tauG2, false, "BLS12-381 SRS G2");
        if (!tauG1[0].equals(JacobianG1BLS381.GENERATOR.toAffine())) {
            throw new IOException("BLS12-381 SRS G1 generator anchor mismatch");
        }
        if (!tauG2[0].equals(JacobianG2BLS381.GENERATOR.toAffine())) {
            throw new IOException("BLS12-381 SRS G2 generator anchor mismatch");
        }
        G2Point g2 = toG2(tauG2[0]);
        G2Point tauG2Point = toG2(tauG2[1]);
        for (int i = 1; i < tauG1.length; i++) {
            boolean consistent = BLS12381Pairing.pairingCheck(
                    new G1Point[]{toG1(tauG1[i]), toG1(tauG1[i - 1]).negate()},
                    new G2Point[]{g2, tauG2Point});
            if (!consistent) {
                throw new IOException("BLS12-381 SRS powers are inconsistent at G1 index " + i);
            }
        }
    }

    static G1Point toG1(AffineG1 point) {
        if (point.isInfinity()) {
            return G1Point.INFINITY;
        }
        return new G1Point(Fp.of(point.xBigInt()), Fp.of(point.yBigInt()));
    }

    static G2Point toG2(AffineG2 point) {
        if (point.isInfinity()) {
            return G2Point.INFINITY;
        }
        return new G2Point(
                Fp2.of(Fp.of(point.x().reBigInt()), Fp.of(point.x().imBigInt())),
                Fp2.of(Fp.of(point.y().reBigInt()), Fp.of(point.y().imBigInt())));
    }

    private static byte[] sha256(byte[] payload) throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(payload);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is not available", e);
        }
    }
}
