package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Binary cache for SRS and Groth16 setup results.
 * <p>
 * Serializes using raw Montgomery limbs (6 × long per Fp element) for maximum
 * speed and compactness. No BigInteger conversion is performed.
 * <p>
 * Format: "ZSC1" magic + version + content type + binary data.
 * <p>
 * Usage:
 * <pre>{@code
 * // Save
 * SetupCache.saveSrs(srs, Path.of("srs.bin"));
 * SetupCache.saveSetup(setupResult, Path.of("setup.bin"));
 *
 * // Load
 * var srs = SetupCache.loadSrs(Path.of("srs.bin"));
 * var setup = SetupCache.loadSetup(Path.of("setup.bin"));
 * }</pre>
 */
public final class SetupCache {

    private static final int MAGIC = 0x5A534331; // "ZSC1"
    private static final int VERSION = 1;
    private static final int TYPE_SRS = 0;
    private static final int TYPE_SETUP = 1;

    private SetupCache() {}

    // ========== SRS ==========

    public static void saveSrs(PtauImporterBLS381.SRS srs, Path path) throws IOException {
        Files.createDirectories(path.getParent());
        try (var out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(path.toFile())))) {
            out.writeInt(MAGIC);
            out.writeInt(VERSION);
            out.writeInt(TYPE_SRS);

            out.writeInt(srs.power());

            // tauG1
            out.writeInt(srs.tauG1().length);
            for (var p : srs.tauG1()) writeG1(out, p);

            // tauG2
            out.writeInt(srs.tauG2().length);
            for (var p : srs.tauG2()) writeG2(out, p);

            // tauScalar (optional)
            if (srs.tauScalar() != null) {
                out.writeBoolean(true);
                byte[] tau = srs.tauScalar().toByteArray();
                out.writeInt(tau.length);
                out.write(tau);
            } else {
                out.writeBoolean(false);
            }
        }
    }

    public static PtauImporterBLS381.SRS loadSrs(Path path) throws IOException {
        try (var in = new DataInputStream(new BufferedInputStream(new FileInputStream(path.toFile())))) {
            checkHeader(in, TYPE_SRS);

            int power = in.readInt();

            int g1Len = in.readInt();
            var tauG1 = new AffineG1[g1Len];
            for (int i = 0; i < g1Len; i++) tauG1[i] = readG1(in);

            int g2Len = in.readInt();
            var tauG2 = new AffineG2[g2Len];
            for (int i = 0; i < g2Len; i++) tauG2[i] = readG2(in);

            BigInteger tau = null;
            if (in.readBoolean()) {
                byte[] tauBytes = new byte[in.readInt()];
                in.readFully(tauBytes);
                tau = new BigInteger(tauBytes);
            }

            return new PtauImporterBLS381.SRS(tauG1, tauG2, power, tau);
        }
    }

    // ========== Groth16 Setup ==========

    public static void saveSetup(Groth16SetupBLS381.SetupResult setup, Path path) throws IOException {
        Files.createDirectories(path.getParent());
        try (var out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(path.toFile())))) {
            out.writeInt(MAGIC);
            out.writeInt(VERSION);
            out.writeInt(TYPE_SETUP);

            var pk = setup.provingKey();
            writeG1(out, pk.alphaG1());
            writeG1(out, pk.betaG1());
            writeG2(out, pk.betaG2());
            writeG1(out, pk.deltaG1());
            writeG2(out, pk.deltaG2());
            out.writeInt(pk.numPublic());

            writeG1Array(out, pk.pointsA());
            writeG1Array(out, pk.pointsB1());
            writeG2Array(out, pk.pointsB2());
            writeG1Array(out, pk.pointsH());
            writeG1Array(out, pk.pointsL());

            writeG2(out, setup.gammaG2());
            writeG1Array(out, setup.ic());
        }
    }

    public static Groth16SetupBLS381.SetupResult loadSetup(Path path) throws IOException {
        try (var in = new DataInputStream(new BufferedInputStream(new FileInputStream(path.toFile())))) {
            checkHeader(in, TYPE_SETUP);

            var alphaG1 = readG1(in);
            var betaG1 = readG1(in);
            var betaG2 = readG2(in);
            var deltaG1 = readG1(in);
            var deltaG2 = readG2(in);
            int numPublic = in.readInt();

            var pointsA = readG1Array(in);
            var pointsB1 = readG1Array(in);
            var pointsB2 = readG2Array(in);
            var pointsH = readG1Array(in);
            var pointsL = readG1Array(in);

            var gammaG2 = readG2(in);
            var ic = readG1Array(in);

            var pk = new Groth16ProvingKeyBLS381(
                    alphaG1, betaG1, betaG2, deltaG1, deltaG2,
                    pointsA, pointsB1, pointsB2, pointsH, pointsL, numPublic);

            return new Groth16SetupBLS381.SetupResult(pk, gammaG2, ic);
        }
    }

    // ========== Internal: point serialization ==========

    private static void writeG1(DataOutputStream out, AffineG1 p) throws IOException {
        writeFp(out, p.x());
        writeFp(out, p.y());
    }

    private static AffineG1 readG1(DataInputStream in) throws IOException {
        var x = readFp(in);
        var y = readFp(in);
        return new AffineG1(x, y);
    }

    private static void writeG2(DataOutputStream out, AffineG2 p) throws IOException {
        writeFp(out, p.x().re());
        writeFp(out, p.x().im());
        writeFp(out, p.y().re());
        writeFp(out, p.y().im());
    }

    private static AffineG2 readG2(DataInputStream in) throws IOException {
        var xRe = readFp(in);
        var xIm = readFp(in);
        var yRe = readFp(in);
        var yIm = readFp(in);
        return new AffineG2(new MontFp2_381(xRe, xIm), new MontFp2_381(yRe, yIm));
    }

    private static void writeFp(DataOutputStream out, MontFp381 fp) throws IOException {
        long[] limbs = fp.toLimbs();
        for (long l : limbs) out.writeLong(l);
    }

    private static MontFp381 readFp(DataInputStream in) throws IOException {
        return MontFp381.fromMontLimbs(
                in.readLong(), in.readLong(), in.readLong(),
                in.readLong(), in.readLong(), in.readLong());
    }

    private static void writeG1Array(DataOutputStream out, AffineG1[] arr) throws IOException {
        out.writeInt(arr.length);
        for (var p : arr) writeG1(out, p);
    }

    private static AffineG1[] readG1Array(DataInputStream in) throws IOException {
        int len = in.readInt();
        var arr = new AffineG1[len];
        for (int i = 0; i < len; i++) arr[i] = readG1(in);
        return arr;
    }

    private static void writeG2Array(DataOutputStream out, AffineG2[] arr) throws IOException {
        out.writeInt(arr.length);
        for (var p : arr) writeG2(out, p);
    }

    private static AffineG2[] readG2Array(DataInputStream in) throws IOException {
        int len = in.readInt();
        var arr = new AffineG2[len];
        for (int i = 0; i < len; i++) arr[i] = readG2(in);
        return arr;
    }

    private static void checkHeader(DataInputStream in, int expectedType) throws IOException {
        int magic = in.readInt();
        if (magic != MAGIC) throw new IOException("Invalid cache file (bad magic: " + Integer.toHexString(magic) + ")");
        int version = in.readInt();
        if (version != VERSION) throw new IOException("Unsupported cache version: " + version);
        int type = in.readInt();
        if (type != expectedType) throw new IOException("Wrong content type: expected " + expectedType + ", got " + type);
    }
}
