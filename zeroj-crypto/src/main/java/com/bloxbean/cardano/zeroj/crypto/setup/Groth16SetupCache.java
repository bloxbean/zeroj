package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Binary cache for BLS12-381 Groth16 circuit-specific setup artifacts.
 *
 * <p>Groth16 uses two setup layers:</p>
 * <ul>
 *   <li>the common BLS12-381 Powers of Tau / SRS artifact, reusable across
 *       compatible circuits up to its supported size; and</li>
 *   <li>the Groth16 phase-2 setup result, specific to one circuit shape and
 *       public-input profile.</li>
 * </ul>
 *
 * <p>If the circuit changes, generate a new Groth16 setup instead of reusing the
 * old phase-2 cache entry.</p>
 */
public final class Groth16SetupCache {
    private Groth16SetupCache() {
    }

    /**
     * Save a BLS12-381 Powers of Tau / SRS artifact for Groth16 phase-1 reuse.
     */
    public static void saveBls12381Srs(PtauImporterBLS381.SRS srs, Path path) throws IOException {
        SrsCache.saveBls12381Srs(srs, path);
    }

    /**
     * Save a development-only SRS cache that includes the toxic tau scalar.
     *
     * <p>This method is only for local single-party setup workflows and requires
     * {@code -Dzeroj.allowInsecureTrustedSetup=true}. Do not use this for production
     * ceremony artifacts.</p>
     */
    public static void saveBls12381InsecureDevSrsWithTau(PtauImporterBLS381.SRS srs, Path path) throws IOException {
        SrsCache.saveBls12381InsecureDevSrsWithTau(srs, path);
    }

    /**
     * Load a BLS12-381 Powers of Tau / SRS artifact for Groth16 phase-1 reuse.
     */
    public static PtauImporterBLS381.SRS loadBls12381Srs(Path path) throws IOException {
        return SrsCache.loadBls12381Srs(path);
    }

    /**
     * Save a BLS12-381 Groth16 circuit-specific setup result.
     */
    public static void saveBls12381Setup(Groth16SetupBLS381.SetupResult setup, Path path) throws IOException {
        validateGroth16Setup(setup);
        SetupCacheIO.writeCacheFile(path, SetupCacheIO.TYPE_GROTH16_BLS12381_SETUP, out -> {
            var pk = setup.provingKey();
            SetupCacheIO.writeG1(out, pk.alphaG1());
            SetupCacheIO.writeG1(out, pk.betaG1());
            SetupCacheIO.writeG2(out, pk.betaG2());
            SetupCacheIO.writeG1(out, pk.deltaG1());
            SetupCacheIO.writeG2(out, pk.deltaG2());
            out.writeInt(pk.numPublic());

            SetupCacheIO.writeG1Array(out, pk.pointsA());
            SetupCacheIO.writeG1Array(out, pk.pointsB1());
            SetupCacheIO.writeG2Array(out, pk.pointsB2());
            SetupCacheIO.writeG1Array(out, pk.pointsH());
            SetupCacheIO.writeG1Array(out, pk.pointsL());

            SetupCacheIO.writeG2(out, setup.gammaG2());
            SetupCacheIO.writeG1Array(out, setup.ic());
        });
    }

    /**
     * Load a BLS12-381 Groth16 circuit-specific setup result.
     */
    public static Groth16SetupBLS381.SetupResult loadBls12381Setup(Path path) throws IOException {
        return SetupCacheIO.readCacheFile(path, SetupCacheIO.TYPE_GROTH16_BLS12381_SETUP, in -> {
            var alphaG1 = SetupCacheIO.readG1(in);
            var betaG1 = SetupCacheIO.readG1(in);
            var betaG2 = SetupCacheIO.readG2(in);
            var deltaG1 = SetupCacheIO.readG1(in);
            var deltaG2 = SetupCacheIO.readG2(in);
            int numPublic = in.readInt();

            var pointsA = SetupCacheIO.readG1Array(in);
            var pointsB1 = SetupCacheIO.readG1Array(in);
            var pointsB2 = SetupCacheIO.readG2Array(in);
            var pointsH = SetupCacheIO.readG1Array(in);
            var pointsL = SetupCacheIO.readG1Array(in);

            var gammaG2 = SetupCacheIO.readG2(in);
            var ic = SetupCacheIO.readG1Array(in);

            validateGroth16SetupShape(numPublic, pointsA, pointsB1, pointsB2, pointsH, pointsL, ic);
            validateGroth16SetupPoints(alphaG1, betaG1, betaG2, deltaG1, deltaG2,
                    pointsA, pointsB1, pointsB2, pointsH, pointsL, gammaG2, ic);

            var pk = new Groth16ProvingKeyBLS381(
                    alphaG1, betaG1, betaG2, deltaG1, deltaG2,
                    pointsA, pointsB1, pointsB2, pointsH, pointsL, numPublic);

            return new Groth16SetupBLS381.SetupResult(pk, gammaG2, ic);
        });
    }

    private static void validateGroth16Setup(Groth16SetupBLS381.SetupResult setup) throws IOException {
        if (setup == null || setup.provingKey() == null || setup.ic() == null) {
            throw new IOException("Groth16 setup must not be null");
        }
        var pk = setup.provingKey();
        validateGroth16SetupShape(pk.numPublic(), pk.pointsA(), pk.pointsB1(), pk.pointsB2(),
                pk.pointsH(), pk.pointsL(), setup.ic());
        validateGroth16SetupPoints(pk.alphaG1(), pk.betaG1(), pk.betaG2(), pk.deltaG1(), pk.deltaG2(),
                pk.pointsA(), pk.pointsB1(), pk.pointsB2(), pk.pointsH(), pk.pointsL(),
                setup.gammaG2(), setup.ic());
    }

    private static void validateGroth16SetupShape(
            int numPublic,
            Object[] pointsA,
            Object[] pointsB1,
            Object[] pointsB2,
            Object[] pointsH,
            Object[] pointsL,
            Object[] ic) throws IOException {
        if (numPublic < 0 || numPublic == Integer.MAX_VALUE) {
            throw new IOException("Invalid Groth16 public input count: " + numPublic);
        }
        if (pointsA.length == 0 || numPublic >= pointsA.length) {
            throw new IOException("Groth16 public input count exceeds wire count: " + numPublic);
        }
        int numWires = pointsA.length;
        if (pointsB1.length != numWires || pointsB2.length != numWires) {
            throw new IOException("Groth16 proving key wire arrays have inconsistent lengths");
        }
        int expectedPrivate = numWires - numPublic - 1;
        if (pointsL.length != expectedPrivate) {
            throw new IOException("Invalid Groth16 private wire point count: expected "
                    + expectedPrivate + ", got " + pointsL.length);
        }
        if (ic.length != numPublic + 1) {
            throw new IOException("Invalid Groth16 IC length: expected " + (numPublic + 1)
                    + ", got " + ic.length);
        }
        if (pointsH.length == 0 || Integer.bitCount(pointsH.length) != 1) {
            throw new IOException("Invalid Groth16 H point count: " + pointsH.length);
        }
    }

    private static void validateGroth16SetupPoints(
            Object alphaG1,
            Object betaG1,
            Object betaG2,
            Object deltaG1,
            Object deltaG2,
            Object[] pointsA,
            Object[] pointsB1,
            Object[] pointsB2,
            Object[] pointsH,
            Object[] pointsL,
            Object gammaG2,
            Object[] ic) throws IOException {
        SetupCacheIO.validateG1((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1) alphaG1, false, "Groth16 alphaG1");
        SetupCacheIO.validateG1((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1) betaG1, false, "Groth16 betaG1");
        SetupCacheIO.validateG2((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2) betaG2, false, "Groth16 betaG2");
        SetupCacheIO.validateG1((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1) deltaG1, false, "Groth16 deltaG1");
        SetupCacheIO.validateG2((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2) deltaG2, false, "Groth16 deltaG2");
        SetupCacheIO.validateG2((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2) gammaG2, false, "Groth16 gammaG2");
        SetupCacheIO.validateG1Array((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1[]) pointsA, true, "Groth16 pointsA");
        SetupCacheIO.validateG1Array((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1[]) pointsB1, true, "Groth16 pointsB1");
        SetupCacheIO.validateG2Array((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2[]) pointsB2, true, "Groth16 pointsB2");
        SetupCacheIO.validateG1Array((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1[]) pointsH, true, "Groth16 pointsH");
        SetupCacheIO.validateG1Array((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1[]) pointsL, true, "Groth16 pointsL");
        SetupCacheIO.validateG1Array((com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1[]) ic, true, "Groth16 IC");
    }
}
