package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * Shared authenticated binary cache for BLS12-381 Powers of Tau / SRS artifacts.
 *
 * <p>This stores the public G1/G2 powers used as the universal setup input for
 * Groth16 phase 2 and PlonK circuit setup. Public cache files never store the
 * development-only {@code tauScalar}; callers that intentionally need that value
 * for local single-party setup must use the explicit insecure-dev method.</p>
 */
final class SrsCache {
    private SrsCache() {
    }

    /**
     * Save a BLS12-381 Powers of Tau / SRS artifact.
     */
    public static void saveBls12381Srs(PtauImporterBLS381.SRS srs, Path path) throws IOException {
        saveBls12381Srs(srs, path, false);
    }

    static void saveBls12381InsecureDevSrsWithTau(PtauImporterBLS381.SRS srs, Path path) throws IOException {
        TrustedSetupPolicy.requireInsecureTrustedSetupEnabled();
        if (srs.tauScalar() == null) {
            throw new IOException("SRS does not contain a tau scalar");
        }
        saveBls12381Srs(srs, path, true);
        setOwnerOnlyPermissions(path);
    }

    /**
     * Load a BLS12-381 Powers of Tau / SRS artifact.
     */
    public static PtauImporterBLS381.SRS loadBls12381Srs(Path path) throws IOException {
        return SetupCacheIO.readCacheFile(path, SetupCacheIO.TYPE_BLS12381_SRS, in -> {
            int power = in.readInt();

            int g1Len = SetupCacheIO.readArrayLength(in, "SRS G1 array", SetupCacheIO.MAX_CACHE_ARRAY_LENGTH);
            var tauG1 = new AffineG1[g1Len];
            for (int i = 0; i < g1Len; i++) {
                tauG1[i] = SetupCacheIO.readG1(in);
            }

            int g2Len = SetupCacheIO.readArrayLength(in, "SRS G2 array", SetupCacheIO.MAX_CACHE_ARRAY_LENGTH);
            var tauG2 = new AffineG2[g2Len];
            for (int i = 0; i < g2Len; i++) {
                tauG2[i] = SetupCacheIO.readG2(in);
            }

            BigInteger tau = null;
            if (in.readBoolean()) {
                tau = SetupCacheIO.readScalar(in, "tau scalar");
            }

            SetupCacheIO.validateBls12381Srs(tauG1, tauG2, power);
            return new PtauImporterBLS381.SRS(tauG1, tauG2, power, tau);
        });
    }

    private static void saveBls12381Srs(PtauImporterBLS381.SRS srs, Path path, boolean includeTau) throws IOException {
        SetupCacheIO.validateBls12381Srs(srs.tauG1(), srs.tauG2(), srs.power());
        SetupCacheIO.writeCacheFile(path, SetupCacheIO.TYPE_BLS12381_SRS, out -> {
            out.writeInt(srs.power());
            SetupCacheIO.writeG1Array(out, srs.tauG1());
            SetupCacheIO.writeG2Array(out, srs.tauG2());
            out.writeBoolean(includeTau && srs.tauScalar() != null);
            if (includeTau && srs.tauScalar() != null) {
                SetupCacheIO.writeScalar(out, srs.tauScalar(), "tau scalar");
            }
        });
    }

    private static void setOwnerOnlyPermissions(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException ignored) {
            // Best effort: POSIX permissions are unavailable on some file systems.
        }
    }
}
