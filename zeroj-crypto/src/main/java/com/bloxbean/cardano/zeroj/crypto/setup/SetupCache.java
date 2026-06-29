package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Package-private compatibility facade for setup artifact caches.
 *
 * <p>Prefer the proof-system-specific cache classes for new code:</p>
 * <ul>
 *   <li>{@link Groth16SetupCache} for BLS12-381 Groth16 Powers of Tau and
 *       circuit-specific phase-2 setup artifacts.</li>
 *   <li>{@link PlonkSetupCache} for BLS12-381 PlonK Powers of Tau / KZG SRS
 *       and circuit-specific proving keys.</li>
 * </ul>
 *
 * <p>This facade is intentionally not public. External callers should use one
 * of the two proof-system-specific cache classes directly.</p>
 *
 * @deprecated Use {@link Groth16SetupCache} or {@link PlonkSetupCache} directly.
 */
@Deprecated(since = "0.1.0-pre3", forRemoval = false)
final class SetupCache {
    private SetupCache() {
    }

    /**
     * Save a BLS12-381 Powers of Tau / SRS artifact.
     *
     * @deprecated Prefer {@link Groth16SetupCache#saveBls12381Srs(PtauImporterBLS381.SRS, Path)}
     * or {@link PlonkSetupCache#saveBls12381Srs(PtauImporterBLS381.SRS, Path)} from the
     * proof-system-specific cache class used by the application.
     */
    @Deprecated(since = "0.1.0-pre3", forRemoval = false)
    public static void saveSrs(PtauImporterBLS381.SRS srs, Path path) throws IOException {
        SrsCache.saveBls12381Srs(srs, path);
    }

    /**
     * Load a BLS12-381 Powers of Tau / SRS artifact.
     *
     * @deprecated Prefer {@link Groth16SetupCache#loadBls12381Srs(Path)}
     * or {@link PlonkSetupCache#loadBls12381Srs(Path)} from the proof-system-specific cache
     * class used by the application.
     */
    @Deprecated(since = "0.1.0-pre3", forRemoval = false)
    public static PtauImporterBLS381.SRS loadSrs(Path path) throws IOException {
        return SrsCache.loadBls12381Srs(path);
    }

    /**
     * Save a BLS12-381 Groth16 circuit-specific setup result.
     *
     * @deprecated Use {@link Groth16SetupCache#saveBls12381Setup(Groth16SetupBLS381.SetupResult, Path)}.
     */
    @Deprecated(since = "0.1.0-pre3", forRemoval = false)
    public static void saveSetup(Groth16SetupBLS381.SetupResult setup, Path path) throws IOException {
        Groth16SetupCache.saveBls12381Setup(setup, path);
    }

    /**
     * Load a BLS12-381 Groth16 circuit-specific setup result.
     *
     * @deprecated Use {@link Groth16SetupCache#loadBls12381Setup(Path)}.
     */
    @Deprecated(since = "0.1.0-pre3", forRemoval = false)
    public static Groth16SetupBLS381.SetupResult loadSetup(Path path) throws IOException {
        return Groth16SetupCache.loadBls12381Setup(path);
    }

    /**
     * Save a BLS12-381 PlonK circuit-specific proving key.
     *
     * @deprecated Use {@link PlonkSetupCache#saveBls12381ProvingKey(PlonKProvingKeyBLS381, Path)}.
     */
    @Deprecated(since = "0.1.0-pre3", forRemoval = false)
    public static void savePlonkProvingKeyBLS381(PlonKProvingKeyBLS381 pk, Path path) throws IOException {
        PlonkSetupCache.saveBls12381ProvingKey(pk, path);
    }

    /**
     * Load a BLS12-381 PlonK circuit-specific proving key.
     *
     * @deprecated Use {@link PlonkSetupCache#loadBls12381ProvingKey(Path)}.
     */
    @Deprecated(since = "0.1.0-pre3", forRemoval = false)
    public static PlonKProvingKeyBLS381 loadPlonkProvingKeyBLS381(Path path) throws IOException {
        return PlonkSetupCache.loadBls12381ProvingKey(path);
    }
}
