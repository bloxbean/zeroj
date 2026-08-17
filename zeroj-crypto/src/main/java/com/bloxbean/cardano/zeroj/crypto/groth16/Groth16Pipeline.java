package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.api.R1CSFlatIO;
import com.bloxbean.cardano.zeroj.crypto.msm.FlatScalars;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * The big-circuit setup/prove orchestration from ADR-0033/0034/0035, extracted from the
 * account-ownership CLI so every large circuit gets the measured memory/time behaviour without
 * reimplementing it. Sits between {@link Groth16Keys} (which abstracts <em>where the key
 * lives</em>) and the expert seams (which this class calls in the measured-optimal order).
 *
 * <p>What the orchestration encodes (each step maps to a measured milestone):</p>
 * <ul>
 *   <li><b>Setup</b> — emit the fingerprint-gated {@code r1cs.bin} constraint cache in the same
 *       pass as the streamed key store, so the first prove skips its compile (ADR-0035 M5).</li>
 *   <li><b>Prove, cache hit</b> — probe only the cache header up front; run witness generation
 *       first; then <b>memory-map</b> the packed constraints (never heap-loaded), so the
 *       constraints and the witness-generation peak never coexist (ADR-0034 M4/M6).</li>
 *   <li><b>Prove, cache miss</b> — compile, write the cache for next time, and verify the
 *       compiled circuit's fingerprint against the key bundle's (a mismatched bundle fails fast
 *       instead of producing an unverifiable proof).</li>
 *   <li><b>Prove, always</b> — H is computed from packed CSR + flat scalars, the constraint
 *       reference is dropped before the MSMs, and nothing on the path boxes a field element
 *       (ADR-0033 M2, ADR-0034 M3).</li>
 * </ul>
 *
 * <p>The two circuit-specific pieces stay with the caller as suppliers: how to compile
 * ({@link Compiled}) and how to produce the witness. The witness supplier should build the
 * circuit graph, evaluate, <b>release the graph</b>, and return packed scalars — see
 * {@code OwnershipCircuitService.witnessFlat} for the reference implementation.</p>
 */
public final class Groth16Pipeline {

    private Groth16Pipeline() {}

    /** File name of the packed-constraint cache inside a key-bundle directory. */
    public static final String R1CS_CACHE = "r1cs.bin";
    private static final Pattern LEGACY_DIMENSION_FINGERPRINT = Pattern.compile(
            "^c[1-9][0-9]*-w[1-9][0-9]*-p[0-9]+$");

    /**
     * A compiled circuit, reduced to what setup/prove need. Build it, then drop every reference
     * to the circuit graph / constraint system before the heavy phase (the pipeline cannot
     * release objects it never sees).
     */
    public static final class Compiled {
        private final R1CSFlat flat;
        private final int numConstraints;
        private final int numWires;
        private final int numPublic;
        private final String r1csSha256;
        private final String fingerprint;

        public Compiled(R1CSFlat flat, int numConstraints, int numWires, int numPublic) {
            if (flat == null) throw new NullPointerException("flat");
            if (numConstraints < 1) throw new IllegalArgumentException("numConstraints must be >= 1");
            if (numWires < 1) throw new IllegalArgumentException("numWires must be >= 1");
            if (numPublic < 0 || numPublic >= numWires) {
                throw new IllegalArgumentException("numPublic must be in [0, numWires)");
            }
            if (flat.rows() != numConstraints) {
                throw new IllegalArgumentException("flat row count does not match numConstraints");
            }
            this.flat = flat;
            this.numConstraints = numConstraints;
            this.numWires = numWires;
            this.numPublic = numPublic;
            this.r1csSha256 = R1CSFlatIO.canonicalSha256(flat, numWires, numPublic);
            this.fingerprint = Groth16Pipeline.fingerprint(
                    numConstraints, numWires, numPublic) + "-r" + r1csSha256;
        }

        public R1CSFlat flat() { return flat; }
        public int numConstraints() { return numConstraints; }
        public int numWires() { return numWires; }
        public int numPublic() { return numPublic; }

        /** Exact circuit fingerprint — gates the {@code r1cs.bin} cache and key bundles. */
        public String fingerprint() {
            return fingerprint;
        }

        /** Canonical content identity used by authenticated-state manifests. */
        public String r1csSha256() {
            return r1csSha256;
        }
    }

    /** Canonical fingerprint format: {@code c<constraints>-w<wires>-p<public>}. */
    public static String fingerprint(int numConstraints, int numWires, int numPublic) {
        if (numConstraints < 1) throw new IllegalArgumentException("numConstraints must be >= 1");
        if (numWires < 1) throw new IllegalArgumentException("numWires must be >= 1");
        if (numPublic < 0 || numPublic >= numWires) {
            throw new IllegalArgumentException("numPublic must be in [0, numWires)");
        }
        return "c" + numConstraints + "-w" + numWires + "-p" + numPublic;
    }

    /** True only for a dimension label suffixed by one canonical lowercase SHA-256 digest. */
    public static boolean isExactFingerprint(String fingerprint) {
        return R1CSFlatIO.parseExactFingerprint(fingerprint) != null;
    }

    /** Circuit dimensions recovered from a {@link #fingerprint}; {@code null} if malformed. */
    public static Dims parseFingerprint(String fp) {
        var exact = R1CSFlatIO.parseExactFingerprint(fp);
        if (exact != null) {
            return new Dims(exact.constraints(), exact.wires(), exact.publicInputs());
        }
        if (fp == null || !LEGACY_DIMENSION_FINGERPRINT.matcher(fp).matches()) return null;
        int w = fp.indexOf("-w"), p = fp.indexOf("-p");
        if (w < 0 || p < w) return null;
        try {
            int end = fp.indexOf("-r", p + 2);
            if (end < 0) end = fp.length();
            int constraints = Integer.parseInt(fp, 1, w, 10);
            int wires = Integer.parseInt(fp, w + 2, p, 10);
            int publicInputs = Integer.parseInt(fp, p + 2, end, 10);
            if (publicInputs >= wires) return null;
            return new Dims(constraints, wires, publicInputs);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Circuit dimensions (from a fingerprint) — enough for pre-compile heap preflight. */
    public record Dims(int numConstraints, int numWires, int numPublic) {
        /** FFT domain: next power of two ≥ constraint count (min 4), as the setup computes it. */
        public int domain() {
            int d = Integer.highestOneBit(numConstraints);
            if (d < numConstraints) d <<= 1;
            return Math.max(d, 4);
        }
    }

    /** Stage callbacks so a CLI can narrate; every method defaults to no-op. */
    public interface Progress {
        default void constraintCacheWritten(Path file, double seconds) {}
        default void constraintCacheWriteFailed(Exception e) {}
        default void constraintsMapped(int rows, double seconds) {}
        default void constraintCacheUnreadable() {}
        /** Witness + constraint load are done; H computation and the MSMs begin now. */
        default void proveStarted() {}
    }

    private static final Progress SILENT = new Progress() {};

    // ---- setup ------------------------------------------------------------------------------

    /** {@link #setup(Compiled, BigInteger, Path, boolean, Progress)} without progress callbacks. */
    public static Groth16SetupBLS381.SetupResult setup(Compiled cc, BigInteger tau,
                                                       Path dir, boolean sparse) throws IOException {
        return setup(cc, tau, dir, sparse, SILENT);
    }

    /**
     * Single-party dev/test setup, streamed into a key store at {@code dir} with the
     * {@code r1cs.bin} constraint cache emitted in the same pass (best-effort — a failed cache
     * write is reported and skipped, never fatal). ~8 GB heap at 19M constraints (ADR-0035).
     *
     * <p>Returns the {@link Groth16SetupBLS381.SetupResult} whose proving key holds only the
     * single points (the store on disk is the key) — export the VK from it. To prove, open the
     * bundle with {@link Groth16Keys#load}.</p>
     */
    public static Groth16SetupBLS381.SetupResult setup(Compiled cc, BigInteger tau, Path dir,
                                                       boolean sparse, Progress progress) throws IOException {
        Files.createDirectories(dir);
        Path cache = dir.resolve(R1CS_CACHE);
        try {
            long t = System.nanoTime();
            R1CSFlatIO.write(cc.flat(), cc.fingerprint(), cache);
            progress.constraintCacheWritten(cache, secs(t));
        } catch (Exception e) {
            progress.constraintCacheWriteFailed(e);
        }
        Groth16SetupBLS381.SetupResult result = Groth16SetupBLS381.setupToStore(
                cc.flat(), cc.numWires(), cc.numPublic(), tau, dir, sparse);
        Groth16PkStore.bindCircuitFingerprint(dir, cc.fingerprint());
        return result;
    }

    // ---- prove ------------------------------------------------------------------------------

    /**
     * True only when the decoded cache relation matches the exact fingerprint. Exact fingerprints
     * incur one full streaming relation hash; use is primarily for diagnostics and setup checks.
     */
    public static boolean cacheMatches(Path constraintCache, String fingerprint) {
        return constraintCache != null && fingerprint != null
                && R1CSFlatIO.hasMatching(constraintCache, fingerprint);
    }

    /** {@link #prove(Groth16Keys, Path, String, Supplier, Supplier, int, ProverBackend, Progress)}
     *  without progress callbacks. */
    public static Groth16ProofBLS381 prove(Groth16Keys keys, Path constraintCache, String fingerprint,
                                           Supplier<Compiled> compile, Supplier<FlatScalars> witness,
                                           int snarkjsBindingRows, ProverBackend backend) throws IOException {
        return prove(keys, constraintCache, fingerprint, compile, witness, snarkjsBindingRows, backend, SILENT);
    }

    /**
     * Cache-aware, memory-ordered prove.
     *
     * @param keys               the opened key bundle ({@link Groth16Keys#load}, or a wrapped
     *                           in-heap setup)
     * @param constraintCache    the {@code r1cs.bin} path (usually
     *                           {@code keysDir.resolve(}{@link #R1CS_CACHE}{@code )}), or
     *                           {@code null} to disable caching entirely (always compile)
     * @param fingerprint        the expected circuit fingerprint (from the bundle metadata), or
     *                           {@code null} if unknown — a non-null value gates the cache AND
     *                           fails fast on a key/circuit mismatch after a compile
     * @param compile            invoked only when the cache cannot be used; its {@link Compiled}
     *                           is written to the cache for next time
     * @param witness            produces the packed witness; runs BEFORE the mapped constraint
     *                           load so the two peaks never coexist. Must build and release any
     *                           circuit graph internally.
     * @param snarkjsBindingRows {@code numPublic + 1} for a snarkjs-ceremony key, 0 for a local
     *                           setup (see {@link Groth16ProverBLS381#computeHFlat})
     * @throws IllegalStateException when the compiled circuit's fingerprint does not match
     *                               {@code fingerprint} (bundle made for a different circuit)
     */
    public static Groth16ProofBLS381 prove(Groth16Keys keys, Path constraintCache, String fingerprint,
                                           Supplier<Compiled> compile, Supplier<FlatScalars> witness,
                                           int snarkjsBindingRows, ProverBackend backend,
                                           Progress progress) throws IOException {
        String storedFingerprint = keys.circuitFingerprint();
        if (storedFingerprint != null && fingerprint == null) {
            fingerprint = storedFingerprint;
        } else if (storedFingerprint != null && fingerprint != null
                && !storedFingerprint.equals(fingerprint)) {
            throw new IllegalStateException("Circuit/key mismatch: stored key bundle fingerprint is "
                    + storedFingerprint + " but the requested circuit is " + fingerprint);
        } else if (storedFingerprint == null && isExactFingerprint(fingerprint)) {
            throw new IllegalStateException("Exact circuit fingerprint " + fingerprint
                    + " was requested, but the key bundle is unbound. Bind an independently "
                    + "verified key bundle explicitly before proving.");
        }
        // Candidate-only preflight preserves the witness-first memory order. The mapped relation
        // is parsed and exact-hashed once, after witness generation, before it can reach proving.
        boolean hit = constraintCache != null && fingerprint != null
                && R1CSFlatIO.hasMatchingHeader(constraintCache, fingerprint);
        R1CSFlat flat = null;
        String fp = fingerprint;
        if (!hit) {
            Compiled cc = compileChecked(compile, fp);
            fp = cc.fingerprint();
            flat = cc.flat();
            if (constraintCache != null) {
                try {
                    long t = System.nanoTime();
                    R1CSFlatIO.write(flat, fp, constraintCache);
                    progress.constraintCacheWritten(constraintCache, secs(t));
                } catch (Exception e) {
                    progress.constraintCacheWriteFailed(e);
                }
            }
        }

        FlatScalars w = witness.get();

        Arena csArena = null;
        try {
            if (hit) {
                // deferred, memory-mapped constraint load (ADR-0034 M4/M6): the witness peak is
                // over, and the CSR arrays are segment-backed — never on the heap.
                long t = System.nanoTime();
                csArena = Arena.ofShared();
                flat = R1CSFlatIO.readMapped(constraintCache, fp, csArena);
                if (flat == null) { // vanished/corrupted since the header probe — recompile
                    progress.constraintCacheUnreadable();
                    csArena.close();
                    csArena = null;
                    Compiled compiled = compileChecked(compile, fp);
                    flat = compiled.flat();
                    try {
                        long writeStarted = System.nanoTime();
                        R1CSFlatIO.write(flat, compiled.fingerprint(), constraintCache);
                        progress.constraintCacheWritten(constraintCache, secs(writeStarted));
                    } catch (Exception e) {
                        progress.constraintCacheWriteFailed(e);
                    }
                } else {
                    progress.constraintsMapped(flat.rows(), secs(t));
                }
            }
            progress.proveStarted();
            FlatScalars h = Groth16ProverBLS381.computeHFlat(flat, w, snarkjsBindingRows, keys.domain());
            flat = null; // constraints served computeH; nothing heavy is resident during the MSMs
            return Groth16ProverBLS381.proveWithHCoeffs(keys.pk(), keys.readers(), backend, w, h);
        } finally {
            if (csArena != null) {
                try { csArena.close(); } catch (Throwable ignore) { /* native-image: unmapped at exit */ }
            }
        }
    }

    private static Compiled compileChecked(Supplier<Compiled> compile, String expectedFp) {
        Compiled cc = compile.get();
        if (expectedFp != null && !expectedFp.equals(cc.fingerprint()))
            throw new IllegalStateException("Circuit/key mismatch: key bundle fingerprint is "
                    + expectedFp + " but the compiled circuit is " + cc.fingerprint()
                    + " — the bundle was made for a different circuit.");
        return cc;
    }

    // ---- heap guidance ----------------------------------------------------------------------

    /**
     * Lower bound for the <b>prove-phase</b> heap: packed witness ({@code 32 B × wires}) +
     * H coefficients and three FFT buffers ({@code 4 × 32 B × domain}) + scratch/JVM slack.
     * At the 19M-constraint circuit this evaluates to ~6.4 GB against a measured 7 GB floor —
     * the gap is the witness-generation phase, whose peak is the (circuit-specific) graph size,
     * which this formula cannot see. Treat it as "definitely won't work below this"; apps that
     * measured their real floor (like the account-ownership CLI) should use the measured value.
     */
    public static long estimateProvePhaseHeapBytes(int numWires, int domain) {
        return 32L * numWires + 4L * 32L * domain + (768L << 20);
    }

    private static double secs(long startNanos) { return (System.nanoTime() - startNanos) / 1e9; }
}
