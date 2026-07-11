package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.crypto.msm.FlatScalars;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;

/**
 * The front door for programmatic Groth16 (BLS12-381) setup and proving: <b>one handle for the
 * key material, wherever it lives</b> — on the heap, in a dense key store, or in a sparse key
 * store — and one {@link #prove} that works identically against all of them.
 *
 * <p>The only decision a caller makes is <em>where the proving key lives</em>, once, at setup
 * time. Everything after that is uniform:</p>
 *
 * <pre>{@code
 * // Tests / small circuits — key on the heap, nothing touches disk:
 * try (var keys = Groth16Keys.setupInMemory(constraints, numWires, numPublic, tau)) {
 *     var proof = keys.prove(witness, constraints);
 * }
 *
 * // Real circuits — key streamed to disk during setup (~8 GB heap at 19M constraints,
 * // ADR-0035), never heap-resident; sparse=true stores infinity points as 1 bit each:
 * try (var keys = Groth16Keys.setupToStore(flat, numWires, numPublic, tau, dir, true)) {
 *     var proof = keys.prove(witness, constraints);
 * }
 *
 * // Every later run — reopen the same bundle (or one imported from a snarkjs ceremony);
 * // dense and sparse formats are auto-detected:
 * try (var keys = Groth16Keys.load(dir)) {
 *     var proof = keys.prove(witness, constraints);
 * }
 * }</pre>
 *
 * <p>Store-backed keys are memory-mapped ({@code prove} at 19M constraints runs in ~7–8 GB of
 * heap, ADR-0033/0034); call {@link #close} (or use try-with-resources) to unmap. Heap-backed
 * keys ignore {@code close()}.</p>
 *
 * <p>The lower-level entry points ({@link Groth16SetupBLS381#setup},
 * {@link Groth16SetupBLS381#setupToStore}, {@link Groth16ProverBLS381#proveWithReaders},
 * {@link Groth16ProverBLS381#proveWithHCoeffs}, {@link Groth16PkStore}) remain public as the
 * expert layer — differential tests and memory-tuned pipelines (e.g. the account-ownership CLI)
 * need those seams — but new integrations should not need anything beyond this class.</p>
 */
public final class Groth16Keys implements AutoCloseable {

    private final Groth16ProvingKeyBLS381 pk;
    private final Groth16ProverBLS381.G1Readers readers;
    private final AffineG2 gammaG2;
    private final AffineG1[] ic;
    private final int domain;
    private final int numWires;
    private final Arena arena; // owns the mmap lifetime for store-backed keys; null when heap-backed

    private Groth16Keys(Groth16ProvingKeyBLS381 pk, Groth16ProverBLS381.G1Readers readers,
                        AffineG2 gammaG2, AffineG1[] ic, int domain, int numWires, Arena arena) {
        this.pk = pk;
        this.readers = readers;
        this.gammaG2 = gammaG2;
        this.ic = ic;
        this.domain = domain;
        this.numWires = numWires;
        this.arena = arena;
    }

    // ---- obtaining keys ---------------------------------------------------------------------

    /**
     * Single-party dev/test setup with the proving key held <b>on the heap</b> — for tests and
     * small circuits (at 19M constraints the key alone is ~24 GB; use
     * {@link #setupToStore} there). Requires the insecure-setup opt-in
     * ({@code TrustedSetupPolicy}), like every single-party setup.
     */
    public static Groth16Keys setupInMemory(List<R1CSConstraint> constraints, int numWires,
                                            int numPublic, BigInteger tau) {
        return of(Groth16SetupBLS381.setup(constraints, numWires, numPublic, tau));
    }

    /**
     * Single-party dev/test setup <b>streamed to a key-store directory</b> (ADR-0035): every
     * point is written straight into the memory-mapped store files, so nothing key-sized is
     * ever heap-resident (~8 GB heap at 19M constraints). The store is then opened and the
     * returned handle proves from it directly.
     *
     * @param sparse {@code true} writes the {@code sparse-v1} format (infinity points as 1 bit
     *               each — ~2.6× smaller at 19M, ADR-0035 M6a); {@code false} writes the dense
     *               format readable by pre-M6 loaders. Both load identically via {@link #load}.
     */
    public static Groth16Keys setupToStore(R1CSFlat flat, int numWires, int numPublic,
                                           BigInteger tau, Path dir, boolean sparse) throws IOException {
        Groth16SetupBLS381.setupToStore(flat, numWires, numPublic, tau, dir, sparse);
        return load(dir);
    }

    /**
     * Open an existing key bundle — a {@link #setupToStore} output, a
     * {@code Groth16PkStore#save} output, or a snarkjs ceremony {@code .zkey} brought in with
     * {@code ZkeyPkStoreImporter}. Dense and sparse formats are auto-detected from the
     * manifest. The key files are memory-mapped; close the handle to unmap.
     */
    public static Groth16Keys load(Path dir) throws IOException {
        var loaded = Groth16PkStore.load(dir);
        return new Groth16Keys(loaded.pk(), loaded.readers(), loaded.gammaG2(), loaded.ic(),
                loaded.domain(), loaded.readers().b2().count(), loaded.arena());
    }

    /**
     * Wrap an already-loaded store handle ({@link Groth16PkStore#load}) — shares its arena, so
     * close the {@code Loaded} (or this handle) exactly once.
     */
    public static Groth16Keys of(Groth16PkStore.Loaded loaded) {
        return new Groth16Keys(loaded.pk(), loaded.readers(), loaded.gammaG2(), loaded.ic(),
                loaded.domain(), loaded.readers().b2().count(), loaded.arena());
    }

    /** Wrap a classic in-heap {@link Groth16SetupBLS381#setup} result in the unified handle. */
    public static Groth16Keys of(Groth16SetupBLS381.SetupResult sr) {
        var pk = sr.provingKey();
        return new Groth16Keys(pk, Groth16ProverBLS381.heapReaders(pk), sr.gammaG2(), sr.ic(),
                Groth16ProvingKeyBLS381.count(pk.pointsH()), pk.pointsB2().length, null);
    }

    // ---- proving ----------------------------------------------------------------------------

    /** Generate a (blinded) proof with the pure-Java MSM backend — the default. */
    public Groth16ProofBLS381 prove(BigInteger[] witness, List<R1CSConstraint> constraints) {
        return prove(ProverBackend.PURE_JAVA, witness, constraints);
    }

    /** {@link #prove(BigInteger[], List)} with an explicit MSM backend (e.g. blst). */
    public Groth16ProofBLS381 prove(ProverBackend backend, BigInteger[] witness,
                                    List<R1CSConstraint> constraints) {
        checkWitness(witness == null ? -1 : witness.length,
                witness != null && witness.length > 0 && BigInteger.ONE.equals(witness[0]));
        return Groth16ProverBLS381.proveWithReaders(pk, readers, backend, witness, constraints,
                numWires, domain);
    }

    /**
     * {@link #prove(BigInteger[], List)} over packed CSR constraints and flat scalars — the
     * allocation-lean path for very large circuits (ADR-0034).
     *
     * @param snarkjsBindingRows {@code 0} for a locally-generated bundle; for a bundle imported
     *                           from a snarkjs ceremony, the {@code numPublic + 1} public-input
     *                           binding rows the ceremony appends after the circuit rows (see
     *                           {@link Groth16ProverBLS381#computeHFlat}).
     */
    public Groth16ProofBLS381 prove(ProverBackend backend, FlatScalars witness, R1CSFlat constraints,
                                    int snarkjsBindingRows) {
        checkWitness(witness == null ? -1 : witness.count(),
                witness != null && witness.count() > 0 && BigInteger.ONE.equals(witness.toBigInteger(0)));
        FlatScalars hCoeffs = Groth16ProverBLS381.computeHFlat(constraints, witness,
                snarkjsBindingRows, domain);
        return Groth16ProverBLS381.proveWithHCoeffs(pk, readers, backend, witness, hCoeffs);
    }

    private void checkWitness(int length, boolean firstIsOne) {
        if (length <= 0)
            throw new IllegalArgumentException("Witness must not be null or empty");
        if (length != numWires)
            throw new IllegalArgumentException(
                    "witness length (" + length + ") must match numWires (" + numWires + ")");
        if (!firstIsOne)
            throw new IllegalArgumentException("witness[0] must be 1");
    }

    // ---- key material -----------------------------------------------------------------------

    /** Single points (alpha/beta/delta) + numPublic; big point arrays are empty for store-backed keys. */
    public Groth16ProvingKeyBLS381 pk() { return pk; }

    /** The proving-key point arrays as readers (heap or mmap-backed) — the expert-layer seam. */
    public Groth16ProverBLS381.G1Readers readers() { return readers; }

    /** gamma in G2 — verification-key component. */
    public AffineG2 gammaG2() { return gammaG2; }

    /** Input-commitment points {@code IC[0] + sum(pub_i * IC[i+1])} — verification-key component. */
    public AffineG1[] ic() { return ic; }

    /** FFT domain size (next power of two ≥ constraint count). */
    public int domain() { return domain; }

    /** Total wire count — a valid witness has exactly this many scalars. */
    public int numWires() { return numWires; }

    /** Unmaps a store-backed key (further proving with this handle fails); no-op for heap keys. */
    @Override
    public void close() {
        if (arena != null) arena.close();
    }
}
