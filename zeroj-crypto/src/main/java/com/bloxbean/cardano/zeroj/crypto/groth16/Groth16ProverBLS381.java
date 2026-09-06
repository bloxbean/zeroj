package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSValidation;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.bls12381.field.FrArith381;
import com.bloxbean.cardano.zeroj.crypto.poly.FrFFTFlat;
import com.bloxbean.cardano.zeroj.crypto.msm.FlatScalars;
import com.bloxbean.cardano.zeroj.crypto.msm.PippengerFlatBLS381;
import com.bloxbean.cardano.zeroj.crypto.msm.G1MsmBackend;
import com.bloxbean.cardano.zeroj.crypto.msm.G2AffineReader;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

/**
 * Pure Java Groth16 prover for BLS12-381.
 *
 * <p>Same algorithm as {@link Groth16Prover} but using BLS12-381 curve types.</p>
 *
 * <p><b>New integrations: start at {@link Groth16Keys}</b> — one handle + one {@code prove} for
 * heap, dense-store, and sparse-store keys alike. The entry points below are the expert layer
 * (reader seams, split H computation, packed scalars) for memory-tuned pipelines.</p>
 *
 * <p><b>Zero-knowledge blinding (ADR-0046, issue #50).</b> Every public prove entry point draws
 * a fresh {@code (r, s)} pair from {@link SecureRandom}; no public API fixes, seeds, or omits the
 * blinders, and this class contains no {@code r = s = 0} path. The deterministic proofs that the
 * byte-equality differential tests need exist only in the unpublished {@code zeroj-crypto} test
 * fixture {@code Groth16UnblindedTestProver}, which feeds {@code (0, 0)} once through the
 * package-private {@code BlinderSource} seam of {@code proveBlinded}. An unblinded proof is
 * <b>not zero-knowledge</b>: it is a deterministic function of the key and the full witness. See
 * ADR-0046 for the boundary and {@code Groth16ProverApiSurfaceTest} for what enforces it.</p>
 *
 * <p><b>Relation validation (issue #46).</b> Every prove and {@code computeH} entry point
 * rejects, with an {@link IllegalArgumentException} and before any FFT or MSM work: a relation
 * whose wire indices fall outside the witness, a witness or H vector whose length does not match
 * the proving key, and an FFT domain that is not a power of two or cannot hold the relation.
 * Malformed terms are never skipped: skipping used to prove a silently weakened relation.</p>
 *
 * <p><b>Proof-point profile (ADR-0045 P1/P2).</b> Every verifier profile rejects a proof whose
 * {@code A}, {@code B}, or {@code C} is the point at infinity. An honest prover reaches that
 * state only by scalar cancellation with probability on the order of {@code 1/r} per point. The
 * randomized entry points therefore resample {@code (r, s)} and recompute when it happens (at
 * most {@link #MAX_BLINDER_RESAMPLES} times, then fail closed); the deterministic unblinded
 * test path cannot resample (its blinder source refuses a second draw) and fails closed
 * instead. No prove path returns a proof point at infinity.</p>
 */
public final class Groth16ProverBLS381 {

    /**
     * Upper bound on {@code (r, s)} resamples per proof (ADR-0045 P1). Each attempt fails with
     * probability on the order of {@code 3/r}, so the bound only makes the loop provably finite.
     */
    static final int MAX_BLINDER_RESAMPLES = 8;

    private Groth16ProverBLS381() {}

    public static Groth16ProofBLS381 prove(
            Groth16ProvingKeyBLS381 pk,
            BigInteger[] witness,
            List<R1CSConstraint> constraints,
            int numWires) {
        int domainSize = Groth16ProvingKeyBLS381.count(pk.pointsH());
        return prove(pk, witness, constraints, numWires, domainSize);
    }

    public static Groth16ProofBLS381 prove(
            Groth16ProvingKeyBLS381 pk,
            BigInteger[] witness,
            List<R1CSConstraint> constraints,
            int numWires,
            int domainSize) {

        if (witness == null || witness.length == 0)
            throw new IllegalArgumentException("Witness must not be null or empty");
        if (!BigInteger.ONE.equals(witness[0]))
            throw new IllegalArgumentException("witness[0] must be 1");
        if (witness.length != numWires)
            throw new IllegalArgumentException(
                    "witness.length (" + witness.length + ") must match numWires (" + numWires + ")");

        if (!pk.alphaG1().isOnCurve())
            throw new IllegalArgumentException("Proving key alphaG1 is not on curve");
        if (!pk.betaG1().isOnCurve())
            throw new IllegalArgumentException("Proving key betaG1 is not on curve");
        if (!pk.betaG2().isOnCurve())
            throw new IllegalArgumentException("Proving key betaG2 is not on curve");
        if (!pk.deltaG1().isOnCurve())
            throw new IllegalArgumentException("Proving key deltaG1 is not on curve");
        if (!pk.deltaG2().isOnCurve())
            throw new IllegalArgumentException("Proving key deltaG2 is not on curve");

        int numConstraints = constraints.size();
        BigInteger[] hCoeffs = computeH(constraints, witness, numConstraints, domainSize);

        return proveBlinded(pk, heapReaders(pk), ProverBackend.PURE_JAVA,
                FlatScalars.pack(witness, witness.length), FlatScalars.pack(hCoeffs, hCoeffs.length),
                secureRandomBlinders());
    }

    /**
     * The proving-key point arrays as readers (heap or mmap-backed). {@code b2} is the G2 key
     * (ADR-0033 M3); when {@code null} (the pre-M3 G1-only constructor) the prover falls back to
     * the on-heap {@code pk.pointsB2()}.
     */
    public record G1Readers(PippengerFlatBLS381.G1AffineReader a, PippengerFlatBLS381.G1AffineReader b1,
                            PippengerFlatBLS381.G1AffineReader h, PippengerFlatBLS381.G1AffineReader l,
                            G2AffineReader b2) {
        /** G1-only form (pre-ADR-0033): the prover reads G2 from {@code pk.pointsB2()} on-heap. */
        public G1Readers(PippengerFlatBLS381.G1AffineReader a, PippengerFlatBLS381.G1AffineReader b1,
                         PippengerFlatBLS381.G1AffineReader h, PippengerFlatBLS381.G1AffineReader l) {
            this(a, b1, h, l, null);
        }
    }

    /** In-RAM readers over the PK's flat G1 arrays + G2 array. */
    public static G1Readers heapReaders(Groth16ProvingKeyBLS381 pk) {
        return new G1Readers(
                new PippengerFlatBLS381.HeapG1Reader(pk.pointsA()),
                new PippengerFlatBLS381.HeapG1Reader(pk.pointsB1()),
                new PippengerFlatBLS381.HeapG1Reader(pk.pointsH()),
                new PippengerFlatBLS381.HeapG1Reader(pk.pointsL()),
                new G2AffineReader.HeapG2Reader(pk.pointsB2()));
    }

    /**
     * Prove with the G1 proving key supplied as {@link G1Readers} — pass mmap-backed
     * {@link PippengerFlatBLS381.SegmentG1Reader}s to prove with the PK off-heap/file-backed
     * (ADR-0029 M4). Single points + G2 come from {@code pk}.
     */
    public static Groth16ProofBLS381 proveWithReaders(
            Groth16ProvingKeyBLS381 pk, G1Readers readers, BigInteger[] witness,
            List<R1CSConstraint> constraints, int numWires, int domainSize) {
        return proveWithReaders(pk, readers, ProverBackend.PURE_JAVA, witness, constraints, numWires, domainSize);
    }

    /** Prove with an explicit G1 MSM backend (e.g. the opt-in FFM blst backend, ADR-0029 M7). */
    public static Groth16ProofBLS381 proveWithReaders(
            Groth16ProvingKeyBLS381 pk, G1Readers readers, ProverBackend backend, BigInteger[] witness,
            List<R1CSConstraint> constraints, int numWires, int domainSize) {
        if (witness == null || witness.length == 0)
            throw new IllegalArgumentException("Witness must not be null or empty");
        if (witness.length != numWires)
            throw new IllegalArgumentException(
                    "witness.length (" + witness.length + ") must match numWires (" + numWires + ")");
        BigInteger[] hCoeffs = computeH(constraints, witness, constraints.size(), domainSize);
        return proveWithHCoeffs(pk, readers, backend, witness, hCoeffs);
    }

    /**
     * Prove from a pre-computed H polynomial (ADR-0033 M2). The heavy R1CS {@code constraints}
     * list (many GB at 19M constraints) is consumed only by {@link #computeH}; splitting it out
     * lets the caller compute H, drop its constraints/circuit references, and only then prove —
     * so none of that memory is resident during the five MSMs (where the peak was hit). The
     * on-chain-facing behaviour is identical to {@link #proveWithReaders}; only the memory
     * lifetime changes.
     */
    public static Groth16ProofBLS381 proveWithHCoeffs(
            Groth16ProvingKeyBLS381 pk, G1Readers readers, ProverBackend backend,
            BigInteger[] witness, BigInteger[] hCoeffs) {
        return proveWithHCoeffs(pk, readers, backend,
                FlatScalars.pack(witness, witness.length), FlatScalars.pack(hCoeffs, hCoeffs.length));
    }

    /**
     * {@link #proveWithHCoeffs(Groth16ProvingKeyBLS381, G1Readers, ProverBackend, BigInteger[],
     * BigInteger[])} with packed flat scalars (ADR-0034 M3) — witness and hCoeffs stay 32 B/scalar
     * end-to-end (no {@code BigInteger} boxing on the prove path; the MSMs read limbs directly).
     */
    public static Groth16ProofBLS381 proveWithHCoeffs(
            Groth16ProvingKeyBLS381 pk, G1Readers readers, ProverBackend backend,
            FlatScalars witness, FlatScalars hCoeffs) {
        return proveBlinded(pk, readers, backend, witness, hCoeffs, secureRandomBlinders());
    }

    /**
     * A source of {@code (r, s)} blinder pairs (ADR-0045 P1). Package-private on purpose: it is
     * the only seam through which a test may fix the blinders (ADR-0045 forced-infinity tests,
     * ADR-0046 unblinded test fixture), and {@code Groth16ProverApiSurfaceTest} fails if it or
     * {@link #proveBlinded} ever becomes public.
     */
    @FunctionalInterface
    interface BlinderSource {
        /** @return {@code {r, s}}, each a canonical scalar in {@code [0, r)} */
        BigInteger[] next();
    }

    /** The production blinder source: two uniformly random scalars from {@link SecureRandom}. */
    static BlinderSource secureRandomBlinders() {
        var rng = new SecureRandom();
        return () -> new BigInteger[]{randomScalar(rng), randomScalar(rng)};
    }

    /**
     * Randomized prove with resampling (ADR-0045 P1): draws {@code (r, s)} from {@code blinders},
     * computes the proof, and retries with a fresh pair while any of {@code A/B/C} is the point at
     * infinity, at most {@link #MAX_BLINDER_RESAMPLES} times before failing closed. A source that
     * throws on its second draw turns this into a deterministic single-shot prove that fails
     * closed on an infinity point (ADR-0045 P2) — the unblinded test fixture relies on that.
     */
    static Groth16ProofBLS381 proveBlinded(
            Groth16ProvingKeyBLS381 pk, G1Readers readers, ProverBackend backend, FlatScalars witness,
            FlatScalars hCoeffs, BlinderSource blinders) {
        for (int attempt = 0; attempt < MAX_BLINDER_RESAMPLES; attempt++) {
            BigInteger[] rs = blinders.next();
            if (rs == null || rs.length != 2 || rs[0] == null || rs[1] == null)
                throw new IllegalStateException("blinder source must return a non-null {r, s} pair");
            ProofPoints points = computeProofPoints(pk, readers, backend, witness, hCoeffs, rs[0], rs[1]);
            if (!points.hasInfinity()) return points.toProof();
            // (r, s) cancelled a proof point (probability ~1/r each): resample, never emit infinity.
        }
        throw new IllegalStateException("Groth16 prove aborted: a proof point was the point at infinity on "
                + MAX_BLINDER_RESAMPLES + " consecutive (r, s) samples, which every verifier profile rejects"
                + " (ADR-0045). This is not reachable with a sound key and uniformly random blinders.");
    }

    /** The three Jacobian proof points of one {@code (r, s)} evaluation. */
    private record ProofPoints(JacobianG1BLS381 a, JacobianG2BLS381 b, JacobianG1BLS381 c) {
        boolean hasInfinity() {
            return a.isInfinity() || b.isInfinity() || c.isInfinity();
        }

        Groth16ProofBLS381 toProof() {
            return new Groth16ProofBLS381(a.toAffine(), b.toAffine(), c.toAffine());
        }
    }

    private static ProofPoints computeProofPoints(
            Groth16ProvingKeyBLS381 pk, G1Readers readers, ProverBackend backend, FlatScalars witness,
            FlatScalars hCoeffs, BigInteger r, BigInteger s) {

        G2AffineReader b2 = readers.b2() != null
                ? readers.b2() : new G2AffineReader.HeapG2Reader(pk.pointsB2());
        requireKeyDimensions(pk, readers, b2, witness, hCoeffs);
        var piA = computePiA(pk, readers.a(), backend.g1(), witness, r);
        var piB = computePiB_G2(pk, b2, backend.g2(), witness, s);
        var piB1 = computePiB_G1(pk, readers.b1(), backend.g1(), witness, s);
        var piC = computePiC(pk, readers.h(), readers.l(), backend.g1(), hCoeffs, witness, r, s, piA, piB1);

        return new ProofPoints(piA, piB, piC);
    }

    /**
     * {@link #computeH(List, BigInteger[], int, int)} over the packed CSR matrices (ADR-0034 M2)
     * — no map iteration, no boxed keys; the coefficient dictionary is converted to Montgomery
     * form once. Only the A and B matrices are read (C is derived pointwise on satisfied rows).
     *
     * @param snarkjsBindingRows number of public-input binding rows a snarkjs ceremony setup
     *                           appends after the circuit rows ({@code numPublic + 1}, one per
     *                           public signal including the ONE wire; each is {@code A={s:1},
     *                           B={}, C={}}), or 0 for a local setup. Row {@code flat.rows()+s}
     *                           evaluates to {@code aEval=witness[s], bEval=0} — equivalent to
     *                           {@code ZkeyPkStoreImporter.snarkjsConstraints} without
     *                           materializing 19M map rows.
     */
    public static BigInteger[] computeH(com.bloxbean.cardano.zeroj.api.R1CSFlat flat, BigInteger[] witness,
                                  int snarkjsBindingRows, int domainSize) {
        FlatScalars h = computeHFlat(flat, FlatScalars.pack(witness, witness.length), snarkjsBindingRows, domainSize);
        BigInteger[] out = new BigInteger[h.count()];
        for (int i = 0; i < out.length; i++) out[i] = h.toBigInteger(i);
        return out;
    }

    /** Montgomery form of R = 2^256 mod r, i.e. R² — multiplies a canonical value into Montgomery form. */
    private static final long[] FR_R2_LIMBS =
            MontFr381.fromBigInteger(BigInteger.ONE.shiftLeft(256).mod(MontFr381.modulus())).toLimbs();
    /** Plain 1 — Montgomery-multiplying by it converts a Montgomery value back to canonical. */
    private static final long[] ONE_LIMBS = {1, 0, 0, 0};

    /**
     * {@link #computeH(com.bloxbean.cardano.zeroj.api.R1CSFlat, BigInteger[], int, int)} with the
     * witness as packed flat scalars and the H coefficients returned the same way (ADR-0034 M3) —
     * the row evaluation runs entirely on {@code FrArith381} flat limbs (witness limbs converted
     * to Montgomery in place via R²), so nothing on the H path allocates per term, and the
     * 33.5M-element result is never boxed.
     */
    public static FlatScalars computeHFlat(com.bloxbean.cardano.zeroj.api.R1CSFlat flat, FlatScalars witness,
                                  int snarkjsBindingRows, int domainSize) {
        if (witness == null || witness.count() == 0)
            throw new IllegalArgumentException("Witness must not be null or empty");
        // Issue #46: a term whose wire lies outside the witness used to be skipped silently.
        R1CSValidation.requireWireIndices(flat, witness.count());
        if (snarkjsBindingRows < 0 || snarkjsBindingRows > witness.count())
            throw new IllegalArgumentException("snarkjsBindingRows (" + snarkjsBindingRows
                    + ") must be in [0, witness count " + witness.count() + "]");
        if (domainSize < 2) domainSize = 2;
        requireFftDomain(domainSize, (long) flat.rows() + snarkjsBindingRows);
        int logN = Integer.numberOfTrailingZeros(domainSize);
        final int domain = domainSize;

        // coefficient dictionary → flat Montgomery limbs, once
        BigInteger[] dictVals = flat.dictionary();
        long[] dictMont = new long[dictVals.length * 4];
        for (int i = 0; i < dictVals.length; i++)
            System.arraycopy(MontFr381.fromBigInteger(dictVals[i]).toLimbs(), 0, dictMont, i * 4, 4);

        long[] aEval = new long[domainSize * 4];
        long[] bEval = new long[domainSize * 4];

        int circuitRows = flat.rows();
        int evalUpper = Math.min(domainSize, circuitRows + snarkjsBindingRows);
        var aM = flat.a();
        var bM = flat.b();
        int wCount = witness.count();
        FrFFTFlat.parallelRange(evalUpper, (lo, hi) -> {
            long[] wCanon = new long[4], wMont = new long[4], term = new long[4];
            for (int i = lo; i < hi; i++) {
                if (i < circuitRows) {
                    evalRowInto(aM, dictMont, i, witness, wCount, aEval, i * 4, wCanon, wMont, term);
                    evalRowInto(bM, dictMont, i, witness, wCount, bEval, i * 4, wCanon, wMont, term);
                } else {
                    // snarkjs binding row s: A={s:1}, B={} — aEval = witness[s], bEval stays 0
                    int s = i - circuitRows; // < wCount: snarkjsBindingRows <= witness count (validated)
                    witness.copyLimbs(s, wCanon, 0);
                    FrArith381.mul(aEval, i * 4, wCanon, 0, FR_R2_LIMBS, 0); // canonical → Montgomery
                }
            } // beyond evalUpper: zeros (MontFr381.ZERO == all-zero limbs)
        });

        long[] cEval = new long[domain * 4];
        FrFFTFlat.parallelRange(domain, (lo, hi) -> {
            for (int i = lo; i < hi; i++) FrArith381.mul(cEval, i * 4, aEval, i * 4, bEval, i * 4);
        });

        long[] inc = FieldFFTBLS381.rootOfUnity(logN + 1).toLimbs();
        cosetFFT(aEval, domain, inc);
        cosetFFT(bEval, domain, inc);
        cosetFFT(cEval, domain, inc);

        // ADR-0034 M6b: the (a·b − c) extraction is elementwise, so the canonical result is
        // written back into aEval in place — no separate 1 GB result array at the peak.
        FrFFTFlat.parallelRange(domain, (lo, hi) -> {
            long[] val = new long[4];
            for (int i = lo; i < hi; i++) {
                FrArith381.mul(val, 0, aEval, i * 4, bEval, i * 4);   // a·b
                FrArith381.sub(val, 0, val, 0, cEval, i * 4);         // - c
                FrArith381.mul(aEval, i * 4, val, 0, ONE_LIMBS, 0);   // Montgomery → canonical
            }
        });
        return FlatScalars.wrap(aEval, domain);
    }

    /** Accumulate row {@code row} of {@code m} · witness into {@code out[outOff..]} (flat Montgomery). */
    private static void evalRowInto(com.bloxbean.cardano.zeroj.api.R1CSFlat.Matrix m, long[] dictMont,
            int row, FlatScalars witness, int wCount, long[] out, int outOff,
            long[] wCanon, long[] wMont, long[] term) {
        for (int k = m.start(row), e = m.end(row); k < e; k++) {
            int wire = requireWire(m.wire(k), wCount);
            witness.copyLimbs(wire, wCanon, 0);
            FrArith381.mul(wMont, 0, wCanon, 0, FR_R2_LIMBS, 0);          // canonical → Montgomery
            FrArith381.mul(term, 0, dictMont, m.coeffIndex(k) * 4, wMont, 0);
            FrArith381.add(out, outOff, out, outOff, term, 0);
        }
    }

    /**
     * The Groth16 H polynomial {@code (A·B − C)/Z} over the coset (ADR-0029 M2c flat FFT path).
     * Public (ADR-0033 M2) so callers can compute it and then release the constraints/circuit
     * before proving. See {@link #proveWithHCoeffs}.
     */
    public static BigInteger[] computeH(List<R1CSConstraint> constraints, BigInteger[] witness,
                                  int numConstraints, int domainSize) {
        BigInteger mod = MontFr381.modulus();
        if (witness == null || witness.length == 0)
            throw new IllegalArgumentException("Witness must not be null or empty");
        // Issue #46: a term whose wire lies outside the witness used to be skipped silently.
        R1CSValidation.requireWireIndices(constraints, witness.length);
        if (numConstraints < 0)
            throw new IllegalArgumentException("numConstraints must be >= 0 (got " + numConstraints + ")");
        if (domainSize < 2) domainSize = 2;
        requireFftDomain(domainSize, Math.min(numConstraints, constraints.size()));
        int logN = Integer.numberOfTrailingZeros(domainSize);

        // ADR-0029 M2c: Fr coefficients held as flat long[] (4 limbs/element) with the allocation-lean
        // FrFFTFlat, instead of MontFr381[] object arrays — halves the prover's transient FFT memory.
        long[] aEval = new long[domainSize * 4];
        long[] bEval = new long[domainSize * 4];

        // ADR-0029 M5b: at domain 2²⁵ these element-wise passes are minutes of single-threaded work
        // (they dominated the prove once the MSMs went multi-core). Each slot is independent, so fan
        // them across cores — same ops per slot ⇒ bit-identical results.
        int constraintCount = constraints.size();
        int evalUpper = Math.min(domainSize, Math.min(numConstraints, constraintCount));
        FrFFTFlat.parallelRange(evalUpper, (lo, hi) -> {
            for (int i = lo; i < hi; i++) {
                R1CSConstraint constraint = constraints.get(i);
                System.arraycopy(evalLinComb(constraint.a(), witness, mod).toLimbs(), 0, aEval, i * 4, 4);
                System.arraycopy(evalLinComb(constraint.b(), witness, mod).toLimbs(), 0, bEval, i * 4, 4);
            } // beyond evalUpper: zeros (MontFr381.ZERO == all-zero limbs)
        });

        return computeHFromEvals(aEval, bEval, domainSize, logN);
    }

    /** Shared computeH tail: {@code c = a·b} pointwise, three coset FFTs, {@code (a·b − c)} extraction. */
    private static BigInteger[] computeHFromEvals(long[] aEval, long[] bEval, int domainSize, int logN) {
        long[] cEval = new long[domainSize * 4];
        FrFFTFlat.parallelRange(domainSize, (lo, hi) -> {
            for (int i = lo; i < hi; i++) FrArith381.mul(cEval, i * 4, aEval, i * 4, bEval, i * 4);
        });

        long[] inc = FieldFFTBLS381.rootOfUnity(logN + 1).toLimbs();
        cosetFFT(aEval, domainSize, inc);
        cosetFFT(bEval, domainSize, inc);
        cosetFFT(cEval, domainSize, inc);

        BigInteger[] result = new BigInteger[domainSize];
        FrFFTFlat.parallelRange(domainSize, (lo, hi) -> {
            long[] val = new long[4];
            for (int i = lo; i < hi; i++) {
                FrArith381.mul(val, 0, aEval, i * 4, bEval, i * 4); // a·b
                FrArith381.sub(val, 0, val, 0, cEval, i * 4);       // - c
                result[i] = MontFr381.fromMontLimbs(val[0], val[1], val[2], val[3]).toBigInteger();
            }
        });
        return result;
    }

    /** In-place coset NTT on flat Fr coefficients: ifft → scale by inc^i → fft. */
    private static void cosetFFT(long[] a, int n, long[] inc) {
        FrFFTFlat.ifft(a, n);
        // scale a[i] by inc^i — chunked, each chunk starts its power walk at inc^lo (M5b)
        FrFFTFlat.parallelRange(n, (lo, hi) -> {
            long[] power = new long[4];
            FrFFTFlat.pow(power, inc, lo);
            for (int i = lo; i < hi; i++) {
                FrArith381.mul(a, i * 4, a, i * 4, power, 0);
                FrArith381.mul(power, 0, power, 0, inc, 0);
            }
        });
        FrFFTFlat.fft(a, n);
    }

    private static JacobianG1BLS381 computePiA(Groth16ProvingKeyBLS381 pk,
            PippengerFlatBLS381.G1AffineReader aReader, G1MsmBackend backend, FlatScalars witness, BigInteger r) {
        var result = JacobianG1BLS381.fromAffine(pk.alphaG1().x(), pk.alphaG1().y());

        int n = Math.min(witness.count(), aReader.count());
        if (n > 0) {
            result = result.add(backend.msm(aReader, n, witness.slice(0, n)));
        }

        result = result.add(JacobianG1BLS381.fromAffine(pk.deltaG1().x(), pk.deltaG1().y()).scalarMul(r));
        return result;
    }

    private static JacobianG2BLS381 computePiB_G2(Groth16ProvingKeyBLS381 pk, G2AffineReader b2,
            com.bloxbean.cardano.zeroj.crypto.msm.G2MsmBackend g2Backend, FlatScalars witness, BigInteger s) {
        var result = JacobianG2BLS381.fromAffine(pk.betaG2().x(), pk.betaG2().y());

        int n = Math.min(witness.count(), b2.count());
        result = result.add(g2Backend.msm(b2, witness, n));

        result = result.add(JacobianG2BLS381.fromAffine(pk.deltaG2().x(), pk.deltaG2().y()).scalarMul(s));
        return result;
    }

    static JacobianG2BLS381 g2Msm(G2AffineReader points, FlatScalars scalars, int n) {
        if (n == 0) return JacobianG2BLS381.INFINITY;

        int c = Math.max(3, Math.min(31 - Integer.numberOfLeadingZeros(n), 12));
        int numBuckets = (1 << c) - 1;
        int numWindows = (255 + c - 1) / c;

        // Single pass over the points (ADR-0033 M3): all windows' buckets are banked together so a
        // reader-backed point (mmap decode ≈ 4 field conversions) is materialized once, not once
        // per window. Per-bucket addition order is unchanged (ascending i), so the result — and
        // the proof — is identical to the per-window walk this replaces. Scalars are packed
        // canonical limbs (ADR-0034 M3) — already reduced, digits read straight from the limbs.
        JacobianG2BLS381[][] buckets = new JacobianG2BLS381[numWindows][numBuckets + 1];
        for (JacobianG2BLS381[] w : buckets) java.util.Arrays.fill(w, JacobianG2BLS381.INFINITY);

        for (int i = 0; i < n; i++) {
            if (scalars.isZero(i)) continue;
            AffineG2 p = points.get(i);
            if (p.isInfinity()) continue;
            JacobianG2BLS381 jac = null;
            for (int w = 0; w < numWindows; w++) {
                int digit = scalars.window(i, w * c, c);
                if (digit != 0) {
                    if (jac == null) jac = JacobianG2BLS381.fromAffine(p.x(), p.y());
                    buckets[w][digit] = buckets[w][digit].add(jac);
                }
            }
        }

        JacobianG2BLS381 result = JacobianG2BLS381.INFINITY;
        for (int w = numWindows - 1; w >= 0; w--) {
            if (!result.isInfinity()) {
                for (int d = 0; d < c; d++) result = result.doublePoint();
            }
            JacobianG2BLS381 runningSum = JacobianG2BLS381.INFINITY;
            JacobianG2BLS381 windowSum = JacobianG2BLS381.INFINITY;
            for (int j = numBuckets; j >= 1; j--) {
                runningSum = runningSum.add(buckets[w][j]);
                windowSum = windowSum.add(runningSum);
            }
            result = result.add(windowSum);
        }
        return result;
    }

    private static JacobianG1BLS381 computePiB_G1(Groth16ProvingKeyBLS381 pk,
            PippengerFlatBLS381.G1AffineReader b1Reader, G1MsmBackend backend, FlatScalars witness, BigInteger s) {
        var result = JacobianG1BLS381.fromAffine(pk.betaG1().x(), pk.betaG1().y());

        int n = Math.min(witness.count(), b1Reader.count());
        if (n > 0) {
            result = result.add(backend.msm(b1Reader, n, witness.slice(0, n)));
        }

        result = result.add(JacobianG1BLS381.fromAffine(pk.deltaG1().x(), pk.deltaG1().y()).scalarMul(s));
        return result;
    }

    private static JacobianG1BLS381 computePiC(
            Groth16ProvingKeyBLS381 pk, PippengerFlatBLS381.G1AffineReader hReader,
            PippengerFlatBLS381.G1AffineReader lReader, G1MsmBackend backend, FlatScalars hCoeffs, FlatScalars witness,
            BigInteger r, BigInteger s,
            JacobianG1BLS381 piA, JacobianG1BLS381 piB1) {

        JacobianG1BLS381 result = JacobianG1BLS381.INFINITY;

        int hLen = Math.min(hCoeffs.count(), hReader.count());
        if (hLen > 0) {
            result = result.add(backend.msm(hReader, hLen, hCoeffs.slice(0, hLen)));
        }

        int numPrivate = witness.count() - pk.numPublic() - 1;
        if (numPrivate > 0 && lReader.count() > 0) {
            int lLen = Math.min(numPrivate, lReader.count());
            result = result.add(backend.msm(lReader, lLen, witness.slice(pk.numPublic() + 1, lLen)));
        }

        result = result.add(piA.scalarMul(s));
        result = result.add(piB1.scalarMul(r));

        BigInteger rs = r.multiply(s).mod(MontFr381.modulus());
        result = result.add(
                JacobianG1BLS381.fromAffine(pk.deltaG1().x(), pk.deltaG1().y()).scalarMul(rs).negate());

        return result;
    }

    private static MontFr381 evalLinComb(Map<Integer, BigInteger> lc, BigInteger[] witness, BigInteger mod) {
        MontFr381 sum = MontFr381.ZERO;
        for (var entry : lc.entrySet()) {
            int wire = requireWire(entry.getKey(), witness.length);
            BigInteger coeff = entry.getValue();
            if (coeff.signum() != 0) {
                sum = sum.add(MontFr381.fromBigInteger(coeff).mul(MontFr381.fromBigInteger(witness[wire])));
            }
        }
        return sum;
    }

    /**
     * Fail closed on a wire outside {@code [0, bound)} (issue #46). Relations are validated at
     * ingress; this keeps the evaluation loops themselves incapable of skipping a term.
     */
    private static int requireWire(int wire, int bound) {
        if (wire < 0 || wire >= bound) {
            throw new IllegalArgumentException("R1CS term references wire " + wire
                    + " outside [0, " + bound + ")");
        }
        return wire;
    }

    /** The FFT domain must be a power of two that holds every evaluated row (issue #46). */
    private static void requireFftDomain(int domainSize, long rows) {
        if (domainSize < 2 || Integer.bitCount(domainSize) != 1) {
            throw new IllegalArgumentException("domainSize must be a power of two >= 2 (got " + domainSize + ")");
        }
        if (rows > domainSize) {
            throw new IllegalArgumentException("relation has " + rows + " rows but the FFT domain holds "
                    + domainSize + " — the constraints do not belong to this proving key");
        }
    }

    /**
     * The witness and H vectors must match the proving key exactly (issue #46). The MSMs used to
     * run over {@code min(vector, key)} points and silently ignore the remainder of either side.
     */
    private static void requireKeyDimensions(Groth16ProvingKeyBLS381 pk, G1Readers readers,
                                             G2AffineReader b2, FlatScalars witness, FlatScalars hCoeffs) {
        int n = witness.count();
        if (n == 0) throw new IllegalArgumentException("Witness must not be empty");
        if (pk.numPublic() < 0 || pk.numPublic() >= n) {
            throw new IllegalArgumentException("proving key numPublic (" + pk.numPublic()
                    + ") must be in [0, witness count " + n + ")");
        }
        requireCount("A", readers.a().count(), n, "witness scalars");
        requireCount("B1", readers.b1().count(), n, "witness scalars");
        requireCount("B2", b2.count(), n, "witness scalars");
        requireCount("L", readers.l().count(), n - pk.numPublic() - 1, "private witness scalars");
        requireCount("H", readers.h().count(), hCoeffs.count(), "H coefficients");
    }

    private static void requireCount(String points, int have, int expected, String what) {
        if (have != expected) {
            throw new IllegalArgumentException("proving key has " + have + " " + points + " points but there are "
                    + expected + " " + what + " — the witness/relation does not belong to this key");
        }
    }

    private static BigInteger randomScalar(SecureRandom rng) {
        byte[] bytes = new byte[64];
        rng.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(MontFr381.modulus());
    }
}
