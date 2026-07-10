package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianArith381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.FrArith381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;
import com.bloxbean.cardano.zeroj.crypto.poly.FrFFTFlat;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Groth16 Phase 2 setup for BLS12-381 — generates a proving key from R1CS constraints + Powers of Tau SRS.
 *
 * <p><b>FOR DEVELOPMENT AND TESTING ONLY.</b> This is a single-party setup — the toxic
 * waste (alpha, beta, gamma, delta, tau) is known to one party. For production, use
 * snarkjs multi-party ceremony: {@code snarkjs groth16 setup circuit.r1cs pot.ptau circuit.zkey}.</p>
 *
 * <p>Algorithm (from Groth16 paper, Section 3.2):</p>
 * <ol>
 *   <li>Sample random alpha, beta, gamma, delta</li>
 *   <li>Compute Lagrange basis evaluations L_i(tau) for each constraint row</li>
 *   <li>For each wire s, compute QAP polynomials u_s(tau), v_s(tau), w_s(tau)</li>
 *   <li>Compute proving key points via scalar multiplication on G1/G2 generators</li>
 *   <li>Compute H points as odd-indexed Lagrange basis on double-sized domain / delta</li>
 * </ol>
 */
public final class Groth16SetupBLS381 {

    private Groth16SetupBLS381() {}

    private static final BigInteger FR = MontFr381.modulus();

    /**
     * Generate a Groth16 proving key from R1CS constraints and known tau.
     *
     * <p><b>FOR DEVELOPMENT AND TESTING ONLY.</b></p>
     *
     * @param constraints R1CS constraints (A*w x B*w = C*w)
     * @param numWires    total wire count
     * @param numPublic   number of public inputs (wires 1..numPublic)
     * @param tau         the toxic waste from PowersOfTauBLS381 (KNOWN — dev/test only)
     * @return Groth16 proving key ready for Groth16ProverBLS381.prove()
     */
    public static SetupResult setup(List<R1CSConstraint> constraints, int numWires,
                                     int numPublic, BigInteger tau) {
        var rng = new SecureRandom();
        return setup(constraints, numWires, numPublic, tau,
                randomScalar(rng), randomScalar(rng), randomScalar(rng), randomScalar(rng));
    }

    /**
     * {@link #setup(List, int, int, BigInteger)} with explicit phase-2 randomness —
     * <b>deterministic; differential tests only</b> (the streaming setup must byte-equal this
     * path's saved store for fixed randomness, ADR-0035 M3).
     */
    public static SetupResult setup(List<R1CSConstraint> constraints, int numWires,
                                     int numPublic, BigInteger tau,
                                     BigInteger alpha, BigInteger beta, BigInteger gamma, BigInteger delta) {
        TrustedSetupPolicy.requireInsecureTrustedSetupEnabled();
        System.err.println("WARNING: Single-party Groth16 Phase 2 setup (BLS12-381) — "
                + "for DEVELOPMENT and TESTING only. "
                + "Use snarkjs multi-party ceremony for production.");

        int nConstraints = constraints.size();

        // Domain size: next power of 2 >= nConstraints
        int domainSize = Integer.highestOneBit(nConstraints);
        if (domainSize < nConstraints) domainSize <<= 1;
        if (domainSize < 4) domainSize = 4;
        int logN = Integer.numberOfTrailingZeros(domainSize);

        BigInteger gammaInv = gamma.modInverse(FR);
        BigInteger deltaInv = delta.modInverse(FR);

        // Compute omega (primitive domainSize-th root of unity)
        MontFr381 omega = FieldFFTBLS381.rootOfUnity(logN);

        // Compute Lagrange basis evaluations at tau: L_i(tau) = (tau^N - 1) / (N * (tau - omega^i))
        BigInteger tauN = tau.modPow(BigInteger.valueOf(domainSize), FR);
        BigInteger zh = tauN.subtract(BigInteger.ONE).mod(FR); // tau^N - 1
        BigInteger nInv = BigInteger.valueOf(domainSize).modInverse(FR);

        // ADR-0029 M5a: the Lagrange evaluations L_i(tau) are independent but each needs a modInverse
        // (the dominant sequential setup cost — domainSize of them). Precompute omega^i sequentially
        // (cheap Fr mults, the only serial dependency), then compute all L_i in parallel.
        BigInteger omegaBi = omega.toBigInteger();
        BigInteger[] omegaPows = new BigInteger[domainSize];
        omegaPows[0] = BigInteger.ONE;
        for (int i = 1; i < domainSize; i++) omegaPows[i] = omegaPows[i - 1].multiply(omegaBi).mod(FR);
        final BigInteger zhNInv = zh.multiply(nInv).mod(FR);
        final BigInteger[] lagrange = new BigInteger[domainSize];
        java.util.stream.IntStream.range(0, domainSize).parallel().forEach(i -> {
            // L_i(tau) = omega^i * (tau^N - 1) / (N * (tau - omega^i))
            BigInteger diff = tau.subtract(omegaPows[i]).mod(FR);
            lagrange[i] = (diff.signum() == 0) ? BigInteger.ONE
                    : omegaPows[i].multiply(zhNInv).mod(FR).multiply(diff.modInverse(FR)).mod(FR);
        });

        // For each wire s, compute u_s(tau), v_s(tau), w_s(tau)
        // u_s = sum_c A_c[s] * L_c(tau), etc.
        BigInteger[] us = new BigInteger[numWires];
        BigInteger[] vs = new BigInteger[numWires];
        BigInteger[] ws = new BigInteger[numWires];
        Arrays.fill(us, BigInteger.ZERO);
        Arrays.fill(vs, BigInteger.ZERO);
        Arrays.fill(ws, BigInteger.ZERO);

        for (int c = 0; c < nConstraints && c < domainSize; c++) {
            var constraint = constraints.get(c);
            BigInteger lc = lagrange[c];
            accumulate(us, constraint.a(), lc);
            accumulate(vs, constraint.b(), lc);
            accumulate(ws, constraint.c(), lc);
        }

        // Compute group elements
        var g1 = JacobianG1BLS381.GENERATOR;
        var g2 = JacobianG2BLS381.GENERATOR;

        AffineG1 alphaG1 = FixedBaseG1BLS381.mulAffine(alpha);
        AffineG1 betaG1 = FixedBaseG1BLS381.mulAffine(beta);
        AffineG2 betaG2 = g2.scalarMul(beta).toAffine();
        AffineG1 deltaG1 = FixedBaseG1BLS381.mulAffine(delta);
        AffineG2 deltaG2 = g2.scalarMul(delta).toAffine();

        // ADR-0029 M5a: the per-wire scalar-muls are independent (each writes its own slot), so run
        // them in parallel across cores. This — not blst — is the setup-time lever: blst's speedup is
        // batched pippenger (a sum), but these are independent muls, and per-op blst is a wash.

        // pointsA[s] = u_s(tau) * G1  (flat: 12 longs/point)
        long[] pointsA = new long[numWires * Groth16ProvingKeyBLS381.G1_STRIDE];
        java.util.stream.IntStream.range(0, numWires).parallel().forEach(s ->
                Groth16ProvingKeyBLS381.writeG1(pointsA, s,
                        us[s].signum() == 0 ? AffineG1.INFINITY : FixedBaseG1BLS381.mulAffine(us[s])));

        // pointsB1[s] = v_s(tau) * G1  (flat)
        long[] pointsB1 = new long[numWires * Groth16ProvingKeyBLS381.G1_STRIDE];
        java.util.stream.IntStream.range(0, numWires).parallel().forEach(s ->
                Groth16ProvingKeyBLS381.writeG1(pointsB1, s,
                        vs[s].signum() == 0 ? AffineG1.INFINITY : FixedBaseG1BLS381.mulAffine(vs[s])));

        // pointsB2[s] = v_s(tau) * G2
        AffineG2[] pointsB2 = new AffineG2[numWires];
        java.util.stream.IntStream.range(0, numWires).parallel().forEach(s ->
                pointsB2[s] = vs[s].signum() == 0 ? AffineG2.INFINITY : g2.scalarMul(vs[s]).toAffine());

        // pointsL[j] = (beta*u_s + alpha*v_s + w_s) / delta * G1  for private wire s = numPublic+1+j
        // (final aliases: alpha/beta are scrubbed as toxic waste after the PK is built, below)
        final BigInteger alphaF = alpha, betaF = beta, deltaInvF = deltaInv;
        int numPrivate = numWires - numPublic - 1;
        long[] pointsL = new long[Math.max(0, numPrivate) * Groth16ProvingKeyBLS381.G1_STRIDE];
        java.util.stream.IntStream.range(0, numPrivate).parallel().forEach(j -> {
            int s = numPublic + 1 + j;
            BigInteger lVal = betaF.multiply(us[s]).add(alphaF.multiply(vs[s])).add(ws[s])
                    .multiply(deltaInvF).mod(FR);
            Groth16ProvingKeyBLS381.writeG1(pointsL, j,
                    lVal.signum() == 0 ? AffineG1.INFINITY : FixedBaseG1BLS381.mulAffine(lVal));
        });

        // H points: odd-indexed Lagrange basis on double-sized domain / delta
        // L_{2i+1}^{(2N)}(tau) / delta * G1
        int domainSize2 = 2 * domainSize;
        MontFr381 omega2 = FieldFFTBLS381.rootOfUnity(logN + 1); // primitive 2N-th root
        BigInteger omega2Bi = omega2.toBigInteger();
        BigInteger tauN2 = tau.modPow(BigInteger.valueOf(domainSize2), FR);
        BigInteger zh2 = tauN2.subtract(BigInteger.ONE).mod(FR);
        BigInteger nInv2 = BigInteger.valueOf(domainSize2).modInverse(FR);

        long[] pointsH = new long[domainSize * Groth16ProvingKeyBLS381.G1_STRIDE];
        final int domainSizeF = domainSize;
        java.util.stream.IntStream.range(0, domainSizeF).parallel().forEach(i -> {
            int lagIdx = 2 * i + 1; // odd index
            // omega2^lagIdx
            BigInteger omegaPow = omega2Bi.modPow(BigInteger.valueOf(lagIdx), FR);
            BigInteger diff = tau.subtract(omegaPow).mod(FR);
            BigInteger hLagrange;
            if (diff.signum() == 0) {
                hLagrange = BigInteger.ONE;
            } else {
                // L_{lagIdx}^{(2N)}(tau) = omega2^{lagIdx} * (tau^{2N} - 1) / (2N * (tau - omega2^{lagIdx}))
                hLagrange = omegaPow.multiply(zh2).mod(FR).multiply(nInv2).mod(FR)
                        .multiply(diff.modInverse(FR)).mod(FR);
            }
            BigInteger hVal = hLagrange.multiply(deltaInv).mod(FR);
            Groth16ProvingKeyBLS381.writeG1(pointsH, i,
                    hVal.signum() == 0 ? AffineG1.INFINITY : FixedBaseG1BLS381.mulAffine(hVal));
        });

        // Verification key components: gamma_G2 and IC points
        AffineG2 gammaG2 = g2.scalarMul(gamma).toAffine();

        // IC[s] = (beta*u_s + alpha*v_s + w_s) / gamma * G1  for public wires s = 0..numPublic
        AffineG1[] ic = new AffineG1[numPublic + 1];
        for (int s = 0; s <= numPublic; s++) {
            BigInteger icVal = beta.multiply(us[s]).add(alpha.multiply(vs[s])).add(ws[s])
                    .multiply(gammaInv).mod(FR);
            ic[s] = icVal.signum() == 0 ? AffineG1.INFINITY : FixedBaseG1BLS381.mulAffine(icVal);
        }

        // Securely discard toxic waste (best-effort — see PowersOfTauBLS381.java for caveats)
        alpha = beta = gamma = delta = BigInteger.ZERO;

        var pk = new Groth16ProvingKeyBLS381(
                alphaG1, betaG1, betaG2, deltaG1, deltaG2,
                pointsA, pointsB1, pointsB2, pointsH, pointsL, numPublic);

        return new SetupResult(pk, gammaG2, ic);
    }

    /**
     * Setup result containing both proving key and verification key components.
     *
     * @param provingKey the Groth16 proving key
     * @param gammaG2    gamma in G2 (needed for verification equation)
     * @param ic         input commitment points: IC[0] + sum(pub_i * IC[i+1])
     */
    public record SetupResult(
            Groth16ProvingKeyBLS381 provingKey,
            AffineG2 gammaG2,
            AffineG1[] ic
    ) {}

    // ==================================================================================
    // Streaming setup (ADR-0035 M2/M3): CSR constraints in, PkStore layout out — the QAP
    // evaluations live as flat Montgomery limbs and every point is written straight into
    // the mmap'd key files, so no output array is ever heap-resident.
    // ==================================================================================

    private static final long[] ONE_LIMBS = {1, 0, 0, 0};

    /**
     * {@link #setup(List, int, int, BigInteger)} over packed CSR constraints, streaming the
     * proving key straight into the {@code Groth16PkStore} layout at {@code dir} (ADR-0035
     * M2/M3). Output is byte-identical to {@code setup(...)} + {@code Groth16PkStore.save}
     * for the same randomness; peak heap is the flat QAP scalars (~4.2 GB at 43.7M wires)
     * instead of ~55 GB. The returned {@link SetupResult}'s proving key holds the single
     * points and <b>empty</b> big arrays (the store on disk is the key), like
     * {@code Groth16PkStore.load}.
     */
    public static SetupResult setupToStore(R1CSFlat flat,
                                           int numWires, int numPublic, BigInteger tau,
                                           Path dir) throws IOException {
        var rng = new SecureRandom();
        return setupToStore(flat, numWires, numPublic, tau,
                randomScalar(rng), randomScalar(rng), randomScalar(rng), randomScalar(rng), dir);
    }

    /** Deterministic {@link #setupToStore} — differential tests only. */
    public static SetupResult setupToStore(R1CSFlat flat,
                                           int numWires, int numPublic, BigInteger tau,
                                           BigInteger alpha, BigInteger beta, BigInteger gamma, BigInteger delta,
                                           Path dir) throws IOException {
        TrustedSetupPolicy.requireInsecureTrustedSetupEnabled();
        System.err.println("WARNING: Single-party Groth16 Phase 2 setup (BLS12-381, streaming) — "
                + "for DEVELOPMENT and TESTING only. "
                + "Use snarkjs multi-party ceremony for production.");

        int nConstraints = flat.rows();
        int domainSize = Integer.highestOneBit(nConstraints);
        if (domainSize < nConstraints) domainSize <<= 1;
        if (domainSize < 4) domainSize = 4;
        int logN = Integer.numberOfTrailingZeros(domainSize);
        final int domain = domainSize;

        BigInteger gammaInv = gamma.modInverse(FR);
        BigInteger deltaInv = delta.modInverse(FR);

        // ---- Lagrange basis L_i(tau) as flat Montgomery limbs; omega powers are walked
        //      per-chunk (omega^lo by modPow, then one multiply per step) — no boxed arrays.
        BigInteger omegaBi = FieldFFTBLS381.rootOfUnity(logN).toBigInteger();
        BigInteger tauN = tau.modPow(BigInteger.valueOf(domain), FR);
        BigInteger zhNInv = tauN.subtract(BigInteger.ONE).mod(FR)
                .multiply(BigInteger.valueOf(domain).modInverse(FR)).mod(FR);
        long[] lagMont = computeLagrangeMont(domain, tau, omegaBi, zhNInv);

        // ---- QAP evaluations u_s/v_s/w_s(tau) as flat Montgomery limbs (ADR-0035 M2):
        //      one pass over the CSR rows, dictionary Montgomery-converted once.
        BigInteger[] dictVals = flat.dictionary();
        long[] dictMont = new long[dictVals.length * 4];
        for (int i = 0; i < dictVals.length; i++)
            System.arraycopy(MontFr381.fromBigInteger(dictVals[i]).toLimbs(), 0, dictMont, i * 4, 4);

        long[] usM = new long[numWires * 4];
        long[] vsM = new long[numWires * 4];
        long[] wsM = new long[numWires * 4];
        var aM = flat.a();
        var bM = flat.b();
        var cM = flat.c();
        long[] lag = lagMont; // QAP loop reads via `lag`; lagMont is nulled after (−1 GB at point gen)
        long[] term = new long[4];
        int rows = Math.min(nConstraints, domain);
        for (int c = 0; c < rows; c++) {
            int lc = c * 4;
            for (int k = aM.start(c), e = aM.end(c); k < e; k++) {
                int w = aM.wire(k);
                if (w < numWires) {
                    FrArith381.mul(term, 0, dictMont, aM.coeffIndex(k) * 4, lag, lc);
                    FrArith381.add(usM, w * 4, usM, w * 4, term, 0);
                }
            }
            for (int k = bM.start(c), e = bM.end(c); k < e; k++) {
                int w = bM.wire(k);
                if (w < numWires) {
                    FrArith381.mul(term, 0, dictMont, bM.coeffIndex(k) * 4, lag, lc);
                    FrArith381.add(vsM, w * 4, vsM, w * 4, term, 0);
                }
            }
            for (int k = cM.start(c), e = cM.end(c); k < e; k++) {
                int w = cM.wire(k);
                if (w < numWires) {
                    FrArith381.mul(term, 0, dictMont, cM.coeffIndex(k) * 4, lag, lc);
                    FrArith381.add(wsM, w * 4, wsM, w * 4, term, 0);
                }
            }
        }
        lagMont = null; // main-domain Lagrange values are done — free ~1 GB before point generation

        // ---- single points + VK bits (tiny)
        var g2 = JacobianG2BLS381.GENERATOR;
        AffineG1 alphaG1 = FixedBaseG1BLS381.mulAffine(alpha);
        AffineG1 betaG1 = FixedBaseG1BLS381.mulAffine(beta);
        AffineG2 betaG2 = g2.scalarMul(beta).toAffine();
        AffineG1 deltaG1 = FixedBaseG1BLS381.mulAffine(delta);
        AffineG2 deltaG2 = g2.scalarMul(delta).toAffine();
        AffineG2 gammaG2 = g2.scalarMul(gamma).toAffine();

        long[] alphaMont = MontFr381.fromBigInteger(alpha).toLimbs();
        long[] betaMont = MontFr381.fromBigInteger(beta).toLimbs();
        long[] deltaInvMont = MontFr381.fromBigInteger(deltaInv).toLimbs();
        long[] gammaInvMont = MontFr381.fromBigInteger(gammaInv).toLimbs();

        // IC[s] = (beta*u_s + alpha*v_s + w_s) / gamma * G1 for public wires (numPublic+1 points)
        AffineG1[] ic = new AffineG1[numPublic + 1];
        {
            long[] t = new long[4], acc = new long[4], canon = new long[4];
            for (int s = 0; s <= numPublic; s++) {
                icLcMont(acc, t, usM, vsM, wsM, s, betaMont, alphaMont);
                FrArith381.mul(acc, 0, acc, 0, gammaInvMont, 0);
                FrArith381.mul(canon, 0, acc, 0, ONE_LIMBS, 0);
                ic[s] = (canon[0] | canon[1] | canon[2] | canon[3]) == 0 ? AffineG1.INFINITY
                        : FixedBaseG1BLS381.mulAffine(new BigInteger(1, beFromCanon(canon)));
            }
        }

        // ---- streamed point files (ADR-0035 M3): mapped READ_WRITE, pre-zeroed = infinity.
        //      All writers work in blocks with batched affine normalization (M4) — one field
        //      inversion per block instead of one per point.
        Files.createDirectories(dir);
        try (var arena = Arena.ofShared()) {
            var segA = mapOut(dir.resolve("pointsA.bin"), (long) numWires * 96, arena);
            streamG1(segA, numWires, (s, canon, scratch) -> {
                FrArith381.mul(canon, 0, usM, s * 4, ONE_LIMBS, 0);
                return (canon[0] | canon[1] | canon[2] | canon[3]) != 0;
            });
            segA.force();

            var segB1 = mapOut(dir.resolve("pointsB1.bin"), (long) numWires * 96, arena);
            streamG1(segB1, numWires, (s, canon, scratch) -> {
                FrArith381.mul(canon, 0, vsM, s * 4, ONE_LIMBS, 0);
                return (canon[0] | canon[1] | canon[2] | canon[3]) != 0;
            });
            segB1.force();

            // pointsB2[s] = v_s(tau) * G2 — comb table + batched Fp2 normalization (M4);
            // BE coords, same layout as PkStore.putG2
            var segB2 = mapOut(dir.resolve("pointsB2.bin"), (long) numWires * 192, arena);
            FrFFTFlat.parallelRange(numWires, (lo, hi) -> {
                long[] canon = new long[4];
                byte[] coord = new byte[48];
                JacobianG2BLS381[] block = new JacobianG2BLS381[BATCH];
                int[] slot = new int[BATCH];
                for (int base = lo; base < hi; base += BATCH) {
                    int end = Math.min(base + BATCH, hi);
                    int k = 0;
                    for (int s = base; s < end; s++) {
                        FrArith381.mul(canon, 0, vsM, s * 4, ONE_LIMBS, 0);
                        JacobianG2BLS381 p = FixedBaseG2BLS381.mulJacobian(canon, 0);
                        if (p == null) continue; // infinity = zeros in the mapped file
                        block[k] = p;
                        slot[k] = s;
                        k++;
                    }
                    AffineG2[] aff = JacobianG2BLS381.batchToAffine(block, k);
                    for (int j = 0; j < k; j++) {
                        long o = slot[j] * 192L;
                        putBe48(segB2, o, aff[j].x().re().toBigInteger(), coord);
                        putBe48(segB2, o + 48, aff[j].x().im().toBigInteger(), coord);
                        putBe48(segB2, o + 96, aff[j].y().re().toBigInteger(), coord);
                        putBe48(segB2, o + 144, aff[j].y().im().toBigInteger(), coord);
                    }
                }
            });
            segB2.force();

            // pointsL[j] = (beta*u_s + alpha*v_s + w_s)/delta * G1, s = numPublic+1+j
            int numPrivate = Math.max(0, numWires - numPublic - 1);
            var segL = mapOut(dir.resolve("pointsL.bin"), (long) numPrivate * 96, arena);
            final int npub = numPublic;
            streamG1(segL, numPrivate, (j, canon, scratch) -> {
                // scratch8: [0..4) = acc, [4..8) = t — per-chunk, no shared state (thread-safe)
                int s = npub + 1 + j;
                FrArith381.mul(scratch, 0, betaMont, 0, usM, s * 4);
                FrArith381.mul(scratch, 4, alphaMont, 0, vsM, s * 4);
                FrArith381.add(scratch, 0, scratch, 0, scratch, 4);
                FrArith381.add(scratch, 0, scratch, 0, wsM, s * 4);
                FrArith381.mul(scratch, 0, scratch, 0, deltaInvMont, 0);
                FrArith381.mul(canon, 0, scratch, 0, ONE_LIMBS, 0);
                return (canon[0] | canon[1] | canon[2] | canon[3]) != 0;
            });
            segL.force();
            // QAP arrays done (H needs none of them) — scrub: they are tau-derived secrets
            Arrays.fill(usM, 0L);
            Arrays.fill(vsM, 0L);
            Arrays.fill(wsM, 0L);

            // pointsH[i] = L_{2i+1}^{(2N)}(tau)/delta * G1 — per-chunk omega2 walk, batched
            // inversions (M4)
            MontFr381 omega2 = FieldFFTBLS381.rootOfUnity(logN + 1);
            BigInteger omega2Bi = omega2.toBigInteger();
            BigInteger omega2Sq = omega2Bi.multiply(omega2Bi).mod(FR);
            BigInteger tauN2 = tau.modPow(BigInteger.valueOf(2L * domain), FR);
            BigInteger zh2NInv2 = tauN2.subtract(BigInteger.ONE).mod(FR)
                    .multiply(BigInteger.valueOf(2L * domain).modInverse(FR)).mod(FR);
            var segH = mapOut(dir.resolve("pointsH.bin"), (long) domain * 96, arena);
            FrFFTFlat.parallelRange(domain, (lo, hi) -> {
                long[] canon = new long[BATCH * 4];
                long[] jacBlock = new long[BATCH * 18];
                long[] affBlock = new long[BATCH * 12];
                boolean[] present = new boolean[BATCH];
                long[] scr = new long[JacobianArith381.SCRATCH_LONGS];
                BigInteger[] omPows = new BigInteger[BATCH];
                BigInteger[] diffs = new BigInteger[BATCH];
                BigInteger[] invs = new BigInteger[BATCH];
                BigInteger omPow = omega2Bi.modPow(BigInteger.valueOf(2L * lo + 1), FR);
                for (int base = lo; base < hi; base += BATCH) {
                    int m = Math.min(BATCH, hi - base);
                    boolean zeroDiff = false;
                    for (int k = 0; k < m; k++) {
                        omPows[k] = omPow;
                        diffs[k] = tau.subtract(omPow).mod(FR);
                        if (diffs[k].signum() == 0) zeroDiff = true;
                        omPow = omPow.multiply(omega2Sq).mod(FR);
                    }
                    if (!zeroDiff) batchModInverse(diffs, invs, m);
                    for (int k = 0; k < m; k++) {
                        BigInteger hLagrange = diffs[k].signum() == 0 ? BigInteger.ONE
                                : omPows[k].multiply(zh2NInv2).mod(FR)
                                        .multiply(zeroDiff ? diffs[k].modInverse(FR) : invs[k]).mod(FR);
                        BigInteger hVal = hLagrange.multiply(deltaInv).mod(FR);
                        System.arraycopy(MontFr381.fromBigInteger(hVal).toLimbs(), 0, canon, k * 4, 4);
                        FrArith381.mul(canon, k * 4, canon, k * 4, ONE_LIMBS, 0);
                        present[k] = FixedBaseG1BLS381.mulJacobianLimbs(canon, k * 4, jacBlock, k * 18, scr);
                    }
                    FixedBaseG1BLS381.batchNormalize(jacBlock, m, present, affBlock);
                    for (int k = 0; k < m; k++)
                        if (present[k])
                            MemorySegment.copy(affBlock, k * 12, segH, ValueLayout.JAVA_LONG, (base + k) * 96L, 12);
                }
            });
            segH.force();
        }

        Groth16PkStore.writeAuxAndManifest(
                dir, alphaG1, betaG1, deltaG1, betaG2, deltaG2, gammaG2, ic,
                numPublic, numWires, domain);

        // empty-array PK (the store on disk is the key), like Groth16PkStore.load
        long[] empty = new long[0];
        var pk = new Groth16ProvingKeyBLS381(alphaG1, betaG1, betaG2, deltaG1, deltaG2,
                empty, empty, new AffineG2[0], empty, empty, numPublic);
        return new SetupResult(pk, gammaG2, ic);
    }

    /** acc = beta*u_s + alpha*v_s + w_s (Montgomery). */
    private static void icLcMont(long[] acc, long[] t, long[] usM, long[] vsM, long[] wsM,
                                 int s, long[] betaMont, long[] alphaMont) {
        FrArith381.mul(acc, 0, betaMont, 0, usM, s * 4);
        FrArith381.mul(t, 0, alphaMont, 0, vsM, s * 4);
        FrArith381.add(acc, 0, acc, 0, t, 0);
        FrArith381.add(acc, 0, acc, 0, wsM, s * 4);
    }

    /** Block size for batched normalization / batched inversion (ADR-0035 M4). */
    private static final int BATCH = 512;

    /**
     * Lagrange basis {@code L_i(tau)} for the whole domain as flat Montgomery limbs: per-chunk
     * omega walks (one {@code modPow} per chunk) and per-block batched inversions (ADR-0035 M4).
     */
    private static long[] computeLagrangeMont(int domain, BigInteger tau, BigInteger omegaBi, BigInteger zhNInv) {
        long[] lagMont = new long[domain * 4];
        FrFFTFlat.parallelRange(domain, (lo, hi) -> {
            BigInteger om = omegaBi.modPow(BigInteger.valueOf(lo), FR);
            BigInteger[] oms = new BigInteger[BATCH];
            BigInteger[] diffs = new BigInteger[BATCH];
            BigInteger[] invs = new BigInteger[BATCH];
            for (int base = lo; base < hi; base += BATCH) {
                int m = Math.min(BATCH, hi - base);
                boolean zeroDiff = false;
                for (int k = 0; k < m; k++) {
                    oms[k] = om;
                    diffs[k] = tau.subtract(om).mod(FR);
                    if (diffs[k].signum() == 0) zeroDiff = true;
                    om = om.multiply(omegaBi).mod(FR);
                }
                if (!zeroDiff) batchModInverse(diffs, invs, m);
                for (int k = 0; k < m; k++) {
                    BigInteger li = diffs[k].signum() == 0 ? BigInteger.ONE
                            : oms[k].multiply(zhNInv).mod(FR)
                                    .multiply(zeroDiff ? diffs[k].modInverse(FR) : invs[k]).mod(FR);
                    System.arraycopy(MontFr381.fromBigInteger(li).toLimbs(), 0, lagMont, (base + k) * 4, 4);
                }
            }
        });
        return lagMont;
    }

    /**
     * Produces point {@code s}'s canonical scalar limbs; false for a zero scalar. Called from
     * multiple chunks concurrently — implementations must keep all state in {@code scratch8}
     * (per-chunk, caller-provided), never in captured mutable fields.
     */
    private interface ScalarAt {
        boolean canon(int s, long[] canonOut4, long[] scratch8);
    }

    /**
     * Stream {@code point[s] = scalar(s)·G1} into a mapped segment (12 native-order longs/point)
     * in blocks: comb multiplications in Jacobian form, then ONE batched normalization per block
     * (ADR-0035 M4) instead of a field inversion per point.
     */
    private static void streamG1(MemorySegment seg, int n, ScalarAt scalars) {
        FrFFTFlat.parallelRange(n, (lo, hi) -> {
            long[] canon = new long[4];
            long[] scratch8 = new long[8];
            long[] jacBlock = new long[BATCH * 18];
            long[] affBlock = new long[BATCH * 12];
            boolean[] present = new boolean[BATCH];
            long[] scr = new long[JacobianArith381.SCRATCH_LONGS];
            for (int base = lo; base < hi; base += BATCH) {
                int m = Math.min(BATCH, hi - base);
                for (int k = 0; k < m; k++) {
                    present[k] = scalars.canon(base + k, canon, scratch8)
                            && FixedBaseG1BLS381.mulJacobianLimbs(canon, 0, jacBlock, k * 18, scr);
                }
                FixedBaseG1BLS381.batchNormalize(jacBlock, m, present, affBlock);
                for (int k = 0; k < m; k++)
                    if (present[k])
                        MemorySegment.copy(affBlock, k * 12, seg, ValueLayout.JAVA_LONG, (base + k) * 96L, 12);
            }
        });
    }

    /**
     * {@code dst[i] = src[i]^{-1} mod r} for {@code n} nonzero values with ONE {@code modInverse}
     * total (Montgomery's trick, ADR-0035 M4).
     */
    private static void batchModInverse(BigInteger[] src, BigInteger[] dst, int n) {
        BigInteger[] prefix = new BigInteger[n];
        BigInteger acc = BigInteger.ONE;
        for (int i = 0; i < n; i++) {
            acc = acc.multiply(src[i]).mod(FR);
            prefix[i] = acc;
        }
        BigInteger inv = acc.modInverse(FR);
        for (int i = n - 1; i >= 0; i--) {
            dst[i] = i == 0 ? inv : inv.multiply(prefix[i - 1]).mod(FR);
            inv = inv.multiply(src[i]).mod(FR);
        }
    }

    private static MemorySegment mapOut(Path p, long size, Arena arena) throws IOException {
        try (var ch = FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.READ,
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            return ch.map(FileChannel.MapMode.READ_WRITE, 0, size, arena);
        }
    }

    /** Canonical BE bytes of 4 LE limbs (for BigInteger interop). */
    private static byte[] beFromCanon(long[] canon) {
        byte[] be = new byte[32];
        for (int j = 0; j < 4; j++) {
            long l = canon[j];
            int o = 24 - j * 8;
            for (int k = 0; k < 8; k++) be[o + 7 - k] = (byte) (l >>> (8 * k));
        }
        return be;
    }

    /** canonical BigInteger → 48-byte BE at {@code off} (the PkStore G2 coordinate encoding). */
    private static void putBe48(MemorySegment seg, long off, BigInteger v, byte[] scratch48) {
        Arrays.fill(scratch48, (byte) 0);
        byte[] be = v.toByteArray();
        int s = Math.max(0, be.length - 48), len = be.length - s;
        System.arraycopy(be, s, scratch48, 48 - len, len);
        MemorySegment.copy(scratch48, 0, seg, ValueLayout.JAVA_BYTE, off, 48);
    }

    private static void accumulate(BigInteger[] target, Map<Integer, BigInteger> sparse, BigInteger lagrange) {
        for (var entry : sparse.entrySet()) {
            int wire = entry.getKey();
            if (wire < target.length) {
                target[wire] = target[wire].add(entry.getValue().multiply(lagrange)).mod(FR);
            }
        }
    }

    private static BigInteger randomScalar(SecureRandom rng) {
        byte[] bytes = new byte[64];
        rng.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(FR);
    }
}
