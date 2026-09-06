package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.crypto.msm.FlatScalars;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * <b>TEST FIXTURE — NOT ZERO-KNOWLEDGE.</b> Deterministic Groth16 proving with the blinders fixed
 * to {@code r = s = 0} (ADR-0046, issue #50).
 *
 * <p>With {@code r = s = 0} and witness values {@code a_i} the proof is
 * {@code A = [alpha + sum_i a_i u_i(tau)]_1}, {@code B = [beta + sum_i a_i v_i(tau)]_2},
 * {@code C = [(sum_{i>l} a_i (beta u_i + alpha v_i + w_i)(tau) + h(tau) t(tau)) / delta]_1}:
 * a deterministic function of the proving key and the <i>full</i> witness. Two proofs of the same
 * witness are byte-identical, proofs of different witnesses are distinguishable, and the Groth16
 * zero-knowledge simulator (Groth, EUROCRYPT 2016, §3.2), which relies on uniformly random
 * {@code r, s}, does not apply. A proof from this type must never leave a test process.</p>
 *
 * <p>This is the only code in ZeroJ that fixes the Groth16 blinders. It lives in the
 * {@code zeroj-crypto} <i>test-fixtures</i> source set, which is never published, and reaches the
 * prover through the package-private {@code BlinderSource} seam of
 * {@code Groth16ProverBLS381.proveBlinded} with a source that yields {@code (0, 0)} exactly once —
 * so it must stay in this package. Its purpose is byte-equality differential testing (heap vs mmap
 * readers, dense vs sparse store, pure-Java vs blst MSM, serial vs parallel MSM), where both sides
 * need the same {@code (r, s)}. ADR-0046 records the boundary and what enforces it. Use
 * {@link Groth16ProverBLS381#prove} or {@link Groth16Keys#prove} for every real proof.</p>
 */
public final class Groth16UnblindedTestProver {

    private Groth16UnblindedTestProver() {}

    /**
     * Deterministic unblinded prove ({@code r = s = 0}) with a reader-supplied key and MSM backend.
     * Runs the same relation validation as the public prove paths (issue #46, via
     * {@link Groth16ProverBLS381#computeH}) and fails closed with {@link IllegalStateException} if
     * a proof point would be the point at infinity (ADR-0045 P2): the blinder source refuses the
     * resample that {@code proveBlinded} would otherwise request.
     *
     * @return a proof that verifies against {@code pk}'s verification key but has <b>no</b>
     *         zero-knowledge property
     */
    public static Groth16ProofBLS381 proveUnblinded(
            Groth16ProvingKeyBLS381 pk, Groth16ProverBLS381.G1Readers readers, ProverBackend backend,
            BigInteger[] witness, List<R1CSConstraint> constraints, int domainSize) {
        BigInteger[] hCoeffs = Groth16ProverBLS381.computeH(constraints, witness, constraints.size(), domainSize);
        return Groth16ProverBLS381.proveBlinded(pk, readers, backend,
                FlatScalars.pack(witness, witness.length), FlatScalars.pack(hCoeffs, hCoeffs.length),
                zeroBlindersOnce());
    }

    /**
     * {@code (0, 0)} exactly once. {@code proveBlinded} draws again only when a proof point was the
     * point at infinity; this source then throws, so the deterministic path fails closed instead
     * of resampling (ADR-0045 P2).
     */
    static Groth16ProverBLS381.BlinderSource zeroBlindersOnce() {
        var drawn = new AtomicBoolean();
        return () -> {
            if (drawn.getAndSet(true)) {
                throw new IllegalStateException("Groth16 prove aborted: a proof point is the point at infinity for"
                        + " the fixed blinders (r, s) = (0, 0) of this deterministic test path, which every"
                        + " verifier profile rejects (ADR-0045 P2); the unblinded test prover does not resample");
            }
            return new BigInteger[]{BigInteger.ZERO, BigInteger.ZERO};
        };
    }
}
