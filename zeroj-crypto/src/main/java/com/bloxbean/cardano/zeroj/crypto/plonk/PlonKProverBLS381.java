package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.kzg.KZGCommitmentBLS381;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;
import com.bloxbean.cardano.zeroj.crypto.transcript.FiatShamirTranscript;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Pure Java PlonK prover for BLS12-381 (snarkjs-compatible, 5-round protocol).
 *
 * <p>Produces proofs verifiable by the existing {@code PlonkBLS381Verifier}.</p>
 *
 * <h3>Protocol rounds</h3>
 * <ol>
 *   <li>Round 1: Commit to wire polynomials a(X), b(X), c(X) with blinding</li>
 *   <li>Round 2: Compute permutation accumulator Z(X), commit</li>
 *   <li>Round 3: Compute quotient t(X) = (gate + alpha*perm + alpha^2*start) / Z_H, commit T1/T2/T3</li>
 *   <li>Round 4: Evaluate polynomials at challenge zeta</li>
 *   <li>Round 5: Compute batched KZG opening proofs at zeta and zeta*omega</li>
 * </ol>
 */
public final class PlonKProverBLS381 {

    private PlonKProverBLS381() {}

    private static final BigInteger FR = MontFr381.modulus();
    private static final int MIN_DOMAIN_SIZE = 8;
    private static final int MAX_DOMAIN_POWER = 24;

    private enum TranscriptEncoding {
        UNCOMPRESSED_AFFINE,
        COMPRESSED_G1
    }

    /**
     * Generate a PlonK proof.
     *
     * @param pk       PlonK proving key (from setup)
     * @param wireA    wire values for column A per constraint row
     * @param wireB    wire values for column B per constraint row
     * @param wireC    wire values for column C per constraint row
     * @param pubInputs public input values (for PI polynomial)
     * @return PlonK proof with 9 commitments + 6 evaluations
     */
    public static PlonKProofBLS381 prove(PlonKProvingKeyBLS381 pk, MontFr381[] wireA, MontFr381[] wireB,
                                    MontFr381[] wireC, BigInteger[] pubInputs) {
        return prove(pk, wireA, wireB, wireC, pubInputs, new SecureRandom());
    }

    /**
     * Generate a PlonK proof using a caller-supplied CSPRNG for blinding
     * scalars. Production callers can use this overload to provide an approved
     * or externally managed {@link SecureRandom} instance.
     */
    public static PlonKProofBLS381 prove(PlonKProvingKeyBLS381 pk, MontFr381[] wireA, MontFr381[] wireB,
                                    MontFr381[] wireC, BigInteger[] pubInputs, SecureRandom rng) {
        if (rng == null) {
            throw new IllegalArgumentException("SecureRandom must not be null");
        }
        MontFr381[] b = new MontFr381[9];
        for (int i = 0; i < 9; i++) b[i] = randomFr(rng);
        return proveInternal(pk, wireA, wireB, wireC, pubInputs, b, TranscriptEncoding.UNCOMPRESSED_AFFINE);
    }

    /**
     * Generate a PlonK proof for the ZeroJ Cardano on-chain verifier profile.
     *
     * <p>The arithmetic is identical to {@link #prove(PlonKProvingKeyBLS381, MontFr381[], MontFr381[], MontFr381[], BigInteger[])},
     * but Fiat-Shamir G1 transcript entries use canonical compressed BLS12-381
     * encodings. That lets the on-chain verifier bind the exact bytes it
     * uncompresses and uses for BLS builtins.</p>
     */
    public static PlonKProofBLS381 proveCardano(PlonKProvingKeyBLS381 pk, MontFr381[] wireA, MontFr381[] wireB,
                                           MontFr381[] wireC, BigInteger[] pubInputs) {
        return proveCardano(pk, wireA, wireB, wireC, pubInputs, new SecureRandom());
    }

    /**
     * Generate a Cardano-profile PlonK proof using a caller-supplied CSPRNG for
     * blinding scalars.
     */
    public static PlonKProofBLS381 proveCardano(PlonKProvingKeyBLS381 pk, MontFr381[] wireA, MontFr381[] wireB,
                                           MontFr381[] wireC, BigInteger[] pubInputs, SecureRandom rng) {
        if (rng == null) {
            throw new IllegalArgumentException("SecureRandom must not be null");
        }
        MontFr381[] b = new MontFr381[9];
        for (int i = 0; i < 9; i++) b[i] = randomFr(rng);
        return proveInternal(pk, wireA, wireB, wireC, pubInputs, b, TranscriptEncoding.COMPRESSED_G1);
    }

    /** Prove without blinding (for debugging). */
    static PlonKProofBLS381 proveUnblinded(PlonKProvingKeyBLS381 pk, MontFr381[] wireA, MontFr381[] wireB,
                                      MontFr381[] wireC, BigInteger[] pubInputs) {
        MontFr381[] b = new MontFr381[9];
        for (int i = 0; i < 9; i++) b[i] = MontFr381.ZERO;
        return proveInternal(pk, wireA, wireB, wireC, pubInputs, b, TranscriptEncoding.UNCOMPRESSED_AFFINE);
    }

    private static PlonKProofBLS381 proveInternal(PlonKProvingKeyBLS381 pk, MontFr381[] wireA, MontFr381[] wireB,
                                             MontFr381[] wireC, BigInteger[] pubInputs, MontFr381[] b,
                                             TranscriptEncoding transcriptEncoding) {
        if (pk == null) {
            throw new IllegalArgumentException("proving key must not be null");
        }
        int n = pk.domainSize();
        int logN = Integer.numberOfTrailingZeros(n);
        MontFr381 omega = pk.omega();
        AffineG1[] srs = pk.srsG1();

        // --- Input validation ---
        validateProverInputs(pk, wireA, wireB, wireC, pubInputs, b);

        MontFr381[] aEvals = wireA;
        MontFr381[] bEvals = wireB;
        MontFr381[] cEvals = wireC;

        // === Round 1: Wire polynomial commitments ===
        var aCoeffs = FieldFFTBLS381.ifft(aEvals);
        var bCoeffs = FieldFFTBLS381.ifft(bEvals);
        var cCoeffs = FieldFFTBLS381.ifft(cEvals);

        // Add blinding: poly(X) += b1*X^n + b2*X^{n+1}
        var aBlind = addBlinding2(aCoeffs, b[0], b[1], n);
        var bBlind = addBlinding2(bCoeffs, b[2], b[3], n);
        var cBlind = addBlinding2(cCoeffs, b[4], b[5], n);

        var commitA = KZGCommitmentBLS381.commit(srs, aBlind).toAffine();
        var commitB = KZGCommitmentBLS381.commit(srs, bBlind).toAffine();
        var commitC = KZGCommitmentBLS381.commit(srs, cBlind).toAffine();

        // Fiat-Shamir: derive beta, gamma
        var transcript = new FiatShamirTranscript(FR, 32, 48);
        addG1(transcript, pk.qmCommit(), transcriptEncoding); addG1(transcript, pk.qlCommit(), transcriptEncoding);
        addG1(transcript, pk.qrCommit(), transcriptEncoding); addG1(transcript, pk.qoCommit(), transcriptEncoding);
        addG1(transcript, pk.qcCommit(), transcriptEncoding);
        addG1(transcript, pk.s1Commit(), transcriptEncoding); addG1(transcript, pk.s2Commit(), transcriptEncoding);
        addG1(transcript, pk.s3Commit(), transcriptEncoding);
        for (var pi : pubInputs) transcript.addScalar(pi);
        addG1(transcript, commitA, transcriptEncoding); addG1(transcript, commitB, transcriptEncoding);
        addG1(transcript, commitC, transcriptEncoding);
        BigInteger betaBi = transcript.getChallenge();
        MontFr381 beta = MontFr381.fromBigInteger(betaBi);

        transcript.reset(); transcript.addScalar(betaBi);
        BigInteger gammaBi = transcript.getChallenge();
        MontFr381 gamma = MontFr381.fromBigInteger(gammaBi);

        // === Round 2: Permutation accumulator Z(X) ===
        MontFr381 k1 = MontFr381.fromBigInteger(pk.k1());
        MontFr381 k2 = MontFr381.fromBigInteger(pk.k2());

        MontFr381[] zEvals = new MontFr381[n];
        zEvals[0] = MontFr381.ONE;
        MontFr381 wi = MontFr381.ONE;
        for (int i = 0; i < n - 1; i++) {
            var num = aEvals[i].add(beta.mul(wi)).add(gamma)
                    .mul(bEvals[i].add(beta.mul(k1).mul(wi)).add(gamma))
                    .mul(cEvals[i].add(beta.mul(k2).mul(wi)).add(gamma));
            var den = aEvals[i].add(beta.mul(pk.s1()[i])).add(gamma)
                    .mul(bEvals[i].add(beta.mul(pk.s2()[i])).add(gamma))
                    .mul(cEvals[i].add(beta.mul(pk.s3()[i])).add(gamma));
            zEvals[i + 1] = zEvals[i].mul(num).mul(den.inverse());
            wi = wi.mul(omega);
        }

        var zCoeffs = FieldFFTBLS381.ifft(zEvals);
        var zBlind = addBlinding3(zCoeffs, b[6], b[7], b[8], n);
        var commitZ = KZGCommitmentBLS381.commit(srs, zBlind).toAffine();

        transcript.reset(); transcript.addScalar(betaBi); transcript.addScalar(gammaBi);
        addG1(transcript, commitZ, transcriptEncoding);
        BigInteger alphaBi = transcript.getChallenge();
        MontFr381 alpha = MontFr381.fromBigInteger(alphaBi);
        MontFr381 alpha2 = alpha.mul(alpha);

        // === Pre-compute polynomial coefficient forms (used in Round 3 and Round 5) ===
        var qlCoeffs = FieldFFTBLS381.ifft(pk.ql());
        var qrCoeffs = FieldFFTBLS381.ifft(pk.qr());
        var qmCoeffs = FieldFFTBLS381.ifft(pk.qm());
        var qoCoeffs = FieldFFTBLS381.ifft(pk.qo());
        var qcCoeffs = FieldFFTBLS381.ifft(pk.qc());
        var s1Coeffs = FieldFFTBLS381.ifft(pk.s1());
        var s2Coeffs = FieldFFTBLS381.ifft(pk.s2());
        var s3Coeffs = FieldFFTBLS381.ifft(pk.s3());

        // === Round 3: Quotient polynomial t(X) via coset evaluation ===
        int n4 = 4 * n;
        int logN4 = Integer.numberOfTrailingZeros(n4);
        MontFr381 omega4 = FieldFFTBLS381.rootOfUnity(logN4);
        MontFr381 shift = MontFr381.fromLong(5); // multiplicative generator, not a root of unity

        // Evaluate all polynomials on the 4n coset
        var aCoset = cosetEval(aBlind, shift, n4, logN4);
        var bCoset = cosetEval(bBlind, shift, n4, logN4);
        var cCoset = cosetEval(cBlind, shift, n4, logN4);
        var zCoset = cosetEval(zBlind, shift, n4, logN4);

        var qlCoset = cosetEval(qlCoeffs, shift, n4, logN4);
        var qrCoset = cosetEval(qrCoeffs, shift, n4, logN4);
        var qmCoset = cosetEval(qmCoeffs, shift, n4, logN4);
        var qoCoset = cosetEval(qoCoeffs, shift, n4, logN4);
        var qcCoset = cosetEval(qcCoeffs, shift, n4, logN4);

        var s1Coset = cosetEval(s1Coeffs, shift, n4, logN4);
        var s2Coset = cosetEval(s2Coeffs, shift, n4, logN4);
        var s3Coset = cosetEval(s3Coeffs, shift, n4, logN4);

        // Z(X * omega) on coset: shift coefficients by omega
        var zOmegaCoeffs = shiftPoly(zBlind, omega);
        var zOmegaCoset = cosetEval(zOmegaCoeffs, shift, n4, logN4);

        // PI polynomial on coset
        var piCoeffs = buildPICoeffs(pubInputs, omega, n, logN);
        var piCoset = cosetEval(piCoeffs, shift, n4, logN4);

        // L1 polynomial on coset
        var l1Coeffs = buildL1Coeffs(omega, n, logN);
        var l1Coset = cosetEval(l1Coeffs, shift, n4, logN4);

        // Z_H on coset: Z_H(x) = x^n - 1
        // For coset point x_i = shift * omega4^i: Z_H(x_i) = (shift * omega4^i)^n - 1
        // = shift^n * (omega4^i)^n - 1 = shift^n * omega4^{in} - 1
        // Since omega4 is the 4n-th root: omega4^n = omega_{4n}^n = primitive 4th root of unity
        MontFr381 shiftN = powFr(shift, n); // shift^n (constant across all coset points)
        MontFr381 omega4N = powFr(omega4, n); // omega4^n = primitive 4th root of unity
        MontFr381[] zhCoset = new MontFr381[n4];
        MontFr381 omega4Ni = MontFr381.ONE; // (omega4^n)^i
        for (int i = 0; i < n4; i++) {
            zhCoset[i] = shiftN.mul(omega4Ni).sub(MontFr381.ONE);
            omega4Ni = omega4Ni.mul(omega4N);
        }

        // Precompute coset points: x_i = shift * omega4^i
        MontFr381[] cosetPoints = new MontFr381[n4];
        cosetPoints[0] = shift;
        for (int i = 1; i < n4; i++) cosetPoints[i] = cosetPoints[i - 1].mul(omega4);

        // Compute t(X) pointwise on the coset
        MontFr381[] tCoset = new MontFr381[n4];
        for (int i = 0; i < n4; i++) {
            var gate = qmCoset[i].mul(aCoset[i]).mul(bCoset[i])
                    .add(qlCoset[i].mul(aCoset[i]))
                    .add(qrCoset[i].mul(bCoset[i]))
                    .add(qoCoset[i].mul(cCoset[i]))
                    .add(qcCoset[i])
                    .add(piCoset[i]);

            MontFr381 xi = cosetPoints[i];

            var permNum = aCoset[i].add(beta.mul(xi)).add(gamma)
                    .mul(bCoset[i].add(beta.mul(k1).mul(xi)).add(gamma))
                    .mul(cCoset[i].add(beta.mul(k2).mul(xi)).add(gamma))
                    .mul(zCoset[i]);
            var permDen = aCoset[i].add(beta.mul(s1Coset[i])).add(gamma)
                    .mul(bCoset[i].add(beta.mul(s2Coset[i])).add(gamma))
                    .mul(cCoset[i].add(beta.mul(s3Coset[i])).add(gamma))
                    .mul(zOmegaCoset[i]);
            var perm = alpha.mul(permNum.sub(permDen));

            // Start constraint: alpha^2 * (z - 1) * L1
            var start = alpha2.mul(zCoset[i].sub(MontFr381.ONE)).mul(l1Coset[i]);

            // t(X) = (gate + perm + start) / Z_H
            tCoset[i] = gate.add(perm).add(start).mul(zhCoset[i].inverse());
        }

        // IFFT coset to get t(X) coefficients
        var tCoeffs = cosetIFFT(tCoset, shift, n4, logN4);

        // Split t into 3 parts: T1 (deg<n), T2 (deg<n), T3 (remaining — may be > n with blinding)
        var t1 = new MontFr381[n]; var t2 = new MontFr381[n];
        // T3 gets all remaining coefficients (degree 2n onwards) — may exceed n due to blinding
        int t3Len = Math.max(n, tCoeffs.length - 2 * n);
        var t3 = new MontFr381[t3Len];
        for (int i = 0; i < n; i++) {
            t1[i] = i < tCoeffs.length ? tCoeffs[i] : MontFr381.ZERO;
            t2[i] = i + n < tCoeffs.length ? tCoeffs[i + n] : MontFr381.ZERO;
        }
        for (int i = 0; i < t3Len; i++) {
            t3[i] = i + 2 * n < tCoeffs.length ? tCoeffs[i + 2 * n] : MontFr381.ZERO;
        }

        var commitT1 = KZGCommitmentBLS381.commit(srs, t1).toAffine();
        var commitT2 = KZGCommitmentBLS381.commit(srs, t2).toAffine();
        var commitT3 = KZGCommitmentBLS381.commit(srs, t3).toAffine();

        transcript.reset(); transcript.addScalar(alphaBi);
        addG1(transcript, commitT1, transcriptEncoding); addG1(transcript, commitT2, transcriptEncoding);
        addG1(transcript, commitT3, transcriptEncoding);
        BigInteger zetaBi = transcript.getChallenge();
        MontFr381 zeta = MontFr381.fromBigInteger(zetaBi);

        // === Round 4: Opening evaluations ===
        BigInteger evalA = FieldFFTBLS381.polyEval(aBlind, zeta).toBigInteger();
        BigInteger evalB = FieldFFTBLS381.polyEval(bBlind, zeta).toBigInteger();
        BigInteger evalC = FieldFFTBLS381.polyEval(cBlind, zeta).toBigInteger();

        // s1Coeffs, s2Coeffs already computed above
        BigInteger evalS1 = FieldFFTBLS381.polyEval(s1Coeffs, zeta).toBigInteger();
        BigInteger evalS2 = FieldFFTBLS381.polyEval(s2Coeffs, zeta).toBigInteger();

        MontFr381 zetaOmega = zeta.mul(omega);
        BigInteger evalZw = FieldFFTBLS381.polyEval(zBlind, zetaOmega).toBigInteger();

        transcript.reset(); transcript.addScalar(zetaBi);
        transcript.addScalar(evalA); transcript.addScalar(evalB); transcript.addScalar(evalC);
        transcript.addScalar(evalS1); transcript.addScalar(evalS2); transcript.addScalar(evalZw);
        BigInteger v1Bi = transcript.getChallenge();
        MontFr381 v1 = MontFr381.fromBigInteger(v1Bi);

        // === Round 5: Batched KZG opening proofs ===
        // W_zeta: opening of r(X) + v*a(X) + v^2*b(X) + v^3*c(X) + v^4*s1(X) + v^5*s2(X) at zeta
        // r(X) is the linearization polynomial

        // Build r(X) coefficient-form from the verification equation
        // r(X) = a_eval*b_eval*Qm(X) + a_eval*Ql(X) + b_eval*Qr(X) + c_eval*Qo(X) + Qc(X)
        //      + alpha * [(a_eval+beta*zeta+gamma)(b_eval+beta*k1*zeta+gamma)(c_eval+beta*k2*zeta+gamma)*Z(X)
        //               - (a_eval+beta*s1_eval+gamma)(b_eval+beta*s2_eval+gamma)*beta*zw_eval*S3(X)]
        //      + alpha^2 * L1(zeta) * Z(X)

        MontFr381 aEv = MontFr381.fromBigInteger(evalA);
        MontFr381 bEv = MontFr381.fromBigInteger(evalB);
        MontFr381 cEv = MontFr381.fromBigInteger(evalC);
        MontFr381 s1Ev = MontFr381.fromBigInteger(evalS1);
        MontFr381 s2Ev = MontFr381.fromBigInteger(evalS2);
        MontFr381 zwEv = MontFr381.fromBigInteger(evalZw);

        // qmCoeffs..s3Coeffs already computed above

        // Build r(X) as sum of weighted polynomials
        // maxLen must accommodate the largest polynomial (including blinding and T3)
        int maxLen = Math.max(zBlind.length, Math.max(aBlind.length,
                Math.max(qmCoeffs.length, Math.max(s3Coeffs.length, t3.length))));
        MontFr381[] rCoeffs = new MontFr381[maxLen];
        for (int i = 0; i < maxLen; i++) rCoeffs[i] = MontFr381.ZERO;

        // r += a*b*Qm + a*Ql + b*Qr + c*Qo + Qc
        addScaled(rCoeffs, qmCoeffs, aEv.mul(bEv));
        addScaled(rCoeffs, qlCoeffs, aEv);
        addScaled(rCoeffs, qrCoeffs, bEv);
        addScaled(rCoeffs, qoCoeffs, cEv);
        addScaled(rCoeffs, qcCoeffs, MontFr381.ONE);

        // Z coefficient in r: alpha * (a+beta*zeta+gamma)(b+beta*k1*zeta+gamma)(c+beta*k2*zeta+gamma) + alpha^2*L1(zeta) + u
        // (the u term is added by the verifier, not by the prover)
        MontFr381 betaZeta = beta.mul(zeta);
        MontFr381 zCoeffInR = alpha.mul(
                aEv.add(betaZeta).add(gamma)
                        .mul(bEv.add(betaZeta.mul(k1)).add(gamma))
                        .mul(cEv.add(betaZeta.mul(k2)).add(gamma)));

        // L1(zeta) = omega^0 * zh / (n * (zeta - omega^0)) = zh / (n * (zeta - 1))
        MontFr381 zetaN = zeta;
        for (int i = 1; i < n; i++) zetaN = zetaN.mul(zeta);
        MontFr381 zh = zetaN.sub(MontFr381.ONE);
        MontFr381 l1Zeta = zh.mul(MontFr381.fromLong(n).mul(zeta.sub(MontFr381.ONE)).inverse());

        zCoeffInR = zCoeffInR.add(alpha2.mul(l1Zeta));
        addScaled(rCoeffs, zBlind, zCoeffInR);

        // S3 coefficient: -alpha * beta * zw * (a+beta*s1+gamma)(b+beta*s2+gamma)
        MontFr381 s3CoeffInR = alpha.mul(beta).mul(zwEv)
                .mul(aEv.add(beta.mul(s1Ev)).add(gamma))
                .mul(bEv.add(beta.mul(s2Ev)).add(gamma))
                .neg();
        addScaled(rCoeffs, s3Coeffs, s3CoeffInR);

        // === snarkjs approach: build R(X) with r0 in constant term so R(zeta) = 0 ===
        // Subtract zh * (T1(X) + xin*T2(X) + xin^2*T3(X)) from R
        MontFr381 xinM = zetaN; // zeta^n, already computed
        MontFr381 zhM = zh;     // zeta^n - 1, already computed
        addScaled(rCoeffs, t1, zhM.neg());
        addScaled(rCoeffs, t2, zhM.neg().mul(xinM));
        addScaled(rCoeffs, t3, zhM.neg().mul(xinM).mul(xinM));

        // Compute r0 = PI(zeta) - alpha*(a+beta*s1+gamma)(b+beta*s2+gamma)*zw*(c+gamma) - alpha^2*L1(zeta)
        // and add to R(X) constant term so that R(zeta) = 0
        MontFr381 e3 = aEv.add(beta.mul(s1Ev)).add(gamma)
                .mul(bEv.add(beta.mul(s2Ev)).add(gamma))
                .mul(zwEv).mul(alpha);
        MontFr381 piZeta = FieldFFTBLS381.polyEval(piCoeffs, zeta);
        MontFr381 r0 = piZeta.sub(e3.mul(cEv.add(gamma))).sub(alpha2.mul(l1Zeta));
        rCoeffs[0] = rCoeffs[0].add(r0);

        // Build W_zeta numerator = R(X) + v*A(X) + v^2*B(X) + v^3*C(X) + v^4*S1(X) + v^5*S2(X)
        //                        - (v*eval_a + v^2*eval_b + v^3*eval_c + v^4*eval_s1 + v^5*eval_s2)
        // Since R(zeta)=0, the numerator at zeta = 0 + v*(A(zeta)-eval_a) + ... = 0
        // So the numerator is divisible by (X - zeta)
        MontFr381 v2 = v1.mul(v1); MontFr381 v3 = v2.mul(v1);
        MontFr381 v4 = v3.mul(v1); MontFr381 v5 = v4.mul(v1);

        MontFr381[] wxiNum = new MontFr381[rCoeffs.length];
        System.arraycopy(rCoeffs, 0, wxiNum, 0, rCoeffs.length);
        addScaled(wxiNum, aBlind, v1);
        addScaled(wxiNum, bBlind, v2);
        addScaled(wxiNum, cBlind, v3);
        addScaled(wxiNum, s1Coeffs, v4);
        addScaled(wxiNum, s2Coeffs, v5);

        // Subtract the scalar evaluation terms from the constant coefficient
        wxiNum[0] = wxiNum[0].sub(v1.mul(aEv)).sub(v2.mul(bEv)).sub(v3.mul(cEv))
                .sub(v4.mul(s1Ev)).sub(v5.mul(s2Ev));

        // The numerator must vanish at zeta for exact division

        // Divide by (X - zeta) via synthetic division — exact since numerator vanishes
        var wxiQuotient = KZGCommitmentBLS381.syntheticDivision(wxiNum, zeta, MontFr381.ZERO);

        // Commit W_zeta
        var commitWxi = KZGCommitmentBLS381.commit(srs, wxiQuotient).toAffine();

        // W_{zeta*omega} = (Z(X) - Z(zeta*omega)) / (X - zeta*omega)
        var commitWxiw = KZGCommitmentBLS381.openingProof(srs, zBlind, zetaOmega,
                MontFr381.fromBigInteger(evalZw)).toAffine();

        return new PlonKProofBLS381(
                commitA, commitB, commitC, commitZ,
                commitT1, commitT2, commitT3,
                evalA, evalB, evalC, evalS1, evalS2, evalZw,
                commitWxi, commitWxiw);
    }

    // --- Polynomial helpers ---

    /** Evaluate polynomial on coset {shift * omega^i}: IFFT → shift coeffs by shift^i → FFT */
    private static MontFr381[] cosetEval(MontFr381[] coeffs, MontFr381 shift, int n, int logN) {
        MontFr381[] padded = new MontFr381[n];
        for (int i = 0; i < n; i++)
            padded[i] = i < coeffs.length ? coeffs[i].mul(powFr(shift, i)) : MontFr381.ZERO;
        return FieldFFTBLS381.fft(padded);
    }

    /** Inverse coset FFT: FFT^{-1} then unshift by shift^{-i} */
    private static MontFr381[] cosetIFFT(MontFr381[] vals, MontFr381 shift, int n, int logN) {
        var coeffs = FieldFFTBLS381.ifft(vals);
        MontFr381 shiftInv = shift.inverse();
        MontFr381 power = MontFr381.ONE;
        for (int i = 0; i < coeffs.length; i++) {
            coeffs[i] = coeffs[i].mul(power);
            power = power.mul(shiftInv);
        }
        return coeffs;
    }

    /** Shift polynomial: if f(X) = sum c_i*X^i, return g where g(X) = f(omega*X) = sum c_i*omega^i*X^i */
    private static MontFr381[] shiftPoly(MontFr381[] coeffs, MontFr381 omega) {
        MontFr381[] result = new MontFr381[coeffs.length];
        MontFr381 power = MontFr381.ONE;
        for (int i = 0; i < coeffs.length; i++) {
            result[i] = coeffs[i].mul(power);
            power = power.mul(omega);
        }
        return result;
    }

    /** Build PI(X) polynomial: PI(omega^i) = -pubInputs[i] for i=0..nPub-1, 0 elsewhere.
     *  Our compiler emits public input rows at positions 0..nPub-1 (the first nPub rows). */
    private static MontFr381[] buildPICoeffs(BigInteger[] pubInputs, MontFr381 omega, int n, int logN) {
        MontFr381[] piEvals = new MontFr381[n];
        for (int i = 0; i < n; i++) {
            if (i < pubInputs.length) {
                piEvals[i] = MontFr381.fromBigInteger(pubInputs[i]).neg();
            } else {
                piEvals[i] = MontFr381.ZERO;
            }
        }
        return FieldFFTBLS381.ifft(piEvals);
    }

    /** Build L1(X) polynomial: L1(omega^i) = 1 if i=0, 0 otherwise */
    private static MontFr381[] buildL1Coeffs(MontFr381 omega, int n, int logN) {
        MontFr381[] l1Evals = new MontFr381[n];
        l1Evals[0] = MontFr381.ONE;
        for (int i = 1; i < n; i++) l1Evals[i] = MontFr381.ZERO;
        return FieldFFTBLS381.ifft(l1Evals);
    }

    /** Add scaled polynomial: result[i] += factor * poly[i] */
    private static void addScaled(MontFr381[] result, MontFr381[] poly, MontFr381 factor) {
        for (int i = 0; i < poly.length && i < result.length; i++) {
            result[i] = result[i].add(factor.mul(poly[i]));
        }
    }

    /**
     * Add blinding via Z_H(X) = X^n - 1: f(X) += b1*Z_H(X) + b2*X*Z_H(X).
     * Z_H vanishes on the domain, so the blinded polynomial agrees with the original
     * at all omega^i points — preserving the Z accumulator's correctness.
     * Coefficients: [-b1, -b2, 0..0, +b1, +b2] at positions 0,1 and n,n+1.
     */
    private static MontFr381[] addBlinding2(MontFr381[] coeffs, MontFr381 b1, MontFr381 b2, int n) {
        var r = new MontFr381[n + 2];
        System.arraycopy(coeffs, 0, r, 0, Math.min(coeffs.length, n));
        for (int i = coeffs.length; i < n + 2; i++) r[i] = MontFr381.ZERO;
        r[0] = r[0].sub(b1);       r[n] = r[n].add(b1);
        r[1] = r[1].sub(b2);       r[n + 1] = r[n + 1].add(b2);
        return r;
    }

    /**
     * Add blinding via Z_H(X): f(X) += b1*Z_H(X) + b2*X*Z_H(X) + b3*X^2*Z_H(X).
     */
    private static MontFr381[] addBlinding3(MontFr381[] coeffs, MontFr381 b1, MontFr381 b2, MontFr381 b3, int n) {
        var r = new MontFr381[n + 3];
        System.arraycopy(coeffs, 0, r, 0, Math.min(coeffs.length, n));
        for (int i = coeffs.length; i < n + 3; i++) r[i] = MontFr381.ZERO;
        r[0] = r[0].sub(b1);       r[n] = r[n].add(b1);
        r[1] = r[1].sub(b2);       r[n + 1] = r[n + 1].add(b2);
        r[2] = r[2].sub(b3);       r[n + 2] = r[n + 2].add(b3);
        return r;
    }

    private static MontFr381 powFr(MontFr381 base, int exp) {
        if (exp == 0) return MontFr381.ONE;
        MontFr381 r = base;
        for (int i = 1; i < exp; i++) r = r.mul(base);
        return r;
    }

    private static void addG1(FiatShamirTranscript t, AffineG1 p, TranscriptEncoding encoding) {
        if (encoding == TranscriptEncoding.COMPRESSED_G1) {
            t.addBytes(Bls12381Codecs.g1ToCompressed(toG1Point(p)));
        } else if (p.isInfinity()) {
            t.addPolCommitment(BigInteger.ZERO, BigInteger.ZERO);
        } else {
            t.addPolCommitment(p.xBigInt(), p.yBigInt());
        }
    }

    private static G1Point toG1Point(AffineG1 p) {
        if (p.isInfinity()) {
            return G1Point.INFINITY;
        }
        return new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static MontFr381 randomFr(SecureRandom rng) {
        byte[] bytes = new byte[32];
        BigInteger value;
        do {
            rng.nextBytes(bytes);
            value = new BigInteger(1, bytes);
        } while (value.compareTo(FR) >= 0);
        return MontFr381.fromBigInteger(value);
    }

    private static void validateProverInputs(
            PlonKProvingKeyBLS381 pk,
            MontFr381[] wireA,
            MontFr381[] wireB,
            MontFr381[] wireC,
            BigInteger[] pubInputs,
            MontFr381[] blinders) {
        if (pk == null) {
            throw new IllegalArgumentException("proving key must not be null");
        }
        int n = pk.domainSize();
        validateDomain(n);
        if (pk.nPublic() < 0 || pk.nPublic() > n) {
            throw new IllegalArgumentException("nPublic must be in [0, domainSize]");
        }
        if (pk.omega() == null) {
            throw new IllegalArgumentException("omega must not be null");
        }
        if (pk.srsG1() == null || pk.srsG1().length < 2 * n) {
            throw new IllegalArgumentException("SRS G1 length must be at least " + (2 * n));
        }

        requireWireArray("wireA", wireA, n);
        requireWireArray("wireB", wireB, n);
        requireWireArray("wireC", wireC, n);

        if (pubInputs == null || pubInputs.length != pk.nPublic()) {
            throw new IllegalArgumentException("pubInputs.length must equal nPublic");
        }
        for (int i = 0; i < pubInputs.length; i++) {
            requireScalar(pubInputs[i], "pubInputs[" + i + "]");
        }

        if (blinders == null || blinders.length != 9) {
            throw new IllegalArgumentException("PlonK BLS12-381 prover requires exactly 9 blinding scalars");
        }
        for (int i = 0; i < blinders.length; i++) {
            if (blinders[i] == null) {
                throw new IllegalArgumentException("blinding scalar " + i + " must not be null");
            }
        }
    }

    private static void validateDomain(int n) {
        if (n < MIN_DOMAIN_SIZE || (n & (n - 1)) != 0) {
            throw new IllegalArgumentException("domainSize must be a power of two >= " + MIN_DOMAIN_SIZE);
        }
        int logN = Integer.numberOfTrailingZeros(n);
        if (logN > MAX_DOMAIN_POWER) {
            throw new IllegalArgumentException("domainSize exceeds supported PlonK domain 2^" + MAX_DOMAIN_POWER);
        }
    }

    private static void requireWireArray(String name, MontFr381[] wires, int n) {
        if (wires == null || wires.length != n) {
            throw new IllegalArgumentException(name + ".length must equal domainSize");
        }
        for (int i = 0; i < wires.length; i++) {
            if (wires[i] == null) {
                throw new IllegalArgumentException(name + "[" + i + "] must not be null");
            }
        }
    }

    private static void requireScalar(BigInteger value, String label) {
        if (value == null || value.signum() < 0 || value.compareTo(FR) >= 0) {
            throw new IllegalArgumentException(label + " must be a canonical BLS12-381 scalar");
        }
    }
}
