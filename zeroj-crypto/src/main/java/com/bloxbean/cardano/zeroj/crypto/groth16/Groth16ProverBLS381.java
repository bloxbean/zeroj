package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.bls12381.field.FrArith381;
import com.bloxbean.cardano.zeroj.crypto.poly.FrFFTFlat;
import com.bloxbean.cardano.zeroj.crypto.msm.PippengerFlatBLS381;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

/**
 * Pure Java Groth16 prover for BLS12-381.
 *
 * <p>Same algorithm as {@link Groth16Prover} but using BLS12-381 curve types.</p>
 */
public final class Groth16ProverBLS381 {

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

        var rng = new SecureRandom();
        BigInteger r = randomScalar(rng);
        BigInteger s = randomScalar(rng);

        return proveInternal(pk, heapReaders(pk), witness, hCoeffs, r, s);
    }

    static Groth16ProofBLS381 proveUnblinded(
            Groth16ProvingKeyBLS381 pk, BigInteger[] witness,
            List<R1CSConstraint> constraints, int numWires, int domainSize) {
        BigInteger[] hCoeffs = computeH(constraints, witness, constraints.size(), domainSize);
        return proveInternal(pk, heapReaders(pk), witness, hCoeffs, BigInteger.ZERO, BigInteger.ZERO);
    }

    /** The G1 proving-key point arrays as readers (heap or mmap-backed). */
    public record G1Readers(PippengerFlatBLS381.G1AffineReader a, PippengerFlatBLS381.G1AffineReader b1,
                            PippengerFlatBLS381.G1AffineReader h, PippengerFlatBLS381.G1AffineReader l) {}

    /** Deterministic (unblinded) prove with reader-supplied G1 key — for differential heap-vs-mmap tests. */
    static Groth16ProofBLS381 proveUnblindedWithReaders(
            Groth16ProvingKeyBLS381 pk, G1Readers readers, BigInteger[] witness,
            List<R1CSConstraint> constraints, int domainSize) {
        BigInteger[] hCoeffs = computeH(constraints, witness, constraints.size(), domainSize);
        return proveInternal(pk, readers, witness, hCoeffs, BigInteger.ZERO, BigInteger.ZERO);
    }

    /** In-RAM readers over the PK's flat G1 arrays. */
    public static G1Readers heapReaders(Groth16ProvingKeyBLS381 pk) {
        return new G1Readers(
                new PippengerFlatBLS381.HeapG1Reader(pk.pointsA()),
                new PippengerFlatBLS381.HeapG1Reader(pk.pointsB1()),
                new PippengerFlatBLS381.HeapG1Reader(pk.pointsH()),
                new PippengerFlatBLS381.HeapG1Reader(pk.pointsL()));
    }

    /**
     * Prove with the G1 proving key supplied as {@link G1Readers} — pass mmap-backed
     * {@link PippengerFlatBLS381.SegmentG1Reader}s to prove with the PK off-heap/file-backed
     * (ADR-0029 M4). Single points + G2 come from {@code pk}.
     */
    public static Groth16ProofBLS381 proveWithReaders(
            Groth16ProvingKeyBLS381 pk, G1Readers readers, BigInteger[] witness,
            List<R1CSConstraint> constraints, int numWires, int domainSize) {
        BigInteger[] hCoeffs = computeH(constraints, witness, constraints.size(), domainSize);
        var rng = new SecureRandom();
        return proveInternal(pk, readers, witness, hCoeffs, randomScalar(rng), randomScalar(rng));
    }

    private static Groth16ProofBLS381 proveInternal(
            Groth16ProvingKeyBLS381 pk, G1Readers readers, BigInteger[] witness, BigInteger[] hCoeffs,
            BigInteger r, BigInteger s) {

        var piA = computePiA(pk, readers.a(), witness, r);
        var piB = computePiB_G2(pk, witness, s);
        var piB1 = computePiB_G1(pk, readers.b1(), witness, s);
        var piC = computePiC(pk, readers.h(), readers.l(), hCoeffs, witness, r, s, piA, piB1);

        return new Groth16ProofBLS381(piA.toAffine(), piB.toAffine(), piC.toAffine());
    }

    static BigInteger[] computeH(List<R1CSConstraint> constraints, BigInteger[] witness,
                                  int numConstraints, int domainSize) {
        BigInteger mod = MontFr381.modulus();
        if (domainSize < 2) domainSize = 2;
        int logN = Integer.numberOfTrailingZeros(domainSize);

        // ADR-0029 M2c: Fr coefficients held as flat long[] (4 limbs/element) with the allocation-lean
        // FrFFTFlat, instead of MontFr381[] object arrays — halves the prover's transient FFT memory.
        long[] aEval = new long[domainSize * 4];
        long[] bEval = new long[domainSize * 4];

        int constraintCount = constraints.size();
        for (int i = 0; i < domainSize; i++) {
            if (i < numConstraints && i < constraintCount) {
                R1CSConstraint constraint = constraints.get(i);
                System.arraycopy(evalLinComb(constraint.a(), witness, mod).toLimbs(), 0, aEval, i * 4, 4);
                System.arraycopy(evalLinComb(constraint.b(), witness, mod).toLimbs(), 0, bEval, i * 4, 4);
            } // else zeros (MontFr381.ZERO == all-zero limbs)
        }

        long[] cEval = new long[domainSize * 4];
        for (int i = 0; i < domainSize; i++) FrArith381.mul(cEval, i * 4, aEval, i * 4, bEval, i * 4);

        long[] inc = FieldFFTBLS381.rootOfUnity(logN + 1).toLimbs();
        cosetFFT(aEval, domainSize, inc);
        cosetFFT(bEval, domainSize, inc);
        cosetFFT(cEval, domainSize, inc);

        BigInteger[] result = new BigInteger[domainSize];
        long[] val = new long[4];
        for (int i = 0; i < domainSize; i++) {
            FrArith381.mul(val, 0, aEval, i * 4, bEval, i * 4); // a·b
            FrArith381.sub(val, 0, val, 0, cEval, i * 4);       // - c
            result[i] = MontFr381.fromMontLimbs(val[0], val[1], val[2], val[3]).toBigInteger();
        }
        return result;
    }

    /** In-place coset NTT on flat Fr coefficients: ifft → scale by inc^i → fft. */
    private static void cosetFFT(long[] a, int n, long[] inc) {
        FrFFTFlat.ifft(a, n);
        long[] power = MontFr381.ONE.toLimbs();
        for (int i = 0; i < n; i++) {
            FrArith381.mul(a, i * 4, a, i * 4, power, 0);
            FrArith381.mul(power, 0, power, 0, inc, 0);
        }
        FrFFTFlat.fft(a, n);
    }

    private static JacobianG1BLS381 computePiA(Groth16ProvingKeyBLS381 pk,
            PippengerFlatBLS381.G1AffineReader aReader, BigInteger[] witness, BigInteger r) {
        var result = JacobianG1BLS381.fromAffine(pk.alphaG1().x(), pk.alphaG1().y());

        int n = Math.min(witness.length, aReader.count());
        if (n > 0) {
            BigInteger[] scalars = new BigInteger[n];
            System.arraycopy(witness, 0, scalars, 0, n);
            result = result.add(PippengerFlatBLS381.msmReader(aReader, n, scalars));
        }

        result = result.add(JacobianG1BLS381.fromAffine(pk.deltaG1().x(), pk.deltaG1().y()).scalarMul(r));
        return result;
    }

    private static JacobianG2BLS381 computePiB_G2(Groth16ProvingKeyBLS381 pk, BigInteger[] witness, BigInteger s) {
        var result = JacobianG2BLS381.fromAffine(pk.betaG2().x(), pk.betaG2().y());

        int n = Math.min(witness.length, pk.pointsB2().length);
        result = result.add(g2Msm(pk.pointsB2(), witness, n));

        result = result.add(JacobianG2BLS381.fromAffine(pk.deltaG2().x(), pk.deltaG2().y()).scalarMul(s));
        return result;
    }

    private static JacobianG2BLS381 g2Msm(AffineG2[] points, BigInteger[] scalars, int n) {
        if (n == 0) return JacobianG2BLS381.INFINITY;

        BigInteger fr = MontFr381.modulus();
        int c = Math.max(3, Math.min(31 - Integer.numberOfLeadingZeros(n), 12));
        int numBuckets = (1 << c) - 1;
        int numWindows = (255 + c - 1) / c;

        JacobianG2BLS381 result = JacobianG2BLS381.INFINITY;
        for (int w = numWindows - 1; w >= 0; w--) {
            if (!result.isInfinity()) {
                for (int d = 0; d < c; d++) result = result.doublePoint();
            }

            JacobianG2BLS381[] buckets = new JacobianG2BLS381[numBuckets + 1];
            for (int i = 0; i <= numBuckets; i++) buckets[i] = JacobianG2BLS381.INFINITY;

            int bitOffset = w * c;
            for (int i = 0; i < n; i++) {
                BigInteger s_i = scalars[i].signum() < 0 || scalars[i].compareTo(fr) >= 0
                        ? scalars[i].mod(fr)
                        : scalars[i];
                int digit = 0;
                for (int b = 0; b < c; b++) {
                    int bitPos = bitOffset + b;
                    if (bitPos < s_i.bitLength() && s_i.testBit(bitPos)) digit |= (1 << b);
                }
                if (digit != 0 && !points[i].isInfinity()) {
                    buckets[digit] = buckets[digit].add(
                            JacobianG2BLS381.fromAffine(points[i].x(), points[i].y()));
                }
            }

            JacobianG2BLS381 runningSum = JacobianG2BLS381.INFINITY;
            JacobianG2BLS381 windowSum = JacobianG2BLS381.INFINITY;
            for (int j = numBuckets; j >= 1; j--) {
                runningSum = runningSum.add(buckets[j]);
                windowSum = windowSum.add(runningSum);
            }
            result = result.add(windowSum);
        }
        return result;
    }

    private static JacobianG1BLS381 computePiB_G1(Groth16ProvingKeyBLS381 pk,
            PippengerFlatBLS381.G1AffineReader b1Reader, BigInteger[] witness, BigInteger s) {
        var result = JacobianG1BLS381.fromAffine(pk.betaG1().x(), pk.betaG1().y());

        int n = Math.min(witness.length, b1Reader.count());
        if (n > 0) {
            BigInteger[] scalars = new BigInteger[n];
            System.arraycopy(witness, 0, scalars, 0, n);
            result = result.add(PippengerFlatBLS381.msmReader(b1Reader, n, scalars));
        }

        result = result.add(JacobianG1BLS381.fromAffine(pk.deltaG1().x(), pk.deltaG1().y()).scalarMul(s));
        return result;
    }

    private static JacobianG1BLS381 computePiC(
            Groth16ProvingKeyBLS381 pk, PippengerFlatBLS381.G1AffineReader hReader,
            PippengerFlatBLS381.G1AffineReader lReader, BigInteger[] hCoeffs, BigInteger[] witness,
            BigInteger r, BigInteger s,
            JacobianG1BLS381 piA, JacobianG1BLS381 piB1) {

        JacobianG1BLS381 result = JacobianG1BLS381.INFINITY;

        int hLen = Math.min(hCoeffs.length, hReader.count());
        if (hLen > 0) {
            BigInteger[] hScalars = new BigInteger[hLen];
            System.arraycopy(hCoeffs, 0, hScalars, 0, hLen);
            result = result.add(PippengerFlatBLS381.msmReader(hReader, hLen, hScalars));
        }

        int numPrivate = witness.length - pk.numPublic() - 1;
        if (numPrivate > 0 && lReader.count() > 0) {
            int lLen = Math.min(numPrivate, lReader.count());
            BigInteger[] lScalars = new BigInteger[lLen];
            System.arraycopy(witness, pk.numPublic() + 1, lScalars, 0, lLen);
            result = result.add(PippengerFlatBLS381.msmReader(lReader, lLen, lScalars));
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
            int wire = entry.getKey();
            BigInteger coeff = entry.getValue();
            if (wire < witness.length && coeff.signum() != 0) {
                sum = sum.add(MontFr381.fromBigInteger(coeff).mul(MontFr381.fromBigInteger(witness[wire])));
            }
        }
        return sum;
    }

    private static BigInteger randomScalar(SecureRandom rng) {
        byte[] bytes = new byte[64];
        rng.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(MontFr381.modulus());
    }
}
