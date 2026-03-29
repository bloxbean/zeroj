package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFT;
import com.bloxbean.cardano.zeroj.verifier.plonk.FiatShamirTranscript;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Debug test: verify intermediate PlonK prover values step by step.
 */
class PlonKDebugTest {

    private static final String PTAU_PATH = "/test-circuits/plonk-multiplier/pot8_final.ptau";
    private static final BigInteger FR = MontFr254.modulus();

    @Test
    void debug_gateConstraintAtZeta() throws IOException {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> {
                    var product = api.mul(api.var("a"), api.var("b"));
                    api.assertEqual(product, api.var("c"));
                });

        var plonk = circuit.compilePlonK(CurveId.BN254);
        var witness = circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BN254);

        var srs = PtauImporter.importPtau(getClass().getResourceAsStream(PTAU_PATH), 256);
        int numGates = plonk.numGates();
        BigInteger[][] gs = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var r = plonk.gateRows().get(i);
            gs[i] = new BigInteger[]{r.qL(), r.qR(), r.qO(), r.qM(), r.qC()};
        }
        var pk = PlonKSetup.setup(numGates, plonk.numPublicInputs(), gs,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);

        var extWitness = plonk.extendWitness(witness);
        int n = pk.domainSize();
        MontFr254 omega = pk.omega();
        int logN = Integer.numberOfTrailingZeros(n);

        // Build wire evaluations
        MontFr254[] aEvals = new MontFr254[n];
        MontFr254[] bEvals = new MontFr254[n];
        MontFr254[] cEvals = new MontFr254[n];
        for (int i = 0; i < n; i++) {
            if (i < numGates) {
                var row = plonk.gateRows().get(i);
                aEvals[i] = MontFr254.fromBigInteger(extWitness[row.wireA()]);
                bEvals[i] = MontFr254.fromBigInteger(extWitness[row.wireB()]);
                cEvals[i] = MontFr254.fromBigInteger(extWitness[row.wireC()]);
            } else {
                aEvals[i] = bEvals[i] = cEvals[i] = MontFr254.ZERO;
            }
        }

        // First verify gate constraint at each omega^i
        System.out.println("=== Gate constraint on domain (no PI) ===");
        int nPub = plonk.numPublicInputs();
        for (int i = 0; i < n; i++) {
            var gate = pk.qm()[i].mul(aEvals[i]).mul(bEvals[i])
                    .add(pk.ql()[i].mul(aEvals[i]))
                    .add(pk.qr()[i].mul(bEvals[i]))
                    .add(pk.qo()[i].mul(cEvals[i]))
                    .add(pk.qc()[i]);

            // PI at omega^i
            MontFr254 piI = MontFr254.ZERO;
            if (i < nPub) {
                piI = MontFr254.fromBigInteger(witness[i + 1]).neg(); // pubInputs[i] = witness[i+1]
            }

            var total = gate.add(piI);
            boolean ok = total.isZero();
            if (!ok) {
                System.out.println("  [" + i + "] gate=" + gate.toBigInteger() + " pi=" + piI.toBigInteger()
                        + " total=" + total.toBigInteger() + " FAIL");
            }
        }

        // Check that gate + PI = 0 for ALL rows
        boolean allSatisfied = true;
        for (int i = 0; i < n; i++) {
            var gate = pk.qm()[i].mul(aEvals[i]).mul(bEvals[i])
                    .add(pk.ql()[i].mul(aEvals[i]))
                    .add(pk.qr()[i].mul(bEvals[i]))
                    .add(pk.qo()[i].mul(cEvals[i]))
                    .add(pk.qc()[i]);
            MontFr254 piI = MontFr254.ZERO;
            if (i < nPub) piI = MontFr254.fromBigInteger(witness[i + 1]).neg();
            if (!gate.add(piI).isZero()) { allSatisfied = false; break; }
        }
        System.out.println("All gates satisfied (with PI): " + allSatisfied);

        // Check permutation: Z(omega^n) should be 1 (Z starts at 1 and accumulates)
        MontFr254 beta = MontFr254.fromLong(7); // dummy challenge for testing
        MontFr254 gamma = MontFr254.fromLong(13);
        MontFr254 k1 = MontFr254.fromBigInteger(pk.k1());
        MontFr254 k2 = MontFr254.fromBigInteger(pk.k2());

        MontFr254[] zEvals = new MontFr254[n];
        MontFr254 zAccum = MontFr254.ONE;
        zEvals[0] = MontFr254.ONE;
        MontFr254 wi = MontFr254.ONE;
        for (int i = 0; i < n; i++) {
            var num = aEvals[i].add(beta.mul(wi)).add(gamma)
                    .mul(bEvals[i].add(beta.mul(k1).mul(wi)).add(gamma))
                    .mul(cEvals[i].add(beta.mul(k2).mul(wi)).add(gamma));
            var den = aEvals[i].add(beta.mul(pk.s1()[i])).add(gamma)
                    .mul(bEvals[i].add(beta.mul(pk.s2()[i])).add(gamma))
                    .mul(cEvals[i].add(beta.mul(pk.s3()[i])).add(gamma));
            zAccum = zAccum.mul(num).mul(den.inverse());
            if (i + 1 < n) zEvals[i + 1] = zAccum;
            wi = wi.mul(omega);
        }
        System.out.println("Z accumulator final (should be 1): " + zAccum.toBigInteger());
        System.out.println("Z final is 1: " + zAccum.isOne());

        // If gate+PI != 0 OR Z final != 1, the constraint system or wire mapping is wrong
        assertTrue(allSatisfied, "All gate+PI constraints must be satisfied on the domain");
        assertTrue(zAccum.isOne(), "Z accumulator must return to 1 (permutation is valid)");

        // Now test that t(X)*Z_H(X) = full_constraint(X) at a random point
        // This verifies the quotient polynomial computation is correct
        // Build wire, selector, and sigma coefficient-form polynomials
        var aCoeffs = FieldFFT.ifft(aEvals);
        var bCoeffs = FieldFFT.ifft(bEvals);
        var cCoeffs = FieldFFT.ifft(cEvals);

        var qlCoeffs = FieldFFT.ifft(pk.ql());
        var qrCoeffs = FieldFFT.ifft(pk.qr());
        var qmCoeffs = FieldFFT.ifft(pk.qm());
        var qoCoeffs = FieldFFT.ifft(pk.qo());
        var qcCoeffs = FieldFFT.ifft(pk.qc());
        var s1Coeffs = FieldFFT.ifft(pk.s1());
        var s2Coeffs = FieldFFT.ifft(pk.s2());
        var s3Coeffs = FieldFFT.ifft(pk.s3());

        BigInteger[] pubInputs = new BigInteger[nPub];
        for (int i = 0; i < nPub; i++) pubInputs[i] = witness[i + 1];

        // PI polynomial: PI(omega^i) = -pubInputs[i] for i < nPub
        MontFr254[] piEvals = new MontFr254[n];
        for (int i = 0; i < n; i++)
            piEvals[i] = i < nPub ? MontFr254.fromBigInteger(pubInputs[i]).neg() : MontFr254.ZERO;
        var piCoeffs = FieldFFT.ifft(piEvals);

        // L1 polynomial
        MontFr254[] l1Evals = new MontFr254[n];
        l1Evals[0] = MontFr254.ONE;
        for (int i = 1; i < n; i++) l1Evals[i] = MontFr254.ZERO;
        var l1Coeffs = FieldFFT.ifft(l1Evals);

        // Build Z polynomial
        var zCoeffs = FieldFFT.ifft(zEvals);

        // Z(omega*X) polynomial
        MontFr254[] zOmegaCoeffs = new MontFr254[zCoeffs.length];
        MontFr254 omegaPow = MontFr254.ONE;
        for (int i = 0; i < zCoeffs.length; i++) {
            zOmegaCoeffs[i] = zCoeffs[i].mul(omegaPow);
            omegaPow = omegaPow.mul(omega);
        }

        // Evaluate everything at a random point to check: t(zeta)*Z_H(zeta) = full constraint
        MontFr254 zeta = MontFr254.fromLong(12345); // arbitrary test point
        MontFr254 aZ = FieldFFT.polyEval(aCoeffs, zeta);
        MontFr254 bZ = FieldFFT.polyEval(bCoeffs, zeta);
        MontFr254 cZ = FieldFFT.polyEval(cCoeffs, zeta);
        MontFr254 qlZ = FieldFFT.polyEval(qlCoeffs, zeta);
        MontFr254 qrZ = FieldFFT.polyEval(qrCoeffs, zeta);
        MontFr254 qmZ = FieldFFT.polyEval(qmCoeffs, zeta);
        MontFr254 qoZ = FieldFFT.polyEval(qoCoeffs, zeta);
        MontFr254 qcZ = FieldFFT.polyEval(qcCoeffs, zeta);
        MontFr254 piZ = FieldFFT.polyEval(piCoeffs, zeta);
        MontFr254 s1Z = FieldFFT.polyEval(s1Coeffs, zeta);
        MontFr254 s2Z = FieldFFT.polyEval(s2Coeffs, zeta);
        MontFr254 s3Z = FieldFFT.polyEval(s3Coeffs, zeta);
        MontFr254 zZ = FieldFFT.polyEval(zCoeffs, zeta);
        MontFr254 zOmZ = FieldFFT.polyEval(zOmegaCoeffs, zeta);
        MontFr254 l1Z = FieldFFT.polyEval(l1Coeffs, zeta);

        // Use the same beta/gamma as above (7, 13) for consistency
        MontFr254 alpha2Test = MontFr254.fromLong(17); // arbitrary alpha for testing

        // gate + PI
        var gate = qmZ.mul(aZ).mul(bZ).add(qlZ.mul(aZ)).add(qrZ.mul(bZ)).add(qoZ.mul(cZ)).add(qcZ).add(piZ);

        // permutation
        MontFr254 betaTest = MontFr254.fromLong(7);
        MontFr254 gammaTest = MontFr254.fromLong(13);
        MontFr254 k1t = MontFr254.fromBigInteger(pk.k1());
        MontFr254 k2t = MontFr254.fromBigInteger(pk.k2());

        var permNum = aZ.add(betaTest.mul(zeta)).add(gammaTest)
                .mul(bZ.add(betaTest.mul(k1t).mul(zeta)).add(gammaTest))
                .mul(cZ.add(betaTest.mul(k2t).mul(zeta)).add(gammaTest))
                .mul(zZ);
        var permDen = aZ.add(betaTest.mul(s1Z)).add(gammaTest)
                .mul(bZ.add(betaTest.mul(s2Z)).add(gammaTest))
                .mul(cZ.add(betaTest.mul(s3Z)).add(gammaTest))
                .mul(zOmZ);
        var perm = betaTest.mul(permNum.sub(permDen)); // using beta as alpha substitute

        var start = alpha2Test.mul(zZ.sub(MontFr254.ONE)).mul(l1Z);

        var fullConstraint = gate.add(perm).add(start);

        // Z_H(zeta)
        MontFr254 zetaN = zeta;
        for (int i = 1; i < n; i++) zetaN = zetaN.mul(zeta);
        MontFr254 zhZeta = zetaN.sub(MontFr254.ONE);

        System.out.println("\n=== Polynomial check at zeta=" + zeta.toBigInteger() + " ===");
        System.out.println("gate+PI at zeta: " + gate.toBigInteger());
        System.out.println("perm at zeta: " + perm.toBigInteger());
        System.out.println("start at zeta: " + start.toBigInteger());
        System.out.println("fullConstraint at zeta: " + fullConstraint.toBigInteger());
        System.out.println("Z_H(zeta): " + zhZeta.toBigInteger());

        // fullConstraint should be divisible by Z_H: fullConstraint = t(zeta) * Z_H(zeta)
        // So fullConstraint / Z_H should be an integer (no remainder)
        var tZeta = fullConstraint.mul(zhZeta.inverse());
        System.out.println("t(zeta) = fullConstraint/Z_H = " + tZeta.toBigInteger());
        System.out.println("Check: t(zeta)*Z_H(zeta) == fullConstraint: " +
                tZeta.mul(zhZeta).equals(fullConstraint));

        // Now test the coset FFT approach matches
        // Build the full constraint numerator on a 4n coset, IFFT to get t(X) coefficients
        int n4 = 4 * n;
        int logN4 = Integer.numberOfTrailingZeros(n4);
        MontFr254 shift = MontFr254.fromLong(5); // same as prover

        // Coset-evaluate all polynomials
        var aCoset = cosetEval(aCoeffs, shift, n4);
        var bCoset = cosetEval(bCoeffs, shift, n4);
        var cCoset = cosetEval(cCoeffs, shift, n4);
        var zCoset = cosetEval(zCoeffs, shift, n4);
        var qlC = cosetEval(qlCoeffs, shift, n4);
        var qrC = cosetEval(qrCoeffs, shift, n4);
        var qmC = cosetEval(qmCoeffs, shift, n4);
        var qoC = cosetEval(qoCoeffs, shift, n4);
        var qcC = cosetEval(qcCoeffs, shift, n4);
        var piC = cosetEval(piCoeffs, shift, n4);
        var s1C = cosetEval(s1Coeffs, shift, n4);
        var s2C = cosetEval(s2Coeffs, shift, n4);
        var s3C = cosetEval(s3Coeffs, shift, n4);
        var l1C = cosetEval(l1Coeffs, shift, n4);
        var zOmC = cosetEval(zOmegaCoeffs, shift, n4);

        MontFr254 omega4 = FieldFFT.rootOfUnity(logN4);
        MontFr254 shiftN = shift;
        for (int i = 1; i < n; i++) shiftN = shiftN.mul(shift);
        MontFr254 omega4N = omega4;
        for (int i = 1; i < n; i++) omega4N = omega4N.mul(omega4);

        // Compute t on coset
        MontFr254[] tCoset = new MontFr254[n4];
        MontFr254 omega4Ni = MontFr254.ONE;
        MontFr254 cosetPt = shift;
        for (int i = 0; i < n4; i++) {
            var zhI = shiftN.mul(omega4Ni).sub(MontFr254.ONE);

            var gateI = qmC[i].mul(aCoset[i]).mul(bCoset[i])
                    .add(qlC[i].mul(aCoset[i]))
                    .add(qrC[i].mul(bCoset[i]))
                    .add(qoC[i].mul(cCoset[i]))
                    .add(qcC[i]).add(piC[i]);

            MontFr254 bTest = MontFr254.fromLong(7);
            MontFr254 gTest = MontFr254.fromLong(13);
            MontFr254 k1Test = MontFr254.fromBigInteger(pk.k1());
            MontFr254 k2Test = MontFr254.fromBigInteger(pk.k2());

            var pnC = aCoset[i].add(bTest.mul(cosetPt)).add(gTest)
                    .mul(bCoset[i].add(bTest.mul(k1Test).mul(cosetPt)).add(gTest))
                    .mul(cCoset[i].add(bTest.mul(k2Test).mul(cosetPt)).add(gTest))
                    .mul(zCoset[i]);
            var pdC = aCoset[i].add(bTest.mul(s1C[i])).add(gTest)
                    .mul(bCoset[i].add(bTest.mul(s2C[i])).add(gTest))
                    .mul(cCoset[i].add(bTest.mul(s3C[i])).add(gTest))
                    .mul(zOmC[i]);
            var permI = bTest.mul(pnC.sub(pdC));

            MontFr254 a2Test = MontFr254.fromLong(17);
            var startI = a2Test.mul(zCoset[i].sub(MontFr254.ONE)).mul(l1C[i]);

            tCoset[i] = gateI.add(permI).add(startI).mul(zhI.inverse());

            omega4Ni = omega4Ni.mul(omega4N);
            if (i < n4 - 1) cosetPt = cosetPt.mul(omega4);
        }

        // Inverse coset FFT to get t(X) coefficients
        var tCoeffsFromCoset = cosetIFFT(tCoset, shift, n4);

        // Evaluate t at our test zeta
        MontFr254 tFromCoset = FieldFFT.polyEval(tCoeffsFromCoset, zeta);
        System.out.println("\nt(zeta) from direct division: " + tZeta.toBigInteger());
        System.out.println("t(zeta) from coset FFT:       " + tFromCoset.toBigInteger());
        System.out.println("Match: " + tZeta.equals(tFromCoset));
        assertEquals(tZeta.toBigInteger(), tFromCoset.toBigInteger(),
                "Coset FFT t(zeta) must match direct computation");
    }

    // Helpers for coset FFT
    private static MontFr254[] cosetEval(MontFr254[] coeffs, MontFr254 shift, int n) {
        MontFr254[] padded = new MontFr254[n];
        for (int i = 0; i < n; i++)
            padded[i] = i < coeffs.length ? coeffs[i].mul(powFr(shift, i)) : MontFr254.ZERO;
        return FieldFFT.fft(padded);
    }

    private static MontFr254[] cosetIFFT(MontFr254[] vals, MontFr254 shift, int n) {
        var coeffs = FieldFFT.ifft(vals);
        MontFr254 shiftInv = shift.inverse();
        MontFr254 power = MontFr254.ONE;
        for (int i = 0; i < coeffs.length; i++) {
            coeffs[i] = coeffs[i].mul(power);
            power = power.mul(shiftInv);
        }
        return coeffs;
    }

    private static MontFr254 powFr(MontFr254 base, int exp) {
        if (exp == 0) return MontFr254.ONE;
        MontFr254 r = base;
        for (int i = 1; i < exp; i++) r = r.mul(base);
        return r;
    }
}
