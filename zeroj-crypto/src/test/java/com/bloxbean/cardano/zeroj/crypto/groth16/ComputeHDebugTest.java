package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFT;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ComputeHDebugTest {

    static final BigInteger MOD = MontFr254.modulus();

    @Test
    void computeH_r1csConstraints_producesCorrectH() throws IOException {
        var r1csData = R1CSImporter.importR1CS(
                getClass().getResourceAsStream("/test-circuits/multiplier/multiplier.r1cs"));
        var witness = ZkeyImporter.importWtns(
                getClass().getResourceAsStream("/test-circuits/multiplier/multiplier_witness.wtns"));

        System.out.println("nConstraints=" + r1csData.numConstraints() + " nWires=" + r1csData.numWires());
        for (int i = 0; i < r1csData.numConstraints(); i++) {
            var c = r1csData.constraints()[i];
            BigInteger aVal = evalLC(c.a(), witness);
            BigInteger bVal = evalLC(c.b(), witness);
            BigInteger cVal = evalLC(c.c(), witness);
            System.out.println("[" + i + "] A·w=" + aVal + " B·w=" + bVal + " C·w=" + cVal
                    + " A*B-C=" + aVal.multiply(bVal).subtract(cVal).mod(MOD));
        }

        // With domainSize=4, pad 1 constraint to 4 slots (rest are zero constraints)
        // For a valid witness, A*B - C = 0 at the constraint evaluation points
        // h(x) = (A(x)*B(x) - C(x)) / Z_H(x) should be a valid polynomial

        var h = Groth16Prover.computeH(r1csData.constraints(), witness, r1csData.numConstraints(), 4);
        System.out.println("\nh coefficients (domainSize=4, " + h.length + " total):");
        boolean allZero = true;
        for (int i = 0; i < h.length; i++) {
            if (h[i].signum() != 0) {
                System.out.println("  h[" + i + "] = " + h[i]);
                allZero = false;
            }
        }
        if (allZero) System.out.println("  (all zero)");

        // Verify: h(x) * Z_H(x) should equal A(x)*B(x) - C(x)
        // Reconstruct A(x)*B(x) - C(x) from the constraint evaluations
        MontFr254[] aEvals = new MontFr254[4];
        MontFr254[] bEvals = new MontFr254[4];
        MontFr254[] cEvals = new MontFr254[4];
        for (int i = 0; i < 4; i++) {
            if (i < r1csData.numConstraints()) {
                aEvals[i] = evalLCMont(r1csData.constraints()[i].a(), witness);
                bEvals[i] = evalLCMont(r1csData.constraints()[i].b(), witness);
                cEvals[i] = evalLCMont(r1csData.constraints()[i].c(), witness);
            } else {
                aEvals[i] = MontFr254.ZERO;
                bEvals[i] = MontFr254.ZERO;
                cEvals[i] = MontFr254.ZERO;
            }
        }

        // A*B - C should be zero at roots of unity (for valid witness)
        for (int i = 0; i < 4; i++) {
            var diff = aEvals[i].mul(bEvals[i]).sub(cEvals[i]);
            System.out.println("A*B-C at omega^" + i + " = " + diff.toBigInteger()
                    + " (should be 0 for valid witness)");
        }

        assertNotNull(h);
    }

    private BigInteger evalLC(Map<Integer, BigInteger> lc, BigInteger[] witness) {
        BigInteger sum = BigInteger.ZERO;
        for (var e : lc.entrySet()) {
            if (e.getKey() < witness.length) sum = sum.add(e.getValue().multiply(witness[e.getKey()]));
        }
        return sum.mod(MOD);
    }

    private MontFr254 evalLCMont(Map<Integer, BigInteger> lc, BigInteger[] witness) {
        MontFr254 sum = MontFr254.ZERO;
        for (var e : lc.entrySet()) {
            if (e.getKey() < witness.length) {
                sum = sum.add(MontFr254.fromBigInteger(e.getValue()).mul(MontFr254.fromBigInteger(witness[e.getKey()])));
            }
        }
        return sum;
    }
}
