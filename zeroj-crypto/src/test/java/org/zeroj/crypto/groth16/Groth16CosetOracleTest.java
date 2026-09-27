package org.zeroj.crypto.groth16;

import org.junit.jupiter.api.Test;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.api.R1CSFlat;
import org.zeroj.crypto.msm.FlatScalars;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

/** Direct Lagrange interpolation over BigInteger, without any ZeroJ field or FFT oracle. */
class Groth16CosetOracleTest {
    private static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    @Test void domainBoundariesAndLargeCosetsMatchDirectInterpolation() {
        // ffjavascript v0.3.1 derives roots from the first quadratic nonresidue (5 here).
        BigInteger nonresidue = BigInteger.TWO;
        while (!nonresidue.modPow(R.subtract(BigInteger.ONE).shiftRight(1), R).equals(R.subtract(BigInteger.ONE)))
            nonresidue = nonresidue.add(BigInteger.ONE);
        Random random = new Random(0x47C05E7L);
        for (int rows : new int[]{7, 8, 9, 4095, 4096, 4097}) {
            int n = Integer.highestOneBit(rows - 1) << 1;
            BigInteger[] a = new BigInteger[n], b = new BigInteger[n];
            Arrays.fill(a, BigInteger.ZERO);
            Arrays.fill(b, BigInteger.ZERO);
            var constraints = new ArrayList<R1CSConstraint>();
            var flat = R1CSFlat.builder();
            for (int j = 0; j < rows; j++) {
                a[j] = new BigInteger(255, random).mod(R);
                b[j] = new BigInteger(255, random).mod(R);
                var am = Map.of(0, a[j]);
                var bm = Map.of(0, b[j]);
                var cm = Map.of(0, a[j].multiply(b[j]).mod(R));
                constraints.add(new R1CSConstraint(am, bm, cm));
                flat.add(am, bm, cm);
            }
            BigInteger[] witness = {BigInteger.ONE};
            var flatR1cs = flat.build();
            BigInteger[] actual = Groth16ProverBLS381.computeH(constraints, witness, rows, n);
            var packed = Groth16ProverBLS381.computeHFlat(flatR1cs, FlatScalars.pack(witness, 1), 0, n);
            if (rows > n / 2) {
                assertThrows(IllegalArgumentException.class,
                        () -> Groth16ProverBLS381.computeH(constraints, witness, rows, n / 2));
                assertThrows(IllegalArgumentException.class,
                        () -> Groth16ProverBLS381.computeHFlat(flatR1cs, FlatScalars.pack(witness, 1), 0, n / 2));
            }
            BigInteger shift = nonresidue.modPow(R.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2L * n)), R);
            BigInteger omega = shift.multiply(shift).mod(R);
            assertEquals(R.subtract(BigInteger.ONE), shift.modPow(BigInteger.valueOf(n), R));
            int[] samples = n <= 16 ? IntStream.range(0, n).toArray()
                    : new int[]{0, 1, n / 3, n / 2, n - 1};
            for (int i : samples) {
                BigInteger x = shift.multiply(omega.modPow(BigInteger.valueOf(i), R)).mod(R);
                BigInteger factor = x.modPow(BigInteger.valueOf(n), R).subtract(BigInteger.ONE)
                        .multiply(BigInteger.valueOf(n).modInverse(R)).mod(R);
                BigInteger aj = BigInteger.ZERO, bj = BigInteger.ZERO, cj = BigInteger.ZERO;
                BigInteger node = BigInteger.ONE;
                for (int j = 0; j < n; j++) {
                    BigInteger basis = factor.multiply(node).multiply(x.subtract(node).mod(R).modInverse(R)).mod(R);
                    aj = aj.add(basis.multiply(a[j])).mod(R);
                    bj = bj.add(basis.multiply(b[j])).mod(R);
                    cj = cj.add(basis.multiply(a[j]).multiply(b[j])).mod(R);
                    node = node.multiply(omega).mod(R);
                }
                // snarkjs H-query basis absorbs division by Z; this API emits A(x)B(x)-C(x).
                BigInteger expected = aj.multiply(bj).subtract(cj).mod(R);
                assertEquals(expected, actual[i], "list rows=" + rows + " coset index=" + i);
                assertEquals(expected, packed.toBigInteger(i), "flat rows=" + rows + " coset index=" + i);
            }
        }
    }
}
