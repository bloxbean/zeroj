package org.zeroj.crypto.groth16;

import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.MontFp2_381;
import org.zeroj.crypto.msm.FlatScalars;
import org.zeroj.crypto.msm.G2AffineReader;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Bucket MSM versus a separate affine BigInteger double-and-add implementation. */
class G2MsmOracleTest {
    private static final BigInteger R = Bls12381Generators.SCALAR_FIELD_ORDER;

    @Test void affineOracleCoversWindowsAndScalarBoundaries() {
        Random random = new Random(0x47B12581L);
        G2Point g = Bls12381Generators.G2;
        for (int n : new int[]{0, 1, 2, 7, 8, 15, 16, 31, 32, 64}) {
            AffineG2[] points = new AffineG2[n];
            BigInteger[] scalars = new BigInteger[n];
            G2Point expected = G2Point.INFINITY;
            BigInteger[] boundaries = {BigInteger.ZERO, BigInteger.ONE, R.subtract(BigInteger.ONE),
                    R, R.add(BigInteger.ONE), BigInteger.ONE.negate(), BigInteger.ONE.shiftLeft(254)};
            for (int i = 0; i < n; i++) {
                G2Point p = i % 5 == 1 ? G2Point.INFINITY : g.scalarMul(BigInteger.valueOf(1 + i % 4));
                scalars[i] = i < boundaries.length ? boundaries[i] : new BigInteger(255, random).mod(R);
                points[i] = p.isInfinity() ? AffineG2.INFINITY : new AffineG2(
                        MontFp2_381.of(p.x().c0().value(), p.x().c1().value()),
                        MontFp2_381.of(p.y().c0().value(), p.y().c1().value()));
                expected = expected.add(p.scalarMul(scalars[i].mod(R)));
            }
            var actual = Groth16ProverBLS381.g2Msm(new G2AffineReader.HeapG2Reader(points),
                    FlatScalars.pack(scalars, n), n).toAffine();
            var oracle = expected.isInfinity() ? AffineG2.INFINITY : new AffineG2(
                    MontFp2_381.of(expected.x().c0().value(), expected.x().c1().value()),
                    MontFp2_381.of(expected.y().c0().value(), expected.y().c1().value()));
            assertEquals(oracle, actual, "G2 MSM n=" + n);
        }
        var gAffine = JacobianG2BLS381.GENERATOR.toAffine();
        assertEquals(AffineG2.INFINITY, Groth16ProverBLS381.g2Msm(
                new G2AffineReader.HeapG2Reader(new AffineG2[]{gAffine, gAffine}),
                FlatScalars.pack(new BigInteger[]{BigInteger.ONE, R.subtract(BigInteger.ONE)}, 2), 2).toAffine());
    }
}
