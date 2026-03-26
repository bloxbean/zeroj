package com.bloxbean.cardano.zeroj.blst;

import supranational.blst.*;

/**
 * BLS12-381 pairing operations via the blst native library.
 *
 * <p>Provides a thin Java-friendly API over the blst SWIG bindings for
 * the operations needed by Groth16 verification: miller loop, multiply
 * miller loop results, and final verification.</p>
 *
 * <p>This follows the same approach as julc-bls {@code BlsOperations} but
 * focused on the pairing subset needed for ZK proof verification.</p>
 */
public final class BlstPairing {

    private BlstPairing() {}

    /**
     * Compute the miller loop for a G1/G2 pair.
     *
     * @param g1Uncompressed 96-byte uncompressed G1 point (x + y, 48 bytes each)
     * @param g2Uncompressed 192-byte uncompressed G2 point (x_c1+x_c0+y_c1+y_c0, 48 bytes each)
     * @return a pairing target (miller loop result)
     */
    public static PT millerLoop(byte[] g1Uncompressed, byte[] g2Uncompressed) {
        var p1 = new P1_Affine(g1Uncompressed);
        var p2 = new P2_Affine(g2Uncompressed);
        return new PT(p1, p2);
    }

    /**
     * Multiply two miller loop results.
     *
     * @return a new PT representing the product
     */
    public static PT mulMlResult(PT a, PT b) {
        var result = a.dup();
        result.mul(b);
        return result;
    }

    /**
     * Final pairing verification: checks if the accumulated pairing result
     * equals the identity element in GT.
     *
     * @param accumulated the accumulated miller loop product
     * @return true if the pairing check passes (product == 1 in GT)
     */
    public static boolean finalVerify(PT accumulated) {
        return PT.finalverify(accumulated, new PT(new P1_Affine(), new P2_Affine()));
    }

    /**
     * Add two G1 points.
     *
     * @param a 96-byte uncompressed G1 point
     * @param b 96-byte uncompressed G1 point
     * @return 96-byte uncompressed result
     */
    public static byte[] g1Add(byte[] a, byte[] b) {
        var pa = new P1(a);
        pa.add(new P1_Affine(b));
        return pa.serialize();
    }

    /**
     * Negate a G1 point.
     */
    public static byte[] g1Neg(byte[] point) {
        var p = new P1(point);
        p.neg();
        return p.serialize();
    }

    /**
     * Scalar multiplication on G1.
     */
    public static byte[] g1ScalarMul(byte[] point, java.math.BigInteger scalar) {
        var p = new P1(point);
        if (scalar.signum() < 0) {
            p.neg();
            scalar = scalar.negate();
        }
        p.mult(scalar);
        return p.serialize();
    }
}
