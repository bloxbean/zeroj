package com.bloxbean.cardano.zeroj.cryptoblst;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.blst.ffm.BlstG1Msm;
import com.bloxbean.cardano.zeroj.blst.ffm.BlstG2Msm;
import com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend;
import com.bloxbean.cardano.zeroj.crypto.msm.G1MsmBackend;
import com.bloxbean.cardano.zeroj.crypto.msm.G2MsmBackend;
import com.bloxbean.cardano.zeroj.crypto.msm.ParallelMsm;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * The opt-in blst-accelerated {@link ProverBackend} for the ZeroJ Groth16 prover (ADR-0029).
 *
 * <p>This is the bridge between {@code zeroj-crypto} (the prover's {@code ProverBackend} SPI) and
 * {@code zeroj-blst} (the FFM {@code blst_p1s/p2s_mult_pippenger} bindings). It adapts the prover's
 * point types to blst's uncompressed encoding and routes both G1 and G2 MSMs through blst — a ~5×
 * prove speedup, proofs bit-identical to pure Java. It lives in its own module so {@code
 * zeroj-crypto} stays pure-Java / native-image-clean by default; apps opt in by adding this
 * dependency.</p>
 *
 * <pre>{@code
 * var proof = Groth16ProverBLS381.proveWithReaders(
 *     pk, Groth16ProverBLS381.heapReaders(pk), BlstProverBackend.create(),
 *     witness, constraints, numWires, domainSize);
 * }</pre>
 *
 * <p>Requires {@code --enable-native-access=ALL-UNNAMED} at run time (see {@code zeroj-blst}).</p>
 */
public final class BlstProverBackend {

    private BlstProverBackend() {}

    /**
     * A full G1+G2 blst prover backend, multi-core (ADR-0029 M5b): large MSMs are chunked across
     * cores — each chunk converts its points and makes its own native pippenger call concurrently,
     * partials are summed. Proof identical to the serial path.
     */
    public static ProverBackend create() {
        return new ProverBackend(ParallelMsm.parallel(g1()), ParallelMsm.parallel(g2()));
    }

    /** The single-native-call-per-MSM variant (pre-M5b behavior). */
    public static ProverBackend createSerial() {
        return new ProverBackend(g1(), g2());
    }

    /** The blst G1 MSM backend (reads the prover's flat Montgomery key, calls native pippenger). */
    public static G1MsmBackend g1() {
        return (reader, n, scalars) -> {
            byte[][] enc = new byte[n][];
            long[] buf = new long[12];
            for (int i = 0; i < n; i++) { reader.readInto(i, buf); enc[i] = g1Uncompressed(buf); }
            byte[] r = BlstG1Msm.msm(enc, scalars);
            if ((r[0] & 0x40) != 0) return JacobianG1BLS381.INFINITY;
            return JacobianG1BLS381.fromAffine(be(r, 0, 48), be(r, 48, 96));
        };
    }

    /** The blst G2 MSM backend. */
    public static G2MsmBackend g2() {
        return (points, scalars, n) -> {
            if (n == 0) return JacobianG2BLS381.INFINITY;
            byte[][] enc = new byte[n][];
            BigInteger[] sc = new BigInteger[n];
            for (int i = 0; i < n; i++) { enc[i] = g2Uncompressed(points[i]); sc[i] = scalars[i]; }
            byte[] r = BlstG2Msm.msm(enc, sc);
            if ((r[0] & 0x40) != 0) return JacobianG2BLS381.INFINITY;
            // 192B: x.c1 | x.c0 | y.c1 | y.c0 ; MontFp2_381.of(re=c0, im=c1)
            return JacobianG2BLS381.fromAffine(
                    MontFp2_381.of(be(r, 48, 96), be(r, 0, 48)),
                    MontFp2_381.of(be(r, 144, 192), be(r, 96, 144)));
        };
    }

    // ---- point conversion: prover types → blst uncompressed ----

    private static byte[] g1Uncompressed(long[] montLimbs12) {
        boolean inf = true;
        for (long l : montLimbs12) if (l != 0) { inf = false; break; }
        byte[] b = new byte[96];
        if (inf) { b[0] = 0x40; return b; }
        MontFp381 x = MontFp381.fromMontLimbs(montLimbs12[0], montLimbs12[1], montLimbs12[2],
                montLimbs12[3], montLimbs12[4], montLimbs12[5]);
        MontFp381 y = MontFp381.fromMontLimbs(montLimbs12[6], montLimbs12[7], montLimbs12[8],
                montLimbs12[9], montLimbs12[10], montLimbs12[11]);
        to48BE(x.toBigInteger(), b, 0);
        to48BE(y.toBigInteger(), b, 48);
        return b;
    }

    private static byte[] g2Uncompressed(AffineG2 p) {
        byte[] b = new byte[192];
        if (p.x().re().isZero() && p.x().im().isZero() && p.y().re().isZero() && p.y().im().isZero()) {
            b[0] = 0x40; return b;
        }
        to48BE(p.x().im().toBigInteger(), b, 0);    // x.c1
        to48BE(p.x().re().toBigInteger(), b, 48);   // x.c0
        to48BE(p.y().im().toBigInteger(), b, 96);   // y.c1
        to48BE(p.y().re().toBigInteger(), b, 144);  // y.c0
        return b;
    }

    private static void to48BE(BigInteger v, byte[] out, int off) {
        byte[] be = v.toByteArray();
        int s = Math.max(0, be.length - 48);
        System.arraycopy(be, s, out, off + 48 - (be.length - s), be.length - s);
    }

    private static BigInteger be(byte[] a, int from, int to) {
        return new BigInteger(1, Arrays.copyOfRange(a, from, to));
    }
}
