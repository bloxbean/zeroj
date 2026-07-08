package com.bloxbean.cardano.zeroj.blst.ffm;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.math.BigInteger;

/**
 * Batched BLS12-381 G2 multi-scalar multiplication via blst's native Pippenger
 * ({@code blst_p2s_mult_pippenger}) through one FFM call per MSM (ADR-0029 M8). The pure-Java G2 MSM
 * (`computePiB_G2`) is the prover's dominant remaining cost (the FFT is ~1.5%), so this is the single
 * biggest prove-time lever.
 *
 * <p>Points are 192-byte uncompressed encodings — for each Fp2 coordinate the imaginary part
 * ({@code c1}) precedes the real part ({@code c0}), each 48-byte big-endian: {@code x.c1‖x.c0‖y.c1‖y.c0}
 * (BLS12-381 IETF/ZCash convention). Infinity = the {@code 0x40} flag byte.</p>
 */
public final class BlstG2Msm {

    private BlstG2Msm() {}

    private static final long P2_AFFINE = 192; // 2 * fp2(96)
    private static final long P2 = 288;        // 3 * fp2(96)
    private static final long SCALAR = 32;
    private static final long NBITS = 255;

    private static final ValueLayout.OfByte BYTE = ValueLayout.JAVA_BYTE;
    private static final ValueLayout.OfLong I64 = ValueLayout.JAVA_LONG;

    private static final MethodHandle SCRATCH_SIZEOF = BlstFfm.downcall(
            "blst_p2s_mult_pippenger_scratch_sizeof", FunctionDescriptor.of(I64, I64));
    private static final MethodHandle PIPPENGER = BlstFfm.downcall(
            "blst_p2s_mult_pippenger", FunctionDescriptor.ofVoid(
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, I64, ValueLayout.ADDRESS, I64, ValueLayout.ADDRESS));
    private static final MethodHandle DESERIALIZE = BlstFfm.downcall(
            "blst_p2_deserialize", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle TO_AFFINE = BlstFfm.downcall(
            "blst_p2_to_affine", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle AFFINE_SERIALIZE = BlstFfm.downcall(
            "blst_p2_affine_serialize", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle FROM_AFFINE = BlstFfm.downcall(
            "blst_p2_from_affine", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle P2_MULT = BlstFfm.downcall(
            "blst_p2_mult", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, I64));

    /** {@code Σ scalars[i] · points[i]} → 192-byte uncompressed result. */
    public static byte[] msm(byte[][] uncompressedPoints, BigInteger[] scalars) {
        int n = uncompressedPoints.length;
        if (n == 0) return infinity();
        if (n == 1) return singleMul(uncompressedPoints[0], scalars[0]);
        try (Arena a = Arena.ofConfined()) {
            MemorySegment pts = a.allocate(P2_AFFINE * n);
            MemorySegment inBuf = a.allocate(P2_AFFINE);
            for (int i = 0; i < n; i++) {
                MemorySegment.copy(uncompressedPoints[i], 0, inBuf, BYTE, 0, (int) P2_AFFINE);
                int err = (int) DESERIALIZE.invoke(pts.asSlice(i * P2_AFFINE, P2_AFFINE), inBuf);
                if (err != 0) throw new IllegalArgumentException("blst_p2_deserialize failed at " + i + " (err=" + err + ")");
            }
            MemorySegment scal = a.allocate(SCALAR * n);
            for (int i = 0; i < n; i++)
                MemorySegment.copy(leBytes32(scalars[i]), 0, scal, BYTE, i * SCALAR, 32);

            MemorySegment ptsPtr = a.allocate(ValueLayout.ADDRESS, n);
            MemorySegment scalPtr = a.allocate(ValueLayout.ADDRESS, n);
            for (int i = 0; i < n; i++) {
                ptsPtr.setAtIndex(ValueLayout.ADDRESS, i, pts.asSlice(i * P2_AFFINE, P2_AFFINE));
                scalPtr.setAtIndex(ValueLayout.ADDRESS, i, scal.asSlice(i * SCALAR, SCALAR));
            }
            long scratchBytes = (long) SCRATCH_SIZEOF.invoke((long) n);
            MemorySegment scratch = a.allocate(Math.max(8, scratchBytes));
            MemorySegment ret = a.allocate(P2);
            PIPPENGER.invoke(ret, ptsPtr, (long) n, scalPtr, NBITS, scratch);

            return serializeAffine(a, ret);
        } catch (RuntimeException e) { throw e; } catch (Throwable t) { throw new RuntimeException("blst G2 MSM failed", t); }
    }

    /** Diagnostic single scalar-mul via {@code blst_p2_mult} (n=1; pippenger is batch-only). */
    public static byte[] singleMul(byte[] uncompressedPoint, BigInteger scalar) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment in = a.allocate(P2_AFFINE);
            MemorySegment.copy(uncompressedPoint, 0, in, BYTE, 0, (int) P2_AFFINE);
            MemorySegment aff = a.allocate(P2_AFFINE);
            int err = (int) DESERIALIZE.invoke(aff, in);
            if (err != 0) throw new IllegalArgumentException("deserialize err=" + err);
            MemorySegment jac = a.allocate(P2);
            FROM_AFFINE.invoke(jac, aff);
            MemorySegment sc = a.allocate(SCALAR);
            MemorySegment.copy(leBytes32(scalar), 0, sc, BYTE, 0, 32);
            MemorySegment ret = a.allocate(P2);
            P2_MULT.invoke(ret, jac, sc, NBITS);
            return serializeAffine(a, ret);
        } catch (RuntimeException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    private static byte[] serializeAffine(Arena a, MemorySegment jacP2) throws Throwable {
        MemorySegment retAff = a.allocate(P2_AFFINE);
        TO_AFFINE.invoke(retAff, jacP2);
        MemorySegment out = a.allocate(P2_AFFINE);
        AFFINE_SERIALIZE.invoke(out, retAff);
        byte[] r = new byte[(int) P2_AFFINE];
        MemorySegment.copy(out, BYTE, 0, r, 0, (int) P2_AFFINE);
        return r;
    }

    private static byte[] infinity() { byte[] b = new byte[(int) P2_AFFINE]; b[0] = 0x40; return b; }

    private static byte[] leBytes32(BigInteger v) {
        byte[] be = v.toByteArray(), le = new byte[32];
        for (int i = 0; i < be.length && i < 32; i++) le[i] = be[be.length - 1 - i];
        return le;
    }
}
