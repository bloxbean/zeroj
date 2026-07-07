package com.bloxbean.cardano.zeroj.blst.ffm;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.math.BigInteger;

/**
 * Batched BLS12-381 G1 multi-scalar multiplication via blst's native Pippenger
 * ({@code blst_p1s_mult_pippenger}), through a single FFM call per MSM (ADR-0029 M6 / Rung B) —
 * unlike the per-op wrapper path, whose {@code numWindows·n} JNI calls made it no faster than
 * pure Java.
 *
 * <p>Points are supplied as 96-byte big-endian uncompressed encodings (x‖y; infinity = the
 * {@code 0x40} flag byte); the result is the same encoding. Scalars are reduced/encoded little-endian
 * (blst convention). All marshalling happens in a confined {@link Arena} per call.</p>
 */
public final class BlstG1Msm {

    private BlstG1Msm() {}

    private static final long P1_AFFINE = 96;   // sizeof(blst_p1_affine) = 2 * fp(48)
    private static final long P1 = 144;         // sizeof(blst_p1)        = 3 * fp(48)
    private static final long SCALAR = 32;
    private static final long NBITS = 255;      // BLS12-381 Fr

    private static final ValueLayout.OfByte BYTE = ValueLayout.JAVA_BYTE;
    private static final ValueLayout.OfLong I64 = ValueLayout.JAVA_LONG;

    private static final MethodHandle SCRATCH_SIZEOF = BlstFfm.downcall(
            "blst_p1s_mult_pippenger_scratch_sizeof", FunctionDescriptor.of(I64, I64));
    private static final MethodHandle PIPPENGER = BlstFfm.downcall(
            "blst_p1s_mult_pippenger", FunctionDescriptor.ofVoid(
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, I64, ValueLayout.ADDRESS, I64, ValueLayout.ADDRESS));
    private static final MethodHandle DESERIALIZE = BlstFfm.downcall(
            "blst_p1_deserialize", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle TO_AFFINE = BlstFfm.downcall(
            "blst_p1_to_affine", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle AFFINE_SERIALIZE = BlstFfm.downcall(
            "blst_p1_affine_serialize", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle FROM_AFFINE = BlstFfm.downcall(
            "blst_p1_from_affine", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle P1_MULT = BlstFfm.downcall(
            "blst_p1_mult", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, I64));

    /** Diagnostic single scalar-mul {@code scalar·point} via blst (isolates conversion from pippenger). */
    public static byte[] singleMul(byte[] uncompressedPoint, BigInteger scalar) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment in = a.allocate(P1_AFFINE);
            MemorySegment.copy(uncompressedPoint, 0, in, BYTE, 0, 96);
            MemorySegment aff = a.allocate(P1_AFFINE);
            int err = (int) DESERIALIZE.invoke(aff, in);
            if (err != 0) throw new IllegalArgumentException("deserialize err=" + err);
            MemorySegment jac = a.allocate(P1);
            FROM_AFFINE.invoke(jac, aff);
            byte[] le = leBytes32(scalar);
            MemorySegment sc = a.allocate(SCALAR);
            MemorySegment.copy(le, 0, sc, BYTE, 0, 32);
            MemorySegment ret = a.allocate(P1);
            P1_MULT.invoke(ret, jac, sc, NBITS);
            MemorySegment retAff = a.allocate(P1_AFFINE);
            TO_AFFINE.invoke(retAff, ret);
            MemorySegment out = a.allocate(P1_AFFINE);
            AFFINE_SERIALIZE.invoke(out, retAff);
            byte[] r = new byte[96];
            MemorySegment.copy(out, BYTE, 0, r, 0, 96);
            return r;
        } catch (RuntimeException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    /**
     * {@code Σ scalars[i] · points[i]} → 96-byte uncompressed result.
     *
     * @param uncompressedPoints {@code n} points, each 96 bytes (big-endian x‖y, {@code 0x40} = infinity)
     * @param scalars            {@code n} scalars
     */
    public static byte[] msm(byte[][] uncompressedPoints, BigInteger[] scalars) {
        int n = uncompressedPoints.length;
        if (n == 0) return infinity();
        if (n == 1) return singleMul(uncompressedPoints[0], scalars[0]); // pippenger is batch-only
        try (Arena a = Arena.ofConfined()) {
            // Deserialize each point into a contiguous internal blst_p1_affine array.
            MemorySegment pts = a.allocate(P1_AFFINE * n);
            MemorySegment inBuf = a.allocate(P1_AFFINE);
            for (int i = 0; i < n; i++) {
                MemorySegment.copy(uncompressedPoints[i], 0, inBuf, BYTE, 0, 96);
                int err = (int) DESERIALIZE.invoke(pts.asSlice(i * P1_AFFINE, P1_AFFINE), inBuf);
                if (err != 0) throw new IllegalArgumentException("blst_p1_deserialize failed at " + i + " (err=" + err + ")");
            }

            // Contiguous little-endian scalars.
            MemorySegment scal = a.allocate(SCALAR * n);
            for (int i = 0; i < n; i++) {
                byte[] le = leBytes32(scalars[i]);
                MemorySegment.copy(le, 0, scal, BYTE, i * SCALAR, 32);
            }

            // points[]/scalars[] are arrays of n pointers into the contiguous buffers.
            MemorySegment ptsPtr = a.allocate(ValueLayout.ADDRESS, n);
            MemorySegment scalPtr = a.allocate(ValueLayout.ADDRESS, n);
            for (int i = 0; i < n; i++) {
                ptsPtr.setAtIndex(ValueLayout.ADDRESS, i, pts.asSlice(i * P1_AFFINE, P1_AFFINE));
                scalPtr.setAtIndex(ValueLayout.ADDRESS, i, scal.asSlice(i * SCALAR, SCALAR));
            }

            long scratchBytes = (long) SCRATCH_SIZEOF.invoke((long) n);
            MemorySegment scratch = a.allocate(Math.max(8, scratchBytes));
            MemorySegment ret = a.allocate(P1);
            PIPPENGER.invoke(ret, ptsPtr, (long) n, scalPtr, NBITS, scratch);

            MemorySegment retAff = a.allocate(P1_AFFINE);
            TO_AFFINE.invoke(retAff, ret);
            MemorySegment out = a.allocate(P1_AFFINE);
            AFFINE_SERIALIZE.invoke(out, retAff);

            byte[] result = new byte[96];
            MemorySegment.copy(out, BYTE, 0, result, 0, 96);
            return result;
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException("blst G1 MSM failed", t);
        }
    }

    private static byte[] infinity() {
        byte[] b = new byte[96];
        b[0] = 0x40;
        return b;
    }

    /** 32-byte little-endian encoding of {@code v mod 2^256} (blst scalar convention). */
    private static byte[] leBytes32(BigInteger v) {
        byte[] be = v.toByteArray();
        byte[] le = new byte[32];
        for (int i = 0; i < be.length && i < 32; i++) le[i] = be[be.length - 1 - i];
        return le;
    }
}
