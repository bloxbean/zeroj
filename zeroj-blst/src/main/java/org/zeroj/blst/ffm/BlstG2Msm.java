package org.zeroj.blst.ffm;

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
    /** blst limb structs hold 64-bit limbs; allocate them 8-byte aligned rather than relying on malloc. */
    private static final long LIMB_ALIGN = 8;

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
    private static final MethodHandle IN_G2 = BlstFfm.downcall(
            "blst_p2_affine_in_g2", FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));

    /** Supplies point {@code i}'s 192-byte uncompressed encoding into a reusable buffer (ADR-0033 M2). */
    @FunctionalInterface
    public interface G2Encoder {
        /** Write point {@code i} ({@code x.c1‖x.c0‖y.c1‖y.c0} BE, {@code 0x40} = infinity) into {@code dst[0..192)}. */
        void encode(int i, byte[] dst);
    }

    /**
     * {@code Σ (scalars[i] mod r) · points[i]} → 192-byte uncompressed result.
     *
     * <p>Each scalar is reduced mod {@code r}. Each point must be a 192-byte uncompressed encoding
     * without the compression or sort flag; blst checks that it is on the curve. Bases are
     * <b>not</b> subgroup-checked on this hot path, so the caller must supply validated points or
     * use {@link #msmValidated} (ADR-0062 D4). With a base outside the subgroup the result is
     * undefined: for fewer than 32 points a small-order base can corrupt the whole sum, not just add
     * a torsion component.</p>
     *
     * @throws IllegalArgumentException if the lengths differ or an encoding is malformed
     */
    public static byte[] msm(byte[][] uncompressedPoints, BigInteger[] scalars) {
        return msmPoints(uncompressedPoints, scalars, false);
    }

    /**
     * {@link #msm(byte[][], BigInteger[])} that also checks every base is in the G2 subgroup
     * ({@code blst_p2_affine_in_g2}) and rejects it otherwise. Use it for untrusted bases.
     */
    public static byte[] msmValidated(byte[][] uncompressedPoints, BigInteger[] scalars) {
        return msmPoints(uncompressedPoints, scalars, true);
    }

    private static byte[] msmPoints(byte[][] uncompressedPoints, BigInteger[] scalars, boolean validateBases) {
        BlstMsmInputs.requireSameLength(uncompressedPoints.length, scalars);
        for (int i = 0; i < uncompressedPoints.length; i++) {
            BlstMsmInputs.requireLength(uncompressedPoints[i], (int) P2_AFFINE, i);
        }
        return msmCore(uncompressedPoints.length,
                (i, dst) -> System.arraycopy(uncompressedPoints[i], 0, dst, 0, (int) P2_AFFINE),
                (i, dst) -> BlstMsmInputs.scalarLe(scalars[i], dst), validateBases);
    }

    /** Supplies scalar {@code i} as 32 little-endian bytes into a reusable buffer (ADR-0034 M3). */
    @FunctionalInterface
    public interface ScalarEncoder {
        /** Write scalar {@code i} (LE, all 32 bytes) into {@code dst[0..32)}. */
        void encode(int i, byte[] dst);
    }

    /**
     * {@code Σ (scalars[i] mod r) · point_i} over {@code n} encoder-supplied points with boxed
     * scalars. Requires {@code scalars.length == n}. Bases are caller-validated (see
     * {@link #msm(byte[][], BigInteger[])}).
     */
    public static byte[] msm(int n, G2Encoder points, BigInteger[] scalars) {
        BlstMsmInputs.requireSameLength(n, scalars);
        return msmCore(n, points, (i, dst) -> BlstMsmInputs.scalarLe(scalars[i], dst), false);
    }

    /**
     * {@code Σ scalars[i] · point_i} over {@code n} encoder-supplied points and scalars → 192-byte
     * uncompressed result. Streaming variant (ADR-0033 M2 / ADR-0034 M3): each point and scalar is
     * encoded into one reusable buffer straight into the native arrays — no {@code byte[][]} of
     * encodings, no per-scalar byte arrays on heap.
     *
     * <p>Precondition: every scalar is canonical ({@code < r}, 32 bytes little-endian) and every
     * point is a validated subgroup element. A non-canonical scalar or a flagged encoding is
     * rejected (ADR-0062 D4); subgroup membership is the caller's responsibility.</p>
     */
    public static byte[] msm(int n, G2Encoder points, ScalarEncoder scalars) {
        return msmCore(n, points, scalars, false);
    }

    private static byte[] msmCore(int n, G2Encoder points, ScalarEncoder scalars, boolean validateBases) {
        if (n < 0) throw new IllegalArgumentException("n must be non-negative");
        if (n == 0) return infinity();
        byte[] buf = new byte[(int) P2_AFFINE];
        byte[] sbuf = new byte[32];
        try (Arena a = Arena.ofConfined()) {
            // Identity bases contribute nothing and are dropped (ADR-0062 F11; see BlstG1Msm).
            MemorySegment pts = a.allocate(P2_AFFINE * n, LIMB_ALIGN);
            MemorySegment scal = a.allocate(SCALAR * n);
            MemorySegment inBuf = a.allocate(P2_AFFINE, LIMB_ALIGN);
            int m = 0;
            for (int i = 0; i < n; i++) {
                points.encode(i, buf);
                scalars.encode(i, sbuf);
                BlstMsmInputs.requireUncompressedFlags(buf, i);
                BlstMsmInputs.requireCanonicalScalar(sbuf, i);
                MemorySegment.copy(buf, 0, inBuf, BYTE, 0, (int) P2_AFFINE);
                MemorySegment slot = pts.asSlice(m * P2_AFFINE, P2_AFFINE);
                int err = (int) DESERIALIZE.invoke(slot, inBuf);
                if (err != 0) throw new IllegalArgumentException("blst_p2_deserialize failed at " + i + " (err=" + err + ")");
                if ((buf[0] & 0x40) != 0) continue; // a well-formed identity encoding
                if (validateBases && !(boolean) IN_G2.invoke(slot)) {
                    throw new IllegalArgumentException("Point " + i + " is not in the G2 subgroup");
                }
                MemorySegment.copy(sbuf, 0, scal, BYTE, m * SCALAR, 32);
                m++;
            }
            if (m == 0) return infinity();
            if (m == 1) { // pippenger is batch-only
                byte[] base = new byte[(int) P2_AFFINE];
                AFFINE_SERIALIZE.invoke(inBuf, pts.asSlice(0, P2_AFFINE));
                MemorySegment.copy(inBuf, BYTE, 0, base, 0, (int) P2_AFFINE);
                byte[] le = new byte[32];
                MemorySegment.copy(scal, BYTE, 0, le, 0, 32);
                return singleMulCore(base, le, false);
            }
            final int count = m;

            MemorySegment ptsPtr = a.allocate(ValueLayout.ADDRESS, count);
            MemorySegment scalPtr = a.allocate(ValueLayout.ADDRESS, count);
            for (int i = 0; i < count; i++) {
                ptsPtr.setAtIndex(ValueLayout.ADDRESS, i, pts.asSlice(i * P2_AFFINE, P2_AFFINE));
                scalPtr.setAtIndex(ValueLayout.ADDRESS, i, scal.asSlice(i * SCALAR, SCALAR));
            }
            long scratchBytes = (long) SCRATCH_SIZEOF.invoke((long) count);
            MemorySegment scratch = a.allocate(Math.max(8, scratchBytes), LIMB_ALIGN);
            MemorySegment ret = a.allocate(P2, LIMB_ALIGN);
            PIPPENGER.invoke(ret, ptsPtr, (long) count, scalPtr, NBITS, scratch);

            return serializeAffine(a, ret);
        } catch (RuntimeException e) { throw e; } catch (Throwable t) { throw new RuntimeException("blst G2 MSM failed", t); }
    }

    /**
     * Single scalar multiplication {@code [scalar mod r]·point} via {@code blst_p2_mult} (n=1;
     * pippenger is batch-only). The point is checked to be on the curve, not to be in the subgroup.
     */
    public static byte[] singleMul(byte[] uncompressedPoint, BigInteger scalar) {
        BlstMsmInputs.requireLength(uncompressedPoint, (int) P2_AFFINE, 0);
        byte[] le = new byte[32];
        BlstMsmInputs.scalarLe(scalar, le);
        return singleMulCore(uncompressedPoint, le, false);
    }

    private static byte[] singleMulCore(byte[] encoded, byte[] le, boolean validateBase) {
        BlstMsmInputs.requireUncompressedFlags(encoded, 0);
        try (Arena a = Arena.ofConfined()) {
            MemorySegment in = a.allocate(P2_AFFINE, LIMB_ALIGN);
            MemorySegment.copy(encoded, 0, in, BYTE, 0, (int) P2_AFFINE);
            MemorySegment aff = a.allocate(P2_AFFINE, LIMB_ALIGN);
            int err = (int) DESERIALIZE.invoke(aff, in);
            if (err != 0) throw new IllegalArgumentException("deserialize err=" + err);
            if (validateBase && !(boolean) IN_G2.invoke(aff)) {
                throw new IllegalArgumentException("Point 0 is not in the G2 subgroup");
            }
            MemorySegment jac = a.allocate(P2, LIMB_ALIGN);
            FROM_AFFINE.invoke(jac, aff);
            MemorySegment sc = a.allocate(SCALAR);
            MemorySegment.copy(le, 0, sc, BYTE, 0, 32);
            MemorySegment ret = a.allocate(P2, LIMB_ALIGN);
            P2_MULT.invoke(ret, jac, sc, NBITS);
            return serializeAffine(a, ret);
        } catch (RuntimeException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    private static byte[] serializeAffine(Arena a, MemorySegment jacP2) throws Throwable {
        MemorySegment retAff = a.allocate(P2_AFFINE, LIMB_ALIGN);
        TO_AFFINE.invoke(retAff, jacP2);
        MemorySegment out = a.allocate(P2_AFFINE, LIMB_ALIGN);
        AFFINE_SERIALIZE.invoke(out, retAff);
        byte[] r = new byte[(int) P2_AFFINE];
        MemorySegment.copy(out, BYTE, 0, r, 0, (int) P2_AFFINE);
        return r;
    }

    private static byte[] infinity() { byte[] b = new byte[(int) P2_AFFINE]; b[0] = 0x40; return b; }
}
