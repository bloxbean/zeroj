package org.zeroj.blst.ffm;

import org.zeroj.bls12381.Bls12381Generators;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * BLS12-381 point arithmetic and pairing over the source-built {@code libblst}, through FFM
 * (ADR-0062 D3). It replaces the prebuilt JNI {@code foundation.icon:blst-java} binding, so every
 * native BLS12-381 path in ZeroJ runs the same pinned library (I4).
 *
 * <p>Points cross this API as uncompressed ZCash encodings: 96 bytes for G1 ({@code x‖y}), 192 bytes
 * for G2 ({@code x.c1‖x.c0‖y.c1‖y.c0}), big-endian, with {@code 0x40} as the identity flag. Every
 * method validates its point inputs and rejects anything else with {@link IllegalArgumentException}:
 * exact length, no compression or sort flag, well-formed per {@code blst_p*_deserialize}
 * (coordinates {@code < p}, on the curve), and in the prime-order subgroup
 * ({@code blst_p*_affine_in_g*}). Scalars are reduced mod {@code r}. Every {@code BLST_ERROR} is
 * checked. Memory lives in a confined {@link Arena} per call.</p>
 *
 * <p>No side-channel property is claimed for any method (ADR-0062 D2, Q2).</p>
 */
public final class BlstCurve {

    private BlstCurve() {}

    /** Result of validating a point encoding. */
    public enum PointStatus {
        /** A valid, non-identity subgroup point. */
        VALID,
        /** The canonical identity encoding. */
        IDENTITY,
        /** Wrong length, a compression/sort flag, a non-canonical coordinate, or another bad encoding. */
        BAD_ENCODING,
        NOT_ON_CURVE,
        NOT_IN_SUBGROUP
    }

    static final int G1_BYTES = 96;
    static final int G2_BYTES = 192;
    private static final long P1_AFFINE = 96;
    private static final long P1 = 144;
    private static final long P2_AFFINE = 192;
    private static final long P2 = 288;
    private static final long FP12 = 576;
    private static final long NBITS = 255;
    private static final BigInteger R = Bls12381Generators.SCALAR_FIELD_ORDER;

    private static final ValueLayout.OfByte BYTE = ValueLayout.JAVA_BYTE;
    private static final ValueLayout.OfInt INT = ValueLayout.JAVA_INT;
    private static final ValueLayout.OfBoolean BOOL = ValueLayout.JAVA_BOOLEAN;
    private static final ValueLayout ADDR = ValueLayout.ADDRESS;

    // BLST_ERROR values (blst.h)
    private static final int BLST_SUCCESS = 0;
    private static final int BLST_POINT_NOT_ON_CURVE = 2;
    private static final int BLST_POINT_NOT_IN_GROUP = 3;

    private static final MethodHandle P1_DESERIALIZE = h("blst_p1_deserialize", FunctionDescriptor.of(INT, ADDR, ADDR));
    private static final MethodHandle P1_AFFINE_IN_G1 = h("blst_p1_affine_in_g1", FunctionDescriptor.of(BOOL, ADDR));
    private static final MethodHandle P1_AFFINE_IS_INF = h("blst_p1_affine_is_inf", FunctionDescriptor.of(BOOL, ADDR));
    private static final MethodHandle P1_FROM_AFFINE = h("blst_p1_from_affine", FunctionDescriptor.ofVoid(ADDR, ADDR));
    private static final MethodHandle P1_SERIALIZE = h("blst_p1_serialize", FunctionDescriptor.ofVoid(ADDR, ADDR));
    private static final MethodHandle P1_ADD = h("blst_p1_add_or_double", FunctionDescriptor.ofVoid(ADDR, ADDR, ADDR));
    private static final MethodHandle P1_CNEG = h("blst_p1_cneg", FunctionDescriptor.ofVoid(ADDR, BOOL));
    private static final MethodHandle P1_MULT = h("blst_p1_mult", FunctionDescriptor.ofVoid(ADDR, ADDR, ADDR, ValueLayout.JAVA_LONG));
    private static final MethodHandle P1_GENERATOR = h("blst_p1_generator", FunctionDescriptor.of(ADDR));

    private static final MethodHandle P2_DESERIALIZE = h("blst_p2_deserialize", FunctionDescriptor.of(INT, ADDR, ADDR));
    private static final MethodHandle P2_AFFINE_IN_G2 = h("blst_p2_affine_in_g2", FunctionDescriptor.of(BOOL, ADDR));
    private static final MethodHandle P2_AFFINE_IS_INF = h("blst_p2_affine_is_inf", FunctionDescriptor.of(BOOL, ADDR));
    private static final MethodHandle P2_FROM_AFFINE = h("blst_p2_from_affine", FunctionDescriptor.ofVoid(ADDR, ADDR));
    private static final MethodHandle P2_SERIALIZE = h("blst_p2_serialize", FunctionDescriptor.ofVoid(ADDR, ADDR));
    private static final MethodHandle P2_ADD = h("blst_p2_add_or_double", FunctionDescriptor.ofVoid(ADDR, ADDR, ADDR));
    private static final MethodHandle P2_CNEG = h("blst_p2_cneg", FunctionDescriptor.ofVoid(ADDR, BOOL));
    private static final MethodHandle P2_MULT = h("blst_p2_mult", FunctionDescriptor.ofVoid(ADDR, ADDR, ADDR, ValueLayout.JAVA_LONG));
    private static final MethodHandle P2_GENERATOR = h("blst_p2_generator", FunctionDescriptor.of(ADDR));

    private static final MethodHandle MILLER_LOOP = h("blst_miller_loop", FunctionDescriptor.ofVoid(ADDR, ADDR, ADDR));
    private static final MethodHandle FP12_MUL = h("blst_fp12_mul", FunctionDescriptor.ofVoid(ADDR, ADDR, ADDR));
    private static final MethodHandle FINAL_EXP = h("blst_final_exp", FunctionDescriptor.ofVoid(ADDR, ADDR));
    private static final MethodHandle FP12_IS_ONE = h("blst_fp12_is_one", FunctionDescriptor.of(BOOL, ADDR));

    private static MethodHandle h(String name, FunctionDescriptor descriptor) {
        return BlstFfm.downcall(name, descriptor);
    }

    // ---- validation ----

    /** Validates a 96-byte uncompressed G1 encoding without throwing. */
    public static PointStatus g1Status(byte[] uncompressed) {
        try (Arena a = Arena.ofConfined()) {
            return status(a, uncompressed, true);
        }
    }

    /** Validates a 192-byte uncompressed G2 encoding without throwing. */
    public static PointStatus g2Status(byte[] uncompressed) {
        try (Arena a = Arena.ofConfined()) {
            return status(a, uncompressed, false);
        }
    }

    // ---- generators ----

    public static byte[] g1Generator() {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment g = ((MemorySegment) P1_GENERATOR.invoke()).reinterpret(P1);
            return serialize(a, g, true);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    public static byte[] g2Generator() {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment g = ((MemorySegment) P2_GENERATOR.invoke()).reinterpret(P2);
            return serialize(a, g, false);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    // ---- group operations ----

    public static byte[] g1Add(byte[] left, byte[] right) {
        return add(left, right, true);
    }

    public static byte[] g2Add(byte[] left, byte[] right) {
        return add(left, right, false);
    }

    public static byte[] g1Negate(byte[] point) {
        return negate(point, true);
    }

    public static byte[] g2Negate(byte[] point) {
        return negate(point, false);
    }

    /** {@code [scalar mod r]·point} on the public path (blst_p1_mult, 255 bits). */
    public static byte[] g1Mul(byte[] point, BigInteger scalar) {
        return mul(point, scalar, true, false);
    }

    /** {@code [scalar mod r]·point} on the public path (blst_p2_mult, 255 bits). */
    public static byte[] g2Mul(byte[] point, BigInteger scalar) {
        return mul(point, scalar, false, false);
    }

    /**
     * {@code [scalar mod r]·point} for a secret scalar (ADR-0062 D2): the scalar is written as a
     * fixed 32-byte little-endian value without {@code toByteArray} length variance, {@code blst}
     * always runs with {@code nbits = 255}, there is no zero-scalar early return, and the temporary
     * Java and native copies of the scalar are zeroed. Any side-channel property comes from blst's
     * internal scalar multiplication, which ZeroJ has not evaluated; {@link BigInteger#mod} is
     * variable-time.
     */
    public static byte[] g1MulSecret(byte[] point, BigInteger scalar) {
        return mul(point, scalar, true, true);
    }

    /** G2 counterpart of {@link #g1MulSecret}. */
    public static byte[] g2MulSecret(byte[] point, BigInteger scalar) {
        return mul(point, scalar, false, true);
    }

    // ---- pairing ----

    /**
     * Whether {@code ∏ e(g1[i], g2[i])} is the identity of GT, via {@code blst_miller_loop},
     * {@code blst_fp12_mul}, {@code blst_final_exp} and {@code blst_fp12_is_one}.
     *
     * <p>Fails closed: null, unequal-length or empty arrays, and any point that is not a valid
     * subgroup point or the identity, are rejected with an exception. A pair with an identity
     * component contributes 1.</p>
     */
    public static boolean pairingProductIsOne(byte[][] g1Points, byte[][] g2Points) {
        Objects.requireNonNull(g1Points, "g1Points required");
        Objects.requireNonNull(g2Points, "g2Points required");
        if (g1Points.length != g2Points.length) {
            throw new IllegalArgumentException("Pairing point arrays must have the same length");
        }
        if (g1Points.length == 0) {
            throw new IllegalArgumentException("Pairing product input must not be empty");
        }
        try (Arena a = Arena.ofConfined()) {
            MemorySegment acc = null;
            MemorySegment term = a.allocate(FP12);
            for (int i = 0; i < g1Points.length; i++) {
                MemorySegment p = affine(a, g1Points[i], true, "g1[" + i + "]");
                MemorySegment q = affine(a, g2Points[i], false, "g2[" + i + "]");
                if ((boolean) P1_AFFINE_IS_INF.invoke(p) || (boolean) P2_AFFINE_IS_INF.invoke(q)) {
                    continue;
                }
                if (acc == null) {
                    acc = a.allocate(FP12);
                    MILLER_LOOP.invoke(acc, q, p);
                } else {
                    MILLER_LOOP.invoke(term, q, p);
                    FP12_MUL.invoke(acc, acc, term);
                }
            }
            if (acc == null) {
                return true; // every pair had an identity component
            }
            MemorySegment gt = a.allocate(FP12);
            FINAL_EXP.invoke(gt, acc);
            return (boolean) FP12_IS_ONE.invoke(gt);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    // ---- internals ----

    private static byte[] add(byte[] left, byte[] right, boolean g1) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment l = projective(a, affine(a, left, g1, "left"), g1);
            MemorySegment r = projective(a, affine(a, right, g1, "right"), g1);
            MemorySegment out = a.allocate(g1 ? P1 : P2);
            (g1 ? P1_ADD : P2_ADD).invoke(out, l, r);
            return serialize(a, out, g1);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    private static byte[] negate(byte[] point, boolean g1) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment p = projective(a, affine(a, point, g1, "point"), g1);
            (g1 ? P1_CNEG : P2_CNEG).invoke(p, true);
            return serialize(a, p, g1);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    private static byte[] mul(byte[] point, BigInteger scalar, boolean g1, boolean secret) {
        Objects.requireNonNull(scalar, "scalar required");
        byte[] le = new byte[32];
        try (Arena a = Arena.ofConfined()) {
            MemorySegment p = projective(a, affine(a, point, g1, "point"), g1);
            if (secret) {
                fixedWidthLe(scalar.mod(R), le);
            } else {
                BlstMsmInputs.scalarLe(scalar, le);
            }
            MemorySegment sc = a.allocate(32);
            try {
                MemorySegment.copy(le, 0, sc, BYTE, 0, 32);
                MemorySegment out = a.allocate(g1 ? P1 : P2);
                (g1 ? P1_MULT : P2_MULT).invoke(out, p, sc, NBITS);
                return serialize(a, out, g1);
            } finally {
                sc.fill((byte) 0);
            }
        } catch (Throwable t) {
            throw rethrow(t);
        } finally {
            Arrays.fill(le, (byte) 0);
        }
    }

    /** 32-byte little-endian encoding of a reduced scalar with a fixed loop count. */
    private static void fixedWidthLe(BigInteger reduced, byte[] dst) {
        for (int i = 0; i < 32; i++) {
            dst[i] = (byte) reduced.shiftRight(8 * i).intValue();
        }
    }

    /** Deserialize and fully validate; returns a native affine point (the identity is allowed). */
    private static MemorySegment affine(Arena a, byte[] encoding, boolean g1, String label) throws Throwable {
        MemorySegment out = a.allocate(g1 ? P1_AFFINE : P2_AFFINE);
        PointStatus status = decode(a, encoding, g1, out);
        if (status != PointStatus.VALID && status != PointStatus.IDENTITY) {
            throw new IllegalArgumentException(label + " is not a valid " + (g1 ? "G1" : "G2") + " point: " + status);
        }
        return out;
    }

    private static PointStatus status(Arena a, byte[] encoding, boolean g1) {
        try {
            return decode(a, encoding, g1, a.allocate(g1 ? P1_AFFINE : P2_AFFINE));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    private static PointStatus decode(Arena a, byte[] encoding, boolean g1, MemorySegment out) throws Throwable {
        int len = g1 ? G1_BYTES : G2_BYTES;
        if (encoding == null || encoding.length != len || (encoding[0] & 0xA0) != 0) {
            return PointStatus.BAD_ENCODING;
        }
        MemorySegment in = a.allocate(len);
        MemorySegment.copy(encoding, 0, in, BYTE, 0, len);
        int err = (int) (g1 ? P1_DESERIALIZE : P2_DESERIALIZE).invoke(out, in);
        if (err == BLST_POINT_NOT_ON_CURVE) return PointStatus.NOT_ON_CURVE;
        if (err == BLST_POINT_NOT_IN_GROUP) return PointStatus.NOT_IN_SUBGROUP;
        if (err != BLST_SUCCESS) return PointStatus.BAD_ENCODING;
        if ((encoding[0] & 0x40) != 0) {
            return PointStatus.IDENTITY; // blst accepted the flag only with all-zero coordinates
        }
        if ((boolean) (g1 ? P1_AFFINE_IS_INF : P2_AFFINE_IS_INF).invoke(out)) {
            // all-zero coordinates without the identity flag: not the canonical identity encoding
            return PointStatus.BAD_ENCODING;
        }
        if (!(boolean) (g1 ? P1_AFFINE_IN_G1 : P2_AFFINE_IN_G2).invoke(out)) {
            return PointStatus.NOT_IN_SUBGROUP;
        }
        return PointStatus.VALID;
    }

    private static MemorySegment projective(Arena a, MemorySegment affine, boolean g1) throws Throwable {
        MemorySegment out = a.allocate(g1 ? P1 : P2);
        (g1 ? P1_FROM_AFFINE : P2_FROM_AFFINE).invoke(out, affine);
        return out;
    }

    private static byte[] serialize(Arena a, MemorySegment projective, boolean g1) throws Throwable {
        int len = g1 ? G1_BYTES : G2_BYTES;
        MemorySegment out = a.allocate(len);
        (g1 ? P1_SERIALIZE : P2_SERIALIZE).invoke(out, projective);
        byte[] bytes = new byte[len];
        MemorySegment.copy(out, BYTE, 0, bytes, 0, len);
        return bytes;
    }

    private static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException e) return e;
        if (t instanceof Error e) throw e;
        return new RuntimeException("blst call failed", t);
    }
}
