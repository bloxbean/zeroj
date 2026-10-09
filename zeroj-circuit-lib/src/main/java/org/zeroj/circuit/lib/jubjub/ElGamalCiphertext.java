package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * An admitted {@code elgamal-jubjub-v1} ciphertext: {@code (A, B)} together with its key context
 * and an <b>established</b> plaintext bound (ADR-0052 D2a, D2c; invariants I7, I13 and I16).
 *
 * <p>The only ways to obtain one are local encryption ({@link ElGamal#encrypt},
 * {@link ElGamal#encryptWithOpening}), verified admission ({@link ElGamal#admit}), and the
 * homomorphic combination ({@link #add}, {@link #sum}, {@link #scale}) of ciphertexts obtained
 * those ways, which carries the combined bound (spec §10.1). There is no constructor from a
 * claimed bound or a claimed key. Homomorphic operations require the same context and refuse a result whose bound reaches
 * {@code l}, so an integer read of a decrypted sum cannot be fooled by a wraparound mod
 * {@code l}.
 *
 * <p>Serialising with {@link #encode()} drops the key and the bound. Decoding the bytes again
 * yields a {@link RawElGamalCiphertext}, which must be admitted again.
 */
public final class ElGamalCiphertext {

    private final JubjubPoint handle;
    private final JubjubPoint blinded;
    private final ElGamalKeyContext context;
    private final BigInteger bound;

    ElGamalCiphertext(JubjubPoint handle, JubjubPoint blinded, ElGamalKeyContext context, BigInteger bound) {
        this.handle = handle.normalized();
        this.blinded = blinded.normalized();
        this.context = context;
        this.bound = bound;
    }

    /**
     * Component-wise sum, encrypting {@code m₁ + m₂} (spec §5).
     *
     * @throws IllegalArgumentException if the contexts differ or the combined bound reaches
     *         {@code l}
     */
    public ElGamalCiphertext add(ElGamalCiphertext other) {
        Objects.requireNonNull(other, "other");
        requireSameContext(other);
        BigInteger sum = requireBound(bound.add(other.bound));
        return new ElGamalCiphertext(
                FastJubjubPoint.of(handle).add(FastJubjubPoint.of(other.handle)).toJubjubPoint(),
                FastJubjubPoint.of(blinded).add(FastJubjubPoint.of(other.blinded)).toJubjubPoint(),
                context, sum);
    }

    /**
     * Sums a non-empty list in one pass, normalizing once.
     *
     * @throws IllegalArgumentException if the list is empty, the contexts differ, or the combined
     *         bound reaches {@code l}
     */
    public static ElGamalCiphertext sum(List<ElGamalCiphertext> ciphertexts) {
        Objects.requireNonNull(ciphertexts, "ciphertexts");
        if (ciphertexts.isEmpty()) {
            throw new IllegalArgumentException("cannot sum an empty list");
        }
        ElGamalCiphertext first = Objects.requireNonNull(ciphertexts.get(0), "ciphertext");
        FastJubjubPoint a = FastJubjubPoint.IDENTITY;
        FastJubjubPoint b = FastJubjubPoint.IDENTITY;
        BigInteger total = BigInteger.ZERO;
        for (ElGamalCiphertext c : ciphertexts) {
            Objects.requireNonNull(c, "ciphertext");
            first.requireSameContext(c);
            total = requireBound(total.add(c.bound));
            a = a.add(FastJubjubPoint.of(c.handle));
            b = b.add(FastJubjubPoint.of(c.blinded));
        }
        return new ElGamalCiphertext(a.toJubjubPoint(), b.toJubjubPoint(), first.context, total);
    }

    /**
     * {@code ([c]·A, [c]·B)}, encrypting {@code c·m} (spec §5).
     *
     * @throws IllegalArgumentException unless {@code 1 ≤ c < l} and {@code c·bound < l}
     */
    public ElGamalCiphertext scale(BigInteger c) {
        Objects.requireNonNull(c, "c");
        if (c.signum() <= 0 || c.compareTo(SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException("scale factor must satisfy 1 <= c < l");
        }
        BigInteger scaled = requireBound(bound.multiply(c));
        return new ElGamalCiphertext(
                FastJubjubPoint.of(handle).scalarMulPublic(c).toJubjubPoint(),
                FastJubjubPoint.of(blinded).scalarMulPublic(c).toJubjubPoint(),
                context, scaled);
    }

    /** {@link #scale(BigInteger)} for a {@code long} factor. */
    public ElGamalCiphertext scale(long c) {
        return scale(BigInteger.valueOf(c));
    }

    /** {@code A}, the decryption handle. */
    public JubjubPoint handle() {
        return handle;
    }

    /** {@code B}, the blinded message. */
    public JubjubPoint blinded() {
        return blinded;
    }

    /** The key context this ciphertext is under. */
    public ElGamalKeyContext context() {
        return context;
    }

    /** The established plaintext bound: the plaintext lies in {@code [0, bound]}. */
    public BigInteger bound() {
        return bound;
    }

    /** The 64-byte encoding (spec §7.2). It carries neither the key nor the bound. */
    public byte[] encode() {
        return raw().encode();
    }

    /** This ciphertext without its key and bound. */
    public RawElGamalCiphertext raw() {
        return new RawElGamalCiphertext(handle, blinded);
    }

    /** Public inputs {@code A.u, A.v, B.u, B.v} (spec §8). */
    public List<BigInteger> publicInputs() {
        return ElGamalEncodings.affine(handle, blinded);
    }

    /** Same {@code (A, B, context)}: the "exact ciphertext" a decryption share is bound to. */
    boolean sameCiphertext(ElGamalCiphertext other) {
        return context.equals(other.context)
                && handle.projectiveEquals(other.handle)
                && blinded.projectiveEquals(other.blinded);
    }

    void requireSameContext(ElGamalCiphertext other) {
        if (!context.equals(other.context)) {
            throw new IllegalArgumentException(
                    "ciphertexts are under different key contexts; homomorphic operations need one key");
        }
    }

    private static BigInteger requireBound(BigInteger bound) {
        if (bound.compareTo(SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException(
                    "plaintext bound would reach l; the result could wrap mod l");
        }
        return bound;
    }

    @Override
    public String toString() {
        return "ElGamalCiphertext{A=" + handle + ", B=" + blinded + ", bound=" + bound
                + ", context=" + context + "}";
    }
}
