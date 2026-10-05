package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.COMPRESSED_POINT_BYTES;

/**
 * A decoded {@code elgamal-jubjub-v1} ciphertext {@code (A, B)} with <b>no key and no
 * plaintext bound</b> (spec §7.2, ADR-0052 D2 raw layer).
 *
 * <p>Its points are canonical, on the curve and in the prime-order subgroup; that is all a
 * decoding can establish. Points that decode correctly say nothing about the range of the
 * message or about which key encrypted it. To add or decrypt on the safe path, admit the
 * ciphertext with {@link ElGamal#admit}.
 *
 * <p>{@link #add} and {@link #unmask} are raw-layer conveniences. Their precondition
 * (everything under one key, honest shares) is the caller's, and they give no guarantee
 * against a wrapped sum, a mixed key or a malicious trustee.
 */
public final class RawElGamalCiphertext {

    private final JubjubPoint handle;
    private final JubjubPoint blinded;

    /** Both points must already be validated subgroup points. */
    RawElGamalCiphertext(JubjubPoint handle, JubjubPoint blinded) {
        this.handle = handle.normalized();
        this.blinded = blinded.normalized();
    }

    /**
     * Decodes 64 bytes (spec §7.2): {@code encode(A) ‖ encode(B)}, each canonical and in the
     * prime-order subgroup. The identity is a valid {@code A} or {@code B}.
     *
     * @throws IllegalArgumentException on any other input
     */
    public static RawElGamalCiphertext decode(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length != ElGamalEncodings.CIPHERTEXT_BYTES) {
            throw new IllegalArgumentException("ciphertext must be "
                    + ElGamalEncodings.CIPHERTEXT_BYTES + " bytes, got " + encoded.length);
        }
        return new RawElGamalCiphertext(
                ElGamalEncodings.decodeSubgroupPoint(encoded, 0, "ciphertext handle A"),
                ElGamalEncodings.decodeSubgroupPoint(encoded, COMPRESSED_POINT_BYTES, "ciphertext B"));
    }

    /**
     * Builds a ciphertext from affine integers, for example a ledger datum (spec §7.4). Each
     * coordinate must be canonical in {@code [0, p)} without reduction, and each point on the
     * curve and in the subgroup.
     */
    public static RawElGamalCiphertext fromAffine(
            BigInteger handleU, BigInteger handleV, BigInteger blindedU, BigInteger blindedV) {
        return new RawElGamalCiphertext(
                ElGamalEncodings.affineSubgroupPoint(handleU, handleV, "ciphertext handle A"),
                ElGamalEncodings.affineSubgroupPoint(blindedU, blindedV, "ciphertext B"));
    }

    /** Builds a ciphertext from points, requiring both to be in the prime-order subgroup. */
    public static RawElGamalCiphertext of(JubjubPoint handle, JubjubPoint blinded) {
        return new RawElGamalCiphertext(
                ElGamalEncodings.requireSubgroup(handle, "ciphertext handle A"),
                ElGamalEncodings.requireSubgroup(blinded, "ciphertext B"));
    }

    /** {@code A}. */
    public JubjubPoint handle() {
        return handle;
    }

    /** {@code B}. */
    public JubjubPoint blinded() {
        return blinded;
    }

    /** The 64-byte encoding. */
    public byte[] encode() {
        byte[] out = new byte[ElGamalEncodings.CIPHERTEXT_BYTES];
        System.arraycopy(handle.toBytes(), 0, out, 0, COMPRESSED_POINT_BYTES);
        System.arraycopy(blinded.toBytes(), 0, out, COMPRESSED_POINT_BYTES, COMPRESSED_POINT_BYTES);
        return out;
    }

    /** Public inputs {@code A.u, A.v, B.u, B.v} (spec §8). */
    public List<BigInteger> publicInputs() {
        return ElGamalEncodings.affine(handle, blinded);
    }

    /**
     * Component-wise sum. <b>Raw layer: no guarantee.</b> The result is meaningful only if both
     * ciphertexts are under the same key, and it carries no bound.
     */
    public RawElGamalCiphertext add(RawElGamalCiphertext other) {
        Objects.requireNonNull(other, "other");
        return new RawElGamalCiphertext(
                FastJubjubPoint.of(handle).add(FastJubjubPoint.of(other.handle)).toJubjubPoint(),
                FastJubjubPoint.of(blinded).add(FastJubjubPoint.of(other.blinded)).toJubjubPoint());
    }

    /**
     * {@code B − Σ shares}. <b>Raw layer: no guarantee</b> against a malicious trustee, who can
     * choose the result. Use {@link ElGamal#decrypt} with verified shares instead.
     */
    public static JubjubPoint unmask(JubjubPoint blinded, List<JubjubPoint> shares) {
        Objects.requireNonNull(blinded, "blinded");
        Objects.requireNonNull(shares, "shares");
        List<JubjubPoint> terms = new ArrayList<>(shares.size() + 1);
        terms.add(blinded);
        for (JubjubPoint share : shares) {
            terms.add(Objects.requireNonNull(share, "share").negate());
        }
        return FastJubjubPoint.sum(terms);
    }

    @Override
    public String toString() {
        return "RawElGamalCiphertext{A=" + handle + ", B=" + blinded + "}";
    }
}
