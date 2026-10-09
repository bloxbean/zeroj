package org.zeroj.circuit.lib.jubjub;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Objects;

/**
 * X25519 on 32-byte strings, with the decoding done here rather than by a provider
 * ([RFC 7748] §5; ADR-0054 D8, I10).
 *
 * <p>Two decodings exist on purpose:
 * <ul>
 *   <li>{@link #decodeUCoordinate} is RFC 7748's function decoding: mask bit 255, then reduce
 *       mod {@code p}. HPKE (RFC 9180) uses it, so any 32-byte value is accepted as the function
 *       requires.</li>
 *   <li>{@link #isCanonical} is the {@code dkg-share-delivery-hpke-v1} message rule (spec §2.1):
 *       bit 255 clear and {@code u < p}. Profile messages refuse anything else before X25519 is
 *       called.</li>
 * </ul>
 * Every shared secret is checked against the all-zero value here, independently of the
 * provider (RFC 9180 §7.1.4).
 *
 * <p><b>Input refusals versus faults.</b> A small-order input is the only way the input can make
 * {@link #dh} fail; it is reported as {@link SmallOrderException}, whether SunEC refuses it in
 * {@code doPhase} or a provider returns the all-zero value. Every other exception is a fault of
 * the platform, and callers must not treat it as a property of the input (review Z-1).
 *
 * <p><b>Secret.</b> Private scalars are compatibility/offline class (ADR-0039 §3.1). The DH
 * itself is the JDK provider's (SunEC); no constant-time claim is made for this class.
 */
final class X25519Bytes {

    /** {@code p = 2^255 − 19}. */
    static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    /** The RFC 7748 base point, {@code u = 9}. */
    static final byte[] BASE_POINT = littleEndian(BigInteger.valueOf(9));

    /** The small-order probe scalar of spec §2.2: {@code 0x09 ‖ 0^31}. */
    static final byte[] PROBE = BASE_POINT.clone();

    private X25519Bytes() {
    }

    /** {@code X25519(k, u)} refused because {@code u} has small order: a property of the input. */
    static final class SmallOrderException extends GeneralSecurityException {
        SmallOrderException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Spec §2.1: exactly 32 bytes, bit 255 clear and {@code u < p}. */
    static boolean isCanonical(byte[] b) {
        if (b == null || b.length != 32 || (b[31] & 0x80) != 0) {
            return false;
        }
        return littleEndianToInteger(b).compareTo(P) < 0;
    }

    /** RFC 7748 §5 {@code decodeUCoordinate}: masks bit 255, then reduces mod {@code p}. */
    static BigInteger decodeUCoordinate(byte[] b) {
        if (b == null || b.length != 32) {
            throw new IllegalArgumentException("an X25519 value is 32 bytes");
        }
        byte[] masked = b.clone();
        masked[31] &= 0x7F;
        return littleEndianToInteger(masked).mod(P);
    }

    /** The provider public key for a 32-byte u-coordinate, decoded per RFC 7748 §5. */
    static PublicKey publicKey(byte[] b) throws GeneralSecurityException {
        return KeyFactory.getInstance("XDH")
                .generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, decodeUCoordinate(b)));
    }

    /** The provider private key for a 32-byte scalar (clamped by X25519 itself). */
    static PrivateKey privateKey(byte[] scalar) throws GeneralSecurityException {
        if (scalar == null || scalar.length != 32) {
            throw new IllegalArgumentException("an X25519 private key is 32 bytes");
        }
        return KeyFactory.getInstance("XDH").generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, scalar));
    }

    /**
     * {@code X25519(scalar, u)}, refusing an all-zero result (RFC 9180 §7.1.4, RFC 7748 §6.1).
     *
     * @throws SmallOrderException      if {@code u} has small order: the result is all-zero, or
     *                                  the provider refused the point in {@code doPhase}
     * @throws GeneralSecurityException any other failure, which is a fault of the platform
     */
    static byte[] dh(PrivateKey scalar, byte[] u) throws GeneralSecurityException {
        Objects.requireNonNull(scalar, "scalar");
        PublicKey point = publicKey(u);
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(scalar);
        try {
            agreement.doPhase(point, true);
        } catch (InvalidKeyException refused) {
            // SunEC computes the result here and refuses small order ("Point has small order").
            // The key and the point are this provider's own objects, so nothing else about the
            // input can be refused at this step.
            throw new SmallOrderException("small-order X25519 input", refused);
        }
        byte[] shared = agreement.generateSecret();
        if (isAllZero(shared)) {
            throw new SmallOrderException("all-zero X25519 output", null);
        }
        return shared;
    }

    /** {@code X25519(scalar, 9)}: the public key of a private scalar. */
    static byte[] publicFromPrivate(byte[] scalar) throws GeneralSecurityException {
        return dh(privateKey(scalar), BASE_POINT);
    }

    /**
     * Spec §2.2: {@code X25519(PROBE, u) ≠ 0^32}, i.e. {@code u} is not of small order.
     *
     * @throws IllegalStateException if X25519 fails for any other reason (a platform fault, never
     *                               reported as a property of {@code u})
     */
    static boolean passesSmallOrderProbe(byte[] u) {
        try {
            dh(privateKey(PROBE), u);
            return true;
        } catch (SmallOrderException smallOrder) {
            return false;
        } catch (GeneralSecurityException fault) {
            throw new IllegalStateException("X25519 is unavailable", fault);
        }
    }

    static boolean isAllZero(byte[] b) {
        int acc = 0;
        for (byte x : b) acc |= x;
        return acc == 0;
    }

    private static BigInteger littleEndianToInteger(byte[] b) {
        byte[] be = new byte[b.length];
        for (int i = 0; i < b.length; i++) be[i] = b[b.length - 1 - i];
        return new BigInteger(1, be);
    }

    static byte[] littleEndian(BigInteger u) {
        byte[] out = new byte[32];
        byte[] be = u.toByteArray();
        for (int i = 0; i < be.length && i < 32; i++) out[i] = be[be.length - 1 - i];
        return out;
    }
}
