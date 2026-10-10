package org.zeroj.circuit.lib.jubjub;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * HPKE [RFC 9180] in Base mode for the single suite of {@code dkg-share-delivery-hpke-v1}
 * (ADR-0054 D1): DHKEM(X25519, HKDF-SHA256) {@code 0x0020}, HKDF-SHA256 {@code 0x0001},
 * ChaCha20Poly1305 {@code 0x0003}. Assembled from the RFC text on JDK primitives
 * ({@code javax.crypto.KDF}, SunEC X25519, SunJCE ChaCha20-Poly1305) through algorithm-only
 * lookups (see {@link X25519Bytes} on providers).
 *
 * <p>Production code uses only single-shot SealBase and OpenBase (§6.1), at sequence number 0:
 * {@link #sealBaseWithEphemeral} with an ephemeral key the caller drew from a {@code SecureRandom}
 * (or {@link #sealBase}, which draws it), and {@link #openBase}. {@link Context#setSequence} exists
 * so that the RFC 9180 Appendix A.2.1 known-answer tests can exercise every listed sequence
 * number, and {@link #deriveKeyPair} and {@link #setupBaseSWithEphemeral} are test seams. The
 * export interface is not provided.
 *
 * <p><b>Failures.</b> A failure caused by the input is an {@link HpkeException}: a small-order
 * {@code enc} or {@code pkR} (RFC 9180 §7.1.4, RFC 7748 §6.1), a wrong length, an AEAD
 * authentication failure, or the message limit. Any other failure of the underlying primitives
 * (a missing or failing provider) is an {@link IllegalStateException}: it says nothing about the
 * input, and callers must not treat it as one (review Z-1).
 *
 * <p><b>Secret.</b> Private keys, shared secrets and AEAD keys are compatibility/offline class
 * (ADR-0039 §3.1). Intermediate arrays are wiped on a best-effort basis.
 */
final class Hpke {

    static final int KEM_ID = 0x0020;
    static final int KDF_ID = 0x0001;
    static final int AEAD_ID = 0x0003;
    static final int N_SECRET = 32;
    static final int N_ENC = 32;
    static final int N_PK = 32;
    static final int N_SK = 32;
    static final int N_K = 32;
    static final int N_N = 12;
    static final int N_T = 16;
    static final int N_H = 32;
    private static final byte MODE_BASE = 0x00;

    private static final byte[] HPKE_V1 = ascii("HPKE-v1");
    /** {@code "KEM" ‖ I2OSP(kem_id, 2)} (§4.1). */
    private static final byte[] KEM_SUITE_ID = concat(ascii("KEM"), i2osp(KEM_ID, 2));
    /** {@code "HPKE" ‖ I2OSP(kem_id, 2) ‖ I2OSP(kdf_id, 2) ‖ I2OSP(aead_id, 2)} (§5.1). */
    private static final byte[] HPKE_SUITE_ID = concat(ascii("HPKE"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2));
    private static final byte[] EMPTY = new byte[0];

    private Hpke() {
    }

    /**
     * An HPKE failure caused by the input (see the class documentation). The message is generic on
     * purpose; callers treat it as absence.
     */
    static final class HpkeException extends Exception {
        HpkeException(Throwable cause) {
            super("HPKE operation failed", cause);
        }
    }

    /**
     * Classifies a failure of the primitives: an {@link HpkeException} if the input caused it,
     * otherwise an {@link IllegalStateException} thrown from here.
     */
    private static HpkeException inputFailure(Exception e) {
        if (e instanceof X25519Bytes.SmallOrderException || e instanceof AEADBadTagException) {
            return new HpkeException(e);
        }
        throw new IllegalStateException("HPKE primitive failure (a platform fault, not a property of the input)", e);
    }

    private static void wipe(byte[] b) {
        if (b != null) Arrays.fill(b, (byte) 0);
    }

    /** The output of {@link #sealBase}: the encapsulation and the ciphertext. */
    record Sealed(byte[] enc, byte[] ct) {
    }

    // ---------------------------------------------------------------- single-shot (§6.1)

    /** {@code SealBase(pkR, info, aad, pt)} with a fresh ephemeral key from {@code random}. */
    static Sealed sealBase(byte[] pkR, byte[] info, byte[] aad, byte[] pt, SecureRandom random) throws HpkeException {
        Objects.requireNonNull(random, "random");
        byte[] skE = new byte[N_SK];
        random.nextBytes(skE);
        try {
            return sealBaseWithEphemeral(skE, pkR, info, aad, pt);
        } finally {
            Arrays.fill(skE, (byte) 0);
        }
    }

    /** Test seam: {@link #sealBase} with a given ephemeral private key. */
    static Sealed sealBaseWithEphemeral(byte[] skE, byte[] pkR, byte[] info, byte[] aad, byte[] pt) throws HpkeException {
        Objects.requireNonNull(pkR, "pkR");
        Objects.requireNonNull(info, "info");
        Objects.requireNonNull(aad, "aad");
        Objects.requireNonNull(pt, "pt");
        if (pkR.length != N_PK) {
            throw new HpkeException(new IllegalArgumentException("pkR must be " + N_PK + " bytes"));
        }
        byte[] dh = null;
        byte[] sharedSecret = null;
        try {
            byte[] enc = X25519Bytes.publicFromPrivate(skE);
            dh = X25519Bytes.dh(X25519Bytes.privateKey(skE), pkR);
            sharedSecret = extractAndExpand(dh, concat(enc, pkR));
            Context context = keySchedule(sharedSecret, info);
            try {
                return new Sealed(enc, context.seal(aad, pt));
            } finally {
                context.destroy();
            }
        } catch (GeneralSecurityException | RuntimeException e) {
            throw inputFailure(e);
        } finally {
            wipe(dh);
            wipe(sharedSecret);
        }
    }

    /** {@code OpenBase(enc, skR, info, aad, ct)}. */
    static byte[] openBase(byte[] enc, byte[] skR, byte[] info, byte[] aad, byte[] ct) throws HpkeException {
        return openBase(enc, skR, null, info, aad, ct);
    }

    /**
     * {@code OpenBase} with the recipient's serialized public key {@code pkRm} supplied, saving one
     * X25519 operation. {@code pkR} must be {@code skR}'s public key; {@code null} recomputes it.
     */
    static byte[] openBase(byte[] enc, byte[] skR, byte[] pkR, byte[] info, byte[] aad, byte[] ct) throws HpkeException {
        Context context = setupBaseR(enc, skR, pkR, info);
        try {
            return context.open(aad, ct);
        } finally {
            context.destroy();
        }
    }

    /**
     * {@code OpenBase} with a provider private key built once by the caller and the recipient's
     * serialized public key {@code pkRm}; used to open many envelopes to one recipient.
     */
    static byte[] openBase(byte[] enc, PrivateKey skR, byte[] pkR, byte[] info, byte[] aad, byte[] ct) throws HpkeException {
        Objects.requireNonNull(skR, "skR");
        Objects.requireNonNull(pkR, "pkR");
        Context context = setupBaseR(enc, skR, pkR, info);
        try {
            return context.open(aad, ct);
        } finally {
            context.destroy();
        }
    }

    // ---------------------------------------------------------------- setup (§5.1.1)

    /** {@code SetupBaseR(enc, skR, info)}. */
    static Context setupBaseR(byte[] enc, byte[] skR, byte[] info) throws HpkeException {
        return setupBaseR(enc, skR, null, info);
    }

    private static Context setupBaseR(byte[] enc, byte[] skR, byte[] knownPkR, byte[] info) throws HpkeException {
        Objects.requireNonNull(skR, "skR");
        byte[] pkR;
        PrivateKey recipient;
        try {
            pkR = knownPkR != null ? knownPkR : X25519Bytes.publicFromPrivate(skR);
            recipient = X25519Bytes.privateKey(skR);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw inputFailure(e);
        }
        return setupBaseR(enc, recipient, pkR, info);
    }

    private static Context setupBaseR(byte[] enc, PrivateKey recipient, byte[] pkR, byte[] info) throws HpkeException {
        Objects.requireNonNull(enc, "enc");
        Objects.requireNonNull(info, "info");
        if (enc.length != N_ENC) {
            throw new HpkeException(new IllegalArgumentException("enc must be " + N_ENC + " bytes"));
        }
        byte[] dh = null;
        byte[] sharedSecret = null;
        try {
            dh = X25519Bytes.dh(recipient, enc);
            sharedSecret = extractAndExpand(dh, concat(enc, pkR));
            return keySchedule(sharedSecret, info);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw inputFailure(e);
        } finally {
            wipe(dh);
            wipe(sharedSecret);
        }
    }

    /** {@code SetupBaseS(pkR, info)} with a given ephemeral key; returns {@code enc} too. Test seam. */
    static Context setupBaseSWithEphemeral(byte[] skE, byte[] pkR, byte[] info, byte[][] encOut) throws HpkeException {
        byte[] dh = null;
        byte[] sharedSecret = null;
        try {
            byte[] enc = X25519Bytes.publicFromPrivate(skE);
            dh = X25519Bytes.dh(X25519Bytes.privateKey(skE), pkR);
            sharedSecret = extractAndExpand(dh, concat(enc, pkR));
            encOut[0] = enc;
            return keySchedule(sharedSecret, info);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw inputFailure(e);
        } finally {
            wipe(dh);
            wipe(sharedSecret);
        }
    }

    /** {@code DeriveKeyPair(ikm)} for X25519 (§7.1.3); returns {@code skR}. Test seam. */
    static byte[] deriveKeyPair(byte[] ikm) throws HpkeException {
        byte[] dkpPrk = null;
        try {
            dkpPrk = labeledExtract(KEM_SUITE_ID, EMPTY, ascii("dkp_prk"), ikm);
            return labeledExpand(KEM_SUITE_ID, dkpPrk, ascii("sk"), EMPTY, N_SK);
        } catch (GeneralSecurityException e) {
            throw new HpkeException(e);
        } finally {
            wipe(dkpPrk);
        }
    }

    // ---------------------------------------------------------------- key schedule (§5.1)

    /**
     * The key schedule. Intermediate secrets are wiped on every path; {@code key} and
     * {@code base_nonce} are wiped too unless they pass to the returned {@link Context}, whose
     * {@code destroy()} is then the caller's (review F4).
     */
    private static Context keySchedule(byte[] sharedSecret, byte[] info) throws GeneralSecurityException {
        return keySchedule(JDK_HKDF, sharedSecret, info);
    }

    /** {@link #keySchedule(byte[], byte[])} over a given HKDF; tests inject failures through it. */
    static Context keySchedule(Hkdf hkdf, byte[] sharedSecret, byte[] info) throws GeneralSecurityException {
        byte[] pskIdHash = labeledExtract(hkdf, HPKE_SUITE_ID, EMPTY, ascii("psk_id_hash"), EMPTY);
        byte[] infoHash = labeledExtract(hkdf, HPKE_SUITE_ID, EMPTY, ascii("info_hash"), info);
        byte[] keyScheduleContext = concat(new byte[]{MODE_BASE}, pskIdHash, infoHash);
        byte[] secret = null;
        byte[] key = null;
        byte[] baseNonce = null;
        boolean transferred = false;
        try {
            secret = labeledExtract(hkdf, HPKE_SUITE_ID, sharedSecret, ascii("secret"), EMPTY);
            key = labeledExpand(hkdf, HPKE_SUITE_ID, secret, ascii("key"), keyScheduleContext, N_K);
            baseNonce = labeledExpand(hkdf, HPKE_SUITE_ID, secret, ascii("base_nonce"), keyScheduleContext, N_N);
            Context context = new Context(key, baseNonce);
            transferred = true;
            return context;
        } finally {
            wipe(secret);
            if (!transferred) {
                wipe(key);
                wipe(baseNonce);
            }
        }
    }

    /** {@code ExtractAndExpand(dh, kem_context)} of DHKEM (§4.1). */
    private static byte[] extractAndExpand(byte[] dh, byte[] kemContext) throws GeneralSecurityException {
        return extractAndExpand(JDK_HKDF, dh, kemContext);
    }

    /** {@link #extractAndExpand(byte[], byte[])} over a given HKDF; tests inject failures through it. */
    static byte[] extractAndExpand(Hkdf hkdf, byte[] dh, byte[] kemContext) throws GeneralSecurityException {
        byte[] eaePrk = null;
        try {
            eaePrk = labeledExtract(hkdf, KEM_SUITE_ID, EMPTY, ascii("eae_prk"), dh);
            return labeledExpand(hkdf, KEM_SUITE_ID, eaePrk, ascii("shared_secret"), kemContext, N_SECRET);
        } finally {
            wipe(eaePrk); // on every path (review F4)
        }
    }

    // ---------------------------------------------------------------- labeled HKDF (§4)

    /**
     * HKDF-SHA256 Extract and Expand (RFC 5869 §2.2, §2.3). Production uses {@link #JDK_HKDF} only;
     * the interface lets tests fail a chosen derivation on any JDK (review F4).
     */
    interface Hkdf {
        byte[] extract(byte[] salt, byte[] ikm) throws GeneralSecurityException;

        byte[] expand(byte[] prk, byte[] info, int length) throws GeneralSecurityException;
    }

    /** HKDF-SHA256 through {@code javax.crypto.KDF}, looked up by algorithm only (see {@link X25519Bytes}). */
    static final Hkdf JDK_HKDF = new Hkdf() {
        @Override
        public byte[] extract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
            HKDFParameterSpec.Builder builder = HKDFParameterSpec.ofExtract().addIKM(ikm);
            if (salt.length > 0) {
                builder.addSalt(salt); // an absent salt is HashLen zero bytes, as RFC 5869 §2.2 requires
            }
            return KDF.getInstance("HKDF-SHA256").deriveData(builder.extractOnly());
        }

        @Override
        public byte[] expand(byte[] prk, byte[] info, int length) throws GeneralSecurityException {
            return KDF.getInstance("HKDF-SHA256")
                    .deriveData(HKDFParameterSpec.expandOnly(new SecretKeySpec(prk, "HKDF-PRK"), info, length));
        }
    };

    /** {@code LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm)}. */
    static byte[] labeledExtract(byte[] suiteId, byte[] salt, byte[] label, byte[] ikm) throws GeneralSecurityException {
        return labeledExtract(JDK_HKDF, suiteId, salt, label, ikm);
    }

    private static byte[] labeledExtract(Hkdf hkdf, byte[] suiteId, byte[] salt, byte[] label, byte[] ikm)
            throws GeneralSecurityException {
        byte[] labeledIkm = concat(HPKE_V1, suiteId, label, ikm);
        try {
            return hkdf.extract(salt, labeledIkm);
        } finally {
            Arrays.fill(labeledIkm, (byte) 0);
        }
    }

    /** {@code LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, L)}. */
    static byte[] labeledExpand(byte[] suiteId, byte[] prk, byte[] label, byte[] info, int length) throws GeneralSecurityException {
        return labeledExpand(JDK_HKDF, suiteId, prk, label, info, length);
    }

    private static byte[] labeledExpand(Hkdf hkdf, byte[] suiteId, byte[] prk, byte[] label, byte[] info, int length)
            throws GeneralSecurityException {
        return hkdf.expand(prk, concat(i2osp(length, 2), HPKE_V1, suiteId, label, info), length);
    }

    static byte[] kemSuiteId() {
        return KEM_SUITE_ID.clone();
    }

    static byte[] hpkeSuiteId() {
        return HPKE_SUITE_ID.clone();
    }

    // ---------------------------------------------------------------- context (§5.2)

    /**
     * An encryption context: {@code key}, {@code base_nonce} and a sequence number. Single-shot use
     * calls one operation at sequence 0. Not thread-safe.
     */
    static final class Context {
        private final byte[] key;
        private final byte[] baseNonce;
        private long seq;

        private Context(byte[] key, byte[] baseNonce) {
            this.key = key;
            this.baseNonce = baseNonce;
        }

        byte[] key() {
            return key.clone();
        }

        byte[] baseNonce() {
            return baseNonce.clone();
        }

        /** Test seam: jump to a sequence number (§5.2's nonce is {@code base_nonce XOR I2OSP(seq, Nn)}). */
        void setSequence(long sequence) {
            if (sequence < 0) throw new IllegalArgumentException("sequence must be non-negative");
            this.seq = sequence;
        }

        byte[] seal(byte[] aad, byte[] pt) throws GeneralSecurityException {
            byte[] out = aead(Cipher.ENCRYPT_MODE, aad, pt);
            seq++;
            return out;
        }

        byte[] open(byte[] aad, byte[] ct) throws HpkeException {
            Objects.requireNonNull(aad, "aad");
            Objects.requireNonNull(ct, "ct");
            if (seq == Long.MAX_VALUE) {
                throw new HpkeException(new GeneralSecurityException("message limit reached"));
            }
            try {
                byte[] out = aead(Cipher.DECRYPT_MODE, aad, ct);
                seq++;
                return out;
            } catch (GeneralSecurityException | RuntimeException e) {
                throw inputFailure(e);
            }
        }

        private byte[] aead(int mode, byte[] aad, byte[] input) throws GeneralSecurityException {
            Objects.requireNonNull(aad, "aad");
            Objects.requireNonNull(input, "input");
            if (seq == Long.MAX_VALUE) {
                throw new GeneralSecurityException("message limit reached"); // far below 2^(8·Nn) − 1
            }
            byte[] nonce = baseNonce.clone();
            byte[] seqBytes = i2osp(seq, N_N);
            for (int i = 0; i < N_N; i++) nonce[i] ^= seqBytes[i];
            return Aead.chacha20Poly1305(mode, key, nonce, aad, input);
        }

        void destroy() {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(baseNonce, (byte) 0);
        }
    }

    // ---------------------------------------------------------------- encoding helpers

    static byte[] i2osp(long value, int length) {
        byte[] out = new byte[length];
        for (int i = length - 1, shift = 0; i >= 0 && shift < 64; i--, shift += 8) {
            out[i] = (byte) (value >>> shift);
        }
        return out;
    }

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.writeBytes(part);
        return out.toByteArray();
    }
}
