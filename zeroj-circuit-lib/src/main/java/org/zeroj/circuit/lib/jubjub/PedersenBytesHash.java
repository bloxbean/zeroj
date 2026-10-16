package org.zeroj.circuit.lib.jubjub;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * {@code HashBytesToScalar} of {@code pedersen-jubjub-bytes-v1}
 * ({@code docs/specs/pedersen-jubjub-bytes-v1.md} §3, ADR-0058 D2/D6): RFC 9380
 * {@code hash_to_field} into {@code GF(l)} with {@code expand_message_xmd}/SHA-256, {@code L = 48},
 * over {@code B || I2OSP(n, 8)}.
 *
 * <p>The payload is fed to the digest exactly once and never copied, so memory is bounded by a
 * fixed buffer whatever the payload size. The length suffix is the count of octets actually
 * hashed, appended only after end of input has been observed and every check has passed.
 *
 * <p>The payload, the digest state and the result are secret during commitment generation.
 * Owned buffers and digest outputs are wiped on every exit; {@link BigInteger} and JCA provider
 * copies cannot be. Nothing is cached or pooled, and no secret is kept in a {@code ThreadLocal}; the
 * only one is a test-only digest-acquisition hook that holds no data.
 */
final class PedersenBytesHash {

    private PedersenBytesHash() {}

    /** The RFC 9380 domain separation tag, 46 ASCII octets. */
    static final String DST = "ZeroJ-pedersen-jubjub-bytes-v1-H2S-XMD:SHA-256";

    /** Largest payload the profile maps: keeps {@code b0}'s input ({@code n + 122}) below 2^61 octets. */
    static final long MAX_PAYLOAD_BYTES = (1L << 61) - 256;

    /** Stream read buffer. Non-normative; never sized by the payload. */
    static final int BUFFER_BYTES = 8192;

    private static final int LEN_IN_BYTES = 48;
    private static final int SHA256_BYTES = 32;
    private static final int Z_PAD_BYTES = 64;
    // Constants are handed to the digest as fresh copies, so even a misbehaving MessageDigest
    // passed through the test seam cannot alter them for later operations.
    /** {@code I2OSP(48, 2) || I2OSP(0, 1)}. */
    private static final byte[] B0_TRAILER = {0x00, 0x30, 0x00};
    private static final byte[] DST_PRIME = dstPrime();

    /**
     * Test-only hook, called whenever an operation obtains its SHA-256 instance, so tests can show
     * that invalid arguments are rejected before any digest is obtained (spec §6). Holds no secret;
     * the same pattern as {@code JubjubPoint}'s secret-schedule observer.
     */
    private static final ThreadLocal<Runnable> DIGEST_OBSERVER = new ThreadLocal<>();

    static void installDigestObserverForTesting(Runnable observer) {
        Objects.requireNonNull(observer, "observer");
        if (DIGEST_OBSERVER.get() != null) {
            throw new IllegalStateException("a digest observer is already installed on this thread");
        }
        DIGEST_OBSERVER.set(observer);
    }

    static void clearDigestObserverForTesting() {
        DIGEST_OBSERVER.remove();
    }

    /** Maps an in-memory payload. The array is read, never copied, retained or wiped. */
    static BigInteger hashToScalar(byte[] payload) {
        return hashToScalar(payload, newSha256());
    }

    static BigInteger hashToScalar(byte[] payload, MessageDigest sha256) {
        Objects.requireNonNull(payload, "payload");
        Throwable primary = null;
        try {
            sha256.update(new byte[Z_PAD_BYTES]);
            sha256.update(payload);
            return finish(sha256, payload.length);
        } catch (Throwable t) {
            primary = t;
            throw t;
        } finally {
            resetAfter(sha256, primary);
        }
    }

    /**
     * Maps a stream. With {@code exact}, the stream must hold exactly {@code bound} octets;
     * otherwise it is read to end of stream and may hold at most {@code bound} octets.
     */
    static BigInteger hashToScalar(InputStream payload, long bound, boolean exact) throws IOException {
        return hashToScalar(payload, bound, exact, MAX_PAYLOAD_BYTES, newSha256());
    }

    /**
     * Stream core. {@code cap} and {@code sha256} are seams for tests only (the cap boundary
     * cannot be reached with real input); production always passes {@link #MAX_PAYLOAD_BYTES} and
     * a fresh SHA-256 instance.
     */
    static BigInteger hashToScalar(InputStream payload, long bound, boolean exact, long cap,
                                   MessageDigest sha256) throws IOException {
        Objects.requireNonNull(payload, "payload");
        if (bound < 0 || bound > cap) {
            throw new IllegalArgumentException("payload bound must be in [0, " + cap + "]");
        }
        byte[] buffer = new byte[(int) Math.max(1, Math.min(BUFFER_BYTES, bound))];
        Throwable primary = null;
        try {
            sha256.update(new byte[Z_PAD_BYTES]);
            long count = 0;
            boolean endSeen = false;
            while (count < bound) {
                int want = (int) Math.min(buffer.length, bound - count);
                int read = payload.read(buffer, 0, want);
                if (read == 0) {
                    // A conforming stream never does this for want > 0. Fall back to a single
                    // blocking read rather than spin.
                    int one = payload.read();
                    if (one > 255 || one < -1) {
                        throw new IOException("InputStream.read() returned an out-of-range value");
                    }
                    if (one >= 0) {
                        buffer[0] = (byte) one;
                        read = 1;
                    } else {
                        read = -1;
                    }
                }
                if (read == -1) {
                    endSeen = true;
                    break;
                }
                if (read < 0 || read > want) {
                    throw new IOException("InputStream.read returned an invalid count");
                }
                sha256.update(buffer, 0, read);
                count += read;
            }
            if (endSeen) {
                if (exact) {
                    throw new IOException("payload stream ended before its declared length");
                }
            } else {
                // count == bound: one probe for end of stream. An extra octet is consumed but
                // never hashed.
                int extra = payload.read();
                if (extra != -1) {
                    throw new IOException(exact
                            ? "payload stream is longer than its declared length"
                            : "payload stream exceeds its maximum length");
                }
            }
            return finish(sha256, count);
        } catch (Throwable t) {
            primary = t;
            throw t;
        } finally {
            Arrays.fill(buffer, (byte) 0);
            resetAfter(sha256, primary);
        }
    }

    /**
     * Test-only view of the expansion of an in-memory payload: {@code {b0, b1, b2, u}}. Fresh
     * arrays the caller owns.
     */
    static byte[][] intermediatesForTesting(byte[] payload) {
        MessageDigest sha256 = newSha256();
        try {
            sha256.update(new byte[Z_PAD_BYTES]);
            sha256.update(payload);
            byte[][] out = new byte[4][];
            finish(sha256, payload.length, out);
            return out;
        } finally {
            sha256.reset();
        }
    }

    /**
     * Discards any partial payload state (best effort; see class doc). A reset failure never hides
     * the operation's own failure: it is attached as suppressed. After an otherwise successful
     * operation it propagates, so no result is returned.
     */
    private static void resetAfter(MessageDigest sha256, Throwable primary) {
        try {
            sha256.reset();
        } catch (RuntimeException e) {
            if (primary == null) {
                throw e;
            }
            if (e != primary) {
                primary.addSuppressed(e);
            }
        }
    }

    private static BigInteger finish(MessageDigest sha256, long n) {
        return finish(sha256, n, null);
    }

    private static BigInteger finish(MessageDigest sha256, long n, byte[][] capture) {
        byte[] length = i2osp8(n);
        byte[] b0 = null;
        byte[] b1 = null;
        byte[] b2 = null;
        byte[] chain = new byte[SHA256_BYTES];
        byte[] uniform = new byte[LEN_IN_BYTES];
        try {
            sha256.update(length);
            sha256.update(B0_TRAILER.clone());
            sha256.update(DST_PRIME.clone());
            b0 = sha256.digest();

            sha256.update(b0);
            sha256.update((byte) 1);
            sha256.update(DST_PRIME.clone());
            b1 = sha256.digest();

            for (int i = 0; i < SHA256_BYTES; i++) {
                chain[i] = (byte) (b0[i] ^ b1[i]);
            }
            sha256.update(chain);
            sha256.update((byte) 2);
            sha256.update(DST_PRIME.clone());
            b2 = sha256.digest();

            System.arraycopy(b1, 0, uniform, 0, SHA256_BYTES);
            System.arraycopy(b2, 0, uniform, SHA256_BYTES, LEN_IN_BYTES - SHA256_BYTES);
            if (capture != null) {
                capture[0] = b0.clone();
                capture[1] = b1.clone();
                capture[2] = b2.clone();
                capture[3] = uniform.clone();
            }
            return new BigInteger(1, uniform).mod(JubjubCurve.SUBGROUP_ORDER);
        } finally {
            wipe(length);
            wipe(b0);
            wipe(b1);
            wipe(b2);
            wipe(chain);
            wipe(uniform);
        }
    }

    private static byte[] i2osp8(long n) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) n;
            n >>>= 8;
        }
        return out;
    }

    private static MessageDigest newSha256() {
        Runnable observer = DIGEST_OBSERVER.get();
        if (observer != null) {
            observer.run();
        }
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required but unavailable", e);
        }
    }

    private static byte[] dstPrime() {
        byte[] dst = DST.getBytes(StandardCharsets.US_ASCII);
        byte[] out = Arrays.copyOf(dst, dst.length + 1);
        out[dst.length] = (byte) dst.length;
        return out;
    }

    private static void wipe(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}
