package org.zeroj.bls12381.bulletproofs;

import org.zeroj.bls12381.Shake128;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * The XOF duplex sponge of {@code draft-irtf-cfrg-fiat-shamir-03} §3.2 with SHAKE128 (§9.1), and
 * {@code DeriveSessionID} (§5.1). Spec {@code bulletproof-range-bls12-381-g1-v1} §4.
 *
 * <p>{@code Init(session_id)} absorbs {@code session_id ‖ zeros(R − 32)}. {@link #absorb} of a
 * non-empty string ends the current output stream; {@link #squeeze} finalizes a <b>copy</b> of the
 * absorbing state on the first call after an absorb, and consecutive squeezes continue that stream.
 * Not thread-safe.
 */
final class DuplexSponge {

    /** Octets of a session identifier. */
    static final int SESSION_ID_BYTES = 32;

    private static final byte[] SESSION_ID_DOMAIN =
            "irtf-cfrg-fiat-shamir/session-id".getBytes(StandardCharsets.US_ASCII);

    private final Shake128 absorbing;
    private Shake128 reader;

    private DuplexSponge(Shake128 absorbing) {
        this.absorbing = absorbing;
    }

    /**
     * {@code Init(session_id)} (fiat-shamir-03 §3.2.1).
     *
     * @throws IllegalArgumentException if {@code sessionId} is not 32 octets
     */
    static DuplexSponge init(byte[] sessionId) {
        Objects.requireNonNull(sessionId, "sessionId");
        if (sessionId.length != SESSION_ID_BYTES) {
            throw new IllegalArgumentException("a session identifier is 32 octets");
        }
        Shake128 xof = new Shake128();
        xof.update(sessionId);
        xof.update(new byte[Shake128.RATE - SESSION_ID_BYTES]);
        return new DuplexSponge(xof);
    }

    /** {@code DeriveSessionID(tag)} (fiat-shamir-03 §5.1). */
    static byte[] deriveSessionId(byte[] tag) {
        Objects.requireNonNull(tag, "tag");
        DuplexSponge ds = init(SESSION_ID_DOMAIN);
        ds.absorb(tag);
        return ds.squeeze(SESSION_ID_BYTES);
    }

    /** {@code Absorb(x)} (§3.2.2): absorbing the empty string changes nothing. */
    void absorb(byte[] x) {
        Objects.requireNonNull(x, "x");
        absorbing.update(x);
        if (x.length != 0) {
            reader = null;
        }
    }

    /** {@code Squeeze(n)} (§3.2.3). */
    byte[] squeeze(int n) {
        if (reader == null) {
            reader = absorbing.copy();
        }
        return reader.squeeze(n);
    }
}
