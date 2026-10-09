package org.zeroj.circuit.lib.jubjub;

import java.util.Arrays;

/**
 * The byte formats of {@code dkg-share-delivery-hpke-v1} (spec §3.1, §4.1): announcements,
 * envelopes and the HPKE {@code info}. Decoding returns {@code null} for anything that is not
 * well-formed; the profile treats every such message as absent.
 */
final class DkgShareDeliveryCodec {

    static final byte[] TAG_A = Hpke.ascii("zeroj.dkg-share-delivery-hpke.v1.announce");
    static final byte[] TAG_E = Hpke.ascii("zeroj.dkg-share-delivery-hpke.v1.envelope");
    static final byte[] TAG_I = Hpke.ascii("zeroj.dkg-share-delivery-hpke.v1.info");

    static final int ANNOUNCE_LENGTH = TAG_A.length + 32 + 1 + 32;            // 106
    static final int SHARE_LENGTH = 100;                                        // threshold spec §4
    static final int CT_LENGTH = SHARE_LENGTH + Hpke.N_T;                       // 116
    static final int ENVELOPE_LENGTH = TAG_E.length + 32 + 2 + Hpke.N_ENC + CT_LENGTH; // 223

    private DkgShareDeliveryCodec() {
    }

    /** A decoded announcement: participant {@code j} and its key {@code pkR}. */
    record Announcement(int participant, byte[] publicKey) {
    }

    /** A decoded envelope header and body. */
    record Envelope(int sender, int recipient, byte[] enc, byte[] ct) {
    }

    static byte[] announcement(DkgConfig config, int j, byte[] publicKey) {
        return Hpke.concat(TAG_A, config.sessionRef(), new byte[]{(byte) j}, publicKey);
    }

    /**
     * The participant an announcement names if its length, tag, session and identifier are
     * well-formed (spec §3.1, without the key checks), or {@code 0}. Cheap: no X25519.
     */
    static int announcedParticipant(DkgConfig config, byte[] bytes) {
        if (bytes == null || bytes.length != ANNOUNCE_LENGTH || !startsWith(bytes, TAG_A)) return 0;
        int at = TAG_A.length;
        if (!Arrays.equals(bytes, at, at + 32, config.sessionRef(), 0, 32)) return 0;
        int j = bytes[at + 32] & 0xFF;
        return j >= 1 && j <= config.n() ? j : 0;
    }

    /** Spec §3.1: well-formed for this session, or {@code null}. Authentication is the caller's. */
    static Announcement decodeAnnouncement(DkgConfig config, byte[] bytes) {
        if (bytes == null || bytes.length != ANNOUNCE_LENGTH || !startsWith(bytes, TAG_A)) return null;
        int at = TAG_A.length;
        if (!Arrays.equals(bytes, at, at + 32, config.sessionRef(), 0, 32)) return null;
        int j = bytes[at + 32] & 0xFF;
        if (j < 1 || j > config.n()) return null;
        byte[] pk = Arrays.copyOfRange(bytes, at + 33, at + 65);
        if (!X25519Bytes.isCanonical(pk) || !X25519Bytes.passesSmallOrderProbe(pk)) return null;
        return new Announcement(j, pk);
    }

    static byte[] info(DkgConfig config, int sender, int recipient) {
        return Hpke.concat(TAG_I, config.sessionRef(), new byte[]{(byte) sender, (byte) recipient});
    }

    static byte[] envelope(DkgConfig config, int sender, int recipient, byte[] enc, byte[] ct) {
        return Hpke.concat(TAG_E, config.sessionRef(), new byte[]{(byte) sender, (byte) recipient}, enc, ct);
    }

    /**
     * Spec §4.2 steps 1, 2 and 4: length, tag, session, identifiers and a canonical {@code enc};
     * or {@code null}. Authentication (step 3) and opening (steps 5–6) are the caller's.
     */
    static Envelope decodeEnvelope(DkgConfig config, byte[] bytes) {
        if (bytes == null || bytes.length != ENVELOPE_LENGTH || !startsWith(bytes, TAG_E)) return null;
        int at = TAG_E.length;
        if (!Arrays.equals(bytes, at, at + 32, config.sessionRef(), 0, 32)) return null;
        int i = bytes[at + 32] & 0xFF;
        int j = bytes[at + 33] & 0xFF;
        if (i < 1 || i > config.n() || j < 1 || j > config.n() || i == j) return null;
        byte[] enc = Arrays.copyOfRange(bytes, at + 34, at + 34 + Hpke.N_ENC);
        if (!X25519Bytes.isCanonical(enc)) return null;
        byte[] ct = Arrays.copyOfRange(bytes, at + 34 + Hpke.N_ENC, bytes.length);
        return new Envelope(i, j, enc, ct);
    }

    private static boolean startsWith(byte[] bytes, byte[] prefix) {
        return Arrays.equals(bytes, 0, prefix.length, prefix, 0, prefix.length);
    }
}
