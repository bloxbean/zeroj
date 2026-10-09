package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.COMPRESSED_POINT_BYTES;
import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * One message of {@code elgamal-jubjub-threshold-v1} key generation (spec §4):
 * {@code session ‖ round ‖ kind ‖ sender ‖ subject ‖ payload}.
 *
 * <p>Messages are created only by a {@link DkgParticipant}, or by {@link #decode}, which
 * enforces well-formedness: exact length, this configuration's session, a consistent round and
 * kind, valid identifiers, canonical scalars ({@code < l}), and canonical points of the
 * prime-order subgroup (the identity allowed). A message that fails any rule is treated by the
 * protocol as absent.
 */
public final class DkgMessage {

    /** Message kinds with their rounds (spec §4). */
    public enum Kind {
        /** R1, broadcast: {@code C_i0 … C_it}. */
        COMMITMENTS(1, 1),
        /** R1, private to {@code subject}: {@code (s_ij, s'_ij)}. */
        SHARE(1, 2),
        /** R2, broadcast: a complaint against dealer {@code subject}. */
        COMPLAINT(2, 3),
        /** R3, broadcast: the dealer's pair for complainer {@code subject}. */
        ANSWER(3, 4),
        /** R4, broadcast: {@code A_i0 … A_it}. */
        EXTRACTION(4, 5),
        /** R5, broadcast: the sender's pair, which satisfies (4) but not (5) for dealer {@code subject}. */
        EXTRACTION_COMPLAINT(5, 6),
        /** R6, broadcast: the sender's pair for reconstructing dealer {@code subject}. */
        RECONSTRUCTION(6, 7),
        /** R7, broadcast: {@code digest ‖ encode(y)}. */
        CONFIRMATION(7, 8);

        private final int round;
        private final int code;

        Kind(int round, int code) {
            this.round = round;
            this.code = code;
        }

        /** The round this kind belongs to. */
        public int round() {
            return round;
        }

        int code() {
            return code;
        }

        static Kind of(int code) {
            for (Kind k : values()) {
                if (k.code == code) return k;
            }
            return null;
        }

        boolean hasPair() {
            return this == SHARE || this == ANSWER || this == EXTRACTION_COMPLAINT || this == RECONSTRUCTION;
        }

        boolean hasPoints() {
            return this == COMMITMENTS || this == EXTRACTION;
        }

        boolean subjectIsZero() {
            return hasPoints() || this == CONFIRMATION;
        }
    }

    static final int HEADER_BYTES = 32 + 4;

    private final byte[] bytes;
    private final Kind kind;
    private final int sender;
    private final int subject;
    private final List<JubjubPoint> points;
    private final BigInteger s;
    private final BigInteger sPrime;
    private final byte[] digest;
    private final JubjubPoint key;

    private DkgMessage(byte[] bytes, Kind kind, int sender, int subject, List<JubjubPoint> points,
                       BigInteger s, BigInteger sPrime, byte[] digest, JubjubPoint key) {
        this.bytes = bytes;
        this.kind = kind;
        this.sender = sender;
        this.subject = subject;
        this.points = points;
        this.s = s;
        this.sPrime = sPrime;
        this.digest = digest;
        this.key = key;
    }

    // ------------------------------------------------------------------ construction

    static DkgMessage points(DkgConfig config, Kind kind, int sender, List<JubjubPoint> points) {
        byte[] out = header(config, kind, sender, 0, points.size() * COMPRESSED_POINT_BYTES);
        int offset = HEADER_BYTES;
        for (JubjubPoint p : points) {
            System.arraycopy(p.toBytes(), 0, out, offset, COMPRESSED_POINT_BYTES);
            offset += COMPRESSED_POINT_BYTES;
        }
        return decode(config, out);
    }

    static DkgMessage pair(DkgConfig config, Kind kind, int sender, int subject, BigInteger s, BigInteger sPrime) {
        byte[] out = header(config, kind, sender, subject, 64);
        System.arraycopy(i2osp32(s), 0, out, HEADER_BYTES, 32);
        System.arraycopy(i2osp32(sPrime), 0, out, HEADER_BYTES + 32, 32);
        return decode(config, out);
    }

    static DkgMessage complaint(DkgConfig config, int sender, int accused) {
        return decode(config, header(config, Kind.COMPLAINT, sender, accused, 0));
    }

    static DkgMessage confirmation(DkgConfig config, int sender, byte[] digest, JubjubPoint y) {
        byte[] out = header(config, Kind.CONFIRMATION, sender, 0, 64);
        System.arraycopy(digest, 0, out, HEADER_BYTES, 32);
        System.arraycopy(y.toBytes(), 0, out, HEADER_BYTES + 32, 32);
        return decode(config, out);
    }

    /**
     * Decodes and validates a message for {@code config} (spec §4).
     *
     * @throws IllegalArgumentException if the message is not well-formed for this session
     */
    public static DkgMessage decode(DkgConfig config, byte[] encoded) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length < HEADER_BYTES) {
            throw new IllegalArgumentException("message shorter than its header");
        }
        if (!Arrays.equals(encoded, 0, 32, config.sessionRef(), 0, 32)) {
            throw new IllegalArgumentException("message is for another session");
        }
        int round = encoded[32] & 0xFF;
        Kind kind = Kind.of(encoded[33] & 0xFF);
        int sender = encoded[34] & 0xFF;
        int subject = encoded[35] & 0xFF;
        if (kind == null || kind.round() != round) {
            throw new IllegalArgumentException("unknown kind or round");
        }
        if (sender < 1 || sender > config.n()) {
            throw new IllegalArgumentException("sender out of range");
        }
        if (kind.subjectIsZero() ? subject != 0 : (subject < 1 || subject > config.n() || subject == sender)) {
            throw new IllegalArgumentException("invalid subject for " + kind);
        }
        byte[] copy = encoded.clone();
        int payload = encoded.length - HEADER_BYTES;
        if (kind.hasPoints()) {
            int count = config.t() + 1;
            if (payload != count * COMPRESSED_POINT_BYTES) {
                throw new IllegalArgumentException(kind + " must carry exactly t + 1 points");
            }
            List<JubjubPoint> points = new ArrayList<>(count);
            for (int k = 0; k < count; k++) {
                points.add(ElGamalEncodings.decodeSubgroupPoint(copy, HEADER_BYTES + k * COMPRESSED_POINT_BYTES, kind + " point"));
            }
            return new DkgMessage(copy, kind, sender, subject, List.copyOf(points), null, null, null, null);
        }
        if (kind.hasPair()) {
            if (payload != 64) {
                throw new IllegalArgumentException(kind + " must carry a 64-byte pair");
            }
            return new DkgMessage(copy, kind, sender, subject, null,
                    scalar(copy, HEADER_BYTES), scalar(copy, HEADER_BYTES + 32), null, null);
        }
        if (kind == Kind.COMPLAINT) {
            if (payload != 0) {
                throw new IllegalArgumentException("COMPLAINT carries no payload");
            }
            return new DkgMessage(copy, kind, sender, subject, null, null, null, null, null);
        }
        if (payload != 64) {
            throw new IllegalArgumentException("CONFIRMATION must carry a digest and a key");
        }
        return new DkgMessage(copy, kind, sender, subject, null, null, null,
                Arrays.copyOfRange(copy, HEADER_BYTES, HEADER_BYTES + 32),
                ElGamalEncodings.decodeSubgroupPoint(copy, HEADER_BYTES + 32, "confirmed key"));
    }

    // ------------------------------------------------------------------ accessors

    /** The canonical bytes. */
    public byte[] encode() {
        return bytes.clone();
    }

    /** The kind. */
    public Kind kind() {
        return kind;
    }

    /** The round. */
    public int round() {
        return kind.round();
    }

    /** The sender's identifier. */
    public int sender() {
        return sender;
    }

    /** The subject: recipient, accused or reconstructed dealer, or complainer; 0 if none. */
    public int subject() {
        return subject;
    }

    byte[] bytesRef() {
        return bytes;
    }

    List<JubjubPoint> points() {
        return points;
    }

    BigInteger s() {
        return s;
    }

    BigInteger sPrime() {
        return sPrime;
    }

    byte[] digest() {
        return digest;
    }

    JubjubPoint confirmedKey() {
        return key;
    }

    /** The message identity {@code (round, kind, sender, subject)} as one integer. */
    int identity() {
        return (kind.code() << 16) | (sender << 8) | subject;
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] header(DkgConfig config, Kind kind, int sender, int subject, int payload) {
        byte[] out = new byte[HEADER_BYTES + payload];
        System.arraycopy(config.sessionRef(), 0, out, 0, 32);
        out[32] = (byte) kind.round();
        out[33] = (byte) kind.code();
        out[34] = (byte) sender;
        out[35] = (byte) subject;
        return out;
    }

    static byte[] i2osp32(BigInteger x) {
        byte[] raw = x.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        Arrays.fill(raw, (byte) 0); // callers include secret scalars (ADR-0055 D9)
        return out;
    }

    private static BigInteger scalar(byte[] bytes, int offset) {
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(bytes, offset, offset + 32));
        if (x.compareTo(SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException("scalar is not canonical (>= l)");
        }
        return x;
    }

    @Override
    public String toString() {
        return "DkgMessage{" + kind + ", sender=" + sender + ", subject=" + subject
                + (kind == Kind.SHARE ? ", <private>" : ", " + HexFormat.of().formatHex(bytes, HEADER_BYTES, bytes.length))
                + "}";
    }
}
