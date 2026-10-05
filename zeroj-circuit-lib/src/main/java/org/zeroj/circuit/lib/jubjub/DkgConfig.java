package org.zeroj.circuit.lib.jubjub;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * The immutable configuration of one threshold key-generation attempt
 * ({@code elgamal-jubjub-threshold-v1} §1–§2; ADR-0053 D2, D4a, D6): threshold {@code t},
 * participant count {@code n}, the roster of authentication keys, the application context
 * and the attempt number, from which the session identifier is derived.
 *
 * <p>Every message carries the session, and admission recomputes it from this configuration.
 * A configuration must therefore come from a trusted source, for example an election manifest.
 * The application must never reuse an attempt number for the same context.
 */
public final class DkgConfig {

    /** The profile identifier. */
    public static final String PROFILE = "elgamal-jubjub-threshold-v1";

    /** The largest supported participant count (ADR-0053 Q4). */
    public static final int MAX_PARTICIPANTS = 64;

    static final byte[] SESSION_TAG =
            "zeroj.elgamal-jubjub-threshold.v1.session".getBytes(StandardCharsets.UTF_8);

    private final int t;
    private final int n;
    private final List<byte[]> roster;
    private final byte[] applicationContext;
    private final long attempt;
    private final byte[] session;

    private DkgConfig(int t, int n, List<byte[]> roster, byte[] applicationContext, long attempt) {
        this.t = t;
        this.n = n;
        this.roster = roster;
        this.applicationContext = applicationContext;
        this.attempt = attempt;
        this.session = deriveSession();
    }

    /**
     * Validates the parameters and derives the session (spec §2).
     *
     * @param t                  the number of faulty participants tolerated; any {@code t + 1}
     *                           can decrypt
     * @param n                  the participant count
     * @param roster             participant {@code j}'s authentication key at index {@code j − 1},
     *                           each 1–65535 bytes, pairwise distinct
     * @param applicationContext 0–65535 bytes identifying the application instance
     * @param attempt            never reused for the same context; encoded as an unsigned 64-bit
     *                           integer
     * @throws IllegalArgumentException unless {@code t ≥ 1} and {@code 2t + 1 ≤ n ≤ 64}, the
     *         roster and context sizes are valid, and no two roster keys are equal
     */
    public static DkgConfig create(int t, int n, List<byte[]> roster, byte[] applicationContext, long attempt) {
        if (t < 1 || n < 2 * t + 1 || n > MAX_PARTICIPANTS) {
            throw new IllegalArgumentException("parameters must satisfy t >= 1 and 2t + 1 <= n <= "
                    + MAX_PARTICIPANTS + " (t < n/2); got t=" + t + ", n=" + n);
        }
        Objects.requireNonNull(roster, "roster");
        Objects.requireNonNull(applicationContext, "applicationContext");
        if (roster.size() != n) {
            throw new IllegalArgumentException("roster must hold exactly n = " + n + " keys");
        }
        List<byte[]> copy = new ArrayList<>(n);
        for (byte[] key : roster) {
            Objects.requireNonNull(key, "roster key");
            if (key.length < 1 || key.length > 0xFFFF) {
                throw new IllegalArgumentException("roster keys must be 1..65535 bytes");
            }
            copy.add(key.clone());
        }
        for (int a = 0; a < copy.size(); a++) {
            for (int b = a + 1; b < copy.size(); b++) {
                if (Arrays.equals(copy.get(a), copy.get(b))) {
                    throw new IllegalArgumentException("roster keys must be distinct (participants "
                            + (a + 1) + " and " + (b + 1) + ")");
                }
            }
        }
        if (applicationContext.length > 0xFFFF) {
            throw new IllegalArgumentException("application context must be at most 65535 bytes");
        }
        return new DkgConfig(t, n, List.copyOf(copy), applicationContext.clone(), attempt);
    }

    /** {@code t}. */
    public int t() {
        return t;
    }

    /** {@code n}. */
    public int n() {
        return n;
    }

    /** The 32-byte session identifier. */
    public byte[] session() {
        return session.clone();
    }

    /** Participant {@code id}'s authentication key. */
    public byte[] rosterKey(int id) {
        requireParticipant(id);
        return roster.get(id - 1).clone();
    }

    /** The application context. */
    public byte[] applicationContext() {
        return applicationContext.clone();
    }

    /** The attempt number. */
    public long attempt() {
        return attempt;
    }

    void requireParticipant(int id) {
        if (id < 1 || id > n) {
            throw new IllegalArgumentException("participant identifiers are 1.." + n + ", got " + id);
        }
    }

    byte[] sessionRef() {
        return session;
    }

    private byte[] deriveSession() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(SESSION_TAG);
        writeU16(out, applicationContext.length);
        out.writeBytes(applicationContext);
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.write((int) (attempt >>> shift) & 0xFF);
        }
        out.write(t);
        out.write(n);
        for (byte[] key : roster) {
            writeU16(out, key.length);
            out.writeBytes(key);
        }
        return Blake2bDigest.blake2b256(out.toByteArray());
    }

    static void writeU16(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    /** Equal iff the sessions are equal: the session commits to every field. */
    @Override
    public boolean equals(Object o) {
        return o instanceof DkgConfig other && Arrays.equals(session, other.session);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(session);
    }

    @Override
    public String toString() {
        return "DkgConfig{t=" + t + ", n=" + n + ", attempt=" + Long.toUnsignedString(attempt)
                + ", session=" + HexFormat.of().formatHex(session) + "}";
    }
}
