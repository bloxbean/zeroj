package org.zeroj.circuit.lib.jubjub;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.SortedSet;

/**
 * The public record of a threshold key generation ({@code elgamal-jubjub-threshold-v1} §6): the
 * configuration plus the delivered broadcast sets of rounds 1–6. Private {@code SHARE} messages
 * and the round-7 confirmations are not part of it.
 *
 * <p>{@link #recompute()} re-derives {@code QUAL}, the marks, the joint key and every
 * verification key by pure algebra. That is <b>not</b> evidence that the run happened: one
 * party can write a perfectly consistent record whose key it knows. A
 * {@link ThresholdKeyContext} is created only by admission with authenticated evidence, or by a
 * participant from its own run (ADR-0053 D4a, invariant I7).
 */
public final class DkgTranscript {

    static final byte[] TRANSCRIPT_TAG =
            "zeroj.elgamal-jubjub-threshold.v1.transcript".getBytes(StandardCharsets.UTF_8);

    private final DkgConfig config;
    private final DkgRound[] rounds;

    DkgTranscript(DkgConfig config, DkgRound[] rounds) {
        this.config = config;
        this.rounds = rounds;
    }

    /**
     * Builds a transcript from the broadcast messages of rounds 1–6, in any order.
     *
     * @throws IllegalArgumentException if a message is malformed or for another session, is a
     *         private {@code SHARE}, or is a round-7 confirmation
     */
    public static DkgTranscript of(DkgConfig config, Collection<byte[]> messages) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(messages, "messages");
        DkgRound[] rounds = emptyRounds();
        for (byte[] bytes : messages) {
            DkgMessage m = DkgMessage.decode(config, bytes);
            if (m.kind() == DkgMessage.Kind.SHARE || m.kind() == DkgMessage.Kind.CONFIRMATION) {
                throw new IllegalArgumentException(m.kind() + " messages are not part of the transcript");
            }
            rounds[m.round()].add(m);
        }
        return new DkgTranscript(config, rounds);
    }

    static DkgRound[] emptyRounds() {
        DkgRound[] rounds = new DkgRound[8];
        for (int r = 1; r <= 7; r++) rounds[r] = new DkgRound(r);
        return rounds;
    }

    /**
     * The delivered set of one round from raw board posts (spec §5, §8). {@code posts} are the
     * posts made while that round was open; a post from an earlier round's window belongs to no
     * round. Drops posts that are malformed, for another session or round, private
     * {@code SHARE}s, or that fail {@code authenticator}; keeps byte-identical duplicates once;
     * returns the canonical order of spec §6. An application's
     * {@link DkgAdmissionVerifier#roundClosed} compares this with the list admission presents.
     */
    public static List<byte[]> deliveredRound(DkgConfig config, int round, List<AuthenticatedDkgMessage> posts,
                                              DkgAdmissionVerifier authenticator) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(posts, "posts");
        Objects.requireNonNull(authenticator, "authenticator");
        if (round < 1 || round > 7) {
            throw new IllegalArgumentException("rounds are 1..7");
        }
        DkgRound delivered = new DkgRound(round);
        for (AuthenticatedDkgMessage post : posts) {
            byte[] bytes = post.message();
            DkgMessage m;
            try {
                m = DkgMessage.decode(config, bytes);
            } catch (IllegalArgumentException malformedOrForeign) {
                continue;
            }
            if (m.round() != round || m.kind() == DkgMessage.Kind.SHARE) continue;
            if (!authenticator.authenticate(m.sender(), config.rosterKey(m.sender()), bytes, post.authenticator())) continue;
            delivered.add(m);
        }
        List<byte[]> out = new ArrayList<>();
        for (DkgMessage m : delivered.canonical()) out.add(m.encode());
        return out;
    }

    /** The configuration. */
    public DkgConfig config() {
        return config;
    }

    /** The canonical encoding of spec §6. */
    public byte[] encode() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(TRANSCRIPT_TAG);
        out.writeBytes(config.sessionRef());
        out.write(config.t());
        out.write(config.n());
        for (int r = 1; r <= 6; r++) {
            List<DkgMessage> messages = rounds[r].canonical();
            int count = messages.size();
            out.write((count >>> 24) & 0xFF);
            out.write((count >>> 16) & 0xFF);
            out.write((count >>> 8) & 0xFF);
            out.write(count & 0xFF);
            for (DkgMessage m : messages) {
                DkgConfig.writeU16(out, m.bytesRef().length);
                out.writeBytes(m.bytesRef());
            }
        }
        return out.toByteArray();
    }

    /** {@code BLAKE2b-256} of the canonical encoding. */
    public byte[] digest() {
        return Blake2bDigest.blake2b256(encode());
    }

    /** A round's messages in canonical order (spec §6), as bytes. */
    public List<byte[]> roundMessages(int round) {
        if (round < 1 || round > 6) {
            throw new IllegalArgumentException("transcript rounds are 1..6");
        }
        List<byte[]> out = new ArrayList<>();
        for (DkgMessage m : rounds[round].canonical()) out.add(m.encode());
        return out;
    }

    /**
     * Recomputes the public outputs of spec §5.
     *
     * @throws FaultAssumptionViolatedException on abort conditions A1, A3, A4 or A5
     */
    public DkgPublicOutcome recompute() {
        DkgRules.Qualification q = DkgRules.qualify(config, rounds[1], rounds[2], rounds[3]);
        DkgRules.Marks marks = DkgRules.mark(config, q, rounds[4], rounds[5]);
        DkgRules.Outputs outputs = DkgRules.finish(config, q, marks, rounds[6]);
        return new DkgPublicOutcome(q.qual(), marks.marked(), outputs.jointKey(), outputs.verificationKeys());
    }

    DkgRound round(int r) {
        return rounds[r];
    }

    /** The public outputs of a key generation. */
    public static final class DkgPublicOutcome {
        private final SortedSet<Integer> qual;
        private final SortedSet<Integer> marked;
        private final JubjubPoint jointKey;
        private final List<JubjubPoint> verificationKeys;

        DkgPublicOutcome(SortedSet<Integer> qual, SortedSet<Integer> marked, JubjubPoint jointKey,
                         List<JubjubPoint> verificationKeys) {
            this.qual = qual;
            this.marked = marked;
            this.jointKey = jointKey;
            this.verificationKeys = verificationKeys;
        }

        /** The qualified dealers. */
        public SortedSet<Integer> qual() {
            return qual;
        }

        /** Dealers whose extraction was reconstructed. */
        public SortedSet<Integer> marked() {
            return marked;
        }

        /** The joint key {@code y}. */
        public JubjubPoint jointKey() {
            return jointKey;
        }

        /** {@code Y_1 … Y_n}, at index {@code j − 1}. */
        public List<JubjubPoint> verificationKeys() {
            return verificationKeys;
        }
    }
}
