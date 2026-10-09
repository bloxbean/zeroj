package org.zeroj.circuit.lib.jubjub;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A board with windows for {@code dkg-share-delivery-hpke-v1} tests (ADR-0054 M2). Round 0
 * carries announcements, round 1 carries envelopes and {@code COMMITMENTS}, and rounds 2–7 are
 * the threshold profile's. Every post carries an authenticator, a keyed hash under its author's
 * roster key, which {@link #AUTH} checks under the claimed sender's roster key. Each participant
 * reads the same final window per round (P2) and is started and closed through
 * {@link DkgShareDelivery} (T1 and the barrier, P3), except participants that a test drives
 * without the barrier as a negative control.
 *
 * <p>{@link Hooks} let a test script corrupt participants, front-running copies, and late or
 * excluded posts.
 */
final class DkgEncryptedHarness {

    /** One board post, authenticated as {@code author}. */
    record Post(int author, byte[] bytes) {
    }

    /** Test hooks. Every default is honest. */
    interface Hooks {
        /** Round-0 posts for participant {@code j}'s announcement (drop, duplicate, replace). */
        default List<byte[]> announcement(int j, byte[] announcement) {
            return List.of(announcement);
        }

        /** Envelope posts for one sealed envelope (drop, duplicate, replace). */
        default List<byte[]> envelope(int i, int j, byte[] envelope) {
            return List.of(envelope);
        }

        /** {@code true} if this envelope misses the round-1 cutoff (it is posted, but too late). */
        default boolean missesCutoff(int i, int j) {
            return false;
        }

        /** Dealers that ignore D7a and post {@code COMMITMENTS} even when envelopes missed the cutoff. */
        default Set<Integer> ignoreCommitmentsLast() {
            return Set.of();
        }

        /** Rewrites a broadcast of rounds 1–7 into the posts that actually happen. */
        default List<byte[]> broadcast(DkgMessage m) {
            return List.of(m.encode());
        }

        /** Posts placed at the front of a round's window, before every honest post (front-running). */
        default List<Post> before(int round, DkgEncryptedHarness h) {
            return List.of();
        }

        /** Extra posts appended to a round's window. */
        default List<Post> extra(int round) {
            return List.of();
        }

        /**
         * {@code true} if recipient {@code j} opens dealer {@code i}'s envelope only after closing
         * round 1. Such a recipient does not use the library's barrier: the negative control of
         * review F1.
         */
        default boolean processedLate(int i, int j) {
            return false;
        }
    }

    static final Hooks HONEST = new Hooks() {
    };

    /** Authenticity: the authenticator is {@code SHA-256(rosterKey ‖ message)} under the claimed sender's key. */
    static final DkgAdmissionVerifier AUTH = new DkgAdmissionVerifier() {
        @Override
        public boolean authenticate(int sender, byte[] rosterKey, byte[] message, byte[] authenticator) {
            return Arrays.equals(tag(rosterKey, message), authenticator);
        }

        @Override
        public boolean roundClosed(DkgConfig config, int round, List<byte[]> canonicalMessages, byte[] evidence) {
            return true;
        }
    };

    static byte[] tag(byte[] rosterKey, byte[] message) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(rosterKey);
            sha.update(message);
            return sha.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    final DkgConfig config;
    final List<ThresholdVss.Dealing> dealings;
    final List<DkgParticipant> participants = new ArrayList<>();
    final Map<Integer, DkgShareDeliveryKeys> keys = new HashMap<>();
    final Map<Integer, byte[]> secrets = new HashMap<>();
    final Map<Integer, FaultAssumptionViolatedException> aborted = new HashMap<>();
    /** Every post per round, 0–7, in board order. */
    final List<List<Post>> board = new ArrayList<>();
    /** Every envelope sealed, before hooks: {@code [i, j, bytes]}. */
    final List<Object[]> sealed = new ArrayList<>();
    DkgKeyDirectory directory;
    private final Hooks hooks;

    private final String tagPrefix;

    DkgEncryptedHarness(DkgConfig config, List<ThresholdVss.Dealing> dealings, Hooks hooks) {
        this(config, dealings, hooks, "");
    }

    /** {@code tagPrefix}: spec §9.1 test keys are {@code tagPrefix + "recipient." + j} and {@code tagPrefix + "ephemeral." + i + "." + j}. */
    DkgEncryptedHarness(DkgConfig config, List<ThresholdVss.Dealing> dealings, Hooks hooks, String tagPrefix) {
        this.config = config;
        this.dealings = dealings;
        this.hooks = hooks;
        this.tagPrefix = tagPrefix;
        for (int r = 0; r <= 7; r++) board.add(new ArrayList<>());
        for (int i = 1; i <= config.n(); i++) {
            participants.add(DkgParticipant.withDealing(config, i, dealings.get(i - 1)));
            byte[] sk = testKey(tagPrefix + "recipient." + i);
            secrets.put(i, sk);
            keys.put(i, DkgShareDeliveryKeys.fromSecret(config, i, sk));
        }
    }

    static DkgEncryptedHarness fixed(DkgConfig config, List<ThresholdVss.Dealing> dealings, Hooks hooks) {
        return new DkgEncryptedHarness(config, dealings, hooks);
    }

    /** Spec §9.1 test keys: SHA-256 of the tag under the profile's test prefix. */
    /**
     * Runs {@code body} with the JDK provider {@code name} removed, then reinstalls it at its
     * position: a platform fault for fail-closed tests. Tests in this module run sequentially.
     */
    static void withoutProvider(String name, Runnable body) {
        Provider[] all = Security.getProviders();
        int position = -1;
        for (int k = 0; k < all.length; k++) {
            if (all[k].getName().equals(name)) position = k;
        }
        if (position < 0) throw new IllegalStateException("no provider " + name);
        Provider removed = all[position];
        Security.removeProvider(name);
        try {
            body.run();
        } finally {
            Security.insertProviderAt(removed, position + 1);
        }
    }

    static byte[] testKey(String tag) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(("zeroj.dkg-share-delivery-hpke.v1.test." + tag).getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    DkgParticipant participant(int id) {
        return participants.get(id - 1);
    }

    List<AuthenticatedDkgMessage> window(List<Post> posts) {
        List<AuthenticatedDkgMessage> out = new ArrayList<>();
        for (Post p : posts) out.add(new AuthenticatedDkgMessage(p.bytes(), tag(config.rosterKey(p.author()), p.bytes())));
        return out;
    }

    private boolean withoutBarrier(int j) {
        for (int i = 1; i <= config.n(); i++) if (hooks.processedLate(i, j)) return true;
        return false;
    }

    DkgEncryptedHarness run() {
        // Round 0: announcements, then the directory from the final window.
        for (int j = 1; j <= config.n(); j++) {
            for (byte[] a : hooks.announcement(j, keys.get(j).announcement())) board.get(0).add(new Post(j, a));
        }
        board.get(0).addAll(hooks.extra(0));
        directory = DkgKeyDirectory.fromRound0(config, window(board.get(0)), AUTH);

        // Round 1: start (T1, seal), envelopes first, COMMITMENTS only after all envelopes made the window.
        List<Post> round1 = new ArrayList<>();
        for (DkgParticipant p : participants) {
            int i = p.id();
            DkgShareDelivery.SealedDealing dealing;
            try {
                dealing = withoutBarrier(i) ? startWithoutBinding(p)
                        : DkgShareDelivery.start(p, directory, keys.get(i), j -> testKey(tagPrefix + "ephemeral." + i + "." + j));
            } catch (FaultAssumptionViolatedException t1) {
                aborted.put(i, t1);
                continue;
            }
            // The plaintext SHAREs never leave through the broadcasts (final review X-2).
            if (dealing.broadcasts().size() != 1 || dealing.broadcasts().get(0).kind() != DkgMessage.Kind.COMMITMENTS) {
                throw new AssertionError("dealer " + i + " broadcasts " + dealing.broadcasts());
            }
            boolean allInWindow = true;
            for (byte[] e : dealing.envelopes()) {
                DkgShareDeliveryCodec.Envelope env = DkgShareDeliveryCodec.decodeEnvelope(config, e);
                sealed.add(new Object[]{env.sender(), env.recipient(), e});
                if (hooks.missesCutoff(env.sender(), env.recipient())) {
                    allInWindow = false;
                    continue; // posted after the cutoff: in no window
                }
                for (byte[] posted : hooks.envelope(env.sender(), env.recipient(), e)) round1.add(new Post(i, posted));
            }
            if (allInWindow || hooks.ignoreCommitmentsLast().contains(i)) {
                for (DkgMessage m : dealing.broadcasts()) {
                    for (byte[] posted : hooks.broadcast(m)) round1.add(new Post(i, posted));
                }
            }
        }
        board.get(1).addAll(hooks.before(1, this)); // front-running copies, computed from the sealed envelopes
        board.get(1).addAll(round1);
        board.get(1).addAll(hooks.extra(1));
        List<AuthenticatedDkgMessage> window1 = window(board.get(1));
        Map<Integer, List<DkgMessage>> outgoing = new HashMap<>();
        for (DkgParticipant p : participants) {
            if (aborted.containsKey(p.id())) continue;
            try {
                outgoing.put(p.id(), withoutBarrier(p.id()) ? closeWithoutBarrier(p, window1)
                        : DkgShareDelivery.closeRound1(p, directory, keys.get(p.id()), window1, AUTH));
            } catch (FaultAssumptionViolatedException e) {
                aborted.put(p.id(), e);
            }
        }

        // Rounds 2–7: the threshold profile's broadcasts, unchanged.
        for (int round = 2; round <= 7; round++) {
            for (DkgParticipant p : participants) {
                for (DkgMessage m : outgoing.getOrDefault(p.id(), List.of())) {
                    for (byte[] posted : hooks.broadcast(m)) board.get(round).add(new Post(p.id(), posted));
                }
            }
            board.get(round).addAll(hooks.extra(round));
            outgoing.clear();
            for (DkgParticipant p : participants) {
                if (aborted.containsKey(p.id())) continue;
                for (Post post : board.get(round)) {
                    try {
                        p.receiveBroadcast(post.author(), post.bytes());
                    } catch (IllegalArgumentException refused) {
                        // absent
                    }
                }
                try {
                    outgoing.put(p.id(), p.closeRound());
                } catch (FaultAssumptionViolatedException e) {
                    aborted.put(p.id(), e);
                }
            }
        }
        return this;
    }

    /** A participant outside the library's barrier: started unbound, sealed with the test seam. */
    private DkgShareDelivery.SealedDealing startWithoutBinding(DkgParticipant p) {
        directory.requireOwn(keys.get(p.id()));
        List<byte[]> envelopes = new ArrayList<>();
        List<DkgMessage> broadcasts = new ArrayList<>();
        for (DkgMessage m : p.start()) {
            if (m.kind() != DkgMessage.Kind.SHARE) {
                broadcasts.add(m);
            } else {
                envelopes.add(DkgShareDelivery.sealOne(config, m.sender(), m.subject(), directory.key(m.subject()).orElseThrow(), m,
                        testKey(tagPrefix + "ephemeral." + m.sender() + "." + m.subject())));
            }
        }
        return new DkgShareDelivery.SealedDealing(envelopes, broadcasts);
    }

    /**
     * The negative control of the review's F1: broadcasts and timely envelopes are delivered,
     * round 1 is closed, and only then are the late envelopes opened, when the participant no
     * longer accepts them.
     */
    private List<DkgMessage> closeWithoutBarrier(DkgParticipant p, List<AuthenticatedDkgMessage> window1) {
        for (AuthenticatedDkgMessage post : window1) {
            byte[] bytes = post.message();
            DkgShareDeliveryCodec.Envelope env = DkgShareDeliveryCodec.decodeEnvelope(config, bytes);
            if (env != null) {
                if (env.recipient() == p.id() && !hooks.processedLate(env.sender(), p.id())) openInto(p, env);
                continue;
            }
            try {
                DkgMessage m = DkgMessage.decode(config, bytes);
                if (AUTH.authenticate(m.sender(), config.rosterKey(m.sender()), bytes, post.authenticator())) {
                    p.receiveBroadcast(m.sender(), bytes);
                }
            } catch (IllegalArgumentException refused) {
                // absent
            }
        }
        List<DkgMessage> out = p.closeRound();
        for (AuthenticatedDkgMessage post : window1) {
            DkgShareDeliveryCodec.Envelope env = DkgShareDeliveryCodec.decodeEnvelope(config, post.message());
            if (env != null && env.recipient() == p.id() && hooks.processedLate(env.sender(), p.id())) openInto(p, env);
        }
        keys.get(p.id()).destroy();
        return out;
    }

    private void openInto(DkgParticipant p, DkgShareDeliveryCodec.Envelope env) {
        try {
            byte[] pt = Hpke.openBase(env.enc(), secrets.get(p.id()), DkgShareDeliveryCodec.info(config, env.sender(), env.recipient()),
                    new byte[0], env.ct());
            p.receivePrivate(env.sender(), pt); // refused once round 1 is closed
        } catch (Hpke.HpkeException | IllegalArgumentException | IllegalStateException late) {
            // absent
        }
    }

    /** The threshold profile's broadcasts of rounds 1–6, authenticated, as the board holds them. */
    List<byte[]> transcriptMessages() {
        List<byte[]> out = new ArrayList<>();
        for (int r = 1; r <= 6; r++) out.addAll(DkgTranscript.deliveredRound(config, r, window(board.get(r)), AUTH));
        return out;
    }

    /** Authenticated messages of a kind posted in a round, byte-identical copies once. */
    List<DkgMessage> posted(int round, DkgMessage.Kind kind) {
        List<DkgMessage> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Post p : board.get(round)) {
            try {
                DkgMessage m = DkgMessage.decode(config, p.bytes());
                if (m.sender() == p.author() && m.kind() == kind && seen.add(Arrays.toString(p.bytes()))) out.add(m);
            } catch (IllegalArgumentException junk) {
                // envelopes and junk
            }
        }
        return out;
    }
}
