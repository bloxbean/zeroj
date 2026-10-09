package org.zeroj.circuit.lib.jubjub;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * A t-of-n key context from {@code elgamal-jubjub-threshold-v1} key generation (spec §9;
 * ADR-0053 D4, D4a, D5a). It consists of:
 * <ul>
 *   <li>the configuration;</li>
 *   <li>the qualified set {@code QUAL};</li>
 *   <li>the joint key {@code y} (never the identity);</li>
 *   <li>every participant's verification key {@code Y_j}.</li>
 * </ul>
 *
 * <p>It is created in exactly two ways (invariant I7):
 * <ul>
 *   <li>{@link #admit}: authenticated evidence of a complete run, with at least {@code t + 1}
 *       matching confirmations;</li>
 *   <li>{@link DkgParticipant#result()}: a participant's own run.</li>
 * </ul>
 * Recomputing a transcript never creates one.
 *
 * <p><b>Share rules (D5a), which differ from n-of-n.</b>
 * <ul>
 *   <li>Shares are keyed by identifier.</li>
 *   <li>A {@code Y_j} may be the identity, and two participants may have equal {@code Y_j}.
 *       Both occur in valid runs, so neither is rejected.</li>
 *   <li>No proof of possession is used: the VSS checks and admission take its place.</li>
 *   <li>Single-key decryption is not defined, because no full secret exists.</li>
 * </ul>
 *
 * <p>Two contexts are equal iff their sessions, {@code QUAL}, joint keys and verification keys
 * are equal, so contexts from different attempts never compare equal (I16).
 */
public final class ThresholdKeyContext implements ElGamalKeyContext {

    private final DkgConfig config;
    private final SortedSet<Integer> qual;
    private final ElGamalPublicKey jointKey;
    private final List<JubjubPoint> verificationKeys;
    private final byte[] transcriptDigest;
    private final byte[] identity;

    ThresholdKeyContext(DkgConfig config, SortedSet<Integer> qual, JubjubPoint jointKey,
                        List<JubjubPoint> verificationKeys, byte[] transcriptDigest) {
        this.config = config;
        this.qual = Collections.unmodifiableSortedSet(new TreeSet<>(qual));
        this.jointKey = new ElGamalPublicKey(ElGamalEncodings.requireKeyPoint(jointKey, "joint key"));
        List<JubjubPoint> normalized = new ArrayList<>(verificationKeys.size());
        for (JubjubPoint y : verificationKeys) normalized.add(y.normalized());
        this.verificationKeys = List.copyOf(normalized);
        this.transcriptDigest = transcriptDigest.clone();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(config.sessionRef());
        for (int i : this.qual) out.write(i);
        out.write(0);
        out.writeBytes(this.jointKey.encodingRef());
        for (JubjubPoint y : this.verificationKeys) out.writeBytes(y.toBytes());
        this.identity = out.toByteArray();
    }

    /**
     * Admits a key generation from authenticated evidence (spec §8). The library:
     * <ol>
     *   <li>derives the session from {@code config};</li>
     *   <li>decodes every transcript message, which checks it is well-formed for this session,
     *       and refuses a {@code SHARE} or {@code CONFIRMATION} among them: the transcript is
     *       built from delivered broadcast sets, which never hold either kind. Byte-identical
     *       duplicates count once;</li>
     *   <li>only then authenticates each transcript message under its sender's roster key;</li>
     *   <li>checks each round's closure, rounds 1–6;</li>
     *   <li>recomputes the outputs and the transcript digest;</li>
     *   <li>checks round 7's closure (the confirmation set), then requires at least {@code t + 1}
     *       distinct qualified participants whose authenticated confirmations equal the bytes it
     *       builds, and refuses if {@code t + 1} or more confirmed something else (abort A7's
     *       condition: an honest participant saw another board). Up to {@code t} differing
     *       confirmations may be lies and do not veto. A sender that equivocated counts as
     *       differing only. Malformed, foreign-session, non-confirmation and unauthenticated
     *       confirmations are ignored.</li>
     * </ol>
     *
     * @param config       the configuration, from a trusted source
     * @param transcript   every broadcast message of rounds 1–6, with authenticators
     * @param roundClosure round number (1–7) mapped to the closure evidence for that round
     * @param confirmations round-7 confirmations, with authenticators
     * @param verifier     the application's authenticity and closure checks
     * @throws IllegalArgumentException          on a malformed, misplaced, unauthenticated or
     *                                           unclosed transcript, an unclosed confirmation set,
     *                                           {@code t + 1} or more differing confirmations, or
     *                                           fewer than {@code t + 1} matching ones
     * @throws FaultAssumptionViolatedException  if the recomputation hits abort A1, A3, A4 or A5
     */
    public static ThresholdKeyContext admit(DkgConfig config, List<AuthenticatedDkgMessage> transcript,
                                            Map<Integer, byte[]> roundClosure,
                                            List<AuthenticatedDkgMessage> confirmations,
                                            DkgAdmissionVerifier verifier) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(transcript, "transcript");
        Objects.requireNonNull(roundClosure, "roundClosure");
        Objects.requireNonNull(confirmations, "confirmations");
        Objects.requireNonNull(verifier, "verifier");
        // Snapshots: the verifier runs application code, which must not change what is admitted.
        transcript = List.copyOf(transcript);
        confirmations = List.copyOf(confirmations);
        // Step 2 for every message before step 3: nothing malformed reaches the authenticator.
        List<DkgMessage> decoded = new ArrayList<>(transcript.size());
        for (AuthenticatedDkgMessage authenticated : transcript) {
            DkgMessage m = DkgMessage.decode(config, authenticated.message());
            if (m.kind() == DkgMessage.Kind.SHARE || m.kind() == DkgMessage.Kind.CONFIRMATION) {
                throw new IllegalArgumentException(m.kind() + " messages are not part of the transcript");
            }
            decoded.add(m);
        }
        DkgRound[] rounds = DkgTranscript.emptyRounds();
        for (int i = 0; i < decoded.size(); i++) {
            DkgMessage m = decoded.get(i);
            if (!verifier.authenticate(m.sender(), config.rosterKey(m.sender()), m.encode(),
                    transcript.get(i).authenticator())) {
                throw new IllegalArgumentException("message from participant " + m.sender() + " failed authentication");
            }
            rounds[m.round()].add(m);
        }
        DkgTranscript record = new DkgTranscript(config, rounds);
        for (int r = 1; r <= 6; r++) {
            if (!verifier.roundClosed(config, r, record.roundMessages(r), roundClosure.get(r))) {
                throw new IllegalArgumentException("round " + r + " is not evidenced as closed and complete");
            }
        }
        DkgTranscript.DkgPublicOutcome outcome = record.recompute();
        byte[] digest = record.digest();
        SortedSet<Integer> matching = new TreeSet<>();
        SortedSet<Integer> differing = new TreeSet<>();
        DkgRound round7 = new DkgRound(7);
        for (AuthenticatedDkgMessage authenticated : confirmations) {
            byte[] bytes = authenticated.message();
            DkgMessage m;
            try {
                m = DkgMessage.decode(config, bytes);
            } catch (IllegalArgumentException malformedOrStale) {
                continue; // malformed, or for another session: ignored, never a veto
            }
            if (m.kind() != DkgMessage.Kind.CONFIRMATION) {
                continue;
            }
            if (!verifier.authenticate(m.sender(), config.rosterKey(m.sender()), bytes, authenticated.authenticator())) {
                continue;
            }
            round7.add(m);
            if (!outcome.qual().contains(m.sender())) {
                continue;
            }
            byte[] expected = DkgMessage.confirmation(config, m.sender(), digest, outcome.jointKey()).bytesRef();
            (Arrays.equals(expected, m.bytesRef()) ? matching : differing).add(m.sender());
        }
        // Round 7 must be evidenced complete too, so differing confirmations cannot be left out.
        List<byte[]> confirmationSet = new ArrayList<>();
        for (DkgMessage m : round7.canonical()) confirmationSet.add(m.encode());
        if (!verifier.roundClosed(config, 7, confirmationSet, roundClosure.get(7))) {
            throw new IllegalArgumentException("round 7 (confirmations) is not evidenced as closed and complete");
        }
        matching.removeAll(differing); // an equivocating sender counts as differing only
        if (differing.size() >= config.t() + 1) {
            throw new IllegalArgumentException(differing.size()
                    + " qualified participants confirmed a different transcript or key; the broadcast lacked agreement");
        }
        if (matching.size() < config.t() + 1) {
            throw new IllegalArgumentException("admission needs authenticated confirmations from at least t + 1 = "
                    + (config.t() + 1) + " qualified participants, got " + matching.size());
        }
        return new ThresholdKeyContext(config, outcome.qual(), outcome.jointKey(), outcome.verificationKeys(), digest);
    }

    @Override
    public ElGamalPublicKey jointKey() {
        return jointKey;
    }

    /** The configuration. */
    public DkgConfig config() {
        return config;
    }

    /** {@code t}: decryption needs {@code t + 1} verified shares. */
    public int threshold() {
        return config.t();
    }

    /** The qualified participants, who may contribute decryption shares. */
    public SortedSet<Integer> qual() {
        return qual;
    }

    /** {@code Y_j}, possibly the identity. */
    public JubjubPoint verificationKey(int id) {
        config.requireParticipant(id);
        return verificationKeys.get(id - 1);
    }

    /** The digest of the transcript this context was built from. */
    public byte[] transcriptDigest() {
        return transcriptDigest.clone();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ThresholdKeyContext other && Arrays.equals(identity, other.identity);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(identity);
    }

    @Override
    public String toString() {
        return "ThresholdKeyContext{t=" + config.t() + ", n=" + config.n() + ", qual=" + qual
                + ", jointKey=" + jointKey + "}";
    }
}
