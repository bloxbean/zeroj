package org.zeroj.circuit.lib.jubjub;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.IntFunction;

/**
 * Encrypted delivery of a threshold key generation's private {@code SHARE}s over the public board:
 * {@code dkg-share-delivery-hpke-v1} (ADR-0054). Each {@code SHARE} is encrypted with HPKE
 * (RFC 9180 Base mode; DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305) to the
 * recipient's per-attempt key from round 0, and posted as an envelope.
 *
 * <p>The key generation itself is unchanged: {@link DkgParticipant} receives each decrypted
 * {@code SHARE} through {@link DkgParticipant#receivePrivate}, and the transcript, digest and
 * admission are exactly those of a run with private channels.
 *
 * <p><b>The rules</b> (spec §3.3, §5; ADR-0054 D4, D6a, D7a). The library enforces those it can:
 * <ol>
 *   <li><b>Round 0.</b> Post {@link DkgShareDeliveryKeys#announcement()}. When the round-0 window
 *       is final, build the {@link DkgKeyDirectory}.</li>
 *   <li><b>Start.</b> Call {@link #start} instead of {@link DkgParticipant#start()}. It applies
 *       abort T1 and <b>binds</b> the participant: from then on its round 1 closes only through
 *       {@link #closeRound1}, and the public {@link DkgParticipant#closeRound()} refuses round 1.</li>
 *   <li><b>Posting order.</b> Post {@link SealedDealing#envelopes()} first. Post
 *       {@link SealedDealing#broadcasts()} (the {@code COMMITMENTS}) <b>only after every envelope
 *       is final on the board within the round-1 window</b>, or post them all atomically. If the
 *       envelopes cannot be made final before the cutoff, do not post the broadcasts. This one
 *       rule is the application's to follow: the library cannot see the board.</li>
 *   <li><b>Barrier.</b> {@link #closeRound1} takes the complete final round-1 window, delivers every
 *       broadcast and opens every envelope, and only then closes round 1. Binding enforces
 *       "process before closing"; that the window is complete is the application's to ensure.
 *       Pass the window only after its cutoff <b>and</b> finality: a snapshot taken earlier can
 *       miss envelopes that become final later. That is the late-processing failure the barrier
 *       exists to prevent (ADR-0054 D6a). Round 1's window opens when round 0's window closes, so
 *       a threshold-profile message posted during round 0 is early and belongs to no window
 *       (spec §5).</li>
 *   <li>Rounds 2–7 continue with {@link DkgParticipant#receiveBroadcast} and
 *       {@link DkgParticipant#closeRound()} as before.</li>
 * </ol>
 *
 * <p><b>Fail closed.</b> If {@link #closeRound1} throws (a refused argument, T1, an exception
 * from the application's verifier, or a fault of the platform's cryptographic providers) the
 * participant is left at round 1, or aborted on T1, and
 * cannot close round 1 any other way, so it never complains about a share it did not process.
 * That costs liveness, never secrecy. A verifier must return {@code false}, not throw, for a
 * post it does not accept; a verifier exception is not treated as "unauthentic", because a
 * transient failure would then turn into false complaints.
 *
 * <p>The delivery contract (P1 bounded publication, P2 agreement and finality) and Assumption A1
 * are the application's and the reviewers', as stated in ADR-0054. Secret operations are
 * compatibility/offline class (ADR-0039 §3.1).
 */
public final class DkgShareDelivery {

    private DkgShareDelivery() {
    }

    /** A dealer's round-1 output, split by posting order (spec §5.2). */
    public static final class SealedDealing {
        private final List<byte[]> envelopes;
        private final List<DkgMessage> broadcasts;

        SealedDealing(List<byte[]> envelopes, List<DkgMessage> broadcasts) {
            this.envelopes = envelopes;
            this.broadcasts = broadcasts;
        }

        /** The envelopes, to post first. */
        public List<byte[]> envelopes() {
            List<byte[]> out = new ArrayList<>(envelopes.size());
            for (byte[] e : envelopes) out.add(e.clone());
            return out;
        }

        /**
         * The round-1 broadcasts (the {@code COMMITMENTS}), to post <b>only after every envelope is
         * final</b> on the board within the round-1 window, or atomically with them.
         */
        public List<DkgMessage> broadcasts() {
            return broadcasts;
        }
    }

    /**
     * Starts {@code participant} for encrypted delivery (spec §3.3, §4.1). It checks that the
     * participant, the directory and the keys share one session and one identifier, applies
     * abort T1, runs a seal-and-open self-test of the platform's primitives, binds the
     * participant (see the class documentation), opens round 1, and seals one envelope per other
     * participant that has a key. It never seals to the dealer itself.
     *
     * <p>If the self-test fails, nothing has changed and {@code start} can be retried. If sealing
     * fails after round 1 opened (a platform fault, never caused by a directory key), no dealing is
     * returned: the application posts nothing for this participant in round 1, so R1 disqualifies
     * its dealing and no honest participant complains about it (spec §5.2).
     *
     * @throws FaultAssumptionViolatedException with reason {@code OWN_KEY_ANNOUNCEMENT_MISSING}
     *         (T1); the participant is then aborted and the keys destroyed
     * @throws IllegalArgumentException if the participant, directory and keys disagree
     * @throws IllegalStateException    if the platform's HPKE primitives fail (see above)
     */
    public static SealedDealing start(DkgParticipant participant, DkgKeyDirectory directory, DkgShareDeliveryKeys keys,
                                      SecureRandom random) {
        Objects.requireNonNull(random, "random");
        return start(participant, directory, keys, recipient -> {
            byte[] skE = new byte[Hpke.N_SK];
            random.nextBytes(skE);
            return skE;
        });
    }

    /**
     * Test seam: {@link #start} with the ephemeral private key for each recipient supplied by
     * {@code ephemeral} (spec §9.1 test keys). Production code uses fresh randomness only.
     */
    static SealedDealing start(DkgParticipant participant, DkgKeyDirectory directory, DkgShareDeliveryKeys keys,
                               IntFunction<byte[]> ephemeral) {
        Objects.requireNonNull(participant, "participant");
        Objects.requireNonNull(directory, "directory");
        Objects.requireNonNull(keys, "keys");
        Objects.requireNonNull(ephemeral, "ephemeral");
        DkgConfig config = participant.config();
        requireSameRun(participant, directory, keys);
        try {
            directory.requireOwn(keys);
        } catch (FaultAssumptionViolatedException t1) {
            participant.abortWith(t1);
            keys.destroy();
            throw t1;
        }
        byte[] ownSecret = keys.secretFor(config);
        try {
            selfTest(X25519Bytes.privateKey(ownSecret), keys.publicKey());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 is unavailable", e);
        } finally {
            Arrays.fill(ownSecret, (byte) 0);
        }
        participant.bindEncryptedDelivery(keys, directory);
        List<DkgMessage> startOutput = participant.start();
        List<byte[]> envelopes = new ArrayList<>();
        List<DkgMessage> broadcasts = new ArrayList<>();
        for (DkgMessage m : startOutput) {
            if (m.kind() != DkgMessage.Kind.SHARE) {
                broadcasts.add(m);
                continue;
            }
            int i = m.sender();
            int j = m.subject();
            if (i == j) continue; // never sealed to oneself (spec §4.1)
            byte[] pkR = directory.key(j).orElse(null);
            if (pkR == null) continue; // no key: no envelope (spec §4.1)
            envelopes.add(sealOne(config, i, j, pkR, m, ephemeral.apply(j)));
        }
        return new SealedDealing(List.copyOf(envelopes), List.copyOf(broadcasts));
    }

    private static final byte[] SELF_TEST_INFO = Hpke.ascii("zeroj.dkg-share-delivery-hpke.v1.self-test");

    /**
     * Seals a fixed plaintext to {@code pkR} under a fresh ephemeral key and opens it with
     * {@code recipient}: a local check of the platform's X25519, HKDF and ChaCha20-Poly1305, run
     * before any input is judged (review Z-1). Nothing of it is posted.
     *
     * @throws IllegalStateException if any step fails or the plaintext differs
     */
    private static void selfTest(PrivateKey recipient, byte[] pkR) {
        byte[] pt = new byte[DkgShareDeliveryCodec.SHARE_LENGTH];
        try {
            Hpke.Sealed sealed = Hpke.sealBase(pkR, SELF_TEST_INFO, new byte[0], pt, new SecureRandom());
            if (!Arrays.equals(pt, Hpke.openBase(sealed.enc(), recipient, pkR, SELF_TEST_INFO, new byte[0], sealed.ct()))) {
                throw new IllegalStateException("HPKE self-test returned a different plaintext");
            }
        } catch (Hpke.HpkeException e) {
            throw new IllegalStateException("HPKE self-test failed", e);
        }
    }

    /** Test seam: seals one given {@code SHARE} message (for envelopes built by negative tests). */
    static byte[] sealOne(DkgConfig config, int i, int j, byte[] pkR, DkgMessage share, byte[] skE) {
        byte[] pt = share.encode();
        try {
            Hpke.Sealed sealed = Hpke.sealBaseWithEphemeral(skE, pkR, DkgShareDeliveryCodec.info(config, i, j), new byte[0], pt);
            return DkgShareDeliveryCodec.envelope(config, i, j, sealed.enc(), sealed.ct());
        } catch (Hpke.HpkeException e) {
            // The directory holds only canonical, non-small-order keys, so sealing cannot fail on
            // the recipient key. Anything else is an environment fault, not a protocol event.
            throw new IllegalStateException("HPKE sealing failed", e);
        } finally {
            Arrays.fill(skE, (byte) 0);
            Arrays.fill(pt, (byte) 0);
        }
    }

    /**
     * Closes round 1 behind the processing barrier (spec §5.1; ADR-0054 D6a, I11). For a
     * participant started with {@link #start}, it:
     * <ol>
     *   <li>checks the session and identifier of the participant, directory and keys, requires
     *       the very keys and directory instances given to {@link #start}, and checks abort T1
     *       again;</li>
     *   <li>authenticates every post of the window under its sender's roster key, and drops those
     *       that fail. Nothing is de-duplicated before authentication, so a copy posted under
     *       another author cannot shadow the genuine post;</li>
     *   <li>delivers every threshold-profile broadcast to the participant;</li>
     *   <li>opens <b>every</b> envelope addressed to it, submitting each accepted {@code SHARE}
     *       through {@link DkgParticipant#receivePrivate}. Byte-identical copies are counted once
     *       by the participant;</li>
     *   <li>only then closes round 1, returning the round-2 complaints.</li>
     * </ol>
     * Before the first post it runs a seal-and-open self-test of the platform's primitives with
     * the participant's own keys.
     *
     * <p>The delivery keys are destroyed once round 1 is closed, or when the participant aborts
     * (T1, or an abort while closing round 1) (spec §7). If anything else throws (the
     * application's verifier, the self-test, a platform fault while opening, or an unexpected
     * failure closing the round), the keys are kept and the call can be retried; while the
     * participant is still at round 1 it stays there. A retry <b>must</b> pass the identical final
     * window: deliveries from the interrupted pass stay with the participant, which counts
     * byte-identical repeats once. An application that abandons the attempt instead calls
     * {@link DkgShareDeliveryKeys#destroy()}. The participant can close round 1 in no other way.
     *
     * <p>An envelope that fails because of its content (spec §4.2 steps 1–6) is silently absence
     * (ADR-0054 I4). A failure of the platform's primitives is never absence: it fails closed as
     * above, since treating it as absence would turn honest dealers' shares into complaints, and
     * so into public answers (review Z-1).
     *
     * @param finalRound1Window every board post of the round-1 window, after the cutoff and
     *                          finality: threshold-profile messages, envelopes and anything else
     * @throws IllegalStateException            if {@code participant} was not started with
     *                                          {@link #start} or is not at round 1, the keys were
     *                                          destroyed, or the platform's primitives failed
     * @throws IllegalArgumentException         if the participant, directory and keys disagree, or
     *                                          are not the instances given to {@link #start}
     * @throws FaultAssumptionViolatedException on T1, or if the participant aborts while closing
     *                                          round 1
     */
    public static List<DkgMessage> closeRound1(DkgParticipant participant, DkgKeyDirectory directory,
                                               DkgShareDeliveryKeys keys,
                                               List<AuthenticatedDkgMessage> finalRound1Window,
                                               DkgAdmissionVerifier verifier) {
        Objects.requireNonNull(participant, "participant");
        Objects.requireNonNull(directory, "directory");
        Objects.requireNonNull(keys, "keys");
        Objects.requireNonNull(finalRound1Window, "finalRound1Window");
        Objects.requireNonNull(verifier, "verifier");
        if (!participant.boundToEncryptedDelivery()) {
            throw new IllegalStateException("start the participant with DkgShareDelivery.start");
        }
        if (participant.openRound() != 1) {
            throw new IllegalStateException("closeRound1 needs a participant at round 1, got round " + participant.openRound());
        }
        requireSameRun(participant, directory, keys);
        if (!participant.boundTo(keys, directory)) {
            // The directory decides which envelopes exist for this participant, and the keys which
            // open. Substituting either after start would turn genuine shares into absences, and so
            // into complaints (review C-1).
            throw new IllegalArgumentException("closeRound1 needs the same keys and directory instances given to start");
        }
        try {
            directory.requireOwn(keys);
        } catch (FaultAssumptionViolatedException t1) {
            participant.abortWith(t1);
            keys.destroy();
            throw t1;
        }
        DkgConfig config = participant.config();
        byte[] skR = keys.secretFor(config);
        byte[] pkR = keys.publicKey();
        try {
            PrivateKey recipient = X25519Bytes.privateKey(skR);
            selfTest(recipient, pkR);
            for (AuthenticatedDkgMessage post : List.copyOf(finalRound1Window)) {
                deliver(config, post.message(), post.authenticator(), recipient, pkR, participant, verifier);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 is unavailable", e);
        } finally {
            Arrays.fill(skR, (byte) 0);
        }
        // Every envelope is processed. An exception above (from the application's verifier or a
        // platform fault) leaves the keys, and the participant at round 1, so closeRound1 can be
        // retried with the same window. The keys go once the round is closed or the participant
        // aborts (spec §7); any other failure keeps them for a retry (review Z-4).
        List<DkgMessage> complaints;
        try {
            complaints = participant.closeRoundOneAfterDelivery();
        } catch (FaultAssumptionViolatedException abort) {
            keys.destroy();
            throw abort;
        }
        keys.destroy();
        return complaints;
    }

    private static void requireSameRun(DkgParticipant participant, DkgKeyDirectory directory, DkgShareDeliveryKeys keys) {
        DkgConfig config = participant.config();
        if (!config.equals(directory.config()) || !config.equals(keys.config())) {
            throw new IllegalArgumentException("the participant, directory and keys belong to different sessions");
        }
        if (participant.id() != keys.id()) {
            throw new IllegalArgumentException("the delivery keys belong to participant " + keys.id()
                    + ", not " + participant.id());
        }
    }

    /** One round-1 post: authenticated first, then routed as an envelope or a broadcast. */
    private static void deliver(DkgConfig config, byte[] bytes, byte[] authenticator, PrivateKey recipient, byte[] pkR,
                                DkgParticipant participant, DkgAdmissionVerifier verifier) {
        DkgShareDeliveryCodec.Envelope envelope = DkgShareDeliveryCodec.decodeEnvelope(config, bytes);
        if (envelope != null) {
            if (envelope.recipient() != participant.id()) return;
            int i = envelope.sender();
            if (!verifier.authenticate(i, config.rosterKey(i), bytes.clone(), authenticator)) return; // step 3
            open(config, envelope, recipient, pkR, participant);
            return;
        }
        DkgMessage m;
        try {
            m = DkgMessage.decode(config, bytes);
        } catch (IllegalArgumentException malformed) {
            return; // not a message of either profile
        }
        if (!verifier.authenticate(m.sender(), config.rosterKey(m.sender()), bytes.clone(), authenticator)) return;
        try {
            participant.receiveBroadcast(m.sender(), bytes);
        } catch (IllegalArgumentException refused) {
            // another round, a SHARE on the board, or otherwise refused: absent
        }
    }

    /**
     * Spec §4.2 steps 5 and 6; a failure caused by the envelope is absence. A platform fault
     * ({@link IllegalStateException} from {@link Hpke}) propagates and fails closed.
     */
    private static void open(DkgConfig config, DkgShareDeliveryCodec.Envelope envelope, PrivateKey recipient, byte[] pkR,
                             DkgParticipant participant) {
        int i = envelope.sender();
        byte[] pt;
        try {
            pt = Hpke.openBase(envelope.enc(), recipient, pkR, DkgShareDeliveryCodec.info(config, i, envelope.recipient()),
                    new byte[0], envelope.ct());
        } catch (Hpke.HpkeException absent) {
            return;
        }
        try {
            participant.receivePrivate(i, pt); // checks: SHARE of this session, sender i, subject j
        } catch (IllegalArgumentException absent) {
            // not a valid SHARE from i to this participant: absent
        } finally {
            Arrays.fill(pt, (byte) 0);
        }
    }
}
