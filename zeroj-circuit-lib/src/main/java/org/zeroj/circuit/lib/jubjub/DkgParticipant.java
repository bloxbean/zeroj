package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * One participant of {@code elgamal-jubjub-threshold-v1} key generation: New-DKG of [GJKR07]
 * Fig. 2 as a deterministic, transport-agnostic state machine (spec §3–§7; ADR-0053 D1, D1a,
 * D4).
 *
 * <pre>{@code
 * List<DkgMessage> out = p.start();                // round 1: COMMITMENTS + private SHAREs
 * for each round r = 1 … 7:
 *     for each broadcast message of round r:  p.receiveBroadcast(sender, bytes)
 *     for each private SHARE to p (round 1):  p.receivePrivate(sender, bytes)
 *     out = p.closeRound();                       // when the round's deadline passes
 * ThresholdKeyShare share = p.result();
 * }</pre>
 *
 * <p>The application supplies the transport (ADR-0053 D3), and must route correctly: the board's
 * messages through {@link #receiveBroadcast}, and only messages from the private channel through
 * {@link #receivePrivate}. A message delivered privately to one participant must never be treated
 * as broadcast. Timely private delivery is a <b>secrecy</b> precondition, not only a liveness one
 * (spec §5.2).
 *
 * <p>An abort is final: after a {@link FaultAssumptionViolatedException}, every method throws it
 * again, and the participant sends nothing more.
 *
 * <p>The transport consists of:
 * <ul>
 *   <li>a broadcast channel with agreement;</li>
 *   <li>private, authenticated channels for {@code SHARE} messages;</li>
 *   <li>round deadlines.</li>
 * </ul>
 * It delivers each message with the sender its channel authenticated. The participant refuses
 * a message whose header disagrees, or that belongs to another round. The participant's own
 * broadcasts must also be delivered back to it, so that it decides on exactly the board's view,
 * as every other honest participant does.
 *
 * <p>Public decisions come from {@link DkgRules}, the same code that recomputes a transcript:
 * {@code QUAL}, the marks, reconstruction and the outputs. This class adds only what depends on
 * the participant's private shares: its complaints, adopting answered pairs, its extraction
 * complaints and reconstruction pairs, and its own secret share. Any condition the assumptions
 * rule out aborts with {@link FaultAssumptionViolatedException} (spec §5.1).
 *
 * <p><b>Secrets.</b> The polynomials and every received pair are secret. Dealing and the checks
 * on received pairs use the blinded best-effort schedule. The class is compatibility/offline
 * class (ADR-0039 §3.1): run each participant on its own isolated host.
 */
public final class DkgParticipant {

    private static final int FINISHED = 8;

    private final DkgConfig config;
    private final int id;
    private ThresholdVss.Dealing dealing;
    private final DkgRound[] delivered = DkgTranscript.emptyRounds();
    private final Map<Integer, List<DkgMessage>> sharesReceived = new HashMap<>();
    private final Set<ByteBuffer> sharesSeen = new HashSet<>();
    private final Map<Integer, BigInteger[]> pairs = new HashMap<>();
    private final Set<Integer> complainedAgainst = new HashSet<>();
    private int open;
    private DkgRules.Qualification qualification;
    private DkgRules.Marks marks;
    private DkgRules.Outputs outputs;
    private BigInteger secretShare;
    private byte[] digest;
    private ThresholdKeyShare result;
    private FaultAssumptionViolatedException abort;
    /** Set by {@link DkgShareDelivery#start}: round 1 then closes only through {@link DkgShareDelivery#closeRound1}. */
    private boolean encryptedDelivery;
    /** The exact keys and directory {@link DkgShareDelivery#start} bound; round 1 closes only with these. */
    private Object boundKeys;
    private Object boundDirectory;

    private DkgParticipant(DkgConfig config, int id, ThresholdVss.Dealing dealing) {
        this.config = config;
        this.id = id;
        this.dealing = dealing;
    }

    /** A participant that samples its own polynomials (spec §3). */
    public static DkgParticipant create(DkgConfig config, int id, SecureRandom random) {
        Objects.requireNonNull(config, "config");
        config.requireParticipant(id);
        return new DkgParticipant(config, id, ThresholdVss.deal(config.t(), random));
    }

    /** Test seam: a participant with fixed polynomials (vectors and fixtures only). */
    static DkgParticipant withDealing(DkgConfig config, int id, ThresholdVss.Dealing dealing) {
        config.requireParticipant(id);
        if (dealing.degree() != config.t()) {
            throw new IllegalArgumentException("dealing degree must equal t");
        }
        return new DkgParticipant(config, id, dealing);
    }

    /** This participant's identifier. */
    public int id() {
        return id;
    }

    /** The round currently open (1–7), 0 before {@link #start()}, 8 when finished. */
    public int openRound() {
        return open;
    }

    /**
     * Opens round 1 and returns this participant's {@code COMMITMENTS} broadcast and one private
     * {@code SHARE} per other participant.
     */
    public List<DkgMessage> start() {
        requireNotAborted();
        if (open != 0) {
            throw new IllegalStateException("already started");
        }
        open = 1;
        List<DkgMessage> out = new ArrayList<>(config.n());
        out.add(DkgMessage.points(config, DkgMessage.Kind.COMMITMENTS, id, dealing.commitments()));
        for (int j = 1; j <= config.n(); j++) {
            if (j != id) {
                out.add(DkgMessage.pair(config, DkgMessage.Kind.SHARE, id, j, dealing.share(j), dealing.sharePrime(j)));
            }
        }
        return out;
    }

    /**
     * Delivers one message from the <b>broadcast</b> channel, for the open round, with the sender
     * the channel authenticated.
     *
     * @throws IllegalArgumentException if the message is malformed or for another session, its
     *         header's sender differs from {@code authenticatedSender}, it belongs to another
     *         round, or it is a {@code SHARE}. The caller treats such a message as absent.
     * @throws FaultAssumptionViolatedException if this participant has aborted
     */
    public void receiveBroadcast(int authenticatedSender, byte[] message) {
        DkgMessage m = accept(authenticatedSender, message);
        if (m.kind() == DkgMessage.Kind.SHARE) {
            throw new IllegalArgumentException("a SHARE is private and never arrives by broadcast");
        }
        delivered[open].add(m);
    }

    /**
     * Delivers one {@code SHARE} from the <b>private</b> channel, with the sender the channel
     * authenticated.
     *
     * @throws IllegalArgumentException if the message is not a well-formed {@code SHARE} of the
     *         open round, addressed to this participant, from {@code authenticatedSender}
     * @throws FaultAssumptionViolatedException if this participant has aborted
     */
    public void receivePrivate(int authenticatedSender, byte[] message) {
        DkgMessage m = accept(authenticatedSender, message);
        if (m.kind() != DkgMessage.Kind.SHARE) {
            throw new IllegalArgumentException(m.kind() + " is a broadcast message, not a private one");
        }
        if (m.subject() != id) {
            throw new IllegalArgumentException("SHARE addressed to participant " + m.subject());
        }
        if (sharesSeen.add(ByteBuffer.wrap(m.bytesRef()))) {
            sharesReceived.computeIfAbsent(m.sender(), k -> new ArrayList<>(1)).add(m);
        }
    }

    private DkgMessage accept(int authenticatedSender, byte[] message) {
        requireNotAborted();
        if (open < 1 || open > 7) {
            throw new IllegalStateException("no round is open");
        }
        DkgMessage m = DkgMessage.decode(config, message);
        if (m.sender() != authenticatedSender) {
            throw new IllegalArgumentException("header sender " + m.sender()
                    + " differs from the authenticated sender " + authenticatedSender);
        }
        if (m.round() != open) {
            throw new IllegalArgumentException("message of round " + m.round() + " while round " + open + " is open");
        }
        return m;
    }

    private void requireNotAborted() {
        if (abort != null) {
            throw abort;
        }
    }

    /**
     * Closes the open round, applies its rules and returns this participant's messages for the
     * next round (possibly none). Closing round 7 completes the run.
     *
     * @throws FaultAssumptionViolatedException on any abort condition of spec §5.1
     */
    public List<DkgMessage> closeRound() {
        requireNotAborted();
        if (encryptedDelivery && open == 1) {
            // The processing barrier of dkg-share-delivery-hpke-v1 §5.1 (ADR-0054 D6a): a bound
            // participant never closes round 1 except after every envelope has been processed.
            throw new IllegalStateException("round 1 of a run using encrypted share delivery closes only through"
                    + " DkgShareDelivery.closeRound1");
        }
        return closeOpenRound();
    }

    /** {@link #closeRound()} without the delivery guard; {@link DkgShareDelivery#closeRound1} only. */
    List<DkgMessage> closeRoundOneAfterDelivery() {
        if (!encryptedDelivery || open != 1) {
            throw new IllegalStateException("not a bound participant at round 1");
        }
        requireNotAborted();
        return closeOpenRound();
    }

    /** Binds this participant to encrypted share delivery with these exact keys and directory; only before {@link #start()}. */
    void bindEncryptedDelivery(Object keys, Object directory) {
        if (open != 0) {
            throw new IllegalStateException("encrypted delivery must be bound before start");
        }
        encryptedDelivery = true;
        boundKeys = keys;
        boundDirectory = directory;
    }

    boolean boundToEncryptedDelivery() {
        return encryptedDelivery;
    }

    /** {@code true} iff {@code keys} and {@code directory} are the very objects bound at start. */
    boolean boundTo(Object keys, Object directory) {
        return encryptedDelivery && boundKeys == keys && boundDirectory == directory;
    }

    /** Aborts this participant (sticky), for transport aborts such as T1. */
    void abortWith(FaultAssumptionViolatedException e) {
        if (abort == null) {
            abort = e;
            forgetSecrets();
        }
    }

    DkgConfig config() {
        return config;
    }

    /** The distinct {@code SHARE}s received from {@code dealer} so far (tests and vectors only). */
    List<DkgMessage> receivedShares(int dealer) {
        return List.copyOf(sharesReceived.getOrDefault(dealer, List.of()));
    }

    private List<DkgMessage> closeOpenRound() {
        try {
            return switch (open) {
                case 1 -> closeDeal();
                case 2 -> closeComplaints();
                case 3 -> closeAnswers();
                case 4 -> closeExtraction();
                case 5 -> closeExtractionComplaints();
                case 6 -> closeReconstruction();
                case 7 -> closeConfirmation();
                default -> throw new IllegalStateException("no round is open");
            };
        } catch (FaultAssumptionViolatedException e) {
            abort = e; // final: no restart within the session (I13)
            forgetSecrets();
            throw e;
        }
    }

    /**
     * The participant's result: its secret share and the key context of its own run.
     *
     * @throws IllegalStateException before round 7 is closed
     */
    public ThresholdKeyShare result() {
        requireNotAborted();
        if (open != FINISHED) {
            throw new IllegalStateException("key generation has not finished");
        }
        return result;
    }

    // ------------------------------------------------------------------ transitions

    private List<DkgMessage> closeDeal() {
        List<DkgMessage> out = new ArrayList<>();
        pairs.put(id, new BigInteger[]{dealing.share(id), dealing.sharePrime(id)});
        for (int i = 1; i <= config.n(); i++) {
            if (i == id) continue;
            DkgMessage commitments = delivered[1].single(DkgMessage.Kind.COMMITMENTS, i, 0);
            if (commitments == null) continue; // the dealer is disqualified by R1 regardless
            List<DkgMessage> variants = sharesReceived.get(i);
            DkgMessage share = variants != null && variants.size() == 1 ? variants.get(0) : null;
            if (share != null && ThresholdVss.checkPedersenPrivate(commitments.points(), id, share.s(), share.sPrime())) {
                pairs.put(i, new BigInteger[]{share.s(), share.sPrime()});
            } else {
                complainedAgainst.add(i);
                out.add(DkgMessage.complaint(config, id, i));
            }
        }
        open = 2;
        return out;
    }

    private List<DkgMessage> closeComplaints() {
        for (int i : complainedAgainst) {
            if (delivered[2].single(DkgMessage.Kind.COMPLAINT, id, i) == null) {
                // A9: this participant's own complaint was not delivered back to it. The board
                // then lacks it for everyone, and an answer to it might never be checked.
                throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.OWN_COMPLAINT_MISSING,
                        "participant " + id + "'s complaint against dealer " + i + " is missing from the board");
            }
        }
        List<DkgMessage> out = new ArrayList<>();
        for (int j = 1; j <= config.n(); j++) {
            if (j != id && delivered[2].single(DkgMessage.Kind.COMPLAINT, j, id) != null) {
                out.add(DkgMessage.pair(config, DkgMessage.Kind.ANSWER, id, j, dealing.share(j), dealing.sharePrime(j)));
            }
        }
        open = 3;
        return out;
    }

    private List<DkgMessage> closeAnswers() {
        qualification = DkgRules.qualify(config, delivered[1], delivered[2], delivered[3]);
        if (!qualification.qual().contains(id)) {
            throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.OWN_DEALING_DISQUALIFIED,
                    "participant " + id + " answered every complaint correctly but was disqualified");
        }
        for (int i : qualification.qual()) {
            if (complainedAgainst.contains(i)) {
                // i stayed qualified, so its answer to this complaint exists and satisfies (4).
                DkgMessage answer = delivered[3].single(DkgMessage.Kind.ANSWER, i, id);
                pairs.put(i, new BigInteger[]{answer.s(), answer.sPrime()});
            }
        }
        open = 4;
        return List.of(DkgMessage.points(config, DkgMessage.Kind.EXTRACTION, id, dealing.extraction()));
    }

    private List<DkgMessage> closeExtraction() {
        List<DkgMessage> out = new ArrayList<>();
        for (int i : qualification.qual()) {
            if (i == id) continue;
            DkgMessage extraction = delivered[4].single(DkgMessage.Kind.EXTRACTION, i, 0);
            BigInteger[] pair = pairs.get(i);
            if (extraction != null && !ThresholdVss.checkFeldmanPrivate(extraction.points(), id, pair[0])) {
                out.add(DkgMessage.pair(config, DkgMessage.Kind.EXTRACTION_COMPLAINT, id, i, pair[0], pair[1]));
            }
        }
        open = 5;
        return out;
    }

    private List<DkgMessage> closeExtractionComplaints() {
        marks = DkgRules.mark(config, qualification, delivered[4], delivered[5]);
        if (marks.marked().contains(id)) {
            // A8: an honest dealer broadcast a correct EXTRACTION in time, so it is never marked.
            // If it was (a late message), reconstruction will publish its contribution; aborting
            // withholds this participant's confirmation, so such a run cannot be admitted.
            throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.OWN_DEALING_MARKED,
                    "participant " + id + "'s own dealing was marked for reconstruction");
        }
        List<DkgMessage> out = new ArrayList<>();
        for (int i : marks.marked()) {
            if (i == id) continue;
            BigInteger[] pair = pairs.get(i);
            out.add(DkgMessage.pair(config, DkgMessage.Kind.RECONSTRUCTION, id, i, pair[0], pair[1]));
        }
        open = 6;
        return out;
    }

    private List<DkgMessage> closeReconstruction() {
        outputs = DkgRules.finish(config, qualification, marks, delivered[6]);
        BigInteger x = BigInteger.ZERO;
        for (int i : qualification.qual()) {
            x = x.add(pairs.get(i)[0]);
        }
        secretShare = x.mod(SUBGROUP_ORDER);
        JubjubPoint mine = JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(secretShare);
        if (!mine.projectiveEquals(outputs.verificationKeys().get(id - 1))) {
            throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.SHARE_MISMATCH,
                    "participant " + id + "'s share does not match its verification key");
        }
        digest = new DkgTranscript(config, delivered).digest();
        open = 7;
        return List.of(DkgMessage.confirmation(config, id, digest, outputs.jointKey()));
    }

    private List<DkgMessage> closeConfirmation() {
        // A7: count distinct qualified senders whose confirmation matches this participant's
        // view, and those that confirmed anything else (an equivocator counts as differing).
        // At most t are faulty, so t + 1 differing include an honest participant who saw another
        // board, and fewer than t + 1 matching means the honest majority did not confirm this one.
        int matching = 0;
        int differing = 0;
        for (int j : qualification.qual()) {
            byte[] expected = DkgMessage.confirmation(config, j, digest, outputs.jointKey()).bytesRef();
            List<DkgMessage> variants = delivered[7].variants(DkgMessage.Kind.CONFIRMATION, j, 0);
            boolean differs = false;
            boolean matches = false;
            for (DkgMessage received : variants) {
                if (Arrays.equals(received.bytesRef(), expected)) matches = true;
                else differs = true;
            }
            if (differs) differing++;
            else if (matches) matching++;
        }
        if (differing >= config.t() + 1 || matching < config.t() + 1) {
            throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.CONFLICTING_CONFIRMATION,
                    matching + " matching and " + differing + " differing confirmations from qualified participants");
        }
        ThresholdKeyContext context = new ThresholdKeyContext(config, qualification.qual(),
                outputs.jointKey(), outputs.verificationKeys(), digest);
        result = new ThresholdKeyShare(context, id, secretShare);
        open = FINISHED;
        forgetSecrets();
        return List.of();
    }

    /** Best effort: drops references to the polynomials and received pairs ({@code BigInteger} cannot be wiped). */
    private void forgetSecrets() {
        dealing = null;
        secretShare = null; // after finishing, the result holds it; after an abort, nobody does
        pairs.clear();
        sharesReceived.clear();
        sharesSeen.clear();
    }
}
