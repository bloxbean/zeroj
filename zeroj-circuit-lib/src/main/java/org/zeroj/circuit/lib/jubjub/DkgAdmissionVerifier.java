package org.zeroj.circuit.lib.jubjub;

import java.util.List;

/**
 * The application's evidence checks for admitting a threshold key generation
 * ({@code elgamal-jubjub-threshold-v1} §8; ADR-0053 D3, D4a).
 *
 * <p>The library does all the counting and binding: it derives the session, checks every
 * header, recomputes the outputs and the transcript digest, builds the exact confirmation bytes
 * and counts the confirmations. The application answers only two questions, about bytes the
 * library hands it:
 * <ul>
 *   <li><b>Authenticity.</b> Was this exact message sent by the participant whose roster key is
 *       given? For example, a signature under that key, or a transaction on a bulletin board
 *       that key controls.</li>
 *   <li><b>Round closure.</b> Is this exactly the complete set of the round's broadcast
 *       messages under the agreed broadcast mechanism, closed by its deadline? On a ledger that
 *       means finality plus completeness of the round's postings.</li>
 * </ul>
 * Returning {@code true} without such a check defeats admission. The honest-majority and
 * transport assumptions remain the application's.
 */
public interface DkgAdmissionVerifier {

    /** {@code true} iff {@code message} was sent by the participant holding {@code rosterKey}. */
    boolean authenticate(int sender, byte[] rosterKey, byte[] message, byte[] authenticator);

    /**
     * {@code true} iff {@code canonicalMessages} is exactly round {@code round}'s complete,
     * closed <b>delivered</b> set for this configuration's session. Rounds 1–6 are the
     * transcript; round 7 is the set of confirmations, so that none can be left out.
     *
     * <p>The delivered set is the board's posts made while that round was open, after dropping
     * anything malformed, for another session, of another round, a private {@code SHARE}, or
     * failing authentication, with byte-identical duplicates once, in the canonical order of
     * spec §6. An early post, made while an earlier round was open, belongs to no round.
     * Compute it from the raw board with
     * {@link DkgTranscript#deliveredRound}, so a faulty participant's junk posts cannot veto
     * admission.
     */
    boolean roundClosed(DkgConfig config, int round, List<byte[]> canonicalMessages, byte[] evidence);
}
