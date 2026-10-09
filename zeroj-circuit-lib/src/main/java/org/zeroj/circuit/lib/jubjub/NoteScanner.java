package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Opens {@code confidential-note-jubjub-v1} deliveries with one viewing key (ADR-0055 D6;
 * spec §5).
 *
 * <p>{@link #open} applies the profile's acceptance steps in order. The cheap public checks
 * (length, point decoding and subgroup membership) come before any secret work. The costliest
 * step, recomputing the commitment, runs only after the AEAD tag verifies:
 * <ol>
 *   <li>the delivery is 89 bytes;</li>
 *   <li>its ephemeral key is canonical, in the prime-order subgroup and not the identity;</li>
 *   <li>the key agreement {@code [8·sk]·E} (one blinded schedule);</li>
 *   <li>the KDF over the received {@code E} bytes;</li>
 *   <li>the AEAD tag verifies;</li>
 *   <li>the version byte is {@code 0x01} and {@code r < l};</li>
 *   <li>{@code [v]·G + [r]·H} equals the note's commitment, recomputed on the blinded
 *       secret-bearing path ({@link PedersenCommitment#commit}, two blinded schedules), never
 *       on the public {@link PedersenCommitment#verify} path (ADR-0055 I13).</li>
 * </ol>
 * Any failure of these steps is the same {@link Optional#empty()}, "not mine" (I8). A fault of
 * the platform's primitives is an {@link IllegalStateException}, never "not mine".
 *
 * <p><b>What stays the wallet's (spec §5).</b> The wallet checks that a note's owner credential
 * is its own before counting an owned note, and that the note sits at the application's script
 * address with its token. Without that check, a copied commitment and delivery placed in
 * someone else's output would look like the wallet's note. To keep scanning cheap:
 * <ul>
 *   <li>open only the delivery at this reader's position in the note (the application fixes the
 *       order: the owner first, then auditors in registry order);</li>
 *   <li>as an owner, filter by owner credential first, so only candidate notes are decrypted.</li>
 * </ul>
 *
 * <p><b>Threads and secrets.</b> A scanner is immutable and safe to use from several threads,
 * for example to scan in parallel. Its operations are compatibility/offline class (ADR-0039
 * §3.1): run it only in the user's own wallet process, never as a shared or network-facing
 * service.
 */
public final class NoteScanner {

    private final NoteViewingKey key;

    private NoteScanner(NoteViewingKey key) {
        this.key = key;
    }

    /**
     * A scanner for {@code key}. It first runs a known-answer self-test of the platform's
     * ChaCha20-Poly1305, so a faulty provider fails closed instead of turning every delivery
     * into "not mine".
     *
     * @throws IllegalStateException if the self-test fails or the key was destroyed
     */
    public static NoteScanner of(NoteViewingKey key) {
        Objects.requireNonNull(key, "key");
        if (key.isDestroyed()) {
            throw new IllegalStateException("the viewing key has been destroyed");
        }
        NoteAeadSelfTest.run();
        return new NoteScanner(key);
    }

    /**
     * Opens one delivery against the note's commitment given as the affine coordinates the note
     * carries (spec §5). Coordinates outside {@code [0, p)}, which this method never reduces, or
     * off the curve are "not mine" (step 7). This public check runs before any secret work.
     *
     * @return the opening, or empty if the delivery is not for this key or does not open
     *         {@code (u, v)}
     * @throws IllegalStateException if the platform's primitives fail, or the key was destroyed
     */
    public Optional<NoteOpening> open(byte[] delivery, BigInteger u, BigInteger v) {
        Objects.requireNonNull(delivery, "delivery");
        Objects.requireNonNull(u, "u");
        Objects.requireNonNull(v, "v");
        if (!canonical(u) || !canonical(v)) {
            return Optional.empty();
        }
        JubjubPoint commitment;
        try {
            commitment = JubjubPoint.fromAffine(u, v);
        } catch (IllegalArgumentException offCurve) {
            return Optional.empty();
        }
        return open(delivery, commitment);
    }

    private static boolean canonical(BigInteger x) {
        return x.signum() >= 0 && x.compareTo(JubjubCurve.BASE_FIELD_PRIME) < 0;
    }

    /**
     * Opens one delivery against the note's commitment (spec §5 steps 1–7), for a commitment the
     * caller already holds as a point.
     *
     * @param delivery   the delivery at this reader's position in the note
     * @param commitment the note's commitment {@code C}, as the note container records it
     * @return the opening, or empty if the delivery is not for this key or does not open
     *         {@code commitment}
     * @throws IllegalStateException if the platform's primitives fail, or the key was destroyed
     */
    public Optional<NoteOpening> open(byte[] delivery, JubjubPoint commitment) {
        Objects.requireNonNull(delivery, "delivery");
        Objects.requireNonNull(commitment, "commitment");
        if (delivery.length != ConfidentialNotes.DELIVERY_LENGTH) {
            return Optional.empty(); // step 1
        }
        byte[] ephemeralKey = Arrays.copyOfRange(delivery, 0, SaplingNoteCrypto.POINT_LENGTH);
        JubjubPoint e = SaplingNoteCrypto.decodeKey(ephemeralKey);
        if (e == null) {
            return Optional.empty(); // step 2
        }
        JubjubPoint shared = SaplingNoteCrypto.agree(key.secretScalar(), e); // step 3
        byte[] symmetricKey = SaplingNoteCrypto.kdf(SaplingNoteCrypto.PERSONALIZATION, shared, ephemeralKey); // step 4
        byte[] pt = null;
        try {
            byte[] ct = Arrays.copyOfRange(delivery, SaplingNoteCrypto.POINT_LENGTH, ConfidentialNotes.DELIVERY_LENGTH);
            pt = SaplingNoteCrypto.decrypt(symmetricKey, ct); // step 5
            if (pt == null) {
                return Optional.empty();
            }
            NoteOpening opening = ConfidentialNotes.parsePlaintext(pt); // step 6
            if (opening == null) {
                return Optional.empty();
            }
            // Step 7 on the secret-bearing path: two blinded schedules (ADR-0055 I13).
            if (!opening.commitment().projectiveEquals(commitment)) {
                return Optional.empty();
            }
            return Optional.of(opening);
        } finally {
            Arrays.fill(symmetricKey, (byte) 0);
            if (pt != null) Arrays.fill(pt, (byte) 0);
        }
    }

    /**
     * Opens every candidate and classifies the results (ADR-0055 I9).
     * <ul>
     *   <li>A candidate that opens is in {@link Scan#opened()}.</li>
     *   <li>A candidate the wallet owns ({@link Candidate#ownedByMe()}, the wallet's own
     *       owner-credential check) that does <b>not</b> open is in
     *       {@link Scan#unopenableOwned()}. It is value the wallet owns but cannot spend, and
     *       evidence of a misbehaving sender. Report it to the user; do not drop it.</li>
     * </ul>
     *
     * @throws IllegalStateException if the platform's primitives fail, or the key was destroyed
     */
    public Scan scan(List<Candidate> candidates) {
        Objects.requireNonNull(candidates, "candidates");
        List<Opened> opened = new ArrayList<>();
        List<Integer> unopenable = new ArrayList<>();
        for (int i = 0; i < candidates.size(); i++) {
            Candidate c = Objects.requireNonNull(candidates.get(i), "candidate");
            Optional<NoteOpening> result = c.commitment != null
                    ? open(c.delivery, c.commitment)
                    : open(c.delivery, c.u, c.v);
            if (result.isPresent()) {
                opened.add(new Opened(i, result.get()));
            } else if (c.ownedByMe) {
                unopenable.add(i);
            }
        }
        return new Scan(List.copyOf(opened), List.copyOf(unopenable));
    }

    /** One note to scan: this reader's delivery, the note's commitment, and whether the wallet owns it. */
    public static final class Candidate {
        private final byte[] delivery;
        private final JubjubPoint commitment; // or null, with u and v
        private final BigInteger u;
        private final BigInteger v;
        private final boolean ownedByMe;

        private Candidate(byte[] delivery, JubjubPoint commitment, BigInteger u, BigInteger v, boolean ownedByMe) {
            this.delivery = delivery;
            this.commitment = commitment;
            this.u = u;
            this.v = v;
            this.ownedByMe = ownedByMe;
        }

        /**
         * @param delivery   the delivery at this reader's position in the note
         * @param commitment the note's commitment
         * @param ownedByMe  the result of the wallet's own owner-credential check (spec §5)
         */
        public static Candidate of(byte[] delivery, JubjubPoint commitment, boolean ownedByMe) {
            Objects.requireNonNull(delivery, "delivery");
            Objects.requireNonNull(commitment, "commitment");
            return new Candidate(delivery.clone(), commitment, null, null, ownedByMe);
        }

        /**
         * As {@link #of(byte[], JubjubPoint, boolean)}, with the commitment as the affine
         * coordinates the note carries; non-canonical coordinates do not open (spec §5 step 7).
         */
        public static Candidate of(byte[] delivery, BigInteger u, BigInteger v, boolean ownedByMe) {
            Objects.requireNonNull(delivery, "delivery");
            Objects.requireNonNull(u, "u");
            Objects.requireNonNull(v, "v");
            return new Candidate(delivery.clone(), null, u, v, ownedByMe);
        }

        /** Whether the wallet owns the note, by its own check. */
        public boolean ownedByMe() {
            return ownedByMe;
        }
    }

    /** A candidate that opened: its index in the scanned list and its opening. */
    public static final class Opened {
        private final int index;
        private final NoteOpening opening;

        private Opened(int index, NoteOpening opening) {
            this.index = index;
            this.opening = opening;
        }

        /** The candidate's index in the scanned list. */
        public int index() {
            return index;
        }

        /** The opening. */
        public NoteOpening opening() {
            return opening;
        }
    }

    /** The result of {@link #scan}. */
    public static final class Scan {
        private final List<Opened> opened;
        private final List<Integer> unopenableOwned;

        private Scan(List<Opened> opened, List<Integer> unopenableOwned) {
            this.opened = opened;
            this.unopenableOwned = unopenableOwned;
        }

        /** The candidates that opened. */
        public List<Opened> opened() {
            return opened;
        }

        /** The indices of owned candidates that did not open: report these to the user. */
        public List<Integer> unopenableOwned() {
            return unopenableOwned;
        }
    }
}
