package org.zeroj.circuit.lib.jubjub;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The round-0 key directory of {@code dkg-share-delivery-hpke-v1} (spec §3.2; ADR-0054 D4, I5): for
 * each participant, its unique delivered announcement's key, or none.
 *
 * <p>It is a deterministic function of the final round-0 window, so every honest participant
 * builds the same directory. Byte-identical announcements count once. Two distinct well-formed,
 * authenticated announcements from one participant are a conflict, and that participant has no
 * key.
 */
public final class DkgKeyDirectory {

    private final DkgConfig config;
    private final byte[][] keys; // index j − 1; null: no key

    private DkgKeyDirectory(DkgConfig config, byte[][] keys) {
        this.config = config;
        this.keys = keys;
    }

    /**
     * Builds the directory from the final round-0 window: the board's posts of round 0, after
     * the window's cutoff and finality (spec §5). Malformed posts, posts for another session and
     * posts that fail {@code verifier}'s authentication under the announcing participant's roster
     * key are ignored.
     */
    public static DkgKeyDirectory fromRound0(DkgConfig config, List<AuthenticatedDkgMessage> finalWindow,
                                             DkgAdmissionVerifier verifier) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(finalWindow, "finalWindow");
        Objects.requireNonNull(verifier, "verifier");
        List<Set<ByteBuffer>> distinct = new ArrayList<>();
        for (int j = 0; j < config.n(); j++) distinct.add(new HashSet<>());
        byte[][] keys = new byte[config.n()][];
        for (AuthenticatedDkgMessage post : List.copyOf(finalWindow)) {
            byte[] bytes = post.message();
            int j = DkgShareDeliveryCodec.announcedParticipant(config, bytes);
            if (j < 1 || distinct.get(j - 1).size() > 1) continue; // malformed header, or already in conflict
            if (!verifier.authenticate(j, config.rosterKey(j), bytes.clone(), post.authenticator())) continue;
            DkgShareDeliveryCodec.Announcement a = DkgShareDeliveryCodec.decodeAnnouncement(config, bytes);
            if (a == null) continue; // non-canonical or small-order key
            if (distinct.get(j - 1).add(ByteBuffer.wrap(bytes))) keys[j - 1] = a.publicKey();
        }
        for (int j = 1; j <= config.n(); j++) {
            if (distinct.get(j - 1).size() != 1) keys[j - 1] = null; // none, or a conflict
        }
        return new DkgKeyDirectory(config, keys);
    }

    /** The configuration this directory belongs to. */
    public DkgConfig config() {
        return config;
    }

    /** Participant {@code j}'s key, or empty if it has none. */
    public Optional<byte[]> key(int j) {
        config.requireParticipant(j);
        byte[] k = keys[j - 1];
        return k == null ? Optional.empty() : Optional.of(k.clone());
    }

    /** {@code true} iff participant {@code j} has a key. */
    public boolean hasKey(int j) {
        config.requireParticipant(j);
        return keys[j - 1] != null;
    }

    /**
     * Abort T1 (spec §3.3): throws if participant {@code id} has no key of its own. A participant
     * that hits T1 must not deal, complain or post anything further for the attempt.
     *
     * @throws FaultAssumptionViolatedException with reason {@code OWN_KEY_ANNOUNCEMENT_MISSING}
     */
    public void requireOwn(int id) {
        if (!hasKey(id)) {
            throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.OWN_KEY_ANNOUNCEMENT_MISSING,
                    "participant " + id + "'s own key announcement is missing or in conflict in the final round-0 window");
        }
    }

    /**
     * Abort T1 for this participant's own keys: throws unless the directory holds exactly
     * {@code keys}' public key for {@code keys.id()}.
     */
    public void requireOwn(DkgShareDeliveryKeys keys) {
        Objects.requireNonNull(keys, "keys");
        requireOwn(keys.id());
        if (!Arrays.equals(this.keys[keys.id() - 1], keys.publicKey())) {
            throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.OWN_KEY_ANNOUNCEMENT_MISSING,
                    "participant " + keys.id() + "'s directory key is not its own announced key");
        }
    }
}
