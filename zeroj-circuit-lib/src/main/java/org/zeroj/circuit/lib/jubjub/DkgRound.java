package org.zeroj.circuit.lib.jubjub;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * The delivered set of one round ({@code elgamal-jubjub-threshold-v1} §4, §5): well-formed
 * messages grouped by identity {@code (kind, sender, subject)}. Byte-identical copies count once.
 * Two different messages with one identity are a conflict, and both are kept as evidence.
 */
final class DkgRound {

    private final int round;
    private final Map<Integer, List<DkgMessage>> byIdentity = new TreeMap<>();
    private final Set<ByteBuffer> seen = new HashSet<>();

    DkgRound(int round) {
        this.round = round;
    }

    int round() {
        return round;
    }

    void add(DkgMessage message) {
        if (message.round() != round) {
            throw new IllegalArgumentException("message of round " + message.round() + " delivered in round " + round);
        }
        if (!seen.add(ByteBuffer.wrap(message.bytesRef()))) {
            return; // a byte-identical copy counts once
        }
        byIdentity.computeIfAbsent(message.identity(), k -> new ArrayList<>(1)).add(message);
    }

    /** The single message with this identity, or {@code null} if it is absent or in conflict. */
    DkgMessage single(DkgMessage.Kind kind, int sender, int subject) {
        List<DkgMessage> variants = byIdentity.get((kind.code() << 16) | (sender << 8) | subject);
        return variants != null && variants.size() == 1 ? variants.get(0) : null;
    }

    /** Every distinct message with this identity: empty if absent, two or more if in conflict. */
    List<DkgMessage> variants(DkgMessage.Kind kind, int sender, int subject) {
        return byIdentity.getOrDefault((kind.code() << 16) | (sender << 8) | subject, List.of());
    }

    /** Every delivered message of a kind, conflicting variants included. */
    List<DkgMessage> all(DkgMessage.Kind kind) {
        List<DkgMessage> out = new ArrayList<>();
        for (List<DkgMessage> variants : byIdentity.values()) {
            for (DkgMessage m : variants) {
                if (m.kind() == kind) out.add(m);
            }
        }
        return out;
    }

    /** Every non-conflicting message of a kind. */
    List<DkgMessage> singles(DkgMessage.Kind kind) {
        List<DkgMessage> out = new ArrayList<>();
        for (List<DkgMessage> variants : byIdentity.values()) {
            if (variants.size() == 1 && variants.get(0).kind() == kind) out.add(variants.get(0));
        }
        return out;
    }

    /** All delivered messages in the canonical order of spec §6. */
    List<DkgMessage> canonical() {
        List<DkgMessage> out = new ArrayList<>();
        for (List<DkgMessage> variants : byIdentity.values()) out.addAll(variants);
        out.sort(Comparator.comparingInt(DkgMessage::identity)
                .thenComparing(DkgMessage::bytesRef, Arrays::compareUnsigned));
        return out;
    }
}
