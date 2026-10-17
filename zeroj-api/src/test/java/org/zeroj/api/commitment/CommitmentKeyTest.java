package org.zeroj.api.commitment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.zeroj.api.commitment.FakeProfiles.FakeCodec;
import org.zeroj.api.commitment.FakeProfiles.FakeCommitment;
import org.zeroj.api.commitment.FakeProfiles.ForeignCommitment;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.zeroj.api.commitment.FakeProfiles.FAKE;
import static org.zeroj.api.commitment.FakeProfiles.OTHER;
import static org.zeroj.api.commitment.FakeProfiles.bytes;

/** {@code commitment-profiles-v1} §12.1 {@code CommitmentKey.of}: check order and key equality. */
class CommitmentKeyTest {

    @Test
    @DisplayName("A foreign class claiming the expected profile is PROFILE_MISMATCH before any of its methods runs")
    void foreignClass() {
        ForeignCommitment foreign = new ForeignCommitment();
        assertMismatch(() -> CommitmentKey.of(foreign, new FakeCodec(FAKE, (byte) 0)));
        assertEquals(0, foreign.calls.get());
    }

    @Test
    @DisplayName("The right class with another descriptor is PROFILE_MISMATCH")
    void otherDescriptor() {
        FakeCommitment other = new FakeCommitment(OTHER, bytes(1, 2, 3, 4), (byte) 0);
        assertMismatch(() -> CommitmentKey.of(other, new FakeCodec(FAKE, (byte) 0)));
    }

    @Test
    @DisplayName("A descriptor with the same identifier string is not the descriptor: identity, never equals")
    void identityNotEquality() {
        // FAKE's id is already defined, so no second descriptor with that id can exist; a codec
        // naming OTHER rejects a FAKE commitment even though both have the same kind of point.
        FakeCommitment c = FakeProfiles.commitment(1, 2, 3, 4);
        assertMismatch(() -> CommitmentKey.of(c, new FakeCodec(OTHER, (byte) 0)));
    }

    @Test
    @DisplayName("The codec's context check runs: another context is PROFILE_MISMATCH")
    void context() {
        FakeCommitment c = new FakeCommitment(FAKE, bytes(1, 2, 3, 4), (byte) 1);
        assertMismatch(() -> CommitmentKey.of(c, new FakeCodec(FAKE, (byte) 2)));
        CommitmentKey.of(c, new FakeCodec(FAKE, (byte) 1));
    }

    @Test
    @DisplayName("Keys are equal iff identifier, point and context are equal")
    void equality() {
        CommitmentKey a = CommitmentKey.of(FakeProfiles.commitment(1, 2, 3, 4), new FakeCodec(FAKE, (byte) 0));
        CommitmentKey same = CommitmentKey.of(FakeProfiles.commitment(1, 2, 3, 4), new FakeCodec(FAKE, (byte) 0));
        CommitmentKey otherPoint = CommitmentKey.of(FakeProfiles.commitment(1, 2, 3, 5), new FakeCodec(FAKE, (byte) 0));
        CommitmentKey otherContext = CommitmentKey.of(new FakeCommitment(FAKE, bytes(1, 2, 3, 4), (byte) 9),
                new FakeCodec(FAKE, (byte) 9));
        CommitmentKey otherProfile = CommitmentKey.of(new FakeCommitment(OTHER, bytes(1, 2, 3, 4), (byte) 0),
                new FakeCodec(OTHER, (byte) 0));
        assertEquals(a, same);
        assertEquals(a.hashCode(), same.hashCode());
        assertNotEquals(a, otherPoint);
        assertNotEquals(a, otherContext);
        assertNotEquals(a, otherProfile);
        Set<CommitmentKey> set = new HashSet<>(Set.of(a, otherPoint, otherContext, otherProfile));
        set.add(same);
        assertEquals(4, set.size());
    }

    @Test
    @DisplayName("Nulls are NullPointerException; a point of the wrong length is MALFORMED_ENCODING")
    void nullsAndLength() {
        assertThrows(NullPointerException.class, () -> CommitmentKey.of(null, new FakeCodec(FAKE, (byte) 0)));
        assertThrows(NullPointerException.class, () -> CommitmentKey.of(FakeProfiles.commitment(1, 2, 3, 4), null));
        FakeCommitment shortPoint = new FakeCommitment(FAKE, bytes(1, 2, 3), (byte) 0);
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class,
                () -> CommitmentKey.of(shortPoint, new FakeCodec(FAKE, (byte) 0)));
        assertEquals(CommitmentError.MALFORMED_ENCODING, e.reason());
    }

    private static void assertMismatch(Executable op) {
        CommitmentFormatException e = assertThrows(CommitmentFormatException.class, op);
        assertEquals(CommitmentError.PROFILE_MISMATCH, e.reason());
    }
}
