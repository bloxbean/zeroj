package org.zeroj.api.commitment;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.FakeProfiles.FakeCodec;
import org.zeroj.api.commitment.FakeProfiles.FakeCommitment;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.zeroj.api.commitment.FakeProfiles.FAKE;
import static org.zeroj.api.commitment.FakeProfiles.OTHER;
import static org.zeroj.api.commitment.FakeProfiles.bytes;
import static org.zeroj.api.commitment.FakeProfiles.concat;

/** {@code commitment-profiles-v1} §12.1: the "if and only if" rule and the per-step exception mapping. */
class CommitmentAcceptanceTest {

    private static final byte[] GOOD = CommitmentEnvelope.encode(FakeProfiles.commitment(1, 2, 3, 4));
    private static final ProvenancePolicy<Object> OK = c -> ProvenancePolicy.Result.OK;
    private static final OpeningCheck<Object> TRUE = c -> true;

    @Test
    @DisplayName("Accepts only when decoding succeeds, provenance is OK and the opening matches")
    void accepts() throws IOException {
        CommitmentCheck check = accept(GOOD, OK, TRUE);
        assertTrue(check.accepted());
        assertEquals(Optional.empty(), check.reason());
        assertFalse(check.policyRejected());
    }

    @Test
    @DisplayName("Decoding failures map to their class, and neither callback runs")
    void decodeFailure() throws IOException {
        AtomicInteger calls = new AtomicInteger();
        ProvenancePolicy<Object> provenance = c -> { calls.incrementAndGet(); return ProvenancePolicy.Result.OK; };
        OpeningCheck<Object> opening = c -> { calls.incrementAndGet(); return true; };
        byte[] otherId = OTHER.id().toAsciiBytes();
        assertRejected(accept(new byte[]{2}, provenance, opening), CommitmentError.MALFORMED_ENCODING, false);
        assertRejected(accept(concat(bytes(1, otherId.length), otherId, bytes(1, 2, 3, 4)), provenance, opening),
                CommitmentError.PROFILE_MISMATCH, false);
        byte[] fakeId = FAKE.id().toAsciiBytes();
        assertRejected(accept(concat(bytes(1, fakeId.length), fakeId, bytes(0xEE, 0, 0, 0)), provenance, opening),
                CommitmentError.NOT_IN_SUBGROUP, false);
        assertEquals(0, calls.get());
    }

    @Test
    @DisplayName("MISSING and MISMATCH are policy rejections, and the opening check does not run")
    void provenance() throws IOException {
        AtomicInteger openings = new AtomicInteger();
        OpeningCheck<Object> opening = c -> { openings.incrementAndGet(); return true; };
        assertRejected(accept(GOOD, c -> ProvenancePolicy.Result.MISSING, opening), CommitmentError.PROVENANCE_MISSING, true);
        assertRejected(accept(GOOD, c -> ProvenancePolicy.Result.MISMATCH, opening), CommitmentError.PROVENANCE_MISMATCH, true);
        assertEquals(0, openings.get());
    }

    @Test
    @DisplayName("The provenance callback receives the decoded commitment of the expected profile")
    void provenanceSeesDecoded() throws IOException {
        ProvenancePolicy<FakeCommitment> provenance = c -> {
            assertSame(FAKE, c.profile());
            return ProvenancePolicy.Result.OK;
        };
        assertTrue(CommitmentAcceptance.accept(GOOD, new FakeCodec(FAKE, (byte) 0), provenance, TRUE).accepted());
    }

    @Test
    @DisplayName("A false opening is OPENING_MISMATCH; an opening format error maps to its class")
    void opening() throws IOException {
        assertRejected(accept(GOOD, OK, c -> false), CommitmentError.OPENING_MISMATCH, false);
        assertRejected(accept(GOOD, OK, c -> {
            throw new CommitmentFormatException(CommitmentError.NON_CANONICAL_SCALAR, "r");
        }), CommitmentError.NON_CANONICAL_SCALAR, false);
        assertRejected(accept(GOOD, OK, c -> {
            throw new CommitmentFormatException(CommitmentError.OUT_OF_RANGE, "v");
        }), CommitmentError.OUT_OF_RANGE, false);
    }

    @Test
    @DisplayName("Propagated unchanged: INVALID_CONFIGURATION from the opening, any provenance exception, IOException, plain IAE")
    void propagation() {
        CommitmentFormatException config = new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION, "k");
        assertSame(config, assertThrows(CommitmentFormatException.class, () -> accept(GOOD, OK, c -> { throw config; })));
        CommitmentFormatException fromProvenance = new CommitmentFormatException(CommitmentError.MALFORMED_ENCODING, "p");
        assertSame(fromProvenance, assertThrows(CommitmentFormatException.class,
                () -> accept(GOOD, c -> { throw fromProvenance; }, TRUE)));
        IllegalStateException state = new IllegalStateException("s");
        assertSame(state, assertThrows(IllegalStateException.class, () -> accept(GOOD, c -> { throw state; }, TRUE)));
        IOException io = new IOException("io");
        assertSame(io, assertThrows(IOException.class, () -> accept(GOOD, OK, c -> { throw io; })));
        IllegalArgumentException plain = new IllegalArgumentException("plain");
        assertSame(plain, assertThrows(IllegalArgumentException.class, () -> accept(GOOD, OK, c -> { throw plain; })));
        UncheckedIOException unchecked = new UncheckedIOException(io);
        assertSame(unchecked, assertThrows(UncheckedIOException.class, () -> accept(GOOD, OK, c -> { throw unchecked; })));
    }

    @Test
    @DisplayName("Null arguments and a null provenance result are NullPointerException, never acceptance")
    void nulls() {
        FakeCodec codec = new FakeCodec(FAKE, (byte) 0);
        assertThrows(NullPointerException.class, () -> CommitmentAcceptance.accept(null, codec, OK, TRUE));
        assertThrows(NullPointerException.class, () -> CommitmentAcceptance.accept(GOOD, null, OK, TRUE));
        assertThrows(NullPointerException.class, () -> CommitmentAcceptance.accept(GOOD, codec, null, TRUE));
        assertThrows(NullPointerException.class, () -> CommitmentAcceptance.accept(GOOD, codec, OK, null));
        assertThrows(NullPointerException.class, () -> accept(GOOD, c -> null, TRUE));
    }

    @Test
    @DisplayName("policyRejected is true exactly for the PROVENANCE_* classes")
    void policyRejectedFlag() {
        for (CommitmentError e : CommitmentError.values()) {
            CommitmentCheck check = CommitmentCheck.rejected(e);
            assertFalse(check.accepted());
            assertEquals(Optional.of(e), check.reason());
            assertEquals(e == CommitmentError.PROVENANCE_MISSING || e == CommitmentError.PROVENANCE_MISMATCH,
                    check.policyRejected());
        }
    }

    private static CommitmentCheck accept(byte[] envelope, ProvenancePolicy<Object> provenance, OpeningCheck<Object> opening)
            throws IOException {
        return CommitmentAcceptance.accept(envelope, new FakeCodec(FAKE, (byte) 0), provenance, opening);
    }

    private static void assertRejected(CommitmentCheck check, CommitmentError reason, boolean policy) {
        assertFalse(check.accepted());
        assertEquals(Optional.of(reason), check.reason());
        assertEquals(policy, check.policyRejected());
    }
}
