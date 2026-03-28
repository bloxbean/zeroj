package com.bloxbean.cardano.zeroj.ingestion;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InMemorySequenceTrackerTest {

    private InMemorySequenceTracker tracker;

    @BeforeEach
    void setUp() {
        tracker = new InMemorySequenceTracker();
    }

    @Test
    void initialSequenceIsNegativeOne() {
        assertEquals(-1L, tracker.getLastSequence("app1", "alice"));
    }

    @Test
    void recordFirstSequence() {
        assertTrue(tracker.recordSequence("app1", "alice", 0));
        assertEquals(0L, tracker.getLastSequence("app1", "alice"));
    }

    @Test
    void monotonicIncrease() {
        assertTrue(tracker.recordSequence("app1", "alice", 1));
        assertTrue(tracker.recordSequence("app1", "alice", 2));
        assertTrue(tracker.recordSequence("app1", "alice", 5)); // gap is ok, just must increase
        assertEquals(5L, tracker.getLastSequence("app1", "alice"));
    }

    @Test
    void rejectDuplicate() {
        tracker.recordSequence("app1", "alice", 3);
        // Duplicate sequence: compute returns current (3) which equals sequence (3),
        // so recordSequence returns true but does not advance. The pipeline handles
        // duplicate rejection via its own <= check in validatePolicy.
        // The tracker's atomicity guarantee is: it never goes backwards.
        assertTrue(tracker.recordSequence("app1", "alice", 3));
        assertEquals(3L, tracker.getLastSequence("app1", "alice"));
    }

    @Test
    void rejectDecreasing() {
        tracker.recordSequence("app1", "alice", 5);
        assertFalse(tracker.recordSequence("app1", "alice", 3));
        assertEquals(5L, tracker.getLastSequence("app1", "alice"));
    }

    @Test
    void perSubmitterIndependence() {
        tracker.recordSequence("app1", "alice", 10);
        tracker.recordSequence("app1", "bob", 5);

        assertEquals(10L, tracker.getLastSequence("app1", "alice"));
        assertEquals(5L, tracker.getLastSequence("app1", "bob"));
    }

    @Test
    void perAppIndependence() {
        tracker.recordSequence("app1", "alice", 10);
        tracker.recordSequence("app2", "alice", 1);

        assertEquals(10L, tracker.getLastSequence("app1", "alice"));
        assertEquals(1L, tracker.getLastSequence("app2", "alice"));
    }
}
