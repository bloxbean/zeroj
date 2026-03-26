package com.bloxbean.cardano.zeroj.yaci.zk;

/**
 * Tracks the last accepted sequence number per submitter per app to prevent replay.
 */
public interface SequenceTracker {

    /**
     * Get the last accepted sequence number for a submitter in an app.
     *
     * @return the last sequence, or -1 if no submission has been accepted
     */
    long getLastSequence(String appId, String submitterId);

    /**
     * Record a new accepted sequence. Returns false if the sequence was already used or is not monotonically increasing.
     */
    boolean recordSequence(String appId, String submitterId, long sequence);
}
