package com.bloxbean.cardano.zeroj.ingestion;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link SequenceTracker}.
 */
public class InMemorySequenceTracker implements SequenceTracker {

    // key = "appId:submitterId"
    private final Map<String, Long> sequences = new ConcurrentHashMap<>();

    @Override
    public long getLastSequence(String appId, String submitterId) {
        return sequences.getOrDefault(appId + ":" + submitterId, -1L);
    }

    @Override
    public boolean recordSequence(String appId, String submitterId, long sequence) {
        var key = appId + ":" + submitterId;
        return sequences.compute(key, (k, current) -> {
            if (current == null) current = -1L;
            if (sequence <= current) return current; // reject — not monotonically increasing
            return sequence;
        }) == sequence;
    }
}
