package com.bloxbean.cardano.zeroj.ingestion;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe, append-only, in-memory implementation of {@link AuditLog}.
 */
public class InMemoryAuditLog implements AuditLog {

    private final List<AuditEntry> entries = new CopyOnWriteArrayList<>();

    @Override
    public void record(AuditEntry entry) {
        entries.add(entry);
    }

    @Override
    public List<AuditEntry> queryByTimeRange(Instant from, Instant to) {
        return entries.stream()
                .filter(e -> !e.timestamp().isBefore(from) && !e.timestamp().isAfter(to))
                .toList();
    }

    @Override
    public List<AuditEntry> queryBySubmitter(String submitterId) {
        return entries.stream()
                .filter(e -> submitterId.equals(e.submitterId()))
                .toList();
    }

    @Override
    public List<AuditEntry> queryByCircuit(String circuitId) {
        return entries.stream()
                .filter(e -> circuitId.equals(e.circuitId()))
                .toList();
    }

    @Override
    public long count() {
        return entries.size();
    }

    /**
     * Get all entries (for testing/inspection).
     */
    public List<AuditEntry> all() {
        return Collections.unmodifiableList(entries);
    }
}
