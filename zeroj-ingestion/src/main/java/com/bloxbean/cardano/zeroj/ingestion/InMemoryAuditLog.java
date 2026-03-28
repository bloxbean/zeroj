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

    @Override
    public List<AuditEntry> queryByAppId(String appId) {
        return entries.stream()
                .filter(e -> appId.equals(e.appId()))
                .toList();
    }

    @Override
    public List<AuditEntry> queryByEventType(String eventType) {
        return entries.stream()
                .filter(e -> eventType.equals(e.eventType()))
                .toList();
    }

    @Override
    public List<AuditEntry> queryRejections() {
        return entries.stream()
                .filter(e -> !e.accepted())
                .toList();
    }

    @Override
    public List<AuditEntry> recent(int limit) {
        int size = entries.size();
        return entries.subList(Math.max(0, size - limit), size).stream().toList();
    }

    /**
     * Get all entries (for testing/inspection).
     */
    public List<AuditEntry> all() {
        return Collections.unmodifiableList(entries);
    }
}
