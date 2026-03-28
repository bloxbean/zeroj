package com.bloxbean.cardano.zeroj.ingestion;

import com.bloxbean.cardano.zeroj.submission.SubmissionResult;
import com.bloxbean.cardano.zeroj.submission.SubmissionResult.RejectionReason;
import com.bloxbean.cardano.zeroj.submission.SubmissionResult.ValidationStage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryAuditLogTest {

    private InMemoryAuditLog log;

    @BeforeEach
    void setUp() {
        log = new InMemoryAuditLog();
    }

    @Test
    void recordAndCount() {
        log.record(entry("app1", "alice", "mul", true));
        assertEquals(1, log.count());
    }

    @Test
    void emptyLogCount() {
        assertEquals(0, log.count());
    }

    @Test
    void queryByTimeRange() {
        var now = Instant.now();
        log.record(entryAt(now.minus(2, ChronoUnit.HOURS), "app1", "alice", true));
        log.record(entryAt(now.minus(1, ChronoUnit.HOURS), "app1", "bob", true));
        log.record(entryAt(now, "app1", "alice", false));

        var results = log.queryByTimeRange(now.minus(90, ChronoUnit.MINUTES), now);
        assertEquals(2, results.size());
    }

    @Test
    void queryBySubmitter() {
        log.record(entry("app1", "alice", "mul", true));
        log.record(entry("app1", "bob", "mul", false));
        log.record(entry("app1", "alice", "add", true));

        assertEquals(2, log.queryBySubmitter("alice").size());
        assertEquals(1, log.queryBySubmitter("bob").size());
        assertEquals(0, log.queryBySubmitter("carol").size());
    }

    @Test
    void queryByCircuit() {
        log.record(entry("app1", "alice", "mul", true));
        log.record(entry("app1", "alice", "add", true));
        log.record(entry("app1", "bob", "mul", false));

        assertEquals(2, log.queryByCircuit("mul").size());
        assertEquals(1, log.queryByCircuit("add").size());
    }

    @Test
    void queryByAppId() {
        log.record(entry("app1", "alice", "mul", true));
        log.record(entry("app2", "alice", "mul", true));

        assertEquals(1, log.queryByAppId("app1").size());
        assertEquals(1, log.queryByAppId("app2").size());
    }

    @Test
    void queryByEventType() {
        log.record(entryWithType("app1", "alice", true, "ACCEPTED"));
        log.record(entryWithType("app1", "bob", false, "REJECTED"));
        log.record(entryWithType("app1", "carol", true, "ACCEPTED"));

        assertEquals(2, log.queryByEventType("ACCEPTED").size());
        assertEquals(1, log.queryByEventType("REJECTED").size());
    }

    @Test
    void queryRejections() {
        log.record(entry("app1", "alice", "mul", true));
        log.record(entry("app1", "bob", "mul", false));
        log.record(entry("app1", "carol", "mul", false));

        assertEquals(2, log.queryRejections().size());
    }

    @Test
    void recent() {
        for (int i = 0; i < 10; i++) {
            log.record(entry("app1", "s" + i, "mul", true));
        }

        var recent = log.recent(3);
        assertEquals(3, recent.size());
        assertEquals("s7", recent.get(0).submitterId());
        assertEquals("s9", recent.get(2).submitterId());
    }

    @Test
    void recentMoreThanAvailable() {
        log.record(entry("app1", "alice", "mul", true));
        var recent = log.recent(100);
        assertEquals(1, recent.size());
    }

    @Test
    void all() {
        log.record(entry("app1", "alice", "mul", true));
        log.record(entry("app1", "bob", "mul", false));

        var all = log.all();
        assertEquals(2, all.size());
    }

    @Test
    void auditEntryBackwardCompatibleConstructor() {
        var entry = new AuditLog.AuditEntry(
                Instant.now(), "app1", "alice", "mul", "v1", 1,
                true, ValidationStage.ACCEPTED, null, null
        );
        assertNull(entry.eventType());
        assertEquals(Map.of(), entry.context());
    }

    @Test
    void auditEntryWithContext() {
        var entry = new AuditLog.AuditEntry(
                Instant.now(), "app1", "alice", "mul", "v1", 1,
                true, ValidationStage.ACCEPTED, null, null,
                "CUSTOM_EVENT", Map.of("key", "value")
        );
        assertEquals("CUSTOM_EVENT", entry.eventType());
        assertEquals("value", entry.context().get("key"));
    }

    private AuditLog.AuditEntry entry(String appId, String submitterId, String circuitId, boolean accepted) {
        return new AuditLog.AuditEntry(
                Instant.now(), appId, submitterId, circuitId, "v1", 1,
                accepted,
                accepted ? ValidationStage.ACCEPTED : ValidationStage.CRYPTOGRAPHIC_VERIFICATION,
                accepted ? null : RejectionReason.PROOF_INVALID,
                accepted ? null : "proof failed"
        );
    }

    private AuditLog.AuditEntry entryAt(Instant ts, String appId, String submitterId, boolean accepted) {
        return new AuditLog.AuditEntry(
                ts, appId, submitterId, "mul", "v1", 1,
                accepted,
                accepted ? ValidationStage.ACCEPTED : ValidationStage.CRYPTOGRAPHIC_VERIFICATION,
                accepted ? null : RejectionReason.PROOF_INVALID,
                null
        );
    }

    private AuditLog.AuditEntry entryWithType(String appId, String submitterId, boolean accepted, String eventType) {
        return new AuditLog.AuditEntry(
                Instant.now(), appId, submitterId, "mul", "v1", 1,
                accepted,
                accepted ? ValidationStage.ACCEPTED : ValidationStage.CRYPTOGRAPHIC_VERIFICATION,
                accepted ? null : RejectionReason.PROOF_INVALID,
                null,
                eventType, Map.of()
        );
    }
}
