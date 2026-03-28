package com.bloxbean.cardano.zeroj.ingestion;

import com.bloxbean.cardano.zeroj.submission.SubmissionResult.RejectionReason;
import com.bloxbean.cardano.zeroj.submission.SubmissionResult.ValidationStage;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringWriter;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AuditExporterTest {

    @Test
    void exportSingleEntry() {
        var entry = new AuditLog.AuditEntry(
                Instant.parse("2026-01-15T10:30:00Z"), "app1", "alice", "mul", "v1", 42,
                true, ValidationStage.ACCEPTED, null, null,
                "ACCEPTED", Map.of()
        );
        var json = AuditExporter.toJson(entry);

        assertTrue(json.contains("\"timestamp\":\"2026-01-15T10:30:00Z\""));
        assertTrue(json.contains("\"appId\":\"app1\""));
        assertTrue(json.contains("\"submitterId\":\"alice\""));
        assertTrue(json.contains("\"circuitId\":\"mul\""));
        assertTrue(json.contains("\"sequence\":42"));
        assertTrue(json.contains("\"accepted\":true"));
        assertTrue(json.contains("\"stage\":\"ACCEPTED\""));
        assertTrue(json.contains("\"rejectionReason\":null"));
        assertTrue(json.contains("\"eventType\":\"ACCEPTED\""));
    }

    @Test
    void exportRejectedEntry() {
        var entry = new AuditLog.AuditEntry(
                Instant.parse("2026-01-15T10:30:00Z"), "app1", "bob", "mul", "v1", 1,
                false, ValidationStage.CRYPTOGRAPHIC_VERIFICATION,
                RejectionReason.PROOF_INVALID, "bad proof",
                "REJECTED", Map.of("detail", "pairing check failed")
        );
        var json = AuditExporter.toJson(entry);

        assertTrue(json.contains("\"accepted\":false"));
        assertTrue(json.contains("\"rejectionReason\":\"PROOF_INVALID\""));
        assertTrue(json.contains("\"message\":\"bad proof\""));
        assertTrue(json.contains("\"detail\":\"pairing check failed\""));
    }

    @Test
    void exportToString() {
        var entries = List.of(
                new AuditLog.AuditEntry(
                        Instant.parse("2026-01-15T10:00:00Z"), "app1", "alice", "mul", "v1", 1,
                        true, ValidationStage.ACCEPTED, null, null
                ),
                new AuditLog.AuditEntry(
                        Instant.parse("2026-01-15T10:01:00Z"), "app1", "bob", "add", "v1", 2,
                        false, ValidationStage.POLICY, RejectionReason.USED_NULLIFIER, "dup"
                )
        );

        var ndjson = AuditExporter.exportToString(entries);
        var lines = ndjson.strip().split("\n");
        assertEquals(2, lines.length);
        assertTrue(lines[0].contains("alice"));
        assertTrue(lines[1].contains("bob"));
    }

    @Test
    void exportToWriter() throws IOException {
        var entry = new AuditLog.AuditEntry(
                Instant.parse("2026-01-15T10:00:00Z"), "app1", "alice", "mul", "v1", 1,
                true, ValidationStage.ACCEPTED, null, null
        );
        var writer = new StringWriter();
        AuditExporter.export(List.of(entry), writer);
        assertTrue(writer.toString().endsWith("\n"));
        assertTrue(writer.toString().contains("\"appId\":\"app1\""));
    }

    @Test
    void jsonEscaping() {
        var entry = new AuditLog.AuditEntry(
                Instant.parse("2026-01-15T10:00:00Z"), "app1", "alice", "mul", "v1", 1,
                false, ValidationStage.SYNTACTIC, RejectionReason.MALFORMED_SUBMISSION,
                "bad \"field\"\nnewline",
                "ERROR", Map.of("path", "a\\b")
        );
        var json = AuditExporter.toJson(entry);

        assertTrue(json.contains("bad \\\"field\\\"\\nnewline"));
        assertTrue(json.contains("a\\\\b"));
    }

    @Test
    void emptyExport() {
        assertEquals("", AuditExporter.exportToString(List.of()));
    }

    @Test
    void roundTrip() {
        // Verify structure is valid JSON-ish (basic sanity)
        var entry = new AuditLog.AuditEntry(
                Instant.parse("2026-01-15T10:30:00Z"), "app1", "alice", "mul", "v1", 1,
                true, ValidationStage.ACCEPTED, null, null,
                "ACCEPTED", Map.of("key", "value")
        );
        var json = AuditExporter.toJson(entry);
        assertTrue(json.startsWith("{"));
        assertTrue(json.endsWith("}"));
        // Basic field presence checks
        assertTrue(json.contains("\"timestamp\""));
        assertTrue(json.contains("\"appId\""));
        assertTrue(json.contains("\"context\""));
        assertTrue(json.contains("\"eventType\""));
    }
}
