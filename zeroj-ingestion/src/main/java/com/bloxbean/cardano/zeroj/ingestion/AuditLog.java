package com.bloxbean.cardano.zeroj.ingestion;

import com.bloxbean.cardano.zeroj.submission.SubmissionResult;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable audit trail for verification decisions.
 *
 * <p>Records every submission processed through the ingestion pipeline,
 * including accepted and rejected submissions with full reason tracking.</p>
 */
public interface AuditLog {

    /**
     * Record a verification decision.
     */
    void record(AuditEntry entry);

    /**
     * Query entries by time range.
     */
    List<AuditEntry> queryByTimeRange(Instant from, Instant to);

    /**
     * Query entries by submitter.
     */
    List<AuditEntry> queryBySubmitter(String submitterId);

    /**
     * Query entries by circuit.
     */
    List<AuditEntry> queryByCircuit(String circuitId);

    /**
     * Get total count of entries.
     */
    long count();

    /**
     * Query entries by app ID.
     */
    default List<AuditEntry> queryByAppId(String appId) {
        return queryByTimeRange(Instant.MIN, Instant.MAX).stream()
                .filter(e -> appId.equals(e.appId()))
                .toList();
    }

    /**
     * Query entries by event type.
     */
    default List<AuditEntry> queryByEventType(String eventType) {
        return queryByTimeRange(Instant.MIN, Instant.MAX).stream()
                .filter(e -> eventType.equals(e.eventType()))
                .toList();
    }

    /**
     * Query rejected entries only.
     */
    default List<AuditEntry> queryRejections() {
        return queryByTimeRange(Instant.MIN, Instant.MAX).stream()
                .filter(e -> !e.accepted())
                .toList();
    }

    /**
     * Get the most recent entries, up to the given limit.
     */
    default List<AuditEntry> recent(int limit) {
        var all = queryByTimeRange(Instant.MIN, Instant.MAX);
        int size = all.size();
        return all.subList(Math.max(0, size - limit), size);
    }

    /**
     * An immutable audit log entry.
     */
    record AuditEntry(
            Instant timestamp,
            String appId,
            String submitterId,
            String circuitId,
            String circuitVersion,
            long sequence,
            boolean accepted,
            SubmissionResult.ValidationStage stage,
            SubmissionResult.RejectionReason rejectionReason,
            String message,
            String eventType,
            Map<String, String> context
    ) {
        public AuditEntry {
            Objects.requireNonNull(timestamp);
            Objects.requireNonNull(appId);
            Objects.requireNonNull(submitterId);
            Objects.requireNonNull(stage);
            if (context == null) context = Map.of();
        }

        /**
         * Backward-compatible constructor (no eventType/context).
         */
        public AuditEntry(
                Instant timestamp, String appId, String submitterId,
                String circuitId, String circuitVersion, long sequence,
                boolean accepted, SubmissionResult.ValidationStage stage,
                SubmissionResult.RejectionReason rejectionReason, String message
        ) {
            this(timestamp, appId, submitterId, circuitId, circuitVersion, sequence,
                    accepted, stage, rejectionReason, message, null, Map.of());
        }

        /**
         * Create an audit entry from a submission and its result.
         */
        public static AuditEntry from(com.bloxbean.cardano.zeroj.submission.AppProofSubmission submission,
                                       SubmissionResult result) {
            return new AuditEntry(
                    Instant.now(),
                    submission.appId(),
                    submission.submitterId(),
                    submission.circuitId(),
                    submission.circuitVersion(),
                    submission.sequence(),
                    result.accepted(),
                    result.stage(),
                    result.reason().orElse(null),
                    result.message().orElse(null),
                    result.accepted() ? "ACCEPTED" : "REJECTED",
                    Map.of()
            );
        }

        /**
         * Create an audit entry with a custom event type and context.
         */
        public static AuditEntry withContext(
                com.bloxbean.cardano.zeroj.submission.AppProofSubmission submission,
                SubmissionResult result,
                String eventType,
                Map<String, String> context
        ) {
            return new AuditEntry(
                    Instant.now(),
                    submission.appId(),
                    submission.submitterId(),
                    submission.circuitId(),
                    submission.circuitVersion(),
                    submission.sequence(),
                    result.accepted(),
                    result.stage(),
                    result.reason().orElse(null),
                    result.message().orElse(null),
                    eventType,
                    context != null ? Map.copyOf(context) : Map.of()
            );
        }
    }
}
