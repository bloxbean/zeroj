package com.bloxbean.cardano.zeroj.yaci.zk;

import com.bloxbean.cardano.zeroj.yaci.protocol.SubmissionResult;

import java.time.Instant;
import java.util.List;
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
            String message
    ) {
        public AuditEntry {
            Objects.requireNonNull(timestamp);
            Objects.requireNonNull(appId);
            Objects.requireNonNull(submitterId);
            Objects.requireNonNull(stage);
        }

        /**
         * Create an audit entry from a submission and its result.
         */
        public static AuditEntry from(com.bloxbean.cardano.zeroj.yaci.protocol.AppProofSubmission submission,
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
                    result.message().orElse(null)
            );
        }
    }
}
