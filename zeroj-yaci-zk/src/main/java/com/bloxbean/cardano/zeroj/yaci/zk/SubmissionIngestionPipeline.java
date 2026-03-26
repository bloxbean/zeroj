package com.bloxbean.cardano.zeroj.yaci.zk;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.VerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;
import com.bloxbean.cardano.zeroj.yaci.protocol.AppProofSubmission;
import com.bloxbean.cardano.zeroj.yaci.protocol.Ed25519Signer;
import com.bloxbean.cardano.zeroj.yaci.protocol.SubmissionResult;
import com.bloxbean.cardano.zeroj.yaci.protocol.SubmissionResult.RejectionReason;
import com.bloxbean.cardano.zeroj.yaci.protocol.SubmissionResult.ValidationStage;

import java.util.Arrays;
import java.util.Objects;

/**
 * Orchestrates the 6-stage validation of a proof-backed state transition submission.
 *
 * <p>Stages (executed in order, fail-fast):</p>
 * <ol>
 *   <li><b>Syntactic</b> — structural field validation</li>
 *   <li><b>Signature</b> — Ed25519 signature verification + submitter authorization</li>
 *   <li><b>Circuit resolution</b> — verify circuit is known, allowed, and VK is available</li>
 *   <li><b>Cryptographic verification</b> — delegate to {@link VerifierOrchestrator}</li>
 *   <li><b>Policy</b> — state root chain, sequence, nullifier uniqueness</li>
 *   <li><b>Accept</b> — update state root, record sequence, mark nullifier</li>
 * </ol>
 *
 * <p>Each stage produces an explicit rejection reason on failure.
 * The pipeline never recomputes the computation — it only verifies.</p>
 */
public class SubmissionIngestionPipeline {

    private final VerifierOrchestrator verifier;
    private final VerificationKeyRegistry vkRegistry;
    private final SubmitterRegistry submitterRegistry;
    private final CircuitAllowlist circuitAllowlist;
    private final StateRootStore stateRootStore;
    private final SequenceTracker sequenceTracker;
    private final NullifierStore nullifierStore;
    private final AuditLog auditLog; // nullable

    public SubmissionIngestionPipeline(
            VerifierOrchestrator verifier,
            VerificationKeyRegistry vkRegistry,
            SubmitterRegistry submitterRegistry,
            CircuitAllowlist circuitAllowlist,
            StateRootStore stateRootStore,
            SequenceTracker sequenceTracker,
            NullifierStore nullifierStore) {
        this(verifier, vkRegistry, submitterRegistry, circuitAllowlist,
                stateRootStore, sequenceTracker, nullifierStore, null);
    }

    public SubmissionIngestionPipeline(
            VerifierOrchestrator verifier,
            VerificationKeyRegistry vkRegistry,
            SubmitterRegistry submitterRegistry,
            CircuitAllowlist circuitAllowlist,
            StateRootStore stateRootStore,
            SequenceTracker sequenceTracker,
            NullifierStore nullifierStore,
            AuditLog auditLog) {
        this.verifier = Objects.requireNonNull(verifier);
        this.vkRegistry = Objects.requireNonNull(vkRegistry);
        this.submitterRegistry = Objects.requireNonNull(submitterRegistry);
        this.circuitAllowlist = Objects.requireNonNull(circuitAllowlist);
        this.stateRootStore = Objects.requireNonNull(stateRootStore);
        this.sequenceTracker = Objects.requireNonNull(sequenceTracker);
        this.nullifierStore = Objects.requireNonNull(nullifierStore);
        this.auditLog = auditLog;
    }

    /**
     * Process a submission through the full 6-stage pipeline.
     */
    public SubmissionResult process(AppProofSubmission submission) {
        // Stage 1: Syntactic validation
        var syntactic = validateSyntactic(submission);
        if (syntactic != null) return audit(submission, syntactic);

        // Stage 2: Signature and authorization
        var signature = validateSignature(submission);
        if (signature != null) return audit(submission, signature);

        // Stage 3: Circuit resolution
        var circuit = validateCircuit(submission);
        if (circuit != null) return audit(submission, circuit);

        // Stage 4: Cryptographic verification
        var crypto = verifyCryptographic(submission);
        if (crypto != null) return audit(submission, crypto);

        // Stage 5: Policy validation
        var policy = validatePolicy(submission);
        if (policy != null) return audit(submission, policy);

        // Stage 6: Accept — update all state
        accept(submission);
        return audit(submission, SubmissionResult.ok());
    }

    private SubmissionResult audit(AppProofSubmission submission, SubmissionResult result) {
        if (auditLog != null) {
            auditLog.record(AuditLog.AuditEntry.from(submission, result));
        }
        return result;
    }

    // --- Stage 1: Syntactic ---

    private SubmissionResult validateSyntactic(AppProofSubmission submission) {
        if (submission.proofBytes().length == 0) {
            return SubmissionResult.rejected(ValidationStage.SYNTACTIC,
                    RejectionReason.EMPTY_PROOF, "Proof bytes are empty");
        }
        if (submission.vkHash().length != 32) {
            return SubmissionResult.rejected(ValidationStage.SYNTACTIC,
                    RejectionReason.INVALID_VK_HASH_LENGTH,
                    "VK hash must be 32 bytes, got " + submission.vkHash().length);
        }
        if (submission.publicInputs().isEmpty()) {
            return SubmissionResult.rejected(ValidationStage.SYNTACTIC,
                    RejectionReason.MALFORMED_SUBMISSION, "Public inputs must not be empty");
        }
        return null; // pass
    }

    // --- Stage 2: Signature ---

    private SubmissionResult validateSignature(AppProofSubmission submission) {
        // Look up submitter
        var pubKeyOpt = submitterRegistry.getPublicKey(submission.submitterId());
        if (pubKeyOpt.isEmpty()) {
            return SubmissionResult.rejected(ValidationStage.SIGNATURE,
                    RejectionReason.UNKNOWN_SUBMITTER,
                    "Unknown submitter: " + submission.submitterId());
        }

        // Check authorization for this app
        if (!submitterRegistry.isAuthorized(submission.submitterId(), submission.appId())) {
            return SubmissionResult.rejected(ValidationStage.SIGNATURE,
                    RejectionReason.UNAUTHORIZED_SUBMITTER,
                    "Submitter " + submission.submitterId() + " not authorized for app " + submission.appId());
        }

        // Verify Ed25519 signature
        if (!Ed25519Signer.verifySubmission(submission, pubKeyOpt.get())) {
            return SubmissionResult.rejected(ValidationStage.SIGNATURE,
                    RejectionReason.INVALID_SIGNATURE, "Ed25519 signature verification failed");
        }

        return null; // pass
    }

    // --- Stage 3: Circuit resolution ---

    private SubmissionResult validateCircuit(AppProofSubmission submission) {
        if (!circuitAllowlist.isAllowed(submission.circuitId(), submission.circuitVersion())) {
            return SubmissionResult.rejected(ValidationStage.CIRCUIT_RESOLUTION,
                    RejectionReason.RETIRED_CIRCUIT,
                    "Circuit " + submission.circuitId() + " v" + submission.circuitVersion() + " is not allowed");
        }

        // Check VK exists in registry
        var vkRef = new VerificationKeyRef.ByHash(submission.vkHash());
        var vkOpt = vkRegistry.lookup(vkRef);
        if (vkOpt.isEmpty()) {
            return SubmissionResult.rejected(ValidationStage.CIRCUIT_RESOLUTION,
                    RejectionReason.VK_NOT_FOUND,
                    "Verification key not found for hash");
        }

        return null; // pass
    }

    // --- Stage 4: Cryptographic verification ---

    private SubmissionResult verifyCryptographic(AppProofSubmission submission) {
        try {
            // Build the proof envelope from the submission
            String proofJson = new String(submission.proofBytes());
            var publicInputs = new PublicInputs(submission.publicInputs());

            var envelope = ZkProofEnvelope.builder()
                    .proofSystem(submission.proofSystem())
                    .curve(submission.curve())
                    .circuitId(new CircuitId(submission.circuitId()))
                    .proofBytes(submission.proofBytes())
                    .publicInputs(publicInputs)
                    .vkRef(new VerificationKeyRef.ByHash(submission.vkHash()))
                    .proofFormat("snarkjs-json")
                    .build();

            // Resolve VK
            var vkRef = new VerificationKeyRef.ByHash(submission.vkHash());
            var material = vkRegistry.lookup(vkRef).orElseThrow();

            // Verify
            var result = verifier.verify(envelope, material);

            if (!result.proofValid()) {
                return SubmissionResult.rejected(ValidationStage.CRYPTOGRAPHIC_VERIFICATION,
                        RejectionReason.PROOF_INVALID,
                        "Proof verification failed: " + result.message().orElse("unknown"));
            }

            return null; // pass
        } catch (Exception e) {
            return SubmissionResult.rejected(ValidationStage.CRYPTOGRAPHIC_VERIFICATION,
                    RejectionReason.PROOF_VERIFICATION_ERROR,
                    "Proof verification error: " + e.getMessage());
        }
    }

    // --- Stage 5: Policy ---

    private SubmissionResult validatePolicy(AppProofSubmission submission) {
        // Check state root chain
        byte[] currentRoot = stateRootStore.getCurrentRoot(submission.appId());
        if (currentRoot != null && !Arrays.equals(currentRoot, submission.prevStateRoot())) {
            return SubmissionResult.rejected(ValidationStage.POLICY,
                    RejectionReason.STALE_STATE_ROOT,
                    "Previous state root does not match current accepted root");
        }

        // Check sequence (must be monotonically increasing)
        long lastSeq = sequenceTracker.getLastSequence(submission.appId(), submission.submitterId());
        if (submission.sequence() <= lastSeq) {
            return SubmissionResult.rejected(ValidationStage.POLICY,
                    RejectionReason.DUPLICATE_SEQUENCE,
                    "Sequence " + submission.sequence() + " not greater than last accepted " + lastSeq);
        }

        // Check nullifier uniqueness (if present)
        byte[] nullifier = submission.nullifier();
        if (nullifier != null && nullifierStore.isUsed(nullifier)) {
            return SubmissionResult.rejected(ValidationStage.POLICY,
                    RejectionReason.USED_NULLIFIER, "Nullifier already used");
        }

        return null; // pass
    }

    // --- Stage 6: Accept ---

    private void accept(AppProofSubmission submission) {
        stateRootStore.updateRoot(submission.appId(), submission.newStateRoot());
        sequenceTracker.recordSequence(submission.appId(), submission.submitterId(), submission.sequence());

        byte[] nullifier = submission.nullifier();
        if (nullifier != null) {
            nullifierStore.markUsed(nullifier);
        }
    }
}
