package com.bloxbean.cardano.zeroj.ingestion;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.InMemoryVerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierRegistry;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.Groth16BN254Verifier;
import com.bloxbean.cardano.zeroj.submission.AppProofSubmission;
import com.bloxbean.cardano.zeroj.submission.Ed25519Signer;
import com.bloxbean.cardano.zeroj.submission.SubmissionHash;
import com.bloxbean.cardano.zeroj.submission.SubmissionResult.RejectionReason;
import com.bloxbean.cardano.zeroj.submission.SubmissionResult.ValidationStage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Adversarial security and governance test suite.
 *
 * <p>Tests circuit lifecycle (deprecation/retirement with grace periods),
 * VK rotation with transition windows, audit trail completeness,
 * and edge-case attack scenarios.</p>
 */
class GovernanceAndSecurityTest {

    private static final String APP_ID = "test-app";
    private static final String CIRCUIT_ID = "multiplier";

    private KeyPair aliceKeys;
    private byte[] vkHash;
    private String proofJson;
    private byte[] genesisRoot;

    @BeforeEach
    void setUp() {
        aliceKeys = Ed25519Signer.generateKeyPair();
        proofJson = loadString("/test-vectors/groth16-bn254/proof.json");
        String vkJson = loadString("/test-vectors/groth16-bn254/verification_key.json");
        vkHash = sha256(vkJson.getBytes(StandardCharsets.UTF_8));
        genesisRoot = sha256("genesis".getBytes());
    }

    // ==================== Circuit Lifecycle ====================

    @Nested
    class CircuitLifecycleTests {

        @Test
        void activeCircuitAcceptsSubmissions() {
            var registry = new InMemoryCircuitRegistry();
            registry.register(CircuitRegistry.CircuitVersionInfo.active(CIRCUIT_ID, "v1"));

            assertTrue(registry.isAllowed(CIRCUIT_ID, "v1"));
            var info = registry.getInfo(CIRCUIT_ID, "v1").orElseThrow();
            assertEquals(CircuitRegistry.Lifecycle.ACTIVE, info.lifecycle());
        }

        @Test
        void deprecatedCircuitAcceptsDuringGracePeriod() {
            var registry = new InMemoryCircuitRegistry();
            registry.register(CircuitRegistry.CircuitVersionInfo.active(CIRCUIT_ID, "v1"));

            // Deprecate with a future deadline
            registry.deprecate(CIRCUIT_ID, "v1",
                    Instant.now().plus(Duration.ofHours(1)),
                    CIRCUIT_ID, "v2");

            // Still allowed during grace period
            assertTrue(registry.isAllowed(CIRCUIT_ID, "v1"));

            var info = registry.getInfo(CIRCUIT_ID, "v1").orElseThrow();
            assertEquals(CircuitRegistry.Lifecycle.DEPRECATED, info.lifecycle());
            assertEquals("v2", info.successorVersion());
        }

        @Test
        void deprecatedCircuitRejectsAfterDeadline() {
            var registry = new InMemoryCircuitRegistry();
            registry.register(CircuitRegistry.CircuitVersionInfo.active(CIRCUIT_ID, "v1"));

            // Deprecate with a past deadline
            registry.deprecate(CIRCUIT_ID, "v1",
                    Instant.now().minus(Duration.ofHours(1)),
                    CIRCUIT_ID, "v2");

            assertFalse(registry.isAllowed(CIRCUIT_ID, "v1"));
        }

        @Test
        void retiredCircuitAlwaysRejects() {
            var registry = new InMemoryCircuitRegistry();
            registry.register(CircuitRegistry.CircuitVersionInfo.active(CIRCUIT_ID, "v1"));
            registry.retire(CIRCUIT_ID, "v1");

            assertFalse(registry.isAllowed(CIRCUIT_ID, "v1"));
            var info = registry.getInfo(CIRCUIT_ID, "v1").orElseThrow();
            assertEquals(CircuitRegistry.Lifecycle.RETIRED, info.lifecycle());
            assertNotNull(info.retiredAt());
        }

        @Test
        void listVersionsShowsAll() {
            var registry = new InMemoryCircuitRegistry();
            registry.register(CircuitRegistry.CircuitVersionInfo.active(CIRCUIT_ID, "v1"));
            registry.register(CircuitRegistry.CircuitVersionInfo.active(CIRCUIT_ID, "v2"));
            registry.retire(CIRCUIT_ID, "v1");

            var versions = registry.listVersions(CIRCUIT_ID);
            assertEquals(2, versions.size());
        }

        @Test
        void unknownCircuitNotAllowed() {
            var registry = new InMemoryCircuitRegistry();
            assertFalse(registry.isAllowed("nonexistent", "v1"));
            assertTrue(registry.getInfo("nonexistent", "v1").isEmpty());
        }
    }

    // ==================== VK Rotation ====================

    @Nested
    class VkRotationTests {

        @Test
        void freshVkIsValid() {
            var registry = new VersionedVkRegistry();
            var mat = makeMaterial("vk-data-v1");
            registry.registerVersion(mat, null);

            byte[] hash = sha256("vk-data-v1".getBytes());
            assertTrue(registry.isValid(hash));
        }

        @Test
        void rotatedVk_bothValidDuringTransition() {
            var registry = new VersionedVkRegistry();
            var matV1 = makeMaterial("vk-v1");
            registry.registerVersion(matV1, null);

            var matV2 = makeMaterial("vk-v2");
            registry.rotate(matV2, Duration.ofHours(1));

            // Both should be valid during transition
            assertTrue(registry.isValid(sha256("vk-v1".getBytes())));
            assertTrue(registry.isValid(sha256("vk-v2".getBytes())));
        }

        @Test
        void expiredVk_notValid() {
            var registry = new VersionedVkRegistry();
            var mat = makeMaterial("vk-expired");
            // Register with an already-passed expiry
            registry.registerVersion(mat, Instant.now().minus(Duration.ofHours(1)));

            assertFalse(registry.isValid(sha256("vk-expired".getBytes())));
        }

        @Test
        void getCurrentVk_returnsLatest() {
            var registry = new VersionedVkRegistry();
            registry.registerVersion(makeMaterial("vk-v1"), null);
            registry.registerVersion(makeMaterial("vk-v2"), null);

            var current = registry.getCurrentVk(CIRCUIT_ID).orElseThrow();
            // Should return v2 (most recently registered)
            assertArrayEquals(sha256("vk-v2".getBytes()), sha256(current.vkBytes()));
        }

        @Test
        void lookupByHash_works() {
            var registry = new VersionedVkRegistry();
            var mat = makeMaterial("vk-lookup");
            registry.register(mat);

            var found = registry.lookup(new VerificationKeyRef.ByHash(sha256("vk-lookup".getBytes())));
            assertTrue(found.isPresent());
        }

        @Test
        void lookupById_returnsCurrentVersion() {
            var registry = new VersionedVkRegistry();
            registry.register(makeMaterial("vk-id-test"));

            var found = registry.lookup(new VerificationKeyRef.ById(CIRCUIT_ID));
            assertTrue(found.isPresent());
        }

        private VerificationMaterial makeMaterial(String vkData) {
            byte[] vkBytes = vkData.getBytes(StandardCharsets.UTF_8);
            return VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16, CurveId.BN254,
                    new CircuitId(CIRCUIT_ID), sha256(vkBytes));
        }
    }

    // ==================== Audit Trail ====================

    @Nested
    class AuditTrailTests {

        @Test
        void auditLogRecordsAcceptedSubmission() {
            var auditLog = new InMemoryAuditLog();
            var pipeline = buildPipelineWithAudit(auditLog);

            var sub = validSubmission(1, genesisRoot, sha256("s1".getBytes()));
            pipeline.process(sub);

            assertEquals(1, auditLog.count());
            var entry = auditLog.all().getFirst();
            assertTrue(entry.accepted());
            assertEquals(APP_ID, entry.appId());
            assertEquals("alice", entry.submitterId());
            assertEquals(CIRCUIT_ID, entry.circuitId());
            assertEquals(1, entry.sequence());
            assertEquals(ValidationStage.ACCEPTED, entry.stage());
        }

        @Test
        void auditLogRecordsRejection() {
            var auditLog = new InMemoryAuditLog();
            var pipeline = buildPipelineWithAudit(auditLog);

            // Submit with wrong state root
            var sub = validSubmission(1, sha256("wrong".getBytes()), sha256("s1".getBytes()));
            pipeline.process(sub);

            assertEquals(1, auditLog.count());
            var entry = auditLog.all().getFirst();
            assertFalse(entry.accepted());
            assertEquals(ValidationStage.POLICY, entry.stage());
            assertEquals(RejectionReason.STALE_STATE_ROOT, entry.rejectionReason());
        }

        @Test
        void auditLogRecordsAllDecisions() {
            var auditLog = new InMemoryAuditLog();
            var pipeline = buildPipelineWithAudit(auditLog);

            var root1 = sha256("s1".getBytes());
            pipeline.process(validSubmission(1, genesisRoot, root1)); // accepted
            pipeline.process(validSubmission(1, root1, sha256("s2".getBytes()))); // rejected (duplicate seq)
            pipeline.process(validSubmission(2, root1, sha256("s2".getBytes()))); // accepted

            assertEquals(3, auditLog.count());
            assertEquals(2, auditLog.queryBySubmitter("alice").stream().filter(AuditLog.AuditEntry::accepted).count());
            assertEquals(1, auditLog.queryBySubmitter("alice").stream().filter(e -> !e.accepted()).count());
        }

        @Test
        void auditLogQueryByCircuit() {
            var auditLog = new InMemoryAuditLog();
            var pipeline = buildPipelineWithAudit(auditLog);

            pipeline.process(validSubmission(1, genesisRoot, sha256("s1".getBytes())));

            var entries = auditLog.queryByCircuit(CIRCUIT_ID);
            assertEquals(1, entries.size());
            assertEquals(CIRCUIT_ID, entries.getFirst().circuitId());
        }

        @Test
        void auditLogQueryByTimeRange() {
            var auditLog = new InMemoryAuditLog();
            var pipeline = buildPipelineWithAudit(auditLog);

            var before = Instant.now();
            pipeline.process(validSubmission(1, genesisRoot, sha256("s1".getBytes())));
            var after = Instant.now();

            var entries = auditLog.queryByTimeRange(before, after);
            assertEquals(1, entries.size());

            // Query outside range should return empty
            var oldEntries = auditLog.queryByTimeRange(
                    Instant.now().minus(Duration.ofDays(1)),
                    Instant.now().minus(Duration.ofHours(1)));
            assertTrue(oldEntries.isEmpty());
        }
    }

    // ==================== Edge-case Attacks ====================

    @Nested
    class EdgeCaseAttacks {

        @Test
        void zeroSequenceAccepted() {
            var pipeline = buildPipeline();
            var sub = validSubmission(0, genesisRoot, sha256("s1".getBytes()));
            assertTrue(pipeline.process(sub).accepted());
        }

        @Test
        void maxSequenceAccepted() {
            var pipeline = buildPipeline();
            var sub = validSubmission(Long.MAX_VALUE - 1, genesisRoot, sha256("s1".getBytes()));
            assertTrue(pipeline.process(sub).accepted());
        }

        @Test
        void emptyNullifierNotStoredAsUsed() {
            // Submission with no nullifier should not consume any nullifier slot
            var pipeline = buildPipeline();
            var sub = validSubmission(1, genesisRoot, sha256("s1".getBytes()));
            assertTrue(pipeline.process(sub).accepted());
            // A subsequent submission with a real nullifier should work
            var root1 = sha256("s1".getBytes());
            var sub2 = buildSubmissionWithNullifier(2, root1, sha256("s2".getBytes()), sha256("n1".getBytes()));
            assertTrue(pipeline.process(sub2).accepted());
        }
    }

    // ==================== Helpers ====================

    private SubmissionIngestionPipeline buildPipeline() {
        return buildPipelineWithAudit(null);
    }

    private SubmissionIngestionPipeline buildPipelineWithAudit(AuditLog auditLog) {
        String vkJson = loadString("/test-vectors/groth16-bn254/verification_key.json");
        byte[] vkBytes = vkJson.getBytes(StandardCharsets.UTF_8);

        var verifierRegistry = VerifierRegistry.empty();
        verifierRegistry.register(new Groth16BN254Verifier());

        var vkRegistry = new InMemoryVerificationKeyRegistry();
        vkRegistry.register(VerificationMaterial.of(
                vkBytes, ProofSystemId.GROTH16, CurveId.BN254,
                new CircuitId(CIRCUIT_ID), vkHash));

        var orchestrator = new VerifierOrchestrator(verifierRegistry, vkRegistry);

        var submitterReg = new InMemorySubmitterRegistry();
        submitterReg.register("alice", aliceKeys.getPublic(), APP_ID);

        var circuitAllowlist = new InMemoryCircuitAllowlist();
        circuitAllowlist.allow(CIRCUIT_ID, "v1");

        var stateRootStore = new InMemoryStateRootStore();
        stateRootStore.initialize(APP_ID, genesisRoot);

        return new SubmissionIngestionPipeline(
                orchestrator, vkRegistry, submitterReg, circuitAllowlist,
                stateRootStore, new InMemorySequenceTracker(), new InMemoryNullifierStore(),
                auditLog);
    }

    private AppProofSubmission validSubmission(long sequence, byte[] prevRoot, byte[] newRoot) {
        return buildSubmissionWithNullifier(sequence, prevRoot, newRoot, null);
    }

    private AppProofSubmission buildSubmissionWithNullifier(long sequence, byte[] prevRoot, byte[] newRoot, byte[] nullifier) {
        var unsigned = AppProofSubmission.builder()
                .appId(APP_ID).proofSystem(ProofSystemId.GROTH16).curve(CurveId.BN254)
                .circuitId(CIRCUIT_ID).circuitVersion("v1")
                .prevStateRoot(prevRoot).newStateRoot(newRoot)
                .publicInputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .vkHash(vkHash).submitterId("alice")
                .submitterSignature(new byte[64]).sequence(sequence)
                .nullifier(nullifier)
                .build();

        byte[] hash = SubmissionHash.compute(unsigned);
        byte[] sig = Ed25519Signer.sign(hash, aliceKeys.getPrivate());

        return AppProofSubmission.builder()
                .appId(unsigned.appId()).proofSystem(unsigned.proofSystem()).curve(unsigned.curve())
                .circuitId(unsigned.circuitId()).circuitVersion(unsigned.circuitVersion())
                .prevStateRoot(unsigned.prevStateRoot()).newStateRoot(unsigned.newStateRoot())
                .publicInputs(unsigned.publicInputs()).proofBytes(unsigned.proofBytes())
                .vkHash(unsigned.vkHash()).submitterId(unsigned.submitterId())
                .submitterSignature(sig).sequence(unsigned.sequence())
                .nullifier(unsigned.nullifier())
                .build();
    }

    private String loadString(String path) {
        try (var in = getClass().getResourceAsStream(path)) {
            if (in == null) fail("Resource not found: " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) { return fail(e.getMessage()); }
    }

    private static byte[] sha256(byte[] data) {
        try { return MessageDigest.getInstance("SHA-256").digest(data); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
}
