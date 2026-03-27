package com.bloxbean.cardano.zeroj.submission;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ProtocolTest {

    // ==================== AppProofSubmission ====================

    @Nested
    class AppProofSubmissionTests {

        @Test
        void builder_validSubmission() {
            var sub = validBuilder().build();
            assertEquals("app1", sub.appId());
            assertEquals(ProofSystemId.GROTH16, sub.proofSystem());
            assertEquals(CurveId.BN254, sub.curve());
            assertEquals("circuit1", sub.circuitId());
            assertEquals("v1", sub.circuitVersion());
            assertEquals(1, sub.sequence());
            assertEquals("submitter1", sub.submitterId());
            assertEquals(2, sub.publicInputs().size());
        }

        @Test
        void builder_missingRequiredFieldThrows() {
            assertThrows(NullPointerException.class, () ->
                    AppProofSubmission.builder().build());
            assertThrows(NullPointerException.class, () ->
                    AppProofSubmission.builder().appId("a").build());
        }

        @Test
        void builder_emptyProofBytesThrows() {
            assertThrows(IllegalArgumentException.class, () ->
                    validBuilder().proofBytes(new byte[0]).build());
        }

        @Test
        void builder_wrongVkHashLengthThrows() {
            assertThrows(IllegalArgumentException.class, () ->
                    validBuilder().vkHash(new byte[16]).build());
        }

        @Test
        void builder_negativeSequenceThrows() {
            assertThrows(IllegalArgumentException.class, () ->
                    validBuilder().sequence(-1).build());
        }

        @Test
        void defensiveCopy_proofBytes() {
            byte[] original = {1, 2, 3};
            var sub = validBuilder().proofBytes(original).build();
            original[0] = 99;
            assertEquals(1, sub.proofBytes()[0]);
        }

        @Test
        void defensiveCopy_vkHash() {
            byte[] hash = new byte[32];
            hash[0] = 42;
            var sub = validBuilder().vkHash(hash).build();
            hash[0] = 99;
            assertEquals(42, sub.vkHash()[0]);
        }

        @Test
        void nullifierIsOptional() {
            var sub = validBuilder().build();
            assertNull(sub.nullifier());

            var subWithNullifier = validBuilder().nullifier(new byte[]{1, 2}).build();
            assertArrayEquals(new byte[]{1, 2}, subWithNullifier.nullifier());
        }

        @Test
        void metadataIsImmutable() {
            var sub = validBuilder().build();
            assertThrows(UnsupportedOperationException.class, () ->
                    sub.metadata().put("x", "y"));
        }

        private AppProofSubmission.Builder validBuilder() {
            return AppProofSubmission.builder()
                    .appId("app1")
                    .proofSystem(ProofSystemId.GROTH16)
                    .curve(CurveId.BN254)
                    .circuitId("circuit1")
                    .circuitVersion("v1")
                    .prevStateRoot(new byte[32])
                    .newStateRoot(new byte[32])
                    .publicInputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)))
                    .proofBytes(new byte[]{1, 2, 3})
                    .vkHash(new byte[32])
                    .submitterId("submitter1")
                    .submitterSignature(new byte[64])
                    .sequence(1);
        }
    }

    // ==================== Ed25519Signer ====================

    @Nested
    class Ed25519SignerTests {

        @Test
        void generateKeyPair() {
            KeyPair kp = Ed25519Signer.generateKeyPair();
            assertNotNull(kp.getPublic());
            assertNotNull(kp.getPrivate());
        }

        @Test
        void signAndVerify_roundTrip() {
            KeyPair kp = Ed25519Signer.generateKeyPair();
            byte[] message = "test message".getBytes();

            byte[] signature = Ed25519Signer.sign(message, kp.getPrivate());
            assertNotNull(signature);
            assertTrue(signature.length > 0);

            assertTrue(Ed25519Signer.verify(message, signature, kp.getPublic()));
        }

        @Test
        void verify_wrongKeyRejected() {
            KeyPair alice = Ed25519Signer.generateKeyPair();
            KeyPair bob = Ed25519Signer.generateKeyPair();

            byte[] message = "secret".getBytes();
            byte[] sig = Ed25519Signer.sign(message, alice.getPrivate());

            // Verify with wrong key should fail
            assertFalse(Ed25519Signer.verify(message, sig, bob.getPublic()));
        }

        @Test
        void verify_tamperedMessageRejected() {
            KeyPair kp = Ed25519Signer.generateKeyPair();
            byte[] sig = Ed25519Signer.sign("original".getBytes(), kp.getPrivate());

            assertFalse(Ed25519Signer.verify("tampered".getBytes(), sig, kp.getPublic()));
        }

        @Test
        void verify_tamperedSignatureRejected() {
            KeyPair kp = Ed25519Signer.generateKeyPair();
            byte[] message = "test".getBytes();
            byte[] sig = Ed25519Signer.sign(message, kp.getPrivate());

            // Flip a bit
            sig[0] ^= 0x01;
            assertFalse(Ed25519Signer.verify(message, sig, kp.getPublic()));
        }

        @Test
        void publicKeyBytes_is32Bytes() {
            KeyPair kp = Ed25519Signer.generateKeyPair();
            byte[] raw = Ed25519Signer.publicKeyBytes(kp.getPublic());
            assertEquals(32, raw.length);
        }
    }

    // ==================== SubmissionHash ====================

    @Nested
    class SubmissionHashTests {

        @Test
        void hash_isDeterministic() {
            var sub = makeSubmission(1);
            byte[] h1 = SubmissionHash.compute(sub);
            byte[] h2 = SubmissionHash.compute(sub);
            assertEquals(32, h1.length);
            assertArrayEquals(h1, h2);
        }

        @Test
        void hash_differentSequenceProducesDifferentHash() {
            byte[] h1 = SubmissionHash.compute(makeSubmission(1));
            byte[] h2 = SubmissionHash.compute(makeSubmission(2));
            assertFalse(java.util.Arrays.equals(h1, h2));
        }

        @Test
        void hash_differentAppProducesDifferentHash() {
            var sub1 = AppProofSubmission.builder()
                    .appId("app-A").proofSystem(ProofSystemId.GROTH16).curve(CurveId.BN254)
                    .circuitId("c").circuitVersion("v1")
                    .prevStateRoot(new byte[32]).newStateRoot(new byte[32])
                    .publicInputs(List.of(BigInteger.ONE))
                    .proofBytes(new byte[]{1}).vkHash(new byte[32])
                    .submitterId("s").submitterSignature(new byte[64]).sequence(1).build();
            var sub2 = AppProofSubmission.builder()
                    .appId("app-B").proofSystem(ProofSystemId.GROTH16).curve(CurveId.BN254)
                    .circuitId("c").circuitVersion("v1")
                    .prevStateRoot(new byte[32]).newStateRoot(new byte[32])
                    .publicInputs(List.of(BigInteger.ONE))
                    .proofBytes(new byte[]{1}).vkHash(new byte[32])
                    .submitterId("s").submitterSignature(new byte[64]).sequence(1).build();

            assertFalse(java.util.Arrays.equals(
                    SubmissionHash.compute(sub1), SubmissionHash.compute(sub2)));
        }

        @Test
        void hash_nullifierPresenceChangesHash() {
            var without = makeSubmission(1);
            var with = AppProofSubmission.builder()
                    .appId("app").proofSystem(ProofSystemId.GROTH16).curve(CurveId.BN254)
                    .circuitId("c").circuitVersion("v1")
                    .prevStateRoot(new byte[32]).newStateRoot(new byte[32])
                    .publicInputs(List.of(BigInteger.ONE))
                    .proofBytes(new byte[]{1}).vkHash(new byte[32])
                    .submitterId("s").submitterSignature(new byte[64]).sequence(1)
                    .nullifier(new byte[]{9, 9, 9}).build();

            assertFalse(java.util.Arrays.equals(
                    SubmissionHash.compute(without), SubmissionHash.compute(with)));
        }

        private AppProofSubmission makeSubmission(long seq) {
            return AppProofSubmission.builder()
                    .appId("app").proofSystem(ProofSystemId.GROTH16).curve(CurveId.BN254)
                    .circuitId("c").circuitVersion("v1")
                    .prevStateRoot(new byte[32]).newStateRoot(new byte[32])
                    .publicInputs(List.of(BigInteger.ONE))
                    .proofBytes(new byte[]{1}).vkHash(new byte[32])
                    .submitterId("s").submitterSignature(new byte[64]).sequence(seq).build();
        }
    }

    // ==================== SubmissionResult ====================

    @Nested
    class SubmissionResultTests {

        @Test
        void ok_isAccepted() {
            var r = SubmissionResult.ok();
            assertTrue(r.accepted());
            assertEquals(SubmissionResult.ValidationStage.ACCEPTED, r.stage());
            assertTrue(r.reason().isEmpty());
        }

        @Test
        void rejected_hasDetails() {
            var r = SubmissionResult.rejected(
                    SubmissionResult.ValidationStage.SIGNATURE,
                    SubmissionResult.RejectionReason.INVALID_SIGNATURE,
                    "bad sig");
            assertFalse(r.accepted());
            assertEquals(SubmissionResult.ValidationStage.SIGNATURE, r.stage());
            assertEquals(SubmissionResult.RejectionReason.INVALID_SIGNATURE, r.reason().orElse(null));
            assertEquals("bad sig", r.message().orElse(null));
        }
    }
}
