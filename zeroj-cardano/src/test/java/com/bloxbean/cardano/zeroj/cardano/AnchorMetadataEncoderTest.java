package com.bloxbean.cardano.zeroj.cardano;

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AnchorMetadataEncoderTest {

    private static final byte[] PROOF_HASH = sha256("test-proof".getBytes());
    private static final byte[] STATE_ROOT = sha256("state-root".getBytes());
    private static final byte[] VK_HASH = sha256("verification-key".getBytes());
    private static final byte[] NULLIFIER = sha256("nullifier".getBytes());

    // --- Round-trip tests for each pattern ---

    @Test
    void roundTrip_proofHashOnly() {
        var anchor = ProofAnchor.builder()
                .pattern(AnchorPattern.PROOF_HASH_ONLY)
                .proofHash(PROOF_HASH)
                .appId("test-app")
                .build();

        byte[] cbor = AnchorMetadataEncoder.encode(anchor);
        var decoded = AnchorMetadataEncoder.decode(cbor);

        assertEquals(AnchorPattern.PROOF_HASH_ONLY, decoded.pattern());
        assertArrayEquals(PROOF_HASH, decoded.proofHash());
        assertEquals("test-app", decoded.appId().orElse(null));
        assertTrue(decoded.stateRoot().isEmpty());
        assertTrue(decoded.circuitId().isEmpty());
    }

    @Test
    void roundTrip_stateRootAndProofHash() {
        var anchor = ProofAnchor.builder()
                .pattern(AnchorPattern.STATE_ROOT_AND_PROOF_HASH)
                .proofHash(PROOF_HASH)
                .stateRoot(STATE_ROOT)
                .build();

        byte[] cbor = AnchorMetadataEncoder.encode(anchor);
        var decoded = AnchorMetadataEncoder.decode(cbor);

        assertEquals(AnchorPattern.STATE_ROOT_AND_PROOF_HASH, decoded.pattern());
        assertArrayEquals(PROOF_HASH, decoded.proofHash());
        assertArrayEquals(STATE_ROOT, decoded.stateRoot().orElse(null));
    }

    @Test
    void roundTrip_fullVerificationRef() {
        var anchor = ProofAnchor.builder()
                .pattern(AnchorPattern.FULL_VERIFICATION_REF)
                .proofHash(PROOF_HASH)
                .stateRoot(STATE_ROOT)
                .circuitId("multiplier-v1")
                .vkHash(VK_HASH)
                .appId("defi-protocol")
                .build();

        byte[] cbor = AnchorMetadataEncoder.encode(anchor);
        var decoded = AnchorMetadataEncoder.decode(cbor);

        assertEquals(AnchorPattern.FULL_VERIFICATION_REF, decoded.pattern());
        assertArrayEquals(PROOF_HASH, decoded.proofHash());
        assertArrayEquals(STATE_ROOT, decoded.stateRoot().orElse(null));
        assertEquals("multiplier-v1", decoded.circuitId().orElse(null));
        assertArrayEquals(VK_HASH, decoded.vkHash().orElse(null));
        assertEquals("defi-protocol", decoded.appId().orElse(null));
    }

    @Test
    void roundTrip_nullifierCommitment() {
        var anchor = ProofAnchor.builder()
                .pattern(AnchorPattern.NULLIFIER_COMMITMENT)
                .proofHash(PROOF_HASH)
                .nullifier(NULLIFIER)
                .build();

        byte[] cbor = AnchorMetadataEncoder.encode(anchor);
        var decoded = AnchorMetadataEncoder.decode(cbor);

        assertEquals(AnchorPattern.NULLIFIER_COMMITMENT, decoded.pattern());
        assertArrayEquals(NULLIFIER, decoded.nullifier().orElse(null));
    }

    // --- Determinism ---

    @Test
    void encodingIsDeterministic() {
        var anchor = ProofAnchor.builder()
                .pattern(AnchorPattern.FULL_VERIFICATION_REF)
                .proofHash(PROOF_HASH)
                .stateRoot(STATE_ROOT)
                .circuitId("test")
                .vkHash(VK_HASH)
                .build();

        byte[] cbor1 = AnchorMetadataEncoder.encode(anchor);
        byte[] cbor2 = AnchorMetadataEncoder.encode(anchor);
        assertArrayEquals(cbor1, cbor2, "Same anchor must produce identical CBOR");
    }

    @Test
    void encodeWithLabel_producesLabeledMap() {
        var anchor = ProofAnchor.builder()
                .pattern(AnchorPattern.PROOF_HASH_ONLY)
                .proofHash(PROOF_HASH)
                .build();

        byte[] cbor = AnchorMetadataEncoder.encodeWithLabel(anchor, AnchorMetadataEncoder.DEFAULT_LABEL);
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
        // The labeled encoding should be larger than the bare encoding (wrapping map)
        byte[] bare = AnchorMetadataEncoder.encode(anchor);
        assertTrue(cbor.length > bare.length);
    }

    // --- Validation ---

    @Test
    void proofHashOnlyRequiresNoOptionalFields() {
        assertDoesNotThrow(() -> ProofAnchor.builder()
                .pattern(AnchorPattern.PROOF_HASH_ONLY)
                .proofHash(PROOF_HASH)
                .build());
    }

    @Test
    void stateRootPatternRequiresStateRoot() {
        assertThrows(IllegalArgumentException.class, () -> ProofAnchor.builder()
                .pattern(AnchorPattern.STATE_ROOT_AND_PROOF_HASH)
                .proofHash(PROOF_HASH)
                .build());
    }

    @Test
    void fullRefRequiresAllFields() {
        assertThrows(IllegalArgumentException.class, () -> ProofAnchor.builder()
                .pattern(AnchorPattern.FULL_VERIFICATION_REF)
                .proofHash(PROOF_HASH)
                .stateRoot(STATE_ROOT)
                // missing circuitId and vkHash
                .build());
    }

    @Test
    void nullifierPatternRequiresNullifier() {
        assertThrows(IllegalArgumentException.class, () -> ProofAnchor.builder()
                .pattern(AnchorPattern.NULLIFIER_COMMITMENT)
                .proofHash(PROOF_HASH)
                .build());
    }

    @Test
    void proofHashMustBe32Bytes() {
        assertThrows(IllegalArgumentException.class, () -> ProofAnchor.builder()
                .pattern(AnchorPattern.PROOF_HASH_ONLY)
                .proofHash(new byte[16])
                .build());
    }

    // --- Helper ---

    private static byte[] sha256(byte[] data) {
        try { return MessageDigest.getInstance("SHA-256").digest(data); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
}
