package com.bloxbean.cardano.zeroj.ingestion;

import com.bloxbean.cardano.zeroj.submission.Ed25519Signer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class InMemorySubmitterRegistryTest {

    private InMemorySubmitterRegistry registry;
    private KeyPair aliceKeys;
    private KeyPair bobKeys;

    @BeforeEach
    void setUp() {
        registry = new InMemorySubmitterRegistry();
        aliceKeys = Ed25519Signer.generateKeyPair();
        bobKeys = Ed25519Signer.generateKeyPair();
    }

    @Test
    void registerAndLookup() {
        registry.register("alice", aliceKeys.getPublic(), "app1", "app2");

        assertTrue(registry.getPublicKey("alice").isPresent());
        assertEquals(aliceKeys.getPublic(), registry.getPublicKey("alice").get());
    }

    @Test
    void unknownSubmitter() {
        assertTrue(registry.getPublicKey("unknown").isEmpty());
    }

    @Test
    void authorization() {
        registry.register("alice", aliceKeys.getPublic(), "app1");

        assertTrue(registry.isAuthorized("alice", "app1"));
        assertFalse(registry.isAuthorized("alice", "app2"));
        assertFalse(registry.isAuthorized("unknown", "app1"));
    }

    @Test
    void isActiveAfterRegistration() {
        registry.register("alice", aliceKeys.getPublic(), "app1");
        assertTrue(registry.isActive("alice"));
    }

    @Test
    void isActiveUnknownSubmitter() {
        assertFalse(registry.isActive("unknown"));
    }

    @Test
    void suspendSubmitter() {
        registry.register("alice", aliceKeys.getPublic(), "app1");
        registry.suspend("alice");

        assertFalse(registry.isActive("alice"));
        assertEquals(SubmitterRegistry.SubmitterStatus.SUSPENDED, registry.getStatus("alice"));
        // Key is still present
        assertTrue(registry.getPublicKey("alice").isPresent());
    }

    @Test
    void reinstateSubmitter() {
        registry.register("alice", aliceKeys.getPublic(), "app1");
        registry.suspend("alice");
        registry.reinstate("alice");

        assertTrue(registry.isActive("alice"));
        assertEquals(SubmitterRegistry.SubmitterStatus.ACTIVE, registry.getStatus("alice"));
    }

    @Test
    void revokeSubmitter() {
        registry.register("alice", aliceKeys.getPublic(), "app1");
        registry.revoke("alice");

        assertFalse(registry.isActive("alice"));
        assertEquals(SubmitterRegistry.SubmitterStatus.REVOKED, registry.getStatus("alice"));
    }

    @Test
    void reinstateDoesNotAffectRevoked() {
        registry.register("alice", aliceKeys.getPublic(), "app1");
        registry.revoke("alice");
        registry.reinstate("alice"); // should have no effect

        assertFalse(registry.isActive("alice"));
        assertEquals(SubmitterRegistry.SubmitterStatus.REVOKED, registry.getStatus("alice"));
    }

    @Test
    void suspendDoesNotAffectRevoked() {
        registry.register("alice", aliceKeys.getPublic(), "app1");
        registry.revoke("alice");
        registry.suspend("alice"); // should not downgrade from REVOKED

        assertEquals(SubmitterRegistry.SubmitterStatus.REVOKED, registry.getStatus("alice"));
    }

    @Test
    void rotateKey() {
        registry.register("alice", aliceKeys.getPublic(), "app1");
        assertTrue(registry.rotateKey("alice", bobKeys.getPublic()));

        assertEquals(bobKeys.getPublic(), registry.getPublicKey("alice").orElseThrow());
    }

    @Test
    void rotateKeyFailsWhenSuspended() {
        registry.register("alice", aliceKeys.getPublic(), "app1");
        registry.suspend("alice");
        assertFalse(registry.rotateKey("alice", bobKeys.getPublic()));
    }

    @Test
    void rotateKeyFailsWhenRevoked() {
        registry.register("alice", aliceKeys.getPublic(), "app1");
        registry.revoke("alice");
        assertFalse(registry.rotateKey("alice", bobKeys.getPublic()));
    }

    @Test
    void rotateKeyFailsForUnknown() {
        assertFalse(registry.rotateKey("unknown", aliceKeys.getPublic()));
    }

    @Test
    void multipleSubmittersIndependent() {
        registry.register("alice", aliceKeys.getPublic(), "app1");
        registry.register("bob", bobKeys.getPublic(), "app1");
        registry.suspend("alice");

        assertFalse(registry.isActive("alice"));
        assertTrue(registry.isActive("bob"));
    }
}
