package com.bloxbean.cardano.zeroj.ingestion;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class VersionedVkRegistryTest {

    private VersionedVkRegistry registry;
    private VerificationMaterial material1;
    private VerificationMaterial material2;

    @BeforeEach
    void setUp() {
        registry = new VersionedVkRegistry();
        material1 = createMaterial("circuit1", new byte[]{1, 2, 3});
        material2 = createMaterial("circuit1", new byte[]{4, 5, 6});
    }

    @Test
    void registerAndLookupByHash() {
        registry.registerVersion(material1, null);

        var hash = sha256(material1.vkBytes());
        var result = registry.lookup(new VerificationKeyRef.ByHash(hash));
        assertTrue(result.isPresent());
        assertArrayEquals(material1.vkBytes(), result.get().vkBytes());
    }

    @Test
    void registerAndLookupById() {
        registry.registerVersion(material1, null);

        var result = registry.lookup(new VerificationKeyRef.ById("circuit1"));
        assertTrue(result.isPresent());
    }

    @Test
    void lookupMissing() {
        assertTrue(registry.lookup(new VerificationKeyRef.ByHash(new byte[32])).isEmpty());
        assertTrue(registry.lookup(new VerificationKeyRef.ById("missing")).isEmpty());
    }

    @Test
    void isValidNonExpired() {
        registry.registerVersion(material1, null);
        assertTrue(registry.isValid(sha256(material1.vkBytes())));
    }

    @Test
    void isValidExpired() {
        registry.registerVersion(material1, Instant.now().minus(1, ChronoUnit.HOURS));
        assertFalse(registry.isValid(sha256(material1.vkBytes())));
    }

    @Test
    void rotateExpiresOldVk() {
        registry.registerVersion(material1, null);
        registry.rotate(material2, Duration.ofHours(1));

        // Both should be in registry
        assertEquals(2, registry.listEntries("circuit1").size());

        // Current should be material2
        var current = registry.getCurrentVk("circuit1").orElseThrow();
        assertArrayEquals(material2.vkBytes(), current.vkBytes());

        // Old one should have expiry set
        var entries = registry.listEntries("circuit1");
        assertNotNull(entries.getFirst().expiresAt());
        assertNull(entries.getLast().expiresAt());
    }

    @Test
    void rotateReturnSuccess() {
        registry.registerVersion(material1, null);
        var result = registry.rotate(material2, Duration.ofHours(1));
        assertInstanceOf(VersionedVkRegistry.RotationResult.Success.class, result);
    }

    @Test
    void policyEnforcement_minTransitionWindow() {
        var policy = new VkRotationPolicy(Duration.ofHours(2), 5, Duration.ZERO);
        var reg = new VersionedVkRegistry(policy);
        reg.registerVersion(material1, null);

        // 1-hour window is less than 2-hour minimum
        var result = reg.rotate(material2, Duration.ofHours(1));
        assertInstanceOf(VersionedVkRegistry.RotationResult.Rejected.class, result);
        assertTrue(((VersionedVkRegistry.RotationResult.Rejected) result).reason()
                .contains("shorter than policy minimum"));
    }

    @Test
    void policyEnforcement_maxActiveVks() {
        var policy = new VkRotationPolicy(Duration.ZERO, 2, Duration.ZERO);
        var reg = new VersionedVkRegistry(policy);
        reg.registerVersion(material1, null);
        reg.registerVersion(material2, null);

        // Third VK would exceed max of 2
        var material3 = createMaterial("circuit1", new byte[]{7, 8, 9});
        var result = reg.rotate(material3, Duration.ofHours(1));
        assertInstanceOf(VersionedVkRegistry.RotationResult.Rejected.class, result);
        assertTrue(((VersionedVkRegistry.RotationResult.Rejected) result).reason()
                .contains("max active VKs"));
    }

    @Test
    void policyEnforcement_minTimeBetweenRotations() {
        var policy = new VkRotationPolicy(Duration.ZERO, 10, Duration.ofHours(1));
        var reg = new VersionedVkRegistry(policy);
        reg.registerVersion(material1, null);

        // Immediate rotation should be rejected
        var result = reg.rotate(material2, Duration.ofHours(1));
        assertInstanceOf(VersionedVkRegistry.RotationResult.Rejected.class, result);
        assertTrue(((VersionedVkRegistry.RotationResult.Rejected) result).reason()
                .contains("Too soon"));
    }

    @Test
    void getCurrentVkReturnsLatestNonExpired() {
        registry.registerVersion(material1, Instant.now().minus(1, ChronoUnit.HOURS)); // expired
        registry.registerVersion(material2, null); // active

        var current = registry.getCurrentVk("circuit1").orElseThrow();
        assertArrayEquals(material2.vkBytes(), current.vkBytes());
    }

    @Test
    void getCurrentVkEmptyWhenAllExpired() {
        registry.registerVersion(material1, Instant.now().minus(1, ChronoUnit.HOURS));
        assertTrue(registry.getCurrentVk("circuit1").isEmpty());
    }

    @Test
    void registerViaInterface() {
        registry.register(material1);
        assertTrue(registry.lookup(new VerificationKeyRef.ById("circuit1")).isPresent());
    }

    @Test
    void vkEntryIsExpiredAt() {
        var now = Instant.now();
        var entry = new VersionedVkRegistry.VkEntry(material1, now, now.minus(1, ChronoUnit.HOURS));
        assertTrue(entry.isExpiredAt(now));

        var entry2 = new VersionedVkRegistry.VkEntry(material1, now, null);
        assertFalse(entry2.isExpiredAt(now));
    }

    private static VerificationMaterial createMaterial(String circuitId, byte[] vkBytes) {
        return new VerificationMaterial(
                vkBytes,
                com.bloxbean.cardano.zeroj.api.ProofSystemId.GROTH16,
                com.bloxbean.cardano.zeroj.api.CurveId.BN254,
                new CircuitId(circuitId),
                Optional.of(sha256(vkBytes))
        );
    }

    private static byte[] sha256(byte[] data) {
        try { return MessageDigest.getInstance("SHA-256").digest(data); }
        catch (NoSuchAlgorithmException e) { throw new RuntimeException(e); }
    }
}
