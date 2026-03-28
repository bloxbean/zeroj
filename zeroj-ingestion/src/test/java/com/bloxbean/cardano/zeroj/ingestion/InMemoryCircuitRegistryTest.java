package com.bloxbean.cardano.zeroj.ingestion;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryCircuitRegistryTest {

    private InMemoryCircuitRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new InMemoryCircuitRegistry();
    }

    @Test
    void registerActiveCircuit() {
        var info = CircuitRegistry.CircuitVersionInfo.active("mul", "v1");
        registry.register(info);

        assertTrue(registry.isAllowed("mul", "v1"));
        var fetched = registry.getInfo("mul", "v1");
        assertTrue(fetched.isPresent());
        assertEquals(CircuitRegistry.Lifecycle.ACTIVE, fetched.get().lifecycle());
    }

    @Test
    void unknownCircuitNotAllowed() {
        assertFalse(registry.isAllowed("unknown", "v1"));
        assertTrue(registry.getInfo("unknown", "v1").isEmpty());
    }

    @Test
    void deprecateCircuit() {
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v1"));
        var deadline = Instant.now().plus(7, ChronoUnit.DAYS);

        registry.deprecate("mul", "v1", deadline, "mul", "v2");

        var info = registry.getInfo("mul", "v1").orElseThrow();
        assertEquals(CircuitRegistry.Lifecycle.DEPRECATED, info.lifecycle());
        assertNotNull(info.deprecatedAt());
        assertEquals(deadline, info.deprecationDeadline());
        assertEquals("mul", info.successorCircuitId());
        assertEquals("v2", info.successorVersion());
        // Still allowed before deadline
        assertTrue(registry.isAllowed("mul", "v1"));
    }

    @Test
    void deprecatedCircuitRejectedPastDeadline() {
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v1"));
        // Deadline in the past
        var deadline = Instant.now().minus(1, ChronoUnit.HOURS);
        registry.deprecate("mul", "v1", deadline, "mul", "v2");

        assertFalse(registry.isAllowed("mul", "v1"));
    }

    @Test
    void retireCircuit() {
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v1"));
        registry.retire("mul", "v1");

        var info = registry.getInfo("mul", "v1").orElseThrow();
        assertEquals(CircuitRegistry.Lifecycle.RETIRED, info.lifecycle());
        assertNotNull(info.retiredAt());
        assertFalse(registry.isAllowed("mul", "v1"));
    }

    @Test
    void fullLifecycle_activeToDeprecatedToRetired() {
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v1"));
        assertEquals(CircuitRegistry.Lifecycle.ACTIVE, registry.getInfo("mul", "v1").orElseThrow().lifecycle());

        registry.deprecate("mul", "v1", Instant.now().plus(1, ChronoUnit.DAYS), null, null);
        assertEquals(CircuitRegistry.Lifecycle.DEPRECATED, registry.getInfo("mul", "v1").orElseThrow().lifecycle());

        registry.retire("mul", "v1");
        assertEquals(CircuitRegistry.Lifecycle.RETIRED, registry.getInfo("mul", "v1").orElseThrow().lifecycle());
    }

    @Test
    void retireExpiredCircuits() {
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v1"));
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v2"));

        // Deprecate v1 with past deadline, v2 with future deadline
        registry.deprecate("mul", "v1", Instant.now().minus(1, ChronoUnit.HOURS), "mul", "v2");
        registry.deprecate("mul", "v2", Instant.now().plus(7, ChronoUnit.DAYS), null, null);

        int retired = registry.retireExpiredCircuits();
        assertEquals(1, retired);

        assertEquals(CircuitRegistry.Lifecycle.RETIRED, registry.getInfo("mul", "v1").orElseThrow().lifecycle());
        assertEquals(CircuitRegistry.Lifecycle.DEPRECATED, registry.getInfo("mul", "v2").orElseThrow().lifecycle());
    }

    @Test
    void retireExpiredCircuits_noExpired() {
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v1"));
        assertEquals(0, registry.retireExpiredCircuits());
    }

    @Test
    void validateMigration_validSuccessor() {
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v1"));
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v2"));
        registry.deprecate("mul", "v1", Instant.now().plus(7, ChronoUnit.DAYS), "mul", "v2");

        assertTrue(registry.validateMigration("mul", "v1"));
    }

    @Test
    void validateMigration_noSuccessor() {
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v1"));
        registry.deprecate("mul", "v1", Instant.now().plus(7, ChronoUnit.DAYS), null, null);

        assertFalse(registry.validateMigration("mul", "v1"));
    }

    @Test
    void validateMigration_successorRetired() {
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v1"));
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v2"));
        registry.deprecate("mul", "v1", Instant.now().plus(7, ChronoUnit.DAYS), "mul", "v2");
        registry.retire("mul", "v2");

        assertFalse(registry.validateMigration("mul", "v1"));
    }

    @Test
    void listVersions() {
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v1"));
        registry.register(CircuitRegistry.CircuitVersionInfo.active("mul", "v2"));
        registry.register(CircuitRegistry.CircuitVersionInfo.active("add", "v1"));

        assertEquals(2, registry.listVersions("mul").size());
        assertEquals(1, registry.listVersions("add").size());
        assertEquals(0, registry.listVersions("unknown").size());
    }

    @Test
    void allowDelegatesToRegister() {
        registry.allow("mul", "v1");
        assertTrue(registry.isAllowed("mul", "v1"));
        var info = registry.getInfo("mul", "v1");
        assertTrue(info.isPresent());
        assertEquals(CircuitRegistry.Lifecycle.ACTIVE, info.get().lifecycle());
    }

    @Test
    void deprecateNonExistentIsNoOp() {
        registry.deprecate("nonexistent", "v1", Instant.now(), null, null);
        assertTrue(registry.getInfo("nonexistent", "v1").isEmpty());
    }

    @Test
    void retireNonExistentIsNoOp() {
        registry.retire("nonexistent", "v1");
        assertTrue(registry.getInfo("nonexistent", "v1").isEmpty());
    }
}
