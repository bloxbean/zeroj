package com.bloxbean.cardano.zeroj.ingestion;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryCircuitAllowlistTest {

    private InMemoryCircuitAllowlist allowlist;

    @BeforeEach
    void setUp() {
        allowlist = new InMemoryCircuitAllowlist();
    }

    @Test
    void allowAndCheck() {
        allowlist.allow("mul", "v1");
        assertTrue(allowlist.isAllowed("mul", "v1"));
    }

    @Test
    void unknownNotAllowed() {
        assertFalse(allowlist.isAllowed("mul", "v1"));
    }

    @Test
    void retireCircuit() {
        allowlist.allow("mul", "v1");
        allowlist.retire("mul", "v1");
        assertFalse(allowlist.isAllowed("mul", "v1"));
    }

    @Test
    void retireIdempotent() {
        allowlist.allow("mul", "v1");
        allowlist.retire("mul", "v1");
        allowlist.retire("mul", "v1"); // second retire is idempotent
        assertFalse(allowlist.isAllowed("mul", "v1"));
    }

    @Test
    void allowIdempotent() {
        allowlist.allow("mul", "v1");
        allowlist.allow("mul", "v1"); // double allow is fine
        assertTrue(allowlist.isAllowed("mul", "v1"));
    }

    @Test
    void independentCircuits() {
        allowlist.allow("mul", "v1");
        allowlist.allow("add", "v1");
        allowlist.retire("mul", "v1");

        assertFalse(allowlist.isAllowed("mul", "v1"));
        assertTrue(allowlist.isAllowed("add", "v1"));
    }

    @Test
    void versionIndependence() {
        allowlist.allow("mul", "v1");
        allowlist.allow("mul", "v2");
        allowlist.retire("mul", "v1");

        assertFalse(allowlist.isAllowed("mul", "v1"));
        assertTrue(allowlist.isAllowed("mul", "v2"));
    }
}
