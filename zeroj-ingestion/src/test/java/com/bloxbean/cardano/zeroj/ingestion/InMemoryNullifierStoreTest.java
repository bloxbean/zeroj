package com.bloxbean.cardano.zeroj.ingestion;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryNullifierStoreTest {

    private InMemoryNullifierStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryNullifierStore();
    }

    @Test
    void markUsedAndCheck() {
        byte[] nullifier = {1, 2, 3, 4};
        assertFalse(store.isUsed(nullifier));
        assertTrue(store.markUsed(nullifier));
        assertTrue(store.isUsed(nullifier));
    }

    @Test
    void markUsedReturnsFalseOnDuplicate() {
        byte[] nullifier = {1, 2, 3, 4};
        assertTrue(store.markUsed(nullifier));
        assertFalse(store.markUsed(nullifier));
    }

    @Test
    void differentNullifersIndependent() {
        byte[] n1 = {1, 2, 3};
        byte[] n2 = {4, 5, 6};
        store.markUsed(n1);

        assertTrue(store.isUsed(n1));
        assertFalse(store.isUsed(n2));
    }

    @Test
    void appScopedMarkAndCheck() {
        byte[] nullifier = {1, 2, 3, 4};
        assertFalse(store.isUsed("app1", nullifier));
        assertTrue(store.markUsed("app1", nullifier));
        assertTrue(store.isUsed("app1", nullifier));
    }

    @Test
    void appScopedReturnsFalseOnDuplicate() {
        byte[] nullifier = {1, 2, 3, 4};
        assertTrue(store.markUsed("app1", nullifier));
        assertFalse(store.markUsed("app1", nullifier));
    }

    @Test
    void appScopedIndependence() {
        byte[] nullifier = {1, 2, 3, 4};
        store.markUsed("app1", nullifier);

        assertTrue(store.isUsed("app1", nullifier));
        assertFalse(store.isUsed("app2", nullifier));
    }

    @Test
    void appScopedSameNullifierDifferentApps() {
        byte[] nullifier = {10, 20, 30};
        assertTrue(store.markUsed("app1", nullifier));
        assertTrue(store.markUsed("app2", nullifier)); // different app scope

        assertTrue(store.isUsed("app1", nullifier));
        assertTrue(store.isUsed("app2", nullifier));
    }

    @Test
    void globalAndScopedAreIndependent() {
        byte[] nullifier = {1, 2, 3};
        store.markUsed(nullifier); // global
        assertFalse(store.isUsed("app1", nullifier)); // scoped is separate

        store.markUsed("app1", nullifier);
        assertTrue(store.isUsed("app1", nullifier));
    }
}
