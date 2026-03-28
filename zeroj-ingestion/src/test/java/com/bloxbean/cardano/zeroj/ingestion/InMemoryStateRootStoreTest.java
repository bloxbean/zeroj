package com.bloxbean.cardano.zeroj.ingestion;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryStateRootStoreTest {

    private InMemoryStateRootStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryStateRootStore();
    }

    @Test
    void initialRootIsNull() {
        assertNull(store.getCurrentRoot("app1"));
    }

    @Test
    void initializeGenesisRoot() {
        byte[] genesis = {0, 0, 0, 1};
        store.initialize("app1", genesis);
        assertArrayEquals(genesis, store.getCurrentRoot("app1"));
    }

    @Test
    void initializeOnlyOnce() {
        store.initialize("app1", new byte[]{1});
        store.initialize("app1", new byte[]{2}); // should not overwrite
        assertArrayEquals(new byte[]{1}, store.getCurrentRoot("app1"));
    }

    @Test
    void updateRoot() {
        store.initialize("app1", new byte[]{1});
        store.updateRoot("app1", new byte[]{2});
        assertArrayEquals(new byte[]{2}, store.getCurrentRoot("app1"));
    }

    @Test
    void updateWithoutInitialize() {
        store.updateRoot("app1", new byte[]{5});
        assertArrayEquals(new byte[]{5}, store.getCurrentRoot("app1"));
    }

    @Test
    void perAppIndependence() {
        store.initialize("app1", new byte[]{1});
        store.initialize("app2", new byte[]{2});

        assertArrayEquals(new byte[]{1}, store.getCurrentRoot("app1"));
        assertArrayEquals(new byte[]{2}, store.getCurrentRoot("app2"));
    }

    @Test
    void defensiveCopy() {
        byte[] root = {1, 2, 3};
        store.updateRoot("app1", root);
        root[0] = 99; // mutate original
        assertArrayEquals(new byte[]{1, 2, 3}, store.getCurrentRoot("app1")); // should be unchanged
    }
}
