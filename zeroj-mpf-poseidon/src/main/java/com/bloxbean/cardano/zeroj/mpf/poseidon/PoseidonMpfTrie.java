package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.vds.core.api.NodeStore;
import com.bloxbean.cardano.vds.mpf.MpfTrie;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.util.Objects;

/**
 * Convenience factory for CCL {@link MpfTrie} instances using the ZeroJ
 * Poseidon-rooted MPF profile.
 */
public final class PoseidonMpfTrie {
    private PoseidonMpfTrie() {}

    public static MpfTrie inMemory() {
        return create(new InMemoryNodeStore(), null, PoseidonParamsBLS12_381T3.INSTANCE);
    }

    public static MpfTrie inMemory(byte[] root) {
        return create(new InMemoryNodeStore(), root, PoseidonParamsBLS12_381T3.INSTANCE);
    }

    public static MpfTrie create(NodeStore store) {
        return create(store, null, PoseidonParamsBLS12_381T3.INSTANCE);
    }

    public static MpfTrie create(NodeStore store, byte[] root) {
        return create(store, root, PoseidonParamsBLS12_381T3.INSTANCE);
    }

    public static MpfTrie create(NodeStore store, byte[] root, PoseidonParams params) {
        Objects.requireNonNull(store, "store");
        PoseidonMpfHash.requireBlsParams(params);
        return new MpfTrie(
                store,
                new PoseidonMpfHashFunction(params),
                root,
                new PoseidonMpfCommitmentScheme(params));
    }
}
