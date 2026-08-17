package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl;

import com.bloxbean.cardano.vds.core.api.NodeStore;
import com.bloxbean.cardano.vds.mpf.MpfTrie;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;

import java.util.Objects;
import java.util.Optional;

/**
 * Production-facing MPF facade for the ZeroJ Poseidon profile.
 *
 * <p>The wrapped CCL trie is deliberately not exposed. In particular, CCL
 * dev1's generic {@code MpfTrie.verifyProofWire} accepts an unauthenticated
 * terminal-ForkStep exclusion form. This facade routes verification through
 * ZeroJ's fail-closed profile verifier while retaining CCL storage behavior.</p>
 */
public final class PoseidonMpfTrie {
    private final MpfTrie delegate;
    private final PoseidonParams params;

    private PoseidonMpfTrie(MpfTrie delegate, PoseidonParams params) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.params = Objects.requireNonNull(params, "params");
    }

    public static PoseidonMpfTrie inMemory() {
        return create(new InMemoryNodeStore(), null, PoseidonParamsBLS12_381T3.INSTANCE);
    }

    public static PoseidonMpfTrie inMemory(byte[] root) {
        return create(new InMemoryNodeStore(), root, PoseidonParamsBLS12_381T3.INSTANCE);
    }

    public static PoseidonMpfTrie create(NodeStore store) {
        return create(store, null, PoseidonParamsBLS12_381T3.INSTANCE);
    }

    public static PoseidonMpfTrie create(NodeStore store, byte[] root) {
        return create(store, root, PoseidonParamsBLS12_381T3.INSTANCE);
    }

    public static PoseidonMpfTrie create(NodeStore store, byte[] root, PoseidonParams params) {
        Objects.requireNonNull(store, "store");
        PoseidonMpfHash.requireBlsParams(params);
        MpfTrie trie = new MpfTrie(
                store,
                new PoseidonMpfHashFunction(params),
                canonicalRoot(root),
                new PoseidonMpfCommitmentScheme(params));
        return new PoseidonMpfTrie(trie, params);
    }

    public void setRootHash(byte[] root) {
        delegate.setRootHash(canonicalRoot(Objects.requireNonNull(root, "root")));
    }

    public byte[] getRootHash() {
        byte[] root = delegate.getRootHash();
        return root == null ? null : root.clone();
    }

    public void put(byte[] key, byte[] value) {
        delegate.put(copy(key, "key"), copy(value, "value"));
    }

    public byte[] get(byte[] key) {
        byte[] value = delegate.get(copy(key, "key"));
        return value == null ? null : value.clone();
    }

    public void delete(byte[] key) {
        delegate.delete(copy(key, "key"));
    }

    public Optional<byte[]> getProofWire(byte[] key) {
        return delegate.getProofWire(copy(key, "key")).map(byte[]::clone);
    }

    /**
     * Verifies a profile proof and rejects unsupported terminal fork
     * exclusions. Malformed proof bytes return {@code false}.
     */
    public boolean verifyProofWire(
            byte[] expectedRoot,
            byte[] key,
            byte[] value,
            boolean including,
            byte[] proofCbor) {
        return PoseidonMpfReference.verify(
                params, expectedRoot, key, value, including, proofCbor);
    }

    private static byte[] copy(byte[] value, String name) {
        return Objects.requireNonNull(value, name).clone();
    }

    private static byte[] canonicalRoot(byte[] root) {
        if (root == null) return null;
        PoseidonMpfHash.fieldFromDigestBytes(root);
        return root.clone();
    }
}
