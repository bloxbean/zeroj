package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl;

import com.bloxbean.cardano.vds.jmt.JellyfishMerkleTree;
import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.vds.jmt.JmtProofVerifier;
import com.bloxbean.cardano.vds.jmt.store.JmtStore;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Fail-closed production facade over a CCL pre5 Poseidon JMT. */
public final class PoseidonJmtTree {
    private final JellyfishMerkleTree delegate;
    private final PoseidonJmtHashFunction hash;
    private final PoseidonJmtCommitmentScheme commitments;

    public PoseidonJmtTree(JmtStore store) {
        this(store, PoseidonJmtCommitmentScheme.DEFAULT_PAIR_CACHE_ENTRIES);
    }

    public PoseidonJmtTree(JmtStore store, int pairCacheEntries) {
        hash = new PoseidonJmtHashFunction();
        commitments = new PoseidonJmtCommitmentScheme(pairCacheEntries);
        delegate = new JellyfishMerkleTree(Objects.requireNonNull(store, "store"),
                PoseidonJmtProfiles.v1(hash, commitments));
    }

    public PoseidonJmtCommitmentScheme.PairCacheStats pairCacheStats() {
        return commitments.pairCacheStats();
    }

    /**
     * Commits a deep snapshot of the supplied batch. Keys and values are copied before CCL sees
     * them, so mutations after this call returns cannot change committed state. Callers must not
     * concurrently mutate the map while this method is taking that snapshot.
     */
    public JellyfishMerkleTree.CommitResult put(long version, Map<byte[], byte[]> updates) {
        Objects.requireNonNull(updates, "updates");
        Map<byte[], byte[]> owned = new LinkedHashMap<>(
                Math.max(16, updates.size() * 4 / 3 + 1));
        updates.forEach((key, value) -> owned.put(
                copy(key, "updates key"), copy(value, "updates value")));
        return delegate.put(version, owned);
    }

    public Optional<byte[]> get(byte[] key) {
        return delegate.get(copy(key, "key")).map(byte[]::clone);
    }

    public Optional<byte[]> get(byte[] key, long version) {
        return delegate.get(copy(key, "key"), version).map(byte[]::clone);
    }

    public Optional<JmtProof> getProof(byte[] key, long version) {
        return delegate.getProof(copy(key, "key"), version);
    }

    public Optional<byte[]> getProofWire(byte[] key, long version) {
        return delegate.getProofWire(copy(key, "key"), version).map(byte[]::clone);
    }

    /** Encodes an already-loaded object proof without traversing the persistent tree again. */
    public byte[] encodeProof(byte[] key, JmtProof proof) {
        return PoseidonJmtProfiles.proofCodec().toWire(
                Objects.requireNonNull(proof, "proof"), copy(key, "key"), hash, commitments);
    }

    public boolean verifyProof(
            byte[] expectedRoot, byte[] key, byte[] expectedValue, JmtProof proof) {
        if (!validArguments(expectedRoot, key, proof)
                || (proof.type() == JmtProof.ProofType.INCLUSION) != (expectedValue != null)) {
            return false;
        }
        try {
            PoseidonJmtHash.decode(expectedRoot);
            boolean including = expectedValue != null;
            return PoseidonJmtReference.verify(
                    expectedRoot, key, expectedValue, including, proof)
                    && JmtProofVerifier.verify(
                    expectedRoot, key, expectedValue, proof, hash, commitments);
        } catch (RuntimeException malformed) {
            return false;
        }
    }

    public boolean verifyInclusionProof(
            byte[] expectedRoot, byte[] key, byte[] expectedValue, JmtProof proof) {
        if (proof == null || proof.type() != JmtProof.ProofType.INCLUSION) return false;
        return verifyProof(expectedRoot, key, expectedValue, proof);
    }

    public boolean verifyNonInclusionProof(
            byte[] expectedRoot, byte[] key, JmtProof proof) {
        if (proof == null || proof.type() == JmtProof.ProofType.INCLUSION) return false;
        return verifyProof(expectedRoot, key, null, proof);
    }

    public boolean verifyProofWire(
            byte[] expectedRoot,
            byte[] key,
            byte[] expectedValue,
            boolean including,
            byte[] proofWire) {
        if (expectedRoot == null || key == null || proofWire == null
                || including != (expectedValue != null)) {
            return false;
        }
        try {
            PoseidonJmtHash.decode(expectedRoot);
            return delegate.verifyProofWire(
                    expectedRoot, key, expectedValue, including, proofWire);
        } catch (RuntimeException malformed) {
            return false;
        }
    }

    private static boolean validArguments(byte[] root, byte[] key, JmtProof proof) {
        return root != null && key != null && proof != null;
    }

    private static byte[] copy(byte[] value, String name) {
        return Objects.requireNonNull(value, name).clone();
    }
}
