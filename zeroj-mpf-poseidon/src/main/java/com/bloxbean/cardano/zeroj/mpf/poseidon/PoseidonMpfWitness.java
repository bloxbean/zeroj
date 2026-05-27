package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Flattened witness arrays consumed by annotated MPF circuits.
 */
public record PoseidonMpfWitness(
        List<BigInteger> keyPath,
        List<BigInteger> kind,
        List<BigInteger> skip,
        List<List<BigInteger>> neighbors,
        List<BigInteger> neighborNibble,
        List<BigInteger> forkPrefixLength,
        List<List<BigInteger>> forkPrefixChunks,
        List<BigInteger> forkRoot,
        List<List<BigInteger>> leafKeyPath,
        List<BigInteger> leafValueDigest,
        List<BigInteger> valid) {

    public PoseidonMpfWitness {
        keyPath = copyFlat(keyPath, "keyPath");
        kind = copyFlat(kind, "kind");
        skip = copyFlat(skip, "skip");
        neighbors = copyNested(neighbors, "neighbors");
        neighborNibble = copyFlat(neighborNibble, "neighborNibble");
        forkPrefixLength = copyFlat(forkPrefixLength, "forkPrefixLength");
        forkPrefixChunks = copyNested(forkPrefixChunks, "forkPrefixChunks");
        forkRoot = copyFlat(forkRoot, "forkRoot");
        leafKeyPath = copyNested(leafKeyPath, "leafKeyPath");
        leafValueDigest = copyFlat(leafValueDigest, "leafValueDigest");
        valid = copyFlat(valid, "valid");
    }

    public ZkInputMap putInto(ZkInputMap inputs, Names names) {
        Objects.requireNonNull(inputs, "inputs");
        Objects.requireNonNull(names, "names");
        inputs.putArray(names.keyPath(), keyPath);
        inputs.putArray(names.kind(), kind);
        inputs.putArray(names.skip(), skip);
        inputs.putNestedArray(names.neighbors(), neighbors);
        inputs.putArray(names.neighborNibble(), neighborNibble);
        inputs.putArray(names.forkPrefixLength(), forkPrefixLength);
        inputs.putNestedArray(names.forkPrefixChunks(), forkPrefixChunks);
        inputs.putArray(names.forkRoot(), forkRoot);
        inputs.putNestedArray(names.leafKeyPath(), leafKeyPath);
        inputs.putArray(names.leafValueDigest(), leafValueDigest);
        inputs.putArray(names.valid(), valid);
        return inputs;
    }

    public ZkInputMap putInto(ZkInputMap inputs) {
        return putInto(inputs, Names.defaults());
    }

    public record Names(
            String keyPath,
            String kind,
            String skip,
            String neighbors,
            String neighborNibble,
            String forkPrefixLength,
            String forkPrefixChunks,
            String forkRoot,
            String leafKeyPath,
            String leafValueDigest,
            String valid) {

        public static Names defaults() {
            return new Names(
                    "key_path",
                    "mpf_kind",
                    "mpf_skip",
                    "mpf_neighbor",
                    "mpf_neighbor_nibble",
                    "mpf_fork_prefix_length",
                    "mpf_fork_prefix",
                    "mpf_fork_root",
                    "mpf_leaf_key_path",
                    "mpf_leaf_value_digest",
                    "mpf_valid");
        }
    }

    private static List<BigInteger> copyFlat(List<BigInteger> values, String name) {
        Objects.requireNonNull(values, name);
        for (int i = 0; i < values.size(); i++) {
            Objects.requireNonNull(values.get(i), name + "[" + i + "]");
        }
        return List.copyOf(values);
    }

    private static List<List<BigInteger>> copyNested(List<List<BigInteger>> values, String name) {
        Objects.requireNonNull(values, name);
        return values.stream()
                .map(row -> copyFlat(row, name + " row"))
                .toList();
    }
}
