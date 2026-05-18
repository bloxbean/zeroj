package com.bloxbean.cardano.zeroj.mpf.poseidon;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Tag;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Converts CCL MPF wire proofs into stable symbolic witness arrays.
 */
public final class PoseidonMpfCodec {
    public static final int KIND_BRANCH = 0;
    public static final int KIND_FORK = 1;
    public static final int KIND_LEAF = 2;
    public static final int KIND_PADDING = 3;

    private static final int TAG_BRANCH = 121;
    private static final int TAG_FORK = 122;
    private static final int TAG_LEAF = 123;

    private PoseidonMpfCodec() {}

    public static PoseidonMpfWitness toWitness(byte[] key, byte[] proofCbor, int maxSteps, int maxForkPrefixChunks) {
        return toWitness(PoseidonParamsBLS12_381T3.INSTANCE, key, proofCbor, maxSteps, maxForkPrefixChunks);
    }

    public static PoseidonMpfWitness toWitness(
            PoseidonParams params,
            byte[] key,
            byte[] proofCbor,
            int maxSteps,
            int maxForkPrefixChunks) {
        PoseidonMpfHash.requireBlsParams(params);
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(proofCbor, "proofCbor");
        if (maxSteps < 0) {
            throw new IllegalArgumentException("maxSteps must be >= 0");
        }
        if (maxForkPrefixChunks < 0) {
            throw new IllegalArgumentException("maxForkPrefixChunks must be >= 0");
        }
        if (maxSteps > 0 && maxForkPrefixChunks < 2) {
            throw new IllegalArgumentException("maxForkPrefixChunks must be >= 2 when maxSteps > 0");
        }

        List<Step> steps = decode(proofCbor);
        if (steps.size() > maxSteps) {
            throw new IllegalArgumentException("proof has " + steps.size()
                    + " steps, exceeding MAX_STEPS=" + maxSteps);
        }

        byte[] keyDigest = new PoseidonMpfHashFunction(params).digest(key);
        int[] keyNibbles = PoseidonMpfHash.digestToNibbles(keyDigest);

        var kind = new ArrayList<BigInteger>(maxSteps);
        var skip = new ArrayList<BigInteger>(maxSteps);
        var neighbors = new ArrayList<List<BigInteger>>(maxSteps);
        var neighborNibble = new ArrayList<BigInteger>(maxSteps);
        var forkPrefixLength = new ArrayList<BigInteger>(maxSteps);
        var forkPrefixChunks = new ArrayList<List<BigInteger>>(maxSteps);
        var forkRoot = new ArrayList<BigInteger>(maxSteps);
        var leafKeyPath = new ArrayList<List<BigInteger>>(maxSteps);
        var leafValueDigest = new ArrayList<BigInteger>(maxSteps);
        var valid = new ArrayList<BigInteger>(maxSteps);

        for (Step step : steps) {
            kind.add(BigInteger.valueOf(step.kind()));
            skip.add(BigInteger.valueOf(step.skip()));
            neighbors.add(padFlat(step.neighbors(), 4));
            neighborNibble.add(BigInteger.valueOf(step.neighborNibble()));
            forkPrefixLength.add(BigInteger.valueOf(step.forkPrefixLength()));
            forkPrefixChunks.add(padFlat(step.forkPrefixChunks(), maxForkPrefixChunks));
            forkRoot.add(step.forkRoot());
            leafKeyPath.add(padFlat(step.leafKeyPath(), PoseidonMpfHash.KEY_PATH_NIBBLES));
            leafValueDigest.add(step.leafValueDigest());
            valid.add(BigInteger.ONE);
        }

        while (kind.size() < maxSteps) {
            kind.add(BigInteger.valueOf(KIND_PADDING));
            skip.add(BigInteger.ZERO);
            neighbors.add(padFlat(List.of(), 4));
            neighborNibble.add(BigInteger.ZERO);
            forkPrefixLength.add(BigInteger.ZERO);
            forkPrefixChunks.add(padFlat(List.of(), maxForkPrefixChunks));
            forkRoot.add(BigInteger.ZERO);
            leafKeyPath.add(padFlat(List.of(), PoseidonMpfHash.KEY_PATH_NIBBLES));
            leafValueDigest.add(BigInteger.ZERO);
            valid.add(BigInteger.ZERO);
        }

        return new PoseidonMpfWitness(
                toBigIntegers(keyNibbles),
                kind,
                skip,
                neighbors,
                neighborNibble,
                forkPrefixLength,
                forkPrefixChunks,
                forkRoot,
                leafKeyPath,
                leafValueDigest,
                valid);
    }

    public static List<Step> decode(byte[] proofCbor) {
        Objects.requireNonNull(proofCbor, "proofCbor");
        try {
            List<DataItem> items = new CborDecoder(new ByteArrayInputStream(proofCbor)).decode();
            if (items.isEmpty() || !(items.getFirst() instanceof Array root)) {
                throw new IllegalArgumentException("Invalid MPF proof CBOR encoding");
            }
            var steps = new ArrayList<Step>();
            for (DataItem item : root.getDataItems()) {
                if (!(item instanceof Array stepArray)) {
                    throw new IllegalArgumentException("Invalid MPF proof step encoding");
                }
                steps.add(decodeStep(stepArray));
            }
            return List.copyOf(steps);
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException iae) {
                throw iae;
            }
            throw new IllegalArgumentException("Failed to decode MPF proof", e);
        }
    }

    private static Step decodeStep(Array array) {
        Tag tag = array.getTag();
        long tagValue = tag == null ? TAG_BRANCH : tag.getValue();
        if (tagValue == TAG_BRANCH) {
            int skip = readUInt(array.getDataItems().get(0));
            byte[] neighborBytes = readBytes(array.getDataItems().get(1));
            if (array.getDataItems().size() > 2) {
                throw new IllegalArgumentException("branch value hashes are not supported by Poseidon MPF v1");
            }
            return Step.branch(skip, splitNeighbors(neighborBytes));
        }
        if (tagValue == TAG_FORK) {
            int skip = readUInt(array.getDataItems().get(0));
            Array neighbor = (Array) array.getDataItems().get(1);
            int nibble = readUInt(neighbor.getDataItems().get(0));
            byte[] prefix = readBytes(neighbor.getDataItems().get(1));
            byte[] root = readBytes(neighbor.getDataItems().get(2));
            return Step.fork(skip, nibble, prefix, root);
        }
        if (tagValue == TAG_LEAF) {
            int skip = readUInt(array.getDataItems().get(0));
            byte[] keyHash = readBytes(array.getDataItems().get(1));
            byte[] valueHash = readBytes(array.getDataItems().get(2));
            return Step.leaf(skip, keyHash, valueHash);
        }
        throw new IllegalArgumentException("Unknown MPF proof step tag: " + tagValue);
    }

    private static int readUInt(DataItem item) {
        if (!(item instanceof UnsignedInteger uint)) {
            throw new IllegalArgumentException("Expected unsigned integer");
        }
        return uint.getValue().intValueExact();
    }

    private static byte[] readBytes(DataItem item) {
        if (!(item instanceof ByteString bytes)) {
            throw new IllegalArgumentException("Expected byte string");
        }
        return bytes.getBytes();
    }

    private static List<BigInteger> splitNeighbors(byte[] bytes) {
        if (bytes.length != 4 * PoseidonMpfHash.DIGEST_LENGTH) {
            throw new IllegalArgumentException("branch neighbors must be 128 bytes, got " + bytes.length);
        }
        var out = new ArrayList<BigInteger>(4);
        for (int i = 0; i < 4; i++) {
            byte[] digest = Arrays.copyOfRange(bytes,
                    i * PoseidonMpfHash.DIGEST_LENGTH,
                    (i + 1) * PoseidonMpfHash.DIGEST_LENGTH);
            out.add(PoseidonMpfHash.fieldFromDigestBytes(digest));
        }
        return List.copyOf(out);
    }

    private static List<BigInteger> prefixChunksForTrailingDigest(byte[] prefix) {
        var chunks = new ArrayList<BigInteger>();
        int totalLength = prefix.length + PoseidonMpfHash.DIGEST_LENGTH;
        int remainder = totalLength % PoseidonMpfHash.DIGEST_LENGTH;
        int offset = 0;
        if (remainder != 0) {
            chunks.add(PoseidonMpfHash.unsigned(Arrays.copyOfRange(prefix, 0, Math.min(remainder, prefix.length))));
            offset = Math.min(remainder, prefix.length);
        }
        while (offset < prefix.length) {
            int end = Math.min(prefix.length, offset + PoseidonMpfHash.DIGEST_LENGTH);
            chunks.add(PoseidonMpfHash.unsigned(Arrays.copyOfRange(prefix, offset, end)));
            offset = end;
        }
        return List.copyOf(chunks);
    }

    private static List<BigInteger> padFlat(List<BigInteger> values, int size) {
        if (values.size() > size) {
            throw new IllegalArgumentException("value count " + values.size() + " exceeds fixed size " + size);
        }
        var out = new ArrayList<BigInteger>(values);
        while (out.size() < size) {
            out.add(BigInteger.ZERO);
        }
        return List.copyOf(out);
    }

    private static List<BigInteger> toBigIntegers(int[] values) {
        var out = new ArrayList<BigInteger>(values.length);
        for (int value : values) {
            out.add(BigInteger.valueOf(value));
        }
        return List.copyOf(out);
    }

    public record Step(
            int kind,
            int skip,
            List<BigInteger> neighbors,
            int neighborNibble,
            int forkPrefixLength,
            List<BigInteger> forkPrefixChunks,
            BigInteger forkRoot,
            List<BigInteger> leafKeyPath,
            BigInteger leafValueDigest) {

        static Step branch(int skip, List<BigInteger> neighbors) {
            return new Step(KIND_BRANCH, skip, neighbors, 0, 0, List.of(),
                    BigInteger.ZERO, List.of(), BigInteger.ZERO);
        }

        static Step fork(int skip, int neighborNibble, byte[] prefix, byte[] root) {
            return new Step(KIND_FORK, skip, List.of(), neighborNibble, prefix.length,
                    prefixChunksForTrailingDigest(prefix),
                    PoseidonMpfHash.fieldFromDigestBytes(root),
                    List.of(),
                    BigInteger.ZERO);
        }

        static Step leaf(int skip, byte[] keyHash, byte[] valueHash) {
            return new Step(KIND_LEAF, skip, List.of(), 0, 0, List.of(),
                    BigInteger.ZERO,
                    toBigIntegers(PoseidonMpfHash.digestToNibbles(keyHash)),
                    PoseidonMpfHash.fieldFromDigestBytes(valueHash));
        }

        public Step {
            if (skip < 0) {
                throw new IllegalArgumentException("skip must be >= 0");
            }
            if (neighborNibble < 0 || neighborNibble > 15) {
                throw new IllegalArgumentException("neighbor nibble out of range: " + neighborNibble);
            }
            neighbors = List.copyOf(Objects.requireNonNull(neighbors, "neighbors"));
            forkPrefixChunks = List.copyOf(Objects.requireNonNull(forkPrefixChunks, "forkPrefixChunks"));
            forkRoot = Objects.requireNonNull(forkRoot, "forkRoot");
            leafKeyPath = List.copyOf(Objects.requireNonNull(leafKeyPath, "leafKeyPath"));
            leafValueDigest = Objects.requireNonNull(leafValueDigest, "leafValueDigest");
        }
    }
}
