package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.vds.core.NibblePath;
import com.bloxbean.cardano.vds.mpf.commitment.CommitmentScheme;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Circuit-friendly MPF commitment scheme for the Poseidon-rooted profile.
 */
public final class PoseidonMpfCommitmentScheme implements CommitmentScheme {
    private static final int RADIX = 16;
    private static final int LEAF_NIBBLES_PER_CHUNK = 31;

    private final PoseidonParams params;
    private final PoseidonMpfHashFunction hashFunction;
    private final byte[] nullHash = new byte[PoseidonMpfHash.DIGEST_LENGTH];

    public PoseidonMpfCommitmentScheme() {
        this(PoseidonParamsBLS12_381T3.INSTANCE);
    }

    public PoseidonMpfCommitmentScheme(PoseidonParams params) {
        PoseidonMpfHash.requireBlsParams(params);
        this.params = Objects.requireNonNull(params, "params");
        this.hashFunction = new PoseidonMpfHashFunction(params);
    }

    public PoseidonParams params() {
        return params;
    }

    @Override
    public byte[] commitBranch(NibblePath prefix, byte[][] childHashes, byte[] valueHash) {
        Objects.requireNonNull(prefix, "prefix");
        Objects.requireNonNull(childHashes, "childHashes");
        if (childHashes.length != RADIX) {
            throw new IllegalArgumentException("branch must expose exactly 16 child slots");
        }
        if (valueHash != null) {
            throw new IllegalArgumentException("branch values are not supported by the Poseidon MPF profile");
        }

        byte[][] nodes = new byte[RADIX][];
        for (int i = 0; i < RADIX; i++) {
            nodes[i] = sanitize(childHashes[i]);
        }
        byte[] subRoot = binaryMerkleRoot(nodes);
        return hashFunction.digest(concat(nibbleBytes(prefix), subRoot));
    }

    @Override
    public byte[] commitLeaf(NibblePath suffix, byte[] valueHash) {
        Objects.requireNonNull(suffix, "suffix");
        BigInteger valueField = PoseidonMpfHash.fieldFromDigestBytes(valueHash);
        int[] nibbles = suffix.getNibbles();

        List<BigInteger> fields = new ArrayList<>();
        fields.add(PoseidonMpfHash.DOMAIN_LEAF);
        fields.add(BigInteger.valueOf(nibbles.length));
        for (int offset = 0; offset < nibbles.length; offset += LEAF_NIBBLES_PER_CHUNK) {
            int end = Math.min(nibbles.length, offset + LEAF_NIBBLES_PER_CHUNK);
            fields.add(packNibbleBytes(nibbles, offset, end));
        }
        while (fields.size() < 2 + PoseidonMpfHash.MAX_DIGEST_CHUNKS) {
            fields.add(BigInteger.ZERO);
        }
        fields.add(valueField);
        return PoseidonMpfHash.toDigestBytes(PoseidonHash.hashN(params, fields.toArray(BigInteger[]::new)));
    }

    @Override
    public byte[] commitExtension(NibblePath path, byte[] childHash) {
        Objects.requireNonNull(path, "path");
        return hashFunction.digest(concat(nibbleBytes(path), sanitize(childHash)));
    }

    @Override
    public byte[] nullHash() {
        return Arrays.copyOf(nullHash, nullHash.length);
    }

    @Override
    public boolean encodesBranchValueInBranchCommitment() {
        return false;
    }

    byte[] binaryMerkleRoot(byte[][] nodes) {
        if (nodes.length != RADIX) {
            throw new IllegalArgumentException("expected 16 child commitments");
        }
        byte[][] current = new byte[RADIX][];
        for (int i = 0; i < RADIX; i++) {
            current[i] = sanitize(nodes[i]);
        }
        int size = current.length;
        while (size > 1) {
            byte[][] next = new byte[size / 2][];
            for (int i = 0; i < size; i += 2) {
                next[i / 2] = hashFunction.digest(concat(current[i], current[i + 1]));
            }
            current = next;
            size = current.length;
        }
        return current[0];
    }

    private byte[] sanitize(byte[] value) {
        if (value == null || value.length == 0) {
            return nullHash();
        }
        if (value.length != PoseidonMpfHash.DIGEST_LENGTH) {
            throw new IllegalArgumentException("commitment must be 32 bytes, got " + value.length);
        }
        PoseidonMpfHash.fieldFromDigestBytes(value);
        return Arrays.copyOf(value, value.length);
    }

    private static byte[] nibbleBytes(NibblePath path) {
        int[] nibbles = path.getNibbles();
        byte[] out = new byte[nibbles.length];
        for (int i = 0; i < nibbles.length; i++) {
            int nibble = nibbles[i];
            if (nibble < 0 || nibble > 15) {
                throw new IllegalArgumentException("nibble out of range: " + nibble);
            }
            out[i] = (byte) nibble;
        }
        return out;
    }

    private static BigInteger packNibbleBytes(int[] nibbles, int start, int end) {
        byte[] bytes = new byte[end - start];
        for (int i = start; i < end; i++) {
            int nibble = nibbles[i];
            if (nibble < 0 || nibble > 15) {
                throw new IllegalArgumentException("nibble out of range: " + nibble);
            }
            bytes[i - start] = (byte) nibble;
        }
        return PoseidonMpfHash.unsigned(bytes);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
