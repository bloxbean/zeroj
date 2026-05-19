package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Objects;

/**
 * Symbolic Poseidon-rooted Merkle Patricia Forestry helpers.
 *
 * <p>This gadget mirrors the ZeroJ Poseidon MPF profile. It is intentionally
 * not compatible with native Cardano/Aiken Blake2b MPF roots.
 */
public final class ZkMpf {
    public static final int KEY_PATH_NIBBLES = 64;
    public static final int KIND_BRANCH = 0;
    public static final int KIND_FORK = 1;
    public static final int KIND_LEAF = 2;
    public static final int KIND_PADDING = 3;

    public static final BigInteger DOMAIN_BYTES = BigInteger.valueOf(0x5a4d5046L);
    public static final BigInteger DOMAIN_LEAF = BigInteger.valueOf(0x5a4d5047L);
    public static final BigInteger DOMAIN_KEY_PATH = BigInteger.valueOf(0x5a4d5048L);
    public static final BigInteger DOMAIN_KEY_NULLIFIER = BigInteger.valueOf(0x5a4d5049L);

    private static final int CURSOR_BITS = 8;
    private static final int MAX_PREFIX_NIBBLES = KEY_PATH_NIBBLES;
    private static final int LEAF_CHUNK_BYTES = 31;
    private static final int BYTE_DIGEST_CHUNK_BYTES = 32;

    private ZkMpf() {}

    public static ZkBool isIncludedPoseidon(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField valueCommitment,
            ZkField expectedRoot,
            ZkMpfProof proof) {
        requireRoot(zk, expectedRoot);
        ZkField root = computeRoot(zk, params, keyPath, valueCommitment, proof, true);
        return root.isEqual(expectedRoot);
    }

    public static void verifyInclusionPoseidon(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField valueCommitment,
            ZkField expectedRoot,
            ZkMpfProof proof) {
        isIncludedPoseidon(zk, params, keyPath, valueCommitment, expectedRoot, proof).assertTrue();
    }

    public static ZkBool isExcludedPoseidon(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField expectedRoot,
            ZkMpfProof proof) {
        requireRoot(zk, expectedRoot);
        ZkField root = computeRoot(zk, params, keyPath, zk.constant(0), proof, false);
        return root.isEqual(expectedRoot);
    }

    public static void verifyExclusionPoseidon(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField expectedRoot,
            ZkMpfProof proof) {
        isExcludedPoseidon(zk, params, keyPath, expectedRoot, proof).assertTrue();
    }

    public static ZkField keyPathCommitment(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath) {
        return hashKeyPath(zk, params, keyPath, DOMAIN_KEY_PATH);
    }

    public static ZkField keyPathNullifier(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath) {
        return hashKeyPath(zk, params, keyPath, DOMAIN_KEY_NULLIFIER);
    }

    private static ZkField computeRoot(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField valueCommitment,
            ZkMpfProof proof,
            boolean inclusion) {
        validateInputs(zk, params, keyPath, valueCommitment, proof);

        PathSignals keyPathSignals = PathSignals.of(keyPath);
        int maxSteps = proof.maxSteps();
        ZkUInt[] cursorBefore = new ZkUInt[maxSteps];
        ZkUInt[] nextCursor = new ZkUInt[maxSteps];
        ZkUInt cursor = uintConst(zk, 0, CURSOR_BITS);

        for (int i = 0; i < maxSteps; i++) {
            ZkBool valid = proof.valid().get(i);
            ZkBool isPadding = eqConst(zk, proof.kind().get(i), KIND_PADDING);
            valid.assertEqual(isPadding.not());
            if (i + 1 < maxSteps) {
                valid.not().and(proof.valid().get(i + 1)).assertFalse();
            }

            cursorBefore[i] = cursor;
            ZkUInt advanced = uintWrap(
                    zk,
                    cursor.signal().add(proof.skip().get(i).signal()).add(1),
                    CURSOR_BITS);
            valid.and(lteConst(zk, advanced, KEY_PATH_NIBBLES).not()).assertFalse();
            valid.and(lteConst(zk, proof.forkPrefixLength().get(i), MAX_PREFIX_NIBBLES).not()).assertFalse();
            nextCursor[i] = advanced;
            cursor = valid.select(advanced, cursor);
        }

        ZkField current = inclusion
                ? commitLeafFromPath(zk, params, keyPathSignals, cursor, valueCommitment)
                : zk.constant(0);

        for (int i = maxSteps - 1; i >= 0; i--) {
            ZkBool valid = proof.valid().get(i);
            ZkUInt stepCursor = cursorBefore[i];
            ZkUInt stepNextCursor = nextCursor[i];
            ZkUInt skip = proof.skip().get(i);
            ZkUInt queryIndex = uintWrap(zk, stepNextCursor.signal().add(-1), CURSOR_BITS);
            ZkUInt queryNibble = keyPathSignals.at(zk, queryIndex.signal());

            ZkBool branchKind = eqConst(zk, proof.kind().get(i), KIND_BRANCH);
            ZkBool forkKind = eqConst(zk, proof.kind().get(i), KIND_FORK);
            ZkBool leafKind = eqConst(zk, proof.kind().get(i), KIND_LEAF);
            ZkBool lastValid = i + 1 == maxSteps
                    ? valid
                    : valid.and(proof.valid().get(i + 1).not());

            ZkField branch = branchStep(
                    zk,
                    params,
                    keyPathSignals,
                    stepCursor,
                    skip,
                    queryNibble,
                    current,
                    proof.neighbors().get(i));

            ZkField forkCommitment = prefixedDigestFromWitness(
                    zk,
                    params,
                    proof.forkPrefixLength().get(i),
                    proof.forkPrefixChunks().get(i),
                    proof.forkRoot().get(i));
            ZkField forkSparse = sparseBranch(
                    zk,
                    params,
                    keyPathSignals,
                    stepCursor,
                    skip,
                    queryNibble,
                    current,
                    proof.neighborNibble().get(i),
                    forkCommitment);
            ZkField fork = inclusion
                    ? forkSparse
                    : lastValid.select(proof.forkRoot().get(i), forkSparse);
            valid.and(forkKind).and(queryNibble.isEqual(proof.neighborNibble().get(i))).assertFalse();
            if (!inclusion) {
                // CCL terminal-fork exclusion exposes an unauthenticated root
                // in the proof. Reject it in-circuit until the witness format
                // carries an authenticated terminal-fork commitment.
                valid.and(forkKind).and(lastValid).assertFalse();
            }

            PathSignals leafPath = PathSignals.of(proof.leafKeyPath().get(i));
            ZkUInt leafNibble = leafPath.at(zk, queryIndex.signal());
            ZkField neighborLeaf = commitLeafFromPath(
                    zk,
                    params,
                    leafPath,
                    stepNextCursor,
                    proof.leafValueDigest().get(i));
            ZkField leafSparse = sparseBranch(
                    zk,
                    params,
                    keyPathSignals,
                    stepCursor,
                    skip,
                    queryNibble,
                    current,
                    leafNibble,
                    neighborLeaf);
            ZkField terminalLeaf = commitLeafFromPath(
                    zk,
                    params,
                    leafPath,
                    stepCursor,
                    proof.leafValueDigest().get(i));
            ZkField leaf = inclusion
                    ? leafSparse
                    : lastValid.select(terminalLeaf, leafSparse);
            assertLeafDivergence(zk, keyPath, proof.leafKeyPath().get(i), queryIndex, queryNibble, leafNibble,
                    valid.and(leafKind));

            ZkField stepResult = branchKind.select(branch, current);
            stepResult = forkKind.select(fork, stepResult);
            stepResult = leafKind.select(leaf, stepResult);
            current = valid.select(stepResult, current);
        }

        return current;
    }

    private static ZkField hashKeyPath(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            BigInteger domain) {
        requireBlsParams(zk, params);
        requireKeyPath(zk, keyPath);

        var fields = new ArrayList<ZkField>(KEY_PATH_NIBBLES + 2);
        fields.add(zk.constant(domain));
        fields.add(zk.constant(KEY_PATH_NIBBLES));
        for (ZkUInt nibble : keyPath.values()) {
            fields.add(nibble.asField());
        }
        return ZkPoseidonN.hash(zk, params, fields.toArray(ZkField[]::new));
    }

    private static ZkField branchStep(
            ZkContext zk,
            PoseidonParams params,
            PathSignals keyPath,
            ZkUInt cursor,
            ZkUInt skip,
            ZkUInt queryNibble,
            ZkField child,
            ZkArray<ZkField> neighbors) {
        ZkField aggregate = aggregateSiblingHashes(zk, params, queryNibble, child, neighbors);
        return prefixedDigestFromPath(zk, params, keyPath, cursor, skip, aggregate);
    }

    private static ZkField sparseBranch(
            ZkContext zk,
            PoseidonParams params,
            PathSignals keyPath,
            ZkUInt cursor,
            ZkUInt skip,
            ZkUInt queryNibble,
            ZkField queryChild,
            ZkUInt neighborNibble,
            ZkField neighborChild) {
        ZkField zero = zk.constant(0);
        ZkField[] children = new ZkField[16];
        for (int i = 0; i < children.length; i++) {
            ZkBool isQuery = eqConst(zk, queryNibble, i);
            ZkBool isNeighbor = eqConst(zk, neighborNibble, i);
            ZkField child = isQuery.select(queryChild, zero);
            children[i] = isNeighbor.select(neighborChild, child);
        }
        ZkField subRoot = binaryMerkleRoot16(zk, params, children);
        return prefixedDigestFromPath(zk, params, keyPath, cursor, skip, subRoot);
    }

    private static ZkField aggregateSiblingHashes(
            ZkContext zk,
            PoseidonParams params,
            ZkUInt nibble,
            ZkField child,
            ZkArray<ZkField> neighbors) {
        ZkField current = child;
        Signal[] bits = nibble.signal().toBinary(4);
        for (int level = 0; level < 4; level++) {
            ZkField sibling = neighbors.get(3 - level);
            ZkBool bit = ZkBool.wrap(zk, bits[level]);
            ZkField left = bit.select(sibling, current);
            ZkField right = bit.select(current, sibling);
            current = byteDigestPair(zk, params, left, right);
        }
        return current;
    }

    private static ZkField binaryMerkleRoot16(
            ZkContext zk,
            PoseidonParams params,
            ZkField[] children) {
        if (children.length != 16) {
            throw new IllegalArgumentException("children must contain 16 entries");
        }
        ZkField[] level = children;
        while (level.length > 1) {
            ZkField[] next = new ZkField[level.length / 2];
            for (int i = 0; i < level.length; i += 2) {
                next[i / 2] = byteDigestPair(zk, params, level[i], level[i + 1]);
            }
            level = next;
        }
        return level[0];
    }

    private static ZkField byteDigestPair(
            ZkContext zk,
            PoseidonParams params,
            ZkField left,
            ZkField right) {
        return ZkPoseidonN.hash(
                zk,
                params,
                zk.constant(DOMAIN_BYTES),
                zk.constant(BYTE_DIGEST_CHUNK_BYTES * 2L),
                left,
                right,
                zk.constant(0));
    }

    private static ZkField prefixedDigestFromPath(
            ZkContext zk,
            PoseidonParams params,
            PathSignals path,
            ZkUInt start,
            ZkUInt length,
            ZkField digest) {
        return ZkPoseidonN.hash(
                zk,
                params,
                zk.constant(DOMAIN_BYTES),
                length.asField().add(zk.constant(BYTE_DIGEST_CHUNK_BYTES)),
                selectPrefixedDigestChunkFromPath(zk, path, start, length, digest, 0),
                selectPrefixedDigestChunkFromPath(zk, path, start, length, digest, 1),
                selectPrefixedDigestChunkFromPath(zk, path, start, length, digest, 2));
    }

    private static ZkField prefixedDigestFromWitness(
            ZkContext zk,
            PoseidonParams params,
            ZkUInt prefixLength,
            ZkArray<ZkField> prefixChunks,
            ZkField digest) {
        if (prefixChunks.size() < 2) {
            throw new IllegalArgumentException(
                    "forkPrefixChunks inner size must be at least 2 for 64-nibble MPF paths");
        }
        return ZkPoseidonN.hash(
                zk,
                params,
                zk.constant(DOMAIN_BYTES),
                prefixLength.asField().add(zk.constant(BYTE_DIGEST_CHUNK_BYTES)),
                selectPrefixedDigestChunkFromWitness(zk, prefixLength, prefixChunks, digest, 0),
                selectPrefixedDigestChunkFromWitness(zk, prefixLength, prefixChunks, digest, 1),
                selectPrefixedDigestChunkFromWitness(zk, prefixLength, prefixChunks, digest, 2));
    }

    private static ZkField selectPrefixedDigestChunkFromPath(
            ZkContext zk,
            PathSignals path,
            ZkUInt start,
            ZkUInt length,
            ZkField digest,
            int chunkIndex) {
        // The prefixed digest layout has only three structural cases
        // (0, 1..32, 33..64), so avoid repacking duplicate candidates for
        // every possible length.
        return switch (chunkIndex) {
            case 0 -> selectPrefixedPathChunk0(zk, path, start, length, digest);
            case 1 -> selectPrefixedPathChunk1(zk, path, start, length, digest);
            case 2 -> lteConst(zk, length, BYTE_DIGEST_CHUNK_BYTES)
                    .select(zk.constant(0), digest);
            default -> zk.constant(0);
        };
    }

    private static ZkField selectPrefixedPathChunk0(
            ZkContext zk,
            PathSignals path,
            ZkUInt start,
            ZkUInt length,
            ZkField digest) {
        ZkField selected = packPathNibbles(zk, path, start, 0, BYTE_DIGEST_CHUNK_BYTES);
        for (int len = 1; len < BYTE_DIGEST_CHUNK_BYTES; len++) {
            ZkBool matchesShortOrLong = eqConst(zk, length, len)
                    .or(eqConst(zk, length, len + BYTE_DIGEST_CHUNK_BYTES));
            selected = matchesShortOrLong.select(
                    packPathNibbles(zk, path, start, 0, len),
                    selected);
        }
        return eqConst(zk, length, 0).select(digest, selected);
    }

    private static ZkField selectPrefixedPathChunk1(
            ZkContext zk,
            PathSignals path,
            ZkUInt start,
            ZkUInt length,
            ZkField digest) {
        ZkField selected = lteConst(zk, length, BYTE_DIGEST_CHUNK_BYTES)
                .select(digest, packPathNibbles(zk, path, start, BYTE_DIGEST_CHUNK_BYTES, BYTE_DIGEST_CHUNK_BYTES));
        selected = eqConst(zk, length, 0).select(zk.constant(0), selected);
        for (int offset = 1; offset < BYTE_DIGEST_CHUNK_BYTES; offset++) {
            selected = eqConst(zk, length, offset + BYTE_DIGEST_CHUNK_BYTES).select(
                    packPathNibbles(zk, path, start, offset, BYTE_DIGEST_CHUNK_BYTES),
                    selected);
        }
        return selected;
    }

    private static ZkField selectPrefixedDigestChunkFromWitness(
            ZkContext zk,
            ZkUInt length,
            ZkArray<ZkField> prefixChunks,
            ZkField digest,
            int chunkIndex) {
        return switch (chunkIndex) {
            case 0 -> eqConst(zk, length, 0).select(digest, prefixChunks.get(0));
            case 1 -> {
                ZkField selected = lteConst(zk, length, BYTE_DIGEST_CHUNK_BYTES)
                        .select(digest, prefixChunks.get(1));
                yield eqConst(zk, length, 0).select(zk.constant(0), selected);
            }
            case 2 -> lteConst(zk, length, BYTE_DIGEST_CHUNK_BYTES)
                    .select(zk.constant(0), digest);
            default -> zk.constant(0);
        };
    }

    private static ZkField commitLeafFromPath(
            ZkContext zk,
            PoseidonParams params,
            PathSignals path,
            ZkUInt start,
            ZkField valueCommitment) {
        ZkUInt length = uintWrap(zk, zk.builder().constant(KEY_PATH_NIBBLES).sub(start.signal()), CURSOR_BITS);
        return ZkPoseidonN.hash(
                zk,
                params,
                zk.constant(DOMAIN_LEAF),
                length.asField(),
                selectLeafChunk(zk, path, start, length, 0),
                selectLeafChunk(zk, path, start, length, 1),
                selectLeafChunk(zk, path, start, length, 2),
                valueCommitment);
    }

    private static ZkField selectLeafChunk(
            ZkContext zk,
            PathSignals path,
            ZkUInt start,
            ZkUInt length,
            int chunkIndex) {
        // Leaf suffix chunks are 31/31/2 bytes. Lengths beyond a chunk's full
        // width reuse the same packed candidate.
        return switch (chunkIndex) {
            case 0 -> selectLeafChunk0(zk, path, start, length);
            case 1 -> selectLeafChunk1(zk, path, start, length);
            case 2 -> selectLeafChunk2(zk, path, start, length);
            default -> zk.constant(0);
        };
    }

    private static ZkField selectLeafChunk0(
            ZkContext zk,
            PathSignals path,
            ZkUInt start,
            ZkUInt length) {
        ZkField selected = lteConst(zk, length, LEAF_CHUNK_BYTES - 1)
                .select(zk.constant(0), leafChunkCandidate(zk, path, start, LEAF_CHUNK_BYTES, 0));
        for (int len = 1; len < LEAF_CHUNK_BYTES; len++) {
            selected = eqConst(zk, length, len).select(
                    leafChunkCandidate(zk, path, start, len, 0),
                    selected);
        }
        return selected;
    }

    private static ZkField selectLeafChunk1(
            ZkContext zk,
            PathSignals path,
            ZkUInt start,
            ZkUInt length) {
        ZkField selected = lteConst(zk, length, (LEAF_CHUNK_BYTES * 2) - 1)
                .select(zk.constant(0), leafChunkCandidate(zk, path, start, LEAF_CHUNK_BYTES * 2, 1));
        for (int len = LEAF_CHUNK_BYTES + 1; len < LEAF_CHUNK_BYTES * 2; len++) {
            selected = eqConst(zk, length, len).select(
                    leafChunkCandidate(zk, path, start, len, 1),
                    selected);
        }
        return selected;
    }

    private static ZkField selectLeafChunk2(
            ZkContext zk,
            PathSignals path,
            ZkUInt start,
            ZkUInt length) {
        ZkField selected = zk.constant(0);
        selected = eqConst(zk, length, (LEAF_CHUNK_BYTES * 2) + 1).select(
                leafChunkCandidate(zk, path, start, (LEAF_CHUNK_BYTES * 2) + 1, 2),
                selected);
        return eqConst(zk, length, KEY_PATH_NIBBLES).select(
                leafChunkCandidate(zk, path, start, KEY_PATH_NIBBLES, 2),
                selected);
    }

    private static ZkField leafChunkCandidate(
            ZkContext zk,
            PathSignals path,
            ZkUInt start,
            int suffixLength,
            int chunkIndex) {
        int offset = chunkIndex * LEAF_CHUNK_BYTES;
        if (offset >= suffixLength) {
            return zk.constant(0);
        }
        int chunkLength = Math.min(LEAF_CHUNK_BYTES, suffixLength - offset);
        return packPathNibbles(zk, path, start, offset, chunkLength);
    }

    private static ZkField packPathNibbles(
            ZkContext zk,
            PathSignals path,
            ZkUInt start,
            int offset,
            int length) {
        ZkField acc = zk.constant(0);
        for (int i = 0; i < length; i++) {
            ZkUInt nibble = path.atOffset(zk, start, offset + i);
            BigInteger coefficient = BigInteger.ONE.shiftLeft(8 * (length - 1 - i));
            acc = acc.add(nibble.asField().mul(zk.constant(coefficient)));
        }
        return acc;
    }

    private static void assertLeafDivergence(
            ZkContext zk,
            ZkArray<ZkUInt> keyPath,
            ZkArray<ZkUInt> leafPath,
            ZkUInt divergenceIndex,
            ZkUInt queryNibble,
            ZkUInt leafNibble,
            ZkBool condition) {
        condition.and(queryNibble.isEqual(leafNibble)).assertFalse();
        for (int i = 0; i < KEY_PATH_NIBBLES; i++) {
            ZkBool beforeDivergence = uintConst(zk, i, CURSOR_BITS).lt(divergenceIndex);
            ZkBool same = keyPath.get(i).isEqual(leafPath.get(i));
            condition.and(beforeDivergence).and(same.not()).assertFalse();
        }
    }

    private static ZkBool eqConst(ZkContext zk, ZkUInt value, int constant) {
        return value.asField().isEqual(zk.constant(constant));
    }

    private static ZkBool lteConst(ZkContext zk, ZkUInt value, int constant) {
        return value.lte(uintConst(zk, constant, value.bits()));
    }

    private static ZkUInt uintConst(ZkContext zk, int value, int bits) {
        return uintWrap(zk, zk.builder().constant(value), bits);
    }

    private static ZkUInt uintWrap(ZkContext zk, Signal signal, int bits) {
        return ZkUInt.wrap(zk, signal, bits);
    }

    private static void validateInputs(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField valueCommitment,
            ZkMpfProof proof) {
        requireBlsParams(zk, params);
        requireKeyPath(zk, keyPath);
        Objects.requireNonNull(valueCommitment, "valueCommitment");
        Objects.requireNonNull(proof, "proof");
        zk.requireSignal(valueCommitment.signal());
        proof.assertWellFormed();
    }

    private static void requireKeyPath(ZkContext zk, ZkArray<ZkUInt> keyPath) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(keyPath, "keyPath");
        if (keyPath.size() != KEY_PATH_NIBBLES) {
            throw new IllegalArgumentException(
                    "keyPath must contain " + KEY_PATH_NIBBLES + " nibbles, got " + keyPath.size());
        }
        for (int i = 0; i < keyPath.size(); i++) {
            ZkUInt nibble = keyPath.get(i);
            if (nibble.bits() != 4) {
                throw new IllegalArgumentException("keyPath[" + i + "] must be a 4-bit ZkUInt");
            }
            zk.requireSignal(nibble.signal());
        }
    }

    private static void requireRoot(ZkContext zk, ZkField root) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(root, "root");
        zk.requireSignal(root.signal());
    }

    private static void requireBlsParams(ZkContext zk, PoseidonParams params) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(params, "params");
        if (!FieldConfig.BLS12_381.equals(params.field())) {
            throw new IllegalArgumentException("ZkMpf requires BLS12-381 Poseidon params");
        }
        if (params.t() != 3 || params.alpha() != 5) {
            throw new IllegalArgumentException("ZkMpf supports only Poseidon t=3, alpha=5 params");
        }
        zk.builder().api().requireField(params.field());
    }

    private record PathSignals(ZkArray<ZkUInt> path, Signal[] signals) {
        static PathSignals of(ZkArray<ZkUInt> path) {
            var signals = new Signal[path.size()];
            for (int i = 0; i < path.size(); i++) {
                signals[i] = path.get(i).signal();
            }
            return new PathSignals(path, signals);
        }

        ZkUInt atOffset(ZkContext zk, ZkUInt start, int offset) {
            return at(zk, start.signal().add(offset));
        }

        ZkUInt at(ZkContext zk, Signal index) {
            return ZkUInt.wrap(zk, zk.builder().arrayAccess(signals, index), 4);
        }
    }
}
