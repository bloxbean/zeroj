package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidonN;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfProfile;

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

    static ZkField branchOnlyRoot(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField terminalValue,
            boolean terminalIsLeaf,
            ZkMpfBranchProof proof) {
        PreparedBranch prepared = prepareBranchProof(zk, params, keyPath, proof);
        ZkField current = terminalIsLeaf
                ? commitLeafFromPath(zk, params, prepared.path(), prepared.finalCursor(), terminalValue)
                : terminalValue;
        return foldBranches(zk, params, prepared, current);
    }

    static ZkField differentLeafRoot(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> queryPath,
            ZkArray<ZkUInt> conflictingLeafPath,
            ZkField conflictingValue,
            ZkUInt terminalSkip,
            ZkMpfBranchProof proof) {
        PreparedBranch prepared = prepareBranchProof(zk, params, queryPath, proof);
        requireKeyPath(zk, conflictingLeafPath);
        Objects.requireNonNull(conflictingValue, "conflictingValue");
        Objects.requireNonNull(terminalSkip, "terminalSkip");
        if (terminalSkip.bits() != 8) {
            throw new IllegalArgumentException("terminalSkip must be an 8-bit ZkUInt");
        }
        terminalSkip.assertWellFormed();
        ZkUInt divergenceIndex = uintWrap(
                zk, prepared.finalCursor().signal().add(terminalSkip.signal()), CURSOR_BITS);
        lteConst(zk, divergenceIndex, KEY_PATH_NIBBLES - 1).assertTrue();
        PathSignals conflicting = PathSignals.of(conflictingLeafPath);
        ZkUInt queryNibble = prepared.path().at(zk, divergenceIndex.signal());
        ZkUInt conflictingNibble = conflicting.at(zk, divergenceIndex.signal());
        assertLeafDivergence(
                zk, queryPath, conflictingLeafPath, divergenceIndex,
                queryNibble, conflictingNibble, ZkBool.wrap(zk, zk.builder().constant(1)));
        ZkField current = commitLeafFromPath(
                zk, params, conflicting, prepared.finalCursor(), conflictingValue);
        return foldBranches(zk, params, prepared, current);
    }

    static void verifyDifferentLeafInsertion(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> queryPath,
            ZkField insertedValue,
            ZkArray<ZkUInt> conflictingLeafPath,
            ZkField conflictingValue,
            ZkUInt terminalSkip,
            ZkField oldRoot,
            ZkField newRoot,
            ZkMpfBranchProof proof) {
        PreparedBranch prepared = prepareBranchProof(zk, params, queryPath, proof);
        requireKeyPath(zk, conflictingLeafPath);
        requireRoot(zk, oldRoot);
        requireRoot(zk, newRoot);
        Objects.requireNonNull(insertedValue, "insertedValue");
        Objects.requireNonNull(conflictingValue, "conflictingValue");
        Objects.requireNonNull(terminalSkip, "terminalSkip");
        if (terminalSkip.bits() != CURSOR_BITS) {
            throw new IllegalArgumentException("terminalSkip must be an 8-bit ZkUInt");
        }
        terminalSkip.assertWellFormed();

        ZkUInt divergenceIndex = uintWrap(
                zk, prepared.finalCursor().signal().add(terminalSkip.signal()), CURSOR_BITS);
        lteConst(zk, divergenceIndex, KEY_PATH_NIBBLES - 1).assertTrue();
        ZkUInt childStart = uintWrap(zk, divergenceIndex.signal().add(1), CURSOR_BITS);
        PathSignals conflicting = PathSignals.of(conflictingLeafPath);
        ZkUInt queryNibble = prepared.path().at(zk, divergenceIndex.signal());
        ZkUInt conflictingNibble = conflicting.at(zk, divergenceIndex.signal());
        assertLeafDivergence(
                zk, queryPath, conflictingLeafPath, divergenceIndex,
                queryNibble, conflictingNibble,
                ZkBool.wrap(zk, zk.builder().constant(1)));

        ZkField oldTerminal = commitLeafFromPath(
                zk, params, conflicting, prepared.finalCursor(), conflictingValue);
        ZkField queryChild = commitLeafFromPath(
                zk, params, prepared.path(), childStart, insertedValue);
        ZkField conflictingChild = commitLeafFromPath(
                zk, params, conflicting, childStart, conflictingValue);
        ZkField newTerminal = sparseBranch(
                zk, params, prepared.path(), prepared.finalCursor(), terminalSkip,
                queryNibble, queryChild, conflictingNibble, conflictingChild);
        ZkField[] roots = foldBranchCurrents(
                zk, params, prepared, oldTerminal, newTerminal);
        roots[0].assertEqual(oldRoot);
        roots[1].assertEqual(newRoot);
    }

    static void verifyBranchTransition(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField oldTerminal,
            boolean oldTerminalIsLeaf,
            ZkField newTerminal,
            boolean newTerminalIsLeaf,
            ZkField oldRoot,
            ZkField newRoot,
            ZkMpfBranchProof proof) {
        PreparedBranch prepared = prepareBranchProof(zk, params, keyPath, proof);
        requireRoot(zk, oldRoot);
        requireRoot(zk, newRoot);
        ZkField oldCurrent;
        ZkField newCurrent;
        if (oldTerminalIsLeaf && newTerminalIsLeaf) {
            ZkField[] leaves = commitLeavesFromPath(
                    zk, params, prepared.path(), prepared.finalCursor(), oldTerminal, newTerminal);
            oldCurrent = leaves[0];
            newCurrent = leaves[1];
        } else {
            oldCurrent = oldTerminalIsLeaf
                    ? commitLeafFromPath(zk, params, prepared.path(), prepared.finalCursor(), oldTerminal)
                    : oldTerminal;
            newCurrent = newTerminalIsLeaf
                    ? commitLeafFromPath(zk, params, prepared.path(), prepared.finalCursor(), newTerminal)
                    : newTerminal;
        }
        ZkField[] roots = foldBranchCurrents(
                zk, params, prepared, oldCurrent, newCurrent);
        roots[0].assertEqual(oldRoot);
        roots[1].assertEqual(newRoot);
    }

    private static PreparedBranch prepareBranchProof(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkMpfBranchProof proof) {
        requireBlsParams(zk, params);
        requireKeyPath(zk, keyPath);
        Objects.requireNonNull(proof, "proof");
        proof.assertWellFormed();
        PathSignals path = PathSignals.of(keyPath);
        ZkUInt[] cursorBefore = new ZkUInt[proof.maxSteps()];
        ZkUInt[] nextCursor = new ZkUInt[proof.maxSteps()];
        ZkUInt cursor = uintConst(zk, 0, CURSOR_BITS);
        for (int index = 0; index < proof.maxSteps(); index++) {
            ZkBool valid = proof.valid().get(index);
            if (index + 1 < proof.maxSteps()) {
                valid.not().and(proof.valid().get(index + 1)).assertFalse();
            }
            cursorBefore[index] = cursor;
            ZkUInt advanced = uintWrap(
                    zk, cursor.signal().add(proof.skip().get(index).signal()).add(1), CURSOR_BITS);
            valid.and(lteConst(zk, advanced, KEY_PATH_NIBBLES).not()).assertFalse();
            nextCursor[index] = advanced;
            cursor = valid.select(advanced, cursor);

            valid.not().and(proof.skip().get(index).asField().isEqual(zk.constant(0)).not())
                    .assertFalse();
            for (ZkField sibling : proof.siblings().get(index).values()) {
                valid.not().and(sibling.isEqual(zk.constant(0)).not()).assertFalse();
            }
        }
        return new PreparedBranch(path, cursorBefore, nextCursor, cursor, proof);
    }

    private static ZkField foldBranches(
            ZkContext zk, PoseidonParams params, PreparedBranch prepared, ZkField terminal) {
        return foldBranchCurrents(zk, params, prepared, terminal)[0];
    }

    private static ZkField[] foldBranchCurrents(
            ZkContext zk,
            PoseidonParams params,
            PreparedBranch prepared,
            ZkField... terminals) {
        ZkField[] current = terminals.clone();
        ZkMpfBranchProof proof = prepared.proof();
        for (int index = proof.maxSteps() - 1; index >= 0; index--) {
            ZkBool valid = proof.valid().get(index);
            ZkUInt queryIndex = uintWrap(
                    zk, prepared.nextCursor()[index].signal().add(-1), CURSOR_BITS);
            ZkUInt queryNibble = prepared.path().at(zk, queryIndex.signal());
            ZkField[] aggregates = new ZkField[current.length];
            for (int item = 0; item < current.length; item++) {
                aggregates[item] = aggregateSiblingHashes(
                        zk, params, queryNibble, current[item], proof.siblings().get(index));
            }
            ZkField[] parents = prefixedDigestsFromPath(
                    zk, params, prepared.path(), prepared.cursorBefore()[index],
                    proof.skip().get(index), aggregates);
            for (int item = 0; item < current.length; item++) {
                current[item] = valid.select(parents[item], current[item]);
            }
        }
        return current;
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
        ZkField zero = zk.constant(0);

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

            isPadding.and(proof.skip().get(i).asField().isEqual(zero).not()).assertFalse();
            for (ZkField neighbor : proof.neighbors().get(i).values()) {
                isPadding.and(neighbor.isEqual(zero).not()).assertFalse();
            }
            isPadding.and(proof.neighborNibble().get(i).asField().isEqual(zero).not())
                    .assertFalse();
            isPadding.and(proof.forkPrefixLength().get(i).asField().isEqual(zero).not())
                    .assertFalse();
            for (ZkField chunk : proof.forkPrefixChunks().get(i).values()) {
                isPadding.and(chunk.isEqual(zero).not()).assertFalse();
            }
            isPadding.and(proof.forkRoot().get(i).isEqual(zero).not()).assertFalse();
            for (ZkUInt nibble : proof.leafKeyPath().get(i).values()) {
                isPadding.and(nibble.asField().isEqual(zero).not()).assertFalse();
            }
            isPadding.and(proof.leafValueDigest().get(i).isEqual(zero).not()).assertFalse();
        }

        ZkField current = inclusion
                ? commitLeafFromPath(zk, params, keyPathSignals, cursor, valueCommitment)
                : zero;

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
        return prefixedDigestsFromPath(zk, params, path, start, length, digest)[0];
    }

    private static ZkField[] prefixedDigestsFromPath(
            ZkContext zk,
            PoseidonParams params,
            PathSignals path,
            ZkUInt start,
            ZkUInt length,
            ZkField... digests) {
        ZkUInt end = uintWrap(zk, start.signal().add(length.signal()), CURSOR_BITS);
        lteConst(zk, end, KEY_PATH_NIBBLES).assertTrue();
        ZkBool longPrefix = lteConst(zk, length, BYTE_DIGEST_CHUNK_BYTES).not();
        ZkUInt zero = uintConst(zk, 0, CURSOR_BITS);
        ZkUInt firstEnd = uintWrap(zk, longPrefix.signal().select(
                end.signal().add(-BYTE_DIGEST_CHUNK_BYTES), end.signal()), CURSOR_BITS);
        ZkUInt secondStart = uintWrap(zk, longPrefix.signal().select(
                end.signal().add(-BYTE_DIGEST_CHUNK_BYTES), zero.signal()), CURSOR_BITS);
        ZkUInt secondEnd = longPrefix.select(end, zero);
        ZkField[] prefixChunks = packPathIntervals(
                zk, path,
                new ZkUInt[]{start, secondStart},
                new ZkUInt[]{firstEnd, secondEnd});
        ZkBool emptyPrefix = eqConst(zk, length, 0);
        ZkField[] output = new ZkField[digests.length];
        for (int index = 0; index < digests.length; index++) {
            ZkField digest = digests[index];
            output[index] = ZkPoseidonN.hash(
                    zk,
                    params,
                    zk.constant(DOMAIN_BYTES),
                    length.asField().add(zk.constant(BYTE_DIGEST_CHUNK_BYTES)),
                    emptyPrefix.select(digest, prefixChunks[0]),
                    emptyPrefix.select(zk.constant(0),
                            longPrefix.select(prefixChunks[1], digest)),
                    longPrefix.select(digest, zk.constant(0)));
        }
        return output;
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
        return commitLeavesFromPath(zk, params, path, start, valueCommitment)[0];
    }

    private static ZkField[] commitLeavesFromPath(
            ZkContext zk,
            PoseidonParams params,
            PathSignals path,
            ZkUInt start,
            ZkField... valueCommitments) {
        ZkUInt length = uintWrap(zk, zk.builder().constant(KEY_PATH_NIBBLES).sub(start.signal()), CURSOR_BITS);
        ZkUInt chunk0End = cappedPathOffset(zk, start, LEAF_CHUNK_BYTES);
        ZkUInt chunk1End = cappedPathOffset(zk, start, LEAF_CHUNK_BYTES * 2);
        ZkUInt pathEnd = uintConst(zk, KEY_PATH_NIBBLES, CURSOR_BITS);
        ZkField[] chunks = packPathIntervals(
                zk, path,
                new ZkUInt[]{start, chunk0End, chunk1End},
                new ZkUInt[]{chunk0End, chunk1End, pathEnd});
        ZkField[] output = new ZkField[valueCommitments.length];
        for (int index = 0; index < valueCommitments.length; index++) {
            output[index] = ZkPoseidonN.hash(
                    zk,
                    params,
                    zk.constant(DOMAIN_LEAF),
                    length.asField(),
                    chunks[0],
                    chunks[1],
                    chunks[2],
                    valueCommitments[index]);
        }
        return output;
    }

    private static ZkUInt cappedPathOffset(ZkContext zk, ZkUInt start, int offset) {
        int largestStartWithoutCapping = KEY_PATH_NIBBLES - offset;
        ZkBool withinPath = lteConst(zk, start, largestStartWithoutCapping);
        Signal selected = withinPath.signal().select(
                start.signal().add(offset),
                zk.builder().constant(KEY_PATH_NIBBLES));
        return uintWrap(zk, selected, CURSOR_BITS);
    }

    /**
     * Packs several dynamic half-open path intervals in one streaming pass.
     *
     * <p>Every endpoint is constrained to [0, 64]. For an interval [start,end),
     * the running one-hot prefix difference is exactly one inside the interval
     * and zero outside it. This avoids the former cubic candidate packing while
     * keeping every selected nibble constrained by the original key path.
     */
    private static ZkField[] packPathIntervals(
            ZkContext zk,
            PathSignals path,
            ZkUInt[] starts,
            ZkUInt[] ends) {
        if (starts.length != ends.length) {
            throw new IllegalArgumentException("path interval endpoint arrays must have equal size");
        }
        int intervals = starts.length;
        Signal[][] startAt = new Signal[intervals][KEY_PATH_NIBBLES + 1];
        Signal[][] endAt = new Signal[intervals][KEY_PATH_NIBBLES + 1];
        Signal[] started = new Signal[intervals];
        Signal[] ended = new Signal[intervals];
        Signal[] accumulators = new Signal[intervals];
        Signal zero = zk.builder().constant(0);
        Signal one = zk.builder().constant(1);

        for (int interval = 0; interval < intervals; interval++) {
            Signal startSum = zero;
            Signal endSum = zero;
            for (int position = 0; position <= KEY_PATH_NIBBLES; position++) {
                Signal positionConstant = zk.builder().constant(position);
                startAt[interval][position] = starts[interval].signal().isEqual(positionConstant);
                endAt[interval][position] = ends[interval].signal().isEqual(positionConstant);
                startSum = startSum.add(startAt[interval][position]);
                endSum = endSum.add(endAt[interval][position]);
            }
            zk.builder().assertEqual(startSum, one);
            zk.builder().assertEqual(endSum, one);
            started[interval] = zero;
            ended[interval] = zero;
            accumulators[interval] = zero;
        }

        for (int position = 0; position < KEY_PATH_NIBBLES; position++) {
            Signal nibble = path.signals()[position];
            for (int interval = 0; interval < intervals; interval++) {
                started[interval] = started[interval].add(startAt[interval][position]);
                ended[interval] = ended[interval].add(endAt[interval][position]);
                Signal active = started[interval].sub(ended[interval]);
                Signal appended = accumulators[interval].mul(256).add(nibble);
                accumulators[interval] = active.select(appended, accumulators[interval]);
            }
        }

        ZkField[] output = new ZkField[intervals];
        for (int interval = 0; interval < intervals; interval++) {
            output[interval] = ZkField.wrap(zk, accumulators[interval]);
        }
        return output;
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
        PoseidonMpfProfile.requireSupported(params);
        zk.builder().api().requireField(params.field());
    }

    private record PreparedBranch(
            PathSignals path,
            ZkUInt[] cursorBefore,
            ZkUInt[] nextCursor,
            ZkUInt finalCursor,
            ZkMpfBranchProof proof) {}

    private record PathSignals(ZkArray<ZkUInt> path, Signal[] signals) {
        static PathSignals of(ZkArray<ZkUInt> path) {
            var signals = new Signal[path.size()];
            for (int i = 0; i < path.size(); i++) {
                signals[i] = path.get(i).signal();
            }
            return new PathSignals(path, signals);
        }

        ZkUInt at(ZkContext zk, Signal index) {
            return ZkUInt.wrap(zk, zk.builder().arrayAccess(signals, index), 4);
        }
    }
}
