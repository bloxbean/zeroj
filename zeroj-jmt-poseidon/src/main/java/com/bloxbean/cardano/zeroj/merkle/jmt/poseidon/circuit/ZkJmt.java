package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.Poseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtCommitments;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;

import java.math.BigInteger;
import java.util.Objects;

/** Shared relation helpers for operation-specific Poseidon JMT v1 circuits. */
final class ZkJmt {
    private ZkJmt() {}

    static Prepared prepare(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyNibbles,
            ZkJmtPathProof proof) {
        requireProfile(zk, params);
        Objects.requireNonNull(proof, "proof").assertWellFormed(zk);
        ZkField key = ZkJmtCanonicalKey.decode(zk, keyNibbles);
        return new Prepared(keyNibbles, key, proof);
    }

    static ZkField leaf(ZkContext zk, PoseidonParams params, ZkField key, ZkField value) {
        return compress(zk, params, PoseidonJmtProfile.DOMAIN_LEAF, key, value);
    }

    static ZkField empty(ZkContext zk) {
        return zk.constant(PoseidonJmtHash.decode(PoseidonJmtCommitments.empty()));
    }

    static ZkField rootFromTerminal(
            ZkContext zk, PoseidonParams params, Prepared prepared, ZkField terminal) {
        ZkField current = terminal;
        for (int level = prepared.proof().maxLevels() - 1; level >= 0; level--) {
            ZkField branch = radixBranch(
                    zk, params, prepared.keyNibbles().get(level), current,
                    prepared.proof().siblings().get(level));
            current = prepared.proof().valid().get(level).select(branch, current);
        }
        return current;
    }

    static ZkField[] rootsFromTerminals(
            ZkContext zk, PoseidonParams params, Prepared prepared, ZkField... terminals) {
        ZkField[] currents = terminals.clone();
        for (int level = prepared.proof().maxLevels() - 1; level >= 0; level--) {
            for (int item = 0; item < currents.length; item++) {
                ZkField branch = radixBranch(
                        zk, params, prepared.keyNibbles().get(level), currents[item],
                        prepared.proof().siblings().get(level));
                currents[item] = prepared.proof().valid().get(level).select(branch, currents[item]);
            }
        }
        return currents;
    }

    static void assertDifferentLeaf(
            ZkContext zk,
            Prepared query,
            ZkArray<ZkUInt> conflictingNibbles,
            ZkField conflictingKey) {
        query.key().isEqual(conflictingKey).assertFalse();
        for (int level = 0; level < query.proof().maxLevels(); level++) {
            ZkBool same = query.keyNibbles().get(level).isEqual(conflictingNibbles.get(level));
            query.proof().valid().get(level).and(same.not()).assertFalse();
        }
    }

    static ZkField differentLeafInsertionTerminal(
            ZkContext zk,
            PoseidonParams params,
            Prepared query,
            ZkField queryLeaf,
            ZkArray<ZkUInt> conflictingNibbles,
            ZkField conflictingLeaf) {
        Signal samePrefix = zk.builder().constant(1);
        Signal divergenceNibbleQuery = zk.builder().constant(0);
        Signal divergenceNibbleConflicting = zk.builder().constant(0);
        Signal[] sameThrough = new Signal[PoseidonJmtProfile.KEY_NIBBLES];
        for (int index = 0; index < PoseidonJmtProfile.KEY_NIBBLES; index++) {
            Signal same = query.keyNibbles().get(index).signal()
                    .isEqual(conflictingNibbles.get(index).signal());
            Signal divergence = samePrefix.and(same.not());
            divergenceNibbleQuery = divergenceNibbleQuery.add(
                    divergence.mul(query.keyNibbles().get(index).signal()));
            divergenceNibbleConflicting = divergenceNibbleConflicting.add(
                    divergence.mul(conflictingNibbles.get(index).signal()));
            samePrefix = samePrefix.and(same);
            sameThrough[index] = samePrefix;
        }
        zk.builder().assertEqual(samePrefix, zk.builder().constant(0));
        ZkUInt queryAtDivergence = ZkUInt.wrap(zk,
                divergenceNibbleQuery, 4);
        ZkUInt conflictingAtDivergence = ZkUInt.wrap(zk,
                divergenceNibbleConflicting, 4);
        ZkField current = twoLeafBranch(
                zk, params, queryAtDivergence, queryLeaf,
                conflictingAtDivergence, conflictingLeaf);

        for (int level = PoseidonJmtProfile.KEY_NIBBLES - 1; level >= 0; level--) {
            ZkBool beforeDivergence = ZkBool.wrap(zk, sameThrough[level]);
            ZkBool outsideAuthenticatedPath = level < query.proof().maxLevels()
                    ? query.proof().valid().get(level).not()
                    : ZkBool.wrap(zk, zk.builder().constant(1));
            ZkBool apply = beforeDivergence.and(outsideAuthenticatedPath);
            ZkField branch = radixBranchWithEmptySiblings(
                    zk, params, query.keyNibbles().get(level), current);
            current = apply.select(branch, current);
        }
        return current;
    }

    private static ZkField radixBranch(
            ZkContext zk,
            PoseidonParams params,
            ZkUInt childIndex,
            ZkField child,
            ZkArray<ZkField> siblings) {
        ZkField current = child;
        for (int binaryLevel = 0; binaryLevel < PoseidonJmtProfile.BRANCH_LEVELS; binaryLevel++) {
            ZkBool bit = ZkBool.wrap(zk,
                    zk.builder().wrap(childIndex.decomposition().bit(binaryLevel)));
            ZkField sibling = siblings.get(binaryLevel);
            ZkField left = bit.select(sibling, current);
            ZkField right = bit.select(current, sibling);
            current = compress(zk, params, PoseidonJmtProfile.branchDomain(binaryLevel), left, right);
        }
        return current;
    }

    private static ZkField radixBranchWithEmptySiblings(
            ZkContext zk, PoseidonParams params, ZkUInt childIndex, ZkField child) {
        ZkField current = child;
        for (int binaryLevel = 0; binaryLevel < PoseidonJmtProfile.BRANCH_LEVELS; binaryLevel++) {
            ZkBool bit = ZkBool.wrap(zk,
                    zk.builder().wrap(childIndex.decomposition().bit(binaryLevel)));
            ZkField sibling = zk.constant(PoseidonJmtHash.decode(
                    PoseidonJmtCommitments.emptySubtree(binaryLevel)));
            ZkField left = bit.select(sibling, current);
            ZkField right = bit.select(current, sibling);
            current = compress(zk, params, PoseidonJmtProfile.branchDomain(binaryLevel), left, right);
        }
        return current;
    }

    private static ZkField twoLeafBranch(
            ZkContext zk,
            PoseidonParams params,
            ZkUInt firstIndex,
            ZkField firstLeaf,
            ZkUInt secondIndex,
            ZkField secondLeaf) {
        ZkField[] children = new ZkField[PoseidonJmtProfile.RADIX];
        ZkField empty = empty(zk);
        for (int index = 0; index < children.length; index++) {
            ZkBool first = firstIndex.asField().isEqual(zk.constant(index));
            ZkBool second = secondIndex.asField().isEqual(zk.constant(index));
            children[index] = first.select(firstLeaf, second.select(secondLeaf, empty));
        }
        ZkField[] level = children;
        for (int binaryLevel = 0; binaryLevel < PoseidonJmtProfile.BRANCH_LEVELS; binaryLevel++) {
            ZkField[] next = new ZkField[level.length / 2];
            for (int index = 0; index < level.length; index += 2) {
                next[index / 2] = compress(zk, params,
                        PoseidonJmtProfile.branchDomain(binaryLevel), level[index], level[index + 1]);
            }
            level = next;
        }
        return level[0];
    }

    private static ZkField compress(
            ZkContext zk,
            PoseidonParams params,
            BigInteger domain,
            ZkField left,
            ZkField right) {
        return ZkField.wrap(zk, zk.builder().wrap(Poseidon.spongeHash(
                zk.builder().api(), params, zk.builder().constant(domain).variable(),
                left.signal().variable(), right.signal().variable())));
    }

    private static void requireProfile(ZkContext zk, PoseidonParams params) {
        PoseidonJmtProfile.requireSupported(params);
        zk.builder().api().requireField(params.field());
    }

    record Prepared(
            ZkArray<ZkUInt> keyNibbles,
            ZkField key,
            ZkJmtPathProof proof) {}
}
