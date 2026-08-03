package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.vds.core.NibblePath;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSFlatIO;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfBranchWitness;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfDifferentLeafWitness;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCommitmentScheme;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfTrie;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfValueCommitment;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ZkMpfOperationCircuitTest {

    @Test
    void inclusionAcceptsCclWitnessAndRejectsRootKeyValueSiblingAndPaddingMutations() {
        PoseidonMpfTrie trie = populated();
        byte[] key = bytes("member-1");
        byte[] value = bytes("active");
        byte[] wire = trie.getProofWire(key).orElseThrow();
        int branches = PoseidonMpfCodec.decode(wire).size();
        int bound = branches + 2;
        var witness = PoseidonMpfBranchWitness.inclusion(
                trie.getRootHash(), key, value, wire, bound);
        var circuit = inclusionCircuit(bound);
        var inputs = new ZkInputMap()
                .put(PoseidonMpfCircuitTemplates.ROOT, field(trie.getRootHash()))
                .put(PoseidonMpfCircuitTemplates.VALUE, PoseidonMpfValueCommitment.field(value));
        witness.putInto(inputs);
        Map<String, List<BigInteger>> valid = inputs.toWitnessMap();

        assertDoesNotThrow(() -> circuit.calculateWitness(valid, CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> calculate(circuit,
                mutate(valid, PoseidonMpfCircuitTemplates.ROOT)));
        assertThrows(ArithmeticException.class, () -> calculate(circuit,
                mutate(valid, PoseidonMpfCircuitTemplates.VALUE)));
        assertThrows(ArithmeticException.class, () -> calculate(circuit, mutateNibble(valid, "key_path_0")));
        assertThrows(ArithmeticException.class, () -> calculate(circuit,
                mutate(valid, "mpf_branch_sibling_0_0")));
        assertThrows(ArithmeticException.class, () -> calculate(circuit,
                with(valid, "mpf_branch_valid_" + branches, BigInteger.ONE)));
        assertThrows(ArithmeticException.class, () -> calculate(circuit,
                with(valid, "mpf_branch_skip_" + branches, BigInteger.ONE)));
        assertThrows(ArithmeticException.class, () -> calculate(circuit,
                with(valid, "mpf_branch_sibling_" + branches + "_0", BigInteger.ONE)));
    }

    @Test
    void bothNonInclusionCircuitsAcceptOnlyTheirOwnAuthenticatedTerminalForm() {
        PoseidonMpfTrie trie = populated();
        byte[] emptyKey = findMissingBranch(trie);
        byte[] emptyWire = trie.getProofWire(emptyKey).orElseThrow();
        int emptyBranches = PoseidonMpfCodec.decode(emptyWire).size();
        var emptyWitness = PoseidonMpfBranchWitness.emptyNonInclusion(
                trie.getRootHash(), emptyKey, emptyWire, emptyBranches + 1);
        var emptyCircuit = emptyCircuit(emptyBranches + 1);
        var emptyInputs = new ZkInputMap().put("root", field(trie.getRootHash()));
        emptyWitness.putInto(emptyInputs);
        Map<String, List<BigInteger>> validEmpty = emptyInputs.toWitnessMap();
        assertDoesNotThrow(() -> calculate(emptyCircuit, validEmpty));
        assertThrows(ArithmeticException.class, () -> calculate(
                emptyCircuit, mutateNibble(validEmpty, "key_path_0")));
        assertThrows(ArithmeticException.class, () -> calculate(
                emptyCircuit, mutate(validEmpty, "root")));

        PoseidonMpfTrie one = PoseidonMpfTrie.inMemory();
        one.put(bytes("only-key"), bytes("only-value"));
        byte[] query = bytes("absent-key");
        byte[] wire = one.getProofWire(query).orElseThrow();
        var different = PoseidonMpfDifferentLeafWitness.nonInclusion(
                one.getRootHash(), query, wire, 1);
        var differentCircuit = differentLeafCircuit(1);
        var differentInputs = new ZkInputMap().put("root", field(one.getRootHash()));
        different.putInto(differentInputs);
        Map<String, List<BigInteger>> validDifferent = differentInputs.toWitnessMap();
        assertDoesNotThrow(() -> calculate(differentCircuit, validDifferent));
        assertThrows(ArithmeticException.class, () -> calculate(
                differentCircuit, mutate(validDifferent, "mpf_conflicting_value")));
        assertThrows(ArithmeticException.class, () -> calculate(
                differentCircuit, mutateNibble(validDifferent, "mpf_conflicting_leaf_path_0")));
        assertThrows(ArithmeticException.class, () -> calculate(
                differentCircuit, mutate(validDifferent, "mpf_terminal_skip")));

        var wrongEmptyCircuit = emptyCircuit(1);
        var branchOnly = new ZkInputMap().put("root", field(one.getRootHash()));
        different.branches().putInto(branchOnly);
        assertThrows(ArithmeticException.class, () -> calculate(
                wrongEmptyCircuit, branchOnly.toWitnessMap()));
    }

    @Test
    void specializedInclusionIsMateriallySmallerThanFullSemanticsAtSameBound() {
        int specialized = inclusionCircuit(1).compileR1CS(CurveId.BLS12_381).numConstraints();
        int full = fullInclusionCircuit(1).compileR1CS(CurveId.BLS12_381).numConstraints();
        assertTrue(specialized <= 12_000,
                () -> "S1 specialized constraint budget regressed: " + specialized);
        assertTrue(specialized < full,
                () -> "specialized=" + specialized + ", full=" + full);
        assertTrue(specialized * 100L <= full * 80L,
                () -> "specialization must remove at least 20%: specialized="
                        + specialized + ", full=" + full);
    }

    @Test
    void randomizedCclInclusionsDifferentiallyMatchTheSpecializedCircuit() {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        var entries = new ArrayList<Map.Entry<byte[], byte[]>>();
        int maxBranches = 0;
        for (int index = 0; index < 128; index++) {
            byte[] key = bytes("differential-key-" + index);
            byte[] value = bytes("differential-value-" + (index * 17L));
            trie.put(key, value);
            entries.add(Map.entry(key, value));
        }
        for (var entry : entries) {
            maxBranches = Math.max(maxBranches,
                    PoseidonMpfCodec.decode(trie.getProofWire(entry.getKey()).orElseThrow()).size());
        }
        int bound = maxBranches + 1;
        CircuitBuilder circuit = inclusionCircuit(bound);
        BigInteger root = field(trie.getRootHash());
        for (var entry : entries) {
            byte[] wire = trie.getProofWire(entry.getKey()).orElseThrow();
            var witness = PoseidonMpfBranchWitness.inclusion(
                    trie.getRootHash(), entry.getKey(), entry.getValue(), wire, bound);
            var inputs = new ZkInputMap()
                    .put(PoseidonMpfCircuitTemplates.ROOT, root)
                    .put(PoseidonMpfCircuitTemplates.VALUE,
                            PoseidonMpfValueCommitment.field(entry.getValue()));
            witness.putInto(inputs);
            assertDoesNotThrow(() -> calculate(circuit, inputs.toWitnessMap()));
        }
    }

    @Test
    void branchProfileConstraintCountsArePinned() {
        int[][] expected = {
                {0, 3_575, 14_831, 65},
                {1, 9_699, 48_429, 71},
                {3, 21_433, 115_559, 83},
                {8, 50_768, 283_384, 113},
                {9, 56_635, 316_949, 119},
                {12, 74_236, 417_644, 137},
                {64, 379_321, 2_163_024, 449}
        };
        String[] digests = {
                "72bbab48083b0f44e347a21b7310c948e8f2f558d68260b3848400d4cee16e07",
                "2ce7c0a3ba476fe849ef1add054223e957ba7c62ecd615115d706f6f77033caf",
                "022a7ee4f514c07b285f35c1430774b145fc7ca67e779d51c4af688953585ee6",
                "e3a9fe7f2bcce454395a5bb0f2fac12e3fd99065d6b6c82325d7cdce16c1b74c",
                "540279f349be215c837245a888934dd507bbfecf21c4a66146a3febcd33d427d",
                "84975e990f84da821650147a9e6b8f5fdd2b67b20ce06c31ecb490411915bf00",
                "9505d73edcbb136c0783636eb45158b8a2b625bf05b6427716071a264ce5a17a"
        };
        for (int index = 0; index < expected.length; index++) {
            int[] profile = expected[index];
            String digest = digests[index];
            int bound = profile[0];
            var r1cs = inclusionCircuit(bound).compileR1CS(CurveId.BLS12_381);
            assertAll("S" + bound,
                    () -> assertEquals(profile[1], r1cs.numConstraints()),
                    () -> assertEquals(profile[2], r1cs.numWires()),
                    () -> assertEquals(profile[3], r1cs.numPrivateInputs()),
                    () -> assertEquals(1, r1cs.numPublicInputs()),
                    () -> assertEquals(digest, R1CSFlatIO.canonicalSha256(
                            r1cs.flat(), r1cs.numWires(), r1cs.numPublicInputs())));
        }
    }

    @Test
    void canonicalTemplateIdentityBindsOperationAndExactR1cs() {
        CircuitBuilder canonical = PoseidonMpfCircuitTemplates.inclusion(1);
        CircuitBuilder reference = PoseidonMpfCircuitTemplates.fullSemanticsInclusion(1);
        assertEquals("zeroj-mpf-v1-inclusion-s1-p1", canonical.constraintGraph().name());
        assertEquals("zeroj-mpf-v1-full-semantics-inclusion-s1-p1",
                reference.constraintGraph().name());
        var canonicalR1cs = canonical.compileR1CS(CurveId.BLS12_381);
        var referenceR1cs = reference.compileR1CS(CurveId.BLS12_381);
        String canonicalDigest = R1CSFlatIO.canonicalSha256(
                canonicalR1cs.flat(), canonicalR1cs.numWires(), canonicalR1cs.numPublicInputs());
        String referenceDigest = R1CSFlatIO.canonicalSha256(
                referenceR1cs.flat(), referenceR1cs.numWires(), referenceR1cs.numPublicInputs());
        assertNotEquals(canonicalDigest, referenceDigest);
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfCircuitTemplates.inclusion(-1));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonMpfCircuitTemplates.inclusion(65));
        assertExactProfile(
                PoseidonMpfCircuitTemplates.nonInclusionEmpty(8),
                "zeroj-mpf-v1-non-inclusion-empty-s8-p1",
                47_397, 269_978, 112,
                "e59025c48cf71b4fb17ce03045944307e43687f60b4dab61916b2f414dcdc46d");
        assertExactProfile(
                PoseidonMpfCircuitTemplates.nonInclusionDifferentLeaf(8),
                "zeroj-mpf-v1-non-inclusion-different-leaf-s8-p1",
                54_766, 291_445, 178,
                "1184ef318658e8b63d752b0e05fb1ab1339a1438adcc689fee6e244484849873");
    }

    private static void assertExactProfile(
            CircuitBuilder circuit,
            String templateId,
            int constraints,
            int wires,
            int privateInputs,
            String sha256) {
        assertEquals(templateId, circuit.constraintGraph().name());
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertEquals(constraints, r1cs.numConstraints());
        assertEquals(wires, r1cs.numWires());
        assertEquals(1, r1cs.numPublicInputs());
        assertEquals(privateInputs, r1cs.numPrivateInputs());
        assertEquals(sha256, R1CSFlatIO.canonicalSha256(
                r1cs.flat(), r1cs.numWires(), r1cs.numPublicInputs()));
    }

    @Test
    void streamingPathPackingMatchesHostAtEverySkipAndWithPadding() {
        int[] path = deterministicPath();
        BigInteger value = BigInteger.valueOf(0x123456L);
        List<BigInteger> keyPath = ints(path);
        List<BigInteger> emptySiblings = emptyBinarySiblings();
        CircuitBuilder exact = inclusionCircuit(1);
        CircuitBuilder padded = inclusionCircuit(3);
        PoseidonMpfCommitmentScheme commitments = new PoseidonMpfCommitmentScheme();
        for (int skip = 0; skip < 64; skip++) {
            byte[] leaf = commitments.commitLeaf(
                    NibblePath.fromRange(path, skip + 1, path.length - skip - 1),
                    PoseidonMpfHash.toDigestBytes(value));
            byte[][] children = new byte[16][];
            children[path[skip]] = leaf;
            byte[] root = commitments.commitBranch(
                    NibblePath.fromRange(path, 0, skip), children, null);

            var base = new ZkInputMap()
                    .put(PoseidonMpfCircuitTemplates.ROOT, field(root))
                    .put(PoseidonMpfCircuitTemplates.VALUE, value)
                    .putArray(PoseidonMpfCircuitTemplates.KEY_PATH, keyPath);
            base.putArray(PoseidonMpfCircuitTemplates.BRANCH_SKIP,
                    List.of(BigInteger.valueOf(skip)));
            base.putNestedArray(PoseidonMpfCircuitTemplates.BRANCH_SIBLING,
                    List.of(emptySiblings));
            base.putArray(PoseidonMpfCircuitTemplates.BRANCH_VALID, List.of(BigInteger.ONE));
            assertDoesNotThrow(() -> calculate(exact, base.toWitnessMap()), "exact skip=" + skip);

            var withPadding = new ZkInputMap()
                    .put(PoseidonMpfCircuitTemplates.ROOT, field(root))
                    .put(PoseidonMpfCircuitTemplates.VALUE, value)
                    .putArray(PoseidonMpfCircuitTemplates.KEY_PATH, keyPath)
                    .putArray(PoseidonMpfCircuitTemplates.BRANCH_SKIP,
                            List.of(BigInteger.valueOf(skip), BigInteger.ZERO, BigInteger.ZERO))
                    .putNestedArray(PoseidonMpfCircuitTemplates.BRANCH_SIBLING,
                            List.of(emptySiblings, zeros(4), zeros(4)))
                    .putArray(PoseidonMpfCircuitTemplates.BRANCH_VALID,
                            List.of(BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO));
            assertDoesNotThrow(() -> calculate(padded, withPadding.toWitnessMap()),
                    "padded skip=" + skip);
        }
    }

    @Test
    void zeroStepTerminalsAndMaximumDepthAreConstrained() {
        PoseidonMpfTrie empty = PoseidonMpfTrie.inMemory();
        byte[] emptyKey = bytes("empty-root-query");
        byte[] emptyWire = empty.getProofWire(emptyKey).orElseThrow();
        var emptyWitness = PoseidonMpfBranchWitness.emptyNonInclusion(
                new byte[32], emptyKey, emptyWire, 0);
        var emptyInputs = new ZkInputMap().put("root", BigInteger.ZERO);
        emptyWitness.putInto(emptyInputs);
        assertDoesNotThrow(() -> calculate(emptyCircuit(0), emptyInputs.toWitnessMap()));

        PoseidonMpfTrie singleton = PoseidonMpfTrie.inMemory();
        singleton.put(bytes("terminal-key"), bytes("terminal-value"));
        byte[] absent = bytes("different-terminal-query");
        var different = PoseidonMpfDifferentLeafWitness.nonInclusion(
                singleton.getRootHash(), absent, singleton.getProofWire(absent).orElseThrow(), 0);
        var differentInputs = new ZkInputMap().put("root", field(singleton.getRootHash()));
        different.putInto(differentInputs);
        assertDoesNotThrow(() -> calculate(
                differentLeafCircuit(0), differentInputs.toWitnessMap()));

        int[] path = deterministicPath();
        BigInteger value = BigInteger.valueOf(77);
        PoseidonMpfCommitmentScheme commitments = new PoseidonMpfCommitmentScheme();
        byte[] current = commitments.commitLeaf(NibblePath.EMPTY, PoseidonMpfHash.toDigestBytes(value));
        List<BigInteger> siblings = emptyBinarySiblings();
        for (int level = 63; level >= 0; level--) {
            byte[][] children = new byte[16][];
            children[path[level]] = current;
            current = commitments.commitBranch(NibblePath.EMPTY, children, null);
        }
        var maximum = new ZkInputMap()
                .put("root", field(current))
                .put("value_commitment", value)
                .putArray("key_path", ints(path))
                .putArray("mpf_branch_skip", zeros(64))
                .putNestedArray("mpf_branch_sibling",
                        java.util.Collections.nCopies(64, siblings))
                .putArray("mpf_branch_valid",
                        java.util.Collections.nCopies(64, BigInteger.ONE));
        assertDoesNotThrow(() -> calculate(inclusionCircuit(64), maximum.toWitnessMap()));
        assertThrows(ArithmeticException.class, () -> calculate(inclusionCircuit(64),
                with(maximum.toWitnessMap(), "mpf_branch_valid_63", BigInteger.ZERO)));
    }

    private static CircuitBuilder inclusionCircuit(int bound) {
        return PoseidonMpfCircuitTemplates.inclusion(bound);
    }

    private static CircuitBuilder emptyCircuit(int bound) {
        return PoseidonMpfCircuitTemplates.nonInclusionEmpty(bound);
    }

    private static CircuitBuilder differentLeafCircuit(int bound) {
        return PoseidonMpfCircuitTemplates.nonInclusionDifferentLeaf(bound);
    }

    private static CircuitBuilder fullInclusionCircuit(int bound) {
        var circuit = CircuitBuilder.create("zk-mpf-full-inclusion-s" + bound)
                .publicVar("root").secretVar("value");
        declareArray(circuit, "key_path", 64);
        declareArray(circuit, "kind", bound);
        declareArray(circuit, "skip", bound);
        declareMatrix(circuit, "neighbor", bound, 4);
        declareArray(circuit, "neighbor_nibble", bound);
        declareArray(circuit, "fork_prefix_length", bound);
        declareMatrix(circuit, "fork_prefix", bound, 2);
        declareArray(circuit, "fork_root", bound);
        declareMatrix(circuit, "leaf_path", bound, 64);
        declareArray(circuit, "leaf_value", bound);
        declareArray(circuit, "valid", bound);
        return circuit.defineSignals(c -> ZkMpf.verifyInclusionPoseidon(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE, path(c),
                ZkField.secret(c, "value"), ZkField.publicInput(c, "root"),
                ZkMpfProof.fromArrays(
                        ZkArray.secretUInts(c, "kind", bound, 2),
                        ZkArray.secretUInts(c, "skip", bound, 8),
                        ZkArray.secretFieldMatrix(c, "neighbor", bound, 4),
                        ZkArray.secretUInts(c, "neighbor_nibble", bound, 4),
                        ZkArray.secretUInts(c, "fork_prefix_length", bound, 8),
                        ZkArray.secretFieldMatrix(c, "fork_prefix", bound, 2),
                        ZkArray.secretFields(c, "fork_root", bound),
                        ZkArray.secretUIntMatrix(c, "leaf_path", bound, 64, 4),
                        ZkArray.secretFields(c, "leaf_value", bound),
                        ZkArray.secretBools(c, "valid", bound))));
    }

    private static ZkArray<com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt> path(SignalBuilder c) {
        return ZkArray.secretUInts(c, "key_path", 64, 4);
    }

    private static ZkMpfBranchProof branchProof(SignalBuilder c, int bound) {
        return ZkMpfBranchProof.fromArrays(
                ZkArray.secretUInts(c, "mpf_branch_skip", bound, 8),
                ZkArray.secretFieldMatrix(c, "mpf_branch_sibling", bound, 4),
                ZkArray.secretBools(c, "mpf_branch_valid", bound));
    }

    private static void declareBranchInputs(CircuitBuilder circuit, int bound) {
        declareArray(circuit, "key_path", 64);
        declareArray(circuit, "mpf_branch_skip", bound);
        declareMatrix(circuit, "mpf_branch_sibling", bound, 4);
        declareArray(circuit, "mpf_branch_valid", bound);
    }

    private static void declareArray(CircuitBuilder circuit, String name, int size) {
        for (int index = 0; index < size; index++) circuit.secretVar(name + "_" + index);
    }

    private static void declareMatrix(CircuitBuilder circuit, String name, int rows, int columns) {
        for (int row = 0; row < rows; row++) {
            for (int column = 0; column < columns; column++) {
                circuit.secretVar(name + "_" + row + "_" + column);
            }
        }
    }

    private static void calculate(CircuitBuilder circuit, Map<String, List<BigInteger>> inputs) {
        circuit.calculateWitness(inputs, CurveId.BLS12_381);
    }

    private static Map<String, List<BigInteger>> mutate(
            Map<String, List<BigInteger>> inputs, String name) {
        return with(inputs, name, inputs.get(name).getFirst().add(BigInteger.ONE));
    }

    private static Map<String, List<BigInteger>> mutateNibble(
            Map<String, List<BigInteger>> inputs, String name) {
        return with(inputs, name,
                inputs.get(name).getFirst().add(BigInteger.ONE).mod(BigInteger.valueOf(16)));
    }

    private static Map<String, List<BigInteger>> with(
            Map<String, List<BigInteger>> inputs, String name, BigInteger value) {
        var copy = new LinkedHashMap<>(inputs);
        copy.put(name, List.of(value));
        return Map.copyOf(copy);
    }

    private static PoseidonMpfTrie populated() {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("member-1"), bytes("active"));
        trie.put(bytes("member-2"), bytes("active"));
        trie.put(bytes("member-3"), bytes("suspended"));
        return trie;
    }

    private static byte[] findMissingBranch(PoseidonMpfTrie trie) {
        for (int index = 0; index < 10_000; index++) {
            byte[] query = bytes("missing-" + index);
            var steps = PoseidonMpfCodec.decode(trie.getProofWire(query).orElseThrow());
            if (steps.stream().allMatch(step -> step.kind() == PoseidonMpfCodec.KIND_BRANCH)) {
                return query;
            }
        }
        throw new AssertionError("failed to find deterministic missing-branch proof");
    }

    private static BigInteger field(byte[] digest) {
        return PoseidonMpfHash.fieldFromDigestBytes(digest);
    }

    private static int[] deterministicPath() {
        int[] path = new int[64];
        for (int index = 0; index < path.length; index++) path[index] = index & 15;
        return path;
    }

    private static List<BigInteger> ints(int[] values) {
        return java.util.Arrays.stream(values).mapToObj(BigInteger::valueOf).toList();
    }

    private static List<BigInteger> zeros(int size) {
        return java.util.Collections.nCopies(size, BigInteger.ZERO);
    }

    private static List<BigInteger> emptyBinarySiblings() {
        List<BigInteger> siblings = new ArrayList<>(4);
        byte[] current = new byte[32];
        siblings.add(BigInteger.ZERO);
        for (int level = 1; level < 4; level++) {
            current = PoseidonMpfHash.digestPair(
                    PoseidonParamsBLS12_381T3.INSTANCE, current, current);
            siblings.add(field(current));
        }
        java.util.Collections.reverse(siblings);
        return List.copyOf(siblings);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
