package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.vds.mpf.MpfTrie;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMpf;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMpfProof;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZkMpfPoseidonGadgetTest {
    private static final int MAX_FORK_PREFIX_CHUNKS = 2;

    @Test
    void keyPathCommitmentMatchesOffChainAdapter() {
        byte[] key = bytes("registry:member:1");
        PoseidonMpfWitness witness = PoseidonMpfCodec.toWitness(key, new byte[]{(byte) 0x80}, 0, 0);
        int[] keyPath = witness.keyPath().stream().mapToInt(BigInteger::intValueExact).toArray();
        BigInteger expectedCommitment = PoseidonMpfHash.keyPathCommitment(
                PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath);
        BigInteger expectedNullifier = PoseidonMpfHash.keyPathNullifier(
                PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath);

        var circuit = CircuitBuilder.create("zk-mpf-key-path-binding")
                .publicVar("commitment")
                .publicVar("nullifier");
        declareUIntArray(circuit, "key_path", ZkMpf.KEY_PATH_NIBBLES);
        circuit.defineSignals(c -> {
            var zk = new ZkContext(c);
            var path = ZkArray.secretUInts(c, "key_path", ZkMpf.KEY_PATH_NIBBLES, 4);
            ZkMpf.keyPathCommitment(zk, PoseidonParamsBLS12_381T3.INSTANCE, path)
                    .assertEqual(ZkField.publicInput(c, "commitment"));
            ZkMpf.keyPathNullifier(zk, PoseidonParamsBLS12_381T3.INSTANCE, path)
                    .assertEqual(ZkField.publicInput(c, "nullifier"));
        });

        var inputs = new ZkInputMap()
                .put("commitment", expectedCommitment)
                .put("nullifier", expectedNullifier)
                .putArray("key_path", witness.keyPath())
                .toWitnessMap();
        assertDoesNotThrow(() -> circuit.calculateWitness(inputs, CurveId.BLS12_381));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));
    }

    @Test
    void verifiesSingleLeafInclusionProofInsideCircuit() {
        MpfTrie trie = PoseidonMpfTrie.inMemory();
        byte[] key = bytes("registry:member:1");
        byte[] value = bytes("active");
        trie.put(key, value);

        byte[] proof = trie.getProofWire(key).orElseThrow();
        PoseidonMpfWitness witness = PoseidonMpfCodec.toWitness(key, proof, 0, 0);
        BigInteger root = PoseidonMpfHash.fieldFromDigestBytes(trie.getRootHash());
        BigInteger valueCommitment = PoseidonMpfValueCommitment.field(value);
        var circuit = inclusionCircuit(0, 0);
        var inputs = new ZkInputMap()
                .put("root", root)
                .put("value_commitment", valueCommitment);
        witness.putInto(inputs);

        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
        assertDoesNotThrow(() -> circuit.compileR1CS(CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                withInput(inputs.toWitnessMap(), "value_commitment", BigInteger.ONE),
                CurveId.BLS12_381));
    }

    @Test
    void verifiesCclBranchInclusionProofInsideCircuit() {
        MpfTrie trie = PoseidonMpfTrie.inMemory();
        byte[] key = bytes("registry:member:1");
        byte[] value = bytes("active");
        trie.put(key, value);
        trie.put(bytes("registry:member:2"), bytes("active"));

        byte[] proof = trie.getProofWire(key).orElseThrow();
        int maxSteps = PoseidonMpfCodec.decode(proof).size();
        assertTrue(maxSteps > 0, "fixture should exercise at least one explicit MPF step");

        PoseidonMpfWitness witness = PoseidonMpfCodec.toWitness(key, proof, maxSteps, MAX_FORK_PREFIX_CHUNKS);
        var circuit = inclusionCircuit(maxSteps, MAX_FORK_PREFIX_CHUNKS);
        var inputs = new ZkInputMap()
                .put("root", PoseidonMpfHash.fieldFromDigestBytes(trie.getRootHash()))
                .put("value_commitment", PoseidonMpfValueCommitment.field(value));
        witness.putInto(inputs);

        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                withInput(inputs.toWitnessMap(), "root", BigInteger.ONE),
                CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                withIncrementedNibble(inputs.toWitnessMap(), "key_path_0"),
                CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                withInput(inputs.toWitnessMap(), "mpf_fork_prefix_length_0", BigInteger.valueOf(65)),
                CurveId.BLS12_381));
    }

    @Test
    void verifiesEmptyTrieExclusionProofInsideCircuit() {
        MpfTrie trie = PoseidonMpfTrie.inMemory();
        byte[] missing = bytes("registry:missing");
        byte[] proof = trie.getProofWire(missing).orElseThrow();
        PoseidonMpfWitness witness = PoseidonMpfCodec.toWitness(missing, proof, 0, 0);

        var circuit = exclusionCircuit(0, 0);
        var inputs = new ZkInputMap().put("root", BigInteger.ZERO);
        witness.putInto(inputs);

        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
    }

    @Test
    void verifiesCclExclusionProofInsideCircuit() {
        MpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("registry:member:1"), bytes("active"));
        trie.put(bytes("registry:member:2"), bytes("active"));
        trie.put(bytes("registry:member:3"), bytes("suspended"));

        byte[] missing = bytes("registry:member:9");
        byte[] proof = trie.getProofWire(missing).orElseThrow();
        int maxSteps = PoseidonMpfCodec.decode(proof).size();
        assertTrue(maxSteps > 0, "fixture should exercise at least one explicit MPF step");

        PoseidonMpfWitness witness = PoseidonMpfCodec.toWitness(missing, proof, maxSteps, MAX_FORK_PREFIX_CHUNKS);
        var circuit = exclusionCircuit(maxSteps, MAX_FORK_PREFIX_CHUNKS);
        var inputs = new ZkInputMap()
                .put("root", PoseidonMpfHash.fieldFromDigestBytes(trie.getRootHash()));
        witness.putInto(inputs);

        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                withInput(inputs.toWitnessMap(), "root", BigInteger.ONE),
                CurveId.BLS12_381));
    }

    @Test
    void rejectsForgedTerminalForkExclusionProof() {
        var circuit = exclusionCircuit(1, MAX_FORK_PREFIX_CHUNKS);
        BigInteger forgedRoot = BigInteger.valueOf(12_345);
        var inputs = new ZkInputMap()
                .put("root", forgedRoot)
                .putArray("key_path", repeated(BigInteger.ZERO, ZkMpf.KEY_PATH_NIBBLES))
                .putArray("mpf_kind", List.of(BigInteger.ONE))
                .putArray("mpf_skip", List.of(BigInteger.ZERO))
                .putNestedArray("mpf_neighbor", List.of(repeated(BigInteger.ZERO, 4)))
                .putArray("mpf_neighbor_nibble", List.of(BigInteger.ONE))
                .putArray("mpf_fork_prefix_length", List.of(BigInteger.ZERO))
                .putNestedArray("mpf_fork_prefix", List.of(repeated(BigInteger.ZERO, MAX_FORK_PREFIX_CHUNKS)))
                .putArray("mpf_fork_root", List.of(forgedRoot))
                .putNestedArray("mpf_leaf_key_path", List.of(repeated(BigInteger.ZERO, ZkMpf.KEY_PATH_NIBBLES)))
                .putArray("mpf_leaf_value_digest", List.of(BigInteger.ZERO))
                .putArray("mpf_valid", List.of(BigInteger.ONE));

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                inputs.toWitnessMap(),
                CurveId.BLS12_381));
    }

    @Test
    void rejectsProofArraysWithWrongBitWidths() {
        var circuit = CircuitBuilder.create("zk-mpf-invalid-widths");
        declareUIntArray(circuit, "mpf_kind", 1);
        declareUIntArray(circuit, "mpf_skip", 1);
        declareFieldMatrix(circuit, "mpf_neighbor", 1, 4);
        declareUIntArray(circuit, "mpf_neighbor_nibble", 1);
        declareUIntArray(circuit, "mpf_fork_prefix_length", 1);
        declareFieldMatrix(circuit, "mpf_fork_prefix", 1, MAX_FORK_PREFIX_CHUNKS);
        declareFieldArray(circuit, "mpf_fork_root", 1);
        declareUIntMatrix(circuit, "mpf_leaf_key_path", 1, ZkMpf.KEY_PATH_NIBBLES);
        declareFieldArray(circuit, "mpf_leaf_value_digest", 1);
        declareBoolArray(circuit, "mpf_valid", 1);

        assertThrows(IllegalArgumentException.class, () -> circuit.defineSignals(c -> ZkMpfProof.fromArrays(
                ZkArray.secretUInts(c, "mpf_kind", 1, 3),
                ZkArray.secretUInts(c, "mpf_skip", 1, 8),
                ZkArray.secretFieldMatrix(c, "mpf_neighbor", 1, 4),
                ZkArray.secretUInts(c, "mpf_neighbor_nibble", 1, 4),
                ZkArray.secretUInts(c, "mpf_fork_prefix_length", 1, 8),
                ZkArray.secretFieldMatrix(c, "mpf_fork_prefix", 1, MAX_FORK_PREFIX_CHUNKS),
                ZkArray.secretFields(c, "mpf_fork_root", 1),
                ZkArray.secretUIntMatrix(c, "mpf_leaf_key_path", 1, ZkMpf.KEY_PATH_NIBBLES, 4),
                ZkArray.secretFields(c, "mpf_leaf_value_digest", 1),
                ZkArray.secretBools(c, "mpf_valid", 1))));
    }

    private static CircuitBuilder inclusionCircuit(int maxSteps, int maxForkPrefixChunks) {
        var circuit = CircuitBuilder.create("zk-mpf-inclusion")
                .publicVar("root")
                .secretVar("value_commitment");
        declareUIntArray(circuit, "key_path", ZkMpf.KEY_PATH_NIBBLES);
        declareProofArrays(circuit, maxSteps, maxForkPrefixChunks);
        return circuit.defineSignals(c -> {
            var zk = new ZkContext(c);
            ZkMpf.verifyInclusionPoseidon(
                    zk,
                    PoseidonParamsBLS12_381T3.INSTANCE,
                    ZkArray.secretUInts(c, "key_path", ZkMpf.KEY_PATH_NIBBLES, 4),
                    ZkField.secret(c, "value_commitment"),
                    ZkField.publicInput(c, "root"),
                    proof(c, maxSteps, maxForkPrefixChunks));
        });
    }

    private static CircuitBuilder exclusionCircuit(int maxSteps, int maxForkPrefixChunks) {
        var circuit = CircuitBuilder.create("zk-mpf-exclusion")
                .publicVar("root");
        declareUIntArray(circuit, "key_path", ZkMpf.KEY_PATH_NIBBLES);
        declareProofArrays(circuit, maxSteps, maxForkPrefixChunks);
        return circuit.defineSignals(c -> {
            var zk = new ZkContext(c);
            ZkMpf.verifyExclusionPoseidon(
                    zk,
                    PoseidonParamsBLS12_381T3.INSTANCE,
                    ZkArray.secretUInts(c, "key_path", ZkMpf.KEY_PATH_NIBBLES, 4),
                    ZkField.publicInput(c, "root"),
                    proof(c, maxSteps, maxForkPrefixChunks));
        });
    }

    private static ZkMpfProof proof(SignalBuilder c, int maxSteps, int maxForkPrefixChunks) {
        return ZkMpfProof.fromArrays(
                ZkArray.secretUInts(c, "mpf_kind", maxSteps, 2),
                ZkArray.secretUInts(c, "mpf_skip", maxSteps, 8),
                ZkArray.secretFieldMatrix(c, "mpf_neighbor", maxSteps, 4),
                ZkArray.secretUInts(c, "mpf_neighbor_nibble", maxSteps, 4),
                ZkArray.secretUInts(c, "mpf_fork_prefix_length", maxSteps, 8),
                ZkArray.secretFieldMatrix(c, "mpf_fork_prefix", maxSteps, maxForkPrefixChunks),
                ZkArray.secretFields(c, "mpf_fork_root", maxSteps),
                ZkArray.secretUIntMatrix(c, "mpf_leaf_key_path", maxSteps, ZkMpf.KEY_PATH_NIBBLES, 4),
                ZkArray.secretFields(c, "mpf_leaf_value_digest", maxSteps),
                ZkArray.secretBools(c, "mpf_valid", maxSteps));
    }

    private static void declareProofArrays(CircuitBuilder circuit, int maxSteps, int maxForkPrefixChunks) {
        declareUIntArray(circuit, "mpf_kind", maxSteps);
        declareUIntArray(circuit, "mpf_skip", maxSteps);
        declareFieldMatrix(circuit, "mpf_neighbor", maxSteps, 4);
        declareUIntArray(circuit, "mpf_neighbor_nibble", maxSteps);
        declareUIntArray(circuit, "mpf_fork_prefix_length", maxSteps);
        declareFieldMatrix(circuit, "mpf_fork_prefix", maxSteps, maxForkPrefixChunks);
        declareFieldArray(circuit, "mpf_fork_root", maxSteps);
        declareUIntMatrix(circuit, "mpf_leaf_key_path", maxSteps, ZkMpf.KEY_PATH_NIBBLES);
        declareFieldArray(circuit, "mpf_leaf_value_digest", maxSteps);
        declareBoolArray(circuit, "mpf_valid", maxSteps);
    }

    private static void declareUIntArray(CircuitBuilder circuit, String baseName, int size) {
        for (int i = 0; i < size; i++) {
            circuit.secretVar(baseName + "_" + i);
        }
    }

    private static void declareBoolArray(CircuitBuilder circuit, String baseName, int size) {
        declareUIntArray(circuit, baseName, size);
    }

    private static void declareFieldArray(CircuitBuilder circuit, String baseName, int size) {
        declareUIntArray(circuit, baseName, size);
    }

    private static void declareUIntMatrix(CircuitBuilder circuit, String baseName, int rows, int cols) {
        declareFieldMatrix(circuit, baseName, rows, cols);
    }

    private static void declareFieldMatrix(CircuitBuilder circuit, String baseName, int rows, int cols) {
        for (int row = 0; row < rows; row++) {
            for (int col = 0; col < cols; col++) {
                circuit.secretVar(baseName + "_" + row + "_" + col);
            }
        }
    }

    private static Map<String, List<BigInteger>> withInput(
            Map<String, List<BigInteger>> inputs,
            String name,
            BigInteger value) {
        var copy = new LinkedHashMap<>(inputs);
        copy.put(name, List.of(value));
        return Map.copyOf(copy);
    }

    private static Map<String, List<BigInteger>> withIncrementedNibble(
            Map<String, List<BigInteger>> inputs,
            String name) {
        BigInteger current = inputs.get(name).getFirst();
        return withInput(inputs, name, current.add(BigInteger.ONE).mod(BigInteger.valueOf(16)));
    }

    private static List<BigInteger> repeated(BigInteger value, int size) {
        return java.util.Collections.nCopies(size, value);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
