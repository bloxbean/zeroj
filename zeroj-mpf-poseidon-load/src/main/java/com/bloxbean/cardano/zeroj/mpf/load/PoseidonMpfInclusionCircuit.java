package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMpf;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMpfProof;

/** The exact inclusion circuit benchmarked by the load tool. */
final class PoseidonMpfInclusionCircuit {
    private PoseidonMpfInclusionCircuit() {}

    static CircuitBuilder build(int maxSteps, int maxForkPrefixChunks) {
        var circuit = CircuitBuilder.create("poseidon-mpf-inclusion-s" + maxSteps + "-f" + maxForkPrefixChunks)
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
        declareUIntArray(circuit, "mpf_fork_root", maxSteps);
        declareFieldMatrix(circuit, "mpf_leaf_key_path", maxSteps, ZkMpf.KEY_PATH_NIBBLES);
        declareUIntArray(circuit, "mpf_leaf_value_digest", maxSteps);
        declareUIntArray(circuit, "mpf_valid", maxSteps);
    }

    private static void declareUIntArray(CircuitBuilder circuit, String baseName, int size) {
        for (int i = 0; i < size; i++) circuit.secretVar(baseName + "_" + i);
    }

    private static void declareFieldMatrix(CircuitBuilder circuit, String baseName, int rows, int cols) {
        for (int row = 0; row < rows; row++) {
            for (int col = 0; col < cols; col++) circuit.secretVar(baseName + "_" + row + "_" + col);
        }
    }
}
