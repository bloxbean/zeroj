package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.CircuitParam;
import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit.ZkMpf;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit.ZkMpfBranchProof;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit.ZkMpfInclusion;

@ZKCircuit(
        name = "annotation-mpf-private-registry-inclusion",
        nameTemplate = "annotation-mpf-private-registry-inclusion-s{maxSteps}",
        version = 1)
public class AnnotatedMpfPrivateRegistryInclusion {
    public AnnotatedMpfPrivateRegistryInclusion(@CircuitParam("maxSteps") int maxSteps) {
    }

    @Prove
    void prove(
            ZkContext zk,
            @Public ZkField registryRoot,
            @Public ZkField keyPathNullifier,
            @Secret(name = "key_path")
            @FixedSize(64)
            @UInt(bits = 4)
            ZkArray<ZkUInt> keyPath,
            @Secret(name = "value_commitment")
            ZkField valueCommitment,
            @Secret(name = "mpf_branch_skip")
            @FixedSize(param = "maxSteps")
            @UInt(bits = 8)
            ZkArray<ZkUInt> stepSkip,
            @Secret(name = "mpf_branch_sibling")
            @FixedSize(param = "maxSteps", inner = 4)
            ZkArray<ZkArray<ZkField>> siblings,
            @Secret(name = "mpf_branch_valid")
            @FixedSize(param = "maxSteps")
            ZkArray<ZkBool> valid) {
        ZkMpfBranchProof proof = ZkMpfBranchProof.fromArrays(stepSkip, siblings, valid);

        ZkMpfInclusion.verify(
                zk,
                PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath,
                valueCommitment,
                registryRoot,
                proof);
        ZkMpf.keyPathNullifier(zk, PoseidonParamsBLS12_381T3.INSTANCE, keyPath)
                .assertEqual(keyPathNullifier);
    }
}
