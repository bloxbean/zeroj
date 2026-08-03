package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSFlatIO;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfBranchWitness;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfDifferentLeafWitness;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfTrie;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfValueCommitment;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ZkMpfTransitionCircuitTest {

    @Test
    void transitionTemplateIdentitiesAndReleaseProfilesArePinned() {
        assertProfile("value-update", 8, 82_651, 517_099, 114,
                "b133da39b0a2ae11788284cb1e526efa072f3c30072ef631bf1816622468f8d4",
                PoseidonMpfCircuitTemplates::valueUpdate);
        assertProfile("insert-empty", 8, 81_449, 510_025, 113,
                "1345f5ee54f5840e9c01b127acdf85c8c85e62885c5c324409738446ed0334cc",
                PoseidonMpfCircuitTemplates::insertEmpty);
        assertProfile("insert-different-leaf", 8, 105_646, 640_109, 179,
                "22d88dda857cf61a9292939517d433db71ea0f71460239b5751d0da1022fc15e",
                PoseidonMpfCircuitTemplates::insertDifferentLeaf);
        assertProfile("value-update", 9, 92_353, 578_994, 120,
                "8cfc8421c8941127149b8743205e0190438d21e7f53213a1e8b9be06b280c85a",
                PoseidonMpfCircuitTemplates::valueUpdate);
        assertProfile("insert-empty", 9, 91_151, 571_920, 119,
                "e89dc5b3d7a2cd7d5c4ddf5d0ffa616cff7077c06079d0d9b9c3bcc444e85b28",
                PoseidonMpfCircuitTemplates::insertEmpty);
        assertProfile("insert-different-leaf", 9, 115_348, 702_004, 185,
                "dae03019cfae6005e4f30674cd3dd13dc1d0131e7afb9f63ebd3f88668e3cd01",
                PoseidonMpfCircuitTemplates::insertDifferentLeaf);
        assertProfile("value-update", 12, 121_459, 764_679, 138,
                "cd8fbba73ebd8a3799eb5648fd91399fd38fbe8932c273f9dba40fadeef006c6",
                PoseidonMpfCircuitTemplates::valueUpdate);
        assertProfile("insert-empty", 12, 120_257, 757_605, 137,
                "c94630baec3eab8ee27d3d282598a9d4f1cf162a576a4c44bcf143104afc716a",
                PoseidonMpfCircuitTemplates::insertEmpty);
        assertProfile("insert-different-leaf", 12, 144_454, 887_689, 203,
                "4c6c2150d1be5a60c6a8a10055202cad02663b177393de7bdd55e7877db2d6f5",
                PoseidonMpfCircuitTemplates::insertDifferentLeaf);
    }

    private static void assertProfile(
            String operation,
            int bound,
            int constraints,
            int wires,
            int privateInputs,
            String sha256,
            java.util.function.IntFunction<CircuitBuilder> factory) {
        CircuitBuilder circuit = factory.apply(bound);
        assertEquals("zeroj-mpf-v1-" + operation + "-s" + bound + "-p2",
                circuit.constraintGraph().name());
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertEquals(constraints, r1cs.numConstraints());
        assertEquals(wires, r1cs.numWires());
        assertEquals(2, r1cs.numPublicInputs());
        assertEquals(privateInputs, r1cs.numPrivateInputs());
        assertEquals(sha256, R1CSFlatIO.canonicalSha256(
                r1cs.flat(), r1cs.numWires(), r1cs.numPublicInputs()));
    }

    @Test
    void valueUpdateMatchesCclBeforeAndAfterRootsAndRejectsMutations() {
        PoseidonMpfTrie trie = populated();
        byte[] key = bytes("member-2");
        byte[] oldValue = bytes("active");
        byte[] newValue = bytes("revoked");
        byte[] oldRoot = root(trie);
        byte[] wire = trie.getProofWire(key).orElseThrow();
        int bound = PoseidonMpfCodec.decode(wire).size() + 1;
        PoseidonMpfBranchWitness witness = PoseidonMpfBranchWitness.inclusion(
                oldRoot, key, oldValue, wire, bound);

        trie.put(key, newValue);
        byte[] newRoot = root(trie);
        CircuitBuilder circuit = PoseidonMpfCircuitTemplates.valueUpdate(bound);
        var inputs = new ZkInputMap()
                .put(PoseidonMpfCircuitTemplates.OLD_ROOT, field(oldRoot))
                .put(PoseidonMpfCircuitTemplates.NEW_ROOT, field(newRoot))
                .put(PoseidonMpfCircuitTemplates.OLD_VALUE,
                        PoseidonMpfValueCommitment.field(oldValue))
                .put(PoseidonMpfCircuitTemplates.NEW_VALUE,
                        PoseidonMpfValueCommitment.field(newValue));
        witness.putInto(inputs);
        Map<String, List<BigInteger>> valid = inputs.toWitnessMap();

        assertDoesNotThrow(() -> calculate(circuit, valid));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.OLD_ROOT)));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.NEW_ROOT)));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.OLD_VALUE)));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.NEW_VALUE)));
        Map<String, List<BigInteger>> noOp = with(
                with(valid, PoseidonMpfCircuitTemplates.NEW_VALUE,
                        valid.get(PoseidonMpfCircuitTemplates.OLD_VALUE).getFirst()),
                PoseidonMpfCircuitTemplates.NEW_ROOT,
                valid.get(PoseidonMpfCircuitTemplates.OLD_ROOT).getFirst());
        assertThrows(ArithmeticException.class, () -> calculate(circuit, noOp),
                "a value-update proof must advance the committed state");
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutateNibble(valid, PoseidonMpfCircuitTemplates.KEY_PATH + "_0")));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.BRANCH_SIBLING + "_0_0")));
    }

    @Test
    void emptyChildInsertionMatchesCclCanonicalRoot() {
        PoseidonMpfTrie trie = populated();
        byte[] key = findProof(trie, false);
        byte[] value = bytes("inserted-empty");
        byte[] oldRoot = root(trie);
        byte[] wire = trie.getProofWire(key).orElseThrow();
        int bound = PoseidonMpfCodec.decode(wire).size() + 1;
        PoseidonMpfBranchWitness witness = PoseidonMpfBranchWitness.emptyNonInclusion(
                oldRoot, key, wire, bound);

        trie.put(key, value);
        byte[] newRoot = root(trie);
        CircuitBuilder circuit = PoseidonMpfCircuitTemplates.insertEmpty(bound);
        var inputs = new ZkInputMap()
                .put(PoseidonMpfCircuitTemplates.OLD_ROOT, field(oldRoot))
                .put(PoseidonMpfCircuitTemplates.NEW_ROOT, field(newRoot))
                .put(PoseidonMpfCircuitTemplates.VALUE,
                        PoseidonMpfValueCommitment.field(value));
        witness.putInto(inputs);
        Map<String, List<BigInteger>> valid = inputs.toWitnessMap();

        assertDoesNotThrow(() -> calculate(circuit, valid));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.OLD_ROOT)));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.NEW_ROOT)));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.VALUE)));
    }

    @Test
    void differentLeafInsertionMatchesCclForRootLeafAndNestedLeaf() {
        verifyDifferentLeafInsertion(singleton(), bytes("absent-singleton"), bytes("new-singleton"));

        PoseidonMpfTrie nested = populated();
        byte[] query = findProof(nested, true);
        verifyDifferentLeafInsertion(nested, query, bytes("new-nested"));
    }

    @Test
    void randomizedStateMachineMatchesEveryCclUpdateAndSupportedInsertRoot() {
        int bound = 8;
        CircuitBuilder updateCircuit = PoseidonMpfCircuitTemplates.valueUpdate(bound);
        CircuitBuilder insertEmptyCircuit = PoseidonMpfCircuitTemplates.insertEmpty(bound);
        CircuitBuilder insertLeafCircuit = PoseidonMpfCircuitTemplates.insertDifferentLeaf(bound);
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        var keys = new ArrayList<byte[]>();
        var values = new ArrayList<byte[]>();

        for (int operation = 0; operation < 48; operation++) {
            if (!keys.isEmpty() && operation % 3 == 0) {
                int selected = (operation * 17) % keys.size();
                byte[] key = keys.get(selected);
                byte[] oldValue = values.get(selected);
                byte[] newValue = bytes("state-update-" + operation);
                byte[] oldRoot = root(trie);
                byte[] wire = trie.getProofWire(key).orElseThrow();
                PoseidonMpfBranchWitness witness = PoseidonMpfBranchWitness.inclusion(
                        oldRoot, key, oldValue, wire, bound);
                trie.put(key, newValue);
                values.set(selected, newValue);

                var inputs = new ZkInputMap()
                        .put(PoseidonMpfCircuitTemplates.OLD_ROOT, field(oldRoot))
                        .put(PoseidonMpfCircuitTemplates.NEW_ROOT, field(root(trie)))
                        .put(PoseidonMpfCircuitTemplates.OLD_VALUE,
                                PoseidonMpfValueCommitment.field(oldValue))
                        .put(PoseidonMpfCircuitTemplates.NEW_VALUE,
                                PoseidonMpfValueCommitment.field(newValue));
                witness.putInto(inputs);
                assertDoesNotThrow(() -> calculate(updateCircuit, inputs.toWitnessMap()));
                continue;
            }

            byte[] key = null;
            byte[] wire = null;
            List<PoseidonMpfCodec.Step> steps = null;
            for (int attempt = 0; attempt < 10_000; attempt++) {
                byte[] candidate = bytes("state-insert-" + operation + "-" + attempt);
                byte[] candidateWire = trie.getProofWire(candidate).orElseThrow();
                List<PoseidonMpfCodec.Step> candidateSteps = PoseidonMpfCodec.decode(candidateWire);
                boolean supported = candidateSteps.stream()
                        .allMatch(step -> step.kind() == PoseidonMpfCodec.KIND_BRANCH)
                        || (!candidateSteps.isEmpty()
                        && candidateSteps.getLast().kind() == PoseidonMpfCodec.KIND_LEAF
                        && candidateSteps.subList(0, candidateSteps.size() - 1).stream()
                            .allMatch(step -> step.kind() == PoseidonMpfCodec.KIND_BRANCH));
                if (supported && candidateSteps.size() <= bound + 1) {
                    key = candidate;
                    wire = candidateWire;
                    steps = candidateSteps;
                    break;
                }
            }
            if (key == null || wire == null || steps == null) {
                throw new AssertionError("failed to find supported insertion proof");
            }
            byte[] oldRoot = root(trie);
            byte[] value = bytes("state-value-" + operation);
            boolean empty = steps.stream()
                    .allMatch(step -> step.kind() == PoseidonMpfCodec.KIND_BRANCH);
            PoseidonMpfBranchWitness emptyWitness = empty
                    ? PoseidonMpfBranchWitness.emptyNonInclusion(oldRoot, key, wire, bound)
                    : null;
            PoseidonMpfDifferentLeafWitness leafWitness = empty
                    ? null
                    : PoseidonMpfDifferentLeafWitness.nonInclusion(oldRoot, key, wire, bound);
            trie.put(key, value);
            keys.add(key);
            values.add(value);

            var inputs = new ZkInputMap()
                    .put(PoseidonMpfCircuitTemplates.OLD_ROOT, field(oldRoot))
                    .put(PoseidonMpfCircuitTemplates.NEW_ROOT, field(root(trie)))
                    .put(PoseidonMpfCircuitTemplates.VALUE,
                            PoseidonMpfValueCommitment.field(value));
            if (empty) {
                emptyWitness.putInto(inputs);
                assertDoesNotThrow(() -> calculate(insertEmptyCircuit, inputs.toWitnessMap()));
            } else {
                leafWitness.putInto(inputs);
                assertDoesNotThrow(() -> calculate(insertLeafCircuit, inputs.toWitnessMap()));
            }
        }
    }

    private static void verifyDifferentLeafInsertion(
            PoseidonMpfTrie trie, byte[] query, byte[] value) {
        byte[] oldRoot = root(trie);
        byte[] wire = trie.getProofWire(query).orElseThrow();
        List<PoseidonMpfCodec.Step> steps = PoseidonMpfCodec.decode(wire);
        int branches = steps.size() - 1;
        int bound = branches + 1;
        PoseidonMpfDifferentLeafWitness witness = PoseidonMpfDifferentLeafWitness.nonInclusion(
                oldRoot, query, wire, bound);

        trie.put(query, value);
        byte[] newRoot = root(trie);
        CircuitBuilder circuit = PoseidonMpfCircuitTemplates.insertDifferentLeaf(bound);
        var inputs = new ZkInputMap()
                .put(PoseidonMpfCircuitTemplates.OLD_ROOT, field(oldRoot))
                .put(PoseidonMpfCircuitTemplates.NEW_ROOT, field(newRoot))
                .put(PoseidonMpfCircuitTemplates.VALUE,
                        PoseidonMpfValueCommitment.field(value));
        witness.putInto(inputs);
        Map<String, List<BigInteger>> valid = inputs.toWitnessMap();

        assertDoesNotThrow(() -> calculate(circuit, valid));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.OLD_ROOT)));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.NEW_ROOT)));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.VALUE)));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.CONFLICTING_VALUE)));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutate(valid, PoseidonMpfCircuitTemplates.TERMINAL_SKIP)));
        assertThrows(ArithmeticException.class, () -> calculate(
                circuit, mutateNibble(valid,
                        PoseidonMpfCircuitTemplates.CONFLICTING_PATH + "_0")));
    }

    private static byte[] findProof(PoseidonMpfTrie trie, boolean differentLeaf) {
        for (int index = 0; index < 100_000; index++) {
            byte[] candidate = bytes("transition-missing-" + index);
            List<PoseidonMpfCodec.Step> steps = PoseidonMpfCodec.decode(
                    trie.getProofWire(candidate).orElseThrow());
            boolean matches = differentLeaf
                    ? !steps.isEmpty()
                        && steps.getLast().kind() == PoseidonMpfCodec.KIND_LEAF
                        && steps.size() > 1
                        && steps.subList(0, steps.size() - 1).stream()
                            .allMatch(step -> step.kind() == PoseidonMpfCodec.KIND_BRANCH)
                    : steps.stream().allMatch(step -> step.kind() == PoseidonMpfCodec.KIND_BRANCH);
            if (matches) return candidate;
        }
        throw new AssertionError("failed to find deterministic "
                + (differentLeaf ? "different-leaf" : "empty-child") + " proof");
    }

    private static PoseidonMpfTrie populated() {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("member-1"), bytes("active"));
        trie.put(bytes("member-2"), bytes("active"));
        trie.put(bytes("member-3"), bytes("suspended"));
        trie.put(bytes("member-4"), bytes("active"));
        return trie;
    }

    private static PoseidonMpfTrie singleton() {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("only-key"), bytes("only-value"));
        return trie;
    }

    private static byte[] root(PoseidonMpfTrie trie) {
        byte[] root = trie.getRootHash();
        return root == null ? new byte[PoseidonMpfHash.DIGEST_LENGTH] : root;
    }

    private static BigInteger field(byte[] digest) {
        return PoseidonMpfHash.fieldFromDigestBytes(digest);
    }

    private static void calculate(
            CircuitBuilder circuit, Map<String, List<BigInteger>> inputs) {
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

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
