package org.zeroj.merkle.mpf.poseidon.circuit;

import org.zeroj.api.CurveId;
import org.zeroj.api.R1CSFlatIO;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.annotation.ZkInputMap;
import org.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfBranchWitness;
import org.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfDifferentLeafWitness;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfTrie;
import org.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;
import org.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfValueCommitment;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ZkMpfTransitionCircuitTest {

    // Template names identify semantic/schema versions. ADR-0068 canonical < Fr key-path
    // constraints and derived-boolean deduplication update the exact R1CS pins and require
    // fresh circuit-specific keys.
    @Test
    void transitionTemplateIdentitiesAndReleaseProfilesArePinned() {
        assertAll(
                () -> assertProfile("value-update", 8, 80_931, 510_975, 114,
                        "984d4da5dc29ce4d9ee0de8a572e0e5e3ba350aa75f79e54c76efb2f41d8c300",
                        PoseidonMpfCircuitTemplates::valueUpdate),
                () -> assertProfile("insert-empty", 8, 79_729, 503_901, 113,
                        "112a2b7848dc8a4de818a9476867a239478151ea02e6abc84fd37c83ef94a251",
                        PoseidonMpfCircuitTemplates::insertEmpty),
                () -> assertProfile("insert-different-leaf", 8, 102_577, 629_031, 179,
                        "45adb2a0194e5518341fa3fff4fe8f695a0bf60c2b358c3b70a9c4f2ab308e8e",
                        PoseidonMpfCircuitTemplates::insertDifferentLeaf),
                () -> assertProfile("value-update", 9, 90_381, 572_120, 120,
                        "9bace08aa18e45fa7861265c0a9820b7a179f1da99c7a00b944b2881afdd3df9",
                        PoseidonMpfCircuitTemplates::valueUpdate),
                () -> assertProfile("insert-empty", 9, 89_179, 565_046, 119,
                        "943dadf5b5b83874748d04790c61d72f5295891b43cb0921198bc06ba722f9ea",
                        PoseidonMpfCircuitTemplates::insertEmpty),
                () -> assertProfile("insert-different-leaf", 9, 112_027, 690_176, 185,
                        "9ebc6b9f69d282780c1da9473bb86b855eb1defef278a282a65ccd31cc45c49f",
                        PoseidonMpfCircuitTemplates::insertDifferentLeaf),
                () -> assertProfile("value-update", 12, 118_731, 755_555, 138,
                        "5c5e088da4e39c7ef68f685e09b953eead144fd682b4b7120a646d4aeda80d9e",
                        PoseidonMpfCircuitTemplates::valueUpdate),
                () -> assertProfile("insert-empty", 12, 117_529, 748_481, 137,
                        "5d22c04bf535f54d87c9d765b4a0b0edcc78b0dd275900fdc7410c0b0bc05eca",
                        PoseidonMpfCircuitTemplates::insertEmpty),
                () -> assertProfile("insert-different-leaf", 12, 140_377, 873_611, 203,
                        "b37e1af49bf0f543095fcbbf781fde341f0a1c5e901a474139c0839eac2dda03",
                        PoseidonMpfCircuitTemplates::insertDifferentLeaf));
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
        assertAll(operation + "-s" + bound,
                () -> assertEquals(constraints, r1cs.numConstraints()),
                () -> assertEquals(wires, r1cs.numWires()),
                () -> assertEquals(2, r1cs.numPublicInputs()),
                () -> assertEquals(privateInputs, r1cs.numPrivateInputs()),
                () -> assertEquals(sha256, R1CSFlatIO.canonicalSha256(
                        r1cs.flat(), r1cs.numWires(), r1cs.numPublicInputs())));
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
                    : !steps.isEmpty()
                        && steps.getLast().kind() == PoseidonMpfCodec.KIND_BRANCH;
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
