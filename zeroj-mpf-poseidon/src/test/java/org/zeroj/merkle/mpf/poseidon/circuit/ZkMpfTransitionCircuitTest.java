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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ZkMpfTransitionCircuitTest {

    // Template names identify semantic/schema versions. ADR-0063 direct Boolean lowering
    // changes the exact R1CS pins and requires fresh circuit-specific keys.
    @Test
    void transitionTemplateIdentitiesAndReleaseProfilesArePinned() {
        assertProfile("value-update", 8, 80_119, 509_503, 114,
                "2bdcd87c53a3ad649cb27c28a3c4caf1d66c5efc37044cd69e737ed991ebb4e0",
                PoseidonMpfCircuitTemplates::valueUpdate);
        assertProfile("insert-empty", 8, 78_917, 502_429, 113,
                "48a0267e615a670218de76bb08304699efd4b263bdfc67896acd7ddffc12002c",
                PoseidonMpfCircuitTemplates::insertEmpty);
        assertProfile("insert-different-leaf", 8, 100_973, 626_087, 179,
                "d096de1decc20bb4df12da79a54aa8facc61462e1031bd03ead0b5bbd1c4576d",
                PoseidonMpfCircuitTemplates::insertDifferentLeaf);
        assertProfile("value-update", 9, 89_571, 570_648, 120,
                "dd4ef446732a67c57a8cf97d3f320eca6d76f227ad42625b5f80770c2bd1eb04",
                PoseidonMpfCircuitTemplates::valueUpdate);
        assertProfile("insert-empty", 9, 88_369, 563_574, 119,
                "d8d132110e41bfc6b646f2775d4ad7d1abb18fd631760a8f76b4ba82eb870ca2",
                PoseidonMpfCircuitTemplates::insertEmpty);
        assertProfile("insert-different-leaf", 9, 110_425, 687_232, 185,
                "1627ee290b5f9f09056152fd1a9eb222d1d2e1f0fef421a8b101a772cd09b899",
                PoseidonMpfCircuitTemplates::insertDifferentLeaf);
        assertProfile("value-update", 12, 117_927, 754_083, 138,
                "65f6458656d08bf960e76dcd211457341a099cc0ec687b3afb6362a5e45becaa",
                PoseidonMpfCircuitTemplates::valueUpdate);
        assertProfile("insert-empty", 12, 116_725, 747_009, 137,
                "53ee3e54949d973a1e0ae1e7af7c7d7c1cd80020ecb5afdc9221500f0e9585c1",
                PoseidonMpfCircuitTemplates::insertEmpty);
        assertProfile("insert-different-leaf", 12, 138_781, 870_667, 203,
                "4e923b71ad150c2f7cd3a50b51e3df22a6b3276a09b486cd2158d32be13ae3c1",
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
