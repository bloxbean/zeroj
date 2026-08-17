package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit;

import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.vds.jmt.store.InMemoryJmtStore;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSFlatIO;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtTree;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtCommitments;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.witness.PoseidonJmtDifferentLeafWitness;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.witness.PoseidonJmtEmptyWitness;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.witness.PoseidonJmtInclusionWitness;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ZkJmtOperationCircuitTest {

    @Test
    void inclusionAndBothNonInclusionFormsUseStrictRealCclWitnesses() {
        Fixture fixture = populated(0, 24);
        byte[] member = bytes("jmt-key-5");
        byte[] value = bytes("jmt-value-5");
        JmtProof inclusion = fixture.tree().getProof(member, 0).orElseThrow();
        int inclusionBound = inclusion.steps().size() + 2;
        PoseidonJmtInclusionWitness inclusionWitness = PoseidonJmtInclusionWitness.create(
                fixture.root(), member, value, inclusion, inclusionBound);
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonJmtInclusionWitness.create(
                        fixture.root(), member, value, inclusion,
                        Math.max(0, inclusion.steps().size() - 1)));
        var inclusionInputs = new ZkInputMap().put("root", field(fixture.root()));
        inclusionWitness.putInto(inclusionInputs);
        Map<String, List<BigInteger>> validInclusion = inclusionInputs.toWitnessMap();
        CircuitBuilder inclusionCircuit = PoseidonJmtCircuitTemplates.inclusion(inclusionBound);
        assertDoesNotThrow(() -> calculate(inclusionCircuit, validInclusion));
        assertThrows(ArithmeticException.class,
                () -> calculate(inclusionCircuit, mutate(validInclusion, "root")));
        assertThrows(ArithmeticException.class,
                () -> calculate(inclusionCircuit, mutate(validInclusion, "jmt_value_hash")));
        assertThrows(ArithmeticException.class,
                () -> calculate(inclusionCircuit, with(validInclusion, "jmt_key_nibble_0",
                        validInclusion.get("jmt_key_nibble_0").getFirst()
                                .add(BigInteger.ONE).mod(BigInteger.valueOf(16)))));
        assertThrows(ArithmeticException.class,
                () -> calculate(inclusionCircuit, mutate(validInclusion, "jmt_sibling_0_0")));
        assertThrows(ArithmeticException.class,
                () -> calculate(inclusionCircuit,
                        with(validInclusion, "jmt_valid_" + inclusion.steps().size(), BigInteger.ONE)));

        ProofCase empty = findProof(fixture, JmtProof.ProofType.NON_INCLUSION_EMPTY);
        int emptyBound = empty.proof().steps().size() + 1;
        PoseidonJmtEmptyWitness emptyWitness = PoseidonJmtEmptyWitness.create(
                fixture.root(), empty.key(), empty.proof(), emptyBound);
        var emptyInputs = new ZkInputMap().put("root", field(fixture.root()));
        emptyWitness.putInto(emptyInputs);
        Map<String, List<BigInteger>> validEmpty = emptyInputs.toWitnessMap();
        CircuitBuilder emptyCircuit = PoseidonJmtCircuitTemplates.nonInclusionEmpty(emptyBound);
        assertDoesNotThrow(() -> calculate(emptyCircuit, validEmpty));
        assertThrows(ArithmeticException.class, () -> calculate(emptyCircuit,
                mutate(validEmpty, "root")));
        assertThrows(ArithmeticException.class, () -> calculate(emptyCircuit,
                with(validEmpty, "jmt_key_nibble_0",
                        validEmpty.get("jmt_key_nibble_0").getFirst()
                                .add(BigInteger.ONE).mod(BigInteger.valueOf(16)))));
        if (!empty.proof().steps().isEmpty()) {
            assertThrows(ArithmeticException.class, () -> calculate(emptyCircuit,
                    mutate(validEmpty, "jmt_sibling_0_0")));
            assertThrows(ArithmeticException.class, () -> calculate(emptyCircuit,
                    with(validEmpty, "jmt_valid_0", BigInteger.ZERO)));
        }

        ProofCase different = findProof(
                fixture, JmtProof.ProofType.NON_INCLUSION_DIFFERENT_LEAF);
        int differentBound = different.proof().steps().size() + 1;
        PoseidonJmtDifferentLeafWitness differentWitness =
                PoseidonJmtDifferentLeafWitness.create(
                        fixture.root(), different.key(), different.proof(), differentBound);
        var differentInputs = new ZkInputMap().put("root", field(fixture.root()));
        differentWitness.putInto(differentInputs);
        Map<String, List<BigInteger>> validDifferent = differentInputs.toWitnessMap();
        assertDoesNotThrow(() -> calculate(
                PoseidonJmtCircuitTemplates.nonInclusionDifferentLeaf(differentBound),
                validDifferent));
        assertThrows(ArithmeticException.class, () -> calculate(
                PoseidonJmtCircuitTemplates.nonInclusionDifferentLeaf(differentBound),
                mutate(validDifferent, "jmt_conflicting_value_hash")));
        CircuitBuilder differentCircuit =
                PoseidonJmtCircuitTemplates.nonInclusionDifferentLeaf(differentBound);
        assertThrows(ArithmeticException.class,
                () -> calculate(differentCircuit, mutate(validDifferent, "root")));
        assertThrows(ArithmeticException.class, () -> calculate(differentCircuit,
                with(validDifferent, "jmt_key_nibble_0",
                        validDifferent.get("jmt_key_nibble_0").getFirst()
                                .add(BigInteger.ONE).mod(BigInteger.valueOf(16)))));
        assertThrows(ArithmeticException.class, () -> calculate(differentCircuit,
                with(validDifferent, "jmt_conflicting_key_nibble_0",
                        validDifferent.get("jmt_conflicting_key_nibble_0").getFirst()
                                .add(BigInteger.ONE).mod(BigInteger.valueOf(16)))));
        if (!different.proof().steps().isEmpty()) {
            assertThrows(ArithmeticException.class, () -> calculate(differentCircuit,
                    mutate(validDifferent, "jmt_sibling_0_0")));
        }

        assertThrows(IllegalArgumentException.class,
                () -> PoseidonJmtEmptyWitness.create(
                        fixture.root(), different.key(), different.proof(), differentBound));
        assertThrows(IllegalArgumentException.class,
                () -> PoseidonJmtDifferentLeafWitness.create(
                        fixture.root(), empty.key(), empty.proof(), emptyBound));
    }

    @Test
    void canonicalKeyRejectsFieldAliasesAndAcceptsExactBoundaries() {
        BigInteger modulus = FieldConfig.BLS12_381.prime();
        BigInteger value = BigInteger.valueOf(19);
        assertSyntheticS0Inclusion(BigInteger.ZERO, value);
        assertSyntheticS0Inclusion(modulus.subtract(BigInteger.ONE), value);

        CircuitBuilder circuit = PoseidonJmtCircuitTemplates.inclusion(0);
        Map<String, List<BigInteger>> valid = syntheticS0Inputs(BigInteger.ZERO, value);
        assertThrows(ArithmeticException.class,
                () -> calculate(circuit, replaceKey(valid, modulus)));
        assertThrows(ArithmeticException.class,
                () -> calculate(circuit, replaceKey(valid, modulus.add(BigInteger.ONE))));
        assertThrows(ArithmeticException.class,
                () -> calculate(circuit, replaceKey(valid, BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE))));
    }

    @Test
    void valueUpdateAndBothCanonicalInsertShapesMatchCclBeforeAndAfterRoots() {
        Fixture updateFixture = populated(0, 12);
        byte[] updateKey = bytes("jmt-key-3");
        byte[] oldValue = bytes("jmt-value-3");
        byte[] newValue = bytes("jmt-value-3-updated");
        JmtProof updateProof = updateFixture.tree().getProof(updateKey, 0).orElseThrow();
        int updateBound = updateProof.steps().size() + 1;
        var updateWitness = PoseidonJmtInclusionWitness.create(
                updateFixture.root(), updateKey, oldValue, updateProof, updateBound);
        byte[] updatedRoot = updateFixture.tree().put(1, Map.of(updateKey, newValue)).rootHash();
        var updateInputs = new ZkInputMap()
                .put("oldRoot", field(updateFixture.root()))
                .put("newRoot", field(updatedRoot))
                .put("jmt_old_value_hash", field(PoseidonJmtHash.digest(oldValue)))
                .put("jmt_new_value_hash", field(PoseidonJmtHash.digest(newValue)));
        updateWitness.path().putInto(updateInputs);
        Map<String, List<BigInteger>> validUpdate = updateInputs.toWitnessMap();
        CircuitBuilder updateCircuit = PoseidonJmtCircuitTemplates.valueUpdate(updateBound);
        assertDoesNotThrow(() -> calculate(updateCircuit, validUpdate));
        assertThrows(ArithmeticException.class,
                () -> calculate(updateCircuit, mutate(validUpdate, "oldRoot")));
        assertThrows(ArithmeticException.class,
                () -> calculate(updateCircuit, mutate(validUpdate, "newRoot")));
        assertThrows(ArithmeticException.class,
                () -> calculate(updateCircuit, mutate(validUpdate, "jmt_old_value_hash")));
        assertThrows(ArithmeticException.class,
                () -> calculate(updateCircuit, mutate(validUpdate, "jmt_new_value_hash")));
        Map<String, List<BigInteger>> noOpUpdate = with(
                with(validUpdate, "jmt_new_value_hash",
                        validUpdate.get("jmt_old_value_hash").getFirst()),
                "newRoot", validUpdate.get("oldRoot").getFirst());
        assertThrows(ArithmeticException.class,
                () -> calculate(updateCircuit, noOpUpdate),
                "a value-update proof must advance the committed state");
        assertThrows(ArithmeticException.class, () -> calculate(updateCircuit,
                with(validUpdate, "jmt_key_nibble_0",
                        validUpdate.get("jmt_key_nibble_0").getFirst()
                                .add(BigInteger.ONE).mod(BigInteger.valueOf(16)))));
        if (!updateProof.steps().isEmpty()) {
            assertThrows(ArithmeticException.class,
                    () -> calculate(updateCircuit, mutate(validUpdate, "jmt_sibling_0_0")));
        }

        var tombstoneInputs = new ZkInputMap()
                .put("oldRoot", field(updateFixture.root()))
                .put("newRoot", field(updatedRoot))
                .put("jmt_old_value_hash", field(PoseidonJmtHash.digest(oldValue)))
                .put("jmt_tombstone_value_hash", field(PoseidonJmtHash.digest(newValue)));
        updateWitness.path().putInto(tombstoneInputs);
        CircuitBuilder tombstoneCircuit = PoseidonJmtCircuitTemplates.tombstoneUpdate(updateBound);
        Map<String, List<BigInteger>> validTombstone = tombstoneInputs.toWitnessMap();
        assertDoesNotThrow(() -> calculate(tombstoneCircuit, validTombstone));
        assertThrows(ArithmeticException.class, () -> calculate(
                tombstoneCircuit, mutate(validTombstone, "jmt_tombstone_value_hash")));

        Fixture emptyFixture = populated(0, 16);
        ProofCase empty = findProof(emptyFixture, JmtProof.ProofType.NON_INCLUSION_EMPTY);
        byte[] insertedValue = bytes("inserted-empty-value");
        int emptyBound = empty.proof().steps().size() + 1;
        var emptyWitness = PoseidonJmtEmptyWitness.create(
                emptyFixture.root(), empty.key(), empty.proof(), emptyBound);
        byte[] emptyInsertedRoot = emptyFixture.tree().put(
                1, Map.of(empty.key(), insertedValue)).rootHash();
        var emptyInputs = new ZkInputMap()
                .put("oldRoot", field(emptyFixture.root()))
                .put("newRoot", field(emptyInsertedRoot))
                .put("jmt_value_hash", field(PoseidonJmtHash.digest(insertedValue)));
        emptyWitness.putInto(emptyInputs);
        Map<String, List<BigInteger>> validEmptyInsert = emptyInputs.toWitnessMap();
        CircuitBuilder emptyInsertCircuit = PoseidonJmtCircuitTemplates.insertEmpty(emptyBound);
        assertDoesNotThrow(() -> calculate(emptyInsertCircuit, validEmptyInsert));
        assertThrows(ArithmeticException.class,
                () -> calculate(emptyInsertCircuit, mutate(validEmptyInsert, "oldRoot")));
        assertThrows(ArithmeticException.class,
                () -> calculate(emptyInsertCircuit, mutate(validEmptyInsert, "newRoot")));
        assertThrows(ArithmeticException.class,
                () -> calculate(emptyInsertCircuit, mutate(validEmptyInsert, "jmt_value_hash")));
        assertThrows(ArithmeticException.class, () -> calculate(emptyInsertCircuit,
                with(validEmptyInsert, "jmt_key_nibble_0",
                        validEmptyInsert.get("jmt_key_nibble_0").getFirst()
                                .add(BigInteger.ONE).mod(BigInteger.valueOf(16)))));

        Fixture singleton = populated(0, 1);
        ProofCase different = findProof(singleton, JmtProof.ProofType.NON_INCLUSION_DIFFERENT_LEAF);
        byte[] splitValue = bytes("split-inserted-value");
        int splitBound = different.proof().steps().size();
        var differentWitness = PoseidonJmtDifferentLeafWitness.create(
                singleton.root(), different.key(), different.proof(), splitBound);
        byte[] splitRoot = singleton.tree().put(1, Map.of(different.key(), splitValue)).rootHash();
        var splitInputs = new ZkInputMap()
                .put("oldRoot", field(singleton.root()))
                .put("newRoot", field(splitRoot))
                .put("jmt_value_hash", field(PoseidonJmtHash.digest(splitValue)));
        differentWitness.putInto(splitInputs);
        Map<String, List<BigInteger>> validSplit = splitInputs.toWitnessMap();
        CircuitBuilder splitCircuit = PoseidonJmtCircuitTemplates.insertDifferentLeaf(splitBound);
        assertDoesNotThrow(() -> calculate(splitCircuit, validSplit));
        assertThrows(ArithmeticException.class,
                () -> calculate(splitCircuit, mutate(validSplit, "newRoot")));
        assertThrows(ArithmeticException.class,
                () -> calculate(splitCircuit, mutate(validSplit, "oldRoot")));
        assertThrows(ArithmeticException.class,
                () -> calculate(splitCircuit, mutate(validSplit, "jmt_value_hash")));
        assertThrows(ArithmeticException.class,
                () -> calculate(splitCircuit, mutate(validSplit, "jmt_conflicting_value_hash")));
        assertThrows(ArithmeticException.class, () -> calculate(splitCircuit,
                with(validSplit, "jmt_conflicting_key_nibble_0",
                        validSplit.get("jmt_conflicting_key_nibble_0").getFirst()
                                .add(BigInteger.ONE).mod(BigInteger.valueOf(16)))));
    }

    @Test
    void differentLeafInsertionMatchesDeepRandomizedCclTransitionsAndS64Boundary() {
        Fixture current = populated(0, 128);
        CircuitBuilder bounded = PoseidonJmtCircuitTemplates.insertDifferentLeaf(8);
        java.util.Set<Integer> divergences = new java.util.LinkedHashSet<>();
        boolean exercisedS64 = false;

        for (int operation = 1; operation <= 12; operation++) {
            ProofCase selected = null;
            ProofCase fallback = null;
            int selectedDivergence = -1;
            for (int candidate = 0; candidate < 100_000; candidate++) {
                byte[] key = bytes("deep-missing-jmt-" + operation + "-" + candidate);
                JmtProof proof = current.tree().getProof(key, current.version()).orElseThrow();
                if (proof.type() != JmtProof.ProofType.NON_INCLUSION_DIFFERENT_LEAF
                        || proof.steps().isEmpty() || proof.steps().size() > 8) continue;
                int divergence = divergence(key, proof.conflictingKeyHash());
                ProofCase proofCase = new ProofCase(key, proof);
                if (fallback == null) fallback = proofCase;
                if (!divergences.contains(divergence)) {
                    selected = proofCase;
                    selectedDivergence = divergence;
                    break;
                }
            }
            if (selected == null) {
                selected = java.util.Objects.requireNonNull(
                        fallback, "failed to find a deep different-leaf proof");
                selectedDivergence = divergence(
                        selected.key(), selected.proof().conflictingKeyHash());
            }
            divergences.add(selectedDivergence);

            byte[] oldRoot = current.root();
            byte[] insertedValue = bytes("deep-inserted-jmt-value-" + operation);
            PoseidonJmtDifferentLeafWitness witness = PoseidonJmtDifferentLeafWitness.create(
                    oldRoot, selected.key(), selected.proof(), 8);
            PoseidonJmtDifferentLeafWitness maxWitness = !exercisedS64
                    ? PoseidonJmtDifferentLeafWitness.create(
                            oldRoot, selected.key(), selected.proof(), 64)
                    : null;
            byte[] newRoot = current.tree().put(
                    operation, Map.of(selected.key(), insertedValue)).rootHash();

            var inputs = new ZkInputMap()
                    .put("oldRoot", field(oldRoot))
                    .put("newRoot", field(newRoot))
                    .put("jmt_value_hash", field(PoseidonJmtHash.digest(insertedValue)));
            witness.putInto(inputs);
            Map<String, List<BigInteger>> valid = inputs.toWitnessMap();
            assertDoesNotThrow(() -> calculate(bounded, valid));
            assertThrows(ArithmeticException.class,
                    () -> calculate(bounded, mutate(valid, "jmt_conflicting_value_hash")));

            if (!exercisedS64) {
                var maxInputs = new ZkInputMap()
                        .put("oldRoot", field(oldRoot))
                        .put("newRoot", field(newRoot))
                        .put("jmt_value_hash", field(PoseidonJmtHash.digest(insertedValue)));
                maxWitness.putInto(maxInputs);
                Map<String, List<BigInteger>> maxValid = maxInputs.toWitnessMap();
                CircuitBuilder maxCircuit = PoseidonJmtCircuitTemplates.insertDifferentLeaf(64);
                assertDoesNotThrow(() -> calculate(maxCircuit, maxValid));
                assertThrows(ArithmeticException.class,
                        () -> calculate(maxCircuit, mutate(maxValid, "jmt_sibling_63_0")),
                        "the S64 padding suffix must remain canonical zero data");
                exercisedS64 = true;
            }
            current = new Fixture(current.tree(), operation, newRoot);
        }

        assertTrue(divergences.size() >= 2,
                "deterministic randomized cases must exercise multiple leaf divergence depths");
        assertTrue(divergences.stream().anyMatch(depth -> depth > 0));
    }

    @Test
    void maximumDepthAndPaddingSuffixAreConstrained() {
        Map<String, List<BigInteger>> valid = syntheticMaxDepthInputs();
        CircuitBuilder circuit = PoseidonJmtCircuitTemplates.inclusion(64);
        assertDoesNotThrow(() -> calculate(circuit, valid));
        assertThrows(ArithmeticException.class,
                () -> calculate(circuit, mutate(valid, "jmt_sibling_63_3")));
        assertThrows(ArithmeticException.class,
                () -> calculate(circuit, with(valid, "jmt_valid_63", BigInteger.ZERO)));

        Map<String, List<BigInteger>> padded = new LinkedHashMap<>(valid);
        padded.put("jmt_valid_62", List.of(BigInteger.ZERO));
        assertThrows(ArithmeticException.class,
                () -> calculate(circuit, Map.copyOf(padded)),
                "valid rows must be one prefix; a later valid row cannot follow padding");
    }

    @Test
    void templateIdsDigestsAndConstraintProfilesArePinned() {
        assertProfile("inclusion", 0, 1, 2_095, 5_605, 65,
                "cb968f54bbd422a39df7f3a886e24cf98ab8103c3bd4daf44ca49c11b77a570e",
                PoseidonJmtCircuitTemplates::inclusion);
        assertProfile("inclusion", 8, 1, 10_069, 51_614, 105,
                "3f967bc5a1376ccbbddab7b1fe3fdf183e400be82d0171ef1342536fde18b73d",
                PoseidonJmtCircuitTemplates::inclusion);
        assertProfile("inclusion", 64, 1, 65_901, 373_670, 385,
                "725996176f225f33ebbdb794902537c3bdd602c91cdaf257f3c5eb2fab79d6dd",
                PoseidonJmtCircuitTemplates::inclusion);
        assertProfile("non-inclusion-empty", 8, 1, 9_829, 50_200, 104,
                "15641ab6baa108f80628a28dbd80f2e25e1b5f00e927e048e1d8c5d41dd58479",
                PoseidonJmtCircuitTemplates::nonInclusionEmpty);
        assertProfile("non-inclusion-different-leaf", 8, 1, 11_976, 55_678, 169,
                "6d94a186f0dcd5870c53d892c49b847cbd1b4afcbf9c5c4a9642e460b1314fad",
                PoseidonJmtCircuitTemplates::nonInclusionDifferentLeaf);
        assertProfile("value-update", 8, 2, 18_067, 98_541, 106,
                "8b6cb5d8bf0ebb0fa69bf5850275351ff8a35e3bcb7c0559762d71540740d7fc",
                PoseidonJmtCircuitTemplates::valueUpdate);
        assertProfile("insert-empty", 8, 2, 17_822, 97_120, 105,
                "639686883abdd97d3c5e37c143b0864fc3864903e2b53fc39f01eba9a87754b5",
                PoseidonJmtCircuitTemplates::insertEmpty);
        assertProfile("insert-different-leaf", 8, 2, 86_602, 489_835, 170,
                "61e34677efabf68c59a7ec58bb91165a8368f777fee1b8217806dd448e1c2b27",
                PoseidonJmtCircuitTemplates::insertDifferentLeaf);
        assertProfile("tombstone-update", 8, 3, 18_067, 98_541, 105,
                "a24c44d57e1be2b2ea1cfc2250ba7b88ad199dd9b617659e289b89b2df9074ff",
                PoseidonJmtCircuitTemplates::tombstoneUpdate);
    }

    private static void assertProfile(
            String operation,
            int bound,
            int publicInputs,
            int constraints,
            int wires,
            int privateInputs,
            String sha256,
            java.util.function.IntFunction<CircuitBuilder> factory) {
        CircuitBuilder circuit = factory.apply(bound);
        assertEquals("zeroj-jmt-v1-" + operation + "-s" + bound + "-p" + publicInputs,
                circuit.constraintGraph().name());
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertEquals(constraints, r1cs.numConstraints());
        assertEquals(wires, r1cs.numWires());
        assertEquals(publicInputs, r1cs.numPublicInputs());
        assertEquals(privateInputs, r1cs.numPrivateInputs());
        assertEquals(sha256, R1CSFlatIO.canonicalSha256(
                r1cs.flat(), r1cs.numWires(), r1cs.numPublicInputs()));
    }

    private static void assertSyntheticS0Inclusion(BigInteger key, BigInteger value) {
        assertDoesNotThrow(() -> calculate(
                PoseidonJmtCircuitTemplates.inclusion(0), syntheticS0Inputs(key, value)));
    }

    private static Map<String, List<BigInteger>> syntheticS0Inputs(
            BigInteger key, BigInteger value) {
        byte[] root = PoseidonJmtCommitments.leaf(
                PoseidonJmtHash.encode(key), PoseidonJmtHash.encode(value));
        var inputs = new ZkInputMap()
                .put("root", field(root))
                .put("jmt_value_hash", value)
                .putArray("jmt_key_nibble", nibbles(key));
        return inputs.toWitnessMap();
    }

    private static Map<String, List<BigInteger>> syntheticMaxDepthInputs() {
        BigInteger key = BigInteger.valueOf(0x1234_5678L);
        BigInteger value = BigInteger.valueOf(0x5a4a4d54L);
        List<BigInteger> keyNibbles = nibbles(key);
        List<byte[]> emptySiblings = List.of(
                PoseidonJmtCommitments.emptySubtree(0),
                PoseidonJmtCommitments.emptySubtree(1),
                PoseidonJmtCommitments.emptySubtree(2),
                PoseidonJmtCommitments.emptySubtree(3));
        byte[] current = PoseidonJmtCommitments.leaf(
                PoseidonJmtHash.encode(key), PoseidonJmtHash.encode(value));
        for (int depth = 63; depth >= 0; depth--) {
            current = PoseidonJmtCommitments.branchPath(
                    keyNibbles.get(depth).intValueExact(), current, emptySiblings);
        }
        List<List<BigInteger>> siblings = new ArrayList<>();
        for (int depth = 0; depth < 64; depth++) {
            siblings.add(emptySiblings.stream().map(PoseidonJmtHash::decode).toList());
        }
        return new ZkInputMap()
                .put("root", field(current))
                .put("jmt_value_hash", value)
                .putArray("jmt_key_nibble", keyNibbles)
                .putNestedArray("jmt_sibling", siblings)
                .putArray("jmt_valid", java.util.Collections.nCopies(64, BigInteger.ONE))
                .toWitnessMap();
    }

    private static Map<String, List<BigInteger>> replaceKey(
            Map<String, List<BigInteger>> inputs, BigInteger key) {
        Map<String, List<BigInteger>> copy = new LinkedHashMap<>(inputs);
        List<BigInteger> nibbles = nibbles(key);
        for (int index = 0; index < 64; index++) {
            copy.put("jmt_key_nibble_" + index, List.of(nibbles.get(index)));
        }
        return Map.copyOf(copy);
    }

    private static List<BigInteger> nibbles(BigInteger value) {
        byte[] bytes = new byte[32];
        byte[] raw = value.toByteArray();
        int source = Math.max(0, raw.length - bytes.length);
        System.arraycopy(raw, source, bytes, bytes.length - (raw.length - source), raw.length - source);
        List<BigInteger> output = new ArrayList<>(64);
        for (byte item : bytes) {
            output.add(BigInteger.valueOf((item >>> 4) & 15));
            output.add(BigInteger.valueOf(item & 15));
        }
        return List.copyOf(output);
    }

    private static int divergence(byte[] queryKey, byte[] conflictingKeyHash) {
        int[] query = PoseidonJmtHash.nibbles(PoseidonJmtHash.digest(queryKey));
        int[] conflicting = PoseidonJmtHash.nibbles(conflictingKeyHash);
        for (int index = 0; index < query.length; index++) {
            if (query[index] != conflicting[index]) return index;
        }
        throw new AssertionError("different-leaf proof reused the query key");
    }

    private static Fixture populated(long version, int entries) {
        PoseidonJmtTree tree = new PoseidonJmtTree(new InMemoryJmtStore());
        Map<byte[], byte[]> values = new LinkedHashMap<>();
        for (int index = 0; index < entries; index++) {
            values.put(bytes("jmt-key-" + index), bytes("jmt-value-" + index));
        }
        byte[] root = tree.put(version, values).rootHash();
        return new Fixture(tree, version, root);
    }

    private static ProofCase findProof(Fixture fixture, JmtProof.ProofType type) {
        for (int index = 0; index < 100_000; index++) {
            byte[] key = bytes("missing-jmt-" + index);
            JmtProof proof = fixture.tree().getProof(key, fixture.version()).orElseThrow();
            if (proof.type() == type) return new ProofCase(key, proof);
        }
        throw new AssertionError("failed to find deterministic proof type " + type);
    }

    private static void calculate(
            CircuitBuilder circuit, Map<String, List<BigInteger>> inputs) {
        circuit.calculateWitness(inputs, CurveId.BLS12_381);
    }

    private static Map<String, List<BigInteger>> mutate(
            Map<String, List<BigInteger>> inputs, String name) {
        return with(inputs, name, inputs.get(name).getFirst().add(BigInteger.ONE)
                .mod(FieldConfig.BLS12_381.prime()));
    }

    private static Map<String, List<BigInteger>> with(
            Map<String, List<BigInteger>> inputs, String name, BigInteger value) {
        Map<String, List<BigInteger>> copy = new LinkedHashMap<>(inputs);
        copy.put(name, List.of(value));
        return Map.copyOf(copy);
    }

    private static BigInteger field(byte[] value) {
        return PoseidonJmtHash.decode(value);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private record Fixture(PoseidonJmtTree tree, long version, byte[] root) {
        private Fixture {
            root = root.clone();
        }
        @Override public byte[] root() { return root.clone(); }
    }

    private record ProofCase(byte[] key, JmtProof proof) {
        private ProofCase { key = key.clone(); }
        @Override public byte[] key() { return key.clone(); }
    }
}
