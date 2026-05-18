package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.PublicInputs;
import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkCircuitMetadata;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.PedersenCommitment;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;
import com.bloxbean.cardano.zeroj.examples.dsl.common.MiMCHash;
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkProver;
import com.bloxbean.cardano.zeroj.prover.spi.ProveResponse;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnnotatedCircuitExamplesTest {

    @Test
    void fieldStyleRangeProofUsesGeneratedInputBuilder() {
        var circuit = AnnotatedRangeProofCircuit.build();
        var schema = AnnotatedRangeProofCircuit.schema();

        assertEquals("annotation-range-proof", schema.name());
        assertEquals(List.of("lo", "hi"), schema.publicInputs().names());
        assertEquals(List.of("secret"), schema.secretInputs().names());

        var inputs = AnnotatedRangeProofCircuit.inputs()
                .secret(42)
                .lo(18)
                .hi(99);

        assertEquals(List.of(BigInteger.valueOf(18), BigInteger.valueOf(99)), inputs.publicValues());
        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BN254));

        var invalid = AnnotatedRangeProofCircuit.inputs()
                .secret(7)
                .lo(18)
                .hi(99);
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(invalid.toWitnessMap(), CurveId.BN254));
    }

    @Test
    void parameterStyleAgeVerificationUsesGeneratedSchema() {
        var circuit = AnnotatedAgeVerificationCircuit.build();
        var schema = AnnotatedAgeVerificationCircuit.schema();

        assertEquals(List.of("threshold"), schema.publicInputs().names());
        assertEquals(List.of("age"), schema.secretInputs().names());
        assertEquals(8, schema.input("age").bits());

        var inputs = AnnotatedAgeVerificationCircuit.inputs()
                .age(25)
                .threshold(18);
        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BN254));

        var underAge = AnnotatedAgeVerificationCircuit.inputs()
                .age(15)
                .threshold(18);
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(underAge.toWitnessMap(), CurveId.BN254));
    }

    @Test
    void ageVerificationHelperBuildsProverArtifactsAndProofEnvelope() {
        var helper = new AnnotatedAgeVerificationProofHelper(CurveId.BN254);
        var inputs = helper.inputs(BigInteger.valueOf(25), BigInteger.valueOf(18));
        var circuit = AnnotatedAgeVerificationCircuit.build();
        var publicInputs = new PublicInputs(List.of(BigInteger.valueOf(18)));

        assertEquals(new CircuitId("annotation-age-verification"),
                AnnotatedAgeVerificationCircuit.circuitId());
        assertEquals(publicInputs, inputs.toPublicInputs());
        assertEquals(publicInputs, AnnotatedAgeVerificationCircuit.publicInputValues(inputs));
        assertTrue(AnnotatedAgeVerificationCircuit
                .calculateWitness(circuit, inputs, CurveId.BN254).length > 0);
        assertTrue(helper.generateR1CS().length > 0);
        assertTrue(helper.generateWitnessBytes(BigInteger.valueOf(25), BigInteger.valueOf(18)).length > 0);

        var metadata = AnnotatedAgeVerificationCircuit.metadata();
        assertEquals("1", metadata.envelopeMetadata().get(ZkCircuitMetadata.CIRCUIT_VERSION_KEY));

        var response = new GnarkProver.FullProveResponse(
                new ProveResponse(
                        "{\"proof\":\"demo\"}",
                        inputs.publicValues(),
                        "groth16",
                        CurveId.BN254.value(),
                        0),
                "{}");
        var envelope = helper.toEnvelope(response, inputs, new VerificationKeyRef.ById("vk-age-v1"));

        assertEquals(ProofSystemId.GROTH16, envelope.proofSystem());
        assertEquals(CurveId.BN254, envelope.curve());
        assertEquals(new CircuitId("annotation-age-verification"), envelope.circuitId());
        assertEquals(publicInputs, envelope.publicInputs());
        assertEquals("annotation-age-verification",
                envelope.metadata().get(ZkCircuitMetadata.CIRCUIT_NAME_KEY));

        var mismatched = new GnarkProver.FullProveResponse(
                new ProveResponse("{}", List.of(BigInteger.ONE), "groth16", CurveId.BN254.value(), 0),
                "{}");
        assertThrows(IllegalArgumentException.class,
                () -> helper.toEnvelope(mismatched, inputs, new VerificationKeyRef.ById("vk-age-v1")));

        var wrongCurve = new GnarkProver.FullProveResponse(
                new ProveResponse("{}", inputs.publicValues(), "groth16", CurveId.BLS12_381.value(), 0),
                "{}");
        assertThrows(IllegalArgumentException.class,
                () -> helper.toEnvelope(wrongCurve, inputs, new VerificationKeyRef.ById("vk-age-v1")));
    }

    @Test
    void privateTransferChecksConservationAndPublicAmount() {
        var circuit = AnnotatedPrivateTransferCircuit.build();
        var inputs = AnnotatedPrivateTransferCircuit.inputs()
                .balanceBefore(1_000)
                .transferAmount(125)
                .publicAmount(125)
                .balanceAfter(875);

        assertEquals(List.of(BigInteger.valueOf(125), BigInteger.valueOf(875)), inputs.publicValues());
        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BN254));

        var wrongPublicAmount = AnnotatedPrivateTransferCircuit.inputs()
                .balanceBefore(1_000)
                .transferAmount(125)
                .publicAmount(124)
                .balanceAfter(875);
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(wrongPublicAmount.toWitnessMap(), CurveId.BN254));

        var underflow = AnnotatedPrivateTransferCircuit.inputs()
                .balanceBefore(100)
                .transferAmount(125)
                .publicAmount(125)
                .balanceAfter(0);
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(underflow.toWitnessMap(), CurveId.BN254));
    }

    @Test
    void hashCommitmentUsesBn254MiMCSymbolicGadgetAdapter() {
        var circuit = AnnotatedHashCommitmentCircuit.build();
        var value = BigInteger.valueOf(1234);
        var salt = BigInteger.valueOf(5678);
        var commitment = MiMCHash.hash(value, salt, FieldConfig.BN254.prime());

        var inputs = AnnotatedHashCommitmentCircuit.inputs()
                .value(value)
                .salt(salt)
                .commitment(commitment);

        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BN254));
        assertNotNull(circuit.compileR1CS(CurveId.BN254));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BLS12_381));

        var wrong = AnnotatedHashCommitmentCircuit.inputs()
                .value(value)
                .salt(salt)
                .commitment(BigInteger.ONE);
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(wrong.toWitnessMap(), CurveId.BN254));
    }

    @Test
    void multiInputCommitmentUsesBlsPoseidonNAdapter() {
        var circuit = AnnotatedMultiInputCommitmentCircuit.build();
        var schema = AnnotatedMultiInputCommitmentCircuit.schema();

        assertEquals("annotation-multi-input-commitment", schema.name());
        assertEquals(List.of("commitment"), schema.publicInputs().names());
        assertEquals(List.of("owner", "assetId", "nonce"), schema.secretInputs().names());

        var owner = BigInteger.valueOf(101);
        var assetId = BigInteger.valueOf(202);
        var nonce = BigInteger.valueOf(303);
        var commitment = PoseidonHash.hashN(
                PoseidonParamsBLS12_381T3.INSTANCE,
                owner,
                assetId,
                nonce);

        var inputs = AnnotatedMultiInputCommitmentCircuit.inputs()
                .owner(owner)
                .assetId(assetId)
                .nonce(nonce)
                .commitment(commitment);

        assertEquals(List.of(commitment), inputs.publicValues());
        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
        assertDoesNotThrow(() -> circuit.compileR1CS(CurveId.BLS12_381));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));

        var wrong = AnnotatedMultiInputCommitmentCircuit.inputs()
                .owner(owner)
                .assetId(assetId)
                .nonce(nonce)
                .commitment(BigInteger.ONE);
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(wrong.toWitnessMap(), CurveId.BLS12_381));
    }

    @Test
    void annotatedSealedBidMirrorsReferenceDslCircuit() {
        var circuit = AnnotatedSealedBidCircuit.build();
        var schema = AnnotatedSealedBidCircuit.schema();

        assertEquals("annotation-sealed-bid", schema.name());
        assertEquals(List.of("bidCommitment", "reservePrice"),
                schema.publicInputs().names());
        assertEquals(List.of("bidAmount", "salt"), schema.secretInputs().names());

        var bidAmount = BigInteger.valueOf(100);
        var reservePrice = BigInteger.valueOf(75);
        var salt = BigInteger.valueOf(88_001);
        var commitment = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, bidAmount, salt);
        var inputs = AnnotatedSealedBidCircuit.inputs()
                .bidCommitment(commitment)
                .reservePrice(reservePrice)
                .bidAmount(bidAmount)
                .salt(salt);

        assertEquals(List.of(commitment, reservePrice), inputs.publicValues());
        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
        assertDoesNotThrow(() -> circuit.compileR1CS(CurveId.BLS12_381));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));

        var belowReserveBid = BigInteger.valueOf(50);
        var belowReserveCommitment = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, belowReserveBid, salt);
        var belowReserveInputs = AnnotatedSealedBidCircuit.inputs()
                .bidCommitment(belowReserveCommitment)
                .reservePrice(reservePrice)
                .bidAmount(belowReserveBid)
                .salt(salt);
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(belowReserveInputs.toWitnessMap(), CurveId.BLS12_381));

        var wrongCommitment = AnnotatedSealedBidCircuit.inputs()
                .bidCommitment(BigInteger.ONE)
                .reservePrice(reservePrice)
                .bidAmount(bidAmount)
                .salt(salt);
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(wrongCommitment.toWitnessMap(), CurveId.BLS12_381));
    }

    @Test
    void annotatedAnonymousVotingMirrorsReferenceDslCircuit() {
        var circuit = AnnotatedAnonymousVotingCircuit.build();
        var schema = AnnotatedAnonymousVotingCircuit.schema();

        assertEquals("annotation-anonymous-vote", schema.name());
        assertEquals(List.of("commitment"), schema.publicInputs().names());
        assertEquals(List.of("vote", "nullifier"), schema.secretInputs().names());

        var vote = BigInteger.ONE;
        var nullifier = BigInteger.valueOf(12_345);
        var commitment = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, vote, nullifier);
        var inputs = AnnotatedAnonymousVotingCircuit.inputs()
                .commitment(commitment)
                .vote(vote)
                .nullifier(nullifier);

        assertEquals(List.of(commitment), inputs.publicValues());
        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
        assertDoesNotThrow(() -> circuit.compileR1CS(CurveId.BLS12_381));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));

        var noVote = BigInteger.ZERO;
        var noVoteCommitment = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, noVote, nullifier);
        var noVoteInputs = AnnotatedAnonymousVotingCircuit.inputs()
                .commitment(noVoteCommitment)
                .vote(noVote)
                .nullifier(nullifier);
        assertDoesNotThrow(() -> circuit.calculateWitness(noVoteInputs.toWitnessMap(), CurveId.BLS12_381));

        var wrongCommitment = AnnotatedAnonymousVotingCircuit.inputs()
                .commitment(BigInteger.ONE)
                .vote(vote)
                .nullifier(nullifier);
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(wrongCommitment.toWitnessMap(), CurveId.BLS12_381));

        var invalidVote = BigInteger.valueOf(2);
        var invalidVoteInputs = AnnotatedAnonymousVotingCircuit.inputs()
                .commitment(PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, invalidVote, nullifier))
                .vote(invalidVote)
                .nullifier(nullifier);
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(invalidVoteInputs.toWitnessMap(), CurveId.BLS12_381));
    }

    @Test
    void parameterizedMerkleMembershipUsesBn254MiMCDepthAndHashType() {
        int depth = 2;
        var hashType = ZkMerkle.HashType.MIMC;
        var circuit = AnnotatedMerkleMembershipCircuit.build(depth, hashType);
        var schema = AnnotatedMerkleMembershipCircuit.schema(depth, hashType);

        assertEquals("annotation-merkle-d2-MIMC--depth-1:2--hashType-4:MIMC", schema.name());
        assertEquals("1:2", schema.parameters().get(0).value());
        assertEquals("4:MIMC", schema.parameters().get(1).value());
        assertEquals(List.of("root"), schema.publicInputs().names());
        assertEquals(List.of("leaf", "sibling_0", "sibling_1", "pathBit_0", "pathBit_1"),
                schema.secretInputs().names());

        var leaf = BigInteger.valueOf(10);
        var sibling0 = BigInteger.valueOf(20);
        var sibling1 = BigInteger.valueOf(30);
        var pathBit0 = BigInteger.ZERO;
        var pathBit1 = BigInteger.ONE;
        var root = merkleRoot(leaf, List.of(sibling0, sibling1), List.of(pathBit0, pathBit1));

        var inputs = AnnotatedMerkleMembershipCircuit.inputs(depth, hashType)
                .leaf(leaf)
                .root(root)
                .siblings(List.of(sibling0, sibling1))
                .pathBits(List.of(pathBit0, pathBit1));

        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BN254));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BLS12_381));
        assertEquals(List.of(root), inputs.publicValues());

        var invalid = AnnotatedMerkleMembershipCircuit.inputs(depth, hashType)
                .leaf(leaf)
                .root(BigInteger.ONE)
                .siblings(List.of(sibling0, sibling1))
                .pathBits(List.of(pathBit0, pathBit1));
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(invalid.toWitnessMap(), CurveId.BN254));
    }

    @Test
    void blsPoseidonMerkleMembershipUsesParamsAwareHelper() {
        int depth = 2;
        var circuit = AnnotatedBlsPoseidonMerkleMembershipCircuit.build(depth);
        var schema = AnnotatedBlsPoseidonMerkleMembershipCircuit.schema(depth);

        assertEquals("annotation-merkle-bls-poseidon-d2--depth-1:2", schema.name());
        assertEquals("1:2", schema.parameters().get(0).value());
        assertEquals(List.of("root"), schema.publicInputs().names());
        assertEquals(List.of("leaf", "sibling_0", "sibling_1", "pathBit_0", "pathBit_1"),
                schema.secretInputs().names());

        var leaf = BigInteger.valueOf(10);
        var sibling0 = BigInteger.valueOf(20);
        var sibling1 = BigInteger.valueOf(30);
        var pathBit0 = BigInteger.ZERO;
        var pathBit1 = BigInteger.ONE;
        var root = poseidonMerkleRoot(leaf, List.of(sibling0, sibling1), List.of(pathBit0, pathBit1));

        var inputs = AnnotatedBlsPoseidonMerkleMembershipCircuit.inputs(depth)
                .leaf(leaf)
                .root(root)
                .siblings(List.of(sibling0, sibling1))
                .pathBits(List.of(pathBit0, pathBit1));

        assertEquals(List.of(root), inputs.publicValues());
        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
        assertDoesNotThrow(() -> circuit.compileR1CS(CurveId.BLS12_381));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));
        assertThrows(IllegalStateException.class,
                () -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BN254));

        var invalid = AnnotatedBlsPoseidonMerkleMembershipCircuit.inputs(depth)
                .leaf(leaf)
                .root(BigInteger.ONE)
                .siblings(List.of(sibling0, sibling1))
                .pathBits(List.of(pathBit0, pathBit1));
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(invalid.toWitnessMap(), CurveId.BLS12_381));
    }

    @Test
    void pedersenCommitmentUsesAdvancedSymbolicAdapter() {
        var circuit = AnnotatedPedersenCommitmentCircuit.build();
        var value = BigInteger.valueOf(42);
        var blinding = BigInteger.valueOf(12345);
        var commitment = PedersenCommitment.commit(value, blinding);

        var inputs = AnnotatedPedersenCommitmentCircuit.inputs()
                .value(value)
                .blinding(blinding)
                .expectedU(commitment.affineU())
                .expectedV(commitment.affineV());

        assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381));
        assertThrows(IllegalStateException.class, () -> circuit.compileR1CS(CurveId.BN254));

        var invalid = AnnotatedPedersenCommitmentCircuit.inputs()
                .value(value)
                .blinding(blinding)
                .expectedU(commitment.affineU().add(BigInteger.ONE))
                .expectedV(commitment.affineV());
        assertThrows(ArithmeticException.class,
                () -> circuit.calculateWitness(invalid.toWitnessMap(), CurveId.BLS12_381));
    }

    private BigInteger merkleRoot(
            BigInteger leaf,
            List<BigInteger> siblings,
            List<BigInteger> pathBits) {
        BigInteger current = leaf;
        for (int i = 0; i < siblings.size(); i++) {
            BigInteger sibling = siblings.get(i);
            current = BigInteger.ZERO.equals(pathBits.get(i))
                    ? MiMCHash.hash(current, sibling, FieldConfig.BN254.prime())
                    : MiMCHash.hash(sibling, current, FieldConfig.BN254.prime());
        }
        return current;
    }

    private BigInteger poseidonMerkleRoot(
            BigInteger leaf,
            List<BigInteger> siblings,
            List<BigInteger> pathBits) {
        BigInteger current = leaf;
        for (int i = 0; i < siblings.size(); i++) {
            BigInteger sibling = siblings.get(i);
            current = BigInteger.ZERO.equals(pathBits.get(i))
                    ? PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, current, sibling)
                    : PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, sibling, current);
        }
        return current;
    }
}
