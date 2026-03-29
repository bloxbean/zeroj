package com.bloxbean.cardano.zeroj.examples.dsl.auction;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.examples.dsl.common.MiMCHash;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the SealedBidCircuit — pure Java, no snarkjs required.
 */
class SealedBidCircuitTest {

    @Test
    void validBid_aboveReserve_bn254() {
        var circuit = SealedBidCircuit.build();
        var prime = FieldConfig.BN254.prime();

        var bidAmount = BigInteger.valueOf(1000);
        var salt = BigInteger.valueOf(42);
        var reservePrice = BigInteger.valueOf(500);
        var commitment = MiMCHash.hash(bidAmount, salt, prime);

        var witness = circuit.calculateWitness(Map.of(
                "bidAmount", List.of(bidAmount),
                "salt", List.of(salt),
                "bidCommitment", List.of(commitment),
                "reservePrice", List.of(reservePrice),
                "isAboveReserve", List.of(BigInteger.ONE)
        ), CurveId.BN254);

        assertNotNull(witness);
        assertEquals(BigInteger.ONE, witness[0]); // constant wire
    }

    @Test
    void validBid_aboveReserve_bls12381() {
        var circuit = SealedBidCircuit.build();
        var prime = FieldConfig.BLS12_381.prime();

        var bidAmount = BigInteger.valueOf(1000);
        var salt = BigInteger.valueOf(42);
        var reservePrice = BigInteger.valueOf(500);
        var commitment = MiMCHash.hash(bidAmount, salt, prime);

        var witness = circuit.calculateWitness(Map.of(
                "bidAmount", List.of(bidAmount),
                "salt", List.of(salt),
                "bidCommitment", List.of(commitment),
                "reservePrice", List.of(reservePrice),
                "isAboveReserve", List.of(BigInteger.ONE)
        ), CurveId.BLS12_381);

        assertNotNull(witness);
    }

    @Test
    void validBid_belowReserve() {
        var circuit = SealedBidCircuit.build();
        var prime = FieldConfig.BN254.prime();

        var bidAmount = BigInteger.valueOf(200);
        var salt = BigInteger.valueOf(99);
        var reservePrice = BigInteger.valueOf(500);
        var commitment = MiMCHash.hash(bidAmount, salt, prime);

        // bidAmount < reservePrice → isAboveReserve=0
        var witness = circuit.calculateWitness(Map.of(
                "bidAmount", List.of(bidAmount),
                "salt", List.of(salt),
                "bidCommitment", List.of(commitment),
                "reservePrice", List.of(reservePrice),
                "isAboveReserve", List.of(BigInteger.ZERO)
        ), CurveId.BN254);

        assertNotNull(witness);
    }

    @Test
    void wrongCommitment_fails() {
        var circuit = SealedBidCircuit.build();

        // Provide wrong commitment → constraint violation
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "bidAmount", List.of(BigInteger.valueOf(1000)),
                "salt", List.of(BigInteger.valueOf(42)),
                "bidCommitment", List.of(BigInteger.valueOf(999)), // wrong!
                "reservePrice", List.of(BigInteger.valueOf(500)),
                "isAboveReserve", List.of(BigInteger.ONE)
        ), CurveId.BN254));
    }

    @Test
    void wrongIsAboveReserve_fails() {
        var circuit = SealedBidCircuit.build();
        var prime = FieldConfig.BN254.prime();

        var bidAmount = BigInteger.valueOf(200);
        var salt = BigInteger.valueOf(99);
        var reservePrice = BigInteger.valueOf(500);
        var commitment = MiMCHash.hash(bidAmount, salt, prime);

        // bidAmount(200) < reservePrice(500), but claiming isAboveReserve=1
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                "bidAmount", List.of(bidAmount),
                "salt", List.of(salt),
                "bidCommitment", List.of(commitment),
                "reservePrice", List.of(reservePrice),
                "isAboveReserve", List.of(BigInteger.ONE) // wrong!
        ), CurveId.BN254));
    }

    @Test
    void compilesToR1CS() {
        var circuit = SealedBidCircuit.build();
        var r1cs = circuit.compileR1CS(CurveId.BN254);
        assertNotNull(r1cs);
        assertTrue(r1cs.numConstraints() > 0, "Should have constraints");
        assertEquals(3, r1cs.numPublicInputs(), "3 public vars: reservePrice, bidCommitment, isAboveReserve");
        assertEquals(2, r1cs.numPrivateInputs(), "2 private vars: bidAmount, salt");
    }

    @Test
    void compilesToR1CS_bls12381() {
        var circuit = SealedBidCircuit.build();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        assertNotNull(r1cs);
        assertTrue(r1cs.numConstraints() > 0);
        assertEquals(FieldConfig.BLS12_381.prime(), r1cs.prime());
    }

    @Test
    void proofHelper_generateR1CS() {
        var helper = new SealedBidProofHelper(CurveId.BLS12_381);
        byte[] r1csBytes = helper.generateR1CS();
        assertNotNull(r1csBytes);
        assertTrue(r1csBytes.length > 100, "R1CS binary should have meaningful size");
        // Verify magic bytes: "r1cs"
        assertEquals(0x72, r1csBytes[0] & 0xFF); // 'r'
        assertEquals(0x31, r1csBytes[1] & 0xFF); // '1'
        assertEquals(0x63, r1csBytes[2] & 0xFF); // 'c'
        assertEquals(0x73, r1csBytes[3] & 0xFF); // 's'
    }

    @Test
    void proofHelper_generateWitness() {
        var helper = new SealedBidProofHelper(CurveId.BLS12_381);
        byte[] wtnsBytes = helper.generateWitness(
                BigInteger.valueOf(1000), BigInteger.valueOf(42), BigInteger.valueOf(500));
        assertNotNull(wtnsBytes);
        assertTrue(wtnsBytes.length > 100, "WTNS binary should have meaningful size");
        // Verify magic bytes: "wtns"
        assertEquals(0x77, wtnsBytes[0] & 0xFF); // 'w'
        assertEquals(0x74, wtnsBytes[1] & 0xFF); // 't'
        assertEquals(0x6e, wtnsBytes[2] & 0xFF); // 'n'
        assertEquals(0x73, wtnsBytes[3] & 0xFF); // 's'
    }
}
