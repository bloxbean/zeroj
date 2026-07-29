package com.bloxbean.cardano.zeroj.examples.dsl;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.examples.dsl.auction.SealedBidCircuit;
import com.bloxbean.cardano.zeroj.examples.dsl.balance.BalanceThresholdCircuit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Pins the comparison relations of the two shipped example circuits, per ADR-0037 Decision 2.
 *
 * <p>Both circuits compare an unbounded private witness against a <b>public input</b> using
 * {@code greaterOrEqual(..., 64)}. Before ADR-0037, {@code lessThan} range-constrained neither
 * operand, so an oversized <em>right</em> operand made {@code diff = (2^64 - 1) + b - a} wrap
 * to a small residue and the comparison returned the wrong answer. That let a value of 0
 * "clear" a threshold near the field prime.
 *
 * <p>These circuits were never exploitable through the operand an attacker normally controls
 * (the private bid/balance), because that is the <em>left</em> operand and the wrap band on
 * that side only forges the {@code <} direction. They were nonetheless unsound as relations:
 * nothing in the circuit constrained the public threshold. These tests pin the corrected
 * behaviour so a future comparator change cannot quietly reintroduce it.
 */
class ComparatorRelationPinningTest {

    private static final BigInteger P = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    // ------------------------------------------------------------------
    //  Sealed-bid auction: bidAmount >= reservePrice
    // ------------------------------------------------------------------

    private static Map<String, List<BigInteger>> bidWitness(
            BigInteger bid, BigInteger salt, BigInteger reserve, BigInteger commitment) {
        return Map.of(
                "bidCommitment", List.of(commitment),
                "reservePrice", List.of(reserve),
                "bidAmount", List.of(bid),
                "salt", List.of(salt));
    }

    /** Computes the Poseidon commitment the circuit expects for (bid, salt). */
    private static BigInteger bidCommitment(BigInteger bid, BigInteger salt) {
        return com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash.hash(
                com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3.INSTANCE,
                bid, salt);
    }

    @Test
    @DisplayName("sealed bid: an honest winning bid is accepted")
    void honestBidAccepted() {
        BigInteger bid = BigInteger.valueOf(5_000_000L);
        BigInteger salt = BigInteger.valueOf(4242);
        BigInteger reserve = BigInteger.valueOf(1_000_000L);
        assertDoesNotThrow(() -> SealedBidCircuit.build().calculateWitness(
                bidWitness(bid, salt, reserve, bidCommitment(bid, salt)), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("sealed bid: a bid below the reserve is rejected")
    void belowReserveRejected() {
        BigInteger bid = BigInteger.valueOf(999_999L);
        BigInteger salt = BigInteger.valueOf(4242);
        BigInteger reserve = BigInteger.valueOf(1_000_000L);
        assertThrows(Exception.class, () -> SealedBidCircuit.build().calculateWitness(
                bidWitness(bid, salt, reserve, bidCommitment(bid, salt)), CurveId.BLS12_381));
    }

    @Test
    @DisplayName("sealed bid: a wrapped reserve price cannot be 'cleared' by a tiny bid")
    void wrappedReservePriceRejected() {
        // Pre-ADR-0037 this combination was accepted: b near p drove diff into the wrap band.
        BigInteger bid = BigInteger.valueOf(42);
        BigInteger salt = BigInteger.valueOf(7);
        BigInteger reserve = P.subtract(BigInteger.ONE.shiftLeft(64)).add(BigInteger.valueOf(100));
        assertThrows(Exception.class, () -> SealedBidCircuit.build().calculateWitness(
                bidWitness(bid, salt, reserve, bidCommitment(bid, salt)), CurveId.BLS12_381),
                "a reserve price above 2^64 must fail the range constraint, not wrap");
    }

    @Test
    @DisplayName("sealed bid: an oversized bid is rejected rather than wrapping")
    void oversizedBidRejected() {
        BigInteger bid = P.subtract(BigInteger.ONE);
        BigInteger salt = BigInteger.valueOf(7);
        BigInteger reserve = BigInteger.valueOf(1_000_000L);
        assertThrows(Exception.class, () -> SealedBidCircuit.build().calculateWitness(
                bidWitness(bid, salt, reserve, bidCommitment(bid, salt)), CurveId.BLS12_381));
    }

    // ------------------------------------------------------------------
    //  Balance threshold: balance >= threshold
    // ------------------------------------------------------------------

    private static Map<String, List<BigInteger>> balanceWitness(
            BigInteger balance, BigInteger threshold, int isAbove) {
        return Map.of(
                "threshold", List.of(threshold),
                "isAboveThreshold", List.of(BigInteger.valueOf(isAbove)),
                "balance", List.of(balance));
    }

    @Test
    @DisplayName("balance threshold: honest above/below both compute correctly")
    void honestBalanceRelation() {
        assertDoesNotThrow(() -> BalanceThresholdCircuit.build().calculateWitness(
                balanceWitness(BigInteger.valueOf(1_500L), BigInteger.valueOf(1_000L), 1),
                CurveId.BLS12_381));
        assertDoesNotThrow(() -> BalanceThresholdCircuit.build().calculateWitness(
                balanceWitness(BigInteger.valueOf(500L), BigInteger.valueOf(1_000L), 0),
                CurveId.BLS12_381));
    }

    @Test
    @DisplayName("balance threshold: claiming 'above' when below is rejected")
    void falseAboveClaimRejected() {
        assertThrows(Exception.class, () -> BalanceThresholdCircuit.build().calculateWitness(
                balanceWitness(BigInteger.valueOf(500L), BigInteger.valueOf(1_000L), 1),
                CurveId.BLS12_381));
    }

    @Test
    @DisplayName("balance threshold: a wrapped threshold cannot be 'cleared' by a zero balance")
    void wrappedThresholdRejected() {
        BigInteger threshold = P.subtract(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE));
        assertThrows(Exception.class, () -> BalanceThresholdCircuit.build().calculateWitness(
                balanceWitness(BigInteger.ZERO, threshold, 1), CurveId.BLS12_381),
                "0 >= p-(2^64-1) is false; the range constraint must reject the threshold");
    }

    @Test
    @DisplayName("balance threshold: an oversized balance is rejected rather than wrapping")
    void oversizedBalanceRejected() {
        assertThrows(Exception.class, () -> BalanceThresholdCircuit.build().calculateWitness(
                balanceWitness(P.subtract(BigInteger.ONE), BigInteger.valueOf(1_000L), 0),
                CurveId.BLS12_381));
    }
}
