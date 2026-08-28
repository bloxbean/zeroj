package com.bloxbean.cardano.zeroj.examples.dsl.auction;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalComparators;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * Sealed-bid auction circuit — proves a bid is valid without revealing the amount.
 *
 * <p>The bidder commits to their bid:
 * {@code bidCommitment = PoseidonBLS12_381(bidAmount, salt)}.
 * The circuit proves two things:</p>
 * <ol>
 *   <li>The bidder knows {@code bidAmount} and {@code salt} that produce the public commitment</li>
 *   <li>The bid amount is at or above the reserve price</li>
 * </ol>
 *
 * <p>Signals:</p>
 * <ul>
 *   <li><b>Private:</b> bidAmount, salt</li>
 *   <li><b>Public:</b> bidCommitment (output), reservePrice (input)</li>
 * </ul>
 */
public class SealedBidCircuit implements CircuitSpec {

    @Override
    public void define(SignalBuilder c) {
        // Private inputs — known only to the bidder
        Signal bidAmount = c.privateInput("bidAmount");
        Signal salt = c.privateInput("salt");

        // Public values — verifiable by anyone and consumed by the on-chain verifier
        Signal bidCommitment = c.publicOutput("bidCommitment");
        Signal reservePrice = c.publicInput("reservePrice");

        // Constraint 1: bidCommitment == PoseidonBLS12_381(bidAmount, salt)
        c.assertEqual(
                SignalPoseidon.hash(c, PoseidonParamsBLS12_381T3.INSTANCE, bidAmount, salt),
                bidCommitment);

        // Constraint 2: bidAmount >= reservePrice must hold inside the proof.
        c.assertEqual(
                SignalComparators.greaterOrEqual(c, bidAmount, reservePrice, 64),
                c.constant(1));
    }

    /**
     * Build a complete circuit with all signals declared.
     *
     * <p>Wire layout (iden3 convention): [1, bidCommitment, reservePrice, bidAmount, salt, ...]</p>
     */
    public static CircuitBuilder build() {
        return CircuitBuilder.create("sealed-bid")
                .publicVar("bidCommitment")
                .publicVar("reservePrice")
                .secretVar("bidAmount")
                .secretVar("salt")
                .defineSignals(new SealedBidCircuit());
    }
}
