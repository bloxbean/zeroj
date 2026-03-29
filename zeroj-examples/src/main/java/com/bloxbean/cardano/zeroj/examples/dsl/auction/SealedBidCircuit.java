package com.bloxbean.cardano.zeroj.examples.dsl.auction;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalComparators;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMiMC;

/**
 * Sealed-bid auction circuit — proves a bid is valid without revealing the amount.
 *
 * <p>The bidder commits to their bid: {@code bidCommitment = MiMC(bidAmount, salt)}.
 * The circuit proves two things:</p>
 * <ol>
 *   <li>The bidder knows {@code bidAmount} and {@code salt} that produce the public commitment</li>
 *   <li>The bid amount is at or above the reserve price</li>
 * </ol>
 *
 * <p>Signals:</p>
 * <ul>
 *   <li><b>Private:</b> bidAmount, salt</li>
 *   <li><b>Public:</b> reservePrice (input), bidCommitment (output), isAboveReserve (output)</li>
 * </ul>
 */
public class SealedBidCircuit implements CircuitSpec {

    @Override
    public void define(SignalBuilder c) {
        // Private inputs — known only to the bidder
        Signal bidAmount = c.privateInput("bidAmount");
        Signal salt = c.privateInput("salt");

        // Public input — the auction's minimum price
        Signal reservePrice = c.publicInput("reservePrice");

        // Public outputs — verifiable by anyone
        Signal bidCommitment = c.publicOutput("bidCommitment");
        Signal isAboveReserve = c.publicOutput("isAboveReserve");

        // Constraint 1: bidCommitment == MiMC(bidAmount, salt)
        c.assertEqual(SignalMiMC.hash(c, bidAmount, salt), bidCommitment);

        // Constraint 2: isAboveReserve == (bidAmount >= reservePrice) ? 1 : 0
        c.assertEqual(
                SignalComparators.greaterOrEqual(c, bidAmount, reservePrice, 64),
                isAboveReserve);
    }

    /**
     * Build a complete circuit with all signals declared.
     *
     * <p>Wire layout (iden3 convention): [1, reservePrice, bidCommitment, isAboveReserve, bidAmount, salt, ...]</p>
     */
    public static CircuitBuilder build() {
        return CircuitBuilder.create("sealed-bid")
                .publicVar("reservePrice")
                .publicVar("bidCommitment")
                .publicVar("isAboveReserve")
                .secretVar("bidAmount")
                .secretVar("salt")
                .defineSignals(new SealedBidCircuit());
    }
}
