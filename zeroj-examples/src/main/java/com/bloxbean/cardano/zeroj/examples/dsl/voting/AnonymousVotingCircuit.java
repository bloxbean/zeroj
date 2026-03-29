package com.bloxbean.cardano.zeroj.examples.dsl.voting;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMiMC;

/**
 * Anonymous voting circuit — proves a vote is valid without revealing the choice.
 *
 * <p>The voter commits to their vote: {@code commitment = MiMC(vote, nullifier)}.
 * The nullifier prevents double-voting (revealed on-chain), while the vote remains private.</p>
 *
 * <p>Signals:</p>
 * <ul>
 *   <li><b>Private:</b> vote (0 or 1), nullifier</li>
 *   <li><b>Public:</b> commitment (output)</li>
 * </ul>
 */
public class AnonymousVotingCircuit implements CircuitSpec {

    @Override
    public void define(SignalBuilder c) {
        // Private inputs
        Signal vote = c.privateInput("vote");
        Signal nullifier = c.privateInput("nullifier");

        // Public output
        Signal commitment = c.publicOutput("commitment");

        // Constraint 1: vote must be boolean (0 or 1)
        vote.assertBoolean();

        // Constraint 2: commitment == MiMC(vote, nullifier)
        c.assertEqual(SignalMiMC.hash(c, vote, nullifier), commitment);
    }

    /**
     * Build a complete circuit with all signals declared.
     */
    public static CircuitBuilder build() {
        return CircuitBuilder.create("anonymous-vote")
                .publicVar("commitment")
                .secretVar("vote")
                .secretVar("nullifier")
                .defineSignals(new AnonymousVotingCircuit());
    }
}
