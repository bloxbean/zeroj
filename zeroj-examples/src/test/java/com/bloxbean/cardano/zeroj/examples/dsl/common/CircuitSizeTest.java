package com.bloxbean.cardano.zeroj.examples.dsl.common;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.examples.dsl.auction.SealedBidCircuit;
import com.bloxbean.cardano.zeroj.examples.dsl.balance.BalanceThresholdCircuit;
import com.bloxbean.cardano.zeroj.examples.dsl.voting.AnonymousVotingCircuit;
import org.junit.jupiter.api.Test;

class CircuitSizeTest {

    @Test
    void printConstraintCounts() {
        var sealed = SealedBidCircuit.build().compileR1CS(CurveId.BLS12_381);
        System.out.println("SealedBid: constraints=" + sealed.numConstraints()
                + " wires=" + sealed.numWires() + " public=" + sealed.numPublicInputs());

        var voting = AnonymousVotingCircuit.build().compileR1CS(CurveId.BLS12_381);
        System.out.println("Voting: constraints=" + voting.numConstraints()
                + " wires=" + voting.numWires() + " public=" + voting.numPublicInputs());

        var balance = BalanceThresholdCircuit.build().compileR1CS(CurveId.BLS12_381);
        System.out.println("Balance: constraints=" + balance.numConstraints()
                + " wires=" + balance.numWires() + " public=" + balance.numPublicInputs());
    }
}
