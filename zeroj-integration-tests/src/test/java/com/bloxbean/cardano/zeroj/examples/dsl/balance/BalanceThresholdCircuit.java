package com.bloxbean.cardano.zeroj.examples.dsl.balance;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalComparators;

/**
 * Balance threshold circuit — proves a balance exceeds a threshold without revealing the balance.
 *
 * <p>Use case: DeFi eligibility checks, tiered access control, credit scoring.</p>
 *
 * <p>Signals:</p>
 * <ul>
 *   <li><b>Private:</b> balance</li>
 *   <li><b>Public:</b> threshold (input), isAboveThreshold (output)</li>
 * </ul>
 */
public class BalanceThresholdCircuit implements CircuitSpec {

    @Override
    public void define(SignalBuilder c) {
        // Private input — the actual balance (not revealed)
        Signal balance = c.privateInput("balance");

        // Public input — the threshold to check against
        Signal threshold = c.publicInput("threshold");

        // Public output — 1 if balance >= threshold, 0 otherwise
        Signal isAboveThreshold = c.publicOutput("isAboveThreshold");

        // Constraint: isAboveThreshold == (balance >= threshold) ? 1 : 0
        c.assertEqual(
                SignalComparators.greaterOrEqual(c, balance, threshold, 64),
                isAboveThreshold);
    }

    /**
     * Build a complete circuit with all signals declared.
     */
    public static CircuitBuilder build() {
        return CircuitBuilder.create("balance-threshold")
                .publicVar("threshold")
                .publicVar("isAboveThreshold")
                .secretVar("balance")
                .defineSignals(new BalanceThresholdCircuit());
    }
}
