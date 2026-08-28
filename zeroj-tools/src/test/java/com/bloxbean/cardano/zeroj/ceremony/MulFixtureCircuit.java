package com.bloxbean.cardano.zeroj.ceremony;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;

/**
 * Tiny programmatic fixture for CLI tests: proves {@code a·b == out} with {@code out} public —
 * shaped exactly like a generated {@code *Circuit} companion (static {@code build()}).
 */
public final class MulFixtureCircuit {

    private MulFixtureCircuit() {}

    public static CircuitBuilder build() {
        return CircuitBuilder.create("mul-fixture")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("out")));
    }
}
