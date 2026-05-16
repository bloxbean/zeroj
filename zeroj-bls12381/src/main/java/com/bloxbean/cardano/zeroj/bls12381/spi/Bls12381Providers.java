package com.bloxbean.cardano.zeroj.bls12381.spi;

/**
 * Built-in BLS12-381 provider factories.
 */
public final class Bls12381Providers {
    private Bls12381Providers() {}

    public static Bls12381Provider pureJava() {
        return PureJavaBls12381Provider.INSTANCE;
    }
}
