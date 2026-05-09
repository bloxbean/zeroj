package com.bloxbean.cardano.zeroj.bbs.spi;

import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Providers;

import java.util.Objects;

/**
 * Built-in BBS provider factories.
 */
public final class BbsProviders {
    private static final PureJavaBbsProvider SHA256 = new PureJavaBbsProvider(
            BbsCiphersuite.BLS12381_SHA256,
            Bls12381Providers.pureJava());
    private static final PureJavaBbsProvider SHAKE256 = new PureJavaBbsProvider(
            BbsCiphersuite.BLS12381_SHAKE256,
            Bls12381Providers.pureJava());

    private BbsProviders() {}

    public static BbsProvider pureJava() {
        return SHA256;
    }

    public static BbsProvider pureJava(BbsCiphersuite ciphersuite) {
        return switch (Objects.requireNonNull(ciphersuite, "ciphersuite required")) {
            case BLS12381_SHA256 -> SHA256;
            case BLS12381_SHAKE256 -> SHAKE256;
        };
    }

    public static BbsProvider withBlsProvider(BbsCiphersuite ciphersuite, Bls12381Provider bls) {
        return new PureJavaBbsProvider(
                Objects.requireNonNull(ciphersuite, "ciphersuite required"),
                Objects.requireNonNull(bls, "BLS provider required"));
    }
}
