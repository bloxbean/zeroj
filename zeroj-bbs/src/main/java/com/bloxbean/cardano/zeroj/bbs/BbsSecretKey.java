package com.bloxbean.cardano.zeroj.bbs;

import java.math.BigInteger;
import java.util.Objects;

/**
 * CFRG BBS secret key scalar.
 */
public record BbsSecretKey(BigInteger value, BbsCiphersuite ciphersuite) {
    public BbsSecretKey {
        Objects.requireNonNull(value, "value required");
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        com.bloxbean.cardano.zeroj.bbs.internal.BbsCodec.scalarToBytes(value);
    }

    public byte[] toBytes() {
        return com.bloxbean.cardano.zeroj.bbs.internal.BbsCodec.scalarToBytes(value);
    }

    @Override
    public String toString() {
        return "BbsSecretKey[redacted, ciphersuite=" + ciphersuite + "]";
    }
}
