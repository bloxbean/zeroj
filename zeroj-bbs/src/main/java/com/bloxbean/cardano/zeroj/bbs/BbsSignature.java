package com.bloxbean.cardano.zeroj.bbs;

import java.util.Arrays;
import java.util.Objects;

/**
 * CFRG BBS signature octets.
 */
public final class BbsSignature {
    private final byte[] bytes;
    private final BbsCiphersuite ciphersuite;

    public BbsSignature(byte[] bytes, BbsCiphersuite ciphersuite) {
        Objects.requireNonNull(bytes, "signature bytes required");
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        if (bytes.length != ciphersuite.g1Bytes() + ciphersuite.scalarBytes()) {
            throw new IllegalArgumentException("BBS signature must be "
                    + (ciphersuite.g1Bytes() + ciphersuite.scalarBytes()) + " bytes, got " + bytes.length);
        }
        this.bytes = bytes.clone();
        this.ciphersuite = ciphersuite;
    }

    public byte[] bytes() {
        return bytes.clone();
    }

    public BbsCiphersuite ciphersuite() {
        return ciphersuite;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof BbsSignature s
                && ciphersuite == s.ciphersuite
                && Arrays.equals(bytes, s.bytes);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(bytes) + ciphersuite.hashCode();
    }
}
