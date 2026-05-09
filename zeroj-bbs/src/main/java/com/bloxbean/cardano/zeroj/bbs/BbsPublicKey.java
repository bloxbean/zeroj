package com.bloxbean.cardano.zeroj.bbs;

import java.util.Arrays;
import java.util.Objects;

/**
 * CFRG BBS public key octets.
 */
public final class BbsPublicKey {
    private final byte[] bytes;
    private final BbsCiphersuite ciphersuite;

    public BbsPublicKey(byte[] bytes, BbsCiphersuite ciphersuite) {
        this.bytes = requireNonEmpty(bytes, "public key").clone();
        this.ciphersuite = Objects.requireNonNull(ciphersuite, "ciphersuite required");
        if (this.bytes.length != ciphersuite.g2Bytes()) {
            throw new IllegalArgumentException("BBS public key must be " + ciphersuite.g2Bytes()
                    + " bytes, got " + this.bytes.length);
        }
    }

    public byte[] bytes() {
        return bytes.clone();
    }

    public BbsCiphersuite ciphersuite() {
        return ciphersuite;
    }

    private static byte[] requireNonEmpty(byte[] bytes, String label) {
        Objects.requireNonNull(bytes, label + " required");
        if (bytes.length == 0) {
            throw new IllegalArgumentException(label + " must not be empty");
        }
        return bytes;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof BbsPublicKey k
                && ciphersuite == k.ciphersuite
                && Arrays.equals(bytes, k.bytes);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(bytes) + ciphersuite.hashCode();
    }
}
