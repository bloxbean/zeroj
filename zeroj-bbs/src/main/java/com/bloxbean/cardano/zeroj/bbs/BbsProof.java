package com.bloxbean.cardano.zeroj.bbs;

import java.util.Arrays;
import java.util.Objects;

/**
 * CFRG BBS proof octets.
 */
public final class BbsProof {
    private final byte[] bytes;
    private final BbsCiphersuite ciphersuite;

    public BbsProof(byte[] bytes, BbsCiphersuite ciphersuite) {
        Objects.requireNonNull(bytes, "proof bytes required");
        Objects.requireNonNull(ciphersuite, "ciphersuite required");
        int floor = 3 * ciphersuite.g1Bytes() + 4 * ciphersuite.scalarBytes();
        if (bytes.length < floor) {
            throw new IllegalArgumentException("BBS proof is too short: " + bytes.length);
        }
        if ((bytes.length - floor) % ciphersuite.scalarBytes() != 0) {
            throw new IllegalArgumentException("BBS proof scalar section is not aligned to 32-byte scalars");
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
        return other instanceof BbsProof p
                && ciphersuite == p.ciphersuite
                && Arrays.equals(bytes, p.bytes);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(bytes) + ciphersuite.hashCode();
    }
}
