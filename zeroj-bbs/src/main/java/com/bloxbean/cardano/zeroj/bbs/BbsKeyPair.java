package com.bloxbean.cardano.zeroj.bbs;

import java.util.Objects;

/**
 * CFRG BBS key pair.
 */
public record BbsKeyPair(BbsSecretKey secretKey, BbsPublicKey publicKey) {
    public BbsKeyPair {
        Objects.requireNonNull(secretKey, "secretKey required");
        Objects.requireNonNull(publicKey, "publicKey required");
        if (secretKey.ciphersuite() != publicKey.ciphersuite()) {
            throw new IllegalArgumentException("secret and public key ciphersuites differ");
        }
    }
}
