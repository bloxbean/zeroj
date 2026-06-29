package com.bloxbean.cardano.zeroj.api;

/**
 * Identifies an elliptic curve used in proof generation and verification.
 */
public enum CurveId {
    /**
     * BN254 (alt_bn128) — legacy/off-chain only in ZeroJ.
     * Cardano does not expose BN254 pairing builtins, and ZeroJ BN254 verifiers
     * are disabled by default.
     */
    BN254("bn128"),

    /**
     * BLS12-381 — Cardano-native curve (CIP-0381), also used by Zcash, Ethereum 2.0.
     */
    BLS12_381("bls12381"),

    /**
     * Pallas — Pasta cycle curve used by Halo2 IPA (no trusted setup).
     * Part of the Pallas/Vesta cycle from Zcash Orchard.
     */
    PALLAS("pallas");

    private final String value;

    CurveId(String value) {
        this.value = value;
    }

    /**
     * Wire/serialization value matching snarkjs convention.
     */
    public String value() {
        return value;
    }

    /**
     * Parse a curve identifier from its wire value.
     *
     * @throws IllegalArgumentException if the value is not recognized
     */
    public static CurveId fromValue(String value) {
        for (CurveId id : values()) {
            if (id.value.equals(value)) {
                return id;
            }
        }
        throw new IllegalArgumentException("Unknown curve: " + value);
    }
}
