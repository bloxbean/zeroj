package com.bloxbean.cardano.zeroj.api;

/**
 * Identifies a zero-knowledge proof system.
 */
public enum ProofSystemId {
    GROTH16("groth16"),
    PLONK("plonk"),
    FFLONK("fflonk"),
    HALO2("halo2");

    private final String value;

    ProofSystemId(String value) {
        this.value = value;
    }

    /**
     * Wire/serialization value (lowercase, stable across versions).
     */
    public String value() {
        return value;
    }

    /**
     * Parse a proof system identifier from its wire value.
     *
     * @throws IllegalArgumentException if the value is not recognized
     */
    public static ProofSystemId fromValue(String value) {
        for (ProofSystemId id : values()) {
            if (id.value.equals(value)) {
                return id;
            }
        }
        throw new IllegalArgumentException("Unknown proof system: " + value);
    }
}
