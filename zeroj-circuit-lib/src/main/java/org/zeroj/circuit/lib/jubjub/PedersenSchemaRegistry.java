package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;

/**
 * Verifier-side registry for {@code pedersen-jubjub-vector-v1} statement binding
 * ({@code docs/specs/pedersen-jubjub-vector-v1.md} §5, ADR-0051 D5).
 *
 * <p>Maps each verification key the deployment accepts to exactly one expected schema digest.
 * Before accepting a proof, the verifier calls {@link #requireStatement} with the key it verified
 * against and the schema-digest public input the proof carries. The expected digest comes only
 * from this registry, which the deployment builds from its own configuration — never from the
 * prover or from data travelling with the proof.
 *
 * <p>Keys are identified by caller-chosen bytes, typically a hash of the serialised verification
 * key. Immutable once built.
 */
public final class PedersenSchemaRegistry {

    private final Map<String, PedersenVectorSchema> expected;

    private PedersenSchemaRegistry(Map<String, PedersenVectorSchema> expected) {
        this.expected = Map.copyOf(expected);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** The schema the deployment expects for {@code verificationKeyId}. */
    public PedersenVectorSchema expectedSchema(byte[] verificationKeyId) {
        PedersenVectorSchema schema = expected.get(key(verificationKeyId));
        if (schema == null) {
            throw new IllegalArgumentException("verification key is not registered for any vector schema");
        }
        return schema;
    }

    /**
     * Accepts the statement only if {@code verificationKeyId} is registered and
     * {@code presentedDigest} — the schema-digest public input of the proof — equals the digest
     * of its registered schema.
     *
     * @throws IllegalArgumentException if the key is unknown or the digest does not match
     */
    public void requireStatement(byte[] verificationKeyId, BigInteger presentedDigest) {
        Objects.requireNonNull(presentedDigest, "presentedDigest");
        PedersenVectorSchema schema = expectedSchema(verificationKeyId);
        if (!schema.digest().equals(presentedDigest)) {
            throw new IllegalArgumentException("proof carries schema digest " + presentedDigest.toString(16)
                    + " but this key expects " + schema + " (" + schema.digest().toString(16) + ")");
        }
    }

    private static String key(byte[] verificationKeyId) {
        Objects.requireNonNull(verificationKeyId, "verificationKeyId");
        return HexFormat.of().formatHex(verificationKeyId);
    }

    /** Builds a registry; each key may be registered once. */
    public static final class Builder {
        private final Map<String, PedersenVectorSchema> entries = new HashMap<>();

        private Builder() {}

        public Builder accept(byte[] verificationKeyId, PedersenVectorSchema schema) {
            Objects.requireNonNull(schema, "schema");
            if (entries.putIfAbsent(key(verificationKeyId), schema) != null) {
                throw new IllegalArgumentException("verification key is already registered");
            }
            return this;
        }

        public PedersenSchemaRegistry build() {
            return new PedersenSchemaRegistry(entries);
        }
    }
}
