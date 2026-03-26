package com.bloxbean.cardano.zeroj.api;

import java.util.Arrays;
import java.util.Objects;

/**
 * Reference to a verification key — by hash or by registry identifier.
 *
 * <p>Proofs reference their verification key either by its SHA-256 hash
 * (for content-addressed lookup) or by a registry id (for named lookup).</p>
 */
public sealed interface VerificationKeyRef {

    /**
     * Reference by SHA-256 hash of the canonical VK encoding.
     *
     * @param hash the 32-byte SHA-256 hash
     */
    record ByHash(byte[] hash) implements VerificationKeyRef {

        public ByHash {
            Objects.requireNonNull(hash, "vk hash must not be null");
            if (hash.length != 32) {
                throw new IllegalArgumentException("vk hash must be 32 bytes, got " + hash.length);
            }
            hash = hash.clone();
        }

        @Override
        public byte[] hash() {
            return hash.clone();
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof ByHash h && Arrays.equals(hash, h.hash);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(hash);
        }

        @Override
        public String toString() {
            return "VKRef.ByHash[" + hexPrefix(hash) + "]";
        }
    }

    /**
     * Reference by a named registry identifier.
     *
     * @param id the registry identifier (must not be null or blank)
     */
    record ById(String id) implements VerificationKeyRef {

        public ById {
            Objects.requireNonNull(id, "vk id must not be null");
            if (id.isBlank()) {
                throw new IllegalArgumentException("vk id must not be blank");
            }
        }

        @Override
        public String toString() {
            return "VKRef.ById[" + id + "]";
        }
    }

    private static String hexPrefix(byte[] bytes) {
        var sb = new StringBuilder();
        for (int i = 0; i < Math.min(4, bytes.length); i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > 4) sb.append("...");
        return sb.toString();
    }
}
