package com.bloxbean.cardano.zeroj.backend.spi;

import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link VerificationKeyRegistry}.
 *
 * <p>Supports lookup by both hash and id. Thread-safe via ConcurrentHashMap.</p>
 */
public class InMemoryVerificationKeyRegistry implements VerificationKeyRegistry {

    private final Map<String, VerificationMaterial> byId = new ConcurrentHashMap<>();
    private final Map<HashKey, VerificationMaterial> byHash = new ConcurrentHashMap<>();

    @Override
    public Optional<VerificationMaterial> lookup(VerificationKeyRef ref) {
        return switch (ref) {
            case VerificationKeyRef.ById id -> Optional.ofNullable(byId.get(id.id()));
            case VerificationKeyRef.ByHash h -> Optional.ofNullable(byHash.get(new HashKey(h.hash())));
        };
    }

    @Override
    public void register(VerificationMaterial material) {
        // Register by hash (computed from VK bytes if not provided)
        byte[] hash = material.vkHash()
                .orElseGet(() -> sha256(material.vkBytes()));
        byHash.put(new HashKey(hash), material);

        // Also register by circuit id for convenience
        byId.put(material.circuitId().value(), material);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private record HashKey(byte[] hash) {
        @Override
        public boolean equals(Object o) {
            return o instanceof HashKey h && Arrays.equals(hash, h.hash);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(hash);
        }
    }
}
