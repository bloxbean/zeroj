package org.zeroj.backend.spi;

import org.zeroj.api.VerificationKeyRef;
import org.zeroj.api.VerificationMaterial;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
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
        Objects.requireNonNull(ref, "VerificationKeyRef must not be null");
        return switch (ref) {
            case VerificationKeyRef.ById id -> Optional.ofNullable(byId.get(id.id()));
            case VerificationKeyRef.ByHash h -> Optional.ofNullable(byHash.get(new HashKey(h.hash())));
        };
    }

    @Override
    public void register(VerificationMaterial material) {
        Objects.requireNonNull(material, "VerificationMaterial must not be null");
        byte[] actualHash = EnvelopeBinding.sha256(material.vkBytes());
        if (material.vkHash().isPresent()
                && !Arrays.equals(material.vkHash().orElseThrow(), actualHash)) {
            throw new IllegalArgumentException(
                    "VerificationMaterial vkHash does not match SHA-256 of vkBytes");
        }
        byHash.put(new HashKey(actualHash), material);

        // Also register by circuit id for convenience
        byId.put(material.circuitId().value(), material);
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
