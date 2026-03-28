package com.bloxbean.cardano.zeroj.ingestion;

import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.backend.spi.VerificationKeyRegistry;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Verification key registry with rotation support.
 *
 * <p>Allows multiple VK versions per circuit. During rotation, both old and new VK are
 * accepted within a configurable transition window. After the window closes, only the
 * new VK is accepted.</p>
 *
 * <p>This prevents breaking in-flight proofs: a proof generated against VK v1 can still
 * be verified even after VK v2 is registered, as long as v1 hasn't expired.</p>
 */
public class VersionedVkRegistry implements VerificationKeyRegistry {

    private final Map<String, VerificationMaterial> byHash = new ConcurrentHashMap<>();
    private final Map<String, List<VkEntry>> byCircuit = new ConcurrentHashMap<>();
    private final VkRotationPolicy policy; // nullable — no policy enforcement if null

    public VersionedVkRegistry() {
        this(null);
    }

    public VersionedVkRegistry(VkRotationPolicy policy) {
        this.policy = policy;
    }

    /**
     * Register a new VK version for a circuit. Previous versions remain valid until expired.
     *
     * @param material  the verification material
     * @param expiresAt when this VK version expires (null = never expires)
     */
    public void registerVersion(VerificationMaterial material, Instant expiresAt) {
        byte[] hash = material.vkHash().orElseGet(() -> sha256(material.vkBytes()));
        String hashKey = hex(hash);
        byHash.put(hashKey, material);

        var entry = new VkEntry(material, Instant.now(), expiresAt);
        byCircuit.computeIfAbsent(material.circuitId().value(), k -> Collections.synchronizedList(new ArrayList<>()))
                .add(entry);
    }

    /**
     * Rotate: register a new VK and set an expiry on the previous version.
     * If a {@link VkRotationPolicy} is set, the rotation is validated against it.
     *
     * @param newMaterial     the new VK
     * @param transitionWindow how long the old VK remains valid after rotation
     * @return the rotation result
     */
    public RotationResult rotate(VerificationMaterial newMaterial, java.time.Duration transitionWindow) {
        var circuitId = newMaterial.circuitId().value();

        // Policy enforcement
        if (policy != null) {
            // Check minimum transition window
            if (transitionWindow.compareTo(policy.minTransitionWindow()) < 0) {
                return new RotationResult.Rejected("Transition window " + transitionWindow
                        + " is shorter than policy minimum " + policy.minTransitionWindow());
            }

            var entries = byCircuit.get(circuitId);
            if (entries != null) {
                // Check max active VKs (count non-expired + the new one)
                var now = Instant.now();
                long activeCount = entries.stream()
                        .filter(e -> e.expiresAt() == null || now.isBefore(e.expiresAt()))
                        .count();
                if (activeCount + 1 > policy.maxActiveVksPerCircuit()) {
                    return new RotationResult.Rejected("Would exceed max active VKs per circuit ("
                            + policy.maxActiveVksPerCircuit() + ")");
                }

                // Check min time between rotations
                if (!policy.minTimeBetweenRotations().isZero() && !entries.isEmpty()) {
                    var lastRegistered = entries.getLast().registeredAt();
                    if (now.isBefore(lastRegistered.plus(policy.minTimeBetweenRotations()))) {
                        return new RotationResult.Rejected("Too soon since last rotation; minimum interval is "
                                + policy.minTimeBetweenRotations());
                    }
                }
            }
        }

        // Expire all current active VKs for this circuit
        var entries = byCircuit.get(circuitId);
        if (entries != null) {
            var expiryTime = Instant.now().plus(transitionWindow);
            for (int i = 0; i < entries.size(); i++) {
                var entry = entries.get(i);
                if (entry.expiresAt() == null) {
                    entries.set(i, new VkEntry(entry.material(), entry.registeredAt(), expiryTime));
                }
            }
        }

        // Register the new VK (never expires until next rotation)
        registerVersion(newMaterial, null);
        return RotationResult.Success.INSTANCE;
    }

    /**
     * Result of a VK rotation attempt.
     */
    public sealed interface RotationResult {
        record Success() implements RotationResult {
            static final Success INSTANCE = new Success();
        }
        record Rejected(String reason) implements RotationResult {}
    }

    /**
     * Check if a specific VK hash is currently valid (registered and not expired).
     */
    public boolean isValid(byte[] vkHash) {
        var material = byHash.get(hex(vkHash));
        if (material == null) return false;

        var entries = byCircuit.get(material.circuitId().value());
        if (entries == null) return false;

        var now = Instant.now();
        return entries.stream()
                .anyMatch(e -> Arrays.equals(sha256(e.material().vkBytes()), vkHash)
                        && (e.expiresAt() == null || now.isBefore(e.expiresAt())));
    }

    /**
     * Get the current (latest non-expired) VK for a circuit.
     */
    public Optional<VerificationMaterial> getCurrentVk(String circuitId) {
        var entries = byCircuit.get(circuitId);
        if (entries == null) return Optional.empty();

        var now = Instant.now();
        // Return the most recently registered non-expired entry
        for (int i = entries.size() - 1; i >= 0; i--) {
            var entry = entries.get(i);
            if (entry.expiresAt() == null || now.isBefore(entry.expiresAt())) {
                return Optional.of(entry.material());
            }
        }
        return Optional.empty();
    }

    /**
     * List all VK entries (active and expired) for a circuit.
     */
    public List<VkEntry> listEntries(String circuitId) {
        return byCircuit.getOrDefault(circuitId, List.of());
    }

    // --- VerificationKeyRegistry implementation ---

    @Override
    public Optional<VerificationMaterial> lookup(VerificationKeyRef ref) {
        return switch (ref) {
            case VerificationKeyRef.ByHash h -> {
                var mat = byHash.get(hex(h.hash()));
                yield Optional.ofNullable(mat);
            }
            case VerificationKeyRef.ById id -> getCurrentVk(id.id());
        };
    }

    @Override
    public void register(VerificationMaterial material) {
        registerVersion(material, null);
    }

    /**
     * A VK entry with registration and expiry timestamps.
     */
    public record VkEntry(VerificationMaterial material, Instant registeredAt, Instant expiresAt) {
        public boolean isExpiredAt(Instant now) {
            return expiresAt != null && now.isAfter(expiresAt);
        }
    }

    private static byte[] sha256(byte[] data) {
        try { return MessageDigest.getInstance("SHA-256").digest(data); }
        catch (NoSuchAlgorithmException e) { throw new RuntimeException(e); }
    }

    private static String hex(byte[] bytes) {
        var sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
