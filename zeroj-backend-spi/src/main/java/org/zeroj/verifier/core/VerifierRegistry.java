package org.zeroj.verifier.core;

import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.backend.spi.ZkVerifier;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe registry of available verification backends.
 *
 * <p>Backends can be registered manually or discovered via {@link java.util.ServiceLoader}.</p>
 */
public class VerifierRegistry {

    private final List<ZkVerifier> verifiers = new CopyOnWriteArrayList<>();

    /**
     * Create a registry that auto-discovers backends via ServiceLoader.
     */
    public static VerifierRegistry withServiceLoader() {
        var registry = new VerifierRegistry();
        ServiceLoader.load(ZkVerifier.class).forEach(registry::register);
        return registry;
    }

    /**
     * Create an empty registry (for manual registration).
     */
    public static VerifierRegistry empty() {
        return new VerifierRegistry();
    }

    /**
     * Register a verification backend.
     */
    public void register(ZkVerifier verifier) {
        verifiers.add(Objects.requireNonNull(verifier));
    }

    /**
     * Find a verifier that supports the given proof system and curve, in registration order,
     * skipping backends that are not {@linkplain ZkVerifier#isAvailable() available} on this
     * platform (e.g. the blst verifier where no {@code libblst} is bundled, ADR-0062).
     *
     * @return the verifier, or empty if no available backend supports this combination
     */
    public Optional<ZkVerifier> find(ProofSystemId proofSystem, CurveId curve) {
        return verifiers.stream()
                .filter(v -> v.descriptor().supports(proofSystem, curve))
                .filter(ZkVerifier::isAvailable)
                .findFirst();
    }

    /**
     * List all registered backends as an immutable snapshot.
     */
    public List<ZkVerifier> all() {
        return List.copyOf(verifiers);
    }
}
