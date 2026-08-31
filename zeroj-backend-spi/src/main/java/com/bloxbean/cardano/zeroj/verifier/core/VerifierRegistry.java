package com.bloxbean.cardano.zeroj.verifier.core;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;

import java.util.*;

/**
 * Registry of available verification backends.
 *
 * <p>Backends can be registered manually or discovered via {@link java.util.ServiceLoader}.</p>
 */
public class VerifierRegistry {

    private final List<ZkVerifier> verifiers = new ArrayList<>();

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
     * Find a verifier that supports the given proof system and curve.
     *
     * @return the verifier, or empty if no backend supports this combination
     */
    public Optional<ZkVerifier> find(ProofSystemId proofSystem, CurveId curve) {
        return verifiers.stream()
                .filter(v -> v.descriptor().supports(proofSystem, curve))
                .findFirst();
    }

    /**
     * List all registered backends.
     */
    public List<ZkVerifier> all() {
        return Collections.unmodifiableList(verifiers);
    }
}
