package org.zeroj.backend.spi;

import org.zeroj.api.VerificationKeyRef;
import org.zeroj.api.VerificationMaterial;

import java.util.Optional;

/**
 * Registry for looking up verification keys by reference.
 *
 * <p>Implementations may store keys in memory, on disk, or in a remote registry.</p>
 */
public interface VerificationKeyRegistry {

    /**
     * Look up a verification key by its reference.
     *
     * @param ref the VK reference (by hash or by id)
     * @return the verification material, or empty if not found
     */
    Optional<VerificationMaterial> lookup(VerificationKeyRef ref);

    /**
     * Register a verification key.
     *
     * @param material the verification material to store
     */
    void register(VerificationMaterial material);
}
