package org.zeroj.backend.spi;

import org.zeroj.api.VerificationMaterial;
import org.zeroj.api.VerificationResult;
import org.zeroj.api.ZkProofEnvelope;

/**
 * Service Provider Interface for ZK proof verification backends.
 *
 * <p>Implementations verify cryptographic proofs for specific proof system + curve combinations.
 * They are discovered via {@link java.util.ServiceLoader} and registered with the
 * {@link org.zeroj.verifier.core.VerifierRegistry}.</p>
 *
 * <p>A verifier is responsible only for <em>cryptographic</em> verification.
 * Policy/protocol validation is handled separately.</p>
 */
public interface ZkVerifier {

    /**
     * Verify a proof envelope against the given verification material.
     *
     * @param envelope the proof envelope containing proof bytes, public inputs, and metadata
     * @param material the verification key and associated metadata
     * @return the verification result (crypto validity only — not policy validity)
     */
    VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material);

    /**
     * Describes what this verifier supports (proof system + curve).
     */
    BackendDescriptor descriptor();

    /**
     * Whether this backend can run on this platform at all, e.g. whether its native library is
     * bundled for it. {@link org.zeroj.verifier.core.VerifierRegistry#find} skips unavailable
     * backends. It must not be used to hide a failure on a supported platform (such as a native
     * library failing its integrity check): that backend stays available and reports the error.
     */
    default boolean isAvailable() {
        return true;
    }
}
