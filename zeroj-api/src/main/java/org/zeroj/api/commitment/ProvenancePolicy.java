package org.zeroj.api.commitment;

/**
 * The application's provenance check ({@code commitment-profiles-v1} §6.3, class P): whether an
 * authenticated issuance record binds this exact point, profile and context.
 *
 * <p>A matching envelope label is not provenance. An implementation that has nothing to check
 * must say so explicitly by returning {@link Result#OK}.
 *
 * @param <C> the commitment type
 */
@FunctionalInterface
public interface ProvenancePolicy<C> {

    /** The outcome of a provenance check. */
    enum Result {
        /** An authenticated record binds this point, profile and context. */
        OK,
        /** No authenticated issuance record exists. */
        MISSING,
        /** A record exists but does not bind this point, profile and context. */
        MISMATCH
    }

    /** Checks the decoded commitment; never returns null. */
    Result check(C commitment);
}
