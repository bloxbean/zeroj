package org.zeroj.api.commitment;

import java.io.IOException;

/**
 * The opening check of {@link CommitmentAcceptance#accept}: usually a strict, profile-specific
 * verification such as {@code PedersenCommitment.verifyScalar}.
 *
 * <p>Returns {@code false} for a well-formed opening that does not match. Throws
 * {@link CommitmentFormatException} for a malformed one; {@code INVALID_CONFIGURATION} means the
 * verifier itself is misconfigured and propagates out of {@code accept}.
 *
 * <p>An opening is secret until disclosed. A variable-time check is acceptable only where the
 * opening is already public or no party from whom it is still secret can observe the verifier's
 * timing ({@code commitment-profiles-v1} §6.2 timing rule).
 *
 * @param <C> the commitment type
 */
@FunctionalInterface
public interface OpeningCheck<C> {

    /** {@code true} iff the opening held by this check opens {@code commitment}. */
    boolean matches(C commitment) throws IOException;
}
