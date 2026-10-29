/**
 * Profile-independent commitment contracts ({@code docs/specs/commitment-profiles-v1.md} §12.1,
 * ADR-0059).
 *
 * <p>These types name a commitment profile, carry a commitment in an off-chain envelope, build a
 * safe map key and combine decoding, provenance and opening checks into one result. They perform
 * no group arithmetic and hold no secret. Concrete profiles (for example the Jubjub Pedersen
 * profiles in {@code zeroj-circuit-lib}) implement {@link org.zeroj.api.commitment.Commitment} and
 * {@link org.zeroj.api.commitment.CommitmentCodec}.
 *
 * <p><b>The expected profile always comes from the caller's trusted configuration</b>, never from
 * data that travels with the input: every decoder takes the expected codec, and no decoder selects
 * a profile from an embedded identifier (spec §6.3). An envelope is not authentication; a matching
 * label is not provenance.
 *
 * <p><b>Closure is a language-level property.</b> "No public factory" and package-private
 * constructors stop ordinary callers, not code that shares the package or uses reflection. The
 * {@code zeroj-api} jar seals this package, so another jar on the class path cannot add classes to
 * it; code that can run reflection or redefine classes in the same process is outside the threat
 * model (spec §12.1).
 *
 * <p>Experimental: these contracts are not approved for value-bearing or mainnet use.
 */
package org.zeroj.api.commitment;
