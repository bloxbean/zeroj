/**
 * BLS12-381 G1 Pedersen commitment profiles {@code pedersen-bls12-381-g1-v1} and
 * {@code pedersen-bls12-381-g1-bytes-v1} ({@code docs/specs/pedersen-bls12-381-g1-v1.md}, ADR-0060).
 *
 * <p>{@link org.zeroj.bls12381.pedersen.G1Pedersen} is the entry point. Commitments decode strictly
 * (48-octet compressed form, subgroup membership, identity accepted), scalars are never reduced,
 * and generation runs only offline/isolated. Experimental: not approved for value-bearing or
 * mainnet use.
 */
package org.zeroj.bls12381.pedersen;
