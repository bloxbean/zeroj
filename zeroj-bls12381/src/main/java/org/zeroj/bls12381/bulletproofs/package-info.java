/**
 * Bulletproof range proofs over {@code pedersen-bls12-381-g1-v1} commitments: the proof protocol
 * {@code bulletproof-range-bls12-381-g1-v1} ({@code docs/specs/bulletproof-range-bls12-381-g1-v1.md},
 * ADR-0061).
 *
 * <p>{@link org.zeroj.bls12381.bulletproofs.G1RangeProver} proves {@code 0 ≤ v < 2^n},
 * {@code n ∈ {16, 32, 64}}, for a commitment {@code V ≠ O};
 * {@link org.zeroj.bls12381.bulletproofs.G1RangeVerifier} checks it under the verifier's own width
 * and application context; {@link org.zeroj.bls12381.bulletproofs.G1RangeProof} is the proof. The
 * transcript is the {@code draft-irtf-cfrg-fiat-shamir-03} SHAKE128 duplex sponge with the
 * {@code sigma-proofs_Shake128_BLS12381} codecs of {@code draft-irtf-cfrg-sigma-protocols-03}.
 *
 * <p>No public or protected member of this package accepts nonces, a seed, a nonce source, a random
 * source, generators or a transcript. A verified proof is not authorization, replay protection or a
 * balance rule (spec §1.1, §13). Proving is offline/isolated only and makes no constant-time claim.
 * There is no on-chain verifier: Plutus V3 has no SHAKE128 builtin (spec §12).
 *
 * <p>Experimental: the registry lists the protocol as {@code active} (experimental) from
 * {@code commitment-profiles-v1} r9. Nothing here is approved for
 * value-bearing or mainnet use; external cryptographic review is required first (ADR-0061).
 */
package org.zeroj.bls12381.bulletproofs;
