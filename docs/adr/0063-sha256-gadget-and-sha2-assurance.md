# ADR-0063: SHA-256 gadget and SHA-2 constraint assurance

## Status and scope

Accepted for bounded implementation under [issue #111](https://github.com/bloxbean/zeroj/issues/111).
Independent security review and production approval remain open. This extends ADR-0027's
standard hash-gadget family without changing the proof system, compiler or setup policy.

Risk: **R2 circuit integration / R3 standard hash implementation**. The implementation
uses FIPS SHA-256, not a new hash construction. SHA-512 receives a focused review and
additional adversarial tests; only concrete compatibility-preserving hardening is in scope.

## References

- NIST [FIPS 180-4, August 2015](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf):
  SHA-256 §§4.1.2, 4.2.2, 5.1.1, 5.2.1, 5.3.3, 6.2; SHA-512 §§4.1.3, 4.2.3,
  5.1.2, 5.2.2, 5.3.5, 6.4.
- NIST [CAVP SHA test vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing),
  with source ZIP hash and selected original messages/digests retained in test resources.
- ADR-0027: standard hash gadgets and symbolic adapters; ADR-0028: hint soundness;
  ADR-0044: default pure-Java module boundary; ADR-0047: independent interoperability.
- Circom 2.2.3, snarkjs 0.7.6, circomlib commit
  `35e54ea21da3e8762557234298dbb553c175ea8d`, Electron-Labs SHA-512 commit
  `be9f01d870c40c3fe4e0ff27c93232d205bc46f7` are independent constraint-level oracles.
  Their licenses stay with optional assurance dependencies; runtime Java code is derived
  from the standard and ZeroJ's existing construction, not copied from those circuits.

## Threat model and invariants

The prover controls message and intermediate witness field values. Message content can
be secret; its array length is fixed at circuit definition and public through the circuit.
Circuit authors choose the public statement and must bind the returned digest themselves.

1. `Sha256.hashBytes` accepts field-valued bytes, constraining each to 0..255 via an
   eight-bit decomposition and reconstruction. It returns all 32 digest bytes in order.
2. `Sha256.hashBits` follows `Sha512.hashBits`: byte-aligned input only, MSB-first within
   each byte, every input constrained boolean, and all 256 output bits in the same order.
3. SHA words are internally LSB-first. Rotations/shifts only reindex constrained bits;
   padding, length suffix, initial words and round constants are circuit constants.
4. Standard Boolean XOR/choice/majority polynomials preserve the Boolean invariant.
   A modular word addition constrains the whole sum and carry before taking low bits.
   At most five words are added: SHA-256 sums are below 2^35 and SHA-512 below 2^67,
   so neither wraps in the supported BLS12-381, BN254 or Pallas scalar fields.
5. Input byte count multiplication and padded-array rounding use checked arithmetic
   before allocation/emitting constraints. Java array limits bound the API more tightly
   than FIPS's theoretical maximum; overflow must fail explicitly.
6. No digest truncation, reduction of a complete digest modulo Fr, host-hash hint,
   unconstrained carry or witness-dependent circuit branch is introduced.
7. `ZkSha256.hash` follows `ZkSha512`, including null checks and context ownership checks.
   No native provider, reflection, new runtime dependency or processor extension is needed.

Underlying witness arithmetic uses the existing DSL and is not claimed constant-time.
Benchmark fixtures are public. Secret-bearing deployment still requires isolation,
side-channel review and the wider repository's security gates. A public deterministic
digest may reveal low-entropy data; a preimage relation alone does not authenticate an
issuer or authorize a transaction. Groth16 remains classical and setup-dependent.

## Decision and alternatives

Add `lib/hash/Sha256` and `lib/zk/ZkSha256` beside the existing SHA-512 APIs. Keep the
fixed-length array contract and full digest output. Reuse ZeroJ bit operations and the
established bounded-carry construction. The byte API calls the checked bit API;
`CircuitAPI.assertBoolean` is idempotent for decomposed byte bits, so this does not
duplicate Boolean constraints. Raw bit callers always receive Boolean checks.

Do not parameterize/refactor both compression functions, introduce lookup arguments,
change compiler optimizations, or substitute Poseidon. Such changes broaden the soundness
surface unnecessarily. Reuse an existing SHA-512 implementation instead of rewriting it.
Checked length hardening does not change constraints for previously supported inputs.
Any discovered relation change must be documented explicitly before implementation.

## Verification and performance

- Default Gradle tests use pinned official digests and JCA differential checks, covering
  empty/abc, high-bit bytes, the 55/56 and 111/112 padding transitions, exact blocks and
  multiple blocks. Exercise both public entry points and the symbolic adapter.
- Mutate compiled R1CS witness values directly: every exposed digest byte/limb, message
  inputs, non-Boolean bits, out-of-range bytes and referenced intermediates. Honest witness
  generation alone is insufficient. Unreferenced eliminated wire slots are not constraints.
- Run independent pinned Circom/ZeroJ R1CS checks in an optional `assurance/sha2-circom`
  harness. Node/Circom remain outside the default build; retain versions, hashes and results.
- Exercise generated BLS12-381 Groth16 proofs, digest/proof tampering and relevant existing
  interoperability checks. All local setup stays explicitly development-only and gated.
- Record constraint/wire counts and measured compile/witness/prove costs where exercised.
  Use deterministic constraint budgets rather than wall-clock CI assertions. Shared-host
  timings and different circuit shapes are not a universal backend speed ranking.
- Run the affected module tests and repository-required build checks, then independently
  review the final diff. Keep external audit, secure ceremony and production claims separate.

## Milestones

1. SHA-256 APIs and tests; SHA-512 source review and bounded hardening.
2. Published-vector, compiled-witness, symbolic and Circom verification.
3. Proof/performance evidence, default build checks, documentation and reviewed PR.

The implementation is additive. Existing SHA-512 digest bytes, public signatures and
ordinary circuit relations must remain compatible. Updated circuit artifacts still require
their exact matching proving/verification keys; no historical benchmark or key is replaced.

Implementation evidence, build results and measured proof costs are recorded in the
[issue #111 validation report](../reviews/sha2-issue-111-validation.md), with separate
[SHA-512 review](../reviews/sha512-issue-111.md) and
[proof review](../reviews/sha2-proof-review-issue-111.md). The optional
[Circom assurance runner](../../assurance/sha2-circom/README.md) documents pinned
independent circuits and compiled-witness checks. These records do not waive the
external-review or production-setup gates.
