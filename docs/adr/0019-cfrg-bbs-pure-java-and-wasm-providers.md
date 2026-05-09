# ADR-0019: CFRG BBS Pure Java and Optional WASM Providers

## Status
Accepted

## Date
2026-05-07

## Context

ADR-0017 planned BBS selective disclosure as a WASM-first feature backed by an
arkworks `bbs_plus` implementation. That direction is no longer the right
default. ADR-0018 has extracted ZeroJ's reusable BLS12-381 primitives into
`zeroj-bls12381`, including point encodings, subgroup checks, pairing product
checks, scalar hashing, and RFC9380 hash-to-curve support. This makes a
standards-oriented pure Java BBS implementation feasible.

The existing `zeroj-bbs/` scaffold is also not the target shape. It uses a
ZeroJ-specific BBS+ suite and CBOR ABI, not the CFRG BBS interface and octet
serialization from `draft-irtf-cfrg-bbs-signatures-10`. We should replace that
incubating code instead of evolving it.

The target standard is pinned to:

```
draft-irtf-cfrg-bbs-signatures-10
```

That draft defines the high-level interface operations `KeyGen`, `SkToPk`,
`Sign`, `Verify`, `ProofGen`, and `ProofVerify`, plus the core operations and
utility operations needed to make those interfaces vector-compatible. It also
defines BLS12-381 SHAKE-256 and SHA-256 ciphersuites and includes test vectors.

## Decision

### 1. Replace the current BBS scaffold

Remove the existing experimental `zeroj-bbs/` directory and its nested
`wasm/` and `rust/` layout during implementation. Create new BBS modules with
the same shape as the BLS modules:

```
zeroj-bbs/
  build.gradle
  src/main/java/com/bloxbean/cardano/zeroj/bbs/...
  src/test/resources/cfrg-bbs/draft10/...

zeroj-bbs-wasm/
  build.gradle
  rust/
  src/main/java/com/bloxbean/cardano/zeroj/bbs/wasm/...
```

`zeroj-bbs` is the default portable implementation. `zeroj-bbs-wasm` is an
optional provider and benchmark target.

### 2. Make pure Java the default BBS provider

`zeroj-bbs` depends on `zeroj-bls12381` and implements CFRG BBS directly in
Java. It must not depend on the WASM module.

The public Java API should be standards-oriented and provider-backed:

- `BbsCiphersuite`
- `BbsSecretKey`
- `BbsPublicKey`
- `BbsKeyPair`
- `BbsSignature`
- `BbsProof`
- `BbsPresentation`
- `BbsProvider`
- `BbsProviders`
- `BbsService`

`BbsProviders.pureJava()` is the default. Alternate providers are explicit
opt-ins. ZeroJ must not silently switch to WASM because `zeroj-bbs-wasm` is on
the classpath.

### 3. Implement the CFRG draft-10 interface, not the older BBS+ API

The implementation target is the draft-10 interface algorithms:

- `KeyGen`
- `SkToPk`
- `Sign`
- `Verify`
- `ProofGen`
- `ProofVerify`

The implementation must also expose or test the draft utility operations needed
for vector compatibility:

- secret-key derivation from key material and key info
- public-key derivation
- message-to-scalar mapping
- generator derivation
- domain calculation
- challenge calculation
- random scalar derivation for test vectors
- scalar, point, signature, proof, and public-key octet serialization

Core cryptographic bytes must follow the CFRG draft octet formats. ZeroJ may
define a small CBOR envelope for `ZkProofEnvelope` integration, but that
envelope must wrap draft-compatible BBS proof bytes rather than replacing the
draft serialization.

### 4. Ciphersuite support

Implement the BLS12-381 SHA-256 ciphersuite first:

```
BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_
```

This is the lowest-risk first target because `zeroj-bls12381` already has the
required RFC9380 XMD SHA-256 hash-to-G1 support and test vectors.

Support the SHAKE-256 ciphersuite as a second milestone:

```
BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_
```

ZeroJ must not advertise full draft-10 ciphersuite coverage until both
ciphersuites pass the corresponding draft vectors. If SHAKE-256 requires new
XOF support in `zeroj-bls12381`, add that as a prerequisite before enabling
the suite.

### 5. Constant-time secret-scalar boundary

BBS uses secret keys, proof randomness, and hidden-message blinding scalars.
The implementation must not route those through provider methods documented
only for public scalar multiplication.

Before production use, `zeroj-bbs` must either:

- add constant-time secret-scalar operations to `zeroj-bls12381` and use them
  for BBS secret-dependent scalar multiplication, or
- keep the BBS module clearly marked experimental until a side-channel review
  is complete.

Correct vector compatibility is required first, but a constant-time contract is
required before advertising the pure Java implementation as production-ready
for secret-bearing BBS workflows.

Implementation note: the follow-up implementation added explicit
`g1SecretScalarMul` and `g2SecretScalarMul` provider methods, wired BBS
`SkToPk`, signing, proof blinding, proof randomness, and hidden-message
commitments through those methods, and replaced BBS secret scalar inversions
with Montgomery-form scalar-field inversion. The JVM implementation uses a
fixed-schedule Jacobian multiplication path; high-value deployments should
still perform an environment-specific side-channel review.

### 6. Add explicit optional non-default providers

`zeroj-bbs-wasm` implements the same `BbsProvider` SPI as an explicit opt-in.
The first implementation reuses the vector-compatible Java BBS core and swaps
the BLS12-381 primitive provider to `zeroj-bls12381-wasm`, which is Rust
compiled to `wasm32-unknown-unknown` and executed through Chicory 1.7.5.

This keeps one audited BBS algorithm path while still allowing WASM-backed
pairing and scalar multiplication. A future optimization may add a coarse Rust
BBS ABI if vector compatibility and performance justify the extra implementation
surface.

Native `blst` is exposed as a BLS12-381 provider from `zeroj-blst`. BBS can use
it through explicit BLS provider selection without adding a separate
`zeroj-bbs-blst` module:

```java
BbsProviders.withBlsProvider(ciphersuite, BlstBls12381Provider.createDefault())
```

The main `zeroj-bbs` module must continue to depend only on the shared
`zeroj-bls12381` API; WASM and blst remain test or user-selected optional
dependencies.

If a coarse Rust BBS ABI is added later, it should use operations like:

- `zeroj_bbs_keygen`
- `zeroj_bbs_sk_to_pk`
- `zeroj_bbs_sign`
- `zeroj_bbs_verify`
- `zeroj_bbs_proof_gen`
- `zeroj_bbs_proof_verify`

The Rust candidate may be `zkryptium` if it compiles cleanly to
`wasm32-unknown-unknown`, has no unexpected host imports, and passes the pinned
draft-10 vectors. If it does not meet those gates, implement the Rust provider
against a lower-level BLS12-381 crate instead. Do not patch the older
`bbs_plus` crate into a draft-10 shape.

The WASM ABI should mirror the hardened `zeroj-bls12381-wasm` pattern:

- committed `Cargo.lock`
- pinned `rust-toolchain.toml`
- generated `.wasm` built by Gradle, not checked in
- exported memory plus explicit `alloc` and `dealloc`
- no unexpected host imports
- typed Java exceptions for malformed responses
- tests for alloc/dealloc balance on error paths

### 7. ZeroJ verifier integration

`zeroj-bbs` should provide a BBS verifier for ZeroJ's verifier APIs:

- proof system: `ProofSystemId.BBS`
- curve: `CurveId.BLS12_381`
- proof format: `bbs-cfrg-draft10-presentation-cbor-v1`

The verifier checks only cryptographic correctness. Issuer trust, schema
semantics, expiration, revocation, holder binding, and disclosure policy remain
application policy concerns, consistent with ADR-0006.

Provider selection remains explicit. ServiceLoader may discover the
`ZkVerifier`, but it must not silently switch the underlying BBS provider from
pure Java to WASM.

## Consequences

### Easier

- BBS follows the same architecture as BLS: portable pure Java default plus an
  optional WASM backend.
- CFRG vector compatibility becomes the primary correctness gate.
- `zeroj-bbs` can be used without Rust, WASM, native code, or Chicory.
- WASM can be benchmarked and improved independently.

### Harder

- The pure Java implementation must implement the full draft algorithm instead
  of wrapping an existing BBS+ library.
- Constant-time secret-scalar handling must be addressed explicitly.
- Supporting both SHA-256 and SHAKE-256 ciphersuites adds hash/XOF work.
- Multiple BLS providers increase the conformance-test burden.

### Neutral

- No Cardano on-chain verifier is implied.
- W3C Data Integrity `bbs-2023` packaging can be layered later on top of the
  CFRG-compatible BBS core.
- Blind BBS signatures and per-verifier linkability are out of scope for this
  ADR.

## Test Plan

### Pure Java tests

- Import draft-10 vectors for:
  - key generation
  - public key derivation
  - message-to-scalar mapping
  - generator derivation
  - signature generation
  - signature verification
  - proof generation
  - proof verification
  - hash-to-scalar cases
  - Appendix D.1 SHAKE-256 signature and proof fixtures from the official draft
    JSON set
  - Appendix D.2 SHA-256 signature and proof fixtures from the official draft
    JSON set
- Add negative tests for:
  - tampered signature
  - tampered proof
  - wrong public key
  - wrong header
  - wrong presentation header
  - wrong revealed message
  - duplicate, unsorted, and out-of-range revealed indexes
  - invalid scalar, G1, and G2 encodings
  - subgroup rejection on public keys and proof points
- Add deterministic mocked-random scalar tests for draft proof vectors.
- Add randomized round-trip tests for sign, verify, proof generation, and proof
  verification after the draft vectors pass.

### Provider conformance tests

- Define one shared conformance suite in `zeroj-bbs`.
- Run the same suite against BBS with selected BLS providers:
  - pure Java BLS from `zeroj-bls12381`
  - WASM BLS from `zeroj-bls12381-wasm`
  - native blst BLS from `zeroj-blst`
- A provider cannot be advertised as BBS-capable until it passes the shared
  draft vectors.

### WASM tests

- Chicory loads the generated WASM artifact.
- The WASM module exports the expected ABI version and operations.
- The module has no unexpected host imports.
- All CFRG vectors match the pure Java provider.
- Malformed requests and malformed responses map to typed Java exceptions.
- Repeated WASM errors do not leak response buffers.
- The Rust crate does not call host randomness for deterministic operations;
  Java supplies randomness or mocked random scalar material.

### Integration tests

- `BbsService` signs, verifies, derives a presentation, and verifies the
  presentation using the pure Java provider.
- `ZkProofEnvelope` can carry a BBS presentation.
- `VerifierOrchestrator` verifies a BBS presentation envelope.
- Wrong proof system, curve, proof format, verification material, and public
  inputs reject cleanly.

## Implementation Plan

1. Supersede ADR-0017 and delete the old experimental `zeroj-bbs/` scaffold.
2. Create `zeroj-bbs` with the public API, `BbsProvider` SPI, and pure Java
   provider shell.
3. Add CFRG draft-10 vector resources and a vector loader.
4. Implement draft serialization utilities, scalar utilities, and ciphersuite
   metadata.
5. Implement `KeyGen`, `SkToPk`, message-to-scalar mapping, and generator
   derivation; pass draft vectors.
6. Implement `Sign` and `Verify`; pass signature vectors and negative tests.
7. Implement `ProofGen` and `ProofVerify`; pass proof vectors and negative
   tests.
8. Add `BbsService`, presentation wrappers, and ZeroJ verifier integration.
9. Create `zeroj-bbs-wasm` with a Rust candidate gated by draft vectors, no
   host imports, and hardened memory cleanup tests.
10. Run the shared conformance suite against pure Java, WASM, and blst BLS
    providers.
11. Add documentation and examples for selective disclosure workflows.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| Draft-10 changes before RFC publication | Medium | Pin proof format and vectors to draft-10; add a new suite for later drafts |
| Pure Java side-channel leakage | Medium | Secret-scalar provider boundary is in place; require environment-specific side-channel review for high-value deployments |
| Incorrect generator/domain/challenge serialization | High | Gate each utility on draft vectors before implementing higher layers |
| Non-default providers drift from pure Java | Medium | Shared provider conformance suite and exact same CFRG vectors |
| Rust crate claims draft-10 but differs in details | Medium | Treat Rust crates as candidates only; vectors decide support |
| Users confuse CFRG core with W3C Data Integrity packaging | Medium | Keep proof format names explicit and document policy/package boundaries |

## References

- ADR-0006: Separation of Crypto and Policy Verification
- ADR-0018: Shared BLS12-381 Primitives and Optional WASM Provider
- BBS draft-10: <https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-10.txt>
- BBS draft datatracker entry: <https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/>
- RFC 9380 hash-to-curve: <https://www.rfc-editor.org/rfc/rfc9380>
- ZKryptium Rust crate candidate: <https://docs.rs/zkryptium>
