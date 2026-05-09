# ADR-0018: Shared BLS12-381 Primitives and Optional WASM Provider

## Status
Accepted

## Date
2026-05-07

## Context

ZeroJ already contains BLS12-381 functionality, but it is not exposed as one
neutral primitive module:

- `zeroj-crypto` contains optimized pure Java Montgomery field arithmetic and
  Jacobian G1/G2 point arithmetic for BLS12-381 provers.
- `zeroj-verifier-groth16` contains pure Java BLS12-381 affine field towers,
  G1/G2 point types, and optimal Ate pairing checks under Groth16 verifier
  packages.
- `zeroj-blst` contains an optional native-backed wrapper for BLS12-381 pairing
  and G1 operations through `foundation.icon:blst-java`.

This split works for Groth16 and PlonK, but it is awkward for BBS. CFRG BBS
needs reusable BLS12-381 primitives beyond a verifier-specific pairing check:
compressed point codecs, subgroup checks, scalar arithmetic, hash-to-curve,
message-to-scalar hashing, generator derivation, and pairing product checks.

ADR-0017 introduced BBS support through Rust WASM, but later review showed that
ZeroJ's existing pure Java BLS12-381 code makes a Java-native CFRG BBS
implementation feasible. At the same time, a small compatibility spike showed
that popular pure Rust BLS12-381 crates such as `zkcrypto/bls12_381` and
`ark-bls12-381` can compile to `wasm32-unknown-unknown` and run under Chicory
1.7.5 with no host imports. Native `blst` remains attractive for speed, but its
Rust crate introduces C/assembly build complexity for `wasm32-unknown-unknown`.

ZeroJ therefore needs a shared BLS12-381 primitive boundary before returning to
the CFRG BBS implementation.

## Decision

### 1. Add `zeroj-bls12381`

Create a neutral pure Java module named:

```
zeroj-bls12381
```

This module is the default BLS12-381 primitive provider for ZeroJ. It should
expose reusable primitives needed by Groth16, PlonK, BBS, KZG, and future
BLS12-381 protocols.

The target API surface includes:

- base field and scalar field helpers for `Fp`, `Fp2`, `Fp6`, `Fp12`, and `Fr`
- G1 and G2 point operations: add, negate, scalar multiplication, identity,
  equality, and subgroup validation
- pairing operations: Miller loop, final exponentiation, and pairing product
  check
- compressed and uncompressed point serialization compatible with the relevant
  standards
- RFC9380 hash-to-curve helpers for BLS12-381 G1/G2
- scalar hashing and canonical byte helpers needed by higher-level protocols

This module must reuse or move existing ZeroJ pure Java implementations. It is
not a second independent pure Java BLS12-381 implementation.

### 2. Prefer a clean pre-release extraction

ZeroJ has not been released yet. The current BLS12-381 classes are only used
inside ZeroJ modules, examples, and use-case documentation, so package-level
source compatibility is not a primary constraint.

Correctness and standards compatibility are more important than preserving the
current Groth16 package locations. If moving implementation code into
`zeroj-bls12381` produces a cleaner and less duplicated design, update the
internal Groth16, PlonK, examples, and use-case imports directly.

The preferred migration path is:

1. introduce `zeroj-bls12381` with neutral APIs
2. move reusable implementation behind those APIs where practical
3. update Groth16/PlonK internals to use the neutral module
4. update `zeroj-examples` and `zeroj-usecases` imports directly
5. add compatibility wrappers only if they materially reduce migration risk

### 3. Add a provider SPI

Define a small BLS12-381 provider boundary so higher-level protocols can choose
between implementations.

The default provider is the pure Java provider from `zeroj-bls12381`.
Alternative providers must be explicit opt-ins. ZeroJ must not silently switch
to native or WASM providers just because an optional module is on the classpath.

Provider implementations must pass the same conformance tests and vector suites
before they are marked supported.

### 4. Add `zeroj-bls12381-wasm` as optional

Create an optional module named:

```
zeroj-bls12381-wasm
```

This module wraps a Rust BLS12-381 implementation compiled to
`wasm32-unknown-unknown` and executed through Chicory. The first candidate is
`zkcrypto/bls12_381` because it is pure Rust and compiled cleanly in the spike.
`ark-bls12-381` remains a backup candidate. Native `blst`-to-WASM is deferred
until its build pipeline can be made reliable.

The WASM provider is not the default. It is an optional provider and benchmark
target.

The WASM ABI should avoid very small cross-boundary calls such as individual
field additions. Prefer coarse operations such as:

- point decode/encode
- hash-to-G1 or hash-to-G2
- G1/G2 scalar multiplication
- G1 multi-scalar multiplication
- pairing product check
- batched generator derivation

For protocols such as BBS, a high-level WASM backend that performs full
`sign`, `verify`, `deriveProof`, and `verifyProof` inside WASM may still be
faster than a low-level primitive provider. This ADR does not require BBS to use
the low-level WASM provider.

### 5. Keep `blst` support explicit

Native `blst` remains valuable for performance. ZeroJ already has a
`zeroj-blst` module for verifier pairing operations, so native provider support
can live there as an explicit `Bls12381Provider` implementation instead of
adding another module immediately. It remains an explicit user opt-in because
native loading has platform and packaging implications.

## Consequences

### Easier

- BBS can target a clean BLS12-381 provider boundary instead of depending on
  Groth16 package internals.
- Groth16, PlonK, KZG, and BBS can share one standards-oriented primitive
  module.
- Pure Java remains the portable default with no native or WASM runtime
  requirement.
- WASM and native providers can be added and benchmarked without changing BBS
  public APIs.

### Harder

- Extracting shared code from verifier/prover modules requires broad internal
  import updates.
- The provider SPI must be small enough to maintain but complete enough for
  CFRG BBS and future protocols.
- Multiple providers increase the conformance test burden.
- WASM performance is not guaranteed to beat optimized JVM code, especially if
  calls are too fine-grained.

### Neutral

- Existing BBS WASM work from ADR-0017 remains valid as an incubating backend.
- Existing `zeroj-blst` can expose native-backed BLS12-381 provider operations
  while remaining an explicit optional dependency.
- On-chain verifier modules are unaffected by this ADR.

## Test Plan

- Unit tests for `zeroj-bls12381`:
  - field arithmetic against existing ZeroJ tests
  - G1/G2 generator, identity, addition, scalar multiplication, and subgroup
    checks
  - pairing product checks, including `e(P, Q) * e(-P, Q) == 1`
  - compressed and uncompressed point encode/decode round trips
  - RFC9380 hash-to-curve vectors for BLS12-381 G1 and G2
- Integration migration tests:
  - existing Groth16 and PlonK BLS12-381 tests continue to pass
  - examples and use-case modules compile against the neutral module
- WASM provider tests:
  - Chicory 1.7.5 loads the WASM artifact
  - the module exports memory and the expected ABI version
  - exported operations have no unexpected host imports
  - outputs match the pure Java provider for shared vectors
- BBS follow-up tests:
  - CFRG BBS draft vectors pass with the pure Java provider first
  - optional WASM/native providers must pass the same vectors before being
    advertised as supported for BBS

## Implementation Plan

1. Create `zeroj-bls12381` and move the existing pure Java BLS12-381
   primitives behind neutral packages where practical.
2. Update current Groth16/PlonK imports to use the new packages directly.
3. Update Groth16/PlonK internals to depend on `zeroj-bls12381`.
4. Add the provider SPI and make pure Java the default provider.
5. Add `zeroj-bls12381-wasm` with a minimal Chicory smoke test and vector
   equality tests against the pure Java provider.
6. Resume CFRG BBS implementation on top of the provider boundary.

## Implementation Status

Implemented on 2026-05-07:

- `zeroj-bls12381` owns the shared pure Java BLS12-381 field, curve, pairing,
  generator, codec, and provider SPI classes.
- Groth16, PlonK, KZG, examples, and on-chain test utilities use the neutral
  BLS12-381 packages instead of Groth16 verifier or `zeroj-crypto` internals.
- `zeroj-bls12381-wasm` provides an explicit Chicory-backed provider using
  Rust `zkcrypto/bls12_381` compiled to `wasm32-unknown-unknown`.
- The WASM ABI currently exposes generator retrieval, G1/G2 scalar
  multiplication, and pairing product checks as coarse operations.
- Shared codecs validate uncompressed points for curve membership and
  prime-order subgroup membership by default, with explicit unchecked decode
  helpers for trusted internal boundaries.
- Shared codecs support compressed and uncompressed G1/G2 encodings with
  round-trip tests, infinity handling, curve-membership checks, and subgroup
  rejection tests.
- The provider SPI covers the BBS-required low-level boundary: G1/G2 identity,
  add, negate, scalar multiplication, subgroup validation, compressed and
  uncompressed codecs, RFC9380 hash-to-curve helpers, encode-to-curve helpers,
  and scalar hashing.
- `zeroj-bls12381` implements RFC9380 hash-to-curve and encode-to-curve for
  BLS12-381 G1/G2 with official vector coverage for the suites required by
  CFRG BBS.
- Provider scalar multiplication reduces signed `BigInteger` inputs modulo the
  BLS12-381 scalar-field order so pure Java and WASM providers have the same
  scalar-domain behavior.
- `zeroj-bls12381-wasm` has explicit ABI conformance tests for no host imports,
  expected exports, wrong-length inputs, invalid point bytes, and repeated
  error handling.
- The WASM Rust crate is built from source with a committed Cargo lockfile and
  a pinned Rust toolchain file; the generated `.wasm` is packaged by Gradle
  rather than checked in.
- `zeroj-blst` exposes `BlstBls12381Provider`, an explicit native-backed
  provider that implements the shared BLS12-381 provider SPI.
- BBS provider conformance tests exercise official draft-10 vectors through the
  pure Java, WASM, and blst BLS providers.
- The BOM and Gradle settings include both new modules.

Future BLS12-381 providers must pass the same provider and BBS conformance
vectors before being advertised as BBS-capable.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| Accidental behavior change during extraction | High | Move code in small slices and keep existing Groth16/PlonK tests passing |
| Provider SPI becomes too low-level and slow for WASM | Medium | Use batched/coarse primitive operations; allow high-level protocol backends |
| WASM provider is slower than pure Java | Medium | Keep pure Java default; benchmark before recommending WASM |
| Hash-to-curve incompatibility | High | Require RFC9380 vectors before using providers for BBS |
| Native/WASM provider auto-selection surprises users | Medium | Require explicit provider selection |
| Refactor delays BBS | Medium | Start with direct internal moves; use adapters only if extraction grows too large |

## References

- ADR-0007: Multi-Module Structure and Boundaries
- ADR-0012: Pure Java Provers for Groth16 and PlonK
- ADR-0017: BBS Selective Disclosure via Rust WASM and Chicory
- Rust `bls12_381` crate: <https://docs.rs/bls12_381/>
- Rust `ark-bls12-381` crate: <https://docs.rs/ark-bls12-381/>
- Rust `blst` crate: <https://docs.rs/blst/>
- Chicory docs: <https://chicory.dev/docs/>
- RFC 9380 hash-to-curve: <https://www.rfc-editor.org/rfc/rfc9380>
