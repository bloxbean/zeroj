# AGENTS.md — ZeroJ

## Mission

ZeroJ is an experimental Java-first zero-knowledge proof toolkit for Cardano.

Priorities, in order:

1. cryptographic correctness and soundness
2. explicit trust/security boundaries
3. safe handling of secrets
4. interoperability with normative specifications/reference implementations
5. deterministic/canonical encodings
6. strong negative and differential testing
7. Java/GraalVM portability
8. performance
9. ergonomics

Never trade 1–6 for performance or convenience without an explicit, reviewed design decision.

## Project Status

ZeroJ is experimental/research software. Some areas are beta/correctness-tested, some experimental/incubator, and material cryptographic paths are not automatically production-safe without external review.

Do not upgrade maturity/security claims based solely on:
- test count
- an AI review
- a benchmark
- successful on-chain execution

## Environment

- Java 25
- maintain GraalVM compatibility where the module promises it
- package namespace should remain under `com.bloxbean.cardano.zeroj`
- Maven group is `com.bloxbean.cardano`

Use the Gradle wrapper.

Do not embed developer-specific absolute paths for tools. Discover optional tools such as `circom` and `snarkjs` from PATH or documented configuration.

## Read Before Significant Work

Inspect:
- `README.md`
- `docs/README.md`
- relevant `docs/adr/*`
- architecture docs
- gadget/support matrices where relevant
- relevant module docs/tests
- `CLAUDE.md` when using Claude Code
- normative external spec/paper/reference implementation for R2/R3 work

Check earlier ADRs before introducing a conflicting architecture.

## Current Major Areas

The repository includes, among other things:

- proof model / codecs / backend SPIs
- circuit DSL and symbolic annotation tooling
- circuit gadget library
- pure-Java Groth16 / PlonK BLS12-381 proving and verification
- BLS12-381 primitives
- optional blst acceleration
- BBS functionality
- Cardano/CCL integration
- JuLC/Plutus V3 on-chain verification
- shared test vectors
- optional native/WASM/incubator paths
- legacy BN254 paths gated for explicit experimental use

Verify current `settings.gradle`, support matrix, and module docs before relying on this summary.

## Security Risk Classification

Classify substantial work:

- **R0**: docs/build/non-security utility
- **R1**: correctness-sensitive but not cryptographic security boundary
- **R2**: security-sensitive validation/codec/circuit/on-chain/protocol integration
- **R3**: primitive, secret operation, side-channel, transcript, proof equation, field/curve core

R2/R3 changes require an ADR or equivalent accepted security design before implementation.

## Non-Negotiable Security Rules

### Do not invent cryptography
For R2/R3 behavior, work from a pinned specification/paper/reference implementation.

If references disagree or are ambiguous, stop and escalate the design question.

### Validate at trust boundaries
Untrusted cryptographic inputs must be validated according to protocol requirements before use.

Depending on type/protocol, this may include:
- canonical encoding
- length/range checks
- field/scalar range
- curve membership
- subgroup membership
- infinity restrictions
- tag/version validation

Do not apply generic validation blindly; follow the relevant specification.

### Canonical serialization
Encoding/decoding is a security boundary.

Avoid multiple accepted encodings when the protocol requires canonical form.

### Secrets and timing
Before touching code that handles secrets, identify:
- which values are secret
- which operations consume them
- whether the existing implementation/provider is approved for secret use

Do not route secret-dependent operations through `BigInteger` or other variable-time code when the ADR/security requirements demand constant-time behavior.

Do not claim Java code is constant-time without evidence appropriate to the implementation and platform.

### Randomness and nonces
Use cryptographically secure randomness and the algorithm specified by the protocol.

Never replace protocol-specified deterministic/random nonce behavior casually.

### Transcript/domain separation
Treat:
- transcript order
- exact bytes
- labels/domain separators
- challenge derivation
- public-input order

as consensus/security-critical behavior when the protocol does.

### Circuits
For circuit/gadget work, verify:
- every intended relation is constrained
- booleans/ranges are constrained
- outputs are constrained
- hints/optimizations cannot bypass constraints
- witness generation agrees with constraints
- public vs secret inputs are correct

A circuit that produces expected outputs for honest witnesses can still be under-constrained.

### Cardano on-chain verification
Cryptographic proof validity is not application authorization.

For real validators, separately reason about:
- `ScriptContext` binding
- replay protection
- nullifiers
- authorization
- state/input/output binding
- business-policy conditions

Do not imply reusable proof verifier code provides these application guarantees automatically.

### Trusted setup
Development/in-repo trusted setup must remain visibly separated from production ceremony requirements.

Do not weaken opt-in/guard rails around insecure development setup.

## Provider / Backend Consistency

When modifying shared crypto or APIs, check all relevant paths:
- pure Java
- blst/native acceleration
- verifier/prover backends
- WASM/native/incubator if in scope

Avoid security semantics that vary silently by provider.

## GraalVM

Where modules promise GraalVM/native-image compatibility:
- avoid hidden dynamic-resource assumptions
- update module-local native-image resources/configuration when needed
- test or document any new native requirements

Do not compromise correctness or security merely to retain native-image compatibility; surface the trade-off.

## Development Workflow

For substantial R2/R3 work:

1. read governing ADR and references
2. state threat model/invariants
3. inspect existing implementation and providers
4. implement one bounded milestone
5. add positive + negative tests
6. run official/reference vectors
7. perform differential/cross-provider checks where possible
8. run relevant property/fuzz tests where useful
9. run affected module tests
10. run E2E/on-chain tests where relevant
11. independently review the diff
12. document remaining audit/security gates

If repository reality conflicts with the ADR, stop that part and propose an ADR amendment.

## Testing

Prefer independent evidence.

Use as applicable:
- known-answer tests
- official/published test vectors
- negative malformed-input vectors
- differential tests against independent libraries
- cross-provider equivalence tests
- algebraic property tests
- fuzz tests
- circuit invalid-witness tests
- proof tampering tests
- serialization round-trip and rejection tests
- end-to-end proof generation/verification
- JuLC/Yaci DevKit on-chain tests

Do not derive all expected values using the code under test.

## Build

Use the Gradle wrapper:

```bash
./gradlew :<module>:test
```

Widen based on impact:

```bash
./gradlew build
```

The repository may contain opt-in native/WASM/integration tasks. Inspect build/CI configuration before assuming a default build exercises every backend.

## ADR Guidance

Create/update an ADR for:
- new proof systems/primitives
- cryptographic algorithm changes
- circuit-soundness architecture
- trusted-setup architecture
- provider/backend architecture
- constant-time/security-path decisions
- new serialization formats
- public-input/transcript changes
- major performance designs touching crypto internals
- on-chain verifier architecture
- security/maturity status changes

R2/R3 ADRs must include:
- risk classification
- threat model
- trust assumptions
- pinned normative references
- exact security invariants
- decision and alternatives
- compatibility
- implementation milestones
- verification/test-vector strategy
- production/audit gates

## Review Checklist

Before completion ask:

- What values are untrusted?
- What values are secret?
- Are encodings canonical?
- Are scalars/points validated correctly?
- Are subgroup/infinity rules correct?
- Can timing/memory access depend on secrets?
- Is randomness/nonce generation correct?
- Is transcript/domain separation exact?
- Can an invalid witness satisfy the circuit?
- Are public inputs ordered/bound correctly?
- Can a valid proof be replayed or used in the wrong context?
- Do all providers implement equivalent semantics?
- Do we have independent test vectors?
- What evidence is still missing for production safety?
