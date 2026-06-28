# ADR-0024: PlonK Release Gates and Multi-Public-Input On-Chain Profile

## Status
Proposed

## Date
2026-06-28

## Context

ADR-0022 and ADR-0023 brought the BLS12-381 PlonK path to an internally
reviewable state:

- pure Java BLS12-381 PlonK prover hardening is in place;
- off-chain BLS12-381 PlonK verifier hardening is in place;
- the current on-chain BLS12-381 PlonK verifier implements the
  `zeroj-plonk-bls12381-cardano-v1-json` compressed-transcript profile for the
  current one-public-input proof shape;
- BN254 remains postponed because Cardano does not currently support BN254
  on-chain;
- third-party cryptographic/security audit remains a release gate.

Two remaining areas must not be lost after the current implementation phase:

1. Broader fuzzing and differential CI gates for the parser/importer/verifier
   boundary.
2. A generic, but still bounded, multi-public-input on-chain PlonK profile.

The second item is likely required for real applications. A one-public-input
profile is useful when an application can safely compress its public statement
into one field element, such as a hash/root/commitment. Many Cardano
applications naturally expose multiple public values: state root, nullifier,
context, policy id, epoch, asset amount, eligibility flag, or recipient binding.
Forcing all of those into one hash is possible, but it moves encoding and
domain-separation complexity out of the verifier and makes application reviews
harder. Supporting multiple public inputs directly gives applications a clearer
and less fragile integration surface.

The multi-public-input profile must not become an unbounded generic verifier.
Public input count directly affects datum size, transcript preimages, scalar
work, public-input polynomial evaluation, adversarial test surface, and budget.

## Decision

### 1. Keep the current one-public-input profile as a versioned profile

`zeroj-plonk-bls12381-cardano-v1-json` remains the strict one-public-input
Cardano profile. It is useful for compact application statements and as a stable
baseline for third-party review.

The multi-public-input work will be introduced as a new versioned profile rather
than changing the semantics of v1.

Working name:

```text
zeroj-plonk-bls12381-cardano-mpi-v1-json
```

The exact name can change before implementation, but it must include:

- proof system: PlonK;
- curve: BLS12-381;
- target: Cardano;
- transcript/profile version;
- public-input profile distinction.

### 2. Implement bounded multi-public-input support, not unbounded generic support

The first multi-public-input profile will support a fixed maximum public input
count. The initial target is:

```text
1 <= publicInputCount <= 8
```

The implementation must make this maximum explicit in code, tests, docs, and
budget gates. If measured budget or script size is too high, the profile may be
reduced to a smaller maximum such as 4. If applications later need more, that
requires another measured profile revision.

The datum must contain exactly `publicInputCount` scalar public inputs. Empty
lists, extra values, negative values, and values outside `Fr` must fail before
curve work.

### 3. Bind public input count and values into the transcript

The multi-public-input transcript must be injective:

- include the profile/version tag;
- include the exact public input count;
- encode each public input as a fixed-width scalar field element;
- preserve public input order;
- reject non-canonical scalar encodings.

The off-chain prover adapter, off-chain verifier, and on-chain verifier must use
the same transcript profile. Existing snarkjs/gnark artifacts are not assumed to
be compatible with the Cardano profile.

### 4. Compute and verify the public-input polynomial on-chain

The on-chain verifier must not trust a caller-supplied public-input polynomial.
It must derive the public-input contribution from the datum values and the
domain parameters.

To avoid expensive on-chain inversion, the redeemer may include per-public-input
inverse witnesses for denominators of the form:

```text
(zeta - omega^i)^-1
```

If inverse witnesses are supplied, the verifier must check each one:

```text
(zeta - omega^i) * inverse_i == 1 mod Fr
```

It must reject zero denominators and malformed inverse scalars. The verifier can
then compute the Lagrange basis values for each public input using the already
available vanishing polynomial value, `nInv`, `omega`, and the verified inverse.

The sign convention must match the off-chain PlonK verifier exactly.

### 5. Extend conversion and verification tooling

The implementation must update:

- `PlonKProverBLS381` Cardano profile generation;
- `PlonKProverToCardano` proof/VK compression and inverse-witness generation;
- `PlonkBLS12381Verifier` off-chain Cardano-profile verifier;
- on-chain `PlonkBLS12381Verifier` datum/redeemer parsing and public-input
  polynomial computation;
- proof-format metadata and docs.

The one-public-input profile must continue to pass unchanged.

### 6. Add budget and script-size gates for each supported count

The multi-public-input profile must measure and gate:

- CPU;
- memory;
- applied script flat bytes;
- redeemer CBOR bytes;
- datum CBOR bytes.

At minimum, tests must measure:

```text
1, 2, 4, and max public inputs
```

The current Cardano budget target remains:

- CPU below the protocol limit with a documented safety margin;
- memory below the protocol limit with a documented safety margin;
- applied script and redeemer sizes below the relevant inline limits, or a
  documented reference-script deployment requirement.

### 7. Add adversarial tests specific to multi-public-input PlonK

The test suite must include:

- valid proofs for 1, 2, 4, and max public inputs;
- wrong public input value;
- swapped public input order;
- missing public input;
- extra public input;
- public input count mismatch between proof metadata, datum, and verifier
  parameters;
- over-field and negative public inputs;
- malformed inverse witnesses;
- denominator-zero rejection;
- tampered proof commitment/evaluation/opening witness under the multi-input
  profile;
- off-chain/on-chain profile mismatch rejection.

### 8. Add fuzzing and differential CI gates before value-bearing release

Fuzzing and differential testing are release gates, not optional cleanup.

Fuzzing targets:

- `SnarkjsPlonkCodec`;
- BLS12-381 `.ptau` importer;
- BLS12-381 `.zkey` importer;
- Cardano-profile proof/redeemer/public-input parsing.

Expected properties:

- no crashes;
- no unbounded memory growth;
- no hangs;
- malformed inputs return stable typed failures;
- parser limits are enforced before expensive work.

Differential gates:

- generate or curate a corpus of circuits with different public-input counts and
  copy-constraint shapes;
- compare ZeroJ off-chain verification against the chosen reference verifier for
  the relevant profile;
- include valid and tampered proofs;
- fail CI if ZeroJ accepts a proof the reference rejects, or rejects a proof the
  profile says is valid.

For the Cardano compressed-transcript profile, the executable reference can be
ZeroJ's off-chain Cardano-profile verifier plus on-chain VM conformance vectors.
For snarkjs or gnark compatibility profiles, the corresponding external verifier
must be the oracle.

## Implementation Plan

### Phase 1: Profile Spec

1. Write the exact profile name and metadata fields.
2. Define public-input datum encoding.
3. Define redeemer additions for inverse witnesses.
4. Define transcript preimage order and fixed-width encodings.
5. Define `MAX_PUBLIC_INPUTS` for the first implementation.

Exit criteria: spec is documented before code changes.

### Phase 2: Off-Chain Converter and Verifier

1. Extend Cardano proof generation to accept `1..MAX_PUBLIC_INPUTS`.
2. Generate inverse witnesses for each public input.
3. Make the off-chain Cardano-profile verifier enforce the same profile.
4. Add 1, 2, 4, and max-input positive and negative tests.

Exit criteria: off-chain prover/verifier and converter produce deterministic
multi-input Cardano-profile artifacts.

### Phase 3: On-Chain Verifier

1. Parse exact public-input datum shape.
2. Parse and range-check inverse witnesses.
3. Compute the public-input polynomial contribution on-chain.
4. Keep all existing proof, VK, domain, coset, transcript, and KZG checks.
5. Add adversarial tests listed above.

Exit criteria: Julc VM accepts valid multi-input proofs and rejects all covered
tampering cases.

### Phase 4: Budget and Packaging

1. Measure CPU, memory, applied script size, datum size, and redeemer size.
2. Update `ScriptBudgetEstimator`.
3. Decide whether the selected max count is acceptable.
4. If not acceptable, reduce the max count or document reference-script
   deployment requirements.

Exit criteria: measured budget gates pass with margin for every supported public
input count.

### Phase 5: Release Assurance Gates

1. Add fuzzing jobs and seed corpora.
2. Add differential/conformance corpus jobs.
3. Pin production ceremony artifacts for release circuits.
4. Submit the BLS12-381 PlonK path for independent cryptographic/security
   audit.

Exit criteria: all gates pass, audit findings are closed or explicitly deferred
with severity-based rationale.

## Consequences

### Easier

- Applications can expose natural public statements directly instead of
  compressing everything into one hash.
- Auditors can reason about public statement binding from the verifier datum.
- The one-input profile remains stable while multi-input support evolves.
- Budget impact is visible by public-input count.

### Harder

- On-chain verifier logic and redeemer shape become more complex.
- More profile metadata and versioning must be maintained.
- Public-input polynomial handling becomes a larger source of soundness risk.
- More tests and budget gates are required before production release.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| Unbounded public input count causes budget or datum-size failure | High | Hard-code and test `MAX_PUBLIC_INPUTS`; measure all supported counts |
| Public-input polynomial sign or indexing differs from off-chain verifier | Critical | Cross-check vectors for every supported count and tamper each input |
| Inverse witnesses are trusted without verification | Critical | Verify every inverse relation on-chain before use |
| Transcript ambiguity enables proof replay across profiles | Critical | Bind version tag, count, order, and fixed-width scalar encodings |
| Multi-input support breaks the existing one-input profile | Medium | Keep v1 tests and profile metadata unchanged |
| Differential oracle is unclear for Cardano-specific transcript | Medium | Use ZeroJ off-chain Cardano verifier plus Julc VM vectors as profile oracle; use snarkjs/gnark only for their native profiles |

## Completion Rule

The current BLS12-381 PlonK implementation phase can be considered internally
complete for the one-public-input profile after its existing tests and Yaci
flows pass.

The broader production roadmap is not complete until this ADR is either:

- implemented for the chosen bounded multi-public-input profile; or
- explicitly deferred with a product decision that value-bearing applications
  will use one public input by hashing/committing their public statement.

Independent third-party audit remains mandatory before value-bearing production
release in either case.

## References

- ADR-0022: Pure Java PlonK Backend Review Outcomes and Hardening Posture
- ADR-0023: On-Chain PlonK Verifier Hardening Posture
- `docs/adr/0022-0023-plonk-production-readiness-addendum.md`
- `zeroj-onchain-julc/src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/plonk/validator/PlonkBLS12381Verifier.java`
- `zeroj-onchain-julc/src/main/java/com/bloxbean/cardano/zeroj/onchain/julc/plonk/codec/PlonKProverToCardano.java`
- `zeroj-verifier-plonk/src/main/java/com/bloxbean/cardano/zeroj/verifier/plonk/PlonkBLS12381Verifier.java`
