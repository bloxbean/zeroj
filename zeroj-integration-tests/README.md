# zeroj-integration-tests

Cross-module integration and end-to-end regression tests for ZeroJ. **Never published.**

Per [ADR-0044](../docs/adr/0044-focused-module-surface-and-optional-provider-isolation.md),
this project holds the security-relevant regressions that used to live in
`zeroj-examples`. They live here rather than in a product module because each
one spans several modules — circuit DSL, circuit library, annotation processor,
pure-Java prover, verifier, codec, MPF, and the Julc on-chain verifiers — so no
single module owns the invariant.

The example circuits and proof helpers under
`src/test/java/com/bloxbean/cardano/zeroj/examples/` are **test fixtures**, not
product code. They kept their original package names so the move stays reviewable
as a move.

Tutorials and runnable applications are **not** here. They live in
[zeroj-usecases](https://github.com/bloxbean/zeroj-usecases).

## Running

```bash
# Offline regressions — no external tooling required
./gradlew :zeroj-integration-tests:test

# End-to-end tests — require external infrastructure, and skip gracefully without it
./gradlew :zeroj-integration-tests:e2eTest
```

`e2eTest` needs:

- **snarkjs** on `PATH` for the independent-prover interoperability tests
  (`npm install -g snarkjs`);
- **Yaci DevKit** running locally for the on-chain tests (Blockfrost-compatible
  API on port 8080, admin API on port 10000).

Tests whose prerequisites are missing are skipped through JUnit assumptions, not
silently passed. Check the skip list in the report when you need evidence that a
given oracle actually ran.

## What each test protects

| Test | Invariant |
|---|---|
| `ComparatorRelationPinningTest` | ADR-0037 comparator soundness: an oversized operand must be **rejected**, not wrap into a small residue that clears a threshold. Pins both shipped comparison circuits. |
| `SealedBidCircuitTest` | Circuit relation and curve policy: bids below reserve and wrong commitments fail witness calculation; BN254 compilation is refused for BLS12-381 Poseidon parameters. |
| `AnnotatedCircuitExamplesTest` | Annotation-processor companions: generated schemas, public/secret input split, public-input **ordering**, circuit metadata, and envelope binding that rejects mismatched public signals and a wrong curve. |
| `SealedBidPureJavaE2ETest`, `BalanceThresholdPureJavaE2ETest`, `AnonymousVotingPureJavaE2ETest`, `ParameterizedCircuitE2ETest` | Pure-Java Groth16 full stack: circuit → R1CS → dev setup → prove → off-chain pairing verification → Julc VM on-chain verification. |
| `SealedBidE2ETest`, `BalanceThresholdE2ETest`, `AnonymousVotingE2ETest`, `SnarkjsProverTest` | **Independent-prover interoperability.** ZeroJ compiles the R1CS and witness; snarkjs — an implementation ZeroJ does not control — produces the proof; ZeroJ's pure-Java BLS12-381 verifier accepts it. Expected values do not come from the implementation under test. Also covers Groth16 and PlonK. |
| `SealedBidOnChainE2ETest`, `PureJavaProverYaciE2ETest` | Cardano on-chain Groth16 verification on Yaci DevKit, from committed proof artifacts and from a freshly proved circuit. |

Cryptographic proof validity is not application authorization. These tests cover
proof and circuit correctness only; `ScriptContext` binding, replay protection,
nullifier registries, and business policy remain the application's responsibility.
