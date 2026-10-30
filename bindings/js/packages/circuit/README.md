# @zeroj/circuit

Experimental typed circuit authoring and portable graph compilation using ZeroJ Java in Wasm.
Exports `defineCircuit`, `field`, `uint`, `bool`, `bytes`, `createCircuitCompiler` and typed
compiler/prover lifecycle interfaces. `@zeroj/circuit/graph` exports the advanced arithmetic
`CircuitBuilder`. Importing these wrappers starts no worker and downloads no image.

Select `@zeroj/bundle-circuit` with `createRuntime`. It includes the compiler, selected existing
Poseidon/SHA-256 gadgets and bounded Groth16 prover/verifier in the same Java heap.
One compilation attempt per runtime; use application-trusted graph/fingerprint and key artifacts.
Private input operations require `experimentalSecrets: true`. No witness export or trusted setup.

See `bindings/circuit/README.md`, ADR-0064, and `bindings/js/examples/circuit` in the source
repository for runnable browser/Node examples, artifact export, limits and remaining milestones.
Small circuits and the measured Poseidon opening generate browser/Node proofs. SHA-256 remains
compile/witness-only under the current 4,096-wire/domain budgets. Compiler key loading uses
64 KiB chunks, a 2 MiB total cap and one successful key per circuit. `loadKey(artifact, {signal})`
can abort: cancellation during loading terminates the whole runtime. `keyResources()` reports
transport counters, not total heap. Reuse a loaded key to avoid repeated subgroup validation. Packages are experimental, not audited and not yet published to npm.
