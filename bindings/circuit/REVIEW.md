# First compiler milestone — implementation review

**Historical M1 review; M2 follow-up appears below.**

2026-10-30. This is an implementation self-review. Independent review remains a draft-PR gate;
no audit, production, constant-time or post-quantum claim is made.

## Boundaries checked

- Graph and recipe tags, explicit compiler policy, fixed canonical order, canonical scalars,
  field profiles, input ordering, bounded parsing and references. Existing Java operations
  determine constraints; raw/custom/multi-output hints are excluded.
- Five recipe expansions match separately authored Java annotation graphs/fingerprints/full
  witnesses. The operation exercise covers every exposed primitive. Standard hash host oracles
  and snarkjs provide additional checks; shared-Java parity alone is not cryptographic assurance.
- The compiler accepts expected graph/fingerprint identities before retaining an object that
  can receive private input. These values must be selected by the trusted application; a digest
  accompanying attacker-selected content does not authenticate its meaning.
- Private operations preserve entropy/experimental-secret opt-in. No consumer witness digest
  or witness vector export remains. Diagnostics contain public metadata and timings only.
- Compiled handles own their proving-key handles. Closing a circuit releases Java key objects;
  keys cannot prove through another typed circuit/runtime. Runtime disposal remains the way to
  interrupt an active computation; compiled.dispose() releases resources through the queue.
- The common session release helper preserves prior behavior and allows composite resources
  to release their children. No prover equations, curve/field code or key parser was modified.
- Build-time recipe export uses existing R1CS export and no setup/witness code. Reachability
  guards exclude it, fixture generation, setup and native blst from the consumer image.

## Findings resolved during implementation

1. Research recipe decoding accepted alternate object-key ordering. The promoted canonical
   recipe rebuilds root/input records and compares exact text; negative tests cover alternatives.
2. Research witness digests were useful fixture diagnostics but unsuitable for a consumer API.
   They are now confined to test source sets; checkWitness returns only validity and timings.
3. Circuit disposal initially needed owned-key cleanup. The Java state tracks its retained keys
   and closes them via BindingSession.release; the TS lifecycle rejects foreign/closed handles.
4. TS-only authors need public artifact identities before browser private work. A build-time
   recipe exporter now emits graph/R1CS/manifest without requiring a Java companion circuit.
5. Repeat packaging failed because GraalVM legal files copy as read-only. Packaging recreates
   only its generated legal-notice subtree, preserving the original notices unchanged.
6. The first Node oracle test used a different snarkjs module path from worker cleanup and left
   oracle workers alive. It now uses the existing CommonJS dependency consistently and terminates
   the matching curve workers; the test process exits normally.
7. Gradle parity tests declare exported TS recipes as inputs and diagnostic vectors as outputs.
   Changing only the TS frontend therefore invalidates cached Java parity checks.

## Remaining gates

The initial promotion is deliberately bounded. Arrays/bits and schema convenience, generated
operation catalogs, full ESLint integration, richer source diagnostics, larger-key transfer and
hard resource accounting remain tracked in PLAN.md. The present estimates and caps are not a
proof of hostile-input heap containment. No test here validates a larger browser proving workload.

The importer still requires application-trusted keys/VKs and self-verifies generated proofs.
Its inherited production key/ceremony consistency gaps are not resolved by this frontend.
A mismatched but structurally valid VK can be detected at proof self-verification; no rejected
proof is returned. Official gadget assurance, independent review, mobile/Safari validation and
release/distribution review remain necessary. Real Cardano application authorization/replay/state
checks and Yaci measurements belong to a later milestone.


## M2 bounded key loading — follow-up self-review

- Separate compiler-only 2 MiB policy; original standalone key and global JSON/string caps
  remain in place. Wire/domain/coefficient budgets and point/subgroup checks are unchanged.
- Small metadata/identity/VK shape are validated before an exact-sized staging reservation.
  No concatenated full-key hex string or second assembled binary array in Java. One upload
  and one lifetime successful key per compiled worker bound retained key growth.
- Upload handles belong to a compiled state. Bad owned chunks/finish release the reservation;
  malformed outer requests cannot dispatch cleanup, but cannot exceed the one-upload bound.
  Aborting/releasing the upload or closing the circuit releases its buffer. Successful finish
  retains no upload buffer; the existing parser owns only its normal parsed objects.
- Failed imports cannot consume the one-key slot. Digest, canonical coordinate, forbidden
  infinity, G1 non-subgroup (order-three point), dimension and relation negatives use real
  snarkjs keys, with recomputed hashes where parser validation must be reached.
- AbortSignal during loading terminates all runtime workers/handles; queued release alone
  cannot interrupt synchronous Java import. Node and both browser tests exercise actual
  cancellation. Deadline failure also invalidates handles. Pre-abort leaves the runtime usable.
- Review caught missing import timing/byte accounting in the legacy direct-request path.
  Both import paths now use the same state update and the compatibility test covers it.
- Imported-key reuse avoids repeating validation; no trusted-point cache or skipped check
  was introduced. Public counters measure transport only; sampled RSS and JVM allocation
  observations are labeled separately in M2-KEY-LOADING.md.
- No equations, core compiler, randomness provider, key parser or curve arithmetic changed.
  This self-review does not satisfy the independent reviewer/audit gate for draft PR #116.

M2 does not prove hostile-input heap containment, stable p95 on real devices, Safari support,
large SHA/Merkle feasibility, full ceremony/key-consistency assurance, or production security.
