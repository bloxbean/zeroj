# Unreleased breaking changes: SHA-2 and Boolean assertions (PR #112)

The direct Boolean assertion changes the compiled relation of affected DSL circuits
across R1CS, PlonK and Halo2. This includes non-SHA circuits such as MPF/JMT and
confidential notes. The SHA round optimizations also change SHA-256/SHA-512 layouts.

- Recompile affected circuits and rebuild fingerprints, constraint caches and
  circuit-specific proving/verification artifacts. Do not reuse a prior
  circuit-specific Groth16 ceremony output for the newly compiled relation.
- Keep old proofs paired with their original verification keys and original
  application configuration. They do not become invalid statements merely because
  a new library version exists; they do not verify against the replacement key.
- A universal or phase-1 setup is distinct from circuit-specific artifacts. This
  migration does not itself require discarding a compatible universal SRS or
  phase-1 Powers of Tau transcript. Circuit-specific setup still must match the
  new relation and the protocol's ceremony requirements.
- Downstream exhaustive switches/visitors over the public sealed `Gate` interface
  must handle the new `Gate.AssertBoolean` subtype when recompiling.

The fingerprint-bound `Groth16Pipeline` rejects mismatched key/cache relations.
Direct expert APIs still require callers to pair the exact relation with its keys.
Do not bypass binding checks or relabel old key material to make it load. For deployed
applications, plan the verification-key/script and state migration explicitly,
including how historical proofs are handled. The generic verifier does not perform
that application migration.

This repository review cannot establish whether external deployments currently
use circuit-specific ceremony keys, including MPF/JMT deployments on preprod.
Deployment owners must inventory those keys before upgrading. No claim that all
deployments are unused or safe to upgrade has been made.

See [ADR-0063](../adr/0063-sha256-gadget-and-sha2-assurance.md), the compiler
[ADR cross-reference](../adr/0028-dsl-optimization-and-hint-soundness.md#follow-up-direct-boolean-assertions-adr-0063-2026-10-29),
and the [optimization report](../reviews/sha2-optimization-results.md). Proof formats,
full SHA digest semantics and security parameters are unchanged. Maturity labels,
production ceremony requirements and external-audit gates are unchanged.
