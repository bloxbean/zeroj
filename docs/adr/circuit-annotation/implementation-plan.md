# Circuit Annotation Implementation Plan

## Status

In progress.

## Execution Rules

- Implement phases in order.
- Keep one git commit per phase.
- Each phase commit includes its phase implementation doc, code, tests, and any
  ADR updates needed to reflect the implemented reality.
- Before each phase commit, run the phase tests, run `git diff --check`, and
  complete three independent reviews:
  - API/design review
  - correctness/security review
  - tests/docs/ergonomics review
- Do not include unrelated dirty or untracked files in phase commits.
- Use path-limited staging and commits for every phase, for example:
  `git add docs/adr/circuit-annotation && git commit -- docs/adr/circuit-annotation`.

## Phase Status

| Phase | Name | Status | Commit |
|-------|------|--------|--------|
| 0 | Planning baseline | Completed | 823c422 |
| 1 | Module scaffolding | Completed | 86f122c |
| 2 | Symbolic foundation | Completed | bfe0b65 |
| 3 | MVP gadget adapters | Completed | 7f49413 |
| 4 | MVP annotation processor | Completed | b033b03 |
| 5 | Schema and input builders | Completed | c7b24b8 |
| 6 | Examples and documentation | Completed | d655fee |
| 7 | Bit and byte symbolic inputs | Completed | 126ef5c |
| 8 | Advanced gadget adapters | Completed | 3b873d2 |
| 9 | Proving flow integration | Completed | Phase 9 commit |

## Defaults

- New annotation modules are included in `zeroj-bom-core` and `zeroj-bom-all`
  during Phase 1.
- `@Secret` and `@Public` are the v1 input visibility names.
- Field style and parameter style both ship in the MVP processor.
- `@CircuitParam` is required before the processor MVP is complete.
- `ZkMiMC`, `ZkPoseidon`, and basic `ZkMerkle` ship in the first usable slice.
- `ZkBits` and `ZkBytes` are deferred until after schema/input builders and
  examples.

## Review Checklist

For each phase:

- API changes match the ADR.
- Generated or public APIs are documented.
- Public/private input ordering is deterministic where touched.
- Circuit constraints are not weakened.
- Tests include at least one negative witness or negative compile scenario when
  behavior can fail.
- Review findings are resolved or documented as non-blocking.

## Post-Phase 9 Cardano Follow-Ups

The Cardano-oriented gadget and curve support matrix is tracked in
[`cardano-gadget-support-matrix.md`](cardano-gadget-support-matrix.md). The
recommended follow-up order is:

| Priority | Work | Status |
|----------|------|--------|
| 1 | Documentation and defaults | Completed |
| 2 | `ZkPoseidonN` symbolic adapter | Completed |
| 3 | Params-aware BLS12-381 `ZkMerkle` helpers | Pending |
| 4 | Generic or generated Cardano Groth16 verifier for arbitrary public-input count | Pending |
| 5 | Example migration to BLS12-381 Poseidon where examples are Cardano-facing | Pending |
| 6 | Optional BLS12-381 MiMC decision | Pending |
