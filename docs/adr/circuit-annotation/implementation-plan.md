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
| 6 | Examples and documentation | Completed | Pending hash |
| 7 | Deferred bits and bytes | Pending | Pending |
| 8 | Advanced gadget adapters | Pending | Pending |
| 9 | Proving flow integration | Pending | Pending |

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
