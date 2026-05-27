# Phase 0: Planning Baseline

## Status

Approved.

## Goal

Establish the accepted circuit-annotation ADR and the execution tracker used by
all subsequent phases.

## Implemented Changes

- Marked the circuit-annotation ADR as accepted for implementation.
- Added this phase record.
- Added `implementation-plan.md` with phase order, review gate, commit policy,
  defaults, and review checklist.
- Closed Phase 0 design decisions in the main ADR:
  - `@Public` / `@Secret` are the v1 visibility annotations.
  - field style and parameter style both ship in the MVP.
  - `@CircuitParam` is required for parameterized circuit templates.
  - `ZkMiMC`, `ZkPoseidon`, and basic `ZkMerkle` ship in the first usable
    slice.
  - generated Phase 4 API is `build(...)` plus constants; Phase 5 adds schema
    and input builders.
  - field-style ordering is deterministic, with non-negative unique `@Order`
    values sorted before unordered fields in stable `javac` source order.
  - annotation modules are included in both BOMs starting in Phase 1.
  - generated/flattened input names must be unique within a circuit.

## Public API Changes

None. This phase is documentation only.

## Test Commands

```text
rg -n "[[:blank:]]$" docs/adr/circuit-annotation
git add docs/adr/circuit-annotation
git diff --cached --check -- docs/adr/circuit-annotation
```

## Review Results

Initial three-agent review found blocking planning ambiguities:

- field-style public/secret ordering needed a deterministic v1 rule
- generated `schema()` / `inputs()` methods were described before their Phase 5
  implementation boundary
- input naming had two unresolved mechanisms
- Phase 0 decisions were still listed as open questions
- BOM inclusion timing differed between the tracker and ADR
- the phase commit must be path-limited because unrelated dirty/untracked files
  exist in the worktree

All ADR/process ambiguities above have been resolved. Re-review pending.

Second re-review found two remaining blockers:

- `@Order` behavior for mixed, duplicate, negative, and scoped values was not
  fully specified.
- `git diff --check` did not validate untracked docs before staging.

Both have been resolved by pinning the `@Order` policy and documenting a
staged diff check for new files.

Final three-agent re-review approved Phase 0:

- API/design review approved the final `@Order`, naming, phase-boundary, and
  BOM decisions.
- Execution-process review approved staged/cached diff checks and path-limited
  commit guidance.
- Docs/ergonomics review approved the decision-complete guidance for future
  implementers.

## Commit

Pending at time of this record; commit will include only
`docs/adr/circuit-annotation`.
