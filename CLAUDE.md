# CLAUDE.md — ZeroJ

@AGENTS.md

## Claude Code

Claude Code may be the primary implementer for ZeroJ.

For R2/R3 changes:

- Use Plan Mode before implementation.
- Read the governing ADR and normative references completely.
- State the threat model and security invariants before editing.
- Do not invent cryptographic behavior when a specification is ambiguous.
- Stop and report conflicts between the ADR, specification, and repository.
- Implement in bounded milestones.
- Add negative/adversarial tests alongside implementation.
- Use authoritative vectors and independent implementations where available.
- Never infer cryptographic security merely from passing tests.

At completion report:

1. risk classification
2. ADR milestone
3. modules/providers affected
4. invariants verified
5. tests/vectors run
6. differential checks
7. remaining assumptions
8. areas requiring human/external review
