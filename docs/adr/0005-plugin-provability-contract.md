# ADR-0005: Explicit Plugin Provability Contract

## Status
Accepted

## Date
2026-03-25

## Context

Yaci supports plugins that can execute computation inside nodes. For ZK, some plugins need to be "provable" — their computation can be expressed as a circuit and proven. However:

- Not all computation is circuit-friendly (floating point, unbounded loops, I/O, non-determinism)
- A plugin that works correctly in normal execution may not be provable
- If the system silently fails to prove, it undermines the entire ZK value proposition

## Decision

Any Yaci plugin that claims to be provable must implement an explicit **provability contract** via the `ProvablePluginSpec` interface:

```
ProvablePluginSpec {
    CircuitId circuitId();
    ProofSystemId proofSystem();
    CurveId curve();
    StateModel stateModel();
    InputModel inputModel();
    OutputModel outputModel();
    PublicInputs derivePublicInputs(Input input, Output output);
    Witness deriveWitness(Input input, State state);
}
```

This is separate from the general `ExecutionPlugin` interface. A plugin can be:
- **Non-provable**: Normal execution only (no ZK)
- **Provable**: Implements `ProvablePluginSpec` with full metadata
- **Externally proven**: Execution happens outside, proof submitted externally

The system will validate at registration time that a provable plugin's declared circuit exists in the circuit registry.

## Consequences

**Easier:**
- Clear compile-time contract for provable plugins
- Circuit/VK resolution is explicit, not magical
- Verifier nodes know exactly what to verify for each plugin
- Plugin developers understand what constraints they must satisfy

**Harder:**
- More boilerplate for plugin developers
- Must maintain circuit registry alongside plugin registry
- Circuit updates require coordinated plugin + registry updates

## Risks

- **Risk**: Developers declare provability but the actual computation diverges from the circuit. **Mitigation**: Deterministic execution tests + proof round-trip tests in CI. Document that computation must be canonically reproducible.
- **Risk**: Overly rigid interface discourages plugin development. **Mitigation**: Provide base classes and builder patterns that handle common cases. Most provable computations follow a small set of patterns (state transition, membership check, etc.).
