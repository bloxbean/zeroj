# ADR-0004: Off-Chain Cardano Anchoring First

## Status
Accepted

## Date
2026-03-25

## Context

Cardano L1 has two potential integration points for ZK:

1. **Off-chain anchoring**: Store proof hashes, state roots, VK hashes, and commitments in transaction metadata or datum. Verification happens off-chain (in Yaci nodes). Cardano L1 provides data availability and settlement finality.

2. **On-chain verification**: Execute pairing/verification logic in Plutus scripts. Cardano added BLS12-381 built-in functions via CIP-0381 (Plutus V3), making this theoretically possible. However, script execution budgets are extremely tight for pairing-heavy operations, and tooling is immature.

## Decision

ZeroJ starts with **off-chain anchoring only**.

Anchoring patterns (in priority order):
1. `proof_hash` — SHA-256 of the proof bytes, stored in tx metadata
2. `state_root + proof_hash` — links state evolution to proof
3. `state_root + circuit_id + vk_hash` — full verification material reference
4. `nullifier_commitment` — for privacy-preserving claims
5. `proof_uri` — optional pointer to off-chain proof storage (IPFS, S3, etc.)

These are stored via:
- Transaction metadata (label TBD, CBOR encoded)
- Datum on UTxOs (for script-guarded state)
- Both via CCL transaction builder helpers

On-chain Plutus verification is an experimental track (Milestone 9), isolated in its own module.

## Consequences

**Easier:**
- Works today with existing Cardano infrastructure
- No Plutus script budget constraints to worry about
- Works with any proof system (not limited to BLS12-381 curves)
- CCL integration is straightforward — just metadata/datum helpers
- Cardano acts as a reliable settlement/DA layer

**Harder:**
- Trust model depends on Yaci node verification, not Cardano L1 consensus
- Anyone can anchor arbitrary data — validity is only meaningful in context of the Yaci network
- On-chain composability with DeFi protocols requires on-chain verification (later)

## Risks

- **Risk**: Users confuse anchoring with on-chain verification — "my proof is on Cardano" doesn't mean "Cardano verified my proof". **Mitigation**: Very clear documentation and naming. Anchoring helpers are in `zeroj-cardano`, not in a "verification" module.
- **Risk**: Metadata format changes or conflicts with other standards. **Mitigation**: Use a dedicated metadata label, follow CIP-10 registry process, version the format.
