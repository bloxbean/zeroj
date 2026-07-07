# Migration 0020: Module Cleanup and Core Restructure

ADR-0020 removes modules that do not fit the v3 local-first privacy path or that
duplicate functionality now owned by the core Cardano and prover modules.

## Removed Coordinates

| Removed module | Replacement |
|----------------|-------------|
| `com.bloxbean.cardano:zeroj-submission` | Move application-specific submission envelopes, authorization, sequencing, and replay protection into the application layer. Use `zeroj-verifier-core` for proof verification and `zeroj-cardano` / `zeroj-ccl` for Cardano anchoring. |
| `com.bloxbean.cardano:zeroj-ingestion` | Use `zeroj-verifier-core` plus an application-owned policy pipeline. ZeroJ no longer ships a generic proof-submission ingestion stack. |
| `com.bloxbean.cardano:zeroj-prover-sidecar` | Use `zeroj-prover-spi` for prover request/response contracts. Remote prover HTTP transports can be reintroduced outside core when there is a concrete v3 deployment requirement. |
| `com.bloxbean.cardano:zeroj-prover-rapidsnark` | Use `zeroj-prover-gnark` for production native proving or `zeroj-crypto` for pure-Java proving where supported. |
| `com.bloxbean.cardano:zeroj-onchain-experimental` | Use `zeroj-onchain-julc`; budget, feasibility, and reference-script deployment configuration helpers now live there. |

## Prover SPI

Code that previously imported SPI types from
`com.bloxbean.cardano.zeroj.prover.sidecar` should import
`com.bloxbean.cardano.zeroj.prover.spi` instead.

The SPI intentionally stays minimal:

- `ProveRequest`
- `ProveResponse`
- `ProverException`
- `ProverService`

`zeroj-prover-gnark` remains the primary production proving path, but it is not
forced to implement every transport-oriented service method.

## BOM Changes

The broad `zeroj-bom` has been replaced by:

- `zeroj-bom-core`: stable v3 path.
- `zeroj-bom-all`: core plus opt-in native, WASM, BBS, and incubator modules.

If you depend on removed modules, pin the previous ZeroJ version until the
application has migrated to the replacement path above.
