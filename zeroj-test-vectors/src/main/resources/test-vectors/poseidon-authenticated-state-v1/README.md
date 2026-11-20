# `zeroj-poseidon-authenticated-state-v1` Test Vectors

Self-generated deterministic vectors for the `zeroj-poseidon-mpf-v1` and `zeroj-poseidon-jmt-v1` commitment and wire-proof profiles (governed by [ADR-0042](../../../../../../docs/adr/0042-operation-specific-poseidon-mpf-and-jmt-circuits.md) and [`docs/merkle/poseidon-authenticated-state-v1.md`](../../../../../../docs/merkle/poseidon-authenticated-state-v1.md)).

## Provenance & Tool Versions

- **Generator / Verifiers:**
  - `PoseidonMpfV1GoldenVectorTest` (`zeroj-mpf-poseidon`) — independently recomputes raw hashes, leaf commitments, all 16 branch positions, CBOR wire proofs (`ForkStep`, `BranchStep`, `LeafStep`), and normalized 4-sibling witnesses from generic `PoseidonHash` without relying on the structure adapters.
  - `PoseidonJmtV1GoldenVectorTest` and `PoseidonJmtCclVectorTest` (`zeroj-jmt-poseidon`) — independently recomputes raw hashes, empty/leaf/branch commitments, JMT roots, and multi-level object/wire proofs.
- **Poseidon parameter bundle:** `PoseidonParamsBLS12_381T3` (fingerprint `4bf489f3a231cbdba3e9b8c2d21966e052bf9132b9ddf6529aa3f569297a8fc2`, BLS12-381 scalar field modulus `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`).
- **Cardano Client Lib (CCL) version:** `0.8.0-pre8`
  - **JMT (`jmt.cclFixture`):** Originally frozen on `0.8.0-pre5-dev1`; reverified byte-for-byte identical on `0.8.0-pre5` and `0.8.0-pre8`.
  - **MPF (`mpf.fixture`):** Root (`5ac3487f...`), exclusion (`delta`), and `differentLeafFixture` are unchanged across `0.8.0-pre5` and `0.8.0-pre8`. Under `0.8.0-pre8`, CCL emits compact 2-child `ForkStep` wire encodings for `inclusionKey = "beta"` (`inclusionWireBase64`, 44 B). The prior `0.8.0-pre5` `BranchStep` wire (`legacyBranchInclusionWireBase64`, 135 B) is retained alongside it to verify backward acceptance and identical normalized 4-sibling circuit witnesses (`normalizedNeighborsHex`).
- **Java toolchain:** Java 25 (verified on `25.0.2`).

## Inputs

All inputs are literal deterministic constants embedded in `vectors.json`:
- Raw hash edge cases (`empty`, `zero`, `abc`, `non-canonical-32`, `sequence-mod-251` lengths `31..97`).
- MPF leaf suffix pattern `nibble[i] = i mod 16` for lengths `{0, 1, 31, 32, 62, 64}` with value `"value-vector"`, and 16 single-child branches with prefix `[1, 2, 3]` and child `"child-vector"`.
- MPF fixture entries `{"alpha": "one", "beta": "two", "gamma": "three"}` (inclusion `"beta"`, exclusion `"delta"`) and singleton `{"only-key": "only-value"}` (query `"absent-key"`).
- JMT fixture `jmt-key-{0..23}` -> `jmt-value-{0..23}` at version `0`, single-neighbor fixture `{"jmt-single-a", "jmt-single-b"}` at version `9`, and root-leaf fixture `{"only-key": "only-value"}` at version `1`.
