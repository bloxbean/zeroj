# Candidate follow-up: remove unused R1CS wire slots

**Proposed core work, not implemented or adopted in the current compiler.** This plan follows the
read-only `MerkleWireCensus` in PR #116. It needs a separate core security design and independent
review before implementation/promotion. The larger-key experiment changes resource admission only.

The existing compiler inlines many linear expressions while preserving the graph's complete wire
numbering in exported R1CS. The census checks all nonzero A/B/C entries and always preserves wire 0
and public input slots. It found:

| Depth | Current wires | Referenced plus constant/public | Unreferenced | Potential raw query bytes removed |
|---|---:|---:|---:|---:|
| 1 | 1,631 | 247 | 1,384 | 664,320 |
| 2 | 3,054 | 491 | 2,563 | 1,230,240 |
| 8 | 11,592 | 1,955 | 9,637 | 4,625,760 |
| 16 | 22,976 | 3,907 | 19,069 | 9,153,120 |
| 32 | 45,744 | 7,811 | 37,933 | 18,207,840 |

The byte estimate is 480 per removed non-public wire in the current uncompressed BLS12-381 zkey
query sections (A G1 + B G1 + B G2 + C G1). It excludes all headers, coefficients, H query and VK.
It is an estimate for a newly generated compatible key, not a tested compacted key size or proof.
All-zero query entries in the generated depth-8/16/32 keys corroborate the unused-column count.
These entries already avoid nontrivial point/subgroup work, so byte savings do **not** establish
proportional import speedups. Coefficient counts and FFT domains remain separate limits.

## Security invariant and implementation path

Removing a column whose A/B/C coefficients are all zero preserves the constraint equations:
project any old witness onto the retained columns, and every dot product remains identical.
Conversely, any satisfying projected witness extends to the old relation by assigning arbitrary
field values to the removed columns. This simple equivalence is the candidate's mathematical
basis; the implementation still needs to preserve public-input interpretation and witness mapping.
Unused wire slots are not, by themselves, evidence of an under-constrained intended statement.

1. Freeze the input constraint system. Compute a deterministic retained-wire map from every
   nonzero A/B/C term; always preserve constant one and **all ordered public inputs**, even unused.
   Retain remaining active wires in original ID order. Reject invalid IDs/overflows. Zero terms
   require explicit canonical treatment consistent with existing compiler/exporter rules.
2. Remap A/B/C indices without changing coefficients, row order, field, public count or equations.
   Return original count, compact count, forward/reverse maps and a new fingerprint. Treat mapping
   metadata as authenticated compiler output, not a caller-supplied unchecked shortcut.
3. Initially retain the original graph witness calculator and project its complete result through
   the checked map. Do not remove witness instructions merely because their output column is
   absent: later hints/operations may still depend on that value. This first phase need not save
   witness-calculation memory; its target is exported relation/key/query overhead.
4. Introduce an explicit new compiler policy/manifest contract. Keep the current policy opt-in
   behavior unchanged; do not silently compact when accepting an old graph/key fingerprint.
   Old proving keys are incompatible. Require new setup artifacts and authenticated identities.
5. Reuse existing R1CS export, setup/key importer, FFT/MSM and verifier. The operation catalog,
   symbolic semantics and cryptographic parameters do not need a second implementation.

## Required evidence

- Property checks of all A/B/C evaluations before/after projection over generated field witnesses,
  including invalid witnesses. Keep constant/public slots, unused public and private inputs,
  zero coefficients, sparse IDs, public order and all exceptional arithmetic cases explicit.
- Differential checks against the unchanged compiler for arithmetic, ranges/booleans, selectors,
  division/zero tests, bit decomposition, Poseidon/Merkle and SHA/hint-heavy circuits.
- Known-answer vectors and adversarial witness tests for the original gadgets; honest proof success
  alone is not an under-constraint test. Match expected rejected relations after projection.
- Newly generated snarkjs keys and proofs cross-verified by JVM/Wasm/snarkjs and the existing
  on-chain codec/verifier. Tampered maps, keys and fingerprints must fail admission.
- Demonstrate that every published compiler backend/provider either uses an explicit correct
  mapping or retains its old policy. Do not let R1CS changes silently affect PlonK/Halo2 behavior.
- Measure setup/key/import/proof/memory separately. Do not omit point validation or trust arbitrary
  prevalidated query objects to improve benchmark numbers. A compressed download is not a reduced
  in-memory key, and reduced query bytes do not imply fewer active subgroup checks.

Even the projected depth-8 key would remain above the current 2 MiB cap by this estimate, and its
52,037 coefficient entries exceed 16,384. Depth 16 would approach the 4,096-wire bound, while
32 would exceed it; all need a separately justified resource policy. Compaction is useful research,
not an automatic reason to raise default SDK limits or claim production browser proving.
