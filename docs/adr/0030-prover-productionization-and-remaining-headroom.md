# ADR-0030: Prover Productionization & Remaining Performance Headroom

## Status
Proposed (2026-07-08) — backlog ADR. Captures the items deliberately deferred at the close of
[ADR-0029](0029-blst-accelerated-groth16-prover.md) so they are not forgotten. None are blocking for
beta/testnet use; the **Production requirements** section is mandatory before anything value-bearing.

## Context

ADR-0029 delivered a practical Groth16 prover: the real 19,075,097-constraint CIP-1852 derivation
proof runs on one 128 GB JVM — setup 47 min one-time (PK persisted via `Groth16PkStore`), warm proof
~4.5 min (load ~2 min + prove ~2.3 min, blst multi-core), verified on-chain for ~0.95 ADA. At that
point further work hit diminishing returns; this ADR records what was left on the table and why.

## 1. Production requirements (mandatory before value-bearing / mainnet)

| item | why | notes |
|---|---|---|
| **MPC trusted-setup ceremony** for the ownership circuit | the in-repo setup is single-party — whoever ran it knows tau and can forge proofs; dev/testnet only (flag-gated) | Groth16 needs a per-circuit Phase 2 ceremony. Path: snarkjs-compatible MPC (Hermez/Zcash-PoT phase 1 + circuit-specific phase 2), then import via the existing `.zkey`/ptau import machinery. The 2²⁵ domain is within public ptau (2²⁸). |
| **`ScriptContext`/TxOutRef binding** in `OwnershipProofValidator` | the demo gate verifies proof-vs-datum only; an observed proof could be replayed in a different tx | follow the `Groth16BLS12381TxOutRefBindingVerifier` pattern; requires adding the binding as a circuit public input or validator-side check |
| **External audit of the ADR-0027 gadget suite** | under-constrained-signal review (SHA-512/HMAC/Blake2b/Ed25519/BIP32 over BLS12-381) | differential tests exist (JCA/BouncyCastle/cardano-client) but are not an audit. Hint-based optimizations (ADR-0028) stay disabled until cleared — would also cut the circuit ~19M → ~11–12M. |

## 2. Performance headroom (optional, ordered by measured value)

| item | current cost | expected win |
|---|---|---|
| **Parallelize `Groth16PkStore.load`** | 108 s — single-threaded parse of the 8.4 GB G2 file into `AffineG2[]` (BigInteger per coordinate) | ~5–10× on the load → warm path ~4.5 → ~2.5 min. Now the largest single warm-path cost. |
| **Persist the PK in blst-native layout** (or pre-convert once at load) | every prove re-converts G1 points (Mont limbs → BigInteger → 48-byte BE) inside each MSM call | recovers part of the gap between the 2.5–3.8× raw-MSM speedup and the delivered prove speedup |
| **M10: consolidated benchmark matrix** | numbers are scattered through ADR-0029's log | one table (pure-Java serial/parallel × blst serial/parallel × sizes), pick/confirm defaults; mostly collation |
| **Flat/streamed G2 in setup + PK** | `pointsB2` is a 22 GB object array during setup (the setup peak driver) | flat `long[]`/segment layout like G1 → lower setup peak, faster save/load, enables mmap'd G2 |
| **mmap-backed setup** (write PK to segments as computed) | setup peak ~73 GB on-heap | setup in ~40 GB heap; auto-engage by size like `Groth16PkMmap.shouldEngage` |

## 3. Platform / packaging follow-ups

- **GraalVM native-image validation** of the FFM blst path — M9 config
  (`--enable-native-access`, resource includes) is in place but a real native-image build+run of a
  blst-backed prove has not been exercised.
- **Windows `libblst.dll`** — add the `windows-latest` matrix entry + a Windows branch in
  `zeroj-blst/scripts/build-blst.sh` (MSYS2 link flags).
- **Run the `build-blst` CI matrix and commit the all-platform set** — only the mac/aarch64 binary
  was rebuilt from source (v0.3.15) locally; the other platforms still carry the old testing-only
  binaries flagged in `zeroj-blst/src/main/resources/native/README.md`.
- **Align zeroj-blst with the gnark/halo2 native pattern** (repo consistency): stop committing
  binaries — build libblst in `ci.yml`/`snapshot.yml` like the release already does, delete the
  committed dev binaries, and make blst tests skip gracefully when the lib is absent (local devs
  run `build-blst.sh` once). Releases are already clean either way (`build-blst-native` stage
  rebuilds from source at tag time).

## Non-goals (measured, deliberately dropped)

- **Vector API SIMD (old M3):** the FFT is ~1.5% of a *serial* prove at 2¹⁶ and the NTT is now
  multi-core; the remaining field-mul hot loop needs 52-bit-limb IFMA rework on an incubator API —
  poor fit for a library.
- **GPU proving:** different league, out of scope for a JVM-first library.

## Decision

Track these here rather than in ADR-0029 (closed) or scattered TODOs. Pick items opportunistically;
re-evaluate the performance section only when a consumer actually needs sub-minute proofs.
