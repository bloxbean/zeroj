# ADR-0031: Groth16 MPC Trusted-Setup Ceremony — snarkjs Path + ZeroJ-Native Contributor

## Status
Proposed (2026-07-08) — planned on `feat/adr_0031_mpc_ceremony`.

## Context

Groth16 requires a **per-circuit trusted setup**: whoever knows the setup randomness ("toxic
waste") can forge proofs. ZeroJ's in-repo setup ([ADR-0029](0029-blst-accelerated-groth16-prover.md))
is **single-party and dev-only** (flag-gated): fine for testnet, unacceptable for anything
value-bearing. [ADR-0030](0030-prover-productionization-and-remaining-headroom.md) lists an MPC
ceremony as a hard production requirement.

An MPC ceremony fixes this: N independent contributors each mix in fresh randomness; the setup is
sound **if at least one contributor was honest and destroyed their randomness**. The reference
target is the account-ownership circuit (19,075,097 constraints, domain 2²⁵, BLS12-381), but the
machinery must work for any ZeroJ Groth16 circuit.

Two facts shape the design:
- ZeroJ can already **consume** snarkjs Groth16 keys: `ZkeyImporterBLS381.importZkey(...)` returns a
  native `Groth16ProvingKeyBLS381` from a `.zkey` stream (SHA-256-pinned overloads included).
- ZeroJ **cannot yet export** its R1CS to the iden3 `.r1cs` binary format that snarkjs phase-2
  tooling requires — the one missing bridge.

## Options considered

| option | how | pros | cons |
|---|---|---|---|
| **A. snarkjs ceremony** | export `.r1cs` → `snarkjs groth16 setup` → N × `zkey contribute` → `zkey beacon` → `zkey verify` → import final `.zkey` | ecosystem-standard, battle-tested, **independently auditable transcript**; ZeroJ import side already exists | Node.js at 2²⁵ is slow — likely hours + tens of GB per contribution; contributor UX heavy |
| **B. ZeroJ-native contributor, snarkjs-compatible** | implement the phase-2 contribution step in ZeroJ, reading/writing the **snarkjs `.zkey` format**, so transcripts still verify with `snarkjs zkey verify` | fast contributions (parallel + blst EC stack, single Java binary for contributors); **verification stays independent** (snarkjs) | new crypto code (BGM17 contribution + proof-of-knowledge + transcript hashing) must match the snarkjs format bit-exactly |
| C. gnark MPC (Go) | Consensys `mpcsetup` | fast | different key format + constraint-system conversion; not snarkjs-interoperable; two new bridges |
| D. PlonK (universal setup) | switch proof system; only a universal phase 1 ever | no per-circuit ceremony at all; circuit changes don't burn a ceremony | larger circuits, PlonK prover lacks the ADR-0029 treatment, on-chain PlonK still experimental |

## Decision

**Implement A and B on a shared foundation** — users choose per preference:

- **Option A (snarkjs)** for teams that want the maximally standard, widely reviewed toolchain and
  accept slower contributions.
- **Option B (ZeroJ-native contributor)** for fast/low-friction contributions — while keeping the
  `.zkey` format and therefore **snarkjs `zkey verify` as the independent verifier of the whole
  transcript**. The tool that *checks* the ceremony is never the tool we wrote.

C is rejected (two non-standard bridges). D is deferred (tracked as a long-term option in ADR-0030;
revisit if per-circuit ceremonies become a recurring cost).

Both paths converge on: **final `.zkey` → `ZkeyImporterBLS381` → `Groth16PkStore.save` (one-time) →
prove exactly as today**; the VK is extracted from the same import for the on-chain validator.

## Shared foundation (needed by both paths)

1. **`R1csExporter`** (new, `zeroj-crypto` or a small tool module): ZeroJ `R1CSConstraintSystem` →
   iden3 `.r1cs` binfile (header: BLS12-381 prime, nWires/nPubOut/nPubIn/nLabels/mConstraints;
   constraint sections as sparse `wire → coeff` maps — same encoding family the `.zkey` importer
   already parses). Must preserve ZeroJ's wire ordering (1 = ONE wire, publics first) so the
   imported key's IC matches the datum/public-input order.
2. **`.zkey` import validation at scale**: `ZkeyImporterBLS381` has only seen small keys; validate
   streaming/memory behavior at a 19M-constraint key (~23 GB) and wire it to `Groth16PkStore` so an
   imported ceremony key is persisted once and mmap-loaded thereafter.
3. **Phase-1 (universal powers) source** — decision spike:
   - run our **own snarkjs `powersoftau`** ceremony to 2²⁵ (heavy but self-contained; phase 1 also
     needs only one honest participant), vs.
   - **reuse Filecoin's BLS12-381 PoT (2²⁷)** with a vetted format conversion to `.ptau`.
   Measure both; pick in M3.
4. **Round-trip conformance test** (small circuit): ZeroJ R1CS → `.r1cs` → snarkjs setup+contribute
   → `.zkey` → import → prove with ZeroJ → verify (off-chain and on a Julc validator). This is the
   correctness gate for the exporter's wire mapping.

## Option B design sketch (ZeroJ-native contributor)

Phase-2 contribution (BGM17): contributor samples random `d`, then
- `delta_G1 ← d·delta_G1`, `delta_G2 ← d·delta_G2`,
- every **H** and **L** query point ← `d⁻¹·point` (the delta-divided sections),
- appends a proof-of-knowledge of `d` (the s-pair construction) + running transcript hash,
in exactly the snarkjs `.zkey` contributions-section layout, so `snarkjs zkey verify` accepts the
chain. CLI shape: `zeroj-ceremony contribute in.zkey out.zkey` (+ `verify`, `beacon`).

**Honest cost estimate:** a contribution rescales ~77M G1 points (H+L) by one scalar — independent
variable-base muls, embarrassingly parallel. Expected ~1 h-class per contribution at 19M on a
12-core box (vs multi-hour Node), **to be measured in M5 before promising numbers**. blst's
`blst_p1_mult` per point is per-op (the M6 lesson: ~wash vs pure Java) — the win here is
parallelism, not blst batching.

## Milestones

| # | milestone | exit criteria |
|---|---|---|
| M1 | `R1csExporter` + small-circuit round-trip | snarkjs accepts the exported `.r1cs`; setup→contribute→import→prove→verify green; wire/IC order proven by an on-chain-style public-input check |
| M2 | `.zkey` import at 19M + `Groth16PkStore` integration | ownership-circuit-scale zkey imports within memory budget; persisted; warm prove works |
| M3 | Phase-1 source decision (spike) | own-ptau vs Filecoin-conversion measured; one selected + documented |
| M4 | **Option A runbook** | scripted, documented snarkjs ceremony (coordinator + contributor guides, transcript publication, beacon procedure); dry-run on a small circuit |
| M5 | **Option B contributor** | `zeroj-ceremony contribute/verify` producing snarkjs-verifiable contributions; cross-verified against snarkjs on the same transcript; timing measured at 19M |
| M6 | Dry-run ceremony on the ownership circuit | ≥3 contributors (mixed A/B tooling on the same transcript), beacon, published transcript, `snarkjs zkey verify` green, imported key proves + verifies on-chain (testnet) |

## Prerequisite — circuit freeze (sequencing, from ADR-0030)

A ceremony binds to the **exact final R1CS**. Enabling hints post-audit (~19M → ~11–12M), adding the
`ScriptContext`-binding public input, or any gadget fix **invalidates the ceremony**. Order:
**gadget audit → replay-binding publics → freeze circuit → then M6.** M1–M5 (the machinery) can
proceed in parallel with the audit; only the production ceremony itself must wait.

## Security considerations

- Soundness needs **one honest contributor** (phase 1 and phase 2 independently); recruit
  contributors from independent orgs; publish the full transcript + contribution hashes.
- Final randomness via a **public beacon** (e.g. drand round / Bitcoin block hash announced in
  advance) — snarkjs `zkey beacon` supports this.
- **Verification independence:** in both options, transcript verification is `snarkjs zkey verify`
  — never ZeroJ-authored code judging its own ceremony. ZeroJ's import additionally pins the final
  `.zkey` by SHA-256.
- The dev single-party path stays flag-gated (`zeroj.allowInsecureTrustedSetup`) and prints its
  warning; production docs must point exclusively at the ceremony flow.
