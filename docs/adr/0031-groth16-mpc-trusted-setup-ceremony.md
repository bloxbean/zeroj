# ADR-0031: Groth16 MPC Trusted-Setup Ceremony — snarkjs Path + ZeroJ-Native Contributor

## Status

Proposed (2026-07-08; amended 2026-11-20 for R3 contributor input validation, secret-scalar
routing, atomic writes, and fail-closed CI interop) — planned on `feat/adr_0031_mpc_ceremony`. The
**CLI artifact boundary** is superseded by
[ADR-0044](0044-focused-module-surface-and-optional-provider-isolation.md).

ADR-0044 merged the `zeroj-ceremony` Gradle module into `zeroj-tools`. This is a
packaging change only. The `zeroj-ceremony` command name, CLI behavior, release
asset names, Picocli configuration, native-image metadata, transcript bytes,
randomness and secret handling, the `zeroj.allowInsecureTrustedSetup` guard, and
the requirement that `snarkjs zkey verify` remain the independent transcript
verifier are all unchanged. No ceremony cryptography moved.

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

### CLI packaging (`zeroj-ceremony`)

The ceremony tooling ships as a **CLI** (new module), because contributors and coordinators are not
Java developers calling APIs — each role gets one command:

| command | who | what | milestone |
|---|---|---|---|
| `export-r1cs --circuit <FQCN of @ZKCircuit> --out c.r1cs` | coordinator | compile the ZeroJ circuit → iden3 `.r1cs` (used by **both** options) | M4 |
| `contribute in.zkey out.zkey` | contributor | Option B phase-2 contribution (entropy prompt + hash printout) | M5 |
| `verify c.r1cs pot.ptau final.zkey` | anyone | convenience wrapper; **independent check remains `snarkjs zkey verify`** | M5 |
| `beacon in.zkey out.zkey --hash <pub randomness>` | coordinator | final beacon contribution | M5 |
| `finalize final.zkey --pk-store <dir>` | coordinator | import + persist via `Groth16PkStore`, export the VK for the validator | M2/M4 |

Same module family later hosts the planned end-user proving CLI (seed phrase → ownership proof) —
the ceremony CLI is its trust-side counterpart.

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

## M3 result — phase-1 source decision (2026-07-08)

**Measured** (snarkjs 0.7.6 / Node, this machine):

| power | `new` | `contribute` | `prepare phase2` |
|---|---|---|---|
| 2¹⁴ | 1 s | 5 s | 77 s |
| 2¹⁶ | 1 s | 19 s | 342 s |
| 2¹⁸ | 5 s | 74 s | 1676 s |

Scaling ≈ ×4 per +2 powers → at **2²⁵**: contribution ≈ **2.5–3 h each**, `prepare phase2` ≈
**60–105 h** (one-time), final `.ptau` ≈ 32 GB.

**Decision: adopt Filecoin's phase 1 as the primary source; own-ptau as fallback.**
- Filecoin's BLS12-381 ceremony (2²⁷, ~20 independent publicly-attested participants + beacon;
  files at `trusted-setup.filecoin.io`, attestations in the perpetualpowersoftau repo) gives far
  stronger phase-1 trust than any small ceremony we could run, at zero contributor cost. Reusing a
  large public phase 1 is the ecosystem norm (all of circom/bn254 reuses PPoT/Hermez; Avail derived
  their BLS12-381 SRS from Filecoin's — direct precedent).
- Conversion (Rust challenge/response format → `.ptau`) is plausible — snarkjs's
  `powersoftau challenge contribute <curve>` / `import response` are curve-parameterized and
  `truncate` cuts 2²⁷ → 2²⁵ — but must be proven on the real (~50–100 GB) files: an M6-adjacent
  verification item. **The pairing-structure check (`snarkjs powersoftau verify`) validates the
  converted accumulator independently of the conversion tool**, so a broken converter cannot slip
  through.
- The one-time `prepare phase2` (~60–105 h Node) is required for **either** source; it is
  circuit-independent, so it is paid once and the prepared `.ptau` is cached and reused for every
  future circuit ≤ 2²⁵. A ZeroJ-native parallel `prepare` (our NTT/EC stack, est. ~5–10× faster) is
  recorded as an optimization, not a blocker.

**CLI shape** — phase-1 source is a pluggable option (user preference, extensible):

```
zeroj-ceremony phase1 --source filecoin|file|new --power 25 --out pot25.ptau
```
Every source funnels through the same non-negotiable pipeline:
**acquire → `powersoftau verify` → `truncate` → `prepare phase2` → cache** (`~/.zeroj/ptau/`).
Note: the phase-1 source choice never removes the need for ≥1 honest **phase-2** contribution —
that stays with the circuit's ceremony (minimum viable: coordinator contribution + public beacon).

## Milestones

| # | milestone | exit criteria |
|---|---|---|
| M1 | `R1csExporter` + small-circuit round-trip | snarkjs accepts the exported `.r1cs`; setup→contribute→import→prove→verify green; wire/IC order proven by an on-chain-style public-input check |
| M2 | `.zkey` import at 19M + `Groth16PkStore` integration | ownership-circuit-scale zkey imports within memory budget; persisted; warm prove works |
| M3 | Phase-1 source decision (spike) | own-ptau vs Filecoin-conversion measured; one selected + documented |
| M4 | **Option A runbook** | scripted, documented snarkjs ceremony (coordinator + contributor guides, transcript publication, beacon procedure); dry-run on a small circuit |
| M5 | **Option B contributor** | `zeroj-ceremony contribute/verify` producing snarkjs-verifiable contributions; cross-verified against snarkjs on the same transcript; timing measured at 19M |
| M6 | Dry-run ceremony on the ownership circuit | ≥3 contributors (mixed A/B tooling on the same transcript), beacon, published transcript, `snarkjs zkey verify` green, imported key proves + verifies on-chain (testnet) |

## Results (2026-07-08) — M1–M6 delivered

| milestone | result |
|---|---|
| M1 | `R1csExporter` + live snarkjs round-trip **green** (ZeroJ r1cs → snarkjs ceremony → `zkey verify` OK → import → ZeroJ prove → pairing verify vs snarkjs VK) |
| M2 | `ZkeyPkStoreImporter` — streaming (mmap) ceremony-`.zkey` → `Groth16PkStore`; bit-identical to the strict importer; `snarkjsConstraints()` binding-row synthesis asserted against real zkeys (which store only the A/B matrices — provers derive C=A·B) |
| M3 | phase-1 decision: **Filecoin PoT primary**, own-ptau fallback (measured table above) |
| M4 | `zeroj-ceremony` CLI (picocli; GraalVM configs auto-emitted; `contribute`/`finalize` native-friendly) + Option-A runbook; full ceremony driven through the CLI **green** |
| M5 | **ZeroJ-native contributor, snarkjs-verified**: `contribute` writes snarkjs-format `.zkey`; interop test: zeroj → `snarkjs zkey verify` OK → snarkjs stacks on top → second zeroj contribution → verify OK → proves. Measured **23.3k parallel G1 muls/s → a 19M-circuit contribution ≈ 0.9 h** (vs ~2.5–3 h Node) |
| M6 | **rehearsal ceremony green** (`docs/ceremony/rehearsal.sh`): mixed tooling (2 ZeroJ + 1 snarkjs), beacon, independent `zkey verify`, finalize → PkStore |

**Bug-compatibility findings** (the two subtleties that make Option B possible, documented in code):
1. ffjavascript's `fromRng` writes sampled bytes canonically but WASM field ops treat buffers as
   Montgomery form → the semantic sampled value is `v·R⁻¹ mod p` (`SnarkjsHashToG2.sampleFp`).
2. The contribution transcript streams each prior record's **raw components** into one running
   blake2b-512 — not the priors' sub-hashes; the two coincide only for the first contribution.

**Still open for the production ceremony** (by design, not omission): the Filecoin
challenge→`.ptau` conversion exercised on the real ~50–100 GB files; the one-time 2²⁵
`prepare phase2` (~60–105 h Node, cached forever); `beacon` in the ZeroJ CLI (use snarkjs's
meanwhile); and the circuit freeze below.

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

---

## 2026-11-20 Amendment — R3 Contributor Hardening & Fail-Closed CI Interop

### Risk classification

- **R3:** `ZkeyContributor` (`zeroj-tools`) applies contributor secret scalars (`k`, `k⁻¹`, `s`) to
  untrusted elliptic-curve points read from an input `.zkey` file.
- **R1 / Process:** Fail-closed CI execution of the four ceremony and streaming `.zkey`
  interoperability suites against pinned `snarkjs@0.7.6`.

### Threat model & trust assumptions

1. **Untrusted input `.zkey`:** The input `.zkey` file supplied to `zeroj-ceremony contribute` is
   treated as untrusted (for example, a compromised coordinator or malicious prior participant). An
   attacker may inject off-curve points, small-subgroup (cofactor) points, non-canonical field
   coordinates (`>= p`), identity `delta1`/`delta2`, mismatched `delta1`/`delta2` pairings, a broken
   prior-contribution chain, malformed/overlapping section tables, or invalid TLV parameters.
   Because short-Weierstrass Jacobian formulas do not depend on `b`, multiplying thousands of
   unvalidated `L`/`H` points by the same secret `k⁻¹` via variable-time `scalarMul` creates an
   invalid-curve and small-subgroup leakage surface against the contributor's secret.
2. **Secret values & ADR-0062 I3 contract:** The freshly sampled scalars `k`, `k⁻¹ mod r`, and `s`
   are secret. Routing all secret multiplications through `JacobianG1BLS381.ctScalarMul` /
   `JacobianG2BLS381.ctScalarMul` ([ADR-0062](0062-bls12381-independent-review-and-remediation.md)
   D1: Clavier–Joye additive scalar splitting + fixed-schedule Montgomery ladder + built-in on-curve
   and prime-order subgroup check) removes variable-time bit-length/operation-schedule leakage and
   blocks invalid-curve/subgroup inputs. Per **ADR-0062 I3**, this is **not** a JVM constant-time
   guarantee (`BigInteger`, field reductions, Java branches, JIT, and GC remain variable-time);
   production ceremony contributions MUST still run on an **offline, isolated host**.
3. **Independent verification unchanged:** `snarkjs zkey verify` (`0.7.6`) remains the independent
   verifier of the complete ceremony transcript. `zeroj-ceremony` implements `export-r1cs`,
   `contribute`, and `finalize`; `verify` and `beacon` remain executed directly with `snarkjs`.

### Pinned normative references

- `snarkjs@0.7.6`: `src/zkey_contribute.js`, `src/zkey_utils.js`, `src/zkey_new.js`,
  `src/zkey_verify_frominit.js`, `src/mpc_applykey.js`, `src/misc.js`.
- `ffjavascript@0.3.1`: `src/wasm_curve.js` (LEM affine zero encoding `0^96` for G1 and `0^192` for
  G2; `batchApplyKey` preserves infinity).
- [ADR-0062](0062-bls12381-independent-review-and-remediation.md) (D1 `ctScalarMul`, I3 honest
  secret-path contract, D7 raw pairing validation).
- [ADR-0047](0047-snarkjs-bidirectional-interop-export-and-ci.md) (pinned `snarkjs@0.7.6` CI oracle
  and `-PrequireSnarkjs`).

### Exact security invariants (`S1`–`S7`)

- **S1 — File & section table framing:** Require `inSize >= 12`, magic `0x79656b7a` (`"zkey"` LE),
  version `∈ {1, 2}`, exactly 10 unique sections (`1..10`), no negative/out-of-bounds sizes, no
  duplicate or unsupported section types, exact consumption (`pos == inSize`, zero trailing bytes),
  section 1 size `== 4` with protocol `== 1` (Groth16), and section 2 size `== 964`.
- **S2 — Exact BLS12-381 primes & section dimensions:** Require `n8q == 48`, exact unsigned LE
  `q == MontFp381.modulus()`, `n8r == 32`, exact unsigned LE `r == MontFr381.modulus()`. Validate
  `nVars >= 1`, `nVars >= nPublic + 1`, `domainSize` positive power of 2, exact section sizes for
  sections 3 (`(nPublic + 1) * 96`), 4 (`4 + nCoeffs * 44`), 5 (`nVars * 96`), 6 (`nVars * 96`),
  7 (`nVars * 192`), 8 (`(nVars - nPublic - 1) * 96`), and 9 (`domainSize * 96`).
- **S3 — Canonical Montgomery decoding & G2 infinity sentinel:** Decode every 48-byte LEM coordinate
  via `MontFp381.fromMontLimbs(...)`, which rejects raw values `>= p` without silent modular
  reduction. `g2FromLem` explicitly detects the 192-byte all-zero infinity sentinel and returns
  `AffineG2.INFINITY`.
- **S4 — Pre-secret header, pairing, and contribution chain validation:** Before sampling `k` or `s`:
  - All six header points (`alpha1`, `beta1`, `beta2`, `gamma2`, `delta1`, `delta2`) and every prior
    contribution's `deltaAfter`, `g1_s`, `g1_sx`, `g2_spx` MUST be canonical (`< p`), non-infinity,
    on-curve, and in the prime-order subgroup (`[r]P = O`).
  - Header deltas MUST satisfy `e(delta1, G2) == e(G1, delta2)`.
  - Section 10 MUST be structurally exact (`size >= 68`, bounded `nContrib`, `type ∈ {0, 1}`,
    strictly ascending TLV parameter tags `{1, 2, 3}` matching `snarkjs zkey_utils.js`, zero
    trailing bytes).
  - Chain continuity: `delta1` MUST equal `G1` when `nContrib == 0`, and MUST equal
    `priors[nContrib - 1].deltaAfter` when `nContrib > 0` (matching
    `snarkjs zkey_verify_frominit.js:48,141`).
- **S5 — Pinned `snarkjs 0.7.6` infinity semantics for `L` and `H`:** Per `snarkjs@0.7.6`
  (`zkey_new.js:460-466`, `mpc_applykey.js:44`) and `ffjavascript@0.3.1` (`wasm_curve.js`), the
  all-zero 96-byte LEM infinity sentinel is legal in `L` (e.g. private wires unused in constraints)
  and preserved unchanged (`k⁻¹ · O = O`, leaking zero bits of `k⁻¹`). Every non-infinity point in
  `L` (section 8) and `H` (section 9) MUST have canonical `< p` coordinates, lie on BLS12-381 G1,
  and lie in the prime-order subgroup. Any violation aborts the contribution with `IOException`.
- **S6 — Secret-scalar routing (`ctScalarMul`):** Every multiplication by `s`, `k`, or `k⁻¹`
  (`g1_s`, `g1_sx`, `g2_spx`, `delta1New`, `delta2New`, and every non-infinity `L`/`H` point) is
  routed through `JacobianG1BLS381.ctScalarMul` / `JacobianG2BLS381.ctScalarMul`. For `L`/`H`,
  validation relies on `ctScalarMul`'s built-in on-curve + prime-order subgroup check (avoiding a
  duplicate subgroup check per point) and maps `IllegalArgumentException` across parallel worker
  threads into a deterministic `IOException`.
- **S7 — Atomic output writes, overwrite guard, and UTF-8 `--name` safety:**
  - In-place overwrite (`in` and `out` resolving to the same file, including symlinks via
    `Files.isSameFile`) is unconditionally rejected, even when overwrite is requested.
  - Existing `out` is rejected by default (`ZkeyContributor.contribute(in, out, name)` and CLI
    `contribute`) unless explicit `overwrite = true` / `--overwrite` is supplied.
  - Output is written to a sibling temp file in `out`'s parent directory, forced to storage
    (`FileChannel.force(true)`), unmapped/closed, and published atomically (`Files.createLink` for
    non-clobbering publish when `!overwrite`, or `Files.move(..., ATOMIC_MOVE, REPLACE_EXISTING)`
    when `overwrite`). On any error, the temp file is deleted and any existing `out` remains
    untouched.
  - `--name` truncates up to 64 code points and `<= 255` UTF-8 bytes on code-point boundaries,
    matching `snarkjs 0.7.6` while preventing surrogate splits and 1-byte TLV length overflow.

### Alternatives considered & measured performance trade-off

- **Measured throughput (16-core Apple Silicon, Java 25, 4,096 affine G1 points after warmup):**
  - Previous unvalidated variable-time `scalarMul`: **19,006 muls/s** (`0.216 s`).
  - Hardened ADR-0062 `ctScalarMul` (includes single on-curve + subgroup check + additive scalar
    splitting + 2×255 Montgomery ladder): **5,326 muls/s** (`0.769 s`), a **`3.57×`** factor.
  - Extrapolated to a 19M-constraint circuit (~77M L+H points): ~**4.0 h** on 16 cores (vs ~1.1 h
    unvalidated variable-time).
- **Alternative rejected:** Inventing an unpinned batched subgroup test to skip per-point subgroup
  checks in `L`/`H`. Rejected under `AGENTS.md` (do not invent cryptography; never trade
  cryptographic soundness/secret safety for performance without an explicit reviewed design).

### Compatibility & breaking notes

- **Behavioral change:** `ZkeyContributor.contribute(Path, Path, String)` now throws `IOException`
  if `out` already exists (previously it deleted `out` first). Callers intending replacement must
  call `contribute(in, out, name, true)` or pass `--overwrite` to `zeroj-ceremony contribute`.
  In-place `--in == --out` is always rejected.
- **Stricter input validation:** Malformed or synthetic `.zkey` files with wrong primes, non-canonical
  coordinates, invalid points, mismatched `delta1`/`delta2` pairings, or broken `deltaAfter` chains
  are now rejected before secret generation.
- **Wire compatibility:** Produced `.zkey` files remain 100% bit-compatible with `snarkjs@0.7.6`.

### CI interop wiring

- Shared test-fixture locator `SnarkjsCliLocator` (`zeroj-crypto` `testFixtures`, excluded from
  published artifacts per ADR-0046) resolves `snarkjs@0.7.6` via `-Dzeroj.snarkjs`, `SNARKJS_BIN`,
  `PATH`, and common npm directories.
- `zeroj-crypto/build.gradle`, `zeroj-tools/build.gradle`, and `zeroj-integration-tests/build.gradle`
  forward `-Dzeroj.snarkjs` and honor `-PrequireSnarkjs` (`zeroj.assurance.requireSnarkjs=true`,
  disabling up-to-date caching).
- `.github/workflows/assurance.yml` (`snarkjs-interop` job) runs all four ceremony / `.zkey` interop
  suites (`R1csSnarkjsCeremonyRoundTripTest`, `ZkeyPkStoreImporterTest`,
  `ZkeyContributorInteropTest`, `CeremonyCliTest`) fail-closed under `-PrequireSnarkjs`.

### Amendment milestones & audit gates

| Milestone | Scope | Status |
|---|---|---|
| M7 | Implement S1–S7 in `ZkeyContributor` and `CeremonyCli` (`--overwrite`) | Implemented |
| M8 | Offline unit/negative test suite (`ZkeyContributorTest`) covering framing, primes, canonical `< p`, infinity, off-curve, small-subgroup, pairing mismatch, chain break, TLV, overwrite/atomic rollback | Implemented |
| M9 | `SnarkjsCliLocator` + `-PrequireSnarkjs` + `assurance.yml` wiring for all 4 ceremony/streaming `.zkey` suites | Implemented |
| M10 | External cryptographic review & ceremony rehearsal sign-off before production value-bearing ceremony | Open (mandatory gate) |

### Revision history

- **2026-07-08:** Initial `Proposed` ADR covering Option A/B ceremony architecture and M1–M6 results.
- **2026-08-31:** CLI artifact boundary superseded by ADR-0044 (`zeroj-ceremony` merged into `zeroj-tools`).
- **2026-11-20:** Added R3 contributor hardening amendment (`S1`–`S7`), measured `ctScalarMul`
  throughput trade-off (`3.57×`), pinned `snarkjs@0.7.6` `L`/`H` infinity semantics, and fail-closed
  CI interop wiring (`SnarkjsCliLocator` + `assurance.yml`). Status remains `Proposed` pending review.
