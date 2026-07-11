# zeroj-ceremony review — transferable optimizations + API-module extraction

*2026-07-10 — follow-up to ADR-0033/0034/0035; requested after the account-ownership CLI
optimization arcs.*

## Scope

Two questions:
1. Which of the account-ownership CLI's setup/prove/verify optimizations transfer to the
   `zeroj-ceremony` CLI (`export-r1cs` / `contribute` / `finalize`)?
2. Which APIs currently trapped in the `zeroj-ceremony` CLI module belong in a reusable
   library module (previously identified; this reviews and confirms)?

## Current state (good news first)

- **`contribute`** (`ZkeyContributor`) is already mmap-in/mmap-out (FFM `MemorySegment`s, no
  whole-file heap buffers) and multi-core (`FrFFTFlat.parallelRange` over the L/H rescale).
- **`finalize`** delegates to `ZkeyPkStoreImporter.importToPkStore` — already the streaming,
  multi-GB-safe path (ADR-0031 M2).
- **`export-r1cs`** rides the shared compiler, so it inherited ADR-0034's CSR + liveness-eviction
  memory improvements automatically.
- The format/store layer the ceremony flow needs (`R1csExporter`, `ZkeyPkStoreImporter`,
  `Groth16PkStore`, now `Groth16Keys`) already lives in `zeroj-crypto` — the CLI is a thin
  picocli wrapper over it, which is the right shape.

## 1. Transferable optimizations (ranked)

### 1a. `contribute`: flat-limb rescale + batch affine normalization — the big one

`rescaleG1Section` processes every L- and H-section point (~77M points at the 19M circuit:
L ≈ 43.7M, H = 33.5M) as:

```
LEM bytes → BigInteger (×R⁻¹ mod p, a BigInteger multiply+mod)  ← fromMontLE
         → MontFp381 objects → generic Jacobian scalarMul(kInv)
         → toAffine()                                            ← ONE Fp inversion PER POINT
         → BigInteger (×R mod p) → LEM bytes                     ← montLE
```

Three ADR-0034/0035 techniques apply directly:
- **Skip the Montgomery round-trips entirely.** The `.zkey` LEM layout is little-endian
  Montgomery with the same R = 2³⁸⁴ as `MontFp381` — points can be read/written as raw limbs
  with zero conversions. The `fromMontLE`/`montLE` BigInteger arithmetic (4 mult+mod per point
  read, 2 per write) is pure waste.
- **Batch affine normalization** (ADR-0035 M4 / `FixedBaseG1BLS381.batchNormalize` pattern):
  keep the scalarMul result Jacobian, normalize 512-point blocks with ONE Fp inversion
  (Montgomery's trick) instead of ~77M individual inversions.
- **Recode the scalar once**: `kInv` is the same for every point — compute its window/wNAF
  digits once per contribution, not per point.

Estimated 2–4× contribute speedup at 19M scale. **Regression gate exists**: add a deterministic
`contribute` overload (explicit `k`, like setup's explicit-randomness overloads) and
byte-compare the output `.zkey` against the current implementation, plus the existing
`ZkeyContributorInteropTest` (stock `snarkjs zkey verify` must keep passing). Effort: medium.

### 1b. `finalize --sparse`

`ZkeyPkStoreImporter` hardcodes the dense manifest (the format-less `writeAuxAndManifest`
overload at ZkeyPkStoreImporter.java:134). The sparse machinery (ADR-0035 M6a,
`SparsePointFile`) is format-level and applies to ceremony keys identically (~57% infinity
points is a circuit property, not a setup-path property) — an opt-in `--sparse` on `finalize`
would shrink production bundles 24 → ~9.3 GB too. Default must stay dense (compatibility
contract). Needs a presence-bitmap pass while streaming the zkey (the streaming setup already
solved the same problem with its exact-bitmap pass). Effort: small–medium.

### 1c. `finalize`: co-locate `r1cs.bin`

The account-ownership `setup` now emits the fingerprint-gated constraint cache in-pass, so the
first prove skips its compile. `finalize` (or the consuming app's `import`) could accept the
circuit/`.r1cs` and write `r1cs.bin` into the pk-store the same way. Effort: small.

### 1d. Fail-fast preflight + measured heap numbers + hard-cap validation

- `export-r1cs` compiles the circuit (multi-GB at 19M) with no heap preflight — port
  `ProveCommand`'s `Runtime.maxMemory()` fail-fast check and document the `-Xmx` requirement
  in the USER-GUIDE.
- `contribute`/`finalize` are mmap-based and heap-light, but neither has measured/documented
  footprints — run them once under a hard 16 GiB Docker cap (the ADR-0034/0035 M5 protocol)
  and put the numbers in the guide.
- Optional: the auto-heap-sizing launcher from the account-ownership distZip.
Effort: trivial–small.

### Not applicable

- **Prove/verify optimizations**: the ceremony tool doesn't prove or verify proofs; transcript
  verification is deliberately delegated to `snarkjs zkey verify` (trust argument: verify with
  the tool we didn't write). A Java transcript verifier would be new scope — note as future.

## 2. API-module extraction (confirms the earlier observation)

**Gap**: the contribution engine — `ZkeyContributor` (clean entry:
`contribute(Path in, Path out, String name) → byte[] hash`), `SnarkjsHashToG2`, `ChaChaRng` —
lives in the CLI module. A consuming app (ceremony-coordinator service, a wallet embedding a
contribution step, or the account-ownership CLI growing a `contribute` command) would have to
depend on a CLI artifact: picocli dragged in, `Main-Class` manifest, and since the CLI declares
its deps as `implementation`, nothing is exposed transitively anyway.

**Recommendation — extract `zeroj-tools`** (Satya's naming, generic so future operator tools —
transcript verifier, bundle inspector, dense↔sparse converter — have a home; guard-rail: library
code stays out, this is for things an operator runs/embeds):
- Moves: `ZkeyContributor`, `SnarkjsHashToG2`, `ChaChaRng` under
  `com.bloxbean.cardano.zeroj.tools.zkey` (+ the self-contained hash-to-G2 test; the
  contributor *interop* test stays in `zeroj-ceremony` — it drives `CeremonyCli.run` end-to-end).
- Deps: `zeroj-crypto`, `zeroj-bls12381` (api — G2 points in signatures), BouncyCastle.
- `zeroj-ceremony` (CLI) keeps picocli + depends on the new module.
- **STATUS: DONE 2026-07-11** (uncommitted, pending review) — both modules' tests green,
  including the live snarkjs mixed-transcript interop test.

**Also done alongside (same session): `Groth16Pipeline`** — the circuit-agnostic setup/prove
orchestration (fingerprint + r1cs.bin cache + deferred mmap constraint load + release ordering)
extracted from the account-ownership CLI into zeroj-crypto, and the CLI switched onto it; see
`docs/groth16-dev-guide.md`. This is the "reuse the optimizations in other big circuits" answer.

**Why not `zeroj-crypto`?** It is deliberately third-party-free (deps: `zeroj-api` +
`zeroj-bls12381` only). `ZkeyContributor` needs Blake2b-512, and the existing
`circuit-lib` Blake2b is the in-circuit gadget (CircuitAPI), not a native hasher. Either vendor
a pure-Java RFC 7693 Blake2b (~150 lines) to keep `zeroj-crypto` clean, or — simpler and
zero-risk — keep BC in the new module. The separate module also matches the existing
per-concern module pattern (`zeroj-verifier-groth16`, `zeroj-codec`).

**API polish worth doing during the move** (all additive):
- Deterministic `contribute` overload (explicit `k` / injected `SecureRandom`) — enables the
  byte-equality regression gate for 1a and mirrors the setup/prove deterministic seams.
- An entropy-callback parameter (snarkjs prompts contributors for entropy; embedding apps will
  want to supply it).
- Return a small record (`hash`, `contributionIndex`, `name`) instead of a raw `byte[]`.
- GraalVM: package the reflection/resource configs in the new module per project convention.

**Suggested order**: extraction first (hours, unblocks consumers, zero behavioral change) →
`finalize --sparse` (1b) → contribute flat-limb/batch work (1a) when a real 19M ceremony is
scheduled — it's the biggest win but should land with its deterministic regression gate.

## Appendix: is the account-ownership CLI using the new `Groth16Keys` facade?

**No — deliberately.** The facade delegates to the same engine, but the CLI's pipeline is
hand-tuned in ways a general-purpose API must not impose: it emits `r1cs.bin` between compile
and setup, nulls the circuit graph before the heavy phase, chooses boxed witness +
`packConsuming` (measured better than born-flat for this bit-heavy circuit), defers the mapped
cache load until after witness, and orders its preflight before the compile.
`Groth16Keys.setupToStore` additionally re-opens the store after setup (the right default for
a library caller; pointless for `SetupCommand`, which writes the VK and exits). Switching the
CLI would risk regressing measured memory floors for zero functional gain — the CLI *is* the
expert-layer reference (linked as such from `docs/groth16-dev-guide.md`), and the facade is for
new integrations.
