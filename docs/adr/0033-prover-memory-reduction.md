# ADR-0033: Prover Memory Reduction — fix the 19M-constraint prove OOM

**Status:** Accepted (2026-07-09) — M2+M3 implemented and measured; target beaten (20 GB floor vs ≤32 GB goal)

## Context

Proving the 19,075,097-constraint account-ownership circuit (43,742,758 wires, FFT domain
2²⁵, Groth16 over BLS12-381) **OOMs at `-Xmx40G`** and **passes at `-Xmx70G`** — consistent with
the ~66–70 GB peak recorded in ADR-0029. The failure is at the *first* MSM:

```
java.lang.OutOfMemoryError
  at ...crypto.msm.ParallelMsm.lambda$parallel$0(ParallelMsm.java:43)
  at ...crypto.groth16.Groth16ProverBLS381.computePiA(Groth16ProverBLS381.java:203)
  at ...crypto.groth16.Groth16ProverBLS381.proveInternal(Groth16ProverBLS381.java:126)
  ...
  at ...usecases.recovery.service.OwnershipCircuitService.prove(OwnershipCircuitService.java:89)
```

ADR-0029 moved the four **G1** proving-key arrays off-heap (mmap). A fresh allocation audit shows
that left **~30–40 GB of avoidable JVM heap** — dominated by one array the mmap work never
covered: **`pointsB2` (the G2 key, 43.7M points) is still fully on-heap as nested `AffineG2`
objects ≈ 15.7 GB.** Everything here **preserves the existing trusted setup / verification key** —
no re-ceremony, the on-chain Julc validator is unchanged, existing key bundles keep working.

## The audit — peak heap at `computePiA` (why 40G fails, 70G passes)

Sizing assumption: `-Xmx40G+` disables compressed oops (threshold ≈ 32 GB), so headers are 16 B
and every reference is 8 B — inflating all object-graph structures.

| # | Buffer | Est. size | Resident at piA? | Fix |
|---|---|---|---|---|
| 1 | `pk.pointsB2` — on-heap `AffineG2[43.7M]`, nested `MontFp2_381→MontFp381` objects (~360 B/pt) — `Groth16PkStore.java:101-104,122` | **~15.7 GB** | yes (from key-load) | M3 mmap |
| 2 | R1CS `constraints` — `List<R1CSConstraint>` (19.1M × three `Map<Integer,BigInteger>`) — `R1CSConstraint.java:12-16`; passed to the prover at `OwnershipCircuitService.java:88-90` and used only by `computeH` | ~6–11 GB | yes (held through all 5 MSMs) | M2 release |
| 3 | blst `enc byte[][]` — every point re-encoded to a fresh heap `byte[96]` across all concurrent chunks — `BlstProverBackend.java:57-59, g1():57-63` | ~5.2 GB transient | yes (piA) | M2 arena |
| 4 | `witness` — `BigInteger[43.7M]` — `OwnershipCircuitService.java:75` | ~4 GB | yes (all MSMs + computeH) | M4 pack |
| 5 | `hCoeffs` — `BigInteger[33.5M]`, held from `computeH` until piC — `Groth16ProverBLS381.java:65,117,168-177` | ~3.75 GB | yes | M4 flat |
| 6 | compiled circuit graph — CLI's `svc` keeps `CircuitBuilder circuit` + `R1CSConstraintSystem r1cs` alive during prove — `OwnershipCircuitService.java:31-42` | ~4 GB | yes | M2 release |
| 7 | `computeH` flat FFT scratch — 3× `long[4·2²⁵]` (aEval/bEval/cEval) — `Groth16ProverBLS381.java:142-158` | 3.2 GB | GC-eligible | already OK |

Sum of resident + piA transient ≈ **41 GB** → exceeds `-Xmx40G`; the decisive trio is
`pointsB2` + `constraints` + the piA `enc` transient. Failing at the very first MSM's parallel
allocation is exactly what the arithmetic predicts.

**Verified layout facts** (make the fixes safe):
- `pointsB2.bin` is written/read as **fixed-width 192 B/point** (four 48-byte big-endian coords)
  via the same `putG2/getG2` used for G1 — `Groth16PkStore.java:62-63,101-104` → directly
  mmap-able like the G1 files.
- `computePiB_G2` consumes `pk.pointsB2()` through `G2MsmBackend.msm(AffineG2[], scalars, n)` —
  `Groth16ProverBLS381.java:210-219`. The G1 MSM already takes a `reader` (mmap) but the G2 MSM
  still takes an on-heap array — the asymmetry M3 closes.
- The blst G2 backend re-derives `BigInteger` coords per point (`BlstProverBackend.java` `g2()` /
  `g2Uncompressed`), so a reader-based G2 source is a drop-in.
- `--backend` **defaults to `blst`** (`ProveCommand.java:38-41`); the blst path is the one that
  OOM'd, and its per-point `byte[96]/byte[192]` encoding (item 3) is a real, fixable heap tax on
  top of the structural ones.

## Decision

Reduce the prover's on-heap footprint in ZeroJ (no setup/VK change), in milestones ordered by
value-per-risk. Target: **~66–70 GB → ≤ 32 GB peak** — which re-engages compressed oops and makes
prove viable on 48 GB machines (vs ~80 GB+ today).

### M2 — Quick wins (zeroj-crypto, zeroj-crypto-blst, CLI)
1. **Release constraints + circuit after H.** Split the prover API additively: make
   `computeH(...)` public and add `proveWithHCoeffs(pk, readers, backend, witness, hCoeffs)`;
   `proveWithReaders` computes H, drops its `constraints` reference, then proves. The
   CLI service computes witness → H → **nulls its cached `circuit`/`r1cs`** → proves. Saves
   ~8–12 GB (items 2 + 6). Note the `snarkjsKey` path builds a *second* derived constraints list
   (`ZkeyPkStoreImporter.snarkjsConstraints`, `OwnershipCircuitService.java:86-88`) — releasing
   after H bounds that transient too.
2. **Encode blst points straight into the native arena.** In the blst G1/G2 backends, write each
   uncompressed encoding directly into the confined `Arena` segment the FFM call already
   allocates, instead of building `byte[][] enc` on heap. Saves ~5 GB transient (item 3).
3. **CLI preflight heap check** in `ProveCommand`: compare `Runtime.getRuntime().maxMemory()`
   against the documented floor and fail fast *before* the ~90 s key load, with the exact
   `-Xmx` to use.

### M3 — mmap `pointsB2` (the ~15.7 GB win)
- Add a `G2AffineReader` (mirror of `PippengerFlatBLS381.G1AffineReader`) with a `SegmentG2Reader`
  over the mmap'd `pointsB2.bin` (no on-disk change) and a `HeapG2Reader` over `AffineG2[]` for
  in-RAM PKs and tests.
- `Groth16PkStore.load` maps `pointsB2.bin` into the existing shared `Arena`; the PK holds an
  empty B2 array; `Loaded` exposes the B2 reader.
- `G2MsmBackend` gains a reader-based `msm(G2AffineReader, scalars, n)` (default adapter for the
  array form); pure-Java `g2Msm` and the blst G2 backend read points on demand.
- Assert `ZkeyPkStoreImporter` writes `pointsB2.bin` in the identical layout (import path stays
  compatible with existing bundles).

### M4 — Stretch (only if M2+M3 miss the 32 GB target)
- Keep `hCoeffs` as flat `long[4·D]` end-to-end into the H-MSM instead of boxing 33.5M
  `BigInteger`s (−2.7 GB).
- Pack the witness to a flat 32 B/scalar array once, drop the `BigInteger[]` (−2.6 GB).

## Alternatives considered (and why not)

The recurring temptation is to delegate proving to a faster/leaner external prover. All were
evaluated against the hard constraint that the proof **must verify on Cardano (BLS12-381
pairings)** and, ideally, **reuse the existing ceremony VK**.

| Option | Reuses our VK? | Memory | Verdict |
|---|---|---|---|
| **Optimize ZeroJ (this ADR)** | ✅ yes | **20 GB measured** after M2–M3 | **Chosen** — only path that keeps the setup and shrinks memory. Beat every alternative below on memory too. |
| **rapidsnark** | (would, but N/A) | very lean, mmap'd | **Ruled out — BN254-only.** `prover.cpp` instantiates `Groth16::makeProver<AltBn128::Engine>` and rejects any zkey whose prime ≠ the BN254 scalar prime with `"zkey curve not supported"`. Our curve is BLS12-381. A BLS12-381 port (ffiasm + G1/G2 ops) is a large unmainlined C++ effort. |
| **classic snarkjs prover** | ✅ yes (same `.zkey`) | ~30–40 GB Node heap | **Documented fallback, not primary.** Supports BLS12-381; `groth16_prove.js` reads the five base sections into accumulating `const` BigBuffers (A+B1+B2+C+H ≈ 24 GB) + polynomial buffers. Est. **~20–60 min** (WASM, calibrated off our measured 2²⁵ `zkey contribute` ≈ 2.5–3 h). **Security caveat: the `.wtns` file contains the root key** — writing it to disk breaks the CLI's "seed never persisted" guarantee, so any snarkjs path must use tmpfs + shred, loudly documented. |
| **gnark hot-swap (keep setup)** | ❌ no | — | **Not possible.** `zeroj-prover-gnark` is a full Go/gnark prover with its own setup + VK; no `.zkey`/`Groth16PkStore` converter exists, and it doesn't implement ZeroJ's `ProverBackend` (that seam is MSM-level). Its only ZeroJ-R1CS entry (`groth16FullProve`) serializes 19M constraints + 43.7M witness values to JSON in JVM heap and **re-runs setup per call** — infeasible. |
| **gnark with a fresh ceremony** | ❌ new VK | ~32–45 GB native RSS | **Feasible but a re-platforming.** gnark v0.14 ships `backend/groth16/bls12-381/mpcsetup`. PK ~24–26 GB raw (no mmap — fully resident in Go RAM). Est. prove ~1.5–3 min (fastest CPU prover), but the in-process FFM path is capped at `GOMAXPROCS(2)` for JVM stability (`main.go:41`), so a real prove needs a standalone Go binary. Requires: iden3→gnark r1cs converter, Java→gnark witness writer, gnark Groth16→Cardano codecs (only PlonK exists), **on-chain validator redeploy with the new VK**, per-platform Go binaries. Weeks of work; buys ~the same memory as M2–M3 without a re-ceremony. Its real differentiator is *speed* — worth a spike (below) before committing. |
| **STARK / zkVM (e.g. RISC Zero)** | ❌ | low RAM, no setup | **Off-chain only** — a STARK receipt is not verifiable by a Plutus validator (Cardano has BLS12-381 pairing builtins, not FRI). Would also prove a weaker statement unless the guest derives from the root. Different product (off-chain attestation), out of scope. |

### Optional spike (M5) — decision data, no integration
1. **snarkjs prove (cheap, first):** export a real `.wtns` (temp, shredded) and run `snarkjs
   groth16 prove` against an existing ceremony `.zkey` with a large `--max-old-space-size`;
   record prove time + peak RSS. All artifacts already exist.
2. **gnark (only if still interesting):** minimal iden3→gnark `cs` converter + single-party
   `groth16.Setup` + prove as a **standalone Go binary** on the exported `circuit.r1cs` + witness
   dump; record pk size, setup/prove time, peak RSS.

Only if one materially beats the M2+M3 outcome does a migration ADR become worth writing.

## Future regime — proving under a hard 16 GB cap (out of current scope)

Under a *hard* memory limit (cgroup/container/physical — a soft target on a big box exerts no
eviction pressure), the binding constraint is the **anonymous (non-evictable) floor**, because
mmap'd clean pages are file-backed and reclaimable but heap is not. Post-M2+M3 that floor is
**measured at 17–20 GB — and it is the R1CS frontend compile** (`R1CSCompiler` building 19M
constraints as three sparse maps each), not the prover: 16 GB dies before proving starts. So the
16 GB regime now needs a frontend workstream first (packed/flat constraint representation, or
compile-once-and-cache the R1CS to disk so `prove` never recompiles), plus M4 (packed witness,
flat hCoeffs) to shrink the prove phase itself to ~9–11 GB. Then it becomes plausible via:
- **Regime A — stream + refault.** A hard cap forces the kernel to evict the mmap'd key; the blst
  path already copies each chunk out of the mapping once per MSM, so a proof reads ~24 GB
  sequentially once (~10–20 s on NVMe). Must confirm the pure-Java Pippenger doesn't do
  per-window multi-pass reads of the same points (that would thrash).
- **Regime B — compressed-point key store.** Store 48 B G1 / 96 B G2 (halving the store to
  ~11.5 GB, cache-resident under 16 GB) and decompress lazily inside the MSM window — one Fp sqrt
  per point per proof (~175M sqrts, est. 1.5–2× prove time). A new PkStore format; future ADR.

There is **no external delegation escape at 16 GB**: rapidsnark is BN254-only and snarkjs itself
needs ~30–40 GB. Reducing the JVM floor is the only route.

## Measurement protocol

- Reuse the existing 19M key bundle (no 47-min re-setup) — the CLI default `--keys` dir.
- After each milestone, prove at descending `-Xmx` (70g → 48g → 40g → 32g); record the floor +
  prove time (must stay ~4–5 min blst).
- Measure **RSS, not just heap**: `-XX:NativeMemoryTracking=summary` + process RSS; the
  file-backed portion of `smaps_rollup` is the mmap'd key, the anonymous portion is the real
  floor. For hard-cap behavior, repeat inside Docker with `mem_limit` (the only way to make
  eviction pressure real on a big box).
- End-to-end: CLI `prove` + `verify` (off-chain) + `verify --onchain` (Yaci DevKit) against the
  existing bundle — proves the VK is preserved.

## Results

_(appended as milestones land)_

| milestone | -Xmx floor | prove time | notes |
|---|---|---|---|
| baseline | ~70 GB (40 GB OOMs) | ~4.7 min blst | pre-M2; key load ~2 min on top |
| M2+M3 | **32 GB PASS** | **2.2 min blst** (2.5 min total) | 2026-07-09, 12-core/128 GB box, same 23 GB bundle, self-check PASS. Key load 0.0 s (mmap, no G2 decode). Peak footprint 39.6 GB (incl. touched file-backed mmap pages, evictable); max RSS 55.5 GB on an unconstrained box. Prove got ~2× faster: no 43.7M-object G2 decode at load, G2 encode is raw byte re-order from the mmap, no `byte[][]` marshalling, far less GC pressure. |
| M2+M3 | **24 GB PASS** | 2.1 min blst (2.5 min total) | Same run, `-Xmx24g`: no slowdown at all (128.9 s vs 132.0 s at 32 GB) — compressed oops re-engage below ~32 GB and shrink every object graph. Peak footprint 37.7 GB. |
| M2+M3 | **20 GB PASS** | 2.6 min blst (3.0 min total) | `-Xmx20g`: passes with a mild GC tax (154.0 s prove). This is the measured floor. |
| M2+M3 | 16 GB **OOM** | — | OOMs in the R1CS **frontend compile** (`R1CSCompiler.addExprs`), before the prove is ever reached — the binding floor is now the 19M-constraint circuit build (three sparse maps/constraint), not the prover. Reducing *that* is a frontend workstream (packed/flat constraint representation), out of this ADR's scope. |
| M2+M3, `--backend java` | 24 GB PASS | **1.7 min pure Java** (2.1 min total) | Unexpected headline: with the key mmap'd, the pure-Java flat Pippenger (104.5 s) now **matches or beats blst (128.9 s)** at 19M scale — it reads the Montgomery limbs straight from the mapping with zero conversion, while the blst path pays a per-point Montgomery→BigInteger→BE encode + native deserialize. Peak footprint just 26.6 GB. The pre-ADR pure-Java prove was ~9 min. A second pair of runs on the same box under normal desktop load measured blst 165.5 s vs java 172.8 s — i.e. **the backends are now equivalent at this scale** (the MSM was never the real bottleneck; marshalling and GC were). Default stays `blst`; the practical win is that the native-image binary (pure-Java only) is now a first-class prover, not a slow fallback. |

**Outcome: target beaten.** The plan aimed for ≤32 GB; the measured floor is **20 GB** (~70 GB
before — a 3.5× reduction), prove time dropped ~2× (blst) / ~5× (pure Java), key load went from
~100 s to instant, and the VK/setup is untouched (self-check + `verify` PASS against the existing
bundle). M4 (flat hCoeffs, packed witness) is **not needed** for the target and stays unimplemented;
the next floor reduction must target the R1CS frontend compile instead.
