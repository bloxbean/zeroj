# ADR-0036: Groth16 API facade (`Groth16Keys`) + reusable orchestration (`Groth16Pipeline`) + `zeroj-tools`

- **Status**: accepted + implemented, 2026-07-11
- **Depends on**: ADR-0029 (PkStore/mmap), ADR-0033 (prover memory), ADR-0034 (frontend/CSR + flat scalars), ADR-0035 (streaming setup + sparse store)

## Context

ADR-0033/0034/0035 left `zeroj-crypto` with two API "worlds": the classic in-heap
`setup(...)`/`prove(pk, …)` pair, and the big-circuit world of reader seams, flat scalars, split
H computation, `r1cs.bin` caching, and streamed stores. The engine underneath was already unified
(every prove funnels into one `proveInternal(pk, readers, …)`), but the *surface* was six prove
overloads and two setup families, with pairing rules a caller had to know (e.g. `setupToStore`'s
`SetupResult` holds empty PK arrays and must be paired with `Groth16PkStore.load` +
`proveWithReaders`).

Worse for reuse: the *orchestration* that actually produced the measured numbers — fingerprint
gating, emit-cache-on-setup, probe-header-before-compile, witness-before-mapped-constraint-load,
release ordering through the MSMs — lived only inside the account-ownership CLI. A second big
circuit would have had to reimplement it by imitation. Separately, the ceremony contribution
engine (`ZkeyContributor` + `SnarkjsHashToG2` + `ChaChaRng`) was trapped inside the
`zeroj-ceremony` CLI module (picocli dependency, `implementation`-scoped deps), unusable as a
library.

## Decision

Three additive layers, no changes to any existing entry point:

1. **`Groth16Keys` (facade)** — one `AutoCloseable` handle for the key material wherever it
   lives: `setupInMemory(...)` (heap), `setupToStore(...)` (streamed, sparse/dense, returns a
   live handle over the store it just wrote — the empty-PK footgun is gone), `load(dir)`
   (dense/sparse auto-detected; also snarkjs-imported bundles), `of(SetupResult)` /
   `of(Loaded)` for interop. Three `prove` overloads (default, explicit backend, packed/CSR)
   that work identically against every key home. Pure delegation.

2. **`Groth16Pipeline` (orchestration)** — the CLI's circuit-agnostic setup/prove flow,
   extracted verbatim: owns the canonical fingerprint (`c<nc>-w<nw>-p<np>`; the CLI's `Bundle`
   now delegates), `Compiled` record, `setup(cc, tau, dir, sparse)` = `r1cs.bin` + streamed
   store, and a cache-aware `prove(keys, cacheFile, fingerprint, compileSupplier,
   witnessSupplier, bindingRows, backend)` that (a) probes only the cache header up front,
   (b) invokes the compile supplier *only on a miss* and writes the cache, (c) runs the witness
   supplier, (d) then memory-maps the constraints — never heap-loads them — and (e) releases
   the constraint reference before the MSMs. `Progress` listener for CLI narration;
   `parseFingerprint` for pre-compile preflight; `estimateProvePhaseHeapBytes` as a documented
   *lower bound* (the true floor is witness-graph-bound, i.e. circuit-specific). The two
   suppliers are exactly the two circuit-specific pieces an app must own.

3. **`zeroj-tools` (new module)** — `ZkeyContributor`, `SnarkjsHashToG2`, `ChaChaRng` moved
   (git mv) to `com.bloxbean.cardano.zeroj.tools.zkey`; deps `zeroj-crypto` +
   `zeroj-bls12381` (api) + BouncyCastle. `zeroj-ceremony` keeps only the picocli CLI and
   depends on it. `zeroj-crypto` stays third-party-free (the reason the contributor does not
   move there: its blake2b-512 needs BC; the circuit-lib Blake2b is an in-circuit gadget).
   Naming is generic per Satya: future operator tools (transcript verifier, bundle inspector,
   dense↔sparse converter) land here; library code does not.

The account-ownership CLI was switched onto the pipeline (its service keeps only circuit build +
witness mapping) and serves as the reference consumer. During the switch a committed bug was
found and fixed: `d53e8e4` left `HARD_MIN_HEAP_GB = 4 // TEMP probe` from the descending-Xmx
experiments, neutering the documented 8/7 GB preflight.

## Alternatives considered

- **Document-only** (keep two worlds, write a guide): rejected — the pairing rules and the
  empty-PK wrinkle would need explaining forever, and the orchestration would remain
  copy-paste-to-reuse.
- **Fold everything into the existing classes** (more overloads on `Groth16ProverBLS381`):
  rejected — the overload matrix was the problem.
- **Pipeline in a new module**: rejected — it orchestrates seams that all live in
  `zeroj-crypto` and adds no dependencies.

## Compatibility

- Every pre-existing public entry point is unchanged (javadoc pointers only); the full
  `zeroj-crypto` suite including the byte-equality differential gates and the live snarkjs
  round-trip stayed green.
- Fingerprint strings are byte-identical to the CLI's previous format (unit-asserted), so
  existing `r1cs.bin` caches and `bundle.properties` keep matching.
- The **one breaking relocation**: code that depended on the `zeroj-ceremony` artifact for
  `ZkeyContributor`/`SnarkjsHashToG2`/`ChaChaRng` must switch to `zeroj-tools` and the new
  package. Judged acceptable pre-1.0: the CLI module's deps were `implementation`-scoped, so
  external library use was effectively impossible anyway. Called out for the release notes.

## Validation (19M account-ownership circuit, pipeline-driven CLI)

| run | result | pre-extraction baseline |
|---|---|---|
| cached prove `-Xmx7g` | proof 53.4 s, self-check PASS, 1.1 min, verify VALID | 55.8 s / 1.1 min |
| no-cache prove `-Xmx8g` | compile 16.5 s, proof 51.9 s, PASS, 1.2 min | ✓ |
| fresh setup `-Xmx8g` | 5.3 min, 10.2 GB sparse bundle | 6.4 min |
| prove from fresh bundle `-Xmx7g` | cache-hit, 1.1 min, PASS, VALID | ✓ |

Unit: `Groth16KeysTest` (3), `Groth16PipelineTest` (5, incl. compile-supplier-never-invoked-on-
cache-hit and fingerprint-format compatibility), ceremony + tools suites green incl. the live
snarkjs mixed-transcript interop test.

## Developer docs

`docs/groth16-dev-guide.md` — decision table (key homes × memory), three worked flows
(in-memory / store / snarkjs import), the pipeline layer, and the expert-seam map. Class javadoc
on `Groth16SetupBLS381`, `Groth16ProverBLS381`, `Groth16PkStore` points new integrations at the
facade. `docs/zeroj-ceremony-review-2026-07-10.md` records the transferable-optimization
backlog for the ceremony tool (contribute flat-limb + batch inversion, `finalize --sparse`,
co-located `r1cs.bin`).
