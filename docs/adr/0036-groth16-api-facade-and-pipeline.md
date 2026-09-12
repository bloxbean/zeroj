# ADR-0036: Groth16 API facade (`Groth16Keys`) + reusable orchestration (`Groth16Pipeline`) + `zeroj-tools`

- **Status**: accepted + implemented, 2026-07-11. The `zeroj-ceremony` CLI
  artifact boundary is superseded by [ADR-0044](0044-focused-module-surface-and-optional-provider-isolation.md),
  which merged that module into `zeroj-tools` without changing the command name,
  CLI behavior, or any ceremony cryptography.
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
   (git mv) to `org.zeroj.tools.zkey`; deps `zeroj-crypto` +
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

## Amendment 2026-09-05 — relation validation at every setup/prove ingress (issue #46)

- **Risk**: R2 — caller-supplied relation validation at the proof-system boundary. No
  cryptographic algorithm, encoding, transcript, or provider semantics change.
- **Finding** (K3 F4 / consolidated triage C-03): the direct heap and streaming setups and every
  prover path skipped any R1CS term whose wire index was `>= numWires` (`>= witness.length` at
  prove time). Because setup and prover skipped the same terms, the resulting proof *verified*
  against a silently weakened relation. `Groth16Keys.setupInMemory` and the list-based
  `Groth16Keys.prove` reached this behaviour, while `Groth16Pipeline.Compiled`, `R1CSImporter`
  and `R1CSFlatIO` already rejected such wires — semantics were path-dependent. Negative indices
  already failed with an `ArrayIndexOutOfBoundsException`; indices above 2^29 could alias onto a
  valid slot through `wire * 4` overflow in the flat paths.
- **Decision**: one shared check, `R1CSValidation` (`zeroj-api`), invoked once at each public
  ingress before any QAP/FFT/MSM work: `Groth16SetupBLS381.setup` and `setupToStore` (every
  overload), `Groth16ProverBLS381.prove`, `proveWithReaders`, `proveUnblindedWithReaders`
  (removed by ADR-0046 on 2026-09-06; the test fixture now calls `computeH` directly),
  `computeH` (list and CSR) and `computeHFlat`; `Groth16Keys` and `Groth16Pipeline` inherit it.
  Invariants: `numWires >= 1`; `0 <= numPublic < numWires`; every A/B/C wire in
  `[0, numWires)` at setup and `[0, witness.length)` at prove; CSR row offsets monotone and
  covering exactly the stored terms; coefficient indices inside the dictionary. The prover
  additionally requires the witness and H vectors to match the key's A/B1/B2/L/H point counts
  exactly (the MSMs used to run over the minimum of the two), `snarkjsBindingRows` in
  `[0, witness length]`, and an FFT domain that is a power of two holding every evaluated row.
  The inner accumulation/evaluation loops now throw instead of skipping, as defence in depth.
  The legacy BN254 `Groth16Setup`/`Groth16Prover` received the same ingress checks so the
  semantics do not vary by curve.
- **Compatibility**: a valid relation produces byte-identical keys and proofs (the streaming-vs-
  heap and CSR-vs-list differential gates are unchanged). Callers that previously passed a
  malformed relation now receive an `IllegalArgumentException` naming the matrix, row and wire;
  a streaming setup fails before the key-store directory is created.
- **Evidence**: `R1CSValidationTest` (`zeroj-api`) and `Groth16RelationValidationTest`
  (`zeroj-crypto`): A/B/C × {`numWires`, `numWires+1`, 2^30, `Integer.MAX_VALUE`, -1,
  `Integer.MIN_VALUE`} across heap, streaming, facade, pipeline and every prover entry point;
  witness/key dimension mismatches; the `numWires - 1` boundary proving and pairing-verifying;
  the weakened-relation reproducer.
- **Out of scope**: the infinity-IC profile for unused public wires (issue #52) and coefficient
  canonicality (values are reduced mod r by the consumers, as before).

## Amendment 2026-09-06 — no public unblinded prove (issue #50, ADR-0046)

- **Risk**: R3 — the zero-knowledge blinders `(r, s)` and which code may omit them.
- **Change**: `Groth16ProverBLS381.proveUnblindedWithReaders` (public, `r = s = 0`) is removed
  from the expert layer, and the prover keeps no fixed-blinder path. The deterministic proofs
  the differential tests need now come from `Groth16UnblindedTestProver` in the unpublished
  `zeroj-crypto` test fixtures, which calls the public `computeH` and then the package-private
  `proveBlinded` with a single-shot `(0, 0)` blinder source. The 2026-09-05 ingress list
  therefore reads `prove`, `proveWithReaders`, `computeH` (list and CSR), and `computeHFlat`;
  `proveWithHCoeffs` takes a caller-computed `H` and receives only the key-dimension check, as
  before.
- **Guard**: `Groth16ProverApiSurfaceTest` pins the exact public method set of
  `Groth16ProverBLS381`, `Groth16Keys`, `Groth16Pipeline`, and `Groth16Prover`, and the set of
  public proof-returning methods across the `groth16`/`plonk` packages; adding one requires
  updating that allowlist after a blinder-policy review.
- **Facade**: `Groth16Keys` and `Groth16Pipeline` are unchanged; they never exposed an
  unblinded path.

