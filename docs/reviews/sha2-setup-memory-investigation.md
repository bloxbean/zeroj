# SHA-2 setup memory investigation — issue #113

Status: feasibility demonstrated for full 16 KiB SHA-256/SHA-512 at 6/8 GiB heap caps.
Follow-up to PR #112, isolated on its own branch.
The raw-evidence cleanup is already present in PR #112; no raw logs, dumps, keys,
per-run vectors or machine-specific path manifests will be committed here.

## Design and invariants

Risk: R1 assurance/orchestration experiment using the existing R2/R3 APIs governed
by ADR-0033, ADR-0034, ADR-0035 and ADR-0036. Production gadgets, compiler, field,
setup equations, prover equations, key formats and verification policy are unchanged.

All messages are public ascending-byte fixtures. The circuit still constrains every
byte and complete SHA-256/SHA-512 digest, as two/four public 128-bit limbs. Exact
canonical relation fingerprints must match the original document-size measurements.
The experiment keeps the explicit insecure development-setup opt-in and randomized
proofs, and uses native-setup binding rows zero. Imported ceremony keys are outside
this experiment; their binding-row convention must not be changed.

1. Reproduce the original compatibility pipeline's OOM with ordinary exception
   reporting to identify the allocation site. These diagnostic timings do not
   replace the original performance data.
2. Measure controlled retained sets with live class histograms: graph + CSR + boxed
   witness, then release the graph, then the witness, then the CSR. Each snapshot
   requests a full GC and is diagnostic, not a timing benchmark. Shared objects and
   release order affect attribution; do not claim this forces the same JIT liveness
   as the original uninstrumented process.
3. Compile in a helper returning only `Groth16Pipeline.Compiled`. Perform streamed
   sparse setup before generating a witness. Let the compiled heap CSR become
   unreachable afterward. Build/evaluate the witness in a helper, release the graph
   on return, then use `FlatScalars.packConsuming`. Prove through the existing exact
   fingerprint-bound pipeline, which maps constraints after witness generation.
4. Require cache-hit evidence, strict Java proof acceptance, changed-digest and
   canonical negated-A rejection, randomized proof diversity, and independent
   snarkjs verification. Never treat a failed pipeline or an oracle crash as success.

Use fresh sequential JVMs, pure Java, eight visible processors and exact 6/8 GiB
heap caps. Profiled live-set runs are separate from unprofiled feasibility/timing
runs. Preserve original failures. Report setup, witness rebuilding/packing, cache
mapping/validation, proof and verification separately, plus heap and RSS. A heap
cap does not establish a physical-RAM limit. New raw outputs stay under ignored
`build/` or `.benchmark-data/` only.

No new cryptography, weakened relations, unblinded proofs, production ceremony,
constant-time or post-quantum claims. Any core-library optimization would require
its own design review and differential/regression tests before implementation.

## What failed and why

The original [2–16 KiB campaign](sha2-document-scaling-results.md) completed 13 of
16 profiles. SHA-256 at 16 KiB/6 GiB and SHA-512 at 16 KiB/6 and 8 GiB exhausted
Java heap **during development setup**. They did not reach proof generation.
SHA-256 at 16 KiB/8 GiB completed. These results remain valid for that measured
compatibility-API orchestration.

Diagnostic reruns preserved the full public fixture, pure-Java backend, exact heap
caps and eight processors, but removed `ExitOnOutOfMemoryError` to obtain ordinary
exception stacks. All three again reported `OutOfMemoryError: Java heap space`:

| 16 KiB profile | Allocating method | Failed allocation in diagnostic rerun |
|---|---|---|
| SHA-256, 6 GiB | `Groth16SetupBLS381.setupToStore` | `wsM`, third QAP array, source line 400 |
| SHA-512, 6 GiB | Same | `usM`, first QAP array, source line 398 |
| SHA-512, 8 GiB | Same | `wsM`, third QAP array, source line 400 |

The documented `memory.py oom` command was also exercised end to end: all three
expected setup failures reproduced with those same stack locations and effective
heap/CPU controls. Its diagnostic command exited successfully while preserving
all three cases as failed proof pipelines, with zero successful proof samples.

These source locations refer to the unchanged setup implementation inherited from
PR #112. The reruns locate the failing allocation, not every retained object. GC
and JIT liveness can change which particular array allocation finally fails; do not
substitute these diagnostic timings for the original measurements.

The original benchmark retains its `CircuitBuilder` for subsequent witnesses while
setup allocates Lagrange values and three QAP arrays. Its CSR constraints also remain
reachable. The first boxed witness might already be dead to the JIT; its natural
liveness is not established merely by a Java local variable remaining in scope.

### Array payloads, before object headers and transient overhead

These calculations follow the actual dimensions and `long[numWires * 4]` setup
arrays. They are allocation sizes, not predictions of whole-process peak memory.

| Full 16 KiB statement | SHA-256 | SHA-512 |
|---|---:|---:|
| Constraints | 6,934,995 | 8,799,049 |
| Wires | 26,447,846 | 33,477,000 |
| A/B/C terms combined | 41,089,391 | 52,439,483 |
| FFT/QAP domain | 8,388,608 | 16,777,216 |
| Each setup QAP array | 0.788 GiB | 0.998 GiB |
| Three QAP arrays plus Lagrange array | 2.615 GiB | 3.493 GiB |
| Heap CSR matrix payload | 0.384 GiB | 0.489 GiB |
| Packed witness | 0.788 GiB | 0.998 GiB |
| Packed witness plus three proving FFT arrays | 1.538 GiB | 2.498 GiB |

One scalar occupies four 64-bit limbs (32 bytes). CSR payload is
`12 * (rows + 1) + 8 * totalTerms`, excluding coefficient dictionary and headers.
Setup and proving figures are **different phases** and must not all be added into
one supposed simultaneous peak. SHA-512's next power-of-two domain doubles its
Lagrange/FFT allocations relative to SHA-256 here.

## Connection to account derivation

Yes: this is the same family of memory-lifetime problem addressed by
[ADR-0033](../adr/0033-prover-memory-reduction.md),
[ADR-0034](../adr/0034-frontend-memory-reduction.md),
[ADR-0035](../adr/0035-setup-memory-time-reduction.md) and the
[existing pipeline API](../adr/0036-groth16-api-facade-and-pipeline.md).
Those changes already moved keys to mapped sparse stores, flattened field/constraint
storage, streamed setup output, and deferred constraint mapping until after witness
construction. They also used helper-method boundaries to release circuit graphs.

The historical account-ownership result was roughly **90 GB to an 8 GiB Java heap
for development setup**; proving had a separate roughly 70 GB to 8 GiB result,
with 7 GiB on the cached path. The hard physical-memory validation was a **16 GiB
container**, not an 8 GB machine. This SHA investigation does not redo those core
optimizations or inherit that container result automatically.

## Controlled live-set measurements

Both 16 KiB diagnostic processes completed at `-Xmx6g`, with all four snapshots
captured and exact original relation fingerprints preserved. Values below are
**live heap in GiB after full GC**, from `jcmd GC.class_histogram`:

| Hash | Graph + CSR + boxed witness | CSR + boxed witness | CSR only | Released | Graph-release delta |
|---|---:|---:|---:|---:|---:|
| SHA-256 | 3.547 | 1.121 | 0.389 | 0.006 | 2.426 |
| SHA-512 | 4.495 | 1.421 | 0.495 | 0.006 | 3.073 |

The graph-release delta is about **2.43 GiB for SHA-256 and 3.07 GiB for SHA-512**.
Releasing the boxed witness afterward frees another 0.732/0.927 GiB respectively.
The remaining CSR-only live set closely agrees with the calculated matrix payload,
plus a small JVM/harness/input baseline. The graph-containing snapshot is dominated
by `BigInteger`, integer arrays, circuit variables, Add/Term gates and object arrays.

These are controlled-root observations: shared objects are charged to whichever
root keeps them alive, release order matters, and this is not a dominator analysis
or a measurement of the original process's exact JIT liveness. Full-GC timing is
excluded from all pipeline timing claims. In particular, the original graph is
still needed for future witnesses, but the first witness's natural liveness is
uncertain. The experiment directly demonstrates the space recoverable by releasing
that graph while retaining both the constraints and witness.

## Existing-pipeline feasibility

Environment: Apple M4 Max, 128 GiB host RAM, macOS 26.0.1, Java 25.0.2, pure Java,
eight JVM-visible processors. Measurements were taken on 2026-10-29. Each profile
uses a fresh sequential JVM with exact 6 or 8 GiB maximum heap. The production
library sources match PR #112 commit `a1e9e8519ff4c41c80f22dc868036e838f6cb1da`;
this follow-up adds external assurance orchestration only. The runner checks
source, harness and compiled runtime identity before and after each case.

These are public ascending-byte fixtures at a fixed circuit length. The experiment
covers hashing the document bytes; it does not parse a document format or enforce
an application's authorization policy. Other sizes and different data distributions
are outside this bounded feasibility campaign.

All four 16 KiB processes completed setup, two randomized proofs, strict verification,
all changed-digest-limb rejections and canonical negated-A rejection. The complete
canonical relation fingerprints match the original campaign under both heap caps.
Every proof used the validated mapped-cache path; fallback compilation is rejected.

| Hash | Heap cap, GiB | Original compatibility path | Existing pipeline | Setup incl. cache, s | Measured proof, s | Sampled heap peak, GiB | Peak RSS, GiB |
|---|---:|---|---|---:|---:|---:|---:|
| SHA-256 | 6 | Setup OOM | **PASS** | 256.216 | 47.799 | 5.652 | 9.279 |
| SHA-512 | 6 | Setup OOM | **PASS** | 364.933 | 87.838 | 5.971 | 10.768 |
| SHA-256 | 8 | PASS | **PASS** | 264.915 | 48.082 | 6.168 | 10.090 |
| SHA-512 | 8 | Setup OOM | **PASS** | 365.192 | 89.320 | 7.452 | 12.622 |

Each new profile has **one warmup and one measured proof**. These observations
establish feasibility, not stable latency estimates or a general speedup over the
older three-sample medians. Setup is a one-shot insecure development setup, and its
timer includes cache writing/hashing plus its progress callback. Proof timing starts
after witness/cache preparation and includes closing the mapped-constraint arena.
The old compatibility results are preserved; they are not relabeled as successes.

| Profile | Compile + fingerprint, s | Witness build/evaluate, s | Pack, s | Map + validate cache, s | Full prove pipeline, s | Strict verify, s |
|---|---:|---:|---:|---:|---:|---:|
| SHA-256 / 6g | 11.096 | 3.806 | 0.391 | 1.455 | 53.453 | 0.269 |
| SHA-512 / 6g | 13.828 | 4.146 | 0.459 | 2.020 | 94.466 | 0.220 |
| SHA-256 / 8g | 11.331 | 2.376 | 0.489 | 1.506 | 52.455 | 0.266 |
| SHA-512 / 8g | 14.677 | 2.892 | 0.503 | 1.913 | 94.630 | 0.222 |

Witness times include rebuilding its graph, with that graph out of scope before
packing. Full pipeline totals include witness, packing, cache validation, proving,
arena close and progress checkpoints; the separate strict verification is afterward.
Individual witness/packing/proof/verification clocks exclude checkpoint IO. Sampled
heap peaks can miss brief peaks; they are not minimal required heap sizes. RSS is
whole-process peak and explicitly exceeds the requested Java heap caps.

SHA-256's key store is about **2.612 GiB**, plus a **0.384 GiB** constraint cache;
SHA-512's is **3.834 GiB**, plus **0.489 GiB** cache. Cache write/hash took about
1.6–1.7 seconds per profile. Temporary key stores were removed after each case;
proofs/VKs and diagnostic logs remain in ignored local output only.

Independent **snarkjs 0.7.6 passed all 24 checks** for the 16 KiB matrix: eight valid
randomized proofs and 16 invalid cases (every changed digest limb plus negated A).
The final 32-byte control campaign passed another **12 independent checks**. Neither
campaign skipped a failed/incomplete case. The oracle also independently recomputed
the complete message digest/public limbs and checked retained artifact hashes.
The lightweight harness suite has **28 passing tests**.
Two independent agents reviewed the implementation and measurement methodology;
these reviews do not constitute a cryptographic audit. Docsite `npm run check` and
`npm run build` passed: zero Astro errors/warnings/hints, 138 Java blocks checked,
64 HTML pages, 62 Markdown twins and five AI artifacts verified.

## Recommendation

**Adopt the existing memory-conscious pipeline for these large SHA-2 circuits.**
The measured OOM is resolved through orchestration alone at the requested 6/8 GiB
heap caps; no cryptographic-core rewrite, constraint reduction or weaker security
setting was needed. The [working assurance example](../../assurance/sha2-optimization/java/org/zeroj/assurance/sha2/Sha2MemoryInvestigation.java)
shows the compile/setup/witness helper boundaries and cache-hit proving flow.

This is a **GO for the measured 16 KiB heap-feasibility case**, with production and
physical-memory validation still open. It is not an arbitrary-document-size or
small-machine guarantee. Prioritize reused-key prove-only measurements and a hard
RAM/swap cap before investing in a new witness program or setup storage redesign.

## Options and boundaries

| Option | Feasibility and trade-off |
|---|---|
| Use the existing `Groth16Pipeline` with explicit graph/CSR lifetime boundaries | Demonstrated here. Reuses existing setup/prover equations and exact cache validation; costs rebuilding the graph for each witness. |
| Reuse a correctly bound key bundle and constraint cache | Existing supported design. Removes per-request setup/compilation; does not itself remove the witness-generation peak. A production ceremony is still required; development keys cannot be promoted. |
| Compact witness program / smaller circuit graph | Follow-up research if witness construction becomes the next limit. Avoiding the full graph could help, but requires a new design and differential/negative tests; no measured savings claimed. |
| Rework setup QAP storage or partition evaluation | Potential fallback beyond the measured sizes, with substantial core-crypto implementation/testing cost. The current three arrays are used together in key-query construction; simply freeing one early is not a valid fix. No prototype or measured savings here. |
| Raise heap / use another backend | Raising heap is a capacity workaround. Native acceleration is not automatically lower-memory; earlier account tests found native arenas can exceed physical limits. Neither is needed merely to test the existing pure-Java pipeline. |

Recommended next measurements are a separate **reused-key, prove-only process**
with cold/warm cache conditions, followed by a hard container/physical-RAM test.
This campaign's fresh JVM performs setup and then loads the new bundle to prove;
it does not claim to have measured a cold prove-only JVM. A physical-memory test
should disable or explicitly bound swap, record cgroup `memory.peak` and
`memory.events`, and distinguish Java heap OOM from kernel OOM-kill. Mapped keys and
constraints, JVM native memory and filesystem pages can put RSS well above `-Xmx`.

Production ceremony imports are also a separate trust boundary: the existing
streaming importer does not validate ceremony transcripts or establish the
key/R1CS association. Those require independent validation, authenticated source
and manifest hashes, and the correct snarkjs binding rows. This experiment's
native-development binding-row value of zero must not be copied to imported keys.

A future two-QAP-buffer design might stream A/B queries and accumulate the L
numerator with reused storage, but must preserve zero-public-query rejection before
writing key output. Fixed-randomness byte-identical key/VK comparisons and independent
proof checks are prerequisites, not optional optimization checks. No such core
redesign is part of this change.

Born-flat witness generation is not assumed superior: SHA's many
boolean values share boxed `ZERO`/`ONE`, whereas a flat scalar always uses 32 bytes.
Do not introduce new crypto or weaken bit/range constraints to reduce memory.

## Reproduction and security scope

See the [harness instructions](../../assurance/sha2-optimization/README.md#setup-memory-investigation).
Raw logs, profiles, generated proofs and keys are ignored local output; the report,
runner and tests are the reviewable deliverables. PR #112's cleanup removes 862 raw
files from its final tree, leaving the separate curated vector set. Old PR commits
still contain historical dumps; squash merge avoids importing that commit history.

This is orchestration/assurance work, not a cryptographic construction change. It
uses public fixtures, randomized Groth16 proofs, unchanged SHA relations, exact key
and cache binding, strict verification, and explicit insecure development setup.
It establishes neither constant-time execution nor a production trusted setup.
Groth16 is pairing-based and **not post-quantum secure**; this work belongs to the
separate conventional SHA/Groth16 research track.
