# M3 larger-Merkle experiment — 2026-10-30

**GO for a separate desktop research profile; RESEARCH for a supported larger browser SDK.**
The existing Java Poseidon Merkle relation can compile, generate witnesses and produce Groth16
proofs at depths 8, 16 and 32 in the measured Node/Chromium/Firefox environments and on the JVM
at both 6 GB and 8 GB heaps. The main obstacle is validating/loading
the proving key, not repeated proof generation. The normal SDK still admits only its previously
measured small keys; no default resource limit was raised.

This extends [M3](M3-MERKLE.md), with the security design in
[ADR-0064](../../docs/adr/0064-portable-circuits-and-typescript-frontend.md) and runnable instructions
in [research/README.md](research/README.md). Core R1CS compilation, witness generation, cryptography
and security parameters are unchanged. These are Groth16/BLS12-381 experiments, **not post-quantum
proofs** and not production readiness evidence.

## What was measured

The path is TS symbolic definition → existing Java `ZkMerkle` / BLS12-381 Poseidon T3 → existing
R1CS compiler → chunked development key import → private path witness → fresh proof → verification.
JVM timing uses the equivalent exported graph; graph and constraint identities match the TS recipe.
The public input is the root; private inputs are a leaf, fixed siblings and boolean directions.
Depth 32 processes 32 path levels, not a materialized tree with 2^32 leaves. This is the existing
raw-field Merkle relation, with no new leaf encoding, domain separator, nullifier or state protocol.

| Depth | Constraints | Wires | FFT domain | Coefficient entries | Raw key bytes |
|---|---:|---:|---:|---:|---:|
| 8 | 1,945 | 11,592 | 2,048 | 52,037 | 8,052,135 |
| 16 | 3,889 | 22,976 | 4,096 | 104,077 | 16,002,823 |
| 32 | 7,777 | 45,744 | 8,192 | 208,157 | 31,904,199 |

The separate `circuit-key-research-merkle-v1` image permits 32 MiB key bytes, 65,536 wires,
8,192 domain entries, 262,144 coefficients and 64 public inputs. The normal `circuit-key-v1`
remains 2 MiB / 4,096 wires / 4,096 domain / 16,384 coefficients / 64 public inputs. Dimensions
are rejected before key staging; actual bytes and coefficients remain checked by the importer.
`withinProverDimensions` is not a guarantee that the eventual key fits every limit. Research
policy is fixed by Java at image construction, retained by circuit state, and cannot be raised
through RPC. It is a resource policy, not a semantic allowlist certifying arbitrary graphs.

The research source set and package output are separate from consumer npm packages. The driver
explicitly uses a 600-second per-call deadline; normal runtime defaults are unchanged. All imports
retain authenticated-digest checks, canonical field/point checks, subgroup checks, relation checks,
public-input order, witness checks and post-proof self-verification. Sequential 64 KiB chunks,
one active upload and one lifetime successfully imported key per circuit remain enforced. The
legacy direct key RPC still has its smaller 256 KiB cap even in the research image.

## Desktop Wasm timings

Seconds, one fresh worker per engine/depth. Key load includes transfer and full import. The first
proof and all three subsequent proofs include witness generation and self-verification; the
reused column is the median of those **three** subsequent samples. Verification is one separate
call. Startup includes instantiation/loading, not a cold internet download.

| Engine | Depth | Startup | Recipe compile | Key load | First proof | Reused proof median | Verify |
|---|---:|---:|---:|---:|---:|---:|---:|
| node | 8 | 0.368 | 0.349 | 65.626 | 3.034 | 2.708 | 0.271 |
| chromium | 8 | 0.201 | 0.156 | 64.495 | 2.608 | 2.775 | 0.278 |
| firefox | 8 | 0.295 | 0.264 | 122.734 | 6.327 | 6.923 | 0.711 |
| node | 16 | 0.283 | 0.313 | 155.922 | 6.178 | 5.504 | 0.333 |
| chromium | 16 | 0.223 | 0.343 | 156.787 | 5.951 | 6.156 | 0.400 |
| firefox | 16 | 0.369 | 0.590 | 324.421 | 10.757 | 10.335 | 0.720 |
| node | 32 | 0.360 | 0.908 | 407.541 | 12.144 | 12.418 | 0.402 |
| chromium | 32 | 0.293 | 0.757 | 352.990 | 9.174 | 9.379 | 0.415 |
| firefox | 32 | 0.373 | 1.228 | 523.097 | 14.092 | 13.907 | 0.623 |

Environment: Apple M4 Max, macOS arm64, Node 22.12.0 with `--experimental-wasm-exnref`, Playwright
Chromium 156.0.8078.4 and Firefox 157.0, pinned GraalVM 25.3.4.1+1.1 / Binaryen 132. Browser runs
are headless desktop tests. Matrices ran concurrently on a shared host, with other work present;
these are feasibility samples, **not isolated engine rankings or p95 estimates**. Larger cases
had different host contention. Do not interpret non-monotonic proof times as algorithmic gains.
Safari, actual phones and constrained desktop devices have not been validated.

The measured matrix image was `circuit-large-research-d38483dd9ed318ad1339914a`, built on base
`219a27b8420bdd50740f5f5caabaf64b8bc1ff41` plus this experiment's uncommitted source. A later
ownership guard reads the profile from circuit state rather than the adapter receiving a call;
it does not change these single-adapter workloads. Final-image smoke/negative checks are recorded
below separately; the timing table is not silently relabeled as a new binary measurement.

## JVM heaps and Node RSS

Each JVM process generated two proofs: first and one reused-key proof. No OOM was observed in any
of the six runs. `-Xmx6g` and `-Xmx8g` were checked through `Runtime.maxMemory()` as 6/8 GiB.
Used heap was sampled every 10 ms; these peaks include uncollected garbage and may miss shorter
spikes. They are neither retained-key size nor total process RSS. No forced-GC retained-size claim
is made. The depth-32/6g run also enabled JFR and carries profiling overhead.

| Depth | Heap cap | Key load (s) | First proof (s) | Reused proof (s) | Sampled used-heap peak (GiB) |
|---|---:|---:|---:|---:|---:|
| 8 | 6g | 50.111 | 1.552 | 1.470 | 1.223 |
| 8 | 8g | 53.144 | 1.694 | 1.545 | 1.223 |
| 16 | 6g | 122.815 | 3.530 | 3.217 | 1.253 |
| 16 | 8g | 157.767 | 4.341 | 3.941 | 1.262 |
| 32 | 6g | 300.696 | 3.525 | 3.215 | 1.404 |
| 32 | 8g | 228.780 | 2.702 | 2.512 | 1.306 |

Per-phase heap samples are recorded for all runs except the initial depth-8/6g run, which has
only a global peak. At depth 32/6g, key-load sampling reached 1.379 GiB and first-proof sampling
1.404 GiB; at depth 32/8g, key loading reached the global 1.306 GiB peak. No inference about a
hard minimum heap follows: smaller JVM caps were not tested here.

| Node depth | OS maximum process RSS (MiB) | Sampled key-load RSS (MiB) |
|---|---:|---:|
| 8 | 418.2 | 414.5 |
| 16 | 435.1 | 431.1 |
| 32 | 627.8 | 623.4 |

Node RSS covers the main process and worker threads, not Java/Wasm managed heap. Sampling and OS
maximum capture stop before the independent snarkjs oracle runs. Browser process-tree peak memory
was not measured; Node RSS is **not** substituted for browser heap. An admission cap is not a hard
memory sandbox or evidence that hostile graphs cannot exhaust a worker.

## Where time and allocation go

The depth-32/6g JFR recording contained 60,887 allocation samples. Their sample weights estimate
**140.743 GiB of cumulative allocation traffic**, not simultaneously live memory. Key import
accounted for 128.078 GiB (91.0%); 99.51% of that import allocation weight had G1/G2 subgroup-check
frames. Integer arrays, `BigInteger`/`MutableBigInteger` and field objects dominated the allocation
classes. This locates temporary allocation pressure; allocation sampling alone is not a CPU-time
profile. The measured key-load wall times independently show the import bottleneck.

Do not omit subgroup checks, accept opaque prevalidated point objects from callers, or replace
secure randomness to improve these numbers. Reusing an already checked key in the same runtime
is the implemented way to avoid repeat import cost. Persistent unchecked object snapshots would
introduce a new trust boundary and are not implemented.

## Key transport and compiler options

Read-only R1CS analysis found 9,637 / 19,069 / 37,933 unreferenced wire columns at depths 8/16/32.
The compiler inlines expressions while retaining original graph numbering. Constant one and all
ordered public inputs must always remain. Matching all-zero entries in generated query sections
corroborate the census; unused columns alone do not establish an under-constrained statement.

A deterministic projection could remove about 4.63 / 9.15 / 18.21 MB of raw query bytes, respectively.
This is an estimate, **not an implemented or verified compacted key**. It changes wire mapping,
fingerprints and setup artifacts, and needs separate core review. It does not reduce coefficient
counts or domain sizes. Zero query entries already avoid expensive nontrivial subgroup work, so
byte savings do not imply proportional import speedup. The concrete follow-up is in
[WIRE-COMPACTION-PLAN.md](WIRE-COMPACTION-PLAN.md).

Compression was measured on the generated local keys (gzip level 9 / Brotli quality 9):

| Depth | Raw bytes | gzip bytes | Brotli bytes |
|---|---:|---:|---:|
| 8 | 8,052,135 | 1,285,834 | 1,020,368 |
| 16 | 16,002,823 | 2,568,578 | 1,998,671 |
| 32 | 31,904,199 | 5,134,820 | 4,243,616 |

This measures network/storage potential only. No new compressed-key loader was implemented.
Parsing still requires the bounded decompressed key and all cryptographic checks. A future
loader must authenticate the artifact, bound compressed and expanded bytes, and cancel safely.

## Validation and limitations

- Default regression checks: **35 adapter JVM tests** (30 circuit, four common, one hash),
  **34 Node compiler tests**, strict TS build and authoring lint. The four new JVM tests cover
  normal-policy early rejection, research allocation bounds/RPC immutability, policy ownership,
  and exact dimension/public-input boundaries. The full nine-image SDK suite was not rerun.
- All **15 engine/depth cases** (Node, Chromium, Firefox, JVM-6g, JVM-8g × 8/16/32) produced fresh
  proofs independently verified by both JVM and snarkjs, with changed-root rejection. Wasm
  drivers also accepted the independent snarkjs proofs and rejected altered private path bits;
  JVM drivers rejected altered siblings before proving. Existing M3 gadget vectors remain the
  independent constraint-assurance baseline; frontend parity alone is insufficient.
- Final image `circuit-large-research-f9e91aa2b031594cd2f378d0` passed normal-policy rejection
  before staging, research length/profile-override limits, incomplete chunks, bad digest,
  oversized wire/domain headers with recomputed hashes, cleanup, and cancellation during actual
  import. JVM importer tests independently reject byte/wire/domain/coefficient ceilings using
  an unchanged valid key and tighter limits.
- The rebuilt research image is **13,433,598 Wasm bytes + 112,275 launcher bytes**, excluding legal
  files. Its actual Chromium page buttons passed cancel → restored controls → fresh depth-8
  compile/import/proof/verify. Lazy loading selected only this image; no external requests or
  page errors occurred. Desktop/390 px screenshots were inspected; width checks are not mobile
  device performance evidence. Its fresh depth-8 smoke import was 55.250 s and first proof
  2.202 s; those separate smoke numbers do not replace the shared-host matrix above.
- Both consumer/research packaging and build selections were checked for isolation. All raw
  proofs, keys, JSON results, screenshots and JFR data remain ignored under `build/`; source,
  reproduction commands and curated results are committed.

Generated keys use pinned snarkjs 0.7.6, BLS12-381 power-13 development setup and fresh local
contributions. Each key and independent snarkjs proof was checked. This is **not a production
ceremony**. Test witnesses are published/generated fixtures, not user secrets; entropy remains
WebCrypto-backed in Wasm, with pure-Java curve implementation and no native blst dependency.
Experimental/variable-time browser secret handling under ADR-0057 is unchanged.

No new on-chain transaction was submitted for depths 8/16/32 in this experiment. The earlier
[M3 local Cardano measurement](M3-MERKLE.md) used depth 1 and its own verification key. Do not
quote that fee as a measured depth-32 application cost. Membership is not anonymity, ownership,
a nullifier or a private state machine; applications still need trusted roots, authorization,
context binding and replay/state-transition rules. No independent audit was performed.

## Recommendation and next work

| Option | Finding | Recommendation |
|---|---|---|
| Existing default SDK | Existing small proofs work; larger keys intentionally reject | Keep current limits |
| Separate larger desktop profile | Useful proofs work with long first import; fixed 600 s deadline and browser differences matter | GO for opt-in research, not supported release |
| Reuse an imported key | Subsequent proofs take seconds without repeating import | Use within the existing runtime lifecycle |
| Compressed key delivery | Measured substantial byte savings; no parsed-memory/import validation savings established | Implement bounded authenticated delivery separately |
| Unused-wire compaction | Concrete zero-column census and significant byte opportunity | RESEARCH through separate core design and differential tests |
| Faster subgroup validation | Import dominates; checks are necessary | Profile existing implementation/reference-backed methods, never skip checks |
| Local JVM proving | All measured cases pass at 6g/8g with shorter observed proof times | Retain local fallback; remote proving exposes witnesses unless separately protected |
| Raise default limits / production release | Device, hostile-input, side-channel, ceremony and independent-review gates remain | Do not promote on benchmark evidence alone |

The next useful optimization is to separate network savings, key-object/validation costs and
compiler-wire overhead, then test each independently. M4 SHA-512/BLAKE2b, richer authoring/lint,
additional Poseidon profiles and private-state protocols remain separate roadmap work. Nothing
in this resource experiment changes proof-system security parameters or creates a PQ guarantee.
