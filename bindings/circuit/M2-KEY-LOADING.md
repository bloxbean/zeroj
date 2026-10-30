# M2: bounded key loading and Poseidon browser proving

Experimental implementation in draft PR #116, stacked on #92. This follow-up supersedes the
M1 report's Poseidon witness-only limit. **GO for this bounded desktop experiment; RESEARCH
for general browser proving and production deployment.** It does not complete all M2 gates.
No core cryptographic algorithms, key parser, R1CS semantics or security parameters changed.

## What changed

A TypeScript-defined BLS12-381 T3 Poseidon opening now expands through the existing Java gadget,
compiles, checks its witness, imports a supplied ceremony key, and generates/self-verifies a
fresh Groth16 proof in Node, Chromium and Firefox. Proofs are cross-checked with snarkjs 0.7.6
and the JVM. Public-input/witness tampering is rejected. All keys in the demonstration are
explicitly disposable development artifacts, not a production ceremony.

| Property | M1 | M2 compiler profile |
|---|---|---|
| Key transport | One hex JSON request | Sequential 64 KiB chunks |
| Maximum raw key | 262,144 bytes | 2,097,152 bytes |
| Concurrent uploads | No chunk transport | One per compiled circuit |
| Successful key imports | General handle limit | One lifetime import per compiled circuit |
| Wire / FFT-domain limits | 4,096 / 4,096 | Unchanged |
| Coefficient limit | 16,384 | Unchanged |
| Request / JSON string caps | 1 MiB / 512 KiB | Unchanged |
| Selected Poseidon opening | Compile + witness only | Compile + witness + prove + verify |
| SHA-256 abc | Compile + witness only | Unchanged, no proving claim |

The opening has **241 constraints, 1,622 wires, domain 256**, and a **1,090,303-byte key**.
It fits the new transport policy without changing the circuit or cryptographic construction.
The standalone `@zeroj/groth16-prover` still uses its original 256 KiB key cap. The compiler's
one-key policy is deliberate: reuse the loaded key for repeated proofs, or create a new runtime
to change keys. Releasing its handle does not reopen the key slot.

## Security and resource boundaries

The upload reserves one exact-sized binary array only after metadata, circuit identity and
length admission. Chunks use exact offsets; duplicate, gapped, empty, oversized and overflowing
chunks terminate a recognized owned upload. Finish is terminal on success or failure. Hash
verification precedes parsing; the existing importer still validates canonical fields,
curve/subgroup membership, forbidden identity points, dimensions and the circuit relation.
Wrong-subgroup tests replace alpha with the on-curve order-three G1 point (0,2) and recompute
the artifact hash, ensuring subgroup validation—not just the hash check—rejects it.

No alternative zkey parser, subgroup-check bypass, trusted-point cache or new cryptographic
implementation was added. Authenticating a key still requires a hash/VK selected by the trusted
application. An attacker choosing both bytes and the alleged expected hash is not authentication.
A structurally valid mismatched VK may fail only at the inherited proof self-verification step;
that does not resolve production ceremony/key-consistency assurance gates.

`compiled.loadKey(artifact, {signal})` accepts a bounded caller-owned Uint8Array. Each request
encodes only one chunk; Java never assembles a full-key hex string. The original caller array
remains in host memory, and the existing parser still consumes a full binary buffer. This is
chunked transport, not a streaming cryptographic parser or a streaming network downloader.

`keyResources()` reports exact transport reservation/receipt/high-water counters and import
elapsed time. These are **not total heap or retained-key measurements**. On finish/failure,
`reservedBytes` returns to zero; the successfully imported key has its normal parsed arrays/maps.
Garbage-collection timing and return of RSS to the operating system are separate concerns.

Abort before import starts leaves the runtime usable. Abort during transfer/import terminates
**the whole runtime and all its workers/handles**, including a verifier sharing it. This can
interrupt synchronous Java validation; a queued release cannot. Protocol abort between calls,
explicit upload release and circuit disposal drop the staging buffer. Runtime deadlines also
terminate the worker. Malformed requests rejected before ownership can be established do not
cancel some other upload; callers can explicitly abort or dispose the runtime. No erasure claim.

## Measurement methodology

Each timing run uses five fresh workers, then five further proofs reusing the last loaded key.
“Cold” means a fresh worker; filesystem/browser/network/engine caches can be warm. Each fresh
worker separately measures startup, compilation, witness checking, key transport/import, proving
including self-verification, and another verification. The p95 is the nearest-rank maximum of
only five observations, not a reliable production-tail estimate. Key files are loaded before
timing and all browser runs are local, headless desktop tests. No network download time is claimed.

Node RSS is sampled every 10 ms with per-phase maxima. RSS covers the entire Node process,
including worker threads; it is not the Java heap. Sampling can miss peaks, especially during
synchronous host encoding. `process.resourceUsage().maxRSS` adds the OS process high-water mark.
The other `process.memoryUsage` fields refer only to the current thread, so they are not used
as Wasm heap measurements. See the [Node process documentation](https://nodejs.org/api/process.html#processmemoryusage).

A separate JVM JFR run profiles this same adapter/importer/prover path. Allocation samples are
weighted estimates of allocation volume, not retained size or peak heap, and JVM results do
not measure Wasm GC. See [Oracle's JFR guidance](https://docs.oracle.com/en/java/javase/25/troubleshoot/troubleshoot-performance-issues-using-jfr.html).

## Completed checks and measurements (2026-10-30)

`python3 bindings/wasm/circuit-check.py` passed on the final implementation:

- 26 JVM tests: 21 compiler/transport tests, four shared boundary tests and one hash regression.
- 23 Node tests, including digest/parser/subgroup/dimension negatives, invalid Poseidon witness,
  pre-abort, active-transfer/import abort, circuit disposal, deadline and direct-key compatibility.
- Six scenarios in Chromium 156.0.8078.4 and Firefox 157.0, plus cancellation during key import.
  Each proving scenario rejects modified public inputs and accepts the independent snarkjs proof.
- Fresh Node/Chromium/Firefox Poseidon proofs verified on the JVM. Those proofs and a fresh JVM
  proof verified with snarkjs and Wasm; altered commitments were rejected by independent verifiers.
- The affected standalone prover/verifier images were also rebuilt. Their existing Node Groth16
  interoperability test passed, including added checks that the 256 KiB standalone/direct cap
  remains enforced. The full nine-image SDK suite was not rerun.
- Strict TypeScript positive/negative tests, authoring lint, and five SDK tarballs installed
  offline outside the workspace with a new compile/prove/verify/tamper check.

Environment: Apple M4 Max, macOS arm64, Node 22.12.0, GraalVM 25.3.4.1+1.1,
Binaryen 132, TypeScript 5.9.3 and snarkjs 0.7.6. Browsers are the local Playwright
headless builds above; these results do not cover Safari or actual mobile devices.
Five fresh workers and five reused-key proofs per engine, with no simultaneous build/test
workload started by this harness. Values below are **p50 / p95 in milliseconds**.

| Phase | Node | Chromium | Firefox |
|---|---:|---:|---:|
| Worker startup | 212.9 / 236.8 | 153.2 / 156.0 | 241.6 / 262.9 |
| Recipe expansion + validation + compilation | 46.5 / 48.0 | 40.6 / 42.2 | 51.9 / 58.1 |
| Witness generation + constraint check | 3.9 / 4.0 | 3.2 / 3.3 | 4.4 / 4.7 |
| Key transport + validated import | 6887.2 / 6971.3 | 6566.8 / 6633.2 | 11698.8 / 11892.7 |
| Import alone (Java timer) | 6684.3 / 6775.4 | 6444.6 / 6506.4 | 11460.8 / 11683.9 |
| First proof + self-verification | 756.2 / 765.3 | 665.6 / 672.2 | 1296.1 / 1886.4 |
| Separate verification | 246.6 / 249.1 | 232.1 / 236.7 | 426.5 / 678.9 |
| Reused-key proof + self-verification | 752.6 / 760.3 | 652.9 / 663.2 | 1143.5 / 1234.6 |

Key import dominates the first-use latency. Reusing the key avoids repeating this cost; the
prover still checks every witness and self-verifies every proof. File/network download is
excluded. At N=5, p95 is just the slowest observed sample; no SLA or production percentile claim.

For Node, baseline process RSS was **48.0 MiB**. The largest 10 ms sample was
**377.6 MiB** (key-loading phase); the OS process high-water mark
was **380.5 MiB**. No OOM occurred in this workload. No browser heap high-water
number is claimed. This is neither a per-key memory requirement nor a browser memory limit.

The upload buffer's exact high-water reservation was **1,090,303 bytes**, and its reservation
returned to zero after successful import. The caller's original array remains separate. JSON
and hex temporaries scale with a 64 KiB chunk, not the total key. The existing importer wraps
the upload array in a ByteBuffer; it still allocates its usual parsed key/constraint objects.

The separate JVM run used `-Xmx2g` and JFR profile settings with 128-frame capture / 64-frame
export. **2,093 allocation samples** yielded these weighted volume estimates:

| JVM path | Estimated cumulative allocation (MiB) |
|---|---:|
| Key import | 3,712.6 |
| All verification calls, including self-check | 2,385.5 |
| Proving | 247.0 |
| Other / startup | 236.0 |

Within import, approximately **2,259.0 MiB** of weighted
allocation involved G1 subgroup checking and **1,448.1 MiB**
involved G2 subgroup checking. The entire run includes multiple independent verification calls
and one key import/proof, so these rows are not per-proof costs. The dominant sampled classes
were `int[]`, BigInteger and MutableBigInteger. Separate witness/FFT/MSM retained sizes were
not established by this short sampled run. No zero-allocation claim follows for unsampled phases.

Recorded JVM pre-GC heap occupancy reached 1,322.9 MiB; the largest recorded post-GC occupancy
was 102.5 MiB. These are observations at GC events, not exact peak heap or retained-key sizes.
Cumulative allocation can exceed the 2 GiB heap because objects are collected. These JVM
measurements cannot be substituted for Wasm GC measurements. Any future optimization of the
existing subgroup-check arithmetic needs separate core/security review and differential tests;
removing subgroup checks is not an option. No such core change is included here.

Measured image: `circuit-b37339dda96bb3b0b90815bb`. Wasm 13,399,576 raw bytes / 3,607,052 Brotli bytes;
launcher 112,275 raw / 18,503 Brotli bytes. Wasm SHA-256:
`8a729187214a29f83ae6ba430fbd7bb0cf650cfcdcd2e486975aeb4ba64aa259`.
The captured descriptor records dirty implementation base `392dd202` and classpath/build hash
`59cb9c8c2c468a921a65d5076e6169542392cf2d39b83696a8306a90f4349950`;
these identify the measured artifact, not a promise of bit-reproducible compiler output.


## Reproduce

```sh
export JAVA_HOME="$GRAALVM_HOME"
python3 bindings/wasm/circuit-check.py

cd bindings/js
node --experimental-wasm-exnref scripts/circuit-benchmark.mjs
node scripts/circuit-benchmark-browser.mjs
cd ../..
./gradlew -p bindings/wasm :adapter-circuit:circuitInterop \
  -PcircuitJfr=../js/build/circuit-results/poseidon-jvm.jfr
"$JAVA_HOME/bin/jfr" print --json --stack-depth 64 --events jdk.ObjectAllocationSample \
  bindings/js/build/circuit-results/poseidon-jvm.jfr \
  > bindings/js/build/circuit-results/poseidon-jvm-allocations.json
python3 bindings/wasm/summarize-circuit-jfr.py \
  bindings/js/build/circuit-results/poseidon-jvm-allocations.json
```

Use the pinned GraalVM toolchain documented in bindings/README.md. Run benchmarks sequentially,
without simultaneous compilation/test workloads. The focused check regenerates all fixtures and
keys, so run it before benchmarks. Summaries belong in this report; generated keys, raw proof
vectors, JFR data, logs, images and raw benchmark JSON stay ignored. No packages are published.

## Remaining gates and recommendation

- This bounded Poseidon workload is demonstrated, not a general size/memory guarantee. SHA's
  103,259-wire example still exceeds the unchanged prover budgets. Merkle depths and multiple
  Poseidon calls require independent measurement and may exceed the 2 MiB key profile.
- Compile/admission limits remain coarse. Complete hard heap/work accounting, retained key/
  witness/FFT/MSM attribution in Wasm, malicious-input soak tests and real low-memory devices
  remain open. A single benchmark with no OOM does not establish maximum safe circuit size.
- Safari, actual mobile devices, independent review, side-channel assessment, production
  ceremony/artifact provenance, release/distribution review and stable API guarantees remain
  outstanding. The local demo's fixed value/salt is not a private application.
- No Yaci transaction, fee result, validator policy, replay protection, nullifier or private
  state machine has been added in this milestone. Groth16/BLS12-381 is not post-quantum.

Next functional work is fixed arrays and existing Java Poseidon Merkle relations, with per-depth
compile/key/prove measurements before expanding admission. Keep the Java cryptographic and
constraint implementations as the sole source of semantics.
