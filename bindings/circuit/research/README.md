# Larger Merkle resource experiment

This opt-in experiment follows [M3](../M3-MERKLE.md) and the R2 extension in
[ADR-0064](../../../docs/adr/0064-portable-circuits-and-typescript-frontend.md).
It uses the same Java constraints, key importer and Groth16 prover with a separately selected
resource policy. The normal SDK keeps its 2 MiB / 4,096-wire/domain / 16,384-coefficient policy.

**Research profile:** 32 MiB key, 65,536 wires, 8,192 domain, 262,144 coefficients, 64 public inputs.
These are admission ceilings, not a hard heap bound. The profile does not certify that an arbitrary
relation is a Merkle circuit. Java chooses it at image construction; RPC cannot change it.
Keys remain chunked at 64 KiB with one upload and one successfully imported key per circuit.
All hash, field, point, subgroup, relation, witness and self-verification checks remain active.
The driver explicitly selects a 600-second call deadline; normal runtime defaults are unchanged.

No source or package in this directory is a production ceremony or an anonymous state-machine
protocol. Witnesses are published test data. Browser secrets remain experimental/variable-time
under ADR-0057; Groth16/BLS12-381 are not post-quantum. The local file loaders assume the generated
fixtures are trusted. Production downloads need authenticated manifests and bounded buffering;
a self-declared hash does not authenticate a circuit or key.

## Generate and run

First build the normal fixtures/workspace as in the [circuit guide](../README.md). From repo root:

```sh
export JAVA_HOME="$GRAALVM_HOME"
node bindings/js/scripts/circuit-large-setup.mjs --research-only
python3 bindings/wasm/build.py circuit-large-research
python3 bindings/wasm/package.py --research-output circuit-large-research
```

The setup uses pinned snarkjs 0.7.6, BLS12-381 powers of tau with power 13, fresh development
contributions and the already-exported depth-8/16/32 `.r1cs`/`.wtns` files. It verifies each key
and an independent snarkjs proof. It writes only `bindings/js/build/circuit-large`; the default
manifest/keys remain unchanged. These disposable contributions are not a production ceremony.

The research Java entry point lives in a separate Gradle source set, excluded from the normal
consumer classpath. Packaging refuses this profile without `--research-output`; assets and legal
notices are generated under ignored `build/circuit-large/bundle`, outside the npm workspace.
No research npm package is published or added to the release inventory. Native blst and setup
remain prohibited from the Wasm image by the existing reachability guards.

```sh
# JVM: run each depth (8, 16, 32) with each heap (6g, 8g).
./gradlew -p bindings/wasm :adapter-circuit:largeMerkleBench \
  -PmerkleDepth=8 -PmerkleHeap=6g --max-workers=2 --console=plain
# Optional JFR on a JVM run; path is relative to bindings/wasm:
# -PmerkleJfr=../js/build/circuit-large/merkle_d32/import-prove-6g.jfr

cd bindings/js
node --experimental-wasm-exnref scripts/circuit-large-node.mjs merkle_d8
node scripts/circuit-large-browser.mjs chromium merkle_d8
node scripts/circuit-large-browser.mjs firefox merkle_d8
# Repeat for merkle_d16 and merkle_d32. Each driver uses one fresh worker and 3 reused-key proofs.
node --experimental-wasm-exnref tests/circuit-large-negative.mjs
node scripts/circuit-large-ui.mjs # actual buttons, cancellation/recovery, final-image proof
node scripts/circuit-large-census.mjs

# Interactive local page, with progress and worker cancellation:
python3 scripts/serve.py --port 8791
# http://127.0.0.1:8791/examples/circuit-large/
```

Desktop experiments can take several minutes per import. The page processes a path, not the
full tree: depth 32 does not allocate 2^32 leaves. Closing/cancelling its worker abandons runtime
handles; it does not establish erasure of every immutable JS/Java copy. The page does not upload
inputs. Research assets must be built explicitly; they are never fetched by the normal demo.

After all five engines (Node, Chromium, Firefox, JVM-6g, JVM-8g) have produced all three cases:

```sh
# From repo root:
./gradlew -p bindings/wasm :adapter-circuit:largeMerkleInterop \
  :adapter-circuit:merkleWireCensus --max-workers=2 --console=plain
node --experimental-wasm-exnref bindings/js/scripts/circuit-large-interop.mjs
```

JVM benchmarks generate one first and one reused-key proof per run; JS/browser drivers generate
one first and three reused-key proofs. The UI check uses a fresh runtime after cancellation.

The JVM interop also exercises byte/wire/domain/coefficient limits using an unchanged real key
and tighter importer policies. The Node negatives test normal-policy rejection before allocation,
research length/RPC-policy bounds, truncation, bad digest, oversized dimensions with recomputed
hashes, cleanup and cancellation during actual import. Normal tests still run independently.

All raw vectors, keys, JSON results, screenshots, traces and images stay under ignored `build/`.
The curated [results](../M3-LARGE-MERKLE.md) distinguish timings, heap/RSS scope, measured engines,
security gates and options. This experiment does not change graph or R1CS fingerprints, nor
implement wire compaction or a new on-chain application protocol.


For allocation profiling, export the optional JFR recording and use the existing summarizer:

```sh
# Repo root; exported JSON can be much larger than the binary recording.
jfr print --json --stack-depth 64 --events jdk.ObjectAllocationSample   bindings/js/build/circuit-large/merkle_d32/import-prove-6g.jfr > /tmp/zeroj-merkle-allocations.json
python3 bindings/wasm/summarize-circuit-jfr.py /tmp/zeroj-merkle-allocations.json
```

JFR sample weights estimate cumulative allocation, not live/peak heap. The benchmark's JVM heap
sampler and Node process RSS have separate scopes; no browser peak-memory claim is made. Tests
use ordinary development fixtures; the census scripts are not parsers for hostile input files.
