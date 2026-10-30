# Fixed arrays, browser Merkle proofs and a Cardano claim

2026-10-30 · experimental M3 / bounded M5 slice in stacked PR #116.
**GO for this bounded demonstration; RESEARCH for useful larger browser trees; not production-ready.**
The previous [M2 report](M2-KEY-LOADING.md) remains the historical key-loading baseline.

TypeScript can now describe fixed arrays and call ZeroJ's existing Java Poseidon Merkle gadget.
Depths 1 and 2 generate proofs in Node, Chromium and Firefox. Depths 8, 16 and 32 compile and
check witnesses but exceed the unchanged proving profile. A fresh Chromium depth-1 proof was
verified and used in a confirmed local Cardano claim with root, signer and action checks.
No core compiler, hash implementation, field/curve algorithm, proof equation, key parser or
randomness provider was changed in this milestone.

## How to use it

A Merkle tree combines pairs of values until one public root remains. A member supplies a leaf,
one sibling per level and directions describing whether the current node is on the left or right.
The circuit computes the root and requires it to equal the public root. The proof exposes the
root rather than the leaf/path values. Privacy still depends on the application, witness entropy,
setup and runtime; the published test values here are not private.

```ts
import {defineCircuit, field, bool, array} from '@zeroj/circuit';

const membership = defineCircuit({
  name: 'allowlist_d1',
  public: {root: field()},
  secret: {
    leaf: field(),
    siblings: array(field(), 1),
    pathBits: array(bool(), 1),
  },
}, ({public: p, secret: s, zk}) => {
  zk.gadgets.merkleRootBls12381T3(
    s.leaf, s.siblings, s.pathBits,
  ).assertEqual(p.root);
});

// Use the authenticated graph/fingerprint and key-loading lifecycle in README.md.
// Inputs to compiled.prove(key, ...) then have this shape:
const inputs = {
  public: {root: approvedRoot}, // bigint from the application's trusted tree
  secret: {leaf: 42n, siblings: [100n], pathBits: [true]},
};
```

The fixture root is `Poseidon(100, 42)`. `true` means the current node is **right**;
`false` means it is left. Siblings and directions proceed from leaf to root. For a depth-2
relation both arrays have length 2. Array lengths and the circuit name are public build-time
choices. Changing the definition requires matching authenticated artifacts and potentially a new
setup; it is not a witness-time option. `approvedRoot` above is intentionally application data,
not a magic SDK constant.

The leaf is a field value. This API does not silently hash a document, authenticate an identity,
encode a Cardano credential, add a domain separator or create a nullifier. Choose a reviewed leaf
encoding/commitment protocol when those meanings matter. Fixed-depth root trust prevents simply
presenting a root chosen by the prover. Membership alone does not authorize a payment.

The full [browser examples](../js/examples/circuit/index.html) include an illustration, proof
buttons for depths 1/2, compile-and-witness buttons for 8/16/32, compact results and expandable
artifact/resource details. [Source definitions](../js/examples/circuit/symbolic-examples.ts)
use only the public SDK. From the built `bindings/js` workspace:

```sh
python3 scripts/serve.py --port 8791
# Open http://127.0.0.1:8791/examples/circuit/
node --experimental-wasm-exnref examples/circuit/node.mjs allowlist_d1 merkle_d2
```

No inputs are uploaded by the example page. All fixtures are same-origin, local development
artifacts. Browser compilation invokes the Java R1CS compiler in Wasm; it does not compile Java
source or annotations. Java annotations and TS recipes independently reach the same graph.
Secure proof randomness continues through the WebCrypto-backed adapter; host WebCrypto digest
operations are not replacements for in-circuit Poseidon or SHA constraints.

## Contract and validation

Recipe v2 adds fixed field/bool/UInt arrays (length 1..64), `.length`, static `.get(index)` and one
explicit BLS12-381 T3 Merkle operation at depth 1..32. Existing definitions retain identical v1
bytes, and v1 rejects the new vocabulary. Graph v1 and compiler policy remain unchanged.
The [format](FORMAT.md#recipe-v2-fixed-arrays-and-poseidon-merkle-paths) specifies canonical key
order, input flattening, length/type/index checks, work bounds and ownership rules.

The Merkle wrapper calls `ZkMerkle.computeRootPoseidon` with the existing
`PoseidonParamsBLS12_381T3.INSTANCE`. Boolean directions and UInt array elements use Java's
existing constrained types. No TS hash rounds, selector equations or witness algorithms were
introduced. Native Java authoring and host Poseidon roots are separate oracles for recipe
expansion, although they still share ZeroJ's underlying cryptography. Existing published-vector
Poseidon suites and independent snarkjs checks add evidence beyond wrapper parity.

Validation performed:

- 31 adapter JVM tests: 26 circuit, 4 common, 1 hash. The five new circuit tests cover exact
  graph/fingerprint/full-witness parity at depths 1/2/8/16/32, all-left/all-right/alternating paths,
  annotation-authored allowlist parity, changed root/leaf/sibling/direction, non-boolean bits,
  UInt ranges, public ordering, malformed arrays, false depth claims and v1 compatibility.
- 34 distinct Node compiler tests, including the existing importer/cancellation negatives,
  new TS types/immutable schemas, actual Wasm array indexing, Merkle constraints and proofs.
  The complete 34-test suite passed, including a valid raw-boundary witness check before
  non-boolean rejection. Strict TS and authoring lint also pass.
- All 12 exported R1CS/witness pairs independently checked by snarkjs. Eight development
  keys/proofs fit the profile; no key/setup/proof was attempted for the four out-of-profile
  fixtures (SHA-256 and Merkle depths 8/16/32).
- Eleven scenarios plus import cancellation in both Chromium and Firefox, no external requests,
  lazy image loading, desktop/mobile-width checks. These headless desktop browsers are not
  evidence for Safari or an actual mobile device.
- Node, Chromium and Firefox proofs for Poseidon opening, allowlist depth 1 and Merkle depth 2
  verified on the JVM. Fresh JVM proofs were exported for reciprocal snarkjs/Wasm verification;
  changed public inputs reject. A separate valid proof for an unapproved root verifies under
  the same key before being rejected by the Cardano policy.
- Existing Java gadget assurance: 97 selected Poseidon/gadget tests plus 22 symbolic-type tests,
  all passed. No original gadget behavior was changed.
- Five local SDK tarballs tested by an offline consumer outside the workspace; no npm publication.

The independent reviewer/audit gate remains open. Tests and this self-review do not raise the
security maturity of the Java prover, GraalVM runtime or application protocol.

## Measured circuit and key sizes

| Depth | Constraints | Wires | Graph bytes | Key bytes | Measured support |
|---|---|---|---|---|---|
| 1 | 244 | 1,631 | 44,973 | 1,095,283 | Compile / witness / prove |
| 2 | 487 | 3,054 | 73,702 | 2,089,119 | Compile / witness / prove |
| 8 | 1,945 | 11,592 | 250,022 | Not generated | Compile / witness only |
| 16 | 3,889 | 22,976 | 507,797 | Not generated | Compile / witness only |
| 32 | 7,777 | 45,744 | 1,033,944 | Not generated | Compile / witness only |

The allowlist variant uses the same 244 constraints / 1,631 wires as depth 1, with its own graph name and development key.

Depth 1 is two possible positions; depth 2 is four. Depth 8 could represent 256 positions,
but compiling/checking its witness is **not** browser proof-generation support. Larger rows
have no measured key/proof result: they were stopped by profile admission before setup.
Depth 2's key has only 8,033 bytes of headroom below the 2,097,152-byte cap. Do not generalize
its success to an application with extra constraints, public inputs or leaf hashing.

The selected compiler/prover Wasm image is 13,430,896 raw bytes plus 112,275 launcher bytes in
this build. This is not a new image per Merkle depth. It is still the selected combined compiler/
prover profile; no claim is made that npm tree shaking removes parts of a precompiled image.
Compressed network transfer depends on hosting. The full nine-image workspace was not rebuilt.

## Timings and memory

| Depth | Engine | Key load p50 / p95 (s) | First proof p50 / p95 (s) | Reused proof p50 / p95 (s) | Verify p50 (s) |
|---|---|---|---|---|---|
| 1 | node | 6.79 / 6.88 | 0.75 / 0.75 | 0.72 / 0.73 | 0.24 |
| 1 | chromium | 6.40 / 6.56 | 0.64 / 0.66 | 0.62 / 0.63 | 0.23 |
| 1 | firefox | 10.30 / 10.88 | 1.10 / 1.17 | 1.15 / 1.16 | 0.38 |
| 2 | node | 13.45 / 13.59 | 1.16 / 1.19 | 1.15 / 1.18 | 0.25 |
| 2 | chromium | 12.65 / 12.72 | 0.97 / 1.00 | 0.98 / 0.98 | 0.22 |
| 2 | firefox | 22.13 / 22.55 | 1.77 / 1.79 | 1.77 / 1.79 | 0.46 |

Five fresh-worker runs and five additional proofs reusing the last key, per circuit/engine.
Cold means a new worker; host/file/browser caches can already be warm. Key load includes bounded
transfer, digest and existing parser/point/subgroup/relation checks. Proof times include witness
construction and self-verification. Independent verifier calls are measured separately. The
reported p95 is the largest of just five samples, not an estimate of a population tail latency.
These are local desktop observations on Apple M4 Max, macOS arm64; background host work can
influence them. Node 22.12.0, Chromium 156.0.8078.4, Firefox 157.0; GraalVM 25.3.4.1+1.1,
Binaryen 132, TypeScript 5.9.3, snarkjs 0.7.6. Test fixtures use disposable BLS12-381 setup.

| Depth | Node baseline RSS (MiB) | Sampled peak RSS (MiB) | OS maxRSS (MiB) | Raw staging bytes |
|---|---|---|---|---|
| 1 | 48.8 | 373.5 | 376.8 | 1,095,283 |
| 2 | 48.7 | 389.3 | 389.5 | 2,089,119 |

RSS covers the whole Node process, including JS and Wasm workers, code, parsed keys and GC.
10 ms sampling can miss peaks; OS maxRSS is separately reported. Neither is retained-key size,
a JVM `-Xmx` measurement nor a browser heap bound. The staging counter is exactly the raw upload
allocation and returns to zero after import; it excludes parsed key/graph/FFT/MSM memory.
No comparable new browser peak-memory measurement or 6/8 GB JVM proving claim is made here.
The earlier [M2 allocation investigation](M2-KEY-LOADING.md) explains why subgroup validation
can dominate import work without implying that all sampled allocation is live memory.

| Depth | Expand (ms) | Graph validate (ms) | R1CS compile (ms) | Witness (ms) | Constraint check (ms) |
|---|---|---|---|---|---|
| 8 | 4.73 | 28.25 | 71.07 | 3.45 | 10.30 |
| 16 | 5.91 | 45.66 | 123.24 | 7.02 | 18.98 |
| 32 | 6.92 | 85.50 | 226.51 | 16.26 | 37.37 |

These larger-depth rows are single Node observations from the functional run, not five-sample
benchmarks. Expansion invokes the Java gadget; graph validation is measured separately; compile
is the inner R1CS compilation. Witness calculation and constraint checking are separate phases.
They show execution within the tested profile, not a malicious-input heap-containment guarantee.

## Actual Cardano execution

The [local runner and instructions](../cardano/README.md) consume the exact Chromium proof through
ZeroJ's existing checked `SnarkjsToCardano` codec and `Groth16BLS12381Lib`. A small application
validator pins the approved root, VK, authorized signer and claim action. The signer authorizes
transaction contents; the ledger enforces consumption of the input UTxO. The signer is public,
and membership proofs remain reusable for other deposits under that policy. There is no
nullifier, anonymity or private-state-machine claim.

| Metric | Measured value |
|---|---|
| Compressed proof | 192 bytes |
| Applied script, flat / CBOR | 1,974 / 1,980 bytes |
| Claim transaction | 2,682 bytes |
| CPU steps | 2,058,505,076 |
| Memory units | 163,706 |
| Execution fee | 0.157865 ADA |
| Total claim fee | 0.435698 ADA |
| Separate lock transaction fee | 0.177029 ADA |

Consumed and declared budgets matched in this run. JuLC Java, the remote transaction evaluator
and Haskell `cardano-cli` reported identical execution units. Live local protocol major 11 limits
were 10,000,000,000 CPU steps, 16,500,000 memory units and 16,384 transaction bytes. Prices were
0.0000721 lovelace/step and 0.0577 lovelace/memory unit. These are **local DevKit measurements**;
this run does not establish current mainnet parameters or identical mainnet fees. The runner
uses an isolated commit-pinned JuLC pre20/CCL pre7 profile; core dependencies are unchanged.

Four fully signed invalid submissions rejected with `ValidationTagMismatch`: valid proof for
an unapproved root, wrong action, absent required signer and negated proof A. The valid claim was
submitted and confirmed. A different transaction attempting the same spent UTxO then rejected
with `ConwayMempoolFailure: All inputs are spent`. This tests ledger consumption, not global
one-use membership. A repeated proof on a fresh deposit is deliberately allowed by the policy.

Recorded at `2026-10-30T08:47:15.831950Z`. Confirmed local claim transaction:
`267a16fa9e1630ed87147580eddddbc6e08aadca4a764237312287370ebc2f8e`.
Chromium proof file SHA-256: `43b35c99bd54d16cf98ec021fa12ec9146eec05b2a754b38ed710043dc3a3e80`.
Verification key SHA-256: `343c0937ced214121169435ff6ee7b15cddd8315a1e842e1f3b0d1e162a02790`.
Expanded allowlist graph SHA-256: `cb6da2a97829b7372e044441d51a15e797866784ff7819181883fd111b1f1ae2`.
The raw source/protocol-parameter/transaction evidence is generated by the runner.

## Reproduce and next decisions

```sh
export JAVA_HOME="$GRAALVM_HOME"
python3 bindings/wasm/circuit-check.py
cd bindings/js
node --experimental-wasm-exnref scripts/circuit-benchmark.mjs allowlist_d1
node --experimental-wasm-exnref scripts/circuit-benchmark.mjs merkle_d2
node scripts/circuit-benchmark-browser.mjs allowlist_d1
node scripts/circuit-benchmark-browser.mjs merkle_d2
# Then follow bindings/cardano/README.md from the repository root.
```

Generated keys, vectors, images, screenshots, raw benchmark JSON, transactions and logs stay
ignored. The repository contains source, deterministic fixture generators and this curated report.
Fresh setup/proof randomness changes artifact/transaction hashes on reproduction; graph identities,
constraint counts and admitted limits should remain stable for this source/compiler profile.

The next resource decision is larger Merkle proving. Options, in order:

1. Reuse the loaded key for repeated proofs within the supported profile. This is implemented
   and measured; no point validation is skipped.
2. Profile larger keys/graphs before proposing any new worker budget. Increasing the byte cap
   alone cannot solve the 4,096-wire bound. Retain cancellation and all cryptographic checks.
3. Investigate unused-wire/linear-expression compaction in the **existing Java compiler** only
   through a separate security design and core review. That can affect witness mapping, circuit
   fingerprints and ceremony compatibility. It is a research option, not an implemented result.
4. Keep JVM/local proving as a fallback for larger applications, with browser verification of
   the result. This milestone does not measure a new JVM large-tree proof. Remote proving has
   a separate witness-disclosure trust cost and is not equivalent to local proving.

M1 still needs richer diagnostics/catalog/lint integration and additional type conveniences.
M3 does not yet expose `ZkPoseidonN` or other Poseidon profiles. M4 SHA-512/BLAKE2b and a reviewed
anonymous/nullifier or private-state protocol remain later milestones. No new cryptographic
construction is introduced to bypass these limits. Groth16 and the BLS12-381 pairing verification
used here are **not post-quantum**. Production still requires authenticated ceremony artifacts,
independent security review, runtime/side-channel assessment, device coverage and release review.
