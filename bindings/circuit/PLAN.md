# Circuit compiler and TypeScript SDK implementation plan

Accepted experimental implementation plan, 2026-10-30; maintainer requested a separate stacked PR above #92. **GO for a bounded experimental SDK; RESEARCH for larger browser proving and advanced gadget packs.** This is a plan to promote the tested research, not a declaration that the APIs below are published. Implementation evidence is in the research report at `zeroj-research/browser-circuit-compiler-poc/docs/SYMBOLIC_REPORT.md` (research commit `d425988`).

Sections 1–7 preserve the accepted roadmap; the implementation ledger at the end records current completion and measured limits.

## 1. The architectural decision

Keep **one implementation of circuit semantics and cryptography, in Java**. TypeScript describes intent and input shapes; it does not implement SHA rounds, Poseidon permutations, elliptic-curve arithmetic, range constraints, witness algorithms, MSM or FFT.

```text
Java @ZKCircuit ── generated companion ───────────────┐
                                                    v
TS defineCircuit ── bounded recipe ── Java Zk* ── ConstraintGraph
                                                    |
                                  existing R1CSCompiler / WitnessCalculator
                                                    |
                             existing supplied-key Groth16 prover / verifier
                                                    |
                             existing Cardano codec → application transaction
```

The TS callback runs once during authoring, with symbolic objects and no witness values. It records a batch of commands. Java expands that batch in the worker using its existing symbolic classes and gadgets. Proving supplies actual inputs later. Do not close over a private value and use it as a definition constant or shape: that embeds it in the public recipe. There is no RPC per addition, no evaluation of TS source in Java, and no interpretation of Java annotations in the browser.

Both frontends reach the same graph, but byte identity requires the same operation ordering, declarations and compiler version. Arbitrarily rewritten equivalent expressions need not have the same graph or R1CS fingerprint. A compiler upgrade may require different setup artifacts. Keep recipe identity, expanded graph identity, constraint fingerprint and trusted key identity distinct.

## 2. The developer experience

This example **works in the research prototype**:

```ts
import {defineCircuit, uint} from './symbolic.js';

const ageCheck = defineCircuit({
  name: 'age_check',
  public: {threshold: uint(8)},
  secret: {age: uint(8)},
}, ({public: p, secret: s}) => {
  s.age.gte(p.threshold).assertTrue();
});

const input = ageCheck.encodeInputs({
  public: {threshold: 18n},
  secret: {age: 21n},
});
// Java expands ageCheck.recipe, compiles it and uses input at witness time.
```

The intended promoted API would add a lifecycle such as the following. **These names are proposed, not implemented exports**:

```ts
const compiled = await compiler.compile(ageCheck, {manifest});
const key = await compiled.loadKey(trustedKeyArtifact);
const proof = await compiled.prove(key, {
  public: {threshold: 18n}, secret: {age: 21n},
});
await verifier.verify(trustedVerificationKey, proof);
await compiled.dispose();
```

`manifest` binds the input layout, supported field/gadget profile, compiler version and accepted circuit identity. The key artifact includes the application-trusted key hash and verification key. The application chooses these; a prover cannot authorize its own relation by submitting a matching key and hash.

Prefer bigint, boolean and Uint8Array; typed schemas produce editor completion for public and private inputs. Errors should identify an operation index and public source label, without echoing witness data. Expose `describe()` and a public cost estimate before key loading. Report compiler admission, witness admission and prover admission separately.

Do not offer JS operator overloading: `x + y`, `x === y` and `if(flag)` do not express circuit operations. Use `x.add(y)`, `x.isEqual(y)` and `flag.select(a,b)`. JS objects are truthy; a proxy/coercion hook cannot intercept boolean truthiness. The prototype includes type-aware lint, but `any`, aliases to conversion functions or arbitrary JS can escape it. A supported SDK needs a documented supported-authoring subset and a required lint/build lane; lint is not a security sandbox. Witness-dependent loops and variable circuit shapes are excluded. Fixed host loops may unroll a public, bounded shape. See the [TypeScript truthiness discussion](https://www.typescriptlang.org/docs/handbook/2/narrowing.html#truthiness-narrowing).

## 3. What to reuse and what remains to expose

Source inventory was checked against ZeroJ commit `844a0625282cc87e77f3c85df1c1cbdd4cc86a3a`. All classes in this table already exist in Java. “Next” means binding and validation work, not a new cryptographic construction.

| Surface | Java owner | Research now | Next work |
|---|---|---|---|
| Field | `ZkField`, `ZkContext` | add/sub/mul/div, constants, equality/assertion | stable shape/field metadata, diagnostics, exceptional arithmetic tests |
| Unsigned integer | `ZkUInt` | arithmetic, comparisons, inRange, asField | preserve Java widening/underflow rules; expose useful checked conversions without inventing wraparound arithmetic |
| Boolean | `ZkBool` | logic, assertions, field/uint/bool select | required authoring lint; branch shape checking |
| Bytes | `ZkBytes` | fixed nonempty input, get/equality | byte/bit order contracts; safe array conversions and length policies |
| Bits and arrays | `ZkBits`, `ZkArray` | deferred | fixed shape vectors/matrices, typed indexing, composition and shape limits |
| Input schemas | `ZkCircuitSchema`, metadata/input maps | research descriptors/flattening | authoritative exported Java metadata and exact public-input ordering |
| Poseidon | `ZkPoseidon`, `ZkPoseidonN` | BLS12-381 T3 two-input hash | explicit supported T3/T5/T6 profiles and arities; domain separation policy per application |
| Merkle | `ZkMerkle` | deferred | Poseidon membership/root with fixed-depth field siblings and boolean path directions |
| SHA-2 | `ZkSha256`, `ZkSha512` | SHA-256 one-block expansion/witness | both algorithms, empty/padding boundary/multiblock policy; larger prover admission |
| BLAKE2b | `ZkBlake2b` | deferred | 224/256-bit profiles for Cardano, exact byte encoding |
| HMAC | `ZkHmacSha512` | deferred | explicit key/message lengths and padding boundary coverage |
| Pedersen | `ZkPedersen`, `ZkPedersenCommitment`, `ZkPedersenVector` | deferred | typed Jubjub points, scalar/blinding bounds, subgroup and schema provenance |
| Exponential ElGamal | `ZkElGamal`, public-key/ciphertext types | deferred | encryption and DLEQ relations with context, bounds and checked point types |
| Signature relations | `ZkEdDSAJubjub` | deferred | strict key/subgroup policies, reduction witness and supported hints |
| Cardano derivation | `ZkCip1852` | deferred, not browser-v1 | non-native/hint coverage and resource feasibility; retain JVM proving route |

Do not expose internal `wrap`, arbitrary signal IDs, arbitrary hints or unsafe/trusted constructors as convenience methods. A TS brand is not proof of subgroup membership, authenticated public provenance, or valid circuit ownership. Validate again in Java. A future safe-layer type must be created by the appropriate validating Java operation.

The preferred first useful gadget pack is **BLS12-381 Poseidon + Poseidon Merkle**, followed by **SHA-256/SHA-512**. The former supports application commitments/allowlists with small constraint counts; the latter connects existing document and governance digests. BLAKE2b is the next Cardano-oriented addition. HMAC and elliptic-curve relation packs follow only after their resource and hint prerequisites pass.

## 4. Modules and download behavior

Promote into the existing opt-in bindings workspace; do not make the root Java build require Node/GraalVM.

```text
bindings/wasm/
  adapter-circuit/                 recipe/graph admission, Java symbolic dispatch,
                                   compiled-circuit handles, typed input layout
  adapter-groth16/                 existing prover/importer/verifier, reused
  bundles/                        explicit selected compiler/prover entry points
bindings/js/packages/
  circuit/                        defineCircuit, descriptors, symbolic types,
                                   compile lifecycle and typed inputs
  circuit-gadgets/                 small wrappers/subpath exports, no algorithms
  eslint-plugin-circuit/          type-aware authoring rules
  bundle-circuit-basic/            core symbolic compiler + bounded prover
  bundle-circuit-poseidon/         compiler/prover + selected Poseidon/Merkle
  bundle-circuit-sha2/             compiler/prover + SHA-256/SHA-512
  runtime/, groth16-*/             existing packages
```

Names are proposed `@zeroj/*` npm packages consistent with ADR-0057; publication is a later release step. Begin with one measured compiler/prover image in research, then measure the dedicated profile builds before choosing release defaults. The prototype is not evidence that splitting into three images saves total bytes.

JS wrappers must stay small and inert on import. Loading a host hash wrapper must not fetch a circuit compiler. A circuit hash wrapper requests a constraint gadget; `@zeroj/hash` computes an ordinary digest and cannot substitute for that gadget. WebCrypto only helps ordinary SHA hashing.

**A physical image is one Java heap.** Compiler, selected gadgets and prover must share that image to use their Java objects/handles directly. Separate images cannot share a graph or symbolic point by passing a handle. For an application needing both Poseidon and SHA, build an explicit combined profile or serialize a checked portable artifact and pay its transfer/validation cost. Do not promise dynamic linking or infer that npm tree shaking removes code from a precompiled Wasm file. A verifier-only user can retain the existing small verifier profile.

Use an explicit, versioned operation catalog to generate TS signatures/schema documentation and Java dispatch metadata. Keep Java calls hand-reviewed. No reflective export of every public Java method. CI must fail when a catalog operation has no handler, the selected image lacks a requested gadget, or semantic parity fixtures change unexpectedly.

## 5. Milestones, dependencies and acceptance gates

The day ranges below are rough engineering effort for one developer familiar with ZeroJ, excluding external review and setup ceremonies. They are planning estimates, not delivery commitments; the larger-key path is the main uncertainty.

### M0 — Validate the architecture (complete in research)

Five TS definitions reproduce the annotation-authored graphs and witnesses. The small examples prove in Node/Chromium/Firefox and interoperate with snarkjs. Poseidon and SHA expand through existing Java gadgets. See the report for measured limits and actual proof coverage.

### M1 — Stabilize the authoring and artifact contract (5–8 days)

- Separate stable recipe version, graph version and compiler-policy version. Specify canonical ordering, input flattening, shapes, field profile and commitments to these identities.
- Add the Java circuit adapter and TS circuit package in a **new PR stacked on #92**. Update the relevant ADR scope: ADR-0057's exclusion of arbitrary runtime circuits cannot silently become a supported public feature. Preserve all runtime, entropy and key validation contracts.
- Promote typed lifecycle handles; keep input ownership/session checks on both sides. Add fixed bits/arrays, shape-only circuit parameters and composition within one recorder.
- Convert research lint into supported project tooling; reject dangerous conditions/operators/casts in the declared subset, explain escape hatches as unsupported, and add negative compile/lint fixtures.
- Add operation-source labels, deterministic identity, worker cancellation, and reproducible source maps without witness values.

Exit: all primitive operations have Java/TS/Wasm parity and adverse-input coverage; exact schema/VK binding tests pass; browser/Node examples use only the promoted public API. No non-native or arbitrary hint support is implied.

### M2 — Make selected gadget proving practical (5–10 days; research gate)

This precedes a “Poseidon proofs supported” claim. The measured opening key is **1,090,303 bytes**, despite only 241 constraints. The current 256 KiB key cap, 512 KiB JSON string cap and 1 MiB request cap all matter; raising just one limit cannot solve the path safely. SHA also exceeds the 4,096-wire/domain budgets.

- Reuse `ZkeyImporterBLS381` and its limits/point validation. Add a bounded key-transfer protocol (chunked or transferable binary), expected total size and authenticated hash, exact offsets/order and terminal states. Keep importing only after complete integrity/identity checks. Do not write another zkey parser.
- Measure copies, parsing, key objects, witness arrays, FFT buffers and MSM allocations separately, including during failures and cancellation. A 1 MiB file is not a 1 MiB memory budget.
- Benchmark the current Poseidon relation first. Then consider wire compaction/reuse in the existing compiler as a **separately reviewed core change**, only if profiling justifies it. Compaction affects witness mapping/fingerprints/setup compatibility and needs semantic proof/tests; it is not a TS optimization.
- Enforce measured per-profile limits before expansion/allocation, plus hard work/allocation counters inside graph construction where feasible. Current coarse recipe costs are admission heuristics, not heap containment.
- Exercise max/max+1 inputs, truncated/oversized key streams, invalid points/fields, wrong circuit/VK, replayed chunks, timeout and worker disposal. No weakening of checks to fit performance targets.

Exit: fresh browser Poseidon proofs verify in Wasm, JVM and snarkjs; cold/warm p50/p95, peak-memory methodology and supported device matrix are recorded. If it fails, retain compile/verify and use a local JVM prover for this profile; do not advertise proof-generation support. Remote proving is a distinct trust choice because it reveals the witness unless another established protocol protects it.

### M3 — First Cardano-friendly pack: Poseidon and Merkle (5–8 days after M1; proof gate depends on M2)

- Expose explicit BLS12-381 profiles and `ZkPoseidonN`, then wrap `ZkMerkle` over fixed-size arrays. Enforce root/leaf/path shape and intended public root visibility in the application template.
- Add a private allowlist example with an application-bound statement and documented issuer/root trust. Membership alone is not uniqueness or authorization. Nullifier construction must use a reviewed domain-separated application protocol, not a new ad hoc TS hash formula.
- Benchmark depths 1, 8, 16 and 32 independently: recipe expansion, gates/wires, constraints, key size, witness/proof time and peak memory. A supported hash does not establish a supported depth-32 proof.
- Check leaf/sibling/direction/root tampering, all-zero/all-one paths, ownership and public-input ordering; compare existing Java vectors and host Merkle implementation.

Exit: ship only depths/profiles that meet the documented prover/resource gates. Publish a capability matrix that distinguishes compile, witness, prove and verify.

### M4 — Web2-aligned SHA-2 and Cardano BLAKE2b (5–10 days after M1/M2)

- Wrap `ZkSha256`/`ZkSha512`, followed by `ZkBlake2b`; no port of their algorithms. Preserve current circuit implementations and test vectors.
- Define fixed input length and padding semantics. Cover SHA-256 lengths 0/1/55/56/63/64/65 and SHA-512 0/1/111/112/127/128/129 where the existing Java API supports them. Empty input needs an explicit Java/recipe representation; this prototype rejects zero-length ZkBytes.
- Cross-check official vectors, JDK/WebCrypto host digests, Java annotation graphs, and independent prover interoperability. A host digest match alone does not demonstrate a constrained hash relation; altered message/digest and witness tests are required.
- Start with bounded one-block proving. Extend to 1/2/4/8/16 KiB only under measured resource budgets. The JVM's document-size results do not establish browser feasibility.
- Add a document-preimage example and a selective-disclosure example only with an unambiguous canonical document format/parser. A plain hash preimage proof does not prove a date, signer, JSON property or legal meaning.

Exit: per-length support/timing/memory table, admitted limits, proof tampering tests and an explicit fallback for unsupported sizes. HMAC-SHA512 follows with its existing key-length/padding semantics and separate budgets.

### M5 — Cardano application integration (5–8 days, after at least one useful proving profile)

- Reuse existing Java proof/VK/Cardano encoding and JuLC verifier conventions; do not add a second TS elliptic-curve codec. Independently check byte identity against the existing codec/vector suite.
- Export a typed public-input layout to the application. Bind the intended relation/VK to the validator and the proof's public inputs to the relevant datum/redeemer/transaction context. Test changed input order, wrong root, wrong action/network context and wrong VK.
- Build a Yaci DevKit example with browser-generated proof and a real validator transaction. Record live protocol parameters, script/transaction sizes, execution units and fees. This research task has not measured any new on-chain cost.
- Test consumption/replay and state transitions, not merely `verify(proof) == true`. An application that needs one-time authorization must constrain/check its own nullifier or UTxO transition appropriately.

Exit: browser → proof → Cardano transaction example, valid/invalid end-to-end tests, beginner tutorial and advanced security/resource notes. BLS12-381's Cardano primitive support is described in [CIP-0381](https://cips.cardano.org/cip/CIP-0381); it does not establish costs or safety of a particular application.

### M6 — Advanced selected relations and release hardening (separate estimates)

After M1–M5, add Pedersen, exponential ElGamal and strict signature relation packs in separate measured slices. Preserve subgroup/identity checks, scalar widths, fresh randomness rules, schema bindings and exact public/secret provenance. Existing `fromVerifierCheckedPublic` paths must not be offered as unchecked TS imports. Audit which gadgets require `Gate.HintN`; the research graph codec deliberately rejects it. Define a closed, constrained, versioned hint registry and negative witness tests before admitting such graphs.

Threshold decryption/DKG and confidential-note delivery already have host bindings in PR #92. Reuse those; they are protocols with context/admission/authenticated-channel obligations, not automatically ZK circuit gadgets. Add circuit-backed encryption/decryption-share relations only through the existing Java safe layers. Confidential notes still need balance/range, authorization, nullifiers and ledger state rules; exposing methods does not implement a private state machine.

Keep large CIP-1852/account ownership off the browser-v1 promise. Its prior memory failures are relevant evidence. Support Java-authored artifacts and JVM/local proving without forcing the circuit into a browser budget.

Before supported distribution: independent review, Safari/actual mobile coverage, entropy-failure and side-channel assessment, malicious-recipe fuzzing, lifetime/disposal tests, artifact provenance/licensing, npm scope/version policy and compatibility CI. No audit/constant-time claim follows from parity tests. The generated GraalVM artifact's distribution terms need explicit review. None of these Groth16/Jubjub/BLS-based features is post-quantum.

## 6. Duplication budget and maintenance

New code should be transport schemas, immutable TS recording objects, typed lifecycle, Java dispatch and examples/tests. The prototype has zero new hash/curve equations. Java still determines field reductions, range constraints, width growth, division hints, padding and gadget internals. Avoid duplicating these rules in generated TS validators: TS may reject obvious bad shapes/values early, but Java is authoritative.

Exact graph/fingerprint/witness parity detects frontend drift; existing published vectors and independent prover checks detect additional classes of error. These are complementary: two wrappers invoking the same buggy Java gadget would agree. Retain the upstream gadget assurance suites and provenance.

A useful bounded beta through M5 is roughly **25–44 engineering days**, with M2 potentially extending or stopping browser proving. Advanced EC relations, large account circuits and independent audit are outside that estimate. First ship a small, truthful capability matrix; broaden it only when each gadget has measured compiler, witness and proof evidence.

## 7. Recommended next implementation

Promote the recipe/graph contract and typed frontend in a new stack above #92, then implement the bounded key-transfer/resource work required for the measured Poseidon case. After that, add fixed arrays and Merkle membership before broadening to SHA-512/BLAKE2b. This order delivers a useful Cardano application path while keeping every cryptographic implementation in existing ZeroJ Java code.

## Implementation ledger for this stack

- Base: PR #92 at `844a0625282cc87e77f3c85df1c1cbdd4cc86a3a`.
- Branch: `feat/wasm-circuit-frontend`.
- Tracking PR: [#116](https://github.com/bloxbean/zeroj/pull/116), draft and explicitly based on PR #92’s branch.
- Governing security design: [ADR-0064](../../docs/adr/0064-portable-circuits-and-typescript-frontend.md).
- First bounded milestone: promote graph codec, selected symbolic recipe dispatcher, typed compilation/proving lifecycle and authoring lint; retain the existing proving limits.
- M1 initial slice implemented and validated: canonical graph/recipe contract; Java adapter and build-time artifact exporter; typed TS lifecycle/input conversion; CLI authoring lint; browser/Node examples; isolated local npm package test.
- M1 remains in progress for fixed bits/arrays, generated operation catalog, full lint/build integration, richer diagnostics and shape parameters. Independent review remains a draft-PR gate.
- M2 bounded transport/Poseidon slice is implemented in this stack; validation and remaining profiling/device gates are tracked in [M2-KEY-LOADING.md](M2-KEY-LOADING.md). M3 and the bounded M5 application slice now have measured evidence below; the remaining gates are still planned.
- Do not publish npm packages or merge this stack as part of implementation.

- M1 validation baseline: 21 JVM and 17 Node tests; see [VALIDATION.md](VALIDATION.md).
- M2 validation: 26 JVM and 23 Node tests, six scenarios plus import cancellation in Chromium/Firefox, Poseidon proof cross-verification with JVM/snarkjs, and five SDK tarballs installed offline. Measurements and limitations are in [M2-KEY-LOADING.md](M2-KEY-LOADING.md).
- M2 retains the standalone prover limits and adds the separately bounded compiler key profile. Full heap containment/device gates remain open; the subsequent fixed-array/Merkle slice is documented below.

- M3 bounded slice implemented: recipe v2 fixed field/bool/UInt arrays and static indexing,
  existing Java BLS12-381 T3 Merkle expansion, browser allowlist illustration, Node/browser proofs
  at depths 1/2, and compile/witness measurements at 8/16/32. V1 bytes and all proving limits remain
  unchanged. Depth 2 nearly fills the 2 MiB key cap; larger browser trees remain RESEARCH.
- Bounded M5 application slice implemented: exact Chromium proof submitted on local Yaci with
  pinned root/VK/signer/action; independent Java/remote/Haskell budget equality, four invalid signed
  claims and same-UTxO replay rejection. Membership remains reusable on other deposits. This does
  not complete private-state, anonymous authorization, nullifier or network-context protocol work.
- Current measurements, reproduction and security limits: [M3-MERKLE.md](M3-MERKLE.md).
  Next resource work is profiling larger keys/graphs and evaluating separately reviewed core wire
  compaction, before broadening the browser proving profile. Other Poseidon profiles, SHA-512 and
  BLAKE2b still require their own measured slices. M1 catalog/lint/diagnostic work remains open.


- M3 larger-Merkle resource experiment completed: separate Java-selected 32 MiB / 65,536-wire /
  8,192-domain / 262,144-coefficient policy, excluded from consumer npm packaging. Defaults and
  core cryptography/compiler remain unchanged. Depths 8/16/32 now prove and cross-verify in Node,
  Chromium, Firefox, and JVM at 6g/8g. Import dominates startup; no OOM in the measured matrix.
- [Larger-Merkle report](M3-LARGE-MERKLE.md) records all phase timings, JVM heap/Node RSS scope,
  JFR allocation attribution, negative tests and local browser controls. These are shared-host
  feasibility samples, not stable p95, browser peak-memory or production evidence.
- Read-only wire/query census and compressed-file measurements motivate the
  [separate core compaction proposal](WIRE-COMPACTION-PLAN.md). No compaction, validation shortcut,
  new compressed loader, larger-depth Cardano measurement or default-limit increase is included.
  Remaining M1/M4/M6/device/audit gates still apply; the overall roadmap is not complete.
