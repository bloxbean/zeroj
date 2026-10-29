# ADR-0057: WebAssembly and native shared-library bindings (GraalVM)

## Status
Accepted for experimental WebAssembly/TypeScript implementation — 2026-10-30, following the
maintainer's explicit direction to implement the modular SDK in PR #92. This accepts the
architecture, not production use, side-channel safety, or permission to publish to npm.
The native C ABI remains a future, separately validated target. The r2 decisions below replace
conflicting r1 packaging, milestone, and distribution proposals; historical measurements remain
identified as such.

This ADR revisits one [ADR-0044](0044-focused-module-surface-and-optional-provider-isolation.md)
disposition. ADR-0044 removed `zeroj-prover-wasm` "unless browser/circom-WASM witness
calculation becomes a committed product goal". Accepting this ADR would make running ZeroJ in
the browser a product goal. It leaves ADR-0044's invariants in force and does not bring back
`zeroj-prover-wasm`, a circom witness runtime.

It does not change [ADR-0018](0018-shared-bls12381-primitives-and-wasm-provider.md) or
[ADR-0019](0019-cfrg-bbs-pure-java-and-wasm-providers.md). Their WASM providers run Rust code
*inside* the JVM as independent oracles. This ADR covers the opposite direction: ZeroJ's own Java
code compiled *to* WebAssembly or to a native library.

## Date
2026-10-13

## Revision history
- **r2 (2026-10-30):** modular Java adapters and TypeScript/npm workspaces; browser and Node
  workers; hashes, Pedersen, BBS, Groth16, exponential ElGamal, threshold decryption/DKG and
  confidential notes. Implementation and milestone reviews stay in PR #92. Main merged at
  `65412c40ed1b6397ecfeb654e7bff547f6ea5b96`. Follow-up research supersedes the monolithic POC.
- **r1 (2026-10-13):** first version, written from the proof of concept described in §Evidence.

## r2 implementation decisions (governing)

### Scope, evidence and limits

The isolated `zeroj-research/zeroj-wasm-poc` study (commit `25a256d`) validated modular
Java-to-Wasm images, WebCrypto entropy, strict verification, browser-made cubic proofs and BBS
presentations, with JVM/snarkjs checks. Chrome and Firefox passed; the local WebKit runner
crashed before loading the application, so Safari is unverified. These are prior research
results, not tests of this PR's eventual artifacts.

Its full account-ownership circuit had 9,951,996 constraints after the existing SHA optimization
(the legacy circuit had 18,757,203). A fresh JVM proof verified in Chrome/Firefox, but Chrome
exhausted memory building the witness graph and Firefox did not finish that graph within 600 s.
No full account-ownership browser proof was generated. The browser SDK supports measured,
bounded workloads; no claim that an arbitrary Java circuit fits a browser follows.

Initial artifacts target the pinned GraalVM 25.3.4.1+1.1 line, with Binaryen 132. The official
Web Image/API guides were rechecked on 2026-10-30. Web Image remains experimental. Its launcher
requires a JavaScript host; these artifacts are not general WASI modules for Python/Go/Rust.

### Repository and package structure

```text
bindings/
  wasm/                       # opt-in Gradle composite build, uses this checkout
    adapter-common/           # bounded wire types, errors, lifecycle, entropy bridge
    adapter-hash/             # ordinary SHA-256/SHA-512/BLAKE2b, explicit Poseidon profile
    adapter-pedersen/          # explicit BLS12-381 and Jubjub profiles
    adapter-bbs/               # explicit ciphersuites
    adapter-groth16/           # strict verify; supplied-key, compiled-circuit proving
    adapter-elgamal/           # exponential ElGamal safe-layer operations
    adapter-threshold/         # DKG state, qualified contexts, verified shares
    adapter-notes/             # confidential-note-jubjub-v1 seal/open
    bundles/                  # explicit entry points; no reflection-based method discovery
  js/                         # private npm workspace root
    packages/
      runtime/                # worker transport and integrity/version checks
      hash/ pedersen/ bbs/ groth16-verifier/ groth16-prover/
      elgamal/ threshold/ confidential-notes/
      bundle-*/               # generated launcher, Wasm, immutable descriptor, notices
    examples/browser/
    examples/node/
    tests/
```

Use the repository Gradle wrapper with `-p bindings/wasm`; the composite substitutes the Java
projects from this same checkout. The root default build/BOM/Maven publication remain unchanged.
Bindings never replace the independent Rust-derived `assurance/*-wasm` oracles. TypeScript
packages use npm workspaces. Proposed public names are `@zeroj/runtime`, `@zeroj/hash`,
`@zeroj/pedersen`, `@zeroj/bbs`, `@zeroj/groth16-verifier`, `@zeroj/groth16-prover`,
`@zeroj/elgamal`, `@zeroj/threshold`, `@zeroj/confidential-notes`, and `@zeroj/bundle-*`.
The organization must control the chosen scope before actual publication.

Java algorithms remain the single implementation. Adapters call existing validating APIs;
ordinary BLAKE2b may receive an additive public facade over its existing implementation, not
a new algorithm. No circuit hash gadget is represented as an ordinary digest API.

### Logical capabilities versus physical images

Wrappers depend on the lightweight runtime, not every image. Applications register immutable
bundle descriptors. One capability can be supplied by a dedicated image or a combined image;
duplicate capability providers are rejected, never chosen implicitly. The runtime shares a
worker by the complete bundle identity, not by API namespace. Each independently compiled
image has its own Java runtime/heap. No Wasm dynamic linking or shared Java heap is claimed.

Profiles include a hash image, crypto combinations (Pedersen/BBS), verifier-only, a
confidential combination (ElGamal/threshold/notes), and explicit compiled-circuit prover images.
Measure raw/gzip/brotli size and cold/warm calls before choosing defaults. A combined image
can avoid duplicated JDK/JCA code. JS tree shaking cannot prune a precompiled Wasm image.
No fetch or worker startup occurs merely from importing a wrapper. WebCrypto may implement
ordinary SHA digests without loading Wasm; callers can explicitly select the Java/Wasm path
for parity and deployments needing it. No fallback to an unreviewed algorithm is permitted.

### Boundary and runtime contract

- Versioned requests select a capability and named operation; exact field sets, nesting,
  request size, collection lengths and scalar ranges are validated in Java.
- Public TS APIs use `Uint8Array` and `bigint`; the first wire format is bounded JSON with
  canonical decimal strings and lowercase hex. No JS `number` for a cryptographic scalar.
  This copies data; it is not a zero-copy ABI. All cryptographic decoders stay in existing Java.
- Stable error codes never include Java stack traces, input values or secret-bearing messages.
- Browser Web Workers and Node worker threads provide the same Promise API. Startup errors,
  deadlines, disposal, concurrent requests and worker failures must settle every pending call.
  A timeout terminates the image and invalidates its state handles. No automatic replay of
  secret operations or implicit runtime restart with stale handles is allowed.
- Opaque, bounded worker-local handles preserve provenance for safe-layer contexts,
  ciphertexts, shares and DKG participants. They are runtime capabilities, not serialized
  cryptographic evidence. Releasing a handle removes references; it cannot guarantee erasure
  of immutable Java/JS values. Raw encoded bytes never automatically regain a verified type.
- A descriptor pins the launcher and Wasm byte lengths/hashes, API version and capabilities.
  Assets are checked before execution. Descriptors and the serving origin are trusted;
  checksums do not protect against replacement of both descriptor and code by that origin.
  Default browser delivery is same-origin and redirect-free; Node loads local package assets.
- Every secret-bearing operation requires an explicit `experimentalSecrets` runtime opt-in,
  checked again by the Java dispatcher. It carries the label **browser/Node Wasm unassessed**.
  This is permission to run experiments, not a claim of cryptographic deployment safety.

### Randomness and native exclusion

Install the WebCrypto provider first, including when entropy is unavailable: in that case it
throws and never leaves the substituted weak provider as a fallback. Probe actual entropy
before secret work. Chunk requests at 65,536 bytes. Node workers use Node's WebCrypto.
The trusted host can still replace its own crypto implementation; no runtime test proves that
a malicious host supplies unpredictable bytes.

Retain D3's defense in depth: core-created RNGs must fail closed in Web Image without the safe
provider. Runtime detection must be validated in the actual image, not assumed from a JVM
property name. Caller-supplied RNG APIs retain their documented trusted-caller obligation;
bindings never accept a caller-supplied RNG. Negative images and absent/throwing/late-failing
entropy tests must demonstrate no weak fallback. Core changes are limited and separately
reviewed; normal JVM behavior stays unchanged.

The binding classpath excludes `zeroj-blst`/`zeroj-crypto-blst`, selects pure-Java providers
explicitly, and builds with reachability guards. This supersedes r1's requirement to modify
all native metadata first. Guard trusted setup/ceremony entry points out of all consumer
images. Any metadata exclusion is narrow, documented and tested; never globally disable
validation or make reflection blindly reachable to obtain a build.

### Expanded cryptographic surface and trust preservation

| Capability | Required semantics |
|---|---|
| Hash | Standard ordinary SHA-256/SHA-512/BLAKE2b; separately named Poseidon field profile |
| Pedersen | Existing profile-specific canonical decoders and hiding/blinding rules; no implicit curve conversion |
| BBS | Existing SHA-256/SHAKE-256 suites; keygen/sign/derive opt-in, verify public; preserve headers and disclosure indexes |
| Groth16 | BLS12-381 strict verifier; trusted VK selected by application; validity is not authorization |
| Exponential ElGamal | `elgamal-jubjub-v1`; same-context sums, established plaintext bounds, explicit bounded decryption search |
| Threshold | `elgamal-jubjub-threshold-v1`; `t` faults means `t+1` shares; qualified identifiers, context/ciphertext binding and duplicate rejection |
| Confidential notes | `confidential-note-jubjub-v1`; distinct readers, fresh per-reader ephemeral secrets, fixed AEAD profile, commitment-checked opening |

Bind to the current ADR-0051/0052/0053/0055/0058/0059/0060/0062 specifications and tests.
The ElGamal and threshold adapters must never create a verified object from a caller's
`verified: true`. Existing proof obligations remain: imported key shares require possession
proofs; imported ciphertexts require the exact encryption/width relation; imported decryption
shares require the exact DLEQ relation. The initial built-in proof bridge uses the existing
Groth16 verifier with public inputs derived from the Java statement and an application-trusted
relation VK. It never trusts public inputs supplied alongside a proof, and introduces no new
Chaum–Pedersen transcript/ciphersuite.

DKG participant APIs retain the Java authenticated-sender/channel contract. The application
must supply authenticated private channels, broadcast agreement, deadlines, and round closure.
Running all participants in a local example is a protocol simulation, not a deployed distributed
trust boundary. Public transcript recomputation does not admit a threshold key context.
External-context admission requires the existing authentication and closure obligations; do
not expose a convenience method that manufactures them. A milestone may explicitly leave a
network transport/admission integration unsupported rather than weaken these checks.

Notes seal/open are delivery primitives, not a complete private ledger: spending authorization,
nullifier/replay checks, balance/range proofs, auditor policy, and on-chain state transitions
remain application responsibilities. None of these elliptic-curve constructions is post-quantum.

### Proving and examples

Keep verifier and prover independently installable/loadable. Proving uses named compiled
circuits and authenticated, validated key artifacts; setup never runs in consumer Wasm.
Small, explicitly development-only examples may carry public development proving parameters,
with fixture provenance and no persisted toxic waste. They are not production setup artifacts.
The supplied-key loader and circuit-template path must document exact formats and bounded
memory, and reject wrong fingerprints, malformed points and mismatched keys. Generic arbitrary
Java class loading, arbitrary R1CS/witness programs and the large ownership prover are excluded.

**Main-code inspection (2026-10-30):** `ZkeyImporterBLS381.importZkeyFull(byte[], byte[])`
already provides a bounded heap importer with an expected SHA-256 and strict field/point
validation. Reuse it for W4 instead of inventing a key format or implementing a second parser.
The r1 G4 claim is stale for zkeys; the mmap store remains unavailable in Web Image. Bind each
named compiled circuit to an application-trusted key hash, exact circuit identity and VK;
passing a hash from the same untrusted source as the key does not authenticate it. Test supplied
key loading and proof generation from these bytes in the actual image. Arbitrary mmap-store
conversion and the native C ABI remain outside this browser/Node milestone.

Examples cover hash parity, a commitment/opening, a BBS credential/presentation, Groth16
prove/verify and tampering, encrypted totals, a threshold round simulation, and notes for an
owner/auditor. Run them in browser and Node with disposable test secrets only. No recovery
phrase field, witness upload, analytics, private-key logs, or hidden remote proving service.

### Distribution and validation

Ship compiled ESM, `.d.ts`, workers, and prebuilt image assets in versioned npm tarballs.
Consumers need no Java/GraalVM compiler. Generated binaries, setup artifacts and raw logs stay
out of Git; curated results and small public fixtures belong in Git. Each release records the
source revision, toolchain, exact wrapper/image compatibility, hashes and third-party notices.
Test `npm pack` outputs as installed dependencies, not only workspace symlinks. Publication
uses a separate protected workflow with npm provenance; implementing packages does not publish
them. Native/Python/Go/Rust distribution remains future work.

Every milestone is implemented, reviewed, tested and corrected in **this same PR #92**, as
requested by the maintainer (supersedes r1's separate-PR instruction):

| Milestone | Exit criteria |
|---|---|
| W0 design | Main merged, r2 architecture/threat model recorded, protocol API inventory |
| W1 foundation | Composite build, adapters, fail-closed entropy and strict boundary tests; native/setup reachability guards |
| W2 SDK | Typed wrappers, lazy bundle mapping, browser/Node workers, lifecycle/error/integrity tests, actual image smoke |
| W3 primitives | Hash/Pedersen/BBS APIs; official/reference vectors, negative and JVM differential checks |
| W4 proofs | Strict verifier, bounded supplied-key proving/circuit example, independent snarkjs checks, key negatives |
| W5 confidential | ElGamal/threshold/notes safe-layer APIs, state/statement tampering tests, reference-vector parity, transport limits |
| W6 delivery | Runnable examples, browser/Node matrix, npm tarball consumer tests, sizes/timings, documentation, final diff review |

The implementation ledger under `bindings/` records actual completion and unresolved gates.
Tests do not establish constant-time behavior, zeroization, external audit, Safari support, or
production readiness. External review of entropy/secret handling and each inherited protocol's
release gates remains required before a production release.

## Risk classification
- **R2:** the decisions as a whole. They add new runtimes and a new distribution of
  cryptographic code. They also add new trust boundaries: the JavaScript↔Java boundary, the C ABI
  and the randomness source. No algorithm, encoding, transcript, proof equation or circuit
  relation changes.
- **R2, security-critical:**
  - D3 (randomness under Web Image). Without it, a Groth16 proof made in the browser leaks
    the witness.
  - D8 (secret-bearing operations in a browser). This falls outside every assurance profile
    ZeroJ has today, so it is escalated (Q1) and needs external review.
- **R1:**
  - D4 (blst isolation in images);
  - D5 (pure-Java encoding of proofs for the Cardano verifier);
  - D6 (loading proving keys from memory).

  These change packaging and APIs, not what is accepted, and each comes with a differential or
  equivalence test.
- **R0:** D9–D12 (circuit packaging, toolchain pinning, ABI conventions, size work).

## Context

### The problem
ZeroJ is Java-only. Today a JavaScript dApp, a wallet, a Python service or a Go indexer that wants
to verify a ZeroJ proof, encode it for the Julc verifier, or prove on the user's device has two
options:
- run a JVM next to it;
- reimplement the crypto (snarkjs covers Groth16 verify and prove for BLS12-381; nothing covers
  ZeroJ's circuits, Poseidon parameters, Pedersen/notes profiles or the Cardano encoding).

Proving on the user's device matters most for ZeroJ's privacy use cases: private allowlist,
age/KYC claims, voting, confidential notes. A server-side prover sees the witness.

### The platform
- **GraalVM Web Image** (`native-image --tool:svm-wasm`) compiles a closed-world Java application
  to WebAssembly (WasmGC) plus a JavaScript launcher.
- **GraalVM Native Image** (`native-image --shared`) compiles it to a shared library with a C ABI
  (`@CEntryPoint`).

Both use the same reachability analysis and the same `META-INF/native-image` metadata.

### Prior art in this organisation
- **JuLC playground engine** (Julc ADR-054, ADR-057): JuLC compiler and VM in WebAssembly.
  - Pins the GraalVM 25.3 release line.
  - Uses the `@JS` helper bootstrap.
  - Ships content-addressed bundles.
  - Substitutes BLS12-381 builtins away because they need native blst. ZeroJ's pure-Java BLS12-381
    could fill that gap.
- **mesmo-wasm**: a Cardano Client Lib facade in WebAssembly. It is where the `SecureRandom`
  substitution was first found and worked around with WebCrypto.
- **Mesmo**: CCL as a native shared library, with Python, Go, Rust and JS wrappers. It is the
  model for D11.

## Evidence (proof of concept r1, 2026-10-13)

### Setup
- **Code:** a standalone Gradle project built from the **released `org.zeroj:*:0.1.0-pre13` jars,
  unchanged**.
  - One facade, `call(method, json) → json`.
  - Three bridges:
    - an `@JS` bootstrap for WebAssembly;
    - `@CEntryPoint zeroj_call` / `zeroj_free` for the native library;
    - a JVM entry point for reference runs.
- **Toolchain:** Oracle GraalVM `25.3.4.1` (`GRAALVM_VERSION` in `<home>/release`), Binaryen
  `wasm-opt` 132.
- **Machine:** macOS 26, Apple Silicon (16 cores).
- **Runtimes:**
  - Node 22.12 with `--experimental-wasm-exnref`;
  - Chrome 155 (headless, Playwright);
  - Python 3.13 ctypes;
  - Bun 1.2.7 `bun:ffi`;
  - snarkjs (global install).

The POC lives outside this repository (Q6).

### What ran

| Capability | JVM | WASM (Node) | WASM (Chrome) | Native lib |
|---|---|---|---|---|
| Circuit compile (annotation circuits) and witness | ✅ | ✅ | ✅ | ✅ |
| Groth16 dev setup, prove, verify (pure Java), tamper rejection | ✅ | ✅ | ✅ | ✅ |
| Poseidon BLS12-381 t=3, Pedersen commit (`pedersen-jubjub-v1`) | ✅ | ✅ byte-identical | ✅ Poseidon only, identical | ✅ byte-identical |
| BBS keygen, sign, verify, derive, verify presentation | ✅ | ✅ | ✅ | ✅ |
| Confidential notes seal/open (JCA X25519, ChaCha20-Poly1305) | ✅ | ✅ | not run | ✅ |
| EdDSA-Jubjub sign/verify | ✅ | ✅ | not run | ✅ |
| Proving-key store (`Groth16Keys.setupToStore` / `load`) | ✅ | ❌ G4 | ❌ G4 | ✅ |
| Cardano compressed proof bytes | blst | ✅ pure Java (D5) | not run | ✅ |

### Interoperability and differential checks
- **Cross-runtime proofs:** a proof made in each runtime (JVM, wasm, native) verifies in the
  other two and in **snarkjs** (`snarkjs groth16 verify` → `OK!`). A changed public input is
  rejected with "Groth16 BLS12-381 pairing check failed".
- **Cardano encoding:** for two proofs, `SnarkjsToCardano.parseProof` (blst, JVM) and the
  pure-Java `Bls12381Codecs.g1ToCompressed` / `g2ToCompressed` path (wasm) produce identical
  `piA`, `piB` and `piC` bytes.
- **Randomness:**
  - With `crypto.getRandomValues` patched to a constant filler, two consecutive dev setups and
    proofs are byte-identical; with real WebCrypto they differ, and all four verify. So every
    random byte the setup and the prover consume came from WebCrypto (D3).
  - `javap -c` on this GraalVM's `svm-wasm.jar` shows
    `Target_sun_security_NativePRNG_Web.engineNextBytes` calling `WebImageUtil.random()`, the
    JavaScript `Math.random()` (G1).

### Performance
Values are milliseconds, from the third run in one process unless noted. The "allowlist" rows use
the docsite private-allowlist circuit.

| Operation | JVM, 16 cores | JVM, 1 core | Native lib | WASM, Node | WASM, Chrome (first run) |
|---|---|---|---|---|---|
| Groth16 verify (pure Java) | 182 | 176 | 213 | 259–280 | 240 |
| Allowlist depth 10 (2,930 constraints): prove | 1,704 | 1,682 | 1,432 | 3,639 | 2,968 |
| Allowlist depth 10: dev setup | 448 | 1,793 | 294 | 7,031 | 7,399 |
| Allowlist depth 20 (5,370 constraints): prove | 2,137 | 2,137 | not run | 4,649 | not run |
| BBS sign / verify | 215 / 370 | 208 / 364 | 257 / 448 | 276 / 495 | 261 / 466 |
| Poseidon (per hash) | 0.13 | not run | 0.14 | 0.18 | not run |

- In wasm, the engine is ready about 160 ms after the launcher loads (Node), or 273 ms (Chrome,
  localhost).
- Wasm reports one CPU, and `ForkJoinPool.commonPool` parallelism is 1.
- **Sizes:**
  - Full facade: 13.4 MiB WebAssembly module (4.9 MiB gzip -9), plus a 110 KiB launcher.
  - Verifier-only image: 12.7 MiB (4.6 MiB gzip). ZeroJ code is not what drives the size: the
    JDK JCA framework, Jackson data binding, regex and class metadata are (about 5,000 reachable
    types).
  - `libzeroj.dylib`: 23.3 MiB.
- **Proving-key bundle** (sparse store): about 520 bytes per constraint, so 1.5 MB at depth 10
  and 2.9 MB at depth 20. This is what a browser prover would download.

### Gaps found

| ID | Gap | Where |
|---|---|---|
| G1 | Web Image 25.3 substitutes `NativePRNG` and `NativeSeedGenerator` with `Math.random()`. `new SecureRandom()` returns that generator, still labelled `NativePRNG`. ZeroJ constructs `new SecureRandom()` in 12 classes (15 occurrences), including `Groth16ProverBLS381` (the blinders `r`, `s`), `Groth16SetupBLS381`, `PlonKProverBLS381`, `PowersOfTauBLS381`, `BbsService`, `EdDSAJubjub` and `DkgShareDelivery`. | Web Image, ZeroJ call sites |
| G2 | `zeroj-verifier-groth16` has an `implementation` dependency on `zeroj-blst`. The `zeroj-blst` jar's `reflect-config.json` registers `BlstBls12381Provider` and `BlstPairing` **without conditions**, so every image that has the jar on its class path makes blst reachable (JNI `blstJNI`, the FFM binding, bundled `libblst` resources). A wasm build with `-H:AbortOnTypeReachable=supranational.blst.*` fails on that trace alone. | `zeroj-blst` metadata |
| G3 | `ProverToCardano.g1Compress` / `g2Compress` and `SnarkjsToCardano.g1Compress` / `g2Compress` (`zeroj-onchain-julc`) compress points through `supranational.blst.P1_Affine` / `P2_Affine`, so the encoding for the Julc verifier cannot run in wasm. | `zeroj-onchain-julc` |
| G4 | `Groth16PkStore.load` maps key files with `FileChannel.map(..., Arena)` (`MmapG1File.map`). The in-memory file system of Web Image does not support it: the call fails with `UnsupportedOperationException`. There is no way to load a proving key (or import a zkey) from bytes in memory. | `zeroj-crypto` |
| G5 | Wasm is single-threaded. Proving is about 2.2× slower than one JVM core; dev setup is about 4× slower than one core and about 15× slower than 16 cores. | Platform |

## Threat model and trust assumptions

### Assets and secrets
- **Secret:**
  - the witness (every `@Secret` input);
  - the Groth16 blinders `r`, `s`;
  - Pedersen, ElGamal and notes blindings;
  - EdDSA-Jubjub, ElGamal, viewing and BBS secret keys;
  - the dev-setup toxic waste `τ`.
- **Public:** verification keys, proofs, public inputs, commitments, ciphertexts, signatures and
  presentations.

### Actors
1. **Untrusted inputs.** Proofs, keys, public inputs and encodings handed to a binding come from
   anyone. The binding must give them exactly the validation the JVM API gives.
2. **The host.** The web origin that serves the bundle, or the process that loads the native
   library, fully controls the binding. It can read every secret and replace the bundle. **It
   is trusted, as a JVM application that embeds ZeroJ is trusted.**
3. **Co-resident content in a browser:** other scripts on the page, other tabs and origins,
   extensions. They may observe timing, cache behaviour, scheduling and memory pressure.
   [ADR-0039](0039-jubjub-online-and-offline-readiness.md) §3.1, the only profile ZeroJ's
   `BigInteger` secret paths have, **requires that no untrusted "browser content" is
   co-resident**. A browser deployment therefore does not satisfy any current assurance profile.
4. **Supply chain.** A CDN or mirror serving a modified `.wasm`/`.js` pair. A browser runs what
   it is served.

### Trust boundaries
- The **JS ↔ Java boundary** (strings, numbers, bytes) and the **C ABI** (`char*`, lengths,
  handles): every value crossing them is untrusted input.
- The **randomness source**: under Web Image, the JCA default is not a CSPRNG (G1).
- The **bundle**: the launcher and the module are versioned and checked as a pair.

### Out of scope
- A malicious host.
- A compromised browser or OS.
- Physical attacks.
- Network transport.

Verifying a proof is not authorization. Binding a proof to an application context (replay,
nullifiers, `ScriptContext`) stays the application's job, as in every ZeroJ runtime.

## Pinned normative references
- **[WEBIMAGE]** GraalVM Web Image reference manual,
  https://www.graalvm.org/latest/reference-manual/web-image/, fetched 2026-10-13. It says:
  - "experimental technology and under active development";
  - "Requires Oracle GraalVM 25.1 or later";
  - build with `native-image --tool:svm-wasm` as the first argument;
  - the output "uses WebAssembly 3.0 features: Garbage Collection, Exception Handling, and Typed
    Function References";
  - Node needs `--experimental-wasm-exnref` before version 25;
  - `file://` loading does not work;
  - standalone runtimes (e.g. `wasmtime`) are not supported.
- **[WEBIMAGE-API]** Web Image API guide,
  https://www.graalvm.org/dev/reference-manual/web-image/api-guide/, fetched 2026-10-13 (the page
  carries no version label). It says:
  - "`@JS.Export` is not implemented yet";
  - "subclasses of `JSObject` are not supported yet";
  - it recommends the helper-based `@JS` pattern.

  The guide does not cover threads, `SecureRandom`, the file system or JNI. **G1 and G4 are
  therefore established by measurement** (§Evidence), not by the documentation.
- **[WEBCRYPTO]** W3C, *Web Cryptography Level 2*, First Public Working Draft, 22 April 2025,
  https://www.w3.org/TR/WebCryptoAPI/, §10.1.1 "The getRandomValues method":
  - step 3: "If byteLength is greater than 65536, throw a QuotaExceededError and terminate the
    algorithm";
  - step 5: "Fill bytes with cryptographically secure random bytes."
- **[NI-CAPI]** GraalVM Native Image C API (`org.graalvm.nativeimage.c.function.CEntryPoint`,
  `graal_create_isolate`). The POC used it with `org.graalvm.sdk:nativeimage:25.3.4.1`, and the
  build generated `libzeroj.h` / `graal_isolate.h`. **Its documentation was not fetched for this
  revision (unverified as a reference).** The behaviour relied on here is limited to what the POC
  exercised.
- **ZeroJ ADRs:**
  - ADR-0039 §3.1 (compatibility/offline profile);
  - ADR-0044 invariants 6, 7, 8, 10 and 12;
  - ADR-0045 (Groth16 infinity-IC profile and public-wire binding);
  - ADR-0047 (snarkjs interop);
  - ADR-0055 D9 (secret handling on the host).
- **Julc ADRs** (organisation prior art, in the Julc repository): ADR-054 (playground WebAssembly
  engine) and ADR-057 (julc-wasm distribution).

## Decision

### D1 — Two opt-in binding modules, outside the default build (R2)
- **New projects:**
  - `zeroj-wasm` (Web Image);
  - `zeroj-native` (`native-image --shared`).
- **Opt-in:** they are included only with `-PincludeBindings`, like `-PincludeAssurance`.
- **No new toolchain for the default build:** `./gradlew build` needs no GraalVM, Binaryen or
  Node (ADR-0044 invariant 6).
- **Isolation:** the bindings are not in `zeroj-bom-core`. Nothing in the product surface depends
  on them, and no pure-Java module gains a WASM or native dependency.
- **Release artifacts:** a versioned bundle (launcher, module, manifest, `SHA256SUMS`) and
  per-platform libraries. They are not Maven jars. The channels are decided in Q2.
- **Alternatives:**
  - *Bindings in a separate repository* (the Mesmo model): see Q5.
  - *Build the bindings in the default build:* rejected, because it would force the toolchain
    on every contributor and on CI.

### D2 — One transport-neutral facade, the same on every target (R2)
- **Shared facade:** a single Java facade, `ZerojBindings`, is shared by both modules. Its JSON
  and bytes contract has versioned method names. Results are `{ok, value}` or
  `{ok:false, error:{code, message}}`. No Java exception, partial result or Java object crosses
  the boundary.
- **Validation:** the facade calls **only the existing validating ZeroJ APIs** (for example
  `SnarkjsJsonCodec`, `Groth16BLS12381PureJavaVerifier`, `Bls12381Codecs` with validation,
  `BbsService`). It adds **no crypto-encoding parser of its own**.
- **JS bridge:** the `@JS` helper bootstrap installs `globalThis.zeroj` ([WEBIMAGE-API]). An ES
  module wrapper runs the engine in a Web Worker and exposes `Uint8Array` and `bigint`.
- **C bridge:** `@CEntryPoint`, specified in D11.
- **Parity:** one set of parity fixtures runs on the JVM, in wasm and in the native library. Any
  difference fails the build (I1).

### D3 — Randomness under Web Image (R2, security-critical)
1. **Install WebCrypto.** Before any ZeroJ call, the wasm binding installs a JCA provider at
   position 1. Its `SecureRandomSpi` reads `crypto.getRandomValues` ([WEBCRYPTO] §10.1.1) in
   chunks of at most 65,536 bytes.
   - `new SecureRandom()` then resolves to it, which covers every G1 site without changing its
     signature.
   - `engineSetSeed` is ignored: output never depends on caller seeds.
2. **Fail closed in ZeroJ.** ZeroJ core gains a check, run before it generates any secret,
   blinder or key:
   - when the runtime is Web Image, and
   - the `SecureRandom` it is about to use comes from the substituted `NativePRNG` or
     `NativeSeedGenerator`,

   the operation throws instead of proceeding. How the runtime is detected (for example
   `os.name` = `Browser`, `java.vm.name` = `Substrate VM`, or a binding-set marker) is settled in
   M1, with a negative test that builds an image *without* the provider and shows prove and
   keygen refusing.
3. **No silent fallback.** If WebCrypto is unavailable, the binding does not install a
   substitute. Verify-only methods keep working; methods that need randomness fail with
   `RANDOMNESS_UNAVAILABLE`.

**Alternatives:**
- *Pass an explicit `SecureRandom` through every API:* this is the cleaner end state, but it
  changes the APIs of all 12 classes. Deferred; D3.2 keeps the binding safe meanwhile.
- *Trust the binding alone, without a ZeroJ check:* rejected, because any other Web Image
  embedder of ZeroJ would silently get `Math.random()` blinders.

The native library needs no change: Substrate VM uses the OS `NativePRNG` there (POC:
`SecureRandom` reports `NativePRNG`/`SUN`, and the output differs per process).

### D4 — blst never reachable in a binding image (R1)
- **Make the metadata conditional.** `zeroj-blst`'s two reflection entries become conditional
  (`"condition": {"typeReached": ...}` on the blst entry points). Its library resources are
  registered only when the blst provider is reachable. This keeps ADR-0044's module layout and
  its invariant 7: classpath presence alone does not change, or here even link, a provider.
- **Guard every binding image.** Images build with `-H:AbortOnTypeReachable` for
  `supranational.blst.*` and `org.zeroj.blst.*`. A future reachability path fails the build
  instead of shipping JNI code that can never run.
- **Alternative:** turn `zeroj-verifier-groth16`'s dependency on `zeroj-blst` into an optional or
  separate artifact. This is a coordinate change; see Q4.
- **Until D4 lands,** the binding builds remove the two blst jars from the image class path, as
  the POC did.

### D5 — Pure-Java point compression for the Cardano encoding (R1)
- **Change:** `ProverToCardano` and `SnarkjsToCardano` compress through `Bls12381Codecs`
  (`g1ToCompressed` / `g2ToCompressed`, after `g1FromUncompressed` / `g2FromUncompressed`, which
  validate) instead of `P1_Affine` / `P2_Affine`.
- **Output:** the bytes must stay identical. That keeps the on-chain verifier's inputs and the
  script hash unchanged.
- **Validation differences:** `Bls12381Codecs.g*FromUncompressed` applies `requireValid`. Before
  the switch, M0 must record which malformed points (off-curve, off-subgroup, non-canonical,
  infinity) the current blst path accepts or rejects. Any input the two paths treat differently
  is listed in the PR and covered by negative vectors.
- **Oracle:** blst stays in the tests as the differential oracle (I1). It is not removed.

### D6 — Loading proving keys from memory (R1)
- **New API.** An additive API loads a Groth16 key bundle, and imports a snarkjs zkey, **from
  bytes** (`byte[]`/`ByteBuffer`/`InputStream`) into heap readers. Example name, not final:
  `Groth16Keys.load(KeyBundleSource)`.
- **Same validation as the file-based path.** It applies the same checks as `Groth16PkStore.load`
  and `ZkeyPkStoreImporter`:
  - the manifest SHA-256 (`Groth16StoreIntegrity`);
  - dense/sparse format detection;
  - the circuit fingerprint;
  - point validation.

  A bundle accepted by one path is accepted by the other, and rejected bundles are rejected the
  same way (I6).
- **File-based path unchanged:** it stays the large-circuit route (ADR-0033/0035).
- **Reason:** without D6, a browser can only prove with a key it generated itself. That means a
  dev setup in the user's tab, which must never ship (I8).

### D7 — What is exported, in tiers (R2)
- **Tier 1 (no secrets).** Groth16 BLS12-381 verify (snarkjs JSON), the Cardano proof and VK
  encoding (D5), Poseidon and Merkle path helpers, Pedersen commit and verify for public openings,
  BBS signature and presentation verify, public-input encoding.
  - Ships first: it needs D2, D4 and D5 only.
- **Tier 2 (handles secrets).** Groth16 prove with a supplied key, witness generation for bundled
  circuits, BBS derive presentation, EdDSA-Jubjub signing, notes seal/open, ElGamal encrypt and
  decrypt.
  - Gated on D3, D6 and D8, and on Q1.
- **Tier 3 (never in wasm).** Trusted setup, including dev setup outside tests; ceremony tooling
  and the zkey contributor; blst acceleration; RocksDB-backed MPF/JMT; very large proving.
  - These belong in the native library or the native `zeroj-tools` CLI.
- **Not yet run in any binding:** PlonK proving and verification (`zeroj-crypto`,
  `zeroj-verifier-plonk`), ElGamal, DKG, and MPF/JMT. Code inspection suggests they are
  portable. Each is admitted to a tier only with parity fixtures (I1).

### D8 — Secret-bearing operations in a browser (R2, escalated; Q1)
- **Lean:** Tier 2 is offered in the browser only under a new, explicit label, "browser
  (unassessed)". It is documented as **outside ADR-0039 §3.1**, because co-resident browser
  content is present. It makes no constant-time or side-channel claim: the code runs in a JS
  engine's JIT and garbage collector, and nothing shows the `Ct*` or blinded-schedule properties
  carry over.
- **Isolation:** Tier 2 runs in a dedicated Web Worker. Secrets never pass through
  `globalThis.zeroj` on the page's main thread.
- **Maturity:** no maturity label is raised by this ADR (ADR-0044 invariant 10).
- **The case for doing it at all:** for client-side proving the alternative is worse. A server
  prover sees the whole witness.

### D9 — Circuits are compiled into a bundle (R0)
- **The constraint.** Images are closed-world: a bundle contains exactly the circuits compiled
  into it, with no runtime class loading.
- **Generic bundle:** Tier 1, plus Tier 2 for circuits ZeroJ ships, if any.
- **Application bundle:** a Gradle task or template builds the app's `@ZKCircuit` classes plus
  ZeroJ into its own wasm bundle and/or native library.
- **Out of scope:** a circuit-agnostic prover (serialized R1CS plus a Java-free witness format)
  needs its own ADR (Q7).

### D10 — Toolchain pinning (R0)
- **GraalVM:** the build reads `GRAALVM_VERSION` from `<GRAALVM_HOME>/release` and refuses any
  release line other than the pinned one (25.3 at r1) unless it is overridden. This is the Julc
  ADR-057 pattern, because `native-image --version` reports the JDK version, not the GraalVM
  line.
- **Binaryen:** at least 119 ([WEBIMAGE]); the POC used 132.
- **Node:** 25 or later, or 22–24 with `--experimental-wasm-exnref`.
- **Browsers:** they need WasmGC and exception handling. Chrome is the only browser tested
  (§Evidence); Firefox and Safari are M2 gates.
- **Newer GraalVM:** the GraalVM documentation lists a 25.4 Innovation line. Moving to it is Q3.

### D11 — C ABI conventions for the native library (R2)
- **Isolates:** one isolate per handle, created with `graal_create_isolate`.
- **Calls:** a generic `zeroj_call(thread, method, json)` that returns a library-allocated UTF-8
  string the caller frees with `zeroj_free`. Typed entry points (bytes plus length) are added
  for hot paths.
- **Errors:** integer error codes alongside the JSON error object.
- **Conventions:** follow Mesmo's (handles, error state, version check on init).
- **Platform matrix:** Linux x64 and arm64 (glibc; musl optional), macOS arm64 and x64, and
  Windows x64. Only macOS arm64 was built in the POC.
- **Wrappers:** Python (ctypes or cffi), Go (cgo), Rust (FFI) and JS for Bun and Deno. Node has
  no built-in FFI, so Node uses the wasm bundle.

### D12 — Size work (R0)
- **Approach:** the facade avoids Jackson data binding (it uses the tree model or a small
  hand-written JSON layer) and keeps the reachable JCA services to the minimum.
- **Measured and gated, not promised:** M2 records the bundle size (raw, gzip and brotli) against
  the POC baseline: 13.4 MiB / 4.9 MiB full, 12.7 MiB / 4.6 MiB verifier-only.

### Alternatives considered
- **Reimplement in TypeScript or Rust (or use snarkjs alone).** This covers Groth16 verify, but
  not ZeroJ's circuits, the Poseidon profile, Pedersen/notes/BBS, or the Cardano encoding.
  Rejected: it would be a second implementation of security-critical code to keep in lockstep.
- **Ship a JVM** (JPype, a sidecar, a JVM in the browser). It defeats the purpose for browsers
  and constrained hosts. Not evaluated further.
- **Other Java→WebAssembly/JS compilers** (for example TeaVM, CheerpJ, J2CL). **Not evaluated in
  this revision.** The same toolchain as Julc and Mesmo, and one metadata format with Native
  Image, favour GraalVM. A reviewer may ask for a comparison.
- **Native executable plus a subprocess** instead of a shared library. It is simpler, but adds
  per-call process cost and serialisation. It stays available through the `zeroj-tools` native
  CLI.

## Security invariants
- **I1 — Semantic equivalence.** For the same inputs, the JVM, wasm and the native library return
  the same accept/reject decision and the same bytes for every deterministic output. This is
  enforced by parity fixtures and by snarkjs, blst and published-vector oracles (D2, D5, D7).
- **I2 — No weak randomness.** Under Web Image, every random byte ZeroJ consumes comes from
  `crypto.getRandomValues`. When that is unavailable, operations that need randomness fail closed
  and never use `Math.random()` (D3).
- **I3 — The default build is unchanged.** `./gradlew build` needs no GraalVM, Binaryen, Node or
  native toolchain (D1; ADR-0044 invariant 6).
- **I4 — Isolation.** No pure-Java product module depends on a binding module. Bindings are not
  in `zeroj-bom-core` (D1).
- **I5 — blst unreachable.** No binding image contains `supranational.blst.*` or
  `org.zeroj.blst.*`. The build fails otherwise (D4).
- **I6 — Same validation.** Untrusted inputs pass through the same validating ZeroJ APIs as on
  the JVM. The bindings add no encoding parser. The D6 loader accepts and rejects exactly the
  bundles the file loader does (D2, D5, D6).
- **I7 — Clean boundary.** No Java exception, partial result or object reference crosses the JS
  or C boundary. Every error is a structured `{ok:false}` with a code (D2, D11).
- **I8 — No insecure setup.** Published bundles expose no trusted setup. The
  `zeroj.allowInsecureTrustedSetup` opt-in and its warnings are unchanged (ADR-0044 invariant 8).
- **I9 — No claim upgrades.** Maturity, constant-time and side-channel claims are unchanged.
  Tier 2 in a browser carries the D8 label (D8; ADR-0044 invariant 10).
- **I10 — Bundle integrity.** Launcher and module are content-addressed and released with
  `SHA256SUMS`. Any launcher patch asserts its anchor and fails the build if the launcher changes
  (D10; Julc ADR-057).

## Consequences
- **Gains:**
  - JavaScript, Python, Go and Rust users can verify ZeroJ proofs and build Cardano verifier
    inputs without a JVM.
  - Browsers can prove client-side (after Tier 2).
  - The JuLC playground could use ZeroJ's pure-Java BLS12-381 instead of disabling BLS builtins.
    This would be a separate Julc decision.
- **Costs:**
  - an opt-in build lane with a preview toolchain;
  - a parity suite on three runtimes;
  - a platform matrix for native libraries;
  - bundle-size and browser-matrix upkeep.
- **ZeroJ core changes (D3–D6):** additive or behaviour-preserving. Each is useful without the
  bindings: D4 also fixes native-image builds of applications that use the pure-Java verifier;
  D6 also helps servers that keep keys in object storage.

## Compatibility
- **No change to:** proof, key or public-input encodings; transcripts; or the accepted sets of the
  verifier.
- **D5:** must produce identical on-chain bytes, so validator script hashes and datums are
  unaffected.
- **D3.2:** throws only under Web Image without a safe provider. JVM and native behaviour is
  unchanged.
- **D6:** additive API.
- **D4:** changes metadata only. JVM behaviour is unchanged. Native-image users of blst must keep
  working (an M0 gate).
- **New artifacts** (the wasm bundle, native libraries) carry their own version and API version.
  They are not new Maven coordinates.

## Implementation milestones
Each milestone has its own PR and review.

- **M0 — Core fixes (D4, D5).**
  - Entry: this ADR accepted.
  - Exit:
    - conditional blst metadata, and a native-image build of a blst-using app still works;
    - a pure-Java Cardano encoding with a blst differential over the existing proof fixtures,
      plus negative vectors for the D5 validation table;
    - all existing tests green.
- **M1 — The randomness guard (D3.2).**
  - Entry: M0.
  - Exit:
    - the guard in ZeroJ core;
    - a Web Image negative test: an image without the provider refuses prove, keygen and
      blinding;
    - a positive test with the provider, plus the constant-filler determinism probe.
- **M2 — `zeroj-wasm`, Tier 1.**
  - Entry: M0, M1.
  - Exit:
    - parity fixtures (JVM == wasm), including malformed-input vectors from the ADR-0045 and
      ADR-0047 suites;
    - snarkjs interop;
    - a headless browser smoke test in Chrome, Firefox and WebKit;
    - an ES module plus worker wrapper with TypeScript declarations;
    - size recorded (D12);
    - the opt-in CI job.
- **M3 — `zeroj-native`, Tier 1.**
  - Entry: M0.
  - Exit:
    - the C ABI (D11) and the platform matrix build;
    - parity fixtures through Python and Go;
    - no blst in the images (I5).
- **M4 — The in-memory key loader (D6).**
  - Entry: M0.
  - Exit: accept and reject equivalence with `Groth16PkStore.load` and `ZkeyPkStoreImporter` over
    valid, tampered-manifest, wrong-fingerprint and invalid-point bundles.
- **M5 — Tier 2 in the bindings.**
  - Entry: M1, M4, Q1 decided, external review of D8 scheduled.
  - Exit:
    - prove, sign and seal in a worker;
    - JVM and snarkjs verify wasm-made proofs;
    - the randomness probe;
    - D8 labels in the API and the docs.
- **M6 — Distribution.**
  - Entry: M2 or M3, and Q2 decided.
  - Exit: content-addressed release assets with checksums, the docsite page, and the version pin
    check (D10).

## Verification and test-vector strategy
- **Independent oracles:**
  - snarkjs for Groth16 verify (both directions);
  - blst for the D5 compression;
  - the official CFRG BBS vectors already in the repo, run through the bindings;
  - the repo's Poseidon and Pedersen known-answer vectors.

  Expected values never come from the binding under test.
- **Parity fixtures:** one JSON request list. The JVM's results are the reference; wasm and native
  must match byte for byte. Fields that are random or timing-dependent are excluded, and the
  exclusion is declared per fixture.
- **Negative cases through the boundary:**
  - malformed JSON;
  - wrong `nPublic`;
  - out-of-range scalars;
  - off-curve, off-subgroup and infinity points;
  - non-canonical encodings;
  - tampered proofs and inputs.

  Each must be rejected exactly as on the JVM.
- **Randomness:**
  - the constant-filler probe (D3);
  - an image without the provider must fail closed (M1);
  - native output must differ per process.
- **Reachability:** the `AbortOnTypeReachable` guards are part of every binding build (I5).
- **Performance and size** are recorded per release; they are not pass/fail, apart from a
  regression budget set in M2.

## Production / audit gates
- External review of D3 (the randomness provider and guard) and of D8 (secret handling in a
  browser) before Tier 2 is published.
- No Tier 2 browser release until Q1 is decided.
- Web Image is experimental ([WEBIMAGE]). Published bundles say so, and say which GraalVM line
  built them.
- The bindings inherit every existing maturity label. A verifier marked experimental on the JVM
  is experimental in wasm.

## Risks
- **The preview toolchain changes.** Web Image is experimental, so interop and launcher behaviour
  may change between release lines. Mitigation: the pin (D10), the launcher anchor assertion
  (I10) and parity CI.
- **The `SecureRandom` substitution is fixed or changed upstream.** D3.2 checks the actual
  provider, not a version number, so it stays correct either way.
- **Users run Tier 2 in an unsafe context** (a shared kiosk browser, a hostile extension). D8
  labels and docs can reduce this, not prevent it.
- **Bundle size** slows the first load on poor connections. Mitigation: D12, lazy loading, and
  Tier 1 bundles without the prover.
- **The native platform matrix** adds release cost (Mesmo has the same cost and has absorbed it).
- **Prover speed in wasm** limits Tier 2 to small and medium circuits until MSM/FFT can be split
  across Web Workers. WasmGC has no shared-memory threads, so that sharding needs its own design.

## Open questions
- **Q1 — Offer Tier 2 in the browser at all?**
  - (a) Never: Tier 1 only, and prove on a server or in the native library.
  - (b) Behind the D8 label and a worker, after external review.
  - (c) Only for named circuits whose witness is low-value.
  - **Lean: (b).** Client-side proving is the main privacy benefit, and a server prover is
    strictly worse for the witness.
- **Q2 — Distribution channels and names:** npm (`@zeroj/wasm`?), PyPI wheels with bundled
  libraries, a Go module, GitHub release assets. **Lean:** GitHub release assets in M6; package
  registries afterwards.
- **Q3 — GraalVM line:** stay on 25.3, as Julc does, or move to 25.4. **Lean:** 25.3 for M2/M3,
  then re-run the parity suite on the newer line before switching.
- **Q4 — D4 mechanism:** conditional metadata (lean; no coordinate change), or an optional
  dependency / split artifact for `zeroj-verifier-groth16`.
- **Q5 — Where the bindings live:** opt-in modules here (lean; parity tests run against the same
  commit), or a separate `zeroj-bindings` repository as Mesmo is for CCL.
- **Q6 — Commit the POC?** The r1 evidence comes from a standalone POC outside this repo. Options:
  - commit it under `bindings/poc/` for reviewers;
  - attach it to the PR;
  - let M2 and M3 supersede it.
- **Q7 — A circuit-agnostic prover** (serialized R1CS plus a Java-free witness format), so one
  generic bundle can prove any circuit. A separate ADR if wanted.

## Related findings (out of scope)
- **Small-circuit proving barely uses parallelism.** At 2,930 and 5,370 constraints, proving
  takes the same time on 16 cores as on 1. The POC did not establish why. Worth a profiling issue.
- **`zeroj-codec` uses Jackson data binding** (`ObjectMapper`) for snarkjs JSON. Its share of
  bundle size is not separately measured. A tree-model parser may help D12.
- **Building a 2^20-leaf Poseidon tree takes about 3 minutes in wasm.** Large tree construction
  belongs on a server, whatever the runtime.
