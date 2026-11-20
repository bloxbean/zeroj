# ZeroJ browser / Node SDK — measured implementation report

Date: 2026-10-30. PR [#92](https://github.com/bloxbean/zeroj/pull/92), ADR-0057 r2.
Base: main `65412c40ed1b6397ecfeb654e7bff547f6ea5b96`, merged before implementation and
re-fetched before completion; main had not advanced. Recommendation: **GO for experimental
source-build adoption; RESEARCH before production or binary npm release.**

## Delivered

The optional `bindings/wasm` Gradle composite and `bindings/js` npm workspace expose existing
ZeroJ Java code to JavaScript hosts. Nine logical packages cover runtime, ordinary hashes,
Pedersen, BBS, Groth16 verification/proving, exponential ElGamal, threshold/DKG and confidential
notes. Six physical image choices let an application select capabilities or share one combined
image. Default Java builds and Maven/BOM publication remain independent of this toolchain.

The working browser app has seven scenarios. Node runs the same scenario functions. A new
beginner/advanced docsite page explains the module structure with a selectable illustration.
The [SDK guide](README.md) contains build commands, API examples, deployment guidance and limits.
The [review records](reviews/W4-W5.md) record corrections and inherited security obligations.

No native blst or setup path is reachable in consumer images. Proof fixtures are generated
outside the images using snarkjs or visibly development-only JVM setup. No binary, raw key,
screenshot, per-test evidence dump or npm tarball is checked into Git. No npm publication or PR
merge is performed by this work.

## Validation evidence

| Area | Result |
|---|---|
| Adapter/JVM boundary | 5 initial tests: canonical encodings, extra/duplicate/trailing fields, integer/resource limits and hash KATs |
| Earlier affected core suites | 122 API, 89 BBS, 138 selected BLS tests; all passed |
| Additional core crypto | 48 executed, all passed; includes bounded zkey-import negatives and Groth16/PlonK regressions |
| Additional circuit-library core | 612 total: 601 executed, 11 opt-in skips; zero failures/errors |
| Actual Node SDK suite | 17 top-level tests passed; later DKG duplicate/resource-abort test also passed |
| Pedersen | 44 independent scalar/byte commitment vectors across both curves through Wasm |
| BBS | 50 official signature/presentation fixtures across both suites through Wasm; fresh proof/challenge/key-lifecycle tests |
| Ordinary hashes | WebCrypto parity and SHA/BLAKE KATs; 3 independent Sage Poseidon pairs |
| Groth16 | Wasm proof accepted by snarkjs; snarkjs proof accepted by Wasm; fresh blinders, wrong inputs/keys/curves/points rejected |
| ElGamal proof bridge | Possession, encryption and share proofs verify in Wasm and independently in snarkjs; exact statement/width/context negatives |
| Confidential notes | 53 independent opening accept/reject vectors plus reference reader keys, generated owner/auditor deliveries and tampering |
| DKG | Seven-round local 2-of-3 simulation; session/channel/sender/round, insufficient/duplicate share and resource-abort negatives |
| Entropy | Actual image without provider rejects guarded defaults; missing/throwing/late-failing entropy, 65,536-byte chunking; no observed Math.random calls |
| Browser | Hash + all six shared crypto scenarios pass Chromium 156.0.8078.4 and Firefox 157; lazy assets, result checks, mobile layout |
| Packaged consumer | 15 local tarballs installed offline outside workspace; TypeScript declarations compile and installed combined image executes |
| Documentation | Astro: 0 errors/warnings/hints; 138 Java snippets checked; 65 HTML pages, 63 Markdown twins and 5 AI artifacts verified; diagram interaction and desktop/mobile QA |

These are functional/interop tests and an implementation self-review, not an independent audit.
The SDK dependency install reported zero vulnerabilities. The unchanged docsite dependency
installation reported seven existing advisories; dependency remediation was not bundled into
this implementation.

## Environment and measurements

Apple M4 Max, arm64 macOS 26.0.1, 128 GiB physical RAM. Oracle GraalVM 25.3.4.1+1.1,
Binaryen 132, Node 22.12.0 with `--experimental-wasm-exnref`, TypeScript 5.9.3, snarkjs 0.7.6.
The image compiler uses a **6 GiB Java heap** and four compiler threads. That is a build setting,
not a measured browser heap ceiling. Generated manifests pin launcher/Wasm hashes and lengths;
new build metadata fingerprints classpath/build inputs and records worktree dirtiness.

### Download size

MiB = 1,048,576 bytes. Launcher + Wasm only; gzip level 9 and Brotli quality 11. These are local
compression measurements, not network latency, resident memory or npm archive sizes.

| Image | Raw MiB | gzip MiB | Brotli MiB |
|---|---:|---:|---:|
| Hash | 12.361 | 4.477 | 3.314 |
| Crypto (Pedersen/BBS) | 12.619 | 4.571 | 3.386 |
| Groth16 verifier | 12.447 | 4.501 | 3.338 |
| Groth16 prover | 12.646 | 4.573 | 3.390 |
| Confidential (ElGamal/DKG/notes) | 12.762 | 4.626 | 3.426 |
| Optional combined | 13.100 | 4.763 | 3.515 |

Each independent image includes the Java runtime. The five separate consumer images total about
16.85 MiB Brotli; the combined image is about 3.52 MiB. Choose separate images for selective
loading; choose the combined image when most capabilities are needed. This is explicit image
selection, not shared-heap dynamic linking or automatic linker splitting.

### Local latency

Node values below are medians of three fresh-runtime samples from
`node --experimental-wasm-exnref scripts/benchmark.mjs`. Total includes worker/image loading and
the scenario. Browser values are single illustrative complete scenario runs; not a statistical
browser benchmark or a mobile-device claim. The cubic circuit has **3 constraints** and 1 public
input. Do not extrapolate these figures to a large account-ownership circuit.

| Scenario | Node total ms | Chromium total ms | Firefox total ms |
|---|---:|---:|---:|
| Pedersen commit + disclosed check | 232 | 204 | 368 |
| BBS key/sign/presentation/verify | 1,497 | 1,424 | 2,781 |
| Groth16 load/prove/verify/tamper | 1,326 | 1,223 | 2,131 |
| Two-trustee encrypted tally | 230 | 203 | 275 |
| Seven-round local 2-of-3 DKG + decrypt | 328 | 294 | 399 |
| Owner/auditor note + altered-tag rejection | 246 | 221 | 276 |

Cubic **prove plus self-verification**: Node median 265 ms; Chromium 242 ms; Firefox 434 ms.
Separate verifier **first call (image/worker load plus strict verification)**: Node median 444 ms;
Chromium 396 ms; Firefox 645 ms. This is not a warmed pairing-only measurement. The proving
measurement starts after key loading; the verifier uses a fresh worker. Do not compare these
figures as if they had identical initialization costs.

## Security and scope conclusions

The implementation preserves existing algorithms, profiles and cryptographic parameters. It
adds strict bounded transport, safe object provenance and host RNG integration. A trusted host
can still read or replace secrets, code and descriptors. Web Workers do not establish constant
time, protection from a compromised origin or complete zeroization. Curve-based Groth16, BBS,
ElGamal and note encryption are not post-quantum. Ordinary SHA does not make a Groth16 circuit
post-quantum and WebCrypto hashing does not construct a circuit.

The threshold example is an honest local simulation, not a deployment of distributed trust.
Applications provide authenticated private channels, broadcast agreement, closure and deadlines.
No API reconstructs an admitted context from a bare transcript. Persistent restoration and
external authenticated-context admission are deliberately unsupported in this initial SDK.
Imported cryptographic objects still require the exact existing proof relations.

Notes provide encrypted delivery and commitment-checked opening. A private state machine also
needs authorization, nullifiers/replay prevention, balance/range proofs, trusted reader policy
and exact old/new state and ledger-output binding. None is supplied implicitly by a note-opening
or generic proof-verification call.

Limits are explicit in [README.md](README.md): 256 KiB byte/key transport, a bounded named-circuit
prover, up to 16 DKG participants and at most 1,000,000 discrete-log search. The previous huge
account-ownership browser experiment did not complete proving. Large-circuit proving, Safari,
WASI, automatic framework bundler integration and native C ABI are not validated deliverables.

## Release recommendation

**GO** to experiment with the Java-derived APIs and local browser/Node examples. The module
structure, independent proof interoperability and packed-consumer execution are working.

**RESEARCH** before a production SDK release: external entropy/secret-boundary review, inherited
protocol audits, mobile/browser coverage, durable/distributed application integration, and larger
compiled-circuit transport/proving are separate work. In particular, the supplied Oracle
GraalVM runtime introduces distribution terms beyond MIT. Generated physical packages remain
private; see [DISTRIBUTION.md](DISTRIBUTION.md). A source-built open-source toolchain is a possible
alternative, not a validated replacement in this report. npm scope ownership, artifact/source
licensing and trusted publication must be settled before publishing.

## Reproduce affected core checks

From the root with the documented Java toolchain:

```sh
./gradlew :zeroj-crypto:test --tests '*ZkeyImporter*' \
  --tests '*Groth16BLS381ZkeyEndToEndTest' --tests '*ProverApiSurface*' \
  --tests '*PlonK*' --max-workers=2
./gradlew :zeroj-circuit-lib:test --tests '*Pedersen*' --tests '*ElGamal*' \
  --tests '*Dkg*' --tests '*ConfidentialNote*' --tests '*Blake2bDigest*' \
  --tests '*SecretScalar*' --max-workers=2
python3 bindings/wasm/check.py
cd bindings/js
node --experimental-wasm-exnref scripts/benchmark.mjs
```

The complete binding check regenerates disposable keys, so proof bytes/key hashes vary. It
reproduces the relations and assertions, not a claim of bit-for-bit deterministic build output.
