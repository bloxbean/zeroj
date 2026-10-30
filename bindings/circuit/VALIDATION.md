# Circuit compiler first milestone — validation

2026-10-30. Experimental initial promotion on `feat/wasm-circuit-frontend`, stacked above
PR #92 at `844a0625282cc87e77f3c85df1c1cbdd4cc86a3a`. The preceding research is commit
`d425988` in the independent browser-circuit-compiler-poc repository. This report covers the
new ZeroJ implementation, not merely rerunning that research tree.

## Result and scope

The first bounded implementation works: portable graph import, canonical symbolic recipes,
existing Java gadget expansion/R1CS compilation, typed inputs, constraint checking, supplied-key
small-circuit proving and verification. Build-time TS recipe export supplies public R1CS/graph/
identity artifacts without requiring a separately authored Java circuit class. It generates no
witness or ceremony keys and is excluded from the consumer image.

All five TS recipes match annotation-authored Java graphs, R1CS fingerprints and full JVM witness
vectors. The promoted graph hashes differ intentionally from research because the format tag and
compiler-policy field changed. The underlying fixture R1CS identities remain unchanged. Every
exposed primitive also executes in actual Wasm with positive/negative relation checks.

No cryptographic algorithms, gadget equations, core R1CS compiler or key parser were changed.
The small common-binding change factors session release so a compiled circuit can release its
owned keys. No new on-chain benchmark, production readiness, constant-time or quantum-resistance
claim is made. Full plan completion and independent review remain outstanding.

## Reproduction and completed checks

```sh
export JAVA_HOME="$GRAALVM_HOME"
python3 bindings/wasm/circuit-check.py
```

Host: Apple M4 Max/macOS 26.0.1 arm64; GraalVM 25.3.4.1+1.1, Binaryen 132,
Node 22.12.0 with the Wasm exception-handling flag, TypeScript 5.9.3, snarkjs 0.7.6.
The image build uses a 6 GiB compiler heap; compiler fixtures/tests use 2 GiB. These are
build-process settings, not measured browser heap bounds.

- **21 JVM tests passed:** 16 circuit tests, four shared boundary tests and one hash regression.
  Test methods contain multiple cases, including 100 deterministic arithmetic graphs, recipe
  parity, malformed graphs/recipes, canonical ordering/policy, input ranges, booleans, hints,
  integer overflow/underflow, division, lifetime, secret opt-in and build-time export.
- **17 Node tests passed:** actual packaged image, small proofs and bidirectional snarkjs
  interoperability, malformed identity/format/policy, primitive/gadget negatives, wrong keys,
  mismatched VK self-verification, cross-runtime/closed handles, key limits, and TS ownership/lint.
- Strict TS compilation and negative type fixtures passed. The type-aware lint accepts the
  examples and rejects six deliberately unsafe symbolic JS uses.
- All six browser scenarios passed in **Chromium 156.0.8078.4** and **Firefox 157.0**. Checks
  include proof tampering, foreign snarkjs proofs, ordinary SHA digest parity, no eager Wasm
  download, no external-origin requests/page errors, and no mobile-viewport horizontal overflow.
  Screenshots were reviewed; labels were changed to normal flow to avoid mobile heading crowding.
- Five local SDK tarballs were installed offline outside the workspace: runtime, verifier,
  circuit, circuit-lint and bundle-circuit. A strict-TS consumer authored, compiled, proved and
  verified cubic and rejected altered public values. No package was published.
- Six R1CS/witness pairs were independently checked by snarkjs. Five disposable keys/proofs
  were produced and verified by snarkjs; four fit the unchanged Wasm proving limits.

The focused check was rerun successfully after fixing repeat packaging of read-only GraalVM
notice files. The separate full nine-image binding check was updated to include this lane but
was not run in full in this iteration. No unchanged core cryptographic suite or Yaci application
run is claimed. Tests use public disposable fixtures; actual private values are not committed.

## Measured observations

Single Node test observations, fresh worker per scenario; **not** p50/p95 benchmarks.
Prove time includes the existing self-verification. No new browser/Node heap profiling was done.

| Fixture | Constraints | Wires | R1CS compile ms | Witness ms | Prove + self-verify ms |
|---|---:|---:|---:|---:|---:|
| multiplier | 2 | 5 | 7.85 | 0.61 | 265.39 |
| cubic | 3 | 8 | 7.62 | 0.62 | 268.76 |
| age_check | 29 | 38 | 6.42 | 0.55 | 269.48 |
| symbolic_select | 3 | 9 | 7.34 | 0.54 | 266.24 |
| poseidon_opening | 241 | 1,622 | 20.91 | 1.03 | Not generated |
| sha256_abc | 25,831 | 103,259 | 112.62 | 12.27 | Not generated |

Wasm image: **13,411,925 raw bytes**, **4,877,267 gzip**, **3,603,641 Brotli**;
launcher: 112,275 raw / 18,503 Brotli bytes.
Image identity: `circuit-14fbaeaaf81b2fee0ca4ef1e`.
Wasm SHA-256: `2e6da005d0cf89ea6118982926fb06c5a77b02f5564a0b1781efe239e5ab2dd8`.
Classpath/build digest: `edb5d7b81e0d61297b6636e2df68999d552b6187640014fe1e2b42a99f0889f1`.
Build metadata records a dirty implementation worktree based on the above PR #92 commit;
committed source and regenerated checks are the reproducibility inputs. Compression is measured
potential transfer size; the local example server serves raw files.

## Limits retained and next work

Poseidon's fixture key is **1,090,303 bytes** versus the existing **262,144-byte** key cap.
The Node wrapper rejects it; it also exceeds the current JSON string/request transport limits.
Its separate snarkjs proof verifies, but **no Poseidon proof was generated in Wasm**. SHA-256 has
**103,259 wires** versus the 4,096-wire/domain cap; no SHA proof/key was generated in this lane.
Both gadgets expand and their witnesses check in Node and both browsers. This does not establish
larger proving feasibility or infeasibility.

Next: bounded larger-key transfer using the existing importer, identity/point/relation checks,
allocation/cancellation tests and measured memory. Then fixed arrays/Merkle, broader SHA-2/
BLAKE2b, and the Cardano/Yaci application example. Resource accounting, stable compatibility,
independent review, Safari/physical mobile devices and distribution/secret-handling assessment
remain gates. See [PLAN.md](PLAN.md), [REVIEW.md](REVIEW.md), and [ADR-0064](../../docs/adr/0064-portable-circuits-and-typescript-frontend.md).

Sources, generators, tests and this summary are tracked. Raw logs, proof/witness vectors, keys,
images, screenshots, copied build notices and npm tarballs remain in ignored build directories.
