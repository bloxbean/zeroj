# ADR-0057 implementation ledger

PR #92; experimental bindings. This ledger records completed evidence, not release approval.

- W0: merged main `65412c40`; r2 architecture adopted in ADR-0057.
- W1: initial boundary/provider guard implemented and tested, including a negative actual image.
- W2: typed runtime/browser/Node workers implemented; hash browser smoke passes.
- W3: hash, scalar/byte Pedersen and BBS implemented; 44 commitment and 50 official BBS vectors
  pass through the Node SDK. See [checkpoint review](reviews/W1-W3.md).
- W4: implemented and tested; strict verifier and bounded supplied-key proving, with independent snarkjs interoperability.
- W5: implemented and tested within documented transport/resource limits.
- W6: delivered; browser/Node examples, docsite guide, packed-consumer checks, measured report and final self-review. See [report](REPORT.md) and [W6 review](reviews/W6.md).

All implementation, corrections, review notes and results stay in this PR. Generated images,
raw logs, keys and npm tarballs are excluded from Git. No npm publication has been performed.

Inherited security gates: browser/Node Wasm secret paths are unassessed; external review remains
required. Threshold transport authentication, agreement, deadlines and closure remain the
application's responsibility. No post-quantum claim is made for curve-based operations.

## W4–W5 checkpoint (2026-10-30)

Supplied-key cubic proving and strict Groth16 verification pass independent snarkjs checks in
both directions. ElGamal, threshold/DKG and notes adapters/wrappers now run in Node and browser
examples, with proof-bound imports and 53 independent note-opening vectors. See
[W4–W5 review](reviews/W4-W5.md). Additional core suites: 48 crypto tests and 601 executed
Jubjub/circuit-library tests (11 opt-in skips), all passing.

W6 completed the packaging, SDK/browser rerun, tarball consumer checks, deployment/tutorial
documentation and final implementation self-review. Distribution review found Oracle runtime terms;
all precompiled bundle packages are private pending the separate npm release gates described in
[DISTRIBUTION.md](DISTRIBUTION.md). No commercial redistribution readiness is asserted.
