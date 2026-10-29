# ADR-0057 implementation ledger

PR #92; experimental bindings. This ledger records completed evidence, not release approval.

- W0: merged main `65412c40`; r2 architecture adopted in ADR-0057.
- W1: initial boundary/provider guard implemented and tested, including a negative actual image.
- W2: typed runtime/browser/Node workers implemented; hash browser smoke passes.
- W3: hash, scalar/byte Pedersen and BBS implemented; 44 commitment and 50 official BBS vectors
  pass through the Node SDK. See [checkpoint review](reviews/W1-W3.md).
- W4: underway; reuse main's existing validated byte-array zkey importer.
- W5–W6: pending (confidential adapters, complete examples, browser matrix, distribution review).

All implementation, corrections, review notes and results stay in this PR. Generated images,
raw logs, keys and npm tarballs are excluded from Git. No npm publication has been performed.

Inherited security gates: browser/Node Wasm secret paths are unassessed; external review remains
required. Threshold transport authentication, agreement, deadlines and closure remain the
application's responsibility. No post-quantum claim is made for curve-based operations.
