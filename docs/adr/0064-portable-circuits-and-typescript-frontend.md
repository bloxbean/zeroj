# ADR-0064: Portable circuits and the symbolic TypeScript frontend

## Status and scope

Accepted for bounded experimental implementation, 2026-10-30, by the maintainer's
request to promote the tested prototype in a separate PR stacked on #92. **R2**:
serialization, untrusted graph/recipe admission and private-witness integration.
This acceptance is not an audit, production approval, or permission to publish.
The implementation milestones and selected gadget priorities are in
[the implementation plan](../../bindings/circuit/PLAN.md).

This amends ADR-0057's runtime-circuit exclusion for the explicitly enumerated
portable graph and symbolic recipe vocabulary only. Arbitrary Java/JS execution,
class loading, custom hints, setup in Wasm, additional proof systems and general
WASI targets remain outside scope. The Java R1CS compiler, witness calculator,
prover, verifier and cryptographic gadgets remain the single implementations.

## References and prior evidence

- ZeroJ `844a0625282cc87e77f3c85df1c1cbdd4cc86a3a`: `Gate`, `WitnessCalculator`,
  `R1CSCompiler`, `ZkField`/`ZkUInt`/`ZkBool`/`ZkBytes`, `ZkPoseidon`, `ZkSha256`,
  `ZkeyImporterBLS381`, and the bindings runtime/strict Groth16 adapters. These
  pinned implementations define the operation semantics; this ADR adds no crypto.
- Research `zeroj-research/browser-circuit-compiler-poc` commit `d425988`: five TS
  recipes matched Java annotation graph bytes/fingerprints/full witnesses; small
  proofs interoperated with snarkjs 0.7.6 in Node/Chromium/Firefox. Poseidon and
  SHA compiled and checked witnesses, but their Wasm proof path exceeded existing
  importer limits. Historical measurements do not establish performance here.
- ADR-0057: WebCrypto entropy, explicit secret opt-in, physical-image ownership,
  pure-Java providers, lifecycle and distribution restrictions remain governing.
- ADR-0063 and the existing gadget assurance suites govern SHA-2 correctness.
- [ECMAScript ToBoolean](https://tc39.es/ecma262/multipage/abstract-operations.html#sec-toboolean)
  and [TypeScript truthiness](https://www.typescriptlang.org/docs/handbook/2/narrowing.html#truthiness-narrowing):
  symbolic objects must not be used as host branch conditions. Type-aware lint is
  a guardrail; it cannot make arbitrary JavaScript a safe circuit language.

## Threat model and trusted inputs

Recipes, graph bytes, public/private input encodings, keys, metadata and handle IDs
can be malformed. Attackers may attempt allocation exhaustion, type/ownership
confusion, noncanonical encodings, wrong field/profile, mismatched relation/key,
invalid witnesses or stale/cross-session handle use. The application/serving origin,
compiler image and immutable bundle descriptor are trusted; integrity hashes do not
protect an application whose origin replaces both code and hashes.

Private inputs are supplied only at witness/proving time. Definition constants and
shapes are public. Host code can accidentally capture a secret in a definition;
the API cannot infer that intent. Never log or return witnesses or witness digests
from the promoted API. Secret operations keep ADR-0057's unassessed browser/Node
label, WebCrypto provider and explicit opt-in. No constant-time/erasure claim.

The application must select an authenticated graph identity, R1CS fingerprint,
proving-key hash and verification key. A caller-provided matching hash is not
independent authentication. An accepted graph can describe a vacuous or incorrect
application statement; graph validity is not circuit soundness or authorization.

## Formats and identity

First promoted formats are `zeroj-graph` v1 and `zeroj-symbolic` v1, field
`bls12-381-fr`, compiler policy `zeroj-r1cs-bls12381-v1`. They are **experimental**;
a semantic/encoding change requires a new version/policy and matching artifacts.
Research `*-research` tags are deliberately rejected. There is no compatibility
claim for Circom source or Circom witness executables.

Graph root order is `format,version,compiler,field,name,public,secret,wires,gates`.
Recipe root order is `format,version,compiler,field,name,inputs,commands`.
Both are minified UTF-8 JSON with exact field sets, fixed order and canonical
nonnegative decimal strings below Fr for scalars. Reordered keys, whitespace,
duplicate keys, unknown fields, numeric rather than string scalars, leading zeroes,
negative/reduced aliases and unsupported versions are rejected. Arrays preserve
order. Input records have `name,visibility,type`, then `bits` or `length` if needed.
Numbers used for indexes/counts are integral JSON integers with bounded ranges.
ASCII identifiers and opcode spellings are fixed; Unicode escaping is noncanonical.

Graph identity commits to witness instructions, field and policy; R1CS fingerprint
commits to the compiled relation. Recipe identity commits to the authoring command
sequence. Keep all identities distinct. The first API requires expected graph hash
and R1CS fingerprint when compiling for a lifecycle that can receive witnesses.
Different but mathematically equivalent authoring programs need not share identity.

Build-time `ExportCircuit` expands a public TS recipe on the JVM and exports its
graph, R1CS, input layout and identity manifest. TS-only authors therefore need no
matching Java circuit class. This artifact/setup build lane uses Java; consumer
browser/Node execution does not. The exporter never receives a witness or creates
ceremony keys and is excluded from the consumer image by a reachability guard.

## Closed operations and validation

Graph v1 permits Const, Add, Mul, AssertEq, AssertBoolean, LinComb, BitDecompose and
single-output hints INVERSE/IS_ZERO_RESULT/IS_ZERO_INVERSE. Raw Select, HintN, custom
code and future enum additions are rejected. The first gate is Const(ONE,1); each
intermediate is assigned exactly once, only reads previously defined wires, and
cannot overwrite inputs/ONE. Field scalars, bit widths, term counts and names are
validated before compilation. A hint supplies advice, not a constraint: intended
relations still need equations, just as in Java. The reviewed Java gadget/DSL
builders supply those equations; the codec cannot certify arbitrary graph intent.

Recipes contain backward-only symbolic IDs, not wires. A closed dispatcher calls
existing Java symbolic methods and validates concrete symbolic types. Public inputs
precede secret inputs; flattened names are unique. UInt widths/ranges, booleans,
selection and gadget constraints remain in Java. Initial gadget profiles are
explicit BLS12-381 T3 Poseidon and one-block SHA-256. No BN254 default is used.

TS uses immutable recording objects and private ownership records. Failed authoring
closes the recorder. Callbacks are synchronous/void, with explicit assertions;
operator overloads, symbolic JS conditions and witness-dependent shapes are excluded.
Typed lint must run for supported application code; bypasses via any/reflection or
arbitrary host code remain outside the supported authoring subset.

## Limits and lifecycle

Retain the researched graph limits: 16 MiB text, 200,000 wires/gates, 1,000,000 linear
terms, 4,096 terms per linear combination and 4,096 named inputs. Recipes admit at
most 64 logical/256 flattened inputs, 128 commands, UInt 1..253, bytes 1..64, four
Poseidon calls and one SHA-256 call of 1..55 bytes, with the 180,000-unit conservative
preflight expansion estimate. Post-expansion graph validation remains mandatory.
These are bounded experimental workloads, not proven hostile-input heap containment.

One compilation attempt per physical compiler worker, including failed attempts.
Graph uploads have bounded length, exact offsets and SHA-256; chunks stay within the
existing 1 MiB request/512 KiB string caps. A compiled-circuit session handle owns its
key handles. Closing it invalidates/releases its keys; runtime disposal/timeout
terminates the worker. A fresh compilation needs a fresh runtime. Keys from another
compiled circuit/runtime cannot be used. Public diagnostics contain counts/identity
and input layout, never witness values. Witness check returns only success/failure.

The first milestone retains the 256 KiB key and 4,096-wire/domain limits and uses
the existing Groth16 adapter/parser. Larger-key transfer is a separately tested
milestone: it must retain exact offsets/total bounds, authenticated hash, point and
relation validation, with measured allocation behavior. No parser duplication or
blind cap increase. The compiler and prover share one Java heap in an explicit
`bundle-circuit` image; verifier-only consumers do not need it. JS tree shaking does
not prune precompiled Wasm. Core/default Java builds remain unchanged.

## Verification and acceptance

- Port graph/recipe positives and malformed-input tests; add canonical root/input
  ordering and explicit hint allowlist tests. Add semantic/width/boolean/range and
  forged-ref negatives, witness tampering and artifact mismatch tests.
- Compare annotation Java and TS recipes: canonical graphs, R1CS fingerprints and
  full witnesses in test-only code. No secret diagnostics in consumer adapters.
- Run actual Node/Chromium/Firefox small proofs, bidirectional snarkjs checks and
  wrong-public-input rejection. Preserve entropy opt-in/failure and ownership gates.
- Inspect independent reference/gadget vectors; wrapper parity is not independent
  cryptographic assurance. Run affected Java and existing binding regressions.
- Measure image bytes, startup, compile/witness/prove/verify, with explicit memory
  scope and supported gadget sizes. No production/large-browser/quantum claims.

## Alternatives and remaining gates

A second TS crypto/compiler implementation would duplicate security-critical rules;
rejected. RPC per symbolic operation is unnecessarily expensive; use a batch recipe.
Java-only exported graphs remain supported alongside recipes. A low-level graph
builder is an advanced escape hatch with the same format/validation limits.

Before broader support: hard allocation/work counters, streaming graph/key memory
accounting, fuzz/property coverage, independent review, Safari/real-device validation,
explicit stable-format compatibility and artifact distribution review. Arrays,
Merkle, broader SHA-2/BLAKE2b, EC relation packs and Yaci/Cardano application policy
checks follow the plan; no such completion is implied by the initial promotion.
