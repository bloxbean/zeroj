# ADR-0045: Groth16 BLS12-381 infinity-IC profile — affirm ADR-0025 and bind every public wire at setup

## Status
Proposed — implemented on branch `fix/52-infinity-ic-profile` (issue
[#52](https://github.com/bloxbean/zeroj/issues/52), Phase 0 of umbrella #54),
awaiting maintainer review; the ADR and the implementation were produced together
and have not been independently reviewed. Value-bearing use of the Groth16 path
still requires the ADR-0025/ADR-0026 independent audit and release-assurance
gates; this ADR does not change any maturity claim.

## Date
2026-09-06

## Risk classification
**R2/R3.** Setup completeness (the dev/test single-party setup), the canonical
serialization profile that every verifier enforces, the import trust boundary for
ceremony keys, and (M4) the prover's blinder sampling on the proof-equation path.
No soundness break was demonstrated or is claimed; the defect is a completeness and
profile inconsistency that could also mask an unbound public input.

## Context

ADR-0025 (Decisions 2 and 3, implementation status 2026-06-29) made the following the
verifier profile for BLS12-381 Groth16 on every path — pure-Java JSON verifier, blst JSON
verifier, and the on-chain JuLC library `Groth16BLS12381Lib`: proof points `A/B/C`, VK points
`alpha/beta/gamma/delta`, and **every `IC[i]` entry (including `IC[0]`)** must be canonically
encoded, on-curve, in the prime-order subgroup, and **not the point at infinity**.

ZeroJ's native single-party setup (`Groth16SetupBLS381`, heap and streaming paths) computes

```
IC[s] = (beta * u_s(tau) + alpha * v_s(tau) + w_s(tau)) / gamma * G1,   s = 0..numPublic
```

and writes `AffineG1.INFINITY` when the scalar is zero. The scalar is zero whenever the public
wire `s` carries no nonzero coefficient in any A/B/C row (`u_s = v_s = w_s = 0` as
polynomials). It is also zero, with probability on the order of `N/r`, when the wire is used
but the random `alpha, beta, tau` cancel the combination. The native setup therefore emits a
verification key that ZeroJ's own verifiers reject.

Reproduced on `main` at `a0c4983` (2026-09-06) with relation `a·b = c`, `1·1 = 1` over wires
`[1, c, unusedPub, a, b]`, `numPublic = 2`:

```
IC[2].isInfinity = true
pure Java: INVALID_PROOF — vk.IC[2] must not be point at infinity
blst     : INVALID_PROOF — vk.IC[2] must not be point at infinity
```

The same relation with the `1·1 = 1` row removed additionally yields `IC[0] = infinity`
(the constant wire is then unreferenced), which every verifier also rejects.

This consolidates K3 finding F2, Grok finding G16-001, and triage items C-02/C-17 in
`docs/zeroj-audit-consolidated-triage-2026-08-20.md`. Grok proposed relaxing the verifiers to
accept a canonical infinity `IC`; the triage correctly flagged that this conflicts with
ADR-0025 and must be resolved by a profile decision, not a verifier-only change.

### Why an infinity `IC[s]` matters beyond completeness

If `IC[s] = O` then public input `s` contributes nothing to `vk_x = IC[0] + Σ pub_i · IC[i]`.
A proof then verifies for **every** value of that public input. An application that relies on
a public input being bound (a recipient address, a nullifier, a transaction reference) would
be silently unprotected by such a key. The ADR-0025 non-infinity rule turns that condition
into a hard verifier rejection. This ADR keeps that rule and makes the producers of keys fail
closed for the same condition, so the failure is reported at setup with the wire named, not at
verification time with an opaque encoding error.

### What snarkjs does (reference behaviour)

snarkjs `zkey_new.js` appends one trivially satisfied row per public signal
`s = 0..nPublic` — `A = {s: 1}, B = {}, C = {}` — after the circuit rows before computing the
QAP. Every `IC[s]` of a snarkjs key is therefore a nonzero multiple of `G1` except with
negligible probability. snarkjs `groth16_verify.js` validates proof points
(`isWellConstructed`) but does not reject an infinity `IC` entry; its keys simply never
contain one.

ZeroJ already reproduces those rows for imported ceremony keys: `ZkeyImporterBLS381`
reads the zkey's own coefficient section (which contains the rows), and
`ZkeyPkStoreImporter.snarkjsConstraints` / `Groth16ProverBLS381.computeHFlat(…,
snarkjsBindingRows, …)` synthesize them for the streaming prover. Imported keys are
therefore already consistent with the ADR-0025 profile. Only the native setup diverges.

## Threat model and trust assumptions

- **Untrusted at verification time:** proof bytes, public inputs, and the verification key
  (JSON, CBOR envelope, or on-chain datum/script constant). Unchanged by this ADR.
- **Untrusted shape at setup time:** the relation (`constraints`, `numWires`, `numPublic`) is
  caller-supplied. As in issue #46, the setup must not weaken or silently reshape a relation;
  it must reject one it cannot produce a profile-conforming key for.
- **Untrusted at import time:** a `.zkey` file. `ZkeyPkStoreImporter` currently accepts an
  infinity `IC` entry (`isOnCurve() || isInfinity()`); after this ADR it rejects it, matching
  the verifier profile at the import boundary.
- **Secret:** `tau, alpha, beta, gamma, delta` in the dev setup (dev/test only, behind the
  ADR-0025 insecure-setup opt-in) and the prover blinders `r, s`. The new checks read only
  relation shape and the derived `IC` scalars; they do not introduce secret-dependent control
  flow beyond the existing (already variable-time, ADR-0012/0021) dev setup and prover.
- **Not in scope:** application binding (`ScriptContext`, replay, nullifiers) remains the
  validator author's responsibility (ADR-0006, ADR-0025 F8). A bound public input is a
  necessary condition for those guarantees, not a sufficient one.

## Pinned normative references

- J. Groth, *On the Size of Pairing-based Non-interactive Arguments*, EUROCRYPT 2016,
  §3.2 — the verification key contains `[(β u_i(x) + α v_i(x) + w_i(x))/γ]_1` for
  `i = 0..ℓ`; the verifier computes `Σ_{i=0..ℓ} a_i · [·]_1` with `a_0 = 1`.
- snarkjs `src/zkey_new.js` (public-signal binding rows) and `src/groth16_verify.js`
  (`isWellConstructed` on proof points only), as pinned by ADR-0031 for the ceremony path.
- ZCash BLS12-381 serialization (compressed infinity: `0xC0` prefix, zero body) as used by
  CIP-0381 builtins on-chain and by `ProverToCardano`/`Groth16BLS12381Lib`.
- ADR-0025 Decisions 2 and 3 and its implementation-status section (the verifier profile).
- ADR-0036 (`Groth16Keys`, `Groth16Pipeline`) and ADR-0035 (streaming setup) for the
  entry points that must enforce the new setup invariants.

## Decision

**Option A of issue #52: affirm ADR-0025. No verifier is relaxed. Producers fail closed.**
(Proposed; becomes the accepted profile when this ADR is accepted.)

### Verifier profile (affirmed, unchanged)

- **V1.** Pure-Java JSON, blst JSON, and on-chain `Groth16BLS12381Lib` reject any `IC[i]`
  (`i = 0..nPublic`) that is the point at infinity, off-curve, off-subgroup, or non-canonical,
  before any scalar multiplication or pairing. Identical semantics on every provider.
- **V2.** Proof points `A/B/C` and VK points `alpha/beta/gamma/delta` remain non-infinity on
  every provider (ADR-0025).
- **V3.** Codecs (`SnarkjsJsonCodec`, the CBOR envelope, `ProverToCardano`) are transport:
  they decode and re-encode canonical forms and are **not** the enforcement point. The
  enforcement points are the verifiers (V1/V2) and the producers (S1/S2/I1 below). A codec
  must not silently drop or rewrite an infinity encoding; the verifier that consumes it must
  reject it. Negative tests cover the projective JSON encoding `[0, 1, 0]` and the compressed
  on-chain encoding `0xC0‖0…0` for `IC[0]` and `IC[i>0]`.

### Setup invariants (new)

- **S1 — structural (deterministic).** Every public wire `s ∈ [0, numPublic]`, including the
  constant wire `0`, must carry at least one coefficient that is nonzero modulo `r` in some
  A, B, or C row. Enforced at ingress by
  `R1CSValidation.requirePublicWiresConstrained(...)` (list and CSR forms) in
  `Groth16SetupBLS381.setup(...)`, `Groth16SetupBLS381.setupToStore(...)`, and
  `Groth16Pipeline.setup(...)` (so the native pipeline fails before creating the bundle
  directory, the `r1cs.bin` cache, or any store file). The error names the offending wire
  and, for wire `0`, explains that the relation has no constant term.
  `Groth16Pipeline.Compiled` is deliberately **not** an enforcement point: it also carries
  the original circuit relation when proving under an imported snarkjs ceremony key, whose
  binding rows are added at H time via `snarkjsBindingRows`; applying S1 there rejected
  valid ceremony keys for circuits with no constant term (PR #56 review finding).
- **S2 — exact (probabilistic remainder).** After the QAP evaluations `u_s, v_s, w_s(tau)` are
  known and before any proving-key point is generated or any store file is written, the setup
  computes every `IC` scalar and throws `IllegalStateException` if one is zero. A native
  setup therefore **never** writes `AffineG1.INFINITY` into `IC`. The heap path's `IC`
  computation moves ahead of point generation so a large relation fails in seconds, not after
  the MSM work. The message tells the caller to re-run setup with fresh randomness; with a
  wire that satisfies S1 this occurs with probability on the order of `N/r` per wire.
- **S3 — parity.** Heap and streaming setup reject the same relation with the same exception
  type and wire name; the existing byte-equality differential for accepted relations is
  unchanged.

### Import invariant (new)

- **I1.** `ZkeyPkStoreImporter` rejects a `.zkey` whose `IC` section contains the point at
  infinity, with the entry index in the message; the same rule now applies to the single VK
  points `alpha/beta/gamma/delta` it reads from the header (previously on-curve only).
  `ZkeyImporterBLS381` does not read `IC` (the JSON verification key is the VK source on that
  path) and already rejects infinity header points; it is unchanged.

### Prover policy for C-17 (decided: resample)

- **P1.** The randomized prove paths (`prove`, `proveWithReaders`, `proveWithHCoeffs`) sample
  fresh `(r, s)` and recompute the proof if any of `A`, `B`, or `C` is the point at infinity,
  up to a small fixed bound (8 attempts), then fail closed with `IllegalStateException`. The
  event has probability on the order of `3/r` per attempt for an honest key and witness, so
  the bound is unreachable in practice; it exists so the loop is provably finite. The check
  is on the Jacobian results inside `proveBlinded` (at the time, `proveInternal`'s caller;
  ADR-0046 later folded `proveInternal` away), so both the pure-Java and blst
  MSM backends get it.
- **P2.** The deterministic, test-only unblinded paths (`r = s = 0`) do not resample; they
  throw `IllegalStateException` instead of returning a proof the profile rejects. (Since
  ADR-0046 the only such path is the unpublished test fixture `Groth16UnblindedTestProver`,
  which feeds `(0, 0)` once through the package-private `BlinderSource` seam of
  `proveBlinded`; the source throws on the second draw an infinity point would trigger.)
- **P3.** Rejection sampling on an event of probability ~`2^-253` does not measurably change
  the distribution of `(r, s)`; the zero-knowledge argument of Groth16 §3.2 (simulator picks
  uniformly random group elements) is unaffected. This is recorded here so the change is
  not mistaken for a nonce-policy change.

### Alternatives considered

1. **Option B — accept a canonical infinity `IC` at the verifiers.** Rejected. It would make
   a declared public input silently unbound (see *Why an infinity `IC[s]` matters*), require
   amending ADR-0025 on all three providers plus the on-chain library, and add a second
   accepted encoding class to the profile for no security benefit.
2. **Append snarkjs-style binding rows in the native setup.** Considered seriously because
   it is the reference behaviour and all prover plumbing exists (`snarkjsBindingRows`).
   Rejected for this ADR: it changes the QAP shape of every native key, so every native-key
   prove would need `snarkjsBindingRows = numPublic + 1`, but neither
   `Groth16ProvingKeyBLS381`, the store manifest, nor the pipeline fingerprint records which
   shape a key has, and every existing caller passes `0`. That is a proof-path (R3) and
   persistence-format change for a dev-only setup, with a silent completeness failure mode
   if a caller gets the flag wrong. Rejecting at setup is R2, setup-local, and gives the
   author an actionable error. The divergence from snarkjs is explicit: snarkjs binds an
   unused public signal, ZeroJ's native setup refuses it. Interoperability is unaffected
   because imported ceremony keys carry snarkjs's own rows.
3. **Special-case `IC[0]`.** Rejected; ADR-0025 rejects `IC[0]` at infinity on every
   provider, so a relation that never references the constant wire cannot produce a usable
   key either. The rule is uniform over `s = 0..numPublic`. DSL circuits are unaffected
   (`assertEqual` emits `(l − r)·1 = 0`, which references wire 0); hand-written raw
   relations such as `a·b = c` alone now fail at setup and need one row that references
   wire 0 (for example `1·1 = 1`).
4. **No prover resampling (document the `1/r` gap).** Rejected as inferior at equal cost:
   three `isInfinity` checks make the system strictly complete under the profile.

## Consequences

- A relation with an unreferenced public wire (or no constant term) now fails at setup with
  the wire named, on the heap, streaming, facade, and pipeline paths, instead of producing a
  key every verifier rejects. This is the intended fail-closed behaviour. It may surface
  latent unbound public inputs in downstream circuits; those are real findings, not a reason
  to relax S1.
- No key, store, cache, or wire format changes. Existing native key bundles for relations
  that satisfy S1 are unaffected. Bundles for relations that violate S1 were never verifiable.
- The prover's public API is unchanged; the resampling loop adds three point checks per
  proof.
- Codec behaviour is unchanged; the ADR records that codecs are transport and verifiers
  enforce.

## Compatibility

- **Native setup / `Groth16Keys` / `Groth16Pipeline`:** new `IllegalArgumentException`
  (S1) and `IllegalStateException` (S2) on relations that previously "succeeded" into an
  unusable key. No signature changes.
- **`ZkeyPkStoreImporter`:** new `IOException` for an infinity `IC` entry or header VK point.
  snarkjs-produced zkeys are unaffected (their `IC` is never infinity except with negligible
  probability, and their header points are nonzero multiples of the generators).
- **Verifiers, codecs, on-chain:** no behaviour change; additional negative tests only.
- **BN254 legacy:** `Groth16Setup` (BN254) does not emit `IC` and is opt-in legacy
  (ADR-0025); out of scope.

## Implementation milestones

- **M1** — `R1CSValidation.requirePublicWiresConstrained` (list + CSR) with unit tests
  in `zeroj-api`.
- **M2** — S1 at both setup ingresses and `Groth16Pipeline.setup` (native setup only; not
  `Compiled`); S2 in both setup paths ahead of point generation; Javadoc.
- **M3** — I1 in `ZkeyPkStoreImporter` with a mutated-zkey negative test.
- **M4** — P1/P2 in `Groth16ProverBLS381` with forced-infinity tests.
- **M5** — Negative vectors: `IC[0]` and `IC[i>0]` infinity for pure-Java JSON, blst JSON
  (identical results asserted), and on-chain JuLC; regression covering the reproducer
  through heap, streaming, facade, and pipeline; heap/streaming parity.
- **M6** — Docs: this ADR, ADR-0025 status pointer, README ADR list, setup Javadoc.

## Verification and test-vector strategy

- **Reproducer as regression:** the relation above must be rejected at setup (S1) on every
  native entry point; a sibling relation that satisfies S1 must set up, prove, and verify on
  pure Java and blst.
- **Ceremony-key regression:** the checked-in snarkjs multiplier zkey (original relation
  `-a·b = -c`, no constant term, two snarkjs binding rows) must import, bind, and prove through
  `Groth16Pipeline.prove` with the cache disabled, on a cache miss, and on a cache hit, and the
  proofs must pairing-verify — S1 must never reach that path.
- **S2 independently forced:** with the explicit-randomness setup overload, choose `beta`
  so that `beta · u_s(tau) + w_s(tau) = 0` for a wire used only in A and C, computing
  `u_s(tau), w_s(tau)` from the Lagrange formula in the test (independent of the setup's
  QAP code). Setup must throw and must not have created the store directory.
- **P1 independently forced:** with the explicit-randomness setup, compute
  `r* = −(alpha + Σ w_i u_i(tau)) · delta^{-1}` (and `s*` for `B`) in the test and feed
  them through a test-only randomness seam; the prover must resample and produce a proof
  that verifies, and must fail closed when the seam always returns `r*`.
- **V1/V3 negatives:** `IC[0]` and `IC[i>0]` set to projective `[0, 1, 0]` in the shared
  `groth16-bls12381` verification-key vector for both JSON verifiers, with equal reason
  codes; compressed `0xC0` infinity for `IC[i>0]` on the JuLC VM (the `IC[0]` case exists).
- **I1 negative:** a zkey produced by the in-repo round-trip writer with one `IC` entry
  zeroed must be rejected by `ZkeyPkStoreImporter`.
- **Existing gates re-run:** `:zeroj-api`, `:zeroj-crypto`, `:zeroj-crypto-blst`,
  `:zeroj-verifier-groth16`, `:zeroj-onchain-julc`, `:zeroj-integration-tests`, `:zeroj-tools`;
  then `publishToMavenLocal` and the `zeroj-usecases` suites against the snapshot with the
  external Yaci DevKit.

## Production / audit gates (unchanged by this ADR)

- Independent review of the Groth16 path (ADR-0025/0026) before any value-bearing use.
- Production keys come from the ADR-0031 ceremony path, not the native setup; this ADR's
  setup invariants protect development and test flows and keep the profile consistent.
- The `1/r`-class events (S2, P1) are not testable by sampling; their handling is verified
  only by the forced tests above.

## Risks

- A downstream circuit with a genuinely unused public input now fails setup. That is the
  intended signal; the fix belongs in the circuit.
- If a future DSL optimisation inlines away every use of a public input, S1 will report it
  at setup rather than let a verifier reject the key later. The DSL-side static analysis
  tracked by #40 is the earlier, richer check; S1 is the trust-boundary backstop.
- The prover resampling loop is on the proof-equation path; it is covered by forced tests
  and bounded, and the accepted-proof computation is unchanged.
