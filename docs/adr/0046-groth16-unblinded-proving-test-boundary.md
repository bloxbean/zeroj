# ADR-0046: Groth16 BLS12-381 unblinded proving is a test fixture, not a public API

## Status
Proposed — implemented on branch `fix/50-gate-unblinded-prove-api` (issue
[#50](https://github.com/bloxbean/zeroj/issues/50), Phase 1 of umbrella #54; consolidated
triage item C-01), awaiting maintainer review. The ADR and the implementation were produced
together and have not been independently reviewed. This ADR closes a privacy/API-boundary
footgun; it does not change any maturity claim, and value-bearing use of the Groth16 path still
requires the ADR-0025/ADR-0026 independent audit and release-assurance gates.

## Date
2026-09-06

## Risk classification
**R3.** The zero-knowledge property of every emitted Groth16 proof depends on the blinders
`(r, s)` being uniformly random and fresh per proof, and this ADR decides which code can
produce a proof without them. No soundness change: an unblinded proof still satisfies the
verification equation; the defect is confidentiality of the witness.

## Context

`Groth16ProverBLS381.proveUnblindedWithReaders(...)` was introduced with the ADR-0029 M4 mmap
prover so that the byte-equality differential tests (heap vs mmap readers, dense vs sparse key
store, pure-Java vs blst MSM, serial vs parallel MSM) could compare two proofs of the same
witness bit for bit, which needs the same `(r, s)` on both sides. It fixed `r = s = 0`, was
`public` in main source, and was documented as "for differential tests". Two independent
Groth16 review reports (K3, Grok, 2026-08-19) stated that every unblinded path is
package-private; the consolidated triage of 2026-08-20 found that claim false (C-01, P1/R3)
and issue #50 asked for a reviewed API boundary: package-private/test-only, or a conspicuous
unsafe/test-support type — and explicitly not a rename on the ordinary public surface.

At the reviewed revision the callers were exclusively tests:

| caller | module / package | purpose |
|---|---|---|
| `MmapProveBLS381Test` | zeroj-crypto / `crypto.groth16` | heap vs mmap G1 readers |
| `Groth16PkStoreTest` | zeroj-crypto / `crypto.groth16` | fresh setup vs store round-trip |
| `Groth16ProofPointResamplingTest` | zeroj-crypto / `crypto.groth16` | ADR-0045 P2 fail-closed |
| `Groth16RelationValidationTest` | zeroj-crypto / `crypto.groth16` | issue #46 ingress on every path |
| `ParallelMsmTest` | zeroj-crypto / `crypto.msm` | serial vs parallel MSM |
| `StreamingSetupDifferentialTest` | zeroj-crypto / `crypto.setup` | dense vs streaming store |
| `BlstProverBenchTest` | zeroj-crypto-blst / `crypto.groth16` | pure Java vs blst |
| `BlstStoreProveDifferentialTest` | zeroj-crypto-blst / `crypto.groth16` | store + blst G2 reader |

Package-private visibility alone (option 1 of the issue) does not cover these callers: two
live in another Gradle module and two in other packages of the same module. `zeroj-usecases`,
`zeroj-tools`, and `zeroj-integration-tests` do not reference the method (grep and a full
`compileTestJava` after removal).

### Why an unblinded proof is not zero-knowledge

Groth16 (§3.1) emits

```
A = [alpha + sum_i a_i u_i(x) + r delta]_1
B = [beta  + sum_i a_i v_i(x) + s delta]_2
C = [(sum_{i>l} a_i (beta u_i(x) + alpha v_i(x) + w_i(x)) + h(x) t(x)) / delta + A s + r B - r s delta]_1
```

and its zero-knowledge argument (§3.2, proof of Theorem 1) simulates a proof by choosing `A`
and `B` uniformly at random, which the real prover matches only because `r, s` are uniform.
With `r = s = 0`, `A` and `B` are deterministic functions of the key and the full witness:

- two proofs of the same witness are byte-identical, so an observer links them;
- `A` commits to `sum_i a_i u_i(x)` in the exponent, so a low-entropy witness (a vote, an
  amount, a small identifier) is recoverable by enumeration: compute the candidate `A` for
  each candidate witness and compare;
- the statement being proved is unchanged and the proof still verifies, so nothing at
  verification time detects the loss.

On Cardano every proof is public forever; an application that reached this path would have
published its witnesses' fingerprints on-chain.

## Threat model and trust assumptions

- **Adversary:** any observer of a proof (on-chain data is public), and an integrator who
  selects the wrong entry point of a public class while reading its Javadoc casually or not at
  all.
- **Secret:** the witness, and the blinders `r, s` (uniform in `[0, r)`, fresh per proof,
  never persisted or logged). Their sampling (`randomScalar`: 64 bytes from `SecureRandom`
  reduced modulo `r`, bias below `2^-256`) and the ADR-0045 P1 resampling loop are unchanged
  by this ADR.
- **Untrusted inputs:** none are added; the relation-validation boundary of issue #46 is
  unchanged.
- **Trust assumptions:** `SecureRandom` is a CSPRNG on the deployment platform; the runtime
  class path is the one the build produced (a deployment does not add the
  `zeroj-crypto-test-fixtures` jar; it is never published, see Z3).
- **Out of scope:** constant-time behaviour of the prover (ADR-0012/ADR-0021, triage C-16);
  PlonK blinding completeness (`b10`/`b11`, triage C-04) and the package-private PlonK
  `proveUnblinded` used by PlonK's own tests; PlonK's public `prove(..., SecureRandom)`
  overload, which takes a caller-managed CSPRNG rather than blinders and is documented as such.
  These remain tracked separately; the API-surface scan below covers the `plonk` package for
  the same name/type patterns so that a public fixed-blinder entry cannot appear there
  unnoticed either.

## Pinned normative references

- J. Groth, *On the Size of Pairing-based Non-interactive Arguments*, EUROCRYPT 2016
  (ePrint 2016/260), §3.1 (proof generation with `r, s <- F`) and §3.2 (zero-knowledge
  simulator picks `A, B` uniformly).
- arkworks `groth16/src/prover.rs` (`create_random_proof` samples `r, s` from the caller's
  RNG; there is no unblinded prover in the public API) and snarkjs `src/groth16_prove.js`
  (`r, s` from `getRandomBytes`), as the maintained reference behaviour.
- ADR-0045 (P1 resampling, P2 fail-closed unblinded path) and ADR-0036 amendment
  2026-09-05 (relation validation at every prove ingress), whose properties the moved path
  must retain.
- Gradle `java-test-fixtures` plugin semantics: test fixtures are a separate source set and
  outgoing variants; `components.java.withVariantsFromConfiguration(...) { skip() }` removes
  them from the published component.

## Security invariants

- **Z1 — every public prove path is blinded.** Each public or protected prove entry of the
  `zeroj-crypto` main artifact (`Groth16ProverBLS381.prove`, `proveWithReaders`,
  `proveWithHCoeffs`; `Groth16Keys.prove`; `Groth16Pipeline.prove`; legacy
  `Groth16Prover.prove`) obtains `(r, s)` from `secureRandomBlinders()` through the ADR-0045
  `proveBlinded` resampling loop. No public API accepts, seeds, fixes, or omits the blinders.
- **Z2 — the only fixed-blinder seam is non-public.** `proveBlinded(..., BlinderSource)` and
  `BlinderSource` (ADR-0045 forced-infinity tests) are package-private, and
  `Groth16ProverBLS381` contains no method of any visibility that fixes the blinders itself.
  No public or protected member of the `groth16` or `plonk` packages names or accepts fixed
  blinders. The package-private PlonK `proveUnblinded` seams (`PlonKProverBLS381`,
  `PlonKProver`) remain for PlonK's own tests and are tracked under triage C-04; they are not
  public and are outside this ADR.
- **Z3 — the deterministic prover is not product code.** The `(0, 0)` choice exists only in
  `Groth16UnblindedTestProver` in the `zeroj-crypto` *test-fixtures* source set; the main
  artifact has no code that sets `r = s = 0`. The published Java component of `zeroj-crypto`
  has no test-fixtures variant: the two variants are skipped at the component level, metadata
  generation fails if a variant with that name ever reappears, and `check` runs that
  generation so `./gradlew build` catches it. Test fixtures are consumed only by test
  configurations: the ADR-0044 module-surface guard fails any `api`/`implementation`/
  `compileOnly`/`runtimeOnly` project dependency that requests a test-fixtures capability. The
  fixture is loaded from a different code source than the prover.
- **Z4 — the oracle is unchanged.** The fixture reproduces the removed method's computation
  exactly: the issue #46 ingress validation via the public `computeH`, the same
  `computeProofPoints` evaluation with `(0, 0)` through `proveBlinded`, and the ADR-0045 P2
  fail-closed behaviour (the source throws on the second draw that only an infinity point
  triggers). Output is bit-identical, so every differential gate keeps its expected values.
- **Z5 — the proving surface is frozen.** The exact public method set of
  `Groth16ProverBLS381`, `Groth16Keys`, `Groth16Pipeline`, and `Groth16Prover`, and the set of
  every public or protected method in the `groth16` and `plonk` packages (nested types
  included) that returns a proof type (20 methods), are pinned by a reflection test; a new
  proof-producing public method fails the build until the allowlist is updated after a
  blinder-policy review.

## Decision

**Option 2 of issue #50, realised as "remove from the product, keep as an unpublished test
fixture":**

1. `Groth16ProverBLS381.proveUnblindedWithReaders` (public) is removed, together with the
   unused package-private heap-only `proveUnblinded` overload and the private `proveInternal`
   that fixed the blinders. The main artifact keeps no `r = s = 0` code path; the only seam
   through which a test can fix `(r, s)` is the package-private `BlinderSource` argument of
   `proveBlinded`, which ADR-0045 already introduced for the forced-infinity tests.
2. A new source set `zeroj-crypto/src/testFixtures` (Gradle `java-test-fixtures`) holds
   `com.bloxbean.cardano.zeroj.crypto.groth16.Groth16UnblindedTestProver`, a final utility
   class whose single method `proveUnblinded(...)` runs the public `computeH`, packs the
   scalars, and calls `proveBlinded` with a blinder source that returns `(0, 0)` exactly once
   and throws on a second draw — which `proveBlinded` requests only when a proof point was the
   point at infinity — so the ADR-0045 P2 fail-closed behaviour is preserved. Its name and
   Javadoc state that it is a test fixture and not zero-knowledge. It must stay in the
   prover's package because the seam is package-private.
3. `zeroj-crypto/build.gradle` skips `testFixturesApiElements` and
   `testFixturesRuntimeElements` from `components.java`, fails `GenerateModuleMetadata` if the
   generated module metadata mentions a test-fixtures variant, and makes `check` depend on
   that generation. The root `verifyDefaultModuleSurface` (ADR-0044) additionally fails any
   runtime-scoped project dependency that requests a test-fixtures capability.
   `zeroj-crypto-blst` consumes the fixture with
   `testImplementation testFixtures(project(':zeroj-crypto'))`; the `zeroj-crypto` test source
   set sees it automatically.
4. `Groth16ProverApiSurfaceTest` (zeroj-crypto) enforces Z1–Z3 and Z5 (details below).
5. R0 cleanup in the same change: the unused BN254 `Groth16Prover.proveUnblinded` and its
   stale comment are removed, so the legacy curve has no unblinded path either.

### Alternatives considered

1. **Package-private only (issue option 1).** Rejected: four of the eight callers are in other
   modules or packages; satisfying them would mean moving differential tests into the prover
   package or duplicating the prover, and would leave the cross-module blst differential
   without an oracle.
2. **Public "unsafe" type in main source behind a system property**, modelled on
   `TrustedSetupPolicy`. Rejected: it still ships a non-zero-knowledge prover in the product
   jar, and a JVM property copied from a test configuration is exactly the accidental path
   the issue asks to close. The insecure-setup gate exists because a local single-party
   setup is a legitimate developer flow; unblinded proving has no legitimate non-test use.
3. **Rename/deprecate on the public surface.** Explicitly excluded by the issue.
4. **A separate support project** (e.g. under `zeroj-test-vectors`). Rejected: the seam must
   stay package-private, so the fixture must be a source set of `zeroj-crypto`.
5. **Injectable RNG or seed on the public prove API.** Rejected: it would put a deterministic
   mode on the public surface (the same footgun with a different name), and `SecureRandom`
   seeding semantics are provider-dependent, so "deterministic" would not even be portable.
6. **A dedicated package-private `proveUnblinded` seam in main** (the first draft of this
   change, reviewed 2026-09-06). Rejected: it kept an `r = s = 0` code path and a second
   fixed-blinder seam in the product jar although the `BlinderSource` seam already existed;
   with the fixture type holding the `computeH`/pack prologue once, the existing seam suffices
   and the product jar carries no fixed-blinder code at all.

## Consequences

- No public API of `zeroj-crypto` can produce an unblinded Groth16 proof. The differential
  tests keep a supported deterministic oracle with unchanged expected values.
- `zeroj-crypto` now has a test-fixtures source set. It is not published; the ADR-0044
  module-surface guard sees only a test-scoped `zeroj-crypto` edge from `zeroj-crypto-blst`.
- The fixture and the prover form a split package across two jars (`zeroj-crypto.jar`,
  `zeroj-crypto-test-fixtures.jar`) on the test class path. ZeroJ has no `module-info`, so
  this resolves on the class path exactly as the existing same-package tests in
  `zeroj-crypto-blst` already do. If ZeroJ adopts JPMS, this seam needs a redesign (the
  fixture moves into the `zeroj-crypto` test source set and the blst differential needs
  another route); that is recorded here as a known constraint.
- `Groth16ProverApiSurfaceTest` makes adding a public method to the four facade classes, or a
  public proof-returning method anywhere in the `groth16`/`plonk` packages, a deliberate act:
  update the allowlist in the same change and confirm the method draws its blinders from
  `secureRandomBlinders()` (or, for PlonK, a fresh or caller-supplied `SecureRandom`).
- The ADR-0044 module-surface guard now also rejects test-fixture edges in runtime
  configurations, and `check` runs the metadata guard, so `./gradlew build` catches both
  leak classes without a publish.

## Compatibility

- **Source-incompatible removal:** `Groth16ProverBLS381.proveUnblindedWithReaders`. No
  consumer in `zeroj-usecases`, `zeroj-tools`, or `zeroj-integration-tests`; downstream code
  that called it was producing non-zero-knowledge proofs and must switch to a public path.
  The published artifacts are pre-1.0 (the last published version is `0.1.0-pre11`); no
  relocation is provided because offering one would preserve the footgun.
- **Proof bytes:** unchanged on every public path (blinders were already random there).
- **Test fixture output:** bit-identical to the removed method (same body).
- **Key, store, cache, wire formats:** unchanged.
- **BN254 legacy:** `Groth16Prover.proveUnblinded` removed (unused, package-private).
  `Groth16Prover.prove` is unchanged.

## Implementation milestones (single change)

- **M1** — fixture on the `BlinderSource` seam + Gradle wiring (`java-test-fixtures`, skipped
  variants, metadata guard on `check`, module-surface fixture-edge check, blst test
  dependency).
- **M2** — migrate the eight test call sites; `compileTestJava` across every module confirms
  no other caller.
- **M3** — `Groth16ProverApiSurfaceTest`.
- **M4** — documentation: this ADR; ADR-0036 and ADR-0045 cross-references; the Groth16
  developer guide's expert-layer section; `zeroj-crypto` README; the README ADR list; prover
  Javadoc.

## Verification and test-vector strategy

- **Frozen surface (Z1, Z5):** `Groth16ProverApiSurfaceTest.publicProverFacadeIsExactlyTheAllowlistedSurface`
  compares the exact public `(name, parameter types)` set of the four facade classes with an
  allowlist; `proofProducingPublicMethodsAreExactlyTheAllowlist` does the same for every
  public/protected method of the `groth16` and `plonk` packages (nested types included) whose
  return type is `Groth16ProofBLS381`, `Groth16Proof`, `PlonKProofBLS381`, or `PlonKProof`
  (20 methods at this revision). Limit: a public method returning something other than a
  proof type is caught only by the name/`BlinderSource` scan below.
- **Package scan and seams (Z2, Z3):** `noPublicMemberOfTheProverPackagesNamesOrAcceptsFixedBlinders`
  enumerates every class of the `groth16` and `plonk` packages from the prover's code source
  (directory or jar), asserts the scan is non-vacuous, and fails on any public/protected
  member whose name contains `unblinded`, `deterministic`, `fixedblinder`, `withblinders`,
  `noblind`, or `zeroblind`, or that accepts a `BlinderSource`; it also asserts the fixture is
  not among the main classes. `blinderSeamsAreNotPublicAndMainHasNoFixedBlinderPath` checks
  `BlinderSource` and `proveBlinded` by reflection and that `Groth16ProverBLS381` declares no
  method (of any visibility) with a fixed-blinder name; `unblindedTestProverIsNotShippedWithTheProver`
  checks that the code-source locations differ (the guarantee) and that the fixture's path
  contains `testFixtures` (a sanity net for Gradle-driven runs).
- **Behaviour (Z1, Z4), independent of the prover:** with the explicit-randomness setup and
  the test-side Lagrange evaluation (`Groth16InfinityIcProfileTest.lagrangeAt`), the test
  computes `[alpha + sum a_i u_i(tau)]_1` and `[beta + sum a_i v_i(tau)]_2` directly from the
  generators. Twenty-two proofs — two from each of the eleven public BLS12-381 prove entry
  points (`Groth16ProverBLS381` ×6, `Groth16Keys` ×3, `Groth16Pipeline` ×2, the latter with a
  null fingerprint against the unbound in-heap key) — must all differ from those points and
  from each other in `A`, `B`, and `C`, and pairing-verify; the fixture must reproduce exactly
  those points, be byte-deterministic across calls, differ from a public-path proof of the
  same witness, and pairing-verify. The legacy BN254 `Groth16Prover.prove` overloads are
  checked for distinct `A`/`C` across four calls only; no independent unblinded reference is
  computed for BN254. PlonK is out of scope (C-04).
- **Publication (Z3):** `:zeroj-crypto:generateMetadataFileForMavenJavaPublication` and
  `generatePomFileForMavenJavaPublication` produce only `apiElements`, `runtimeElements`,
  `javadocElements`, `sourcesElements`; with the two `skip()` lines temporarily removed the
  guard fails the task, and with the blst edge temporarily changed to
  `implementation testFixtures(...)` `verifyDefaultModuleSurface` fails (both verified once by
  hand, 2026-09-06). After `publishToMavenLocal` the version directory must contain no
  `-test-fixtures` jar.
- **Differential gates re-run unchanged:** `MmapProveBLS381Test`, `Groth16PkStoreTest`,
  `ParallelMsmTest`, `StreamingSetupDifferentialTest`, `Groth16ProofPointResamplingTest`,
  `Groth16RelationValidationTest` (zeroj-crypto); `BlstProverBenchTest`,
  `BlstStoreProveDifferentialTest` (zeroj-crypto-blst).
- **Wider gates:** `./gradlew build` and `verifyDefaultModuleSurface`; `publishToMavenLocal`
  followed by the `zeroj-usecases` Groth16 suites against the snapshot.

## Production / audit gates (unchanged by this ADR)

- Independent review of the Groth16 path (ADR-0025/0026) before any value-bearing use; the
  reviewer should confirm Z1 by reading `secureRandomBlinders`/`randomScalar` and the
  `proveBlinded` loop, not from this test alone.
- The blinders' uniformity is argued, not measured: the test detects `r = 0` or `s = 0` and
  repeated `(r, s)`, not statistical bias.
- Triage C-16 (variable-time prover) still bounds where a prover may run.

## Risks

- A downstream project that used the removed method for reproducible proofs loses that
  ability by design. The fixture is deliberately unavailable to published consumers.
- The allowlist test adds friction to API evolution of four classes. That friction is the
  control the issue asked for; the cost is one line per new method.
- The split-package arrangement depends on class-path loading (see Consequences).
