# Boolean assertion cost-pin migration

Date: 2026-10-29. Scope: the ten deterministic cost-pin failures in nine circuit-lib
classes exposed by ADR-0063's direct Boolean assertion gate. No curve, signature,
commitment or encryption production code was changed in this migration. The SHA
majority and deferred-sum changes do not occur in these circuits.

## Why the relation is retained

The previous lowering constrained `t = b*(b-1)` and then `t = 0`. The new explicit
assertion constrains `b*(b-1) = 0` directly. Over the supported prime fields this
still permits exactly zero and one. No Booleanity, range, canonicality, subgroup,
public-input or output condition is removed. Constant zero/one assertions may fold;
non-Boolean constant assertions remain unsatisfiable. For these measured R1CS
relations every removed auxiliary-product/assertion row accounts for three fewer
sparse matrix terms. There is no general row-pattern optimization.

The source assertions and adversarial cases in the affected gadget tests remain
unchanged. Only deterministic expected costs, corresponding display text and
comments were updated. The dedicated DSL Boolean-assertion tests additionally check
malicious witnesses against compiled R1CS, PlonK and Halo2 equations, including
expression operands, constants, raw gates and pressure-policy materialization.

These are equivalent input/output relations with different internal shapes.
Graph identities, auxiliary wire numbering and circuit-specific setup/proof keys
must be regenerated. This migration is not an independent cryptographic audit.

## Exact pin changes

Old values below are the assertions at baseline commit `3f1570f`. New values were
measured from the compiled candidate and then checked by the focused test run.
The complete baseline windowed-cost test was also rerun and passed, reconfirming
both old scalar-multiplication paths and their sparse-matrix/domain pins. A dash
means that metric was not pinned by the existing test; it is not a zero.

| Circuit/path | R1CS rows before | R1CS rows after | Nonzeros before | Nonzeros after |
|---|---:|---:|---:|---:|
| Raw-coordinate subgroup assertion | 5,556 | 5,304 | — | — |
| 252-bit windowed fixed-base multiply, including decomposition | 1,506 | 1,254 | 7,865 | 7,109 |
| 252-bit bitwise fixed-base reference, including decomposition | 2,513 | 2,261 | 638,804 | 638,048 |
| EdDSA verifyCore | 8,929 | 7,657 | 364,200 | 360,384 |
| EdDSA registered-key verifier | 8,962 | 7,690 | 364,342 | 360,526 |
| EdDSA strict verifier | 14,500 | 12,976 | 705,251 | 700,679 |
| Complete Pedersen commitment, 64/252 bits | 2,410 | 1,841 | 11,683 | 9,976 |
| Complete Pedersen commitment, 252/252 bits | 4,042 | 3,032 | 19,338 | 16,308 |
| Subgroup assertion on established affine point | 5,547 | 5,294 | 341,190 | 340,431 |
| witnessInSubgroup | 5,547 | 5,294 | — | — |
| Balanced transfer, two inputs/one output plus fee | 7,284 | 5,545 | 35,244 | 30,027 |
| Vector commitment, dimension 1, 64-bit values | 2,411 | 1,842 | 11,686 | 9,979 |
| Vector commitment, dimension 4, 64-bit values | 3,581 | 2,820 | 17,755 | 15,472 |
| Vector commitment, dimension 16, 64-bit values | 8,261 | 6,732 | 42,031 | 37,444 |
| ElGamal encryption, fixed key, 1-bit message | 6,558 | 6,305 | — | — |
| ElGamal encryption, fixed key, 16-bit message | 6,650 | 6,382 | — | — |
| ElGamal encryption, fixed key, 64-bit message | 6,938 | 6,622 | — | — |
| ElGamal encryption, witnessed key, 1-bit message | 12,105 | 11,600 | — | — |
| ElGamal DLEQ | 6,546 | 6,294 | — | — |

`JubjubCleanupP5Test` and `WindowedFixedBaseTest` both pin the same 1,254-row
complete multiplication. The `witnessAffine` and `assertWellFormed` pins remain
5 and 13 rows. The tagged challenge cost also remains unchanged.

The ElGamal test already prints nonzeros without asserting them. The candidate
measurements are respectively 347,077; 346,753; 348,113; 687,258; and 346,026.
No unmeasured baseline nonzero counts are inferred here.

| Existing domain/backend pin | Before | After |
|---|---:|---:|
| verifyCore row-derived padded R1CS domain | 16,384 | 8,192 |
| Registered-key row-derived padded R1CS domain | 16,384 | 8,192 |
| Strict row-derived padded R1CS domain | 16,384 | 16,384 |
| Windowed row-derived padded R1CS domain | 2,048 | 2,048 |
| Bitwise row-derived padded R1CS domain | 4,096 | 4,096 |
| Registered-key PlonK gates, including three public anchors | 32,563 | 28,747 |
| Registered-key Halo2 rows | 32,560 | 28,744 |
| Registered-key PlonK/Halo2 domain | 32,768 | 32,768 |

The row-derived domain pins are powers of two calculated from the row count in
these tests, not a claim about every backend's complete setup-domain policy.
PlonK/Halo2 retain equal wire counts and public-input counts, the three-row public
anchor difference, and their existing advice/selector-column assertions.

## Windowing comparison

Both paths lose exactly 252 rows and 756 terms because they share the same
252-bit decomposition. Windowing's absolute advantage stays at 1,007 rows and
630,939 terms. Its relative row saving increases from approximately 40.1% to
44.5%. The existing `windowed < bitwise` assertion was retained unchanged, as
were the 2,048/4,096 domain pins. No threshold was relaxed. The registered-versus-
strict verifier's existing `strict - registered > 5,000` condition also remains
unchanged and passes with a difference of 5,286 rows.

## Reproduction and validation

From the candidate worktree:

```sh
./gradlew :zeroj-circuit-lib:test \
  --tests '*InCircuitJubjubSubgroupTest' \
  --tests '*JubjubCleanupP5Test' \
  --tests '*JubjubSoundnessM1Test' \
  --tests '*JubjubVerifierM3Test' \
  --tests '*WindowedFixedBaseTest' \
  --tests '*PedersenHidingSafeApiTest' \
  --tests '*PedersenHomomorphicApiTest' \
  --tests '*PedersenVectorApiTest' \
  --tests '*ZkElGamalTest' --max-workers=2
```

Result: **119 tests, zero failures/errors/skips**, using the module's existing
4 GiB test maximum heap, within the user's 6 GiB ceiling for this verification.
The run completed successfully in seven seconds; this is a regression run,
not a controlled proof-performance benchmark. Temporary measurement prints used
to collect assertions hidden behind earlier failures were removed before this run.

From the baseline worktree checked out at `3f1570f`:

```sh
./gradlew :zeroj-circuit-lib:test \
  --tests '*WindowedFixedBaseTest.windowedIsCheaper' --max-workers=2
```

Result: one test, zero failures, under the same 4 GiB test cap. `git diff --check`
passes. Full repository regression and timed 6/8 GiB proof matrices are separate
parent-coordinated acceptance gates; these local results do not replace them.

## Confidential-note integration pins

The subsequent full `--continue` build reached the confidential-note Plutus VM
integration test and exposed two further row pins. Its completed
`TEST-org.zeroj.examples.pedersen.ConfidentialNoteOnChainTest.xml` recorded these
actual values before the test updates:

| Confidential-note circuit | Rows before | Rows after |
|---|---:|---:|
| Current reference split circuit | 7,231 | 5,524 |
| Earlier comparator-bearing gadget relation, rebuilt with the current compiler | 8,755 | 6,289 |

The reference's 8,192 evaluation-domain assertion is retained. The comparison
helper deliberately reinstates a redundant 252-bit `< l` comparator for each
64-bit amount. It recreates the earlier gadget-level relation, while using the
current direct Boolean lowering; it does **not** reproduce byte-identical
historical R1CS or historical key material. Its test comments now state this
boundary explicitly.

The key/witness mismatch rejection and the pipeline dimension-fingerprint
inequality assertions are unchanged, as are all valid-proof, tampering,
authorization/binding, unbalanced-witness and wraparound tests. A dimension label
is only one part of current production pipeline fingerprints, which additionally
bind exact R1CS content; the test comment does not claim dimension-only identity
is generally sufficient.

The final full build passed both corrected pins and the stale-key rejection and
fingerprint assertions, together with the module's other security tests.
The integration module's ordinary test JVM has a 2 GiB maximum heap;
`git diff --check` also passes.

## JMT and MPF exact relation identities

The full `--continue` build also exposed four profile-pin tests whose first old
row/hash assertion stopped later profiles from being observed. A focused measurement
run compiled all **27** profiles: nine JMT operations, seven MPF inclusion bounds,
two MPF non-inclusion forms and nine MPF transitions. It captured actual rows, wires,
public/private input arities and `R1CSFlatIO.canonicalSha256` values.

The complete old/new row, wire and **full canonical SHA-256** values are retained in
[the machine-readable profile migration evidence](sha2-optimization-profile-migration.json).
Old values are the strict source pins at `3f1570f`, not fresh baseline measurements.
All public/private input arities remain unchanged.

| Template | Rows before → after | Wires before → after |
|---|---:|---:|
| `zeroj-jmt-v1-inclusion-s0-p1` | 2,095 → 1,455 | 5,605 → 3,685 |
| `zeroj-jmt-v1-inclusion-s8-p1` | 10,069 → 9,421 | 51,614 → 49,670 |
| `zeroj-jmt-v1-inclusion-s64-p1` | 65,901 → 65,197 | 373,670 → 371,558 |
| `zeroj-jmt-v1-non-inclusion-empty-s8-p1` | 9,829 → 9,181 | 50,200 → 48,256 |
| `zeroj-jmt-v1-non-inclusion-different-leaf-s8-p1` | 11,976 → 10,688 | 55,678 → 51,814 |
| `zeroj-jmt-v1-value-update-s8-p2` | 18,067 → 17,419 | 98,541 → 96,597 |
| `zeroj-jmt-v1-insert-empty-s8-p2` | 17,822 → 17,174 | 97,120 → 95,176 |
| `zeroj-jmt-v1-insert-different-leaf-s8-p2` | 86,602 → 85,146 | 489,835 → 485,464 |
| `zeroj-jmt-v1-tombstone-update-s8-p3` | 18,067 → 17,419 | 98,541 → 96,597 |
| `zeroj-mpf-v1-inclusion-s0-p1` | 3,575 → 3,051 | 14,831 → 13,259 |
| `zeroj-mpf-v1-inclusion-s1-p1` | 9,699 → 8,921 | 48,429 → 46,095 |
| `zeroj-mpf-v1-inclusion-s3-p1` | 21,433 → 20,163 | 115,559 → 111,749 |
| `zeroj-mpf-v1-inclusion-s8-p1` | 50,768 → 48,268 | 283,384 → 275,884 |
| `zeroj-mpf-v1-inclusion-s9-p1` | 56,635 → 53,889 | 316,949 → 308,711 |
| `zeroj-mpf-v1-inclusion-s12-p1` | 74,236 → 70,752 | 417,644 → 407,192 |
| `zeroj-mpf-v1-inclusion-s64-p1` | 379,321 → 363,045 | 2,163,024 → 2,114,196 |
| `zeroj-mpf-v1-non-inclusion-empty-s8-p1` | 47,397 → 45,165 | 269,978 → 263,282 |
| `zeroj-mpf-v1-non-inclusion-different-leaf-s8-p1` | 54,766 → 50,881 | 291,445 → 279,787 |
| `zeroj-mpf-v1-value-update-s8-p2` | 82,651 → 80,119 | 517,099 → 509,503 |
| `zeroj-mpf-v1-insert-empty-s8-p2` | 81,449 → 78,917 | 510,025 → 502,429 |
| `zeroj-mpf-v1-insert-different-leaf-s8-p2` | 105,646 → 100,973 | 640,109 → 626,087 |
| `zeroj-mpf-v1-value-update-s9-p2` | 92,353 → 89,571 | 578,994 → 570,648 |
| `zeroj-mpf-v1-insert-empty-s9-p2` | 91,151 → 88,369 | 571,920 → 563,574 |
| `zeroj-mpf-v1-insert-different-leaf-s9-p2` | 115,348 → 110,425 | 702,004 → 687,232 |
| `zeroj-mpf-v1-value-update-s12-p2` | 121,459 → 117,927 | 764,679 → 754,083 |
| `zeroj-mpf-v1-insert-empty-s12-p2` | 120,257 → 116,725 | 757,605 → 747,009 |
| `zeroj-mpf-v1-insert-different-leaf-s12-p2` | 144,454 → 138,781 | 887,689 → 870,667 |

Template names identify the semantic/schema version, operation, branch/depth bound
and public-input arity. Those meanings and the Poseidon/tree semantics are unchanged.
A template name is not an exact R1CS identity. Direct Boolean lowering changes the
canonical relation hash and auxiliary-wire layout; circuit-specific setup keys,
proof artifacts and exact-R1CS-bound caches require regeneration. Historical
research caches and baseline pins were not rewritten or relabeled.

All original strict name, row, wire, arity and canonical digest assertions are
restored with measured constants. The separate canonical-versus-full-semantics
digest inequality and every range, padding, membership, mutation and state-transition
test remain intact. Temporary instrumentation suppressed only early profile-cost
assertion aborts to collect all profiles; it was removed before handoff and was
not treated as evidence that the final strict tests or security suite had passed.

Measurement command:

```sh
./gradlew :zeroj-jmt-poseidon:test \
  --tests '*ZkJmtOperationCircuitTest.templateIdsDigestsAndConstraintProfilesArePinned' \
  :zeroj-mpf-poseidon:test \
  --tests '*ZkMpfOperationCircuitTest.branchProfileConstraintCountsArePinned' \
  --tests '*ZkMpfOperationCircuitTest.canonicalTemplateIdentityBindsOperationAndExactR1cs' \
  --tests '*ZkMpfTransitionCircuitTest.transitionTemplateIdentitiesAndReleaseProfilesArePinned' \
  --max-workers=2
```

The four instrumented measurement methods completed successfully in 27 seconds
under the modules' existing 1 GiB test maximum heaps. This is profile measurement,
not a proof-performance benchmark. `git diff --check` passes. Final validation: **`./gradlew build --continue --max-workers=2` passed**, including
all restored strict JMT/MPF pins and the default security regression suites. The
confidential-note stale-key rejection, fingerprint inequality and cost pins also passed.
