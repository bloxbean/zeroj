# Independent review of SHA-2 circuit optimization

Date: 2026-10-29. Reviewer: a separate AI agent, not an implementation author.
Baseline: `3f1570f33ef2f45d26abeaf6085de5a2dc7a1c5e`. Governing design:
[ADR-0063 optimization extension](../adr/0063-sha256-gadget-and-sha2-assurance.md).

## Result and scope

No blocking correctness or soundness defect was identified in the reviewed production
changes. This conclusion is bounded to source inspection and the checks below; it is
not a formal proof, external cryptographic audit, timing-side-channel review or
production approval. The final integration must also pass the separately reported full
regression, independent proof checks and comparative benchmark gates.

The review covers both SHA gadgets, `CircuitAPIImpl`, `Gate`, `WitnessCalculator`,
`R1CSCompiler`, `PlonKCompiler`, `Halo2Compiler`, and the new Boolean/SHA optimization
tests. Existing source consumers of the sealed graph gate type were searched for
missing handling. No missing in-repository production consumer was found.

## Relation and bounds review

- **Majority:** the actual code reuses `ab` in `ab + c*(a+b-2*ab)`. For Boolean
  inputs this equals the original majority function, including the `111` case.
  The SHA inputs and decomposed state words establish Booleanity; XOR, choice and
  majority preserve it algebraically. The helper is package-private for testing,
  not a new public arbitrary-field majority API.
- **Deferred round sums:** `T1` retains five bounded word addends and `T2` two.
  `T1+d` and `T1+T2` have six/seven addends, respectively, hence are strictly below
  `2^(w+3)`. SHA-256 uses 35-bit decompositions and SHA-512 67-bit decompositions
  at these outputs. Every supported scalar field is larger than those bounds.
  The code decomposes the entire sum, then returns only the low word. It does
  not discard an unconstrained carry, weaken a bit range, or reinterpret a field
  residue as an unbounded integer. Message-schedule and feed-forward reductions
  retain their own sufficient widths. No reduction is deferred across a round
  boundary where the next round requires bits.
- **Standard SHA statement:** rounds, IVs, constants, rotations, message schedule,
  padding, length suffix and full digest order are unchanged. The algebraic
  changes preserve the FIPS computation; they do not change its security parameter.
- **Boolean assertion:** the explicit gate has no witness hint or auxiliary result.
  R1CS emits `b*(b-1)=0`; PlonK/Halo2 emit the corresponding selector equation with
  the same wire in both multiplicative columns. Existing permutation/copy handling
  connects those occurrences. Boxed, flat and chunked witnesses share the same
  evaluator and reject non-Boolean field values.
- **Compiler expression handling:** the Boolean expression is consumed once and
  reused locally for both R1CS factors. Later uses remain in the read-count plan.
  Constant folding eliminates only assertions of zero/one; invalid constants remain
  unsatisfiable. Resource estimates cover both row factors, and pressure mode
  materializes a live expression before consumption. No arbitrary row matcher or
  auxiliary-liveness elimination is introduced.
- **Lifecycle:** the explicit assertion retains the pre-cache frozen-graph guard
  and per-wire idempotency. Field compatibility checks remain at direct compiler
  and witness entry points. This change does not broaden the existing variable-
  ownership contract or claim constant-time witness/prover execution.

## Independent executable check

A standalone Java review program ran with `-Xmx6g` and four active processors against
the built candidate classes. It independently constructed digest-limb circuits,
computed expected digests with JCA, and evaluated each complete R1CS directly rather
than treating successful witness generation as sufficient evidence.

**18 positive cases passed:** SHA-256/SHA-512 on each of BLS12-381, BN254 and Pallas,
at message lengths `0,17,129` / `0,17,257` bytes. Nonempty messages used byte
`(149*i) XOR 0xff`, providing high-bit inputs and multiblock cases. This explicitly
exercised the complete SHA-512/Pallas relation, not just its majority helper.

**78 direct witness mutations were rejected:** every public digest limb was changed
separately (54 checks), and every nonempty profile's first private byte was replaced
by `256` and `Fr-1` (24 checks). The observed maximum heap was 6,442,450,944 bytes.
This is an additional ad hoc review check, not a replacement for the permanent
NIST/JCA, carry/bit mutation and independent proof suites.

The permanent new tests were inspected for the following distinct obligations:
exhaustive majority truth tables, malicious input/output values, high-carry patterns
across padding boundaries, sampled final round carry/low-bit mutations, raw graph
Boolean gates, supported fields, invalid constants, all compiler backends, expression
inlining policies and pressure-mode input binding. Their mutation sets are bounded;
they are not exhaustive searches over every malicious intermediate assignment.

## Compatibility observation

The public sealed `Gate` interface gains a permitted subtype. Downstream code with
an exhaustive gate switch must handle `AssertBoolean` and rebuild. Graph wire counts,
compiled relations and circuit fingerprints change. Existing circuit-specific keys,
ceremony artifacts and proofs must not be reused for the optimized relations. This
is a migration requirement, not a cryptographic vulnerability.

No proving-speed, memory-improvement or reduced Cardano-fee conclusion is made by this
review. Those require the separate controlled baseline/candidate measurements.

## Reviewed production source identities

SHA-256 of the working-tree source files inspected during this review:

| File | SHA-256 |
|---|---|
| `Sha256.java` | `76089dca42c5f18e952db1af4abf21194def1d38c9f808f3144a3e148cc39f18` |
| `Sha512.java` | `dddc62aadf03223fc10ce2f659e11ccd12a0d9069ab2c0bdbfdf70f76c05ccb9` |
| `CircuitAPIImpl.java` | `ad9df73d05473b92e8480e104f0c741fc8fa39cae0361a84202d8cf079bc551b` |
| `Gate.java` | `ecc1d0489a906ae4e8f8ef33f23738255d1301fc4f5bdc8cd2c857a7e338a7f2` |
| `WitnessCalculator.java` | `92f207eed9811c4eae3a72d685ba6cc75227d8513b72d0c202ccfe24359212c6` |
| `R1CSCompiler.java` | `ec2bc772acf7558be90d74d1dae06811a1a836e18e0e03c47fea42d366b52c90` |
| `PlonKCompiler.java` | `6a79130c6f884d4c416cd0f764a09cacaadfae131b3036fd214d2e9bfee47d8a` |
| `Halo2Compiler.java` | `be3c47ef21e7ae2e6f9ca544cc0108c9c9f80c3dcdff902addbe7b9294856c51` |

## Benchmark-method review before measurements

The optional `assurance/sha2-optimization` harness was independently inspected before
the timed matrix. No heavy benchmark was run by this reviewer. No blocking fairness,
proof-relation or measurement-labeling defect was identified in its source.

- Both checkouts compile the same external harness against their own project
  dependencies. The runner records source, harness, runtime artifact and Java
  executable hashes and checks them before and after each sequential process.
- Each case constructs the actual library gadget, binds the complete JCA digest as
  two/four big-endian 128-bit public limbs, and uses fresh development setup. Every
  randomized proof must pass strict verification; changed public limbs and a
  canonical negated-A proof must fail. The optional pinned snarkjs oracle checks all
  retained randomized proofs and independently recomputes the digest with Python.
  Honest-proof success remains distinct from the malicious-witness relation tests.
- Setup/compile/first-witness are single observations. Proving medians omit the
  first-call warmup; one warmup does not establish full JIT stabilization, and three
  samples do not establish a general speedup. Alternating pair order reduces one
  source of bias but does not remove thermal, filesystem-cache or host-load effects.
- The heap sampler measures simultaneous usage, labels possible missed peaks, and
  retains separate pool peaks without adding them. RSS is explicitly separate;
  macOS bytes and Linux KiB conversion are correct. Key-store bytes include all
  files; temporary proving keys close and are removed on the ordinary completion
  path. Abrupt termination and severe resource exhaustion can require manual cleanup.
- Nonzero process exits, OOMs and timeouts are failed profiles; remaining profiles
  continue. Timeout cleanup kills the owned POSIX process group. Independent oracle
  crashes are not counted as proof rejection. Source/runtime changes stop the matrix.

**Resolved hardening observation:** `run.py` now requires each successful result's
effective maximum heap to equal the requested **6,442,450,944** or **8,589,934,592**
bytes and its effective processor count to match the experiment. An environment
override that changes either value fails the profile. Malformed JSON, missing
result fields and incompatible JSON types are recorded as failed profiles rather
than interrupting the matrix. The README accurately documents the control check.
Seven lightweight mocked-process checks independently exercised both valid heap
caps, a mismatched heap, a mismatched processor count, malformed JSON, missing fields
and a JSON array in place of an object. All seven produced the expected pass/fail
status and persisted it in `process.json`; no JVM or benchmark was launched.

Reviewed harness identities (SHA-256):

| File | SHA-256 |
|---|---|
| `run.py` | `9a91bf5add47832bfb7b27769539ab2e3ce876488da9d6e1c7bc1d8d5d4a1102` |
| `benchmark.gradle` | `9a36bb1efea63779d163324b163d064ff3a44f35da395f496c52140d9950a43f` |
| `Sha2OptimizationBenchmark.java` | `431005bedf76a00dbbbf15854c86a476b06d4f9f443701877b9cc6d3f0f8e112` |
| `README.md` | `19213e525b297fe4b42a8fc2b19e7ab686faf89c3bbd3188cbf67164f4766a19` |

## Final deterministic-pin migration review

The final diff of all 13 existing test files with updated cost/relation pins was
inspected, together with the migration evidence and ADR/DSL documentation. No
security assertion or acceptance threshold was removed or relaxed. An independent
source comparison also confirmed identical non-literal code structure and
assertion-call sequence in these files. The separate `InCircuitJubjub` production
diff changes cost comments only.

The confidential-note test retains stale-key proving rejection and dimension-
fingerprint inequality. Its revised comments correctly identify the legacy helper
as a comparator-bearing gadget relation compiled with the current compiler, not
the byte-identical historical R1CS. Valid-proof, binding, tampering, unbalanced-
witness and wraparound assertions are unchanged.

All **27** JMT/MPF migration records were independently parsed and compared against
both baseline and candidate test sources, per template: rows, wires, canonical hash,
public-input count and private-input count match. Template identifiers, input
schemas, profile assertion helpers and adversarial tests remain unchanged. Exact
hash assertions are retained; new keys remain mandatory despite stable semantic
template names. This check verifies the evidence transcription and test scope,
not the compiler's computed output. The coordinated full regression run supplies
that separate evidence; no heavy test was launched for this review.

Reviewed final additional test identities (SHA-256):

| File | SHA-256 |
|---|---|
| `ConfidentialNoteOnChainTest.java` | `f50d497055790bcb0d1a466c70942426d4dbc8c63551080358c059666ccaa7b3` |
| `ZkJmtOperationCircuitTest.java` | `abb1800aca3c593ee175adf97d6ebcf92391cc8ff493c779e7c6b3f2183aab43` |
| `ZkMpfOperationCircuitTest.java` | `2f2868a825267984433bef04c6e1bd01c56f445da0bc5ce4e67b94db155a3a46` |
| `ZkMpfTransitionCircuitTest.java` | `3643d217392b7f8271c9a54ca43c69f197a89c2e54f81f781d121481591f5e2b` |

## Final retained-evidence and report audit

The completed results report, evidence README, four benchmark summaries and oracle
verdict sets, Cardano records/provenance, and updated tutorial were independently
reviewed. No defect was identified in this final evidence/report check.

- All **861** retained-manifest entries and **628** per-process artifact hashes
  matched. The four summaries recomputed exactly from their underlying records.
- All **44 benchmark JVMs** reported the requested effective 6/8 GiB maximum heap
  and eight processors. Their verification-key hashes were distinct. The recorded
  candidate production-source and harness hashes still matched the current files.
- Oracle records contain exactly **184 accepted randomized proofs and 180 rejected
  invalid fixtures: 364 passing checks**, using pinned snarkjs 0.7.6. Message digests
  and complete public limbs were independently recomputed from the retained fixtures.
- Structural, proof-time, other-stage, memory and native-provider tables match the
  raw summaries and their stated rounding. The primary 11/12 pure-Java and 7/8 native
  improvement counts are correct. Original timing and memory regressions remain
  visible alongside separate repeats; no universal performance improvement is claimed.
- The **four additional Cardano JVMs** have matching heap settings, confirmed-spend
  records, eight rejected VM negatives each and signed-invalid-submission records.
  Reported budgets/fees match the Haskell records; retained transaction/script byte
  lengths match the tables. Proof inputs match the optimized benchmark artifacts.
  Current verifier-library, validator and codec source hashes match provenance.
- Tutorial measurements contain ZeroJ numbers, distinguish the measured 32-byte
  preimage from the 48-byte approval policy, and retain local-devnet, development-
  setup, security and performance limits. Relative evidence/report links resolve.

This was a read-only consistency and source/provenance audit by an AI reviewer,
not an external cryptographic audit or a rerun of proof generation, independent
verification, ledger submissions or browser layout inspection. No heavy workload
was launched for this final check.
