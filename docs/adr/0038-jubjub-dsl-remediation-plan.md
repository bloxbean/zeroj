# ADR-0038: Jubjub and DSL Remediation Plan (post-ADR-0037 review)

## Status
**Implemented through P7.** See the amendment notes in Decisions 1, 3 and 4. P7 closes the
distributed-fan-out counterexample, corrects the raw scalar timing analysis, adds
multiple-of-`l` scalar blinding, restores a public Pedersen verification path, repairs the
benchmark, and adds local projective-predicate guards. Incorrect claims are retained only when
explicitly marked superseded, so this document records why plausible earlier rationales failed.

## Date
2026-07-26 (P7 amendment 2026-07-27)

## Context

ADR-0037 shipped M0–M5 and a security review that reported no HIGH or MEDIUM findings. A
subsequent independent review (Codex) found **two soundness defects and one performance
regression that the earlier passes missed**. Both soundness defects were verified directly
against the code before this plan was written.

Two of the three are defects in code ADR-0037 itself introduced, and one is a documentation
claim ADR-0037 introduced that is **false**. That is the more serious pattern: the M4
documentation rewrite replaced an accurate "not production-ready" warning with an assertion
of a safety property that does not hold.

Separately, a closer look at the constant-time restriction identified the specific published
attack that applies, which ADR-0037's addendum described only in general terms.
A final related-component cross-check also found that off-circuit Pedersen commitment
generation uses the same variable-time scalar multiplication for secret inputs.

### What the review found, verified

| # | Finding | Severity | Verified |
|---|---|---|---|
| 1 | `ZkJubjubPoint.fromTrustedAffine` sets `Z=1`, `T=u·v` but **never asserts the curve equation**; `assertWellFormed()` checks four ordinary field values and adds no point constraints | High | Confirmed by reading both methods. An off-curve `(u,v)=(1,1)` is accepted |
| 2 | `BitDecomposition` binds `source`, `width`, `bits` but **not the circuit that emitted the constraints**. Wire ids restart per circuit, so a decomposition from circuit A is accepted as evidence about unrelated same-id wires in circuit B | High | Confirmed: the class has exactly three fields, and `lessThan(BitDecomposition, BitDecomposition)` skips `requireRange` on the strength of them |
| 3 | Constant-multiplication folding always propagates the scaled expression. With high fan-out the expression is copied into every downstream row — a reported ~72× nonzero-term amplification on a 500-term × 500-fan-out shape. A later review pass established the mechanism is general to `Add`/`LinComb` inlining as well — see Decision 3 | Medium | Accepted as reported; the mechanism is evident from the code |
| 4 | `InCircuitJubjub` variable-base Javadoc still states the withdrawn "subgroup-check off-circuit" contract; the readiness addendum's "ready" verdicts are now unsupported | Medium | Confirmed |
| 5 | `computeChallenge`/`witnessComputeKReduction` do not enforce `msg ∈ [0,p)`; dead 252-entry doubling table in `scalarMulFixedBase`; stale 2,772-constraint figure in `JubjubEdDSASuite` | Low | Confirmed |
| 6 | `PedersenCommitment.commit(value, blinding)` passes both secret inputs to variable-time `JubjubPoint.scalarMul`, despite the readiness addendum marking the component ready without a side-channel restriction | Medium | Confirmed directly at both scalar-multiplication call sites |

### Why finding 2 matters most

`BitDecomposition` was introduced by ADR-0037 **specifically to make a range guarantee
unforgeable**. Its own Javadoc says the guarantee "cannot be forged". Omitting circuit
identity reopens exactly the comparator forgery ADR-0037 closed — `p − 1 < 1,000,000`
accepted under a nominal 64-bit comparison — through a different door, and without needing
classpath control or any exotic capability. The consumer simply has to be handed a
decomposition minted elsewhere.

This also invalidates the earlier security review's conclusion. Two independent passes
examined `BitDecomposition` and both checked the *wrong* property: defensive copying and
constructor visibility, not cross-circuit identity.

### On the constant-time analysis

ADR-0037's addendum described the signing leak generically. The specific issue is sharper:

`JubjubPoint.scalarMul` bounds its loop by `scalar.bitLength()`, and `sign` calls it on the
secret nonce `r`. Signing time is therefore linearly correlated with `r.bitLength()`. This is
a **credible Minerva / TPM-Fail-class vulnerability** in this custom Schnorr-style scheme.

The attribution needs care, and an earlier draft of this ADR overstated it. Minerva's
published ECDSA attack needed hundreds to thousands of signatures; its authors explicitly note
the **EdDSA path was unclear**, because the scalar they observed was the full hash rather than
its reduction. Citing "Minerva recovered EdDSA keys from exactly this leak" was wrong.

What makes the attack algebraically applicable *here* is specific to this scheme, and is a
stronger argument than the EdDSA analogy: ZeroJ reduces `r mod l` explicitly, and the
signature equation `S = r + k·sk mod l` places that reduced `r` **linearly in a public
value** — precisely the Hidden Number Problem relation a lattice attack needs. TPM-Fail
demonstrated the analogous attack against ECSchnorr, including remotely, though at different
timing magnitude and observation counts.

`r` is *statistically close to* uniform in `[0, l)` — the reduction carries the documented
`≈ 2^-129` bias — so short nonces occur predictably and each reveals leading zero bits of a
secret nonce. Determinism does not help: it prevents nonce *reuse*, not nonce-length
*leakage*.

**Not established for this implementation:** the required signature count, and whether the
channel survives network noise. Those need a lattice simulation and a timing/noise experiment
against this code. Until then the vulnerability is credible and algebraically sound, not
quantified.

One local exploratory measurement observed `scalarMul` at 1.01 ms for 252 bits (~4 µs per
iteration), so a 4-bit-short nonce was ~16 µs faster out of a 2.89 ms signature — about 0.55%.
Those figures are environment-specific evidence of a signal, not a portable attack estimate;
the P4 benchmark records the JVM, hardware, sampling method, and uncertainty.

The review also correctly identified that ADR-0037's addendum **understated the remediation
cost**:

- `MontFr381` covers the base field `p` (coordinates, Poseidon) but signing also needs
  fixed-limb arithmetic modulo the **subgroup order `l`** for `r`, `k`, `S`. That layer does
  not exist.
- `MontFr381` is fixed-limb but still contains data-dependent branches.
- `sign(BigInteger sk, ...)` is itself a variable-time secret-import boundary.
- A timing harness that fails to recover a key does not establish safety.

The fixed-width-ladder fix is nevertheless **separable and worth doing on its own**: it
removes the loop-bound channel without requiring any of the above. It does not, by itself,
make signing constant-time — see Decision 4 for the precise scope claim.

The same primitive is also used with secret inputs outside signing:
`PedersenCommitment.commit(value, blinding)` calls variable-time `scalarMul` for both values.
Pedersen does not expose the Schnorr/HNP relation above, so this is not the same key-recovery
claim, but it invalidates the addendum's unconditional production-ready verdict for
side-channel-exposed commitment generation.

For the original variable-length implementation, the right characterisation was
**side-channel leakage of
value/blinding magnitude during commitment generation**, not a break or weakening of hiding.
The commitment string's perfect hiding is information-theoretic and remains intact; the
generation-time channel sits outside that model. But the channel is direct, not
lattice-grade subtle: the loop bound for `[value]·G` is `value.bitLength()`, so the value
multiplication exposes magnitude-dependent timing to an observer able to isolate that phase
or statistically separate it from the `[blinding]·H` leg, `BigInteger` variance, and
scheduling noise — and commitment values are documented as "typically small", so what leaks
is approximately the committed magnitude. `scalarMul` additionally returns early for a zero
scalar, skipping the entire `[value]·G` leg, which should make `commit(0, r)` readily
distinguishable. How few observations suffice — including whether one is enough — and the
zero-case distinguishability are expectations to be confirmed by the P4 measurement, not
established results; practical recovery from *remote or aggregate* timing has not been
demonstrated and remains unquantified.

P4 removed that variable-length mechanism. Its remaining raw fixed-schedule channel was later
measured and identified more precisely as `lowestSetBit(k)` leakage; P7.2 blinds it. See
Decision 4 rather than applying this historical paragraph to the current implementation.

## Decision

### 0. Withdraw the unsupported claims immediately, before any code change

Same posture ADR-0037 M0 took, and for the same reason: documentation asserting a safety
property that does not hold is itself a live defect.

- `docs/circuit-annotation-user-guide.md` — the M4 rewrite claims every prover-supplied point
  is curve-checked by the gadget. **This is false** for `ZkJubjubPoint.fromTrustedAffine`.
  Withdraw it and state the actual position.
- `docs/adr/0037-jubjub-production-readiness-status.md` — withdraw the ✅ verdicts for
  `ZkJubjubPoint` and the general DSL surface, and the "two independent passes found no HIGH
  or MEDIUM issue" statement, which is no longer true.
- `InCircuitJubjub` variable-base Javadoc — remove the withdrawn off-circuit-subgroup-check
  contract.
- `README` and the gadget support matrix — re-mark the symbolic Jubjub adapter.
- The readiness addendum's unconditional `PedersenCommitment` verdict and "no special handling"
  recipe — replace them with the side-channel restriction in Decision 4. Its algebraic
  binding/hiding construction is not in question; secret-bearing execution is.

### 1. Bind `BitDecomposition` to its issuing circuit

`BitDecomposition` gains an opaque owner reference set by `CircuitAPIImpl` at mint time.
Every consumer validates it:

- `CircuitAPIImpl.lessThan(BitDecomposition, BitDecomposition)` — reject a foreign
  decomposition rather than skipping `requireRange` on its word.
- `InCircuitJubjub.scalarMulFixedBase(api, base, BitDecomposition)` and
  `scalarMulVariableBase(api, base, BitDecomposition)` — these call `scalar.bits()` directly
  and currently perform no ownership check at all.
- A `CircuitAPI.requireOwned(BitDecomposition)` seam so gadgets outside the DSL package can
  validate without reaching into internals. Its default implementation **throws**
  `UnsupportedOperationException`, as `requirePublicOrConstant` does: a `CircuitAPI`
  implementation that has not opted into provenance tracking must fail closed rather than
  silently accept typed evidence it cannot authenticate.

The owner must be an identity the caller cannot fabricate, compared by **reference**, not a
name or an id. It must **not** be the `CircuitAPIImpl` instance itself: a decomposition that
escapes its circuit would then retain the entire builder and its gate list, which on a
19M-constraint circuit is a serious leak. Use a dedicated token:

```java
private final Object circuitToken = new Object();   // in CircuitAPIImpl
```

stored in `BitDecomposition` and compared by identity. The token has no public accessor;
`requireOwned` performs the comparison internally. Neither an exception nor `toString()` may
disclose it.

There are exactly four consumers of the typed object, and all four must validate:
`CircuitAPI.lessThan(BitDecomposition, BitDecomposition)`,
`InCircuitJubjub.scalarMulFixedBase(api, base, BitDecomposition)`, and
`InCircuitJubjub.scalarMulVariableBase(api, base, BitDecomposition)`, plus the typed
`InCircuitPedersen.commit(api, BitDecomposition, BitDecomposition)` overload from Decision 5.
The Pedersen consumer authenticates both operands up front; its rejection fixtures and the P6
gate cover the full inventory. A consumer
taking more than one decomposition validates **every** operand before reading any bits or
emitting any constraint, so a foreign operand cannot be rejected only after another
operand's constraints have already mutated the circuit.

**Validation must precede reading the bits, and every operand must be validated before any
constraint is emitted.** `requireOwned` is the first meaningful operation of every consumer.

*Correction, recorded because getting this wrong is the failure this ADR exists to prevent.*
An earlier revision of this section justified the ordering by claiming that `CircuitAPIImpl`'s
id-keyed caches (`booleanWires`, `rangeBounds`, `constantWireValues`) let a foreign
decomposition with colliding wire ids suppress the booleanity constraints a consumer would
otherwise emit. **That mechanism does not exist.** Those caches are per-circuit, and every
entry is written by the same circuit at the moment it emits the corresponding constraint, so a
cache hit means the *local* wire with that id genuinely carries the property and skipping is
correct.

The actual defect is simpler and sufficient on its own, and differs per consumer:

- `lessThan(BitDecomposition, BitDecomposition)` **skips `requireRange` entirely** on the
  strength of the typed evidence, so a foreign operand leaves the comparison with no range
  bound at all — directly the `p − 1 < 1,000,000` forgery.
- The scalar-multiplication overloads read `bits()` and multiply by them. The gadget does
  re-assert booleanity, but the constraint tying those bits to the scalar they decompose,
  `Σ bits[i]·2^i == source`, lives in the **minting** circuit. Consuming a foreign
  decomposition multiplies by bits that nothing in this circuit binds to any particular value,
  so the prover chooses the effective scalar freely — signature forgery inside `verifyCore`.

Validating every operand before emitting anything remains required, so that a foreign second
operand cannot be rejected only after the first has already mutated the circuit.

**`decompose` additionally resolves its source by wire id** against this circuit's own
allocation. `Variable` is a public record, so a caller can fabricate one naming a wire this
circuit never allocated; rejecting that makes `requireOwned`'s guarantee the stronger "this
circuit emitted these constraints *about a wire of this circuit*", matching the wire-id
resolution ADR-0037 Decision 4 applied to `requirePublicOrConstant`.

**Scope of the barrier.** Ownership is an API-level guarantee. There is no `module-info.java`
in this repo, so classpath code can join the DSL package or use reflection to reach the token;
that is not the threat model, since whoever defines the circuit already controls it. The
property being bought is that *typed evidence cannot be passed between circuits by accident or
by an untrusted caller through the public API*.

The `Variable`-plus-width scalar-mul overloads mint their decomposition from the same `api` one
expression earlier, so ownership holds by construction; they consume `bits()` directly rather
than routing through `requireOwned`, which would otherwise impose the seam on `CircuitAPI`
implementations that never handle caller-supplied evidence.

**Regression tests**, all asserting **definition-time rejection** rather than merely a failing
witness:
- foreign operand in the left position, the right position, and both;
- two foreign decompositions originating from the same other circuit;
- evidence reused across two `define()` invocations on the same builder;
- each of the four consumers above;
- an alternate/non-owning `CircuitAPI` whose default `requireOwned` must throw rather than
  accept evidence minted by a different implementation;
- a foreign decomposition whose bit and source ids deliberately collide with wires this
  circuit has already allocated — the configuration in which the foreign evidence looks
  locally plausible and nothing but provenance distinguishes it;
- **each consumer tested in its own module**: the `lessThan` fixtures live in the DSL module,
  which cannot see `zeroj-circuit-lib`, so the two scalar-multiplication overloads need their
  own fixtures there or their guards are untested;
- a fabricated `Variable` naming a wire this circuit never allocated, rejected by `decompose`;
- the reported `p − 1 < 1,000,000` witness specifically.

### 2. Make `ZkJubjubPoint` safe by construction

- `fromTrustedAffine` delegates to `InCircuitJubjub.witnessAffine`, which asserts the affine
  curve equation. The name is withdrawn — "trusted" describes exactly the model ADR-0037
  removed — in favour of `witnessAffine`, with the old name deprecated and delegating.
- `ZkJubjubPoint.assertWellFormed()` enforces the projective point invariants via
  `InCircuitJubjub.assertWellFormed`, rather than four independent field-element checks.
  This needs a design decision: the method is `assertWellFormed()` with **no `ZkContext`
  parameter** (it implements `ZkValue`), so the instance must retain its originating
  context/builder at construction in order to emit constraints. Retaining the context is the
  smaller change and keeps the `ZkValue` contract intact.

**Tests:** off-curve affine `(1,1)`; projective `Z = 0`; broken `T·Z = U·V`; the all-zero
projective point; a valid *rescaled* projective point (must be **accepted** — it is a
legitimate representation); cross-builder inputs; and the deprecated `fromTrustedAffine` path,
proving it delegates to the safe binder rather than merely being marked deprecated. Repeated
calls to `assertWellFormed()` on the same point must be idempotent: the second call emits no
additional constraints. Points constructed through the eager affine binder are marked as
already checked; an internal projective wrapper emits the invariant constraints at most once.

### 3. Make linear-expression inlining fan-out aware (not only constant-multiplication folding)

A subsequent review pass established that the amplification mechanism is **general to derived
linear expressions**, not specific to constant-multiplication folding. The compiler inlines
the sparse expression of every `Add`, `LinComb`, and folded constant-multiplication output
into each row that reads it, so a 500-term `Add`/`LinComb` output consumed by 500
variable-by-variable multiplication rows produces the same ~T×F nonzero amplification with no
constant multiplication anywhere. A policy that gates only constant-multiplication nodes
fixes the reported reproducer and leaves the sibling shape shipping. The materialisation
decision below therefore applies to **every eligible derived linear node**: `Add` outputs,
`LinComb` outputs, and constant-multiplication outputs.

Inlining is mathematically sound but not always profitable. The local comparison — identical
for all three node kinds, since materialising an `Add`/`LinComb` is one `(expr)·(1) = out`
row and a constant multiplication is one `(expr)·(c) = out` row — is:

```
fold:         T × F           nonzero terms
materialize:  T + F + 2       nonzero terms, plus one constraint row
```

where `T` is the expression's sparse term count and `F` its fan-out. An earlier draft of this
ADR used `T + F` and compared nonzeros only. That is too naive; a usable model must also
account for:

- **the two extra terms** in the materialisation row (`A·B = C` contributes the output and the
  one-wire alongside the `T`-term expression);
- **constraint-row count**, because the proving domain is padded to a power of two — crossing a
  boundary can double the domain and swamp any nonzero saving;
- **propagation through subsequent `Add`/`LinComb` nodes**, so `T` is not static;
- **term cancellation**, which can shrink `T` unpredictably;
- **`reads[]` being immediate fan-out only**, not transitive.

The original plan specified the following **three-pass deterministic policy**. It is retained
as design history; the implementation amendments immediately below supersede its terminal-use
and selection claims:

1. **Planning pass.** Forward constant propagation identifies pure constants and computes the
   all-fold sparse expression at each linear node, including actual coefficient cancellation.
   For a constant multiplication, `T` is the non-constant input's resulting sparse term count.
   **Memory discipline is part of the contract**: the pass uses the same live-map eviction
   ADR-0034 introduced (expressions evicted on their last read) and retains only per-node
   integer summaries (`T`, and later `U`) across the graph — never the full expression set,
   which on the 19M-constraint circuit is the difference between holding and losing the
   ADR-0034/0035 memory floor. Where exact cancellation would require retaining excessive
   state, a conservative **overestimate** of `T` is permitted and safe: it biases the rule
   below toward materialisation, which stays within the materialise-all baseline; it can only
   forgo a saving, never recreate the blow-up.
2. **Conservative terminal-use pass.** Traverse the graph backwards and compute `U`, an upper
   bound on how many terminal R1CS-row positions a node's output can reach through
   `Add`, `LinComb`, and further constant multiplications. A variable-by-variable `Mul` operand
   and either side of `AssertEq` are terminal uses. Count repeated occurrences and ignore
   possible downstream cancellation; over-estimation may forgo an optimisation but cannot
   recreate the fan-out explosion. Counts use saturating arithmetic.
3. **Selection and emission.**
   - fold multiplication by `0`, `1`, and `−1` unconditionally;
   - for every other eligible derived linear node — `Add`, `LinComb`, or constant
     multiplication — inline only when `T × U <= T + U + 2`; otherwise materialise one
     `A·B=C` row;
   - emit from the selected plan, then compute exact row, nonzero, and padded-domain metrics.

> **Amended during implementation — both halves of this rule were wrong, and the ADR's own
> gates caught them.** Recorded rather than quietly fixed, because the corrections are
> instructive.
>
> **(a) `U` must be immediate fan-out, not a transitive path count.** Implemented as specified
> — backward propagation through `Add`/`LinComb`/constant multiplications — `U` counts *paths*,
> and paths compound wherever the graph reconverges. A Poseidon lane feeding `t` MDS
> multiplications per round multiplies by `t` each round, so across 57 partial rounds the
> counter saturates and every lane is materialised. It is also the wrong quantity: `addExprs`
> merges coefficients, so a wire reaching one row along six paths is copied into it **once**,
> not six times. What governs cost is *distinct* reachability, and computing that exactly needs
> a set per node. Immediate fan-out — exactly the compiler's existing `reads[]` — is tractable
> and exact per step, and it targets the reported shape directly (a 500-term expression read by
> 500 multiplications has fan-out 500).
>
> **P7.1 correction: the final sentence of the original amendment was false.** A 500-term
> expression propagated through a depth-9 binary tree has immediate fan-out exactly two at
> every node. The local 8× rule materialises none of them, so the expression reaches all 512
> terminal rows: 257,536 nonzeros versus the materialise-all baseline's 9,664 (~27×). The
> emitted equations are sound, but the availability/performance invariant was not enforced.
>
> **(b) `T × U <= T + U + 2` prices a constraint row at two nonzero terms, which is far too
> cheap.** Rows set the QAP degree and therefore the padded FFT domain — they drive proving
> time and memory — while nonzeros only enlarge the sparse matrices. Measured against the
> incumbent all-inline compiler, the literal rule regressed:
>
> | Shape | incumbent | literal rule |
> |---|---|---|
> | Poseidon `t=6` tagged challenge | 321 | 1,881 |
> | 252-bit windowed fixed-base multiplication | 1,506 | 2,430 |
> | EdDSA `verifyCore` | 8,929 | 12,421 |
>
> The shipped rule keeps the defect this decision exists to fix and drops the
> micro-optimisation it did not ask for: **cap the amplification, do not chase single
> nonzeros.** Inlining stays the default; a row is bought only when inlining would cost more
> than `8 ×` the materialised cost *and* the absolute saving is at least 64 nonzeros. Measured
> on the 500 × 500 reproducer, both variants:
>
> | Policy | rows | nonzeros |
> |---|---|---|
> | all-inline (incumbent) | 500 | 251,000 |
> | materialise-all (safety baseline) | 1,499 | 5,495 |
> | **selected** | **501** | **2,002** |
>
> A 125× nonzero reduction for one extra row, inside the safety baseline on *both* metrics,
> with every incumbent pin — Poseidon 321, fixed-base 1,506, `verifyCore` 8,929,
> `verifyWithRegisteredKey` 8,962 — unchanged. This is exactly what the two-sided gate was
> written to produce: the safety baseline bounds the pathological shape, the incumbent pins
> reject a mis-calibrated cost model.

> **P7.1 final implementation: one online sparse pass with explicit resource bounds.** The
> exact-baseline/fallback design above was implemented and benchmarked before release. It
> traversed the graph three sparse times (candidate planning, materialise-all measurement,
> candidate emission), made ordinary 40k-gate compilation about 1.9–2.1× slower, allocated
> about 2× as much, and required roughly 831 MB of planner arrays at 43.7M wires. Worse, the
> supposedly protective planning passes performed the same unbounded sparse-map propagation
> they were meant to guard. It was therefore withdrawn before release.
>
> The shipped compiler restores ADR-0034's traversal shape: one integer-only read/resource
> pre-pass and one sparse-expression emission pass. Decisions use the expression size
> emission actually produced after cancellation:
>
> - the final local `32×`/64-nonzero rule handles obvious wide/high-fan-out nodes. The initial
>   `8×` calibration added 3,840 rows to the stable CIP-1852 circuit; the 32× gate preserves
>   its exact incumbent row count while both 500×500 fixtures still collapse;
> - a cumulative input-term copy/merge work proxy, live expression terms, live expression
>   entries, and emitted CSR terms are tracked independently with saturating/checked `long`
>   accounting. The proxy counts source terms copied or merged; result-map cleanup scans add
>   at most a small constant factor, so it is a deterministic bound rather than an exact
>   HashMap-visit counter;
> - approaching a deterministic soft limit enters **pressure mode** before the next operand is
>   consumed. Stored multi-term operands are materialised first, and subsequent multi-term
>   derived outputs are materialised on definition. This collapses the suffix to graph-linear
>   sparse work without discarding or replaying a partially built CSR;
> - even a single-term alias is pinned if the live-entry limit itself would be crossed;
> - dead derived linear outputs emit no row (genuine multiplication gates still emit their
>   defining constraint);
> - fixed hard limits fail explicitly rather than relying on an eventual JVM OOM:
>   350,000,000 total CSR terms, signed-`int` capacity per matrix and row count,
>   1,000,000 live expression terms, and 250,000 live expression entries. Graph-relative soft
>   limits are versioned multipliers (`CSR=32`, cumulative work `=64`, live frontier `=4`) and
>   reserve enough space for aggressive suffix materialisation.
>   The live limits cover the stored expression frontier. A single exceptionally wide
>   `LinComb` still needs one transient result map while its row is formed; circuit definitions
>   are trusted build inputs, and success for an arbitrary-width single gate on an arbitrary
>   heap is outside this guarantee.
>
> The same graph therefore produces the same R1CS on every machine. A machine with a smaller
> heap may still be unable to compile a graph below those format/resource caps; the claim is
> deterministic bounded compiler work/storage, not universal success on arbitrary hardware.
> There is no exact materialise-all row/NNZ guarantee in the public contract: that claim is
> withdrawn. Direct pathological fixtures retain the stronger measured comparison where it
> is useful.
>
> The distributed depth-9 binary-tree fixture makes the accepted trade explicit:
>
> | Policy | rows | nonzeros | padded domain |
> |---|---:|---:|---:|
> | dynamic materialise-all oracle | 1,011 | 3,532 | 2,048 |
> | **public pressure controller** | **529** | **10,070** | **1,024** |
>
> The public plan therefore retains 2.85× the oracle's sparse terms while roughly halving the
> row count and padded domain. This is intentional: rows determine the FFT domain and are the
> dominant proving metric for this shape. The contract is bounded deterministic resource use,
> exact production-shape pins, and explicit pressure reporting — not dominance over
> materialise-all on both structural metrics.
>
> `R1CSCompiler.compileWithDiagnostics(...)` and
> `CircuitBuilder.compileR1CSWithDiagnostics(...)` expose whether pressure mode was entered,
> together with the emitted rows, total CSR terms, and cumulative expression-work count. The
> existing compile APIs remain source-compatible. Build/deployment tooling should record the
> flag before circuit-specific setup: pressure is semantics-preserving, but it may change the
> R1CS fingerprint and therefore requires fresh setup/proving/verifying artifacts.

The all-inline and dynamic materialise-all policies remain package-private differential-test
oracles. The public safety property is enforced directly by the resource controller, not
inferred from either oracle. The depth-9 distributed tree and a 300-term expression propagated
through 5,000 single-use aliases are permanent load-bearing fixtures for the two distinct
failure modes: distributed CSR amplification and cumulative map-copy work.

The production gate is deliberately separate: Poseidon/Jubjub rows, exact nonzero counts, and
row-derived padded domains remain pinned to the incumbent compiler. Current pins include:

| Shape | rows | nonzeros | padded domain |
|---|---:|---:|---:|
| Tagged `t=6` challenge plus output binding | 322 | 9,194 | 512 |
| 252-bit windowed fixed-base | 1,506 | 7,865 | 2,048 |
| 252-bit bitwise fixed-base reference | 2,513 | 638,804 | 4,096 |
| EdDSA `verifyCore` | 8,929 | 364,200 | 16,384 |
| `verifyWithRegisteredKey` | 8,962 | 364,342 | 16,384 |
| `verifyStrict` | 14,500 | 705,251 | 16,384 |

These are **structural** guarantees. Wall-clock and allocation remain environment-sensitive
and are recorded by `:zeroj-circuit-dsl:r1csCompilerBenchmark`, which compares the public
controller with the incumbent all-inline policy on the same 40k-row graph. On the recorded
OpenJDK 25.0.2/macOS aarch64 run (median of nine), incumbent/public were
9.211/9.139 ms and 76.6/76.6 MiB allocated: 0.992× time and 1.000× allocation.
Independent final-review repeats ranged from 0.992× to 1.038× time with allocation unchanged
(latest: 8.823/9.161 ms),
illustrating why this remains a recorded benchmark rather than a CI timing gate.

The opt-in default CIP-1852 gate also compiles the same 18,754,215-row graph under the public
controller and incumbent all-inline policy and requires identical row counts (padded domain
2²⁵). The earlier 8× calibration produced 18,758,055 rows and was rejected as a stable-shape
regression before release.

**Testing split, deliberately:**
- **Pinned in CI:** constraint-row count, nonzero-term count, and padded Groth16 domain size.
  All three are deterministic. Pathological fixtures assert the fixed resource caps and their
  stronger expected reductions; production shapes assert exact incumbent values.
- **Separate benchmark, not a unit assertion:** heap and wall-clock, with recorded hardware and
  JVM. The task records ratios for review and has no CI pass/fail tolerance. ADR-0037 proposed
  asserting memory and time in tests; that would be flaky and is withdrawn.
- Cover a Poseidon-heavy shape **and** a high-fan-out shape. ADR-0037 measured one shape
  (CIP-1852) and generalised from it — that is exactly how this was missed.
- The 500-term × 500-fan-out fixture exists in **two variants**: the reported
  constant-multiplication shape, and a pure `Add`/`LinComb` shape containing no constant
  multiplication at all. Both are pinned within the dynamic materialise-all baseline; the
  distributed binary-tree and deep single-use variants exercise online pressure rather than a
  replay/fallback.
- Preserve the existing Poseidon/Jubjub constraint pins, including the 321-constraint `t=6`
  challenge, unless a separately recorded benchmark demonstrates and approves a deliberate
  trade.

The readiness addendum's "no regression on large circuits" claim is narrowed to the shape
actually measured.

### 4. Remove the variable-loop contribution from secret Jubjub scalar multiplication

**P4 baseline, superseded at secret-bearing call sites by P7.2 below.** Independent of the
broader constant-time question. **Scope claim, stated precisely: this
removes the variable loop-bound channel. It does not "close the attack"** — that phrasing was
used in an earlier draft and is withdrawn until measurement supports it.

`JubjubPoint` gains a fixed-width, **best-effort** secret-scalar multiplication for scalars in
`[0,l)`, running exactly 252 iterations regardless of `bitLength()`. The raw method is
package-private and named to make its restriction explicit
(`scalarMulSecretRaw252UnsafeForTiming`); it was the P4 path for
`keypairFromSecret`, nonce-point generation, and both secret multiplications in
`PedersenCommitment.commit`; P7.2 retains it as a raw primitive but moves those call sites to
the blinded 316-iteration wrapper.

The enforceable scope with the current `BigInteger` representation is:

- every iteration performs the same expensive group-operation schedule — compute one
  addition and one doubling, never skip the addition;
- the current `scalarMul` returns the identity immediately for a zero scalar; the
  fixed-schedule path **removes that early exit**. Scalars `0` and `l − 1` run the identical
  252-iteration schedule, and both appear in the deterministic operation-count gate —
  `commit(0, r)` is a common commitment and today skips its entire `[value]·G` leg;
- selection between the already-computed point objects may still use a secret-dependent Java
  branch. It performs no additional coordinate arithmetic, but it is **not constant-time** and
  the API/Javadoc must say so;
- deterministic operation-count tests show identical add/double counts across scalars of
  differing bit length and Hamming weight;
- timing correlation against both bit length and Hamming weight is a separately recorded
  statistical benchmark, not a flaky CI unit assertion and not proof of safety;
- all signature golden vectors remain bit-identical — this is an execution-schedule change,
  not a scheme change.

**Expected runtime cost, so the trade is explicit.** Never skipping the addition raises the
group-operation count from roughly 126 additions plus 252 doublings to 252 of each — about
**1.3× per full-width secret scalar multiplication** (measured 1.01 ms → ~1.3 ms). An
earlier draft attached "~3.6 ms" to `sign` generically, which contradicted this ADR's own
API decision below; the per-API estimates, under the same assumptions, are:

- `sign(Keypair, msg)` — the new primary API — drops the `[sk]·G` recomputation entirely and
  keeps one fixed-schedule `[r]·G`: `2.89 − 1.01 + 0.29 ≈` **~2.2 ms**, i.e. *faster* than
  today's 2.89 ms;
- deprecated `sign(BigInteger, BigInteger)`, delegating through `keypairFromSecret` — two
  fixed-schedule multiplications: ≈ **~3.5 ms**;
- `PedersenCommitment.commit` — the 1.3× factor holds only when both scalars are full-width.
  Values are documented "typically small": a 64-bit value runs ~64 loop iterations today, so
  its leg slows roughly **5×** under the fixed schedule, and a small-value/full-blinding
  commit goes from roughly ~1.3 ms to ~2.6 ms (≈2× total). That slowdown *is the fix
  working* — the old speed was the leak.

All of these are estimates extrapolated from one exploratory measurement; **none is pinned
until the P4 benchmark**, which must measure separately: `sign(Keypair, msg)`; deprecated
`sign(BigInteger, BigInteger)`; `keypairFromSecret`; commitment with a small value and
full-width blinding; commitment with two full-width scalars; and zero and boundary scalars
(`0` and `l − 1`). The cost falls only on secret scalars: verification keeps the
variable-length path and is unchanged.

> **Historical P4 measurement — superseded by P7.2/P7.4 below.** This run predates scalar
> blinding, deterministic output normalization, and the mandatory verify-before-release
> signing check. It is retained only as design history; its values are not the shipping
> performance matrix or a release gate.
>
> | Case | median | p10 | p90 |
> |---|---|---|---|
> | fixed-schedule secret mul, full width | 1.085 ms | 1.045 | 1.333 |
> | variable-time mul, full width (public path, unchanged) | 0.748 ms | 0.739 | 0.772 |
> | variable-time mul, 64-bit (public path, unchanged) | 0.053 ms | 0.053 | 0.056 |
> | **`sign(Keypair, msg)`** — primary | **1.434 ms** | 1.409 | 1.496 |
> | `sign(BigInteger, BigInteger)` — deprecated | 2.518 ms | 2.463 | 2.577 |
> | `keypairFromSecret` | 1.058 ms | 1.045 | 1.089 |
> | `commit(small value, full blinding)` | 2.118 ms | 2.095 | 2.170 |
> | `commit(full value, full blinding)` | 2.192 ms | 2.140 | 2.345 |
> | `commit(0, full blinding)` — boundary | 1.940 ms | 1.871 | 2.171 |
> | `commit(l − 1, full blinding)` — boundary | 2.230 ms | 2.152 | 2.459 |
> | `verify` | **invalid measurement** | — | — |
>
> At that historical stage the per-scalar overhead was **1.45×** (0.748 → 1.085 ms), and the
> primary signing form was cheaper because it performed one secret multiplication instead of
> two. Neither the signing nor commitment timings in this table describe the final P7 path.
>
> The original "verify" lambda called `sign(keypair, msg)` inside the timed operation, so its
> 4.915 ms figure was sign + verify and is withdrawn. P7.4 precomputes the signature, adds a
> separate Pedersen verification case, and updates this document from the corrected run.
>
> **Historical P4 correlation probe (superseded implementation and interpretation).** Median
> time for the raw fixed-schedule
> multiplication, by scalar:
>
> | scalar | bits | weight | median |
> |---|---|---|---|
> | `0` | 0 | 0 | 0.806 ms |
> | `1` | 1 | 1 | 1.071 ms |
> | `2^64` | 65 | 1 | 1.008 ms |
> | `2^128` | 129 | 1 | 0.941 ms |
> | `2^251` | 252 | 1 | 0.807 ms |
> | `2^251 + 1` | 252 | 2 | 1.080 ms |
> | dense | 251 | 251 | 1.083 ms |
> | `l − 1` | 252 | 116 | 1.077 ms |
> | random | 248 | 129 | 1.067 ms |
>
> The add/double **counts** are provably identical — that is the CI gate — but a **~25%
> timing spread remains** (0.806–1.083 ms), and it does not track bit length: `2^251` is a
> full-width scalar and among the fastest. It tracks how long the accumulator stays at the
> identity, whose coordinates `(0,1,1,0)` are single-word `BigInteger`s that multiply far
> faster than full-width residues. This is precisely the residual Decision 6 defers, now
> measured rather than asserted: **the schedule is fixed, the arithmetic underneath is not.**
> At that stage `commit(0, ·)` remained 0.25 ms faster than `commit(l − 1, ·)` for the same
> reason. The final blinded commitment measurements below supersede that result.
>
> The original conclusion called this an "operand-magnitude" channel and treated the absence
> of bit-length correlation as reassuring. That conclusion is withdrawn. In this LSB-first
> loop, time spent at the identity is exactly the scalar's trailing-zero count:
> `lowestSetBit(k)`. It therefore exposes known nonce LSBs, a structured HNP input. The
> offline-only classification is unchanged.

> **P7.2 mitigation.** Secret-bearing call sites no longer use the raw 252-bit representation.
> They sample a fresh uniform 64-bit `m` and compute `[k + m·l]P` in a fixed 316-iteration
> schedule. Since `l` is odd, the represented scalar's low 64 bits are uniform; since every
> permitted base has order `l`, the affine result and signature/commitment bytes are unchanged.
> The helper is package-private and its subgroup precondition is pinned by a mixed-order
> counterexample. Development and test environments may additionally enable
> `-Dzeroj.jubjub.debugSecretSubgroupChecks=true`; this performs an expensive full subgroup
> check and fails on a mixed-order base. It is deliberately off by default and is a misuse
> detector, not a constant-time production boundary. This is scalar blinding, not
> constant-time arithmetic: Java selection,
> `BigInteger`, reductions, JIT and GC remain variable-time, so signing stays offline-only.
>
> **P7.2/P7.4 measured after output normalization and verify-before-release.** OpenJDK
> 25.0.2, macOS 26.0.1 aarch64, 16 cores, 1 GiB benchmark heap, 200 warmup / 400 samples.
> Intervals are exact distribution-free 95% confidence intervals for the population median
> (binomial order statistics):
>
> | Case | median | exact 95% median CI | p10 | p90 |
> |---|---:|---:|---:|---:|
> | raw fixed-252 primitive, full width | 1.064 ms | [1.060, 1.070] | 1.036 | 1.194 |
> | blinded fixed-316 secret path | 1.330 ms | [1.327, 1.331] | 1.298 | 1.357 |
> | public variable-time full-width mul | 0.743 ms | [0.742, 0.745] | 0.725 | 0.764 |
> | public variable-time 64-bit mul | 0.051 ms | [0.050, 0.052] | 0.049 | 0.056 |
> | **`sign(Keypair, msg)` including self-check** | **5.084 ms** | **[5.080, 5.093]** | 4.995 | 5.164 |
> | deprecated `sign(sk, msg)` including self-check | 6.486 ms | [6.475, 6.491] | 6.366 | 6.569 |
> | `keypairFromSecret` | 1.356 ms | [1.354, 1.358] | 1.323 | 1.380 |
> | commit, small/full scalars | 2.734 ms | [2.727, 2.743] | 2.655 | 2.883 |
> | commit, full/full scalars | 2.725 ms | [2.719, 2.728] | 2.679 | 2.766 |
> | commit, zero value/full blinding | 2.723 ms | [2.720, 2.726] | 2.682 | 2.761 |
> | commit, `l−1` value/full blinding | 2.734 ms | [2.730, 2.737] | 2.684 | 2.771 |
> | EdDSA verify, signature precomputed | 3.395 ms | [3.391, 3.399] | 3.333 | 3.434 |
> | Pedersen verify, public opening path | 1.472 ms | [1.469, 1.473] | 1.443 | 1.492 |
>
> The blinded correlation medians were 1.353–1.366 ms across zero, powers of two with
> trailing-zero counts 64/128/251, dense, boundary and random scalars; the raw column retained
> its 0.808–1.093 ms trailing-zero profile. This is the current P4/P7 benchmark matrix and the
> timing profile referenced by the release gates below. It supports the intended blinding
> effect but is not a constant-time proof.

Requiring branchless point selection while deferring fixed-limb coordinates would be
internally contradictory: object-reference selection branches, while arithmetic selection
over `BigInteger` has data-dependent work. Removing that final selection channel belongs to
Decision 6.

The variable-length `scalarMul` stays for public scalars, where the optimisation is harmless.

**API decision — an earlier draft was internally contradictory.** It said `sign` should stop
recomputing `pk = [sk]·G` "because the keypair already holds `pk`", but the current signature
is `sign(BigInteger sk, BigInteger msg)` and receives no keypair. Resolve it explicitly:

- add `sign(Keypair, BigInteger msg)` and deprecate `sign(BigInteger, BigInteger)`; and
- **fix `Keypair` first.** Its compact constructor null-checks only, so it admitted an
  inconsistent `(sk, pk)` pair — a signature computed against a mismatched `pk` would simply
  fail to verify, silently. A public Java record cannot hide its canonical constructor, so
  replace the record with a final class. Preserve the public `(sk, pk)` constructor for
  direct-call compatibility, but make it validate `0 < sk < l` and
  `pk = [sk]G` immediately. The factories (`keypairFromSecret`, `generateKeypair`) use a
  private trusted path after computing that relation themselves, avoiding a duplicate scalar
  multiplication. Redacted `toString()` and `sk()` / `pk()` accessors remain. Code relying
  specifically on record reflection or assigning the value to `java.lang.Record` must migrate.

The deprecated `sign(BigInteger, BigInteger)` validates and delegates through
`keypairFromSecret`; it must not retain a second variable-length secret multiplication path.

`PedersenCommitment.commit(value, blinding)` canonicalises both inputs modulo `l` and uses the
same best-effort blinded 316-iteration path for `[value]G` and `[blinding]H`. Reduction and
blinding through `BigInteger` remain variable-time, so this does not make commitment generation
constant-time. Commitment golden vectors and homomorphism tests remain unchanged. Binding is
to the scalar residue `value mod l`, and hiding requires a uniform blinding scalar.
Verification handles a disclosed opening and now deliberately uses a separate faster
public-scalar recomputation path with identical canonicalisation semantics.

**Fault posture — detection for one modeled class, not a resistance claim.** Deterministic
nonces are the textbook differential-fault target: a glitch during `[r]·G` yields
`R' ≠ R`, hence `k' = Poseidon(R', …)` and `S' = r + k'·sk`, and one clean plus one faulted
signature over the same message recover `sk`. The faulted signature fails verification
(`[S']·G = R + [k']·pk ≠ R' + [k']·pk`), so a verify-before-release check catches this
modeled fault class. Signing now performs that full verification before releasing a candidate.
It materially increases signer latency, does not protect against common-mode faults or a
skipped/corrupted check, and an independently implemented verification path would be stronger.
The offline-only classification still bounds exposure; the check must not be described as
fault resistance.

**Recorded API decision:** every public signing API performs the full verify-before-release
check unconditionally, and there is no public unchecked bypass. The current primary path
measures 5.084 ms including that check. This cost is accepted for an offline signer because
releasing one suitable deterministic-nonce fault can expose the signing key; bulk test
issuance is not allowed to silently select a weaker production API. This is detection for the
modeled single-computation fault class, not resistance to common-mode faults, a skipped check,
or compromise of the Java process.

The statistical benchmark records the **residual** channels this decision does not close:
`BigInteger` word-count variance inside both schedules and in `S = r + k·sk mod l`, the fresh
blinding arithmetic, Java selection branches, and Poseidon nonce derivation's variable-time
processing of `sk` — so that "best-effort" carries a measured scope rather than an implied one.

**The offline-only classification is unchanged by this work.** P4 improves a restricted signer;
it does not make signing production-approved.

### 5. Low-severity cleanup

- `computeChallenge` and `witnessComputeKReduction` enforce `msg ∈ [0,p)`, matching the
  reject-not-reduce semantics `sign`/`verify` already promise.
- Remove the dead 252-entry doubling table built and discarded in `scalarMulFixedBase`.
- Correct the stale 2,772-constraint figure in `JubjubEdDSASuite` to the pinned 321.
- After P1 lands, reuse decompositions in the Pedersen adapters instead of re-emitting them
  (performance only; savings are width-dependent — measure, don't assert):
  - `InCircuitPedersen.commit(api, value, blinding, numBits)` calls `toBinary`
    unconditionally, re-decomposing scalars that the annotation path (`ZkPedersen.commit`
    over `ZkUInt`) already decomposed at construction — the range cache satisfies
    `assertCanonicalScalar`, but `toBinary` emits regardless.
  - The mechanism must be stated because none of the pieces exists yet: `ZkUInt` retains
    only its signal and width (its `assertInRange` discards the bits), and
    `InCircuitPedersen` has no `BitDecomposition` overload. The fix is a typed
    `InCircuitPedersen.commit(api, BitDecomposition value, BitDecomposition blinding)`
    overload, plus lazily minting and caching an owned decomposition at the scalar's
    **actual width** on first need — including for derived (`trusted()`) `ZkUInt`s, which
    carry no cached range bound and today re-decompose at 252 bits in
    `assertCanonicalScalar`. Without both halves, an implementer preserves either the
    duplicate decomposition or the shared 252-bit cost.
  - The typed overload is the **fourth ownership consumer** (Decision 1). It calls
    `requireOwned` on **both** decompositions before reading either's bits or emitting any
    constraint — not by delegating to the two scalar-multiplication calls in sequence, which
    would reject a foreign blinding only after the value multiplication had already mutated
    the circuit. Definition-time rejection tests: foreign value, foreign blinding, both
    foreign.
  - Order matters in the adapter: a constrained `ZkUInt` retains the decomposition its
    `assertWellFormed()` created; a derived (`trusted()`) value mints and caches one lazily
    at its declared width; and `ZkPedersen.commit` obtains both actual-width decompositions
    **before** calling `assertCanonicalScalar`, then passes those same objects to the typed
    overload. Running `assertCanonicalScalar` first on a derived value still emits and
    discards a 252-bit decomposition — preserving exactly the regression this item removes.
  - `ZkPedersen.commit` shares `max(value.bits(), blinding.bits())` across both legs, so a
    small value pays full-width windowing for `[value]·G`; per-scalar widths are cheaper,
    and `commitBits` already accepts asymmetric widths.

### 6. Full constant-time secret-bearing Jubjub operations stay deferred

Superseded as a delivery plan by
[ADR-0039](0039-jubjub-online-and-offline-readiness.md). The current restriction remains in
force until ADR-0039's online-provider gates pass. The observations below remain useful
context:

- A fixed-limb layer modulo the **subgroup order `l`** is required; `MontFr381` covers `p`
  only and does not serve signing's `r`, `k`, `S` or canonical secret-scalar imports.
  ADR-0039 specifies a separate 4×64-bit pure-Java Montgomery kernel for this modulus.
- `MontFr381` itself needs its data-dependent branches removed before it can back secret point
  arithmetic for signing or Pedersen commitments.
- `Keypair` still contains a `BigInteger` secret even after Decision 4. Full constant-time work
  therefore needs a fixed-limb secret-import API; merely deprecating `sign(BigInteger, ...)`
  does not remove the boundary.
- Deterministic v1 signing additionally needs secret-bearing Poseidon nonce derivation over
  the hardened base-field representation. ADR-0039 preserves that compatibility path and
  separately gates a hedged online profile on a normative nonce specification.
- Java cannot give a universal hard guarantee because JIT and GC behavior sit below the source
  language. ADR-0039 therefore limits any future online label to explicitly reviewed and
  measured dedicated/single-tenant JVM/CPU configurations; hostile shared-host use remains out
  of scope.

Until then:

- **isolated/offline signing only**, as ADR-0037 Decision 8 states;
- do not expose secret-bearing off-circuit Pedersen commitment generation to an untrusted
  timing observer or co-resident adversary.

An HSM qualifies only if the complete Jubjub operation (and Poseidon for signing) executes
inside its reviewed boundary and the secret never enters this Java `BigInteger` path; merely
storing a key in an HSM does not make the Java operation constant-time.

### 7. Release gate

A final phase, and nothing is re-labelled before every item passes:

- full `./gradlew test --rerun-tasks`;
- end-to-end Groth16 proof generation and verification **after** the compiler change, not only
  unit tests;
- R1CS satisfiability differential tests for the materialisation policy, covering zero, one,
  and negative constants, term cancellation, single-use expressions, and high fan-out in both
  the constant-multiplication and pure `Add`/`LinComb` variants, run against the generalised
  all-materialised and all-fold reference policies;
- deterministic rows, nnz, and padded-domain gates for the selected policy, including the
  Poseidon/Jubjub pins (as the incumbent all-fold gate) and both 500 × 500 high-fan-out
  fixtures;
- every P1 cross-circuit exploit fixture rejected at definition time and every P2 invalid-point
  fixture rejected, including repeated `assertWellFormed()` idempotency; the ownership-consumer
  inventory is fully fixture-covered — all four consumers, including foreign value, foreign
  blinding, and both-foreign Pedersen cases, reject at definition time;
- all Jubjub signature golden vectors bit-identical;
- all Pedersen commitment fixtures and homomorphism vectors unchanged;
- the secret-scalar add/double operation-count gate green, including scalars `0` and `l − 1`;
  the statistical timing benchmark and six-case matrix recorded with their JVM, hardware,
  sample count, and confidence interval, without treating a negative result as proof of
  constant time;
- **documentation and readiness status reconciled only after every gate above is green.**

That last item is the discipline that failed in ADR-0037 M4: docs were rewritten to assert a
safety property before anything verified it, which is how the false curve-check claim shipped.

## Sequencing

| Phase | Scope | Gate |
|---|---|---|
| **P0** | Decision 0 — withdraw the false and unsupported claims | No published document asserts a safety property that does not hold |
| **P1** | Decision 1 — `BitDecomposition` ownership | Cross-circuit reuse rejected for `lessThan` and both scalar-mul overloads; the `p−1 < 10^6` witness fails |
| **P2** | Decision 2 — `ZkJubjubPoint` safe by construction | Off-curve `(1,1)` rejected; adapter tests green |
| **P3** | Decision 3 — fan-out-aware materialisation of derived linear expressions | Direct fan-out fixtures remain within their dynamic materialise-all baseline; distributed/deep fixtures trigger deterministic online pressure; exact production rows/NNZ/domain pins hold; heap/wall-clock recorded separately |
| **P4** | Decision 4 — secret scalar timing | Production-loop instrumentation proves the raw 252- and blinded 316-iteration add/double schedules, including scalars `0` and `l − 1`; the benchmark matrix is recorded; public outputs normalize deterministically; the validating `Keypair` constructor, primary `sign(Keypair, msg)`, and verify-before-release check are in place. Remaining branch/`BigInteger`/nonce-derivation leakage is documented; signing stays offline-only |
| **P5** | Decision 5 — low cleanup | May land alongside P0–P2 |
| **P6** | Decision 7 — release gate | Every gate green *before* any doc is re-labelled |
| **P7.1** | Online compiler resource controller | One integer pre-pass plus one sparse emission; distributed fan-out and deep map-copy fixtures enter pressure before fixed CSR/live/work limits; all incumbent production pins unchanged |
| **P7.2–P7.5** | Scalar blinding, public Pedersen verification, corrected benchmarks/docs, local point guards | Golden vectors unchanged; 316-operation gate; raw/blinded timing profile recorded; every projective predicate rejects `Z = 0` |

P0 is immediate. P1 and P2 are soundness work and respectively block the
`BitDecomposition`-consuming overloads and the symbolic `ZkJubjubPoint` API. P5 can land
alongside them.

**P3 precedes P4 by default.** The inlining regression affects the general compiler for every
circuit compiled today, whereas P4 improves a signer that is already restricted to offline use
and does not become production-approved either way. Move P4 ahead of P3 only if
remotely-reachable signing becomes a near-term requirement; doing so does not relax the
offline-only classification.

## Consequences

- The readiness addendum's verdicts regressed with separate gates, now resolved:
  - `BitDecomposition`-consuming overloads — restored by P1;
  - `ZkJubjubPoint` — restored by P2;
  - the R1CS compiler's structural bound — restored by P7.1 as deterministic independent
    CSR/live-frontier/cumulative-work limits with online pressure, including distributed
    low-degree fan-out; heap and wall-clock remain separately benchmarked rather than inferred;
  - off-circuit `PedersenCommitment.commit` remains **not approved** for side-channel-exposed
    secret inputs. P4 removed the loop/operation-count channel and P7.2 blinds the structured
    trailing-zero signal, but variable-time Java/`BigInteger` arithmetic keeps the offline-only
    restriction in force. Its algebraic construction and in-circuit gadgets are unaffected.

### Additional findings surfaced during implementation

Multiple adversarial review passes ran against the fixes themselves. Beyond the two corrected
rationales noted in Status, they produced:

- **A frozen-builder guard.** `assertWellFormed()` takes no context (the `ZkValue` contract
  gives it none), so a symbolic value outliving its `define()` block emitted into a
  snapshotted gate list — returning normally, constraining nothing, and marking itself
  checked. `CircuitAPIImpl` now rejects emission after `buildGraph()`. This closes the same
  latent hole for `ZkUInt` and `ZkBool`, which share the pattern.
- **Wire-id resolution in `decompose`.** `Variable` is a public record, so a fabricated one
  naming an unallocated wire could be decomposed. Rejecting it upgrades `requireOwned`'s
  guarantee to "this circuit emitted these constraints *about a wire of this circuit*".
- **Cross-module test coverage.** The `lessThan` fixtures live in the DSL module, which cannot
  see `zeroj-circuit-lib`; both `InCircuitJubjub` guards were initially untested and could
  have been deleted with the suite green. Mutation testing now confirms 9 of 13 gadget
  fixtures fail when the guards are removed.
- **Fail-closed direct compiler boundaries.** A caller could construct a raw public
  `Gate.Select`; the witness evaluator handled it, but R1CS emission previously treated its
  output as an unconstrained base wire. R1CS now rejects raw `Select` rather than compiling an
  unsound relation. Direct R1CS, PlonK, Halo2, and witness entry points also enforce the
  graph's declared field before allocation, not only when invoked through `CircuitBuilder`.
- **Overflow-safe graph accounting.** Per-wire future-read counters now reject before signed
  integer wrap. A wrapped negative count could otherwise make a live linear output look dead
  and turn a later read into an unconstrained base wire.
- **Atomic raw Pedersen validation.** Both raw bit-array operands are fully checked for nulls
  and the supported 1–252-bit width before either fixed-base multiplication emits a
  constraint. An invalid right operand therefore cannot leave a partial value leg.
- **Projective comparison defence-in-depth, closed in P7.5.** Every equality, affine-equality
  and identity predicate now establishes `Z != 0` locally and idempotently. The all-zero raw
  wrapper is rejected at every public predicate boundary rather than relying on the
  construction inventory staying closed.
- `EdDSAJubjub.verify` and `InCircuitEdDSAJubjub.verifyStrict` are unaffected by findings 1
  and 2 — `verifyCore` takes affine wires and routes through `InCircuitJubjub.witnessAffine`,
  and it does not consume caller-supplied `BitDecomposition` instances. They remain release
  candidates pending external review.
- Adding `witnessAffine` while retaining a deprecated, safely delegating `fromTrustedAffine` is
  source-compatible in this release. A later removal of the deprecated name would be
  source-breaking.
- Replacing the public `Keypair` record with a final class preserves direct construction through
  a validating public `(sk, pk)` constructor, the `sk()` / `pk()` accessors, and value-style
  `equals` / `hashCode`; a regression test also preserves the exact former two-component
  record hash formula. The constructor now rejects out-of-range secrets and mismatched public
  keys and, because it verifies `pk = [sk]G`, measured 1.356 ms in the current benchmark.
  Factories remain preferred because they establish the relation without recomputing it.
  It is nevertheless a compatibility change for code that relies on
  record reflection, record-component metadata, pattern matching as a record, or assignment to
  `java.lang.Record`; those callers must migrate and recompile.
- Scalar blinding randomises raw projective coordinates, so newly generated public keys,
  signatures, and commitments are normalized to a deterministic affine representative before
  return. Affine values, compressed encodings, signatures, and commitment semantics are
  unchanged and literal golden-vector pinned. Explicit caller construction of `Keypair` and
  `Signature` preserves the supplied valid point object/representation.
- The materialisation cost model may reduce the constraint savings ADR-0037 measured on
  Poseidon-heavy shapes, bounded by the incumbent all-fold pins in Decision 3. That is the
  correct trade: a 72× nonzero amplification on an unmeasured shape is worse than forgoing
  some savings on a measured one.
- A graph for which pressure or local policy now materialises a different set of expressions
  has a different R1CS shape. Cached circuit-specific trusted setup, proving keys, verifying
  keys, and proofs derived from that R1CS (including Groth16 and gnark-PlonK artifacts) are
  not reusable; recompile and regenerate them during migration. Native `PlonKCompiler`
  artifacts are outside this R1CS materialisation change.
- Alternate `CircuitAPI` implementations must implement decomposition provenance and
  `requireOwned`; the interface default deliberately fails closed. Such implementations must
  migrate before calling typed-decomposition comparators or Jubjub/Pedersen gadgets.

## Process note

Three review passes examined `BitDecomposition` and none checked circuit identity; two checked
defensive copying and constructor visibility instead. The generalisation from one benchmarked
circuit shape to "large circuits are not regressed" was similarly unchallenged. Future
reviews of this surface should treat *"what evidence does this type actually carry, and across
what scope?"* and *"what shape was NOT measured?"* as standing questions rather than
incidental ones.

The review rounds on this ADR repeated the pattern twice more: an earlier draft of
Decision 3 scoped the fix to constant-multiplication folding because that was the node kind
in the reproducer, when the mechanism — inlining a shared linear expression into every
reading row — applies to every derived linear node; and an earlier draft of Decision 4
attached one timing estimate to "sign" when the two signing APIs it defines have materially
different costs. *"Is the fix scoped to the mechanism or to the reproducer?"* joins the
standing questions above.

## References

- [ADR-0037](0037-jubjub-soundness-and-hardening.md) — soundness fixes and hardening
- [ADR-0037 addendum](0037-jubjub-production-readiness-status.md) — readiness status, amended by this ADR
- [ADR-0021](0021-bls12381-review-and-hardening.md) — constant-time posture precedent
- [`docs/specs/jubjub-eddsa-v1.md`](../specs/jubjub-eddsa-v1.md) — normative scheme
- Minerva (2019) — <https://minerva.crocs.fi.muni.cz/> — nonce-bit-length timing attack on
  ECDSA; the authors note the EdDSA path was unclear
- TPM-Fail (2019) — <https://arxiv.org/abs/1911.05673> — the analogous attack against
  ECSchnorr, demonstrated remotely
- Romailler & Pelissier (FDTC 2017) — "Practical fault attack against the Ed25519 and EdDSA
  signature schemes" — <https://doi.org/10.1109/FDTC.2017.12> — the differential-fault attack
  on deterministic nonces recorded in Decision 4's fault posture
- zkcrypto/jubjub — <https://github.com/zkcrypto/jubjub> (unaudited)
