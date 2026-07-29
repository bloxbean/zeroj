# ADR-0039 implementation and release-gate status

## Status

Informational implementation record for
[ADR-0039](0039-jubjub-online-and-offline-readiness.md).

This is not a validated dedicated-host approval. It distinguishes locally completed
engineering from external/platform/deployment gates that ZeroJ cannot self-certify.

## Date

2026-07-27

## Goal check

The implementation target remains:

> A pure-Java Jubjub signing service that accepts network-originated, attacker-chosen messages
> and request timing on a dedicated or single-tenant host, without processing secret signing
> material through `BigInteger`, and without changing existing signatures, verifiers,
> circuits, R1CS/PLONK shapes, proving keys, or verification keys.

The intended first deployment is a credential/signing microservice. An offline ceremony does
not meet its availability and interactive-latency requirements. The provisional engineering
target for platform qualification is:

- at least 100 sustained signatures/second per service instance;
- p95 below 25 ms and p99 below 50 ms at the declared service concurrency;
- a dedicated/single-tenant host with no hostile co-tenant;
- canonical 32-byte key provisioning from an offline generation/secret-store boundary, with
  caller and service buffers wiped under their documented ownership rules;
- no readiness until the exact JDK/JVM/CPU/GC/CSPRNG profile is pinned and attested.

These are release-engineering targets, not a promise for every machine. M8 must replace them
with the actual deployment SLO and load-test evidence.

## Milestone status

| Milestone | Local implementation status | Remaining release gate |
|---|---|---|
| M0 | Complete: legacy deterministic nonce rejects zero; key-recovery fixtures and docs added | None beyond normal release review |
| M1 | Complete locally: requirement above; fixed-limb constants, codecs, ownership, exact 8-round `p -> l`, 17-round unsigned-256 reduction, and proof notes recorded | Independent arithmetic review |
| M2 | Complete locally: allocation-free 4×64 Montgomery `Fq`/`Fr` kernels; direct forbidden-dependency checks plus transitive classification of every in-package dependency reachable from the hardened region | Carry/borrow mutation campaign and external fixed-limb review |
| M3 | Complete locally: fixed-limb points, fixed 252-iteration scalar multiplication, normalization, Poseidon t=3, deterministic-v1 compatibility signer | External implementation review |
| M4 | Candidate complete: [`jubjub-eddsa-hedged-v1-candidate`](../specs/jubjub-eddsa-hedged-v1-candidate.md), independent transcript/vector tests, nonzero mapping and bias bound | **External cryptographic design approval; profile may change** |
| M5 | Candidate complete: `JubjubMessage` plus public circuit-field bridge, typed verifier, `HardenedJubjubKey`, per-call scratch, explicit shared destruction-domain contract, deterministic signer, hedged candidate, nonce re-derivation and release check | Public online API is not frozen; approved RNG/platform source and key-provisioning boundary remain gated |
| M6 | Diagnostic evidence recorded below; C1/C2/interpreter negative controls work and no signal appeared in selected classes | Generated-code/wipe inspection, deoptimization/OSR, approved provider, remote timing, repeated independent runs |
| M7 | Not complete | Independent external review and remediation |
| M8 | [Fail-closed release checklist](0039-jubjub-dedicated-host-release-checklist.md) added; matrix has no approved row and validated factory deliberately throws | Supported platform row, operational evidence, load/remote timing, deployment approval |
| M9 | Internal candidate complete: mutable opening, explicit widths/modulo-`l`, fixed-limb two-leg generation; classes are package-private | Separate timing, external review, platform approval, and public API decision |

`JubjubSigners.validatedDedicatedHostJavaRequired()` is deliberately fail-closed while M4–M8
remain open. It accepts no untagged general key, cannot relabel caller-asserted provenance,
and cannot fall back to deterministic-v1 or the legacy signer.
Selection and validation of the first concrete platform/service profile is tracked in
[ADR-0040](0040-jubjub-dedicated-host-signing-profile-v1.md).

## Correctness evidence

The local tests cover:

- exhaustive small and randomized/boundary `Fq`/`Fr` arithmetic against `BigInteger`;
- reproducible 64/128/192-bit carry/borrow boundaries, field identities, and distributivity;
- `R`, `R²`, the modulus, and the Montgomery inverse independently re-derived for both fields,
  rather than validated only through the new kernel's own output;
- canonical imports, aliasing, inverses, every `p/l` quotient, every unsigned-256/l quotient,
  exact raw-limb borrow propagation, zero-inversion semantics, and nonzero-mapping carry
  chains through every 64-bit limb;
- every embedded Poseidon t=3 round/MDS constant against the generated preset and a digest pin;
- randomized Poseidon permutations and deterministic/hedged nonce transcripts against the
  independent existing `BigInteger` implementation;
- complete point add/double/negate/scalar multiplication against `JubjubPoint`;
- deterministic-v1 public keys/signatures byte-for-byte against the legacy signer;
- independent hedged nonce and signature vectors;
- hedged signatures through off-circuit verification and both `verifyStrict` and
  `verifyWithRegisteredKey`, without changing their row/nonzero pins;
- typed message byte order, canonical boundary, defensive copying, a public circuit-input
  conversion, and independently pinned SHA-512 framing/block-boundary vectors;
- key rejection sampling, zero-nonce-key rejection, provider failure, lifecycle/source wiping,
  close/sign and concurrent/double-close races, recorded close-failure replay, shared key
  destruction semantics, and concurrent signing;
- fault injection into nonce state, secret-key scratch, `R`, and `S`;
- compiled fixed-limb scalar-multiplication structure pins the 252-iteration primitive
  schedule and branch-free mask-selection chain;
- the hardened dependency gate uses exact external class/method and public-boundary-edge
  allow-lists, scans nested classes, and includes negative fixtures for boxing,
  data-dependent collections, and an unapproved public-adapter call;
- hardened Pedersen outputs against legacy generation for boundary and random 256-bit inputs,
  including commit/close races.

On 2026-07-27, the final local source state passed:

- `./gradlew --no-daemon test --rerun-tasks`: 3,991 tests, zero failures, zero errors,
  20 skipped; all 145 actionable tasks executed;
- a separate rerun of
  `GnarkFullProveTest.groth16FullProve_multiplierCircuit`, which generated and verified the
  Groth16 proof successfully;
- the registered-key verifier cross-backend smoke pin: PLONK 32,563 gates (three public
  anchors), Halo2 32,560 rows, padded domain 32,768 for both, with the same public-input
  values and wire identities.

These are local regression and interoperability gates. They do not satisfy M4, M6, M7, or M8.

## Performance evidence

One diagnostic run on:

```text
OpenJDK 64-Bit Server VM 25.0.2+12-LTS
Mac OS X / aarch64 / 16 logical processors
G1 GC / `-Xmx1g` benchmark worker
default `SecureRandom`: `NativePRNG`, provider `SUN/25`
```

recorded:

| Operation | Median | p95 | p99 | Approx. allocation |
|---|---:|---:|---:|---:|
| Legacy `sign(Keypair,msg)` | 5.903 ms | 6.622 ms | 8.345 ms | 15.68 MB/op |
| Fixed deterministic-v1 sign + nonce re-derivation + release verify | 4.377 ms | 4.639 ms | 5.421 ms | 11.36 MB/op |
| Fixed hedged candidate sign + nonce re-derivation + release verify | 4.553 ms | 4.906 ms | 5.351 ms | 11.28 MB/op |
| Existing public verify | 3.971 ms | 4.223 ms | 4.775 ms | 10.34 MB/op |
| Legacy Pedersen generation | 3.042 ms | 3.360 ms | 4.045 ms | 7.87 MB/op |
| Fixed Pedersen candidate | 0.342 ms | 0.386 ms | 0.407 ms | 5.8 KB/op |
| Hardened key import/derivation | 0.213 ms | 0.257 ms | 0.639 ms | 7.2 KB/op |

This rerun includes the final nonce re-derivation and invariant check. It is a diagnostic
single-process run, not a stable performance budget or platform approval.

The unchanged independent `BigInteger` public release verification dominates hardened signing
latency and allocation. That is the cost of implementation diversity required by Decision 7,
not secret-bearing fallback. It also means allocation/GC behavior is an M6/M8 production gate.

A warmed concurrency diagnostic (25 warmup and 200 measured operations per thread) recorded
approximately 218, 441, 865, and 1,453 signatures/s at 1, 2, 4, and 8 threads respectively.
This was an unloaded local process, not a service load test.

## Timing evidence

The opt-in Welch harness alternates classes, prints results, and asserts only that its
deliberately leaky control is detected. On the machine above:

| Execution mode | Point `1` vs `l-1` | Poseidon `sk=1` vs `l-1` | Hedged `aux=00` vs `ff` | Leaky control |
|---|---:|---:|---:|---:|
| Normal tiered | `|t|=0.890` | `1.538` | `0.735` | `502.238` |
| C1 only | `0.253` | `1.554` | `1.097` | `183.613` |
| C2 batch | `0.956` | `0.927` | `0.943` | `18.659` |
| Interpreter | `2.108` | `0.257` | `0.830` | `520.177` |

No detected signal in these selected classes is useful evidence for this run only. It does
not establish constant-time execution, remote safety, other secrets/classes, deoptimization
behavior, or another JVM/CPU.

## Stable-component impact

The ADR-0039 path is additive. It does not modify the R1CS compiler, PLONK compiler,
constraint graph, circuit gadgets, Poseidon parameters, or existing verifier equations. It
deliberately reuses the existing public challenge and release verifier after public
conversion.
`JubjubMessage` adds typed public overloads; existing calls with statically typed
`BigInteger` arguments and existing bytecode remain compatible. Untyped Java `null` literals
may require a cast because of overload resolution.
Deterministic-v1 vectors are unchanged. The hedged profile changes only newly generated
signature bytes, which existing verifiers/circuits accept.

M6/M7 release review must reject any final source state that changes circuit rows, nonzeros,
padded domains, public verification behavior, or the existing local CIP-1852 pin. The
downstream account-ownership application does not yet have a binding full graph/R1CS digest;
that separate release gate remains open in the dedicated-host checklist and VK compatibility
must not be claimed from its current print-only measurement.
