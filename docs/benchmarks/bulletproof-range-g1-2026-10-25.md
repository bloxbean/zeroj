# Bulletproof range proofs over BLS12-381 G1 (`bulletproof-range-bls12-381-g1-v1`): host and Cardano measurements (ADR-0061 M3, M4)

**Date:** 2026-10-25

These numbers are records, not checks (ADR-0061 I11, `commitment-profiles-v1` §15). They describe
this JVM, this CPU and these cost models only. They make no timing-side-channel claim, and they
are not security evidence.

**Machine:** Apple M4 Max (arm64, 16 cores), macOS 26.0.1, Oracle GraalVM JDK 25.0.2 (JIT, not
native image).

**Not measured:**
- GraalVM native image;
- x86-64;
- a Plutus V3 verifier, because none can exist: the challenges are SHAKE128 outputs, and Plutus V3
  has no SHAKE128 (spec §12). The Cardano figures below are for the algebra only.

## Proof sizes

| `n` | `k` | Proof | Commitment |
|---:|---:|---:|---:|
| 16 | 4 | 736 octets | 48 octets |
| 32 | 5 | 832 octets | 48 octets |
| 64 | 6 | 928 octets | 48 octets |

## Host (M3)

**Harness:** `BulletproofBenchmark` (a `zeroj-bls12381` test fixture), a standalone `main` that
launches three fresh JVM forks per provider. Each figure is the median, across the forks, of each
fork's p50 and p95. Allocation is per operation, on the calling thread. Every result goes through a
volatile sink, so the JIT cannot drop the work. Run it with
`./gradlew :zeroj-bls12381:bulletproofBenchmark` (pure Java) or
`./gradlew :zeroj-blst:bulletproofBenchmarkBlst` (blst).

**Load:** other services were running on the machine. The load average was 5–9 during the
pure-Java run and rose to 20 near the end of the blst run. p95 stays within 2% of p50 throughout.

| Operation | Pure Java p50 | Pure Java p95 | blst p50 | blst p95 | Allocated/op (pure) |
|---|---:|---:|---:|---:|---:|
| prove, n = 16 (secret path) | 1,555 ms | 1,579 ms | 1,785 ms | 1,803 ms | 918 MB |
| prove, n = 32 | 3,115 ms | 3,134 ms | 3,538 ms | 3,553 ms | 1.82 GB |
| prove, n = 64 | 6,219 ms | 6,227 ms | 6,965 ms | 6,977 ms | 3.62 GB |
| decode, n = 16 (every point subgroup-checked) | 51.3 ms | 52.7 ms | 51.3 ms | 52.4 ms | 28.7 MB |
| decode, n = 32 | 59.8 ms | 60.3 ms | 59.8 ms | 60.9 ms | 33.5 MB |
| decode, n = 64 | 68.8 ms | 69.5 ms | 67.5 ms | 72.1 ms | 38.3 MB |
| verify, decoded proof and commitment, n = 16 | 414 ms | 420 ms | 428 ms | 436 ms | 233 MB |
| verify, decoded, n = 32 | 700 ms | 703 ms | 715 ms | 723 ms | 394 MB |
| verify, decoded, n = 64 | 1,260 ms | 1,274 ms | 1,273 ms | 1,283 ms | 708 MB |
| verify from octets (decode `V` and proof), n = 16 | 466 ms | 472 ms | 480 ms | 488 ms | 264 MB |
| verify from octets, n = 32 | 767 ms | 771 ms | 780 ms | 790 ms | 430 MB |
| verify from octets, n = 64 | 1,335 ms | 1,363 ms | 1,345 ms | 1,358 ms | 749 MB |

**Wall time per verification from octets** across threads:

| `n` | Pure Java, 1 thread | Pure Java, 8 threads | blst, 1 thread | blst, 8 threads |
|---:|---:|---:|---:|---:|
| 16 | 468 ms | 59.5 ms | 483 ms | 60.5 ms |
| 32 | 767 ms | 97.1 ms | 775 ms | 98.5 ms |
| 64 | 1,335 ms | 170 ms | 1,342 ms | 172 ms |

**Where the time goes.**
- **The provider re-checks every point.** Verification makes `5 + 2n + 2k + 4` provider
  multiplications (`VerifierWorkTest`): 49, 83 and 149. Both providers call
  `Bls12381Codecs.requireValid` on every input point, a pure-Java subgroup check of about 4.3 ms
  (measured in ADR-0060). That alone is about 0.2, 0.36 and 0.64 s, roughly half the total.
- **blst gives no speed-up here.** The re-check, plus the conversion between ZeroJ's affine points
  and blst's, costs more than blst saves on the multiplication. Proving on blst is 12–15% slower.
- **The levers** are an MSM in the provider SPI (#22) and trusted-point handling (#104). Neither is
  in this ADR. No check was removed for speed (ADR-0061 M3 exit criterion).
- **Allocation** is large, because the pure-Java affine arithmetic allocates a `BigInteger` per
  field operation: about 0.7 GB per 64-bit verification.

**Determinism** (`BulletproofDeterminismTest`, in `zeroj-blst`): the verdict and layer of all 128
positive and negative vector cases hash to the same digest across two in-process runs on each
provider, across the providers, and in a fresh JVM per provider.

## Cardano cost study (M4): the verifier algebra in the Julc VM, PV11

**Harness:** `BulletproofAlgebraCostTest` with the probe `BulletproofAlgebraCostProbe` in
`zeroj-onchain-julc` test sources. Run it with
`./gradlew :zeroj-onchain-julc:test --tests '*BulletproofAlgebraCostTest'`. The Julc VM is
`0.1.0-pre18`, with the Plutus V3 PV11 cost model shipped with it (350 parameters). Limits:
10,000,000,000 CPU steps and 16,500,000 memory units per transaction.

**The probe is not a verifier.** It takes the transcript challenges `y`, `z`, `x`, `x_u` and
`x_1 … x_k` as redeemer inputs. A real verifier must derive them with SHAKE128, which Plutus V3
cannot do. The probe does everything else a verifier would do:
- checks the five proof scalars are below `q`;
- checks the supplied inverses of `y` and every `x_j`;
- refuses the identity encoding for `V` and every proof point;
- hashes the `2n + 1` supplied generator encodings and compares the digest (the cost of binding
  them; a real script would embed the generators or their digest);
- computes `δ(y, z)`, the `s_i` products (most significant bit first), and every check-2
  coefficient on-chain;
- decompresses every point (with its subgroup check) and evaluates check 1 (5 terms) and check 2
  (`2n + 2k + 4` terms) with `bls12_381_G1_multiScalarMul`, each compared with the identity.

An honest proof made by the Java prover passes, and the same proof with `a + 1` fails, at every
width.

| `n` | CPU steps | Share of the CPU limit | Memory units | Share of the memory limit | Verdict for the algebra alone |
|---:|---:|---:|---:|---:|---|
| 16 | 5,441,488,644 | 54.4% | 3,776,233 | 22.9% | fits one transaction |
| 32 | 8,868,037,216 | 88.7% | 6,771,077 | 41.0% | fits, with 11% CPU left for everything else |
| 64 | 15,541,762,169 | 155.4% | 12,671,729 | 76.8% | does not fit |

- **Script:** 3,797 octets (flat encoding), the same for every width. The redeemer carries the
  generator encodings (`48·(2n + 1)` octets: 1,584, 3,120 and 6,192) and the proof.
- **Against the ADR D8 estimate** (decompression and MSMs only: about 4.4e9, 7.1e9 and 12.2e9
  steps), the measured figures are 24%, 25% and 27% higher. The difference is the on-chain
  coefficient arithmetic, the generator hashing and the scalar and inverse checks.

**Verdict.** There is no verifier at any width: the transcript cannot be computed on-chain. The
algebra alone fits a transaction at `n = 16`, barely at `n = 32`, and not at `n = 64`. A
Cardano-native range proof would need a different transcript (for example SHA-256 based), a new
protocol identifier and its own ADR (ADR-0061 D3 note, D8). This study publishes nothing.

### Generators on-chain (I1)

`BulletproofGeneratorsProbe` recomputes all 129 generators with the Julc VM's
`bls12_381_G1_hashToGroup` (RFC 9380 hash-to-curve), in 9 evaluations of up to 16 points, and
compares each with the pinned encoding of spec Appendix A. All 129 match; a wrong tag does not.
Total: 7,745,275,620 CPU steps and 2,657,253 memory units (about 60M CPU steps per point). This is a
fourth reproduction of the generator set, after the Java test, the Python implementation and
py_ecc.
