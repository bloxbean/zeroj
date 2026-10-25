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
- a Plutus V3 verifier: the challenges are SHAKE128 outputs, and Plutus V3 has no SHAKE128 builtin
  (spec §12). An in-script Keccak-f[1600] with the PV11 bitwise builtins was not measured. The
  Cardano figures below are for the algebra only;
- the §15 Yaci DevKit confirmation and fees, which matter only for a verifier that could be
  deployed.

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

**Samples:** proving runs 12, 8 and 6 measured iterations at `n` = 16, 32, 64, and verification
24 to 40, after warm-up. With 6 iterations, p95 is the largest sample.

**Load:** other services were running on the machine, with a load average of about 7 to 12 (16
cores) throughout. In this run p95 is within 2% of p50 for every single-threaded figure. An
earlier run under similar load was 1–3% slower and had one figure (blst decode at `n = 64`) 7%
apart.

### One thread

| Operation | Pure Java p50 | Pure Java p95 | Pure Java allocated/op | blst p50 | blst p95 | blst allocated/op |
|---|---:|---:|---:|---:|---:|---:|
| prove, n = 16 (secret path) | 1,526 ms | 1,538 ms | 916 MB | 1,748 ms | 1,770 ms | 994 MB |
| prove, n = 32 | 3,037 ms | 3,048 ms | 1.82 GB | 3,467 ms | 3,490 ms | 1.96 GB |
| prove, n = 64 | 6,049 ms | 6,070 ms | 3.62 GB | 6,883 ms | 6,910 ms | 3.89 GB |
| decode, n = 16 (every point subgroup-checked) | 49.9 ms | 50.4 ms | 28.7 MB | 50.2 ms | 50.8 ms | 28.7 MB |
| decode, n = 32 | 58.5 ms | 59.5 ms | 33.5 MB | 58.5 ms | 59.5 ms | 33.5 MB |
| decode, n = 64 | 66.7 ms | 67.2 ms | 38.3 MB | 67.7 ms | 68.7 ms | 38.3 MB |
| verify, decoded proof and commitment, n = 16 | 405 ms | 411 ms | 233 MB | 412 ms | 417 ms | 235 MB |
| verify, decoded, n = 32 | 681 ms | 690 ms | 395 MB | 699 ms | 707 ms | 398 MB |
| verify, decoded, n = 64 | 1,231 ms | 1,243 ms | 708 MB | 1,264 ms | 1,280 ms | 714 MB |
| verify from octets (decode `V` and proof), n = 16 | 459 ms | 464 ms | 264 MB | 466 ms | 471 ms | 266 MB |
| verify from octets, n = 32 | 747 ms | 756 ms | 430 MB | 765 ms | 775 ms | 434 MB |
| verify from octets, n = 64 | 1,304 ms | 1,321 ms | 749 MB | 1,340 ms | 1,351 ms | 755 MB |

### Wall time per operation, 1 and 8 threads

| Operation | Pure Java, 1 thread | Pure Java, 8 threads | blst, 1 thread | blst, 8 threads |
|---|---:|---:|---:|---:|
| prove, n = 16 | 1,523 ms | 196 ms | 1,747 ms | 225 ms |
| prove, n = 32 | 3,034 ms | 390 ms | 3,449 ms | 443 ms |
| prove, n = 64 | 6,037 ms | 788 ms | 6,900 ms | 884 ms |
| verify from octets, n = 16 | 458 ms | 58.8 ms | 469 ms | 60.0 ms |
| verify from octets, n = 32 | 748 ms | 96.1 ms | 765 ms | 97.8 ms |
| verify from octets, n = 64 | 1,304 ms | 167 ms | 1,338 ms | 171 ms |

Each operation is independent, so 8 threads give about 7.7× the throughput.

**Where the time goes.**
- **Re-validation of points dominates verification.** Verification makes `5 + 2n + 2k + 4`
  provider multiplications (`VerifierWorkTest`): 49, 83 and 149. The pure-Java provider calls
  `Bls12381Codecs.requireValid` on each input point. That is a pure-Java subgroup check of about
  4.3 ms (measured in ADR-0060), about the cost of one scalar multiplication, which accounts for
  about half the total: 0.21, 0.36 and 0.64 s.
- **blst checks twice.** The blst provider re-validates the input point and validates its output
  again when decoding it back (`Bls12381Codecs.g1FromUncompressed`). That is two pure-Java
  subgroup checks per call: 2 × 149 × 4.3 ms ≈ 1.28 s at `n = 64`, essentially all of its 1.26 s
  verification. blst's faster multiplication therefore gains nothing, and proving on blst is
  about 14% slower.
- **The levers** are an MSM in the provider SPI (#22) and trusted-point handling (#104), which
  would remove the input and output re-validation. Neither is in this ADR. No check was removed for
  speed (ADR-0061 M3 exit criterion).
- **Allocation** is large, because the pure-Java affine arithmetic allocates a `BigInteger` per
  field operation: about 0.7 GB per 64-bit verification.

**Determinism** (`BulletproofDeterminismTest`, in `zeroj-blst`): the verdict and layer of all 128
positive and negative vector cases hash to the same digest:
- across two in-process runs on each provider;
- across the two providers;
- in a fresh JVM process per provider (the same binary and flags).

## Cardano cost study (M4): the verifier algebra in the Julc VM, PV11

**Harness:** `BulletproofAlgebraCostTest` with the probe `BulletproofAlgebraCostProbe` in
`zeroj-onchain-julc` test sources. Run it with
`./gradlew :zeroj-onchain-julc:test --tests '*BulletproofAlgebraCostTest'`. The Julc VM is
`0.1.0-pre18`, with the Plutus V3 PV11 cost model shipped with it (350 parameters). Limits:
10,000,000,000 CPU steps and 16,500,000 memory units per transaction.

**The probe is not a verifier.** It takes the transcript challenges `y`, `z`, `x`, `x_u` and
`x_1 … x_k` as redeemer inputs. A real verifier must derive them with SHAKE128, for which Plutus V3
has no builtin. The probe does most of what a verifier would do after that:
- checks the five proof scalars are below `q`;
- checks the supplied inverses of `y` and every `x_j`;
- refuses the identity encoding for `V` and every proof point;
- hashes the `2n + 1` supplied generator encodings and compares the digest (the cost of binding
  them; a real script would embed the generators or their digest);
- computes `δ(y, z)`, the `s_i` products (most significant bit first), and every check-2
  coefficient on-chain;
- decompresses every point (with its subgroup check) and evaluates check 1 (5 terms) and check 2
  (`2n + 2k + 4` terms) with `bls12_381_G1_multiScalarMul`, each compared with the identity.

It leaves out, so the figures slightly understate a full verifier's algebra:
- the zero checks on `z`, `x` and `x_u` (`y` and every `x_j` are covered by the inverse check);
- parsing the proof octets: the length check, slicing, and converting the five scalars;
- computing the inverses, which are supplied and only checked.

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

**Verdict.** There is no verifier at any width: Plutus V3 has no SHAKE128 builtin, and an in-script
Keccak-f[1600] (not measured) would come on top of the algebra. The algebra alone fits a
transaction at `n = 16`, barely at `n = 32`, and not at `n = 64`. A
Cardano-native range proof would need a different transcript (for example SHA-256 based), a new
protocol identifier and its own ADR (ADR-0061 D3 note, D8). This study publishes nothing.

### Generators on-chain (I1)

`BulletproofGeneratorsProbe` recomputes all 129 generators with the Julc VM's
`bls12_381_G1_hashToGroup` (RFC 9380 hash-to-curve), in 9 evaluations of up to 16 points, and
compares each with the pinned encoding of spec Appendix A. All 129 match; a wrong tag does not.
Total: 7,745,275,620 CPU steps and 2,657,253 memory units (about 60M CPU steps per point). This is a
fourth reproduction of the generator set, after the Java test, the Python implementation and
py_ecc.
