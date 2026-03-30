# ADR-0012: Pure Java Provers for Groth16 and PlonK

## Status
Proposed

## Date
2026-03-29

## Context

ZeroJ's proving pipeline depends on native libraries: gnark (Go) for Groth16/PlonK, and Rust for Halo2. While these deliver excellent performance, they create friction:

1. **Cross-compilation burden** — each target platform (macOS ARM64, Linux x86_64, Linux ARM64) needs separately compiled native libraries
2. **GraalVM native-image incompatibility** — Go's embedded runtime and Rust's allocator interact poorly with `native-image`; the static `LIBRARY_ARENA` hack in `GnarkLibrary` exists because Go's runtime cannot be re-initialized after `dlclose`
3. **Mobile deployment impossible** — Android/iOS cannot load Go/Rust shared libraries without JNI wrappers
4. **Serverless cold starts** — native library extraction and loading adds 500ms-2s to Lambda/Cloud Run cold starts
5. **Developer experience** — cannot step-debug through the proving process in IntelliJ

Meanwhile, **ZeroJ already has 60% of the cryptographic primitives needed for a pure Java prover**:

| Primitive | Status | Location |
|-----------|--------|----------|
| BN254 field tower (Fp -> Fp2 -> Fp6 -> Fp12) | Complete | `zeroj-verifier-groth16/.../bn254/` |
| BLS12-381 field tower (Fp -> Fp2 -> Fp6 -> Fp12) | Complete | `zeroj-verifier-groth16/.../bls12381/field/` |
| BN254 optimal Ate pairing | Complete | `BN254Pairing.java` |
| BLS12-381 optimal Ate pairing | Complete | `BLS12381Pairing.java` |
| G1/G2 point arithmetic (affine) | Complete | `G1Point.java`, `G2Point.java` |
| Groth16 verifier (BN254 + BLS12-381) | Complete, tested | `Groth16BN254Verifier.java`, etc. |
| PlonK verifier (BN254 + BLS12-381) | Complete, tested | `PlonkBN254Verifier.java`, etc. |
| Fiat-Shamir transcript (Keccak + SHA-256) | Complete, tested | `FiatShamirTranscript.java` |
| R1CS constraint system | Complete | `zeroj-circuit-dsl/.../r1cs/` |
| PlonK constraint system | Complete | `zeroj-circuit-dsl/.../plonk/` |
| Witness calculator | Complete | `WitnessCalculator.java` |
| **FFT/NTT over Fr** | **Missing** | — |
| **Multi-scalar multiplication (MSM)** | **Missing** | — |
| **Montgomery-form field arithmetic** | **Missing** | — |
| **Jacobian/projective coordinates** | **Missing** | — |
| **Polynomial arithmetic over Fr[x]** | **Missing** | — |
| **KZG polynomial commitment** | **Missing** | — |

The proving algorithm itself is well-documented (Groth16 paper, PlonK paper) and the existing verifier code demonstrates the mathematical patterns (pairing checks, polynomial evaluations, Fiat-Shamir challenges). **A prover inverts the verifier's operations**: where the verifier checks `e(A, B) = e(alpha, beta) * e(L, gamma) * e(C, delta)`, the prover computes `A`, `B`, `C` from the proving key + witness via MSM and polynomial evaluation.

### Performance reality

The dominant cost in proving is multi-scalar multiplication (MSM). Estimated performance:

| Implementation | 1K-constraint Groth16 | 10K constraints | 100K constraints |
|---------------|----------------------|-----------------|------------------|
| gnark (Go + hand-written asm) | ~20 ms | ~100 ms | ~1-2 sec |
| Pure Java (BigInteger, naive) | ~3-8 sec | ~30-90 sec | ~10-30 min |
| Pure Java (Montgomery + Pippenger) | ~200-500 ms | ~2-5 sec | ~20-60 sec |
| Pure Java + Panama Vector API | ~100-300 ms | ~1-3 sec | ~10-30 sec |

The `BigInteger` bottleneck: no Montgomery form (full `mod()` division per operation), object allocation per arithmetic op, no SIMD. With proper `long[4]` Montgomery fields + Pippenger MSM + Jacobian coordinates, the gap closes from ~200x to ~10-30x.

For context: **snarkjs does Groth16 proving in JavaScript** (~5-10 seconds for 1K constraints). Pure Java can match or beat that.

### Strategic value

The pure Java prover is NOT about beating gnark. It's the **portable fallback**:

- gnark FFM remains the production prover for large circuits and server deployments
- Pure Java prover enables: zero-dependency GraalVM native-image, Android/iOS mobile, serverless, full IntelliJ debugging
- Same relationship that `Groth16BLS12381PureJavaVerifier` already has to the native `blst`-based verifier

## Decision

### Build pure Java provers for Groth16 and PlonK, starting with optimized field arithmetic foundations

The implementation follows a layered approach: optimize the foundations first (field arithmetic, EC operations, FFT, MSM), then build Groth16 prover, then PlonK prover. Each layer is independently useful and testable.

### Layer 1: Montgomery-form field arithmetic (`MontFp`)

Replace `BigInteger`-based field elements with fixed-width `long[]` arrays using Montgomery multiplication:

```java
// BN254 scalar field: 4 x 64-bit limbs
public final class MontFp254 {
    private final long l0, l1, l2, l3;  // Montgomery form

    public MontFp254 mul(MontFp254 other) {
        // 4-limb Montgomery multiplication
        // Uses Math.multiplyHigh (Java 9+) and Math.unsignedMultiplyHigh (Java 18+)
        // No BigInteger allocation, no mod() division
    }

    public MontFp254 add(MontFp254 other) {
        // 4-limb addition with conditional subtraction
    }
}
```

Expected improvement: **5-10x** over BigInteger for Fp multiply.

Java 25's `Math.unsignedMultiplyHigh` provides the 128-bit multiply primitive needed for efficient Montgomery reduction without `BigInteger`.

### Layer 2: Jacobian/projective EC point arithmetic

Replace affine coordinates (requires Fp inversion per addition) with Jacobian:

```java
// Jacobian: (X, Y, Z) represents affine (X/Z^2, Y/Z^3)
public record JacobianG1(MontFp254 x, MontFp254 y, MontFp254 z) {

    public JacobianG1 add(JacobianG1 other) {
        // 11M + 5S (no inversion!)
    }

    public JacobianG1 doublePoint() {
        // 1M + 8S (no inversion!)
    }

    public AffineG1 toAffine() {
        // Single inversion at the end
        var zInv = z.inverse();
        // ...
    }
}
```

Expected improvement: **3-5x** for point operations (eliminates inversion from inner loops).

### Layer 3: FFT/NTT over Fr

Radix-2 Number Theoretic Transform over the scalar field, needed for polynomial multiplication and h(x) computation:

```java
public final class FieldFFT {

    public static MontFp254[] fft(MontFp254[] coeffs, MontFp254 omega) {
        // In-place Cooley-Tukey butterfly
        // omega = primitive root of unity for the domain
    }

    public static MontFp254[] ifft(MontFp254[] evals, MontFp254 omegaInv, MontFp254 domainInv) {
        // Inverse FFT: evaluations -> coefficients
    }
}
```

Domain generation: find the largest power-of-2 root of unity in the scalar field. For BN254 Fr, the 2-adicity is 28 (supports domains up to 2^28 = 268M).

### Layer 4: Pippenger multi-scalar multiplication (MSM)

The single most impactful optimization. Computes `sum(s_i * P_i)` for n scalars and n points:

```java
public final class MSM {

    public static JacobianG1 pippenger(AffineG1[] points, MontFp254[] scalars) {
        // 1. Choose window size c = max(1, log2(n) - 2)
        // 2. Decompose each scalar into c-bit windows
        // 3. For each window position:
        //    - Bucket sort: bucket[j] += points[i] for window digit j
        //    - Bucket reduction: running_sum = sum(j * bucket[j])
        // 4. Combine window results via doubling
    }
}
```

| n (points) | Naive (double-and-add) | Pippenger | Speedup |
|------------|----------------------|-----------|---------|
| 100 | 25,600 EC ops | ~5,000 | 5x |
| 1,000 | 256,000 EC ops | ~33,000 | 8x |
| 10,000 | 2,560,000 EC ops | ~250,000 | 10x |
| 100,000 | 25,600,000 EC ops | ~2,000,000 | 13x |

### Layer 5: Groth16 prover

Given: R1CS constraint system `(A, B, C)`, proving key `pk`, witness `w`.

```java
public final class Groth16Prover {

    public Groth16Proof prove(R1CSConstraintSystem r1cs, ProvingKey pk, BigInteger[] witness) {
        // 1. Compute h(x) = (A(x) * B(x) - C(x)) / Z_H(x)
        //    - Evaluate A, B, C at witness → a_vals, b_vals, c_vals
        //    - FFT to get polynomial coefficients
        //    - Polynomial division by Z_H
        //    - IFFT to get h(x) coefficients

        // 2. Sample random blinding factors r, s

        // 3. Compute proof elements via MSM:
        //    A = [alpha]_1 + sum(a_i * [A_i]_1) + r * [delta]_1
        //    B = [beta]_2  + sum(a_i * [B_i]_2) + s * [delta]_2
        //    C = sum(h_i * [H_i]_1) + sum(w_i * [L_i]_1) + s*A + r*B - r*s*[delta]_1

        // 4. Return Groth16Proof(A_G1, B_G2, C_G1)
    }
}
```

**Proving key format**: import from gnark or snarkjs exported files. The proving key contains the encrypted evaluation points `[A_i]_1`, `[B_i]_2`, `[H_i]_1`, `[L_i]_1` from the trusted setup.

### Layer 6: PlonK prover

Given: PlonK constraint system, SRS, witness.

```java
public final class PlonKProver {

    public PlonKProof prove(PlonKConstraintSystem plonk, SRS srs, BigInteger[] witness) {
        // Round 1: Commit to wire polynomials
        //   [a(x)]_1, [b(x)]_1, [c(x)]_1 via KZG commit (= MSM with SRS)

        // Round 2: Compute permutation accumulator Z(x)
        //   Fiat-Shamir challenges beta, gamma
        //   Z(x) encodes copy constraint satisfaction

        // Round 3: Compute quotient polynomial t(x)
        //   t(x) = (gate_constraint + permutation_constraint + ...) / Z_H(x)
        //   Split into t_lo, t_mid, t_hi and commit

        // Round 4: Compute opening evaluations
        //   Fiat-Shamir challenge zeta
        //   Evaluate all polynomials at zeta

        // Round 5: Compute opening proofs
        //   KZG opening proof = (f(x) - f(zeta)) / (x - zeta) committed

        // Return PlonKProof(commitments, evaluations, opening_proofs)
    }
}
```

### Module structure

```
zeroj-crypto/                          (new module — shared crypto primitives)
  src/main/java/com/bloxbean/cardano/zeroj/crypto/
    field/
      MontFp254.java                   — BN254 Fr in Montgomery form (long[4])
      MontFp381.java                   — BLS12-381 Fr in Montgomery form (long[6])
      FieldFFT.java                    — NTT/IFFT over Fr
    ec/
      JacobianG1.java                  — BN254 G1 in Jacobian coords
      JacobianG2.java                  — BN254 G2 in Jacobian coords
      JacobianG1BLS.java              — BLS12-381 G1 in Jacobian coords
      JacobianG2BLS.java              — BLS12-381 G2 in Jacobian coords
    msm/
      Pippenger.java                   — Multi-scalar multiplication
    poly/
      UnivariatePoly.java             — Polynomial over Fr (coefficients)
      PolyArith.java                  — add, mul, div, evaluate

zeroj-prover-java/                     (new module — pure Java provers)
  src/main/java/com/bloxbean/cardano/zeroj/prover/java/
    groth16/
      Groth16JavaProver.java           — implements ZkProver SPI
      ProvingKey.java                  — proving key data structure
      ProvingKeyImporter.java          — import from snarkjs/gnark format
    plonk/
      PlonKJavaProver.java            — implements ZkProver SPI
      SRS.java                         — structured reference string
      KZGCommitment.java              — KZG polynomial commitment
```

### Prover key management

The pure Java prover can obtain proving keys in two ways:

**For development/testing:** Use the pure Java `PowersOfTau.generate()` and `Groth16Setup.setup()` (see ADR-0013). This is single-party and NOT secure for production.

**For production:** Import proving keys generated by established MPC ceremony tools:

| Source | Format | Import method |
|--------|--------|---------------|
| snarkjs | `.zkey` file (iden3 binary) | `ZkeyImporter.importZkey(path)` |
| Powers of Tau ceremony | `.ptau` file | `PtauImporter.importPtau(path)` |

Production deployments MUST use SRS from established multi-party computation ceremonies (Hermez, Zcash PoT, Perpetual PoT). See ADR-0013 for details.

## Implementation Plan

### Phase 1: Foundation — Montgomery fields + Jacobian coords (4-6 weeks)

**Deliverables:**
- `MontFp254` — BN254 scalar field, Montgomery form, `long[4]`
- `MontFp381` — BLS12-381 scalar field, Montgomery form, `long[6]`
- `JacobianG1`, `JacobianG2` — Jacobian coordinate EC arithmetic
- Benchmark suite: field mul, EC add/double/scalarMul vs BigInteger baseline

**Acceptance criteria:**
- `MontFp254.mul` is >= 5x faster than `BigInteger.multiply().mod()`
- `JacobianG1.scalarMul` is >= 3x faster than current affine `G1Point.scalarMul`
- All existing verifier tests pass when swapped to new field/EC types

**Side benefit:** The existing pure Java verifiers immediately benefit. Montgomery fields make verification 5-10x faster, improving the `PureJavaVerifier` experience.

### Phase 2: FFT + Pippenger MSM (3-4 weeks)

**Deliverables:**
- `FieldFFT` — radix-2 NTT/IFFT, domain generation (roots of unity)
- `Pippenger` — multi-scalar multiplication with configurable window size
- `UnivariatePoly` — polynomial type with add/mul/div/evaluate

**Acceptance criteria:**
- FFT(IFFT(coeffs)) == coeffs for random polynomials
- Pippenger MSM produces same result as naive sum-of-scalarMul
- Pippenger is >= 5x faster than naive for n >= 100 points

### Phase 3: Groth16 pure Java prover (4-6 weeks)

**Deliverables:**
- `Groth16JavaProver` — pure Java Groth16 proving
- `ProvingKeyImporter` — import snarkjs `.zkey` files
- h(x) polynomial computation via FFT
- Proof generation via 3x MSM + polynomial evaluation

**Acceptance criteria:**
- Prove the multiplier circuit (1 constraint) — proof verifies with existing pure Java verifier
- Prove a Poseidon hash circuit (~250 constraints) — proof verifies
- Prove a 1K-constraint circuit in < 10 seconds
- Proof bytes are identical format to gnark/snarkjs (same verification works)

### Phase 4: PlonK pure Java prover (6-8 weeks)

**Deliverables:**
- `KZGCommitment` — KZG polynomial commitment using MSM
- `PlonKJavaProver` — full 5-round PlonK prover
- SRS import from Powers of Tau ceremony files

**Acceptance criteria:**
- Prove the multiplier circuit — proof verifies with existing pure Java PlonK verifier
- Fiat-Shamir transcript byte-for-byte compatible with snarkjs (reuse existing `FiatShamirTranscript`)
- 1K-constraint circuit in < 10 seconds

### Phase 5: Optimization (ongoing)

- Panama Vector API (`jdk.incubator.vector`) for SIMD Montgomery multiplication
- Parallel MSM using virtual threads (bucket accumulation is embarrassingly parallel)
- GraalVM native-image profiling and optimization
- Lazy polynomial evaluation (avoid materializing large polynomials)

## Consequences

### Positive

1. **Zero native dependencies for proving** — GraalVM `native-image` produces a single binary with no external .dylib/.so
2. **Android/iOS mobile proving** — no JNI, no cross-compilation of Go/Rust
3. **Serverless-friendly** — no library extraction on cold start
4. **Full debuggability** — step through proving in IntelliJ, profile with JFR/async-profiler
5. **Foundation reuse** — Montgomery fields + Pippenger MSM + FFT benefit the existing verifiers and any future pure Java crypto
6. **Correctness reference** — readable Java implementation easier to audit than gnark's assembly
7. **Progressive enhancement** — each phase is independently useful (Phase 1 speeds up verifiers, Phase 2 enables polynomial math, etc.)

### Negative

1. **10-30x slower than gnark** for optimized Java, 50-200x for BigInteger baseline — not suitable for production proving of large circuits (>50K constraints)
2. **Significant implementation effort** — ~4-6 months for the full stack (Groth16 + PlonK)
3. **Security risk** — a new prover implementation needs extensive testing and ideally third-party audit before production use
4. **Montgomery field arithmetic is subtle** — carry chain bugs produce wrong field elements that may pass some tests but fail on edge cases
5. **Proving key formats are underdocumented** — snarkjs `.zkey` and gnark binary formats have limited specifications; may need reverse engineering

## Known Limitations

### Constant-time operations

The pure Java cryptographic primitives are **NOT constant-time**. Variable-time operations
include field inversion (BigInteger GCD), scalar multiplication (double-and-add), and
conditional subtraction after Montgomery reduction.

This is acceptable for a **ZK prover** (runs locally, secret witness is not exposed via
timing). It would be a vulnerability if these primitives were used for:
- Digital signature generation (private key leaks via timing)
- Verifier-with-secret protocols
- Key generation ceremonies

**TODO:** Implement constant-time alternatives (Fermat inversion via addition chain,
Montgomery ladder for scalar multiplication) if the cryptographic primitives are ever
used beyond the ZK prover context. See ADR-0013 for the full constant-time assessment table.

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Montgomery field implementation bugs | High | Differential testing: `MontFp254.mul(a,b)` == `BigInteger a*b mod p` for millions of random inputs |
| Pippenger MSM correctness | High | Compare against naive MSM for random inputs; test with gnark's test vectors |
| Proving key import parsing errors | Medium | Validate imported keys by re-verifying a known proof before using for proving |
| Non-constant-time crypto primitives | Medium | Acceptable for prover (local execution); document limitation; implement CT alternatives if scope expands |
| Performance worse than estimated | Medium | Benchmark at each phase; if Montgomery gives < 3x improvement, reassess |
| Panama Vector API removed from JDK | Low | Montgomery field works without SIMD (just slower); SIMD is an optimization, not a requirement |
| snarkjs/gnark format breaking changes | Low | Pin to specific versions; proving key format is stable (hasn't changed in years) |

## References

- [Groth16 paper — On the Size of Pairing-based Non-interactive Arguments](https://eprint.iacr.org/2016/260)
- [PlonK paper — Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge](https://eprint.iacr.org/2019/953)
- [Pippenger MSM — On the Evaluation of Powers and Monomials](https://cr.yp.to/papers/pippenger.pdf)
- [Montgomery multiplication — Modular Multiplication Without Trial Division](https://doi.org/10.1090/S0025-5718-1985-0777282-X)
- [Hyperledger Besu alt_bn128](https://github.com/hyperledger/besu/tree/main/crypto/algorithms/src/main/java/org/hyperledger/besu/crypto/altbn128) — Java Montgomery field reference
- [snarkjs source](https://github.com/iden3/snarkjs) — reference prover in JavaScript (proves using BigInt, similar constraints as Java BigInteger)
- ADR-0003: Pure Java MVP
- ADR-0010: Java DSL for ZK Circuit Definition
- ADR-0011: Generic Halo2 Prover via Rust FFM
