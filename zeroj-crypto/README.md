# zeroj-crypto

Pure Java proving primitives and cryptographic building blocks for ZeroJ.

This module is the implementation-heavy core for zero-native-dependency proving.
It includes optimized field arithmetic, elliptic-curve operations, FFT/MSM/KZG
utilities, Groth16 and PlonK setup/proving code, zkey/ptau importers, and the
shared Fiat-Shamir transcript utilities used by PlonK.

## What It Provides

| Area | Key Types |
|------|-----------|
| Legacy BN254 arithmetic | `MontFp254`, `MontFp2_254`, `MontFr254`, `JacobianG1BN254`, `JacobianG2BN254` |
| BLS12-381 proving | `Groth16ProverBLS381`, `PlonKProverBLS381`, `KZGCommitmentBLS381`, `PippengerBLS381` |
| Legacy BN254 Groth16 | `Groth16Setup`, `Groth16Prover`, `ZkeyImporter` (requires `-Dzeroj.allowLegacyBn254=true`) |
| Legacy BN254 PlonK | `PlonKSetup`, `PlonKProver`, `PlonKZkeyImporter`, `PtauImporter` (requires `-Dzeroj.allowLegacyBn254=true`) |
| R1CS import | `R1CSImporter` |
| Polynomial tools | `FieldFFT`, `FieldFFTBLS381`, `KZGCommitment`, `Pippenger` |
| Setup helpers | `PowersOfTau`, `PowersOfTauBLS381`, `Groth16SetupCache`, `PlonkSetupCache` |
| Transcript | `FiatShamirTranscript`, `Keccak256` |

## Why It Is Useful

- Provides a portable proving path with no Go, Node.js, Rust, or native library
  dependency.
- Keeps the default privacy stack local-first and JVM-native.
- Shares transcript and polynomial code across provers and verifiers, avoiding
  verifier-to-prover dependency inversions.
- Supports BLS12-381 flows used by Cardano-oriented examples. BN254 high-level
  proving/import/setup APIs are disabled by default and require explicit legacy
  opt-in for off-chain experiments.

## Production Notes

The in-module `PowersOfTau*` and single-party setup helpers are intended for
development, tests, and local demos. They are disabled by default and require
`-Dzeroj.allowInsecureTrustedSetup=true`. Production Groth16 or PlonK
deployments should use imported ceremony outputs appropriate to the proof system
and circuit, with pinned artifact hashes.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-crypto'
}
```
