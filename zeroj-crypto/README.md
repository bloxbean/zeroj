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
| BLS12-381 Groth16 (start here) | `Groth16Keys`, `Groth16Pipeline` — facade over setup + prove with a disk-backed, `mmap`'d key store so large circuits prove within commodity memory |
| BLS12-381 proving (low level) | `Groth16ProverBLS381`, `Groth16SetupBLS381`, `Groth16PkStore` (sparse/dense store, `setupToStore`/`load`), `PlonKProverBLS381`, `KZGCommitmentBLS381`, `PippengerBLS381` |
| Legacy BN254 Groth16 | `Groth16Setup`, `Groth16Prover`, `ZkeyImporter` (requires `-Dzeroj.allowLegacyBn254=true`) |
| Legacy BN254 PlonK | `PlonKSetup`, `PlonKProver`, `PlonKZkeyImporter`, `PtauImporter` (requires `-Dzeroj.allowLegacyBn254=true`) |
| R1CS import | `R1CSImporter` |
| snarkjs interop (ADR-0047) | `R1csExporter` (iden3 `.r1cs` for a snarkjs ceremony), `ZkeyImporterBLS381`, `PlonKZkeyImporterBLS381`; `SnarkjsGroth16Json` / `SnarkjsPlonkJson` write `proof.json`, `verification_key.json`, `public.json` byte-for-byte as snarkjs 0.7.6 does, so ZeroJ proofs and ZeroJ-native keys verify under `snarkjs groth16/plonk verify` |
| Polynomial tools | `FieldFFT`, `FieldFFTBLS381`, `KZGCommitment`, `Pippenger` |
| Setup helpers | `PowersOfTau`, `PowersOfTauBLS381`, `Groth16SetupCache`, `PlonkSetupCache` |
| Transcript | `FiatShamirTranscript`, `Keccak256` |

## Why It Is Useful

- Provides a portable proving path with no Go, Node.js, Rust, or native library
  dependency by default. An optional native blst backend (`ProverBackend`, via the
  separate `zeroj-crypto-blst` module) can be opted into for extra speed; pure Java
  matches it at large circuit sizes.
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

Every public Groth16 prove path blinds the proof with fresh `SecureRandom` scalars
`(r, s)`. There is no public unblinded or deterministic prove: such a proof is a
deterministic function of the witness and is not zero-knowledge. The deterministic
prover that ZeroJ's own byte-equality differential tests use
(`Groth16UnblindedTestProver`) lives in this module's unpublished test fixtures and
is never part of a published artifact (ADR-0046).

## Gradle

```gradle
dependencies {
    implementation 'org.zeroj:zeroj-crypto'
}
```
