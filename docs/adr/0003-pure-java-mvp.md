# ADR-0003: Hybrid Crypto Backend — blst for BLS12-381, Pure Java for BN254

## Status
Accepted (supersedes original "Pure Java for MVP")

## Date
2026-03-25

## Context

ZK verification requires elliptic curve arithmetic including pairing operations. These are computationally intensive. Options:

1. **Pure Java**: Implement curve arithmetic and pairings in Java. Slower but portable, GraalVM-friendly, zero native dependencies.
2. **JNI/FFM**: Bind to native Rust/C libraries (arkworks, blst, etc.). Fast but adds build complexity, platform-specific binaries, and GraalVM native-image challenges.
3. **Hybrid**: Use native bindings for one curve (BLS12-381 via blst) and pure Java for the other (BN254).

After analysis, a hybrid approach provides the best trade-off:
- **BLS12-381** is Cardano's native curve (CIP-0381). The `foundation.icon:blst-java` library is already a proven dependency in the bloxbean ecosystem (used by julc-bls). It provides native blst-backed operations through JNI/SWIG bindings.
- **BN254** is the Ethereum/snarkjs ecosystem curve. Pure Java is viable here because: (a) extensive Ethereum test vectors exist (EIP-196, EIP-197), (b) Hyperledger Besu has reference Java implementations, and (c) 100-300ms verification latency is acceptable for semi-trusted node networks.

## Decision

Use a **hybrid backend from day one** (Milestone 2):

- **BLS12-381**: via `foundation.icon:blst-java:0.3.2` (JNI/SWIG, same as julc-bls). The `zeroj-blst` module wraps the blst library and exposes curve operations needed for Groth16 verification.
- **BN254**: via pure Java implementation in `zeroj-verifier-groth16`. Field arithmetic (Fp through Fp12 tower), curve operations (G1, G2), and optimal Ate pairing implemented in Java.

Both backends are behind the `ZkVerifier` SPI, so consumers don't need to know which backend handles their proof.

## Consequences

**Easier:**
- BLS12-381 is fast and correct from day one (blst is audited and battle-tested)
- BN254 pure Java is testable against Ethereum's extensive vector suites
- GraalVM native-image: blst works (julc-bls already proves this), BN254 pure Java is trivial
- No need to implement BLS12-381 pairing math in Java (the hardest part)

**Harder:**
- blst adds platform-specific native binaries (handled by blst-java's packaging)
- Two different implementation strategies to maintain
- BN254 pure Java pairing still requires careful implementation

## Risks

- **Risk**: BN254 pure Java pairing has bugs. **Mitigation**: EIP-196/197 test vectors, snarkjs cross-validation, Besu reference code.
- **Risk**: blst-java platform support gaps. **Mitigation**: blst-java covers all major platforms (linux-x64, linux-arm64, macos-x64, macos-arm64, windows-x64). julc-bls is the existence proof.
- **Risk**: GraalVM + blst native. **Mitigation**: julc-bls already works in GraalVM. Include JNI config in `zeroj-blst` native-image metadata.
