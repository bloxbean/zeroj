# ADR-0009: Halo2 Support Strategy

## Status
Proposed (planning for future implementation)

## Date
2026-03-27

## Context

Halo2 is a proof system based on PLONKish arithmetization with two polynomial commitment variants: IPA (Inner Product Argument, transparent — no trusted setup) and KZG (Kate commitments, universal setup). It was developed by Zcash (Electric Coin Company) and has been forked by PSE/Scroll/Axiom for EVM-focused applications.

Halo2 is strategically important for Cardano because:
1. **IPA variant requires no trusted setup** — aligns with Cardano's trust-minimized philosophy
2. **Recursive proof composition** — compress N proofs into 1 (essential for L2 rollups, proof aggregation)
3. **PLONKish circuit model** — custom gates and lookup tables enable more expressive circuits than R1CS
4. **IOG has already demonstrated Halo2 KZG verification on Cardano mainnet** (November 2024, via `plutus-halo2-verifier-gen`)

However, Halo2 presents challenges that differ from Groth16/PlonK:
- It's a Rust ecosystem (zcash/halo2, PSE, Axiom) — no Go or Java implementations
- IPA variant uses Pasta curves (Pallas/Vesta), not BLS12-381
- KZG variant works with BLS12-381 but reintroduces a setup
- No JVM libraries or bindings exist today

## Decision

### Phase 1: Off-chain Halo2 verification via Rust FFM (Near-term)

Even without Plutus builtins for IPA/Pasta curves, Halo2 is valuable off-chain:
- **Yaci app-layer verification** — nodes verify Halo2 proofs without on-chain constraints
- **Java applications** — privacy-preserving computations verified in Java
- **Recursive proof aggregation** — compress multiple proofs before anchoring on Cardano

**Implementation approach:**
1. Build a Rust shared library (`cdylib`) wrapping Halo2 KZG verification on BLS12-381
2. Expose C-ABI functions: `halo2_verify(vk, proof, public_inputs) → bool`
3. Call from Java via FFM (same pattern as zeroj-blst and zeroj-prover-gnark)
4. Register as `ZkVerifier` SPI implementation (`Halo2BLS12381Verifier`)
5. The rest of ZeroJ (patterns, pipeline, anchoring) works unchanged

**Rust library candidates:**
- `axiom-crypto/halo2-lib` (recommended — actively maintained, KZG variant, BN254/BLS12-381)
- `privacy-ethereum/halo2` (PSE fork — maintenance mode since Jan 2025, but stable)
- `zcash/halo2` (original — IPA only, Pasta curves)

### Phase 2: On-chain Halo2 KZG verification (Medium-term)

With Plutus V3 BLS12-381 builtins, Halo2 KZG verification is feasible:
- IOG's `plutus-halo2-verifier-gen` has demonstrated this on mainnet
- The verification uses the same builtins as Groth16/PlonK: millerLoop, finalVerify, G1 operations
- Budget is tight but feasible for KZG variant

**ZeroJ deliverables:**
1. Halo2 KZG proof codec (parse Halo2 proof artifacts into `ZkProofEnvelope`)
2. On-chain verifier in Julc (like existing `Groth16BLS12381GenericVerifier.java`)
3. E2E test on Cardano preprod

### Phase 3: Recursive proof aggregation (Long-term)

This is Halo2's killer feature. The IPA variant supports efficient recursion via accumulation:
- Each proof carries an "accumulator" from the previous verification
- The expensive final MSM check is deferred to the end of the recursion chain
- N proofs are compressed into 1 final proof

**Use cases for Cardano:**
- L2 rollup state updates — batch 1000 transactions into 1 proof
- Cross-chain bridging — aggregate proofs from multiple chains
- Catalyst voting — aggregate all votes into a single verifiable result

**Implementation:**
1. Halo2 IPA recursive prover (Rust sidecar)
2. Final IPA proof → converted to Groth16/PlonK BLS12-381 for on-chain verification (wrapping trick)
3. Or: wait for Plutus Pasta curve builtins (future CIP)

### Phase 4: Halo2 IPA native support (Long-term, depends on Plutus evolution)

IPA verification on Cardano would require new Plutus builtins:
- Pasta curve operations (Pallas/Vesta group arithmetic)
- Or: MSM builtins (CIP-0133) efficient enough for IPA verification on BLS12-381

This is a CIP-level conversation with IOG. ZeroJ should be ready to support it when available.

## What We Can Do Today (Off-chain)

Even without on-chain IPA support, Halo2 is useful in ZeroJ:

| Capability | Variant | Curve | On-chain? | Use Case |
|------------|---------|-------|-----------|----------|
| Off-chain verification | KZG | BLS12-381 | No (Yaci/Java) | Privacy apps, L2 state |
| Off-chain verification | IPA | Pasta | No (Yaci/Java) | Recursive proofs, aggregation |
| On-chain verification | KZG | BLS12-381 | Yes (Plutus V3) | Cardano L1 settlement |
| Recursive aggregation | IPA | Pasta | Wrap to KZG | L2 rollups |

## Module Structure

```
zeroj-verifier-halo2/          (new module)
  src/main/java/.../halo2/
    Halo2BLS12381Verifier.java  (implements ZkVerifier SPI)
    Halo2NativeLibrary.java     (FFM bindings to Rust cdylib)
    Halo2NativeLoader.java      (platform-aware library loading)
  src/main/resources/native/
    macos-arm64/libzeroj_halo2.dylib
    linux-x86_64/libzeroj_halo2.so

zeroj-halo2-rust/              (Rust source, builds the cdylib)
  src/lib.rs                    (C-ABI exports: halo2_verify, halo2_prove)
  Cargo.toml                   (depends on axiom-crypto/halo2-lib)
```

## Proof Format

Halo2 proof format differs significantly from Groth16/PlonK:

| Property | Groth16 | PlonK | Halo2 KZG | Halo2 IPA |
|----------|---------|-------|-----------|-----------|
| Commitments | 2G1+1G2 | ~9G1 | Variable (circuit-dependent) | Variable |
| Evaluations | 0 | ~7 | Variable | Variable |
| Proof size | ~192B | ~656B | ~1-5KB | ~1-10KB |
| Trusted setup | Per-circuit | Universal SRS | Universal SRS | None |
| Recursion | No | No | With effort | Native |

The `zeroj-codec` module needs a Halo2-specific parser. The `ZkProofEnvelope` is proof-system-agnostic (it carries opaque `proofBytes`), so no API changes needed.

## Consequences

### Positive
- Halo2 KZG gives Cardano a second on-chain verifiable proof system alongside Groth16
- IPA variant eliminates trusted setup entirely
- Recursive proofs enable L2-scale applications on Cardano
- Off-chain Halo2 verification in Yaci expands the platform's capabilities immediately
- Same ZeroJ SPI — patterns, pipeline, anchoring all work unchanged

### Negative
- Rust dependency introduces a new build toolchain (cargo)
- Halo2 ecosystem is fragmented (zcash, PSE, Axiom, Scroll forks)
- PSE fork is in maintenance mode — Axiom fork recommended but less mature
- IPA on-chain support requires future Plutus CIPs
- Proof sizes are larger than Groth16/PlonK

### Risks
- Halo2 Rust FFM integration is more complex than gnark Go FFM (Rust has no GC, different ABI)
- KZG variant may not justify the complexity over PlonK (similar setup model, similar on-chain cost)
- IPA-to-KZG wrapping for on-chain verification adds proof generation overhead
- Cardano community may not prioritize Pasta curve CIPs

## References

- [Halo2 Book (zcash)](https://zcash.github.io/halo2/)
- [Axiom halo2-lib (recommended fork)](https://github.com/axiom-crypto/halo2-lib)
- [PSE halo2 fork (maintenance mode)](https://github.com/privacy-ethereum/halo2)
- [IOG plutus-halo2-verifier-gen](https://github.com/input-output-hk/plutus-halo2-verifier-gen)
- [IOG Blog: Halo2 on Cardano](https://www.iog.io/news/unlocking-zero-knowledge-proofs-for-cardano-the-halo2-plutus-verifier)
- [CIP-0381: BLS12-381 Plutus builtins](https://cips.cardano.org/cip/CIP-0381)
- [CIP-0133: Multi-Scalar Multiplication (proposed)](https://cips.cardano.org/cip/CIP-0133)
- [Halo paper (Bowe, Grigg, Hopwood 2019)](https://eprint.iacr.org/2019/1021)
