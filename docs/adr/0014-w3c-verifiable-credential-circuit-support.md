# ADR-0014: W3C Verifiable Credential Support in Circuit Lib

## Status
Proposed

## Date
2026-04-02

## Context

The identity-kyc demo (`zeroj-usecases/identity-kyc`) demonstrates privacy-preserving KYC on Cardano — users prove eligibility (age, country) without revealing personal data. However, it uses **Poseidon-signed credentials** (a shared-secret scheme), which has two limitations:

1. **No standard interoperability** — Poseidon-signed credentials are ZeroJ-specific. They can't be issued or verified by W3C VC tooling, DID wallets, or Atala PRISM.
2. **Weak security model** — the issuer and holder share the same secret (`credentialSecret`). The issuer can impersonate the holder, and the secret must be transmitted securely.

To support W3C Verifiable Credentials and DID-based identity, the ZK circuit library needs three new capabilities that enable **asymmetric credential signatures** verifiable inside a ZK proof.

### Current state of zeroj-circuit-lib

| Primitive | Status | Notes |
|-----------|--------|-------|
| Poseidon hash | Available | Used for credential hashing today |
| Merkle proof verification | Available | Used for country whitelist |
| Range comparisons | Available | Used for age >= minAge |
| **BabyJubJub curve** | **Removed** | Was in circuit-lib, removed during security audit (missing subgroup checks) |
| **EdDSA signature verification** | **Removed** | Depended on BabyJubJub, removed with it (signature malleability issues) |
| **BBS+ signature verification** | **Not implemented** | Requires pairing math inside circuit |

The BabyJubJub and EdDSA implementations were removed after a security audit identified:
- BabyJubJub: missing cofactor-clearing / subgroup checks — points from the larger curve group could bypass verification
- EdDSA: signature malleability — multiple valid signatures for the same message (S + L is also valid where L is the subgroup order)
- Both: zero test coverage for edge cases

### Why these matter for Cardano

Cardano's identity ecosystem is moving toward DID and W3C VCs:
- **Atala PRISM** uses W3C Verifiable Credentials with DID:prism identifiers
- **CIP-0030 / CIP-0045** wallet standards support credential presentation
- **EU eIDAS 2.0** mandates interoperable digital identity — W3C VC is the baseline format

Without in-circuit signature verification, ZeroJ can only prove statements about credentials signed with symmetric (Poseidon) schemes, limiting adoption to single-issuer, closed systems.

## Decision

### Add three capabilities to zeroj-circuit-lib, in priority order:

### 1. BabyJubJub curve (re-add with hardening)

Re-implement the BabyJubJub twisted Edwards curve with proper security:

```java
public class SignalBabyJubJub {
    // Point addition on BabyJubJub (twisted Edwards: ax^2 + y^2 = 1 + dx^2y^2)
    // a = 168700, d = 168696 (matching circomlib)
    static Signal[] add(SignalBuilder c, Signal[] p1, Signal[] p2);

    // Scalar multiplication via double-and-add (constant-time ladder)
    static Signal[] scalarMul(SignalBuilder c, Signal scalar, Signal[] basePoint, int nBits);

    // Subgroup check: verify point is in the prime-order subgroup
    // Multiplies by cofactor (8) and checks result is not identity
    static void assertInSubgroup(SignalBuilder c, Signal[] point);
}
```

**Security fixes:**
- Cofactor clearing: `assertInSubgroup()` ensures points are in the prime-order subgroup (order `l`), not the larger curve group (order `8l`)
- All public inputs that are curve points must pass subgroup check before use in arithmetic
- Test vectors from circomlib/iden3 for edge cases (identity, generator, cofactor multiples)

**Constraints:** ~500 per scalar multiplication (256 doublings + ~128 additions for 256-bit scalar)

### 2. EdDSA signature verification in-circuit

Verify EdDSA (EdDSA-BabyJubJub, compatible with circomlib/iden3) signatures inside a ZK proof:

```java
public class SignalEdDSA {
    /**
     * Verify an EdDSA signature (R, S) on message M under public key A.
     *
     * Checks: [S]B == R + [H(R, A, M)]A
     * where B is the generator and H is Poseidon (matching circomlib).
     */
    static Signal verify(SignalBuilder c,
                          Signal[] pubKeyA,    // [Ax, Ay]
                          Signal[] sigR,       // [Rx, Ry]
                          Signal sigS,         // scalar S
                          Signal message);     // message hash
}
```

**Security fixes:**
- Strict S range check: `S < l` (subgroup order) — prevents signature malleability where `S + l` is also valid
- R point subgroup check via `assertInSubgroup()`
- Public key subgroup check via `assertInSubgroup()`
- Use Poseidon for H(R, A, M) — matching circomlib's `EdDSAPoseidonVerifier`

**Constraints:** ~3,000 (2 scalar multiplications + 1 point addition + Poseidon hash + range check)

### 3. BBS+ selective disclosure (future)

BBS+ signatures allow a holder to selectively disclose individual claims from a credential without revealing others. This is the gold standard for W3C VC privacy.

```java
public class SignalBBS {
    /**
     * Verify a BBS+ signature on a set of messages, with selective disclosure.
     *
     * Only disclosed messages are public inputs. Hidden messages are private.
     * The verifier learns: "a trusted issuer signed these claims, and the
     * disclosed claims have these values" — without learning the hidden claims.
     */
    static Signal verify(SignalBuilder c,
                          Signal[] disclosedMessages,   // public
                          Signal[] hiddenMessages,      // private
                          Signal[] signature,           // private
                          Signal[] issuerPublicKey);    // public
}
```

**Complexity:** Requires BLS12-381 pairing operations inside the circuit (~10,000+ constraints). This is the most complex primitive and should be implemented after EdDSA is stable.

**Note:** BBS+ is still evolving as a standard (IETF draft). Implementation should track the latest spec.

## Consequences

### Positive

1. **W3C VC compatibility** — credentials issued by any W3C VC compliant issuer (Atala PRISM, Spruce, etc.) can be verified inside ZeroJ ZK proofs
2. **Multi-issuer ecosystems** — asymmetric signatures mean the issuer can't impersonate the holder
3. **Atala PRISM integration** — enables ZK proofs over PRISM-issued credentials on Cardano
4. **EU eIDAS readiness** — Cardano DApps can accept European Digital Identity Wallet credentials
5. **Selective disclosure (BBS+)** — holders reveal only the claims needed, not the entire credential
6. **Ecosystem alignment** — matches what other ZK projects (circomlib, Polygon ID, Iden3) provide

### Negative

1. **Circuit size increase** — EdDSA verification adds ~3,000 constraints vs ~660 for Poseidon-signed, increasing proof generation time by ~3x
2. **BabyJubJub is not Cardano-native** — Cardano's Plutus V3 has BLS12-381 builtins, not BabyJubJub. EdDSA signature verification happens inside the ZK circuit (off-chain), not via on-chain builtins
3. **Implementation complexity** — elliptic curve arithmetic in R1CS is error-prone; incomplete addition formulas, special-case handling for identity/doubling
4. **BBS+ is speculative** — the IETF standard is not finalized; implementation may need to change

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| BabyJubJub subgroup check bypass | **Critical** | Mandatory cofactor clearing; test with all 8 coset representatives; differential testing against circomlib |
| EdDSA signature malleability | **Critical** | Strict S < l range check (bit decomposition); test with S, S+l, S+2l; compare against circomlib EdDSAPoseidonVerifier |
| Incomplete addition formula edge cases | High | Use complete twisted Edwards addition formula (no exceptions for doubling/identity); exhaustive test with identity, generator, -generator, cofactor points |
| BBS+ spec changes | Medium | Implement behind feature flag; track IETF draft; plan for breaking changes |
| Performance regression for simple use cases | Low | Poseidon-signed credentials remain available as a lightweight option; circuit choice is per-application |

## Implementation Order

1. **Phase 1: BabyJubJub** — re-add with subgroup checks, 100% test coverage, differential testing against circomlib
2. **Phase 2: EdDSA** — signature verification circuit, malleability fix, test against circomlib EdDSAPoseidonVerifier
3. **Phase 3: Identity KYC demo upgrade** — switch from Poseidon-signed to EdDSA-signed credentials
4. **Phase 4: BBS+** — selective disclosure (when IETF spec stabilizes)

## References

- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
- [BabyJubJub — iden3 specification](https://iden3-docs.readthedocs.io/en/latest/iden3_repos/research/publications/zkproof-standards-workshop-2/baby-jubjub/baby-jubjub.html)
- [circomlib EdDSAPoseidonVerifier](https://github.com/iden3/circomlib/blob/master/circuits/eddsa.circom)
- [BBS+ Signatures — IETF Draft](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-07.html)
- [Atala PRISM — Cardano Identity](https://atalaprism.io/)
- [EU eIDAS 2.0 — European Digital Identity](https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation)
- ZeroJ security audit findings (BabyJubJub/EdDSA removal rationale)
- `zeroj-usecases/identity-kyc` — current Poseidon-signed credential demo
- `docs/usecases/identity-and-credentials.md` — full design doc with 3 credential approaches
