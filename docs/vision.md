# JuLC + ZeroJ — A Java-Native Platform for Programmable Trust on Cardano

> **Write validators and zero-knowledge circuits in Java.
> Ship privacy-preserving, verifiable applications without writing cryptographic plumbing.**

[JuLC](https://julc.dev) and [ZeroJ](https://github.com/bloxbean/zeroj) are two
complementary, Java-first compilers and runtimes for Cardano.
**JuLC** compiles Java to UPLC for on-chain validators.
**ZeroJ** compiles Java to zero-knowledge constraint systems for off-chain
proving and on-chain verification.
Together they form a unified developer surface for **smart contracts, ZK
applications, verifiable credentials, and privacy-preserving protocols** — all
expressible in the language the world's largest engineering workforce already
knows.

---

## 1. The Opportunity

Cardano's developer story today is dominated by Aiken, Plutus (Haskell),
Plutarch, and OpShin. Each is excellent within its niche. None of them
meet enterprises, identity providers, governments, or large engineering teams
where they already live: **on the JVM**.

At the same time, zero-knowledge cryptography is moving from research into
production — but the entry barrier is brutal. Circom, Noir, Halo2, and arkworks
all assume the developer is comfortable with field arithmetic, R1CS,
witness generation, and ceremony semantics.

**Our thesis:**

```
Java is the largest production-grade language ecosystem on Earth.
Cardano needs a Java path to be taken seriously by enterprises,
identity providers, and supply-chain operators.
ZK needs a higher-level developer surface to leave the research bubble.
JuLC + ZeroJ deliver both — on the same platform, with the same idioms.
```

---

## 2. Who This Is For

| Audience                                | Why they care                                                                 |
|-----------------------------------------|--------------------------------------------------------------------------------|
| Enterprise Java teams                   | Build on Cardano without retraining engineers in Haskell, Rust, or DSLs.       |
| Identity & credential issuers           | Issue and verify W3C VC / BBS+ credentials with first-class JVM tooling.       |
| Supply-chain & DPP integrators          | Anchor product passports, prove provenance, disclose selectively.              |
| dApp builders already on Bloxbean stack | Extend Cardano Client Lib / Yaci with native validator and ZK authoring.       |
| Privacy & governance researchers        | Prototype zk-voting, anonymous DReps, reputation systems in a familiar IDE.    |

---

## 3. How We're Different

| Dimension                                      | Aiken    | Plutus/Plutarch | Helios | OpShin   | **JuLC + ZeroJ**                                  |
|------------------------------------------------|----------|-----------------|--------|----------|----------------------------------------------------|
| Source language                                | DSL      | Haskell eDSL    | TS-ish | Python   | **Java (standard)**                                |
| Ecosystem reach                                | Cardano  | Cardano         | Cardano| Cardano  | **JVM + Cardano**                                  |
| ZK first-class                                 | No       | No              | No     | No       | **Yes (ZeroJ)**                                    |
| Enterprise tooling (IDE, debuggers, profilers) | Limited  | Limited         | Limited| Limited  | **Native (IntelliJ, VS Code, JFR, GraalVM)**       |
| Native-image compilation                       | n/a      | n/a             | n/a    | n/a      | **GraalVM AOT**                                    |
| Shared crypto runtime with off-chain dApp code | No       | No              | No     | No       | **Yes (one stack)**                                |

---

## 4. Project Responsibilities

### 4.1 JuLC — Java → UPLC

JuLC compiles a deterministic, functional subset of Java into UPLC validators.

Focus areas:

* spending / minting / certifying / withdrawal validators
* ledger abstractions (`ScriptContext`, `TxInfo`, value, datums, redeemers)
* CIP-30 and CIP-25/68 friendliness
* deterministic, bounded execution
* Plutus interop and reference-script-based composition

```java
@SpendingValidator
public class VestingValidator {

    @Entrypoint
    static boolean validate(VestingDatum datum,
                            PlutusData redeemer,
                            ScriptContext ctx) {

        return ctx.txInfo()
                  .signatories()
                  .contains(datum.beneficiary());
    }
}
```

### 4.2 ZeroJ — Java → Zero-Knowledge Circuits

ZeroJ compiles Java circuit code into a backend-agnostic Constraint IR and
emits proving keys, verification keys, and (where applicable) on-chain
verifiers.

Focus areas:

* circuit DSL (`@Circuit`, `SignalBuilder`)
* field arithmetic and gadgets (Poseidon, Merkle/IMT, EdDSA-Jubjub, range checks)
* BBS / BBS+ selective disclosure
* witness generation
* multi-backend lowering (R1CS, ACIR, PLONKish, AIR)
* generated, strongly-typed verifier artifacts

```java
@Circuit
public class AgeCredentialCircuit {

    public void define(SignalBuilder c) {
        Field issuerPk = c.publicInput("issuerPk");
        Field minAge   = c.publicInput("minAge");

        Field age      = c.witness("age");
        Field sig      = c.witness("issuerSig");

        c.constrain(EdDSA.verify(issuerPk, sig, c.hash(age)));
        c.constrain(age.gte(minAge));
    }
}
```

### 4.3 Shared Foundation — `zeroj-crypto`

Both projects depend on a common, audited Java cryptographic substrate:

```
BLS12-381   ·   BBS / BBS+   ·   Poseidon   ·   EdDSA-Jubjub
Merkle / IMT   ·   Pedersen   ·   Pairings   ·   Field & Group ops
```

This substrate is also usable directly by off-chain Java dApps built on
Cardano Client Lib — one cryptographic stack from issuance to verification.

---

## 5. Joint Architecture

```
                           ┌──────────────────┐
                           │   Java Source    │
                           │  (validator or   │
                           │     circuit)     │
                           └────────┬─────────┘
                                    │
                ┌───────────────────┴────────────────────┐
                ▼                                        ▼
          ┌──────────┐                            ┌──────────┐
          │   JuLC   │                            │  ZeroJ   │
          │ Compiler │                            │ Compiler │
          └────┬─────┘                            └────┬─────┘
               │                                       │
               ▼                                       ▼
            UPLC                              Constraint IR
               │                                       │
               │                       ┌───────────────┼─────────────────┐
               │                       ▼               ▼                 ▼
               │                     R1CS         PLONKish              AIR
               │                       │               │                 │
               │                       └──────┬────────┘─────────────────┘
               │                              ▼
               │                     ProvingKey + VerificationKey
               │                              │
               │                              ▼
               │                   Generated Verifier Artifacts
               │                              │
               └──────────────┐  ┌────────────┘
                              ▼  ▼
                       ┌──────────────────┐
                       │ On-chain layout  │
                       │ • Validator      │
                       │ • Reference VK   │
                       │ • Datum / Inline │
                       └──────────────────┘
                                │
                                ▼
                         Cardano Ledger
```

The **on-chain layout** is a first-class concern: VKs are deployed as
reference data (typically reference scripts or inline datums), and validators
parameterize against them rather than embedding them. This enables circuit
upgrades without redeploying every consumer validator.

---

## 6. Core Philosophy

### Functional and immutable (JuLC)

UPLC is a deterministic, untyped lambda calculus. JuLC enforces a functional,
immutable subset of Java that maps cleanly onto it. No hidden state, no
side effects, no ambiguity.

### Constraint-oriented (ZeroJ)

ZK circuits are not programs that run — they are **statements that must be
satisfiable**. ZeroJ's DSL pushes developers toward thinking in constraints,
not procedures, while still using familiar Java syntax.

### One restricted Java, two compilers

| Property             | JuLC      | ZeroJ     |
|----------------------|-----------|-----------|
| Deterministic        | Required  | Required  |
| Immutable preferred  | Yes       | Yes       |
| Bounded loops        | Required  | Required  |
| Side effects         | Forbidden | Forbidden |
| Reflection           | Forbidden | Forbidden |
| Runtime randomness   | Forbidden | Forbidden |
| Dynamic allocation   | Limited   | Limited   |
| Field-friendly types | Optional  | Required  |

This shared discipline — "ZK-safe Java" — is what lets the two projects share
tooling, linters, IDE plugins, and education material.

---

## 7. zk-Enabled Validators

The integration goal:

> A JuLC validator should verify a ZeroJ proof in **one line of business
> logic**, with no exposed cryptography.

```java
@SpendingValidator
public class PrivateClaimValidator {

    @Entrypoint
    static boolean validate(ClaimDatum datum,
                            ClaimRedeemer r,
                            ScriptContext ctx) {

        return ZeroJ.verify(
                AgeCredentialCircuit.class,
                r.proof(),
                r.publicInputs()
        ) && ctx.txInfo().validRange().contains(datum.deadline());
    }
}
```

What happens under the hood (chosen by the compiler/runtime, never by the
developer):

* the `AgeCredentialCircuit` reference is resolved to a deployed VK
* the VK is loaded from a reference UTxO (configurable layout)
* the verifier lowers to BLS12-381 pairing checks for Groth16,
  or to the backend-appropriate primitive for Plonk/AIR
* public inputs are bound and hashed deterministically

### VK lifecycle

* **Issuance:** circuit compile produces `CircuitVK`, signed/registered by the
  issuer.
* **Deployment:** VK is published on-chain as reference data.
* **Consumption:** validators reference the VK by hash; consumers verify
  proofs against it.
* **Rotation:** issuer publishes a new VK; validators parameterized over a
  set of accepted VK hashes upgrade without redeployment.

---

## 8. Public Inputs vs Private Witnesses

ZeroJ circuits cleanly separate the two.

| Public Inputs                | Private Witnesses                     |
|------------------------------|---------------------------------------|
| Issuer public key            | Age, country, salary, identifiers     |
| Policy parameters            | Issuer signatures                     |
| Merkle / accumulator roots   | Merkle paths                          |
| Nullifiers, commitments      | Secrets, randomness                   |
| Anything the validator reads | Anything that must remain hidden      |

Generated artifacts (`CircuitPublicInputs`, `CircuitProof`, `CircuitVK`,
`CircuitVerifier`) make this split type-safe at the Java boundary.

---

## 9. Proof System Abstraction

Developer APIs are **backend-agnostic** by default.

| Avoid                  | Prefer            |
|------------------------|-------------------|
| `Groth16Proof`         | `Proof`           |
| `Halo2Proof`           | `ZkProof`         |
| `PlonkProof`           | `CircuitProof<C>` |

Backend choice is build-time configuration, not source code. The same Java
circuit can target Groth16 today and PLONK or STARK tomorrow.

---

## 10. Showcase Use Cases

### 10.1 Selective-Disclosure Credentials (BBS / BBS+)

Issuer signs a multi-attribute credential. Holder proves *only* the selected
attributes plus optional predicates (age ≥ 18, country ∈ allow-list) without
revealing the rest. Cardano validators accept the proof at gates: airdrops,
DAO membership, age-restricted markets.

### 10.2 Privacy-Preserving Digital Product Passport (DPP)

Manufacturer anchors product attributes (origin, materials, certifications)
under a commitment. Retailer or customs proves compliance predicates
("contains no banned substance X", "origin ∈ approved set") without revealing
the full bill of materials.

### 10.3 Anonymous Governance

Voter proves "I am a DRep with stake ≥ T at snapshot S" without revealing
identity. Validator counts votes against a public stake-snapshot root.

### 10.4 zk-KYC Gates

User proves once at issuance, reuses across dApps. The dApp's validator only
sees "this user satisfies our policy" — never the underlying KYC document.

### 10.5 Verifiable Reputation

Reputation scores accumulate under a commitment. User proves "score ≥ X" or
"top-decile" without disclosing the full history or graph.

---

## 11. Developer Experience

| Pillar              | What it means                                                                                   |
|---------------------|--------------------------------------------------------------------------------------------------|
| **Same IDE**        | IntelliJ / VS Code / Eclipse for validators *and* circuits. Refactor, jump-to-def, debug as Java. |
| **Same build**      | Gradle / Maven plugins for compile, prove, deploy.                                              |
| **Same tests**      | JUnit tests for validators (via Yaci DevKit) and for circuits (witness gen + verify in-process). |
| **GraalVM AOT**     | Native-image compilation for compilers, provers, and CLI tooling.                               |
| **Strong types**    | Generated `CircuitProof<C>`, `CircuitPublicInputs<C>`, `CircuitVK<C>` — wrong types fail to compile. |
| **First-class CLI** | `zeroj compile / prove / verify / deploy-vk` and `julc compile / build-tx / debug`.             |

---

## 12. Ecosystem Alignment

JuLC and ZeroJ are not greenfield — they extend the Bloxbean Java-on-Cardano
stack:

* **Cardano Client Lib (CCL)** — transaction building, signing, fee estimation.
* **Yaci DevKit** — local Cardano network for end-to-end validator and proof testing.
* **Yaci Store** — indexed chain data for off-chain proving and witness generation.
* **CIP alignment** — CIP-30 (wallets), CIP-25/68 (token metadata, anchor commitments),
  CIP-1694 (governance), emerging BBS/VC CIPs.

A developer who already builds Cardano apps in Java does not learn a new
ecosystem — they add two new capabilities to the one they have.

---

## 13. Roadmap

### Phase 1 — Production-grade foundations *(now)*

* JuLC: stable validator subset, reference-script flow, Yaci DevKit integration.
* ZeroJ: R1CS + Groth16 backend, BLS12-381, Poseidon, EdDSA-Jubjub, Merkle,
  generated verifier artifacts, BBS/BBS+ selective disclosure.
* Shared: `zeroj-crypto` substrate, GraalVM native-image support, IntelliJ plugin v1.

### Phase 2 — Backend flexibility *(next 12 months)*

* ZeroJ: ACIR export, PLONK backend, universal setup.
* JuLC: generalized on-chain verifier framework parameterized by backend.
* Reference apps: privacy-preserving DPP, zk-KYC, BBS+ credentials end-to-end.

### Phase 3 — Scale and recursion *(12–24 months)*

* PLONKish / STARK backends, proof aggregation, recursion.
* Multi-circuit composition.
* Optional zk-rollup-style batching for high-throughput dApps.
* Enterprise integrations (HSM-backed issuance, JCA providers).

---

## 14. Success Criteria

We will know JuLC + ZeroJ have succeeded when:

1. A Java engineer with **no Haskell, no Rust, no DSL experience** can ship a
   privacy-preserving Cardano dApp in under a week.
2. At least one enterprise issuer (identity, supply chain, or governance) runs
   ZeroJ-generated verifiers in production.
3. The same JVM codebase serves issuance, proving, transaction building, and
   on-chain verification — no language switch across the stack.
4. Independent teams have built on `zeroj-crypto` without modifying it.
5. JuLC and ZeroJ appear in CIPs and reference implementations alongside
   Aiken and Plutus.

---

## 15. Design Principles

* **Developer experience first.** Java developers should write business logic,
  not cryptography.
* **Strong separation of concerns.**
  - JuLC owns on-chain validation.
  - ZeroJ owns circuits and proving.
  - Generated artifacts bridge them.
  - Backends implement cryptography.
* **Privacy by default.** Reveal statements, not data.
* **Backend-agnostic.** No public API should leak the proof system.
* **Composable with the existing stack.** CCL, Yaci, and the rest are
  first-class neighbours, not afterthoughts.

---

## 16. Vision

> **JuLC enables Java developers to build Cardano validators.
> ZeroJ enables Java developers to build zero-knowledge circuits.
> Together they make Cardano the natural home for programmable trust,
> privacy, and verifiable computation — written in the language the world
> already runs on.**
