# JuLC + ZeroJ — A Java-Native Platform for Privacy-First Programmable Trust on Cardano

> **Write validators and zero-knowledge applications in Java.**
> **Ship privacy-preserving Cardano systems where disclosure is intentional,
> verifiable, and minimal.**

[JuLC](https://julc.dev) and [ZeroJ](https://github.com/bloxbean/zeroj) are
complementary, Java-first projects for Cardano.

* **JuLC** compiles a deterministic subset of Java to UPLC validators.
* **ZeroJ** lets Java developers define zero-knowledge circuits, generate and
  verify proofs in pure Java, and post Cardano-ready verification artifacts
  on-chain through Plutus V3 BLS12-381 builtins.

Together they form a JVM-native platform for privacy-preserving Cardano
applications — credentials, gated dApps, digital product passports, anonymous
governance, reputation, compliance, and verifiable computation — built and
audited with the same toolchain Java teams already use.

The goal is not only "Java for Cardano" or "Java for ZK." The goal is:

```text
Privacy as a first-class application primitive.

Developers express what must be proven, what may be revealed, what must
remain hidden, and how proofs bind to Cardano transactions — without writing
cryptographic plumbing.
```

---

## 1. The Opportunity

Cardano has strong foundations for verifiable computation: UTXO accounting,
script validation, native assets, on-chain governance, and Plutus V3
BLS12-381 builtins for pairing-based proof verification. But the developer
story is still dominated by specialist languages: Aiken, Plutus, Plutarch,
Helios, OpShin — and the ZK story is dominated by research-grade toolchains
like Circom, Noir, Halo2, and arkworks.

That is a barrier for enterprises, identity providers, governments,
supply-chain operators, and the millions of Java teams already running
production systems on the JVM.

At the same time, privacy is becoming a normal product requirement:

* prove eligibility without revealing identity
* prove compliance without revealing trade secrets
* prove a credential is valid without exposing the credential
* prove a vote is authorized without linking it to a voter
* prove a threshold, range, membership, or state transition without revealing
  the underlying data

Zero-knowledge systems can solve these problems, but today's developer
surface is still too close to cryptography research: fields, curves,
constraint systems, witness assignment, proving keys, ceremonies,
serialization formats, and backend-specific behavior.

**Thesis:**

```text
Java is one of the largest production software ecosystems in the world.
Cardano needs a serious JVM path for enterprise adoption.
Privacy-preserving applications need a higher-level developer surface.
JuLC + ZeroJ combine validators, circuits, transaction tooling, and
privacy patterns into one Java-native stack — practical for engineering
teams, auditable by security teams, safe for users by default.
```

---

## 2. Who This Is For

| Audience                                | Why they care                                                                                       |
|-----------------------------------------|-----------------------------------------------------------------------------------------------------|
| Enterprise Java teams                   | Build Cardano applications without retraining engineers in Haskell, Rust, or ZK-specific DSLs.      |
| Identity & credential issuers           | Issue credentials and support selective disclosure with JVM tooling and W3C VC alignment.           |
| Supply-chain and DPP integrators        | Anchor product claims while hiding sensitive supplier, material, and pricing data.                  |
| Regulated dApp builders                 | Enforce KYC, accreditation, residency, or age policies without collecting raw user data.            |
| Governance researchers                  | Prototype private voting, anonymous DRep proofs, stake thresholds, nullifier-based participation.   |
| Bloxbean ecosystem users                | Extend Cardano Client Lib, Yaci Store, and Yaci DevKit with native validator and ZK workflows.      |

---

## 3. How We're Different

| Dimension                                       | Aiken    | Plutus / Plutarch | Helios | OpShin | **JuLC + ZeroJ**                                          |
|-------------------------------------------------|----------|-------------------|--------|--------|------------------------------------------------------------|
| Source language                                 | DSL      | Haskell eDSL      | TS-ish | Python | **Standard Java subset, JVM tooling**                      |
| Ecosystem reach                                 | Cardano  | Cardano           | Cardano| Cardano| **JVM + Cardano**                                          |
| ZK first-class                                  | No       | No                | No     | No     | **Yes — built-in (ZeroJ)**                                 |
| Privacy primitives (commitments, nullifiers, roots) | App-by-app | App-by-app    | App-by-app | App-by-app | **Reusable library + typed proof envelopes**         |
| Off-chain proving                               | Native CLIs / sidecars | Native CLIs / sidecars | Native CLIs / sidecars | Native CLIs / sidecars | **Pure-Java proving; optional native acceleration**  |
| Enterprise tooling                              | Limited  | Limited           | Limited| Limited| **IntelliJ, Gradle/Maven, JUnit, GraalVM, JFR**            |
| Shared stack with off-chain dApp code           | No       | No                | No     | No     | **One stack: issuance → proof → transaction → index**      |

The platform should not claim that every proof system is equally
on-chain-ready. Cardano's Plutus V3 capabilities make some combinations
practical and others infeasible (see §10). The developer experience can be
backend-aware without leaking unnecessary cryptography into application code.

---

## 4. Why Java, Why Now

JVM is where the world's regulated enterprises already build — banks,
governments, identity providers, large supply-chain operators. Asking those
teams to retrain on Haskell, a Rust dialect, or a bespoke DSL is the wrong
question. The right question is: **what would make Cardano and ZK adoptable
in Java without compromising correctness?**

JuLC + ZeroJ answer that with:

* **Same toolchain.** IntelliJ / VS Code / Eclipse, Gradle / Maven, JUnit,
  the JVM debugger and profiler, JFR — for validators *and* circuits.
* **Pure-Java default.** Witnesses, proofs, and verification run on the JVM
  with no native dependencies required. Native acceleration (e.g. `blst`,
  gnark via FFM) is opt-in for hot paths.
* **GraalVM-ready.** Modules ship `META-INF/native-image` configs so
  applications can compile down to native images for cold-start-sensitive
  proving services, CLIs, and edge use cases.
* **One stack from issuance to chain.** The same JVM code that issues a
  credential can generate witnesses, build proofs, construct Cardano
  transactions with CCL, submit through Yaci, and index results through
  Yaci Store. No language switch anywhere.

Now is the right moment because Plutus V3 ships BLS12-381 pairing builtins,
making Groth16 on-chain verification practical *today* and giving PlonK a
credible experimental path once the KZG opening check and budgets mature. Privacy
requirements are catching up to compliance and governance roadmaps. And the
Bloxbean Java-on-Cardano stack (CCL, Yaci) is mature enough that JuLC and
ZeroJ can plug in rather than start from zero.

---

## 5. Privacy Model

A proof system alone does not make an application private. The application
must define what is public, what is private, who learns what, and how
correlation is controlled.

### 5.1 What May Be Public

Public values are the minimum data needed by validators, indexers, verifiers,
and auditors — and must be assumed visible forever once on-chain:

* proof bytes or proof hash
* public inputs
* verification key hash or reference
* policy / circuit identifier
* Merkle or accumulator root
* scoped nullifier
* commitment
* validity interval or epoch
* application-specific statement (e.g. `eligible = true`)

### 5.2 What Must Remain Private

Private values never go on-chain and should not reach dApps unless the
product explicitly requires disclosure:

* age, country, salary, identity attributes, documents
* credential body and credential subject
* issuer signature or credential secret
* supply-chain bill of materials and exact measurements
* Merkle paths (unless intended to be disclosed)
* randomness used for commitments
* voting identity, stake credential, delegation identity
* reputation history or graph data

ZeroJ circuits make this distinction explicit at the Java boundary:
`c.publicInput(...)` and `c.privateInput(...)` are different calls with
different types, and pattern APIs (see §6) refuse to surface witnesses as
public outputs.

### 5.3 Adversary Model

| Observer        | What they can see                                | Privacy goal                                                          |
|-----------------|--------------------------------------------------|------------------------------------------------------------------------|
| Chain observer  | Transactions, scripts, metadata, public inputs   | Cannot recover private witness data.                                  |
| dApp operator   | Submitted proof and public statement             | Learns eligibility/compliance, not raw credential or attributes.      |
| Issuer          | Credential issuance event and issuer records     | Cannot track every future use unless the application reveals it.      |
| Verifier        | Proof, roots, nullifier, policy                  | Cannot link unrelated presentations unless nullifier scope permits.   |
| Colluding apps  | Shared public values across applications         | Cannot correlate users when nullifiers are app-scoped.                |
| Prover service  | Witness, if outsourced                           | Must be avoided or explicitly trusted; local proving is the default.  |

### 5.4 Guarantees

* **Data minimization.** Reveal statements, not source data.
* **Soundness.** A valid proof means the statement is true under the
  accepted circuit and verification key.
* **Replay protection.** Nullifiers or transaction-bound public inputs
  prevent proof reuse where reuse is unsafe.
* **Scoped unlinkability.** Different apps, policies, or epochs use
  different nullifier scopes.
* **Auditability.** Public roots, commitments, proof hashes, and VK hashes
  make claims tamper-evident.
* **Local-first proving.** Users generate proofs without sending secrets
  to dApps or hosted provers.

### 5.5 Non-Guarantees

ZK alone does *not*:

* prove that an issuer was honest at credential issuance
* hide transaction timing, funding patterns, IP addresses, or wallet fingerprints
* prevent credential sharing unless bound to a hardware key or external trust
  mechanism
* make public inputs private — poor public-input design can defeat privacy
* remove the need for audits of circuits, libraries, ceremonies, and verifiers

Privacy-first templates ship with explicit warnings and defaults for these
failure modes.

---

## 6. Core Privacy Primitives

ZeroJ ships reusable building blocks so every application is not reinventing
its own privacy protocol.

| Primitive                       | Purpose                                                                                       |
|---------------------------------|-----------------------------------------------------------------------------------------------|
| Commitments                     | Bind to private data while revealing only a commitment.                                       |
| Scoped nullifiers               | Prevent replay or double-use without revealing identity.                                      |
| Merkle / accumulator roots      | Prove membership, non-membership, or state inclusion against public roots.                    |
| Revocation roots                | Support expired, revoked, or refreshed credentials without exposing credential data.          |
| Range and comparison gadgets    | Prove predicates such as `age ≥ 18`, `stake ≥ T`, `carbon < limit`.                           |
| Signature gadgets               | Prove an issuer signed private data.                                                          |
| Proof envelopes                 | Carry proof bytes, proof system, curve, VK reference, public inputs, and metadata uniformly.  |
| Policy binding                  | Bind a proof to an application, validator, circuit, chain, epoch, or transaction context.     |

The highest-value abstraction is not a raw proof — it is a typed statement:

```text
This holder has a valid credential from issuer I, satisfies policy P,
is not revoked under root R, and has not used this claim before under
nullifier N.
```

Today, pattern verifiers such as `NullifierClaimVerifier` and
`MembershipVerifier` in `zeroj-patterns` already encode this style at the
application boundary.

---

## 7. Project Responsibilities

### 7.1 JuLC — Java → UPLC

JuLC compiles a deterministic, functional subset of Java into UPLC validators.

* spending, minting, withdrawal, and certificate validators
* Cardano ledger abstractions (`ScriptContext`, `TxInfo`, value, datums,
  redeemers, signatories, validity intervals, reference inputs)
* deterministic and bounded execution
* Plutus interop and reference-script-friendly composition
* on-chain ZK verifier validators that wrap supported ZeroJ proof formats

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

JuLC already produces a working on-chain Groth16 verifier through
`zeroj-onchain-julc/Groth16BLS12381Verifier` against Plutus V3 BLS12-381
builtins. `PlonkBLS12381TranscriptPrototype` is an experimental prototype today: it
checks the transcript and inverse constraints, while the KZG batch opening
pairing check remains deferred.

### 7.2 ZeroJ — Java → ZK Circuits and Proofs

ZeroJ provides Java APIs for defining circuits, generating witnesses,
proving, verifying, and preparing Cardano-compatible artifacts.

Shipping today:

* `CircuitSpec` / `SignalBuilder` Java circuit DSL
* public / private signal declarations, comparators, hashes, Merkle
* pure-Java Groth16 over BN254 and BLS12-381
* pure-Java PlonK over BLS12-381
* native acceleration through `zeroj-blst` (BLS12-381 via JNI/SWIG) and
  `zeroj-prover-gnark` (gnark Groth16/PlonK prover via FFM)
* on-chain Plutus V3 verifier for Groth16 on BLS12-381, plus an experimental
  PlonK Julc prototype with KZG pairing verification still deferred
* pattern verifiers (nullifier claims, membership, range)
* `zeroj-cardano` and `zeroj-ccl` integration for transaction layout and
  submission

Example circuit (real, matches the codebase):

```java
public class AgeCredentialCircuit implements CircuitSpec {

    @Override
    public void define(SignalBuilder c) {
        Signal minAge           = c.publicInput("minAge");
        Signal credentialHash   = c.publicInput("credentialHash");

        Signal age              = c.privateInput("age");
        Signal credentialSecret = c.privateInput("credentialSecret");

        Signal expected = SignalPoseidon.hash(c, credentialSecret, age);

        c.assertEqual(expected, credentialHash);
        c.assertTrue(age.gte(minAge));
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("age-credential")
                .publicVar("minAge")
                .publicVar("credentialHash")
                .secretVar("age")
                .secretVar("credentialSecret")
                .defineSignals(new AgeCredentialCircuit());
    }
}
```

### 7.3 Shared Foundation — `zeroj-crypto` and `zeroj-circuit-lib`

`zeroj-crypto` is the common cryptographic substrate: field and EC
arithmetic, pairing operations, FFT/MSM, canonical serialization. Pure-Java
first, with `zeroj-blst` providing JNI/SWIG-backed BLS12-381 acceleration where
performance matters.

`zeroj-circuit-lib` provides the standard gadget catalog: Poseidon, MiMC,
Merkle/IMT, range checks, comparators, and credential primitives.

Both substrates are auditable, reusable, and *boring in the best sense*:
stable APIs, deterministic serialization, test vectors, and clear versioning.
They are also usable directly by off-chain Java dApps — one cryptographic
stack from issuance to verification.

### 7.4 One Restricted Java, Two Compilers

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

This shared discipline — "ZK-safe Java" — is what lets the two projects
share linters, IDE plugins, education material, and review checklists.

---

## 8. Joint Architecture and the Golden Path

```text
                       Java Application Code
              validators, circuits, policies, tests
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
            JuLC                            ZeroJ
       Java → UPLC               Java → Constraint Systems
              │                               │
              ▼                               ▼
       Cardano Validator              R1CS / PlonK / future IRs
              │                               │
              │                               ▼
              │                  Proving Key / Verification Key
              │                               │
              │                               ▼
              │                  Proof Envelope + Public Inputs
              │                               │
              └───────────────┬───────────────┘
                              ▼
                  Cardano Transaction Layout
        validator · datum · redeemer · metadata
        proof · public inputs · VK reference / hash
        commitment · root · scoped nullifier
                              │
                              ▼
                       Cardano Ledger
```

Transaction layout is part of the privacy design. A technically valid proof
can still leak data through ill-chosen public inputs, metadata, roots, or
nullifiers — so transaction construction (via CCL) is treated as a
first-class step in the developer flow.

### Golden Path — a privacy-preserving dApp end to end

1. **Issuer creates a private claim.** A KYC provider, auditor, government
   agency, DPP auditor, or DAO registry signs or commits to user/product
   attributes.
2. **Application publishes policy.** The dApp defines a circuit, accepted
   issuer keys, accepted roots, required thresholds, nullifier scope, and
   VK references.
3. **User proves locally.** The wallet or local app generates a witness
   and proof without sending private attributes to the dApp.
4. **Transaction carries only public privacy artifacts.** Proof or proof
   hash, public inputs, VK hash/reference, root or commitment, scoped
   nullifier, policy identifier.
5. **JuLC validator verifies the statement.** Checks the proof, binds it
   to the expected policy, validates the nullifier or root, enforces
   business logic.
6. **Observers learn the statement, not the source data.** "Eligible",
   "not revoked", "stake threshold met", "product claim compliant",
   "vote authorized".

This is the default user journey for privacy-enabled Java Cardano apps.

---

## 9. zk-Enabled Validators and Verification-Key Lifecycle

### 9.1 Today's API surface

Today, applications use concrete verifier classes and pattern verifiers:

```java
boolean ok = NullifierClaimVerifier.verify(
        AgeCredentialCircuit.class,
        proofEnvelope,
        publicInputs,
        nullifierScope);
```

### 9.2 Target DX (not yet implemented)

The aspirational JuLC bridge collapses the above into a single business-level
call inside a validator:

```java
@SpendingValidator
public class PrivateClaimValidator {

    @Entrypoint
    static boolean validate(ClaimDatum datum,
                            ClaimRedeemer redeemer,
                            ScriptContext ctx) {

        return ZeroJ.verify(                         // ← target DX
                AgeCredentialCircuit.class,
                redeemer.proof(),
                redeemer.publicInputs())
            && ctx.txInfo().validRange().contains(datum.deadline());
    }
}
```

Under the hood the bridge will:

* resolve the circuit identity to an accepted VK hash or reference
* bind public inputs to the validator, policy, datum, redeemer, chain,
  and transaction context
* verify proof bytes with the supported on-chain verifier
* enforce nullifier scope and replay rules where configured
* fail closed on unknown proof systems, malformed public inputs, or
  unsupported verifier layouts

### 9.3 VK Lifecycle

| Stage     | Description                                                                  |
|-----------|------------------------------------------------------------------------------|
| Compile   | Circuit build produces constraints and VK material.                          |
| Identify  | VK is canonically encoded and hashed.                                        |
| Register  | Issuer or application registry signs and publishes accepted VK hashes.       |
| Deploy    | Application chooses a deployment pattern (table below).                      |
| Consume   | Validators accept only configured VK hashes/references.                      |
| Rotate    | New VKs roll out through explicit transition windows.                        |
| Retire    | Old VKs expire after pending proofs and users have migrated.                 |

### 9.4 Deployment Patterns

| Pattern               | Strength                                       | Tradeoff                                                |
|-----------------------|------------------------------------------------|---------------------------------------------------------|
| VK in script          | Simple and concrete                            | Validator redeploy needed for VK changes.               |
| Reference datum VK    | Smaller reusable logic; VK is rotatable        | More complex UTxO governance.                           |
| VK hash commitment    | Smallest script commitment                     | Full VK must be supplied off-chain or via reference.    |

---

## 10. Public Inputs, Private Witnesses, and Backend Feasibility

### 10.1 The Public / Private Boundary

| Public Inputs              | Private Witnesses                          |
|----------------------------|--------------------------------------------|
| Issuer public key or ID    | Credential body                            |
| Policy parameters          | Age, country, salary, identifiers          |
| Merkle / accumulator root  | Merkle path                                |
| Nullifier                  | Nullifier secret                           |
| Commitment                 | Commitment randomness                      |
| Threshold or range limit   | Exact value                                |
| Validity epoch             | Raw document or event history              |
| Proof context hash         | User or wallet binding secret              |

Rule of thumb:

```text
Anything the validator needs to read is public.
Anything that would harm the user, issuer, or business if disclosed is private.
```

ZeroJ ships a public-input linter that flags suspicious public values: raw
identifiers, exact birth dates, unscoped nullifiers, stable cross-app
commitments, or unnecessary metadata.

### 10.2 Backend Feasibility on Cardano

Developer APIs are backend-agnostic at the application boundary but
backend-*explicit* at deployment, cost estimation, and audit boundaries.

| Capability                                        | Status today                | Notes                                                                |
|---------------------------------------------------|-----------------------------|----------------------------------------------------------------------|
| Java circuit definition with `CircuitSpec`        | **Shipping**                | Core developer path.                                                 |
| Pure-Java Groth16 (BN254 and BLS12-381)           | **Shipping**                | Default for zero-native-dependency workflows.                        |
| Native Groth16/PlonK proving via gnark / blst     | **Shipping**                | Opt-in acceleration through gnark FFM and blst JNI/SWIG.             |
| Pure-Java PlonK on BLS12-381                      | **Shipping**                | Includes full Fiat-Shamir transcript verification.                   |
| Groth16 BLS12-381 on-chain verification           | **Shipping**                | `Groth16BLS12381Verifier` against Plutus V3 builtins.                |
| PlonK BLS12-381 off-chain verification            | **Shipping**                | Pure Java verifier with full KZG pairing check.                       |
| PlonK BLS12-381 on-chain verification             | Experimental                | Julc prototype has transcript/inverse checks; KZG pairing check deferred. |
| BN254 on-chain verification                       | Not feasible                | No BN254 pairing builtins in Plutus.                                 |
| Halo2 / Pallas on-chain verification              | Not feasible                | No Pallas builtins in Plutus.                                        |
| BBS / BBS+ selective disclosure                   | Mainline opt-in             | Strong off-chain credential backend; outside `zeroj-bom-core`. |
| STARK / AIR on-chain verification                 | Research                    | Needs proof-size, verifier-cost, and builtin analysis.               |
| Recursion / proof aggregation                     | Research                    | Valuable for scale; not a Phase 1 dependency.                        |

---

## 11. Showcase Use Cases

### 11.1 Selective-Disclosure Credentials

A user proves a policy without revealing the credential:

* age ≥ 18
* country in an allow-list
* credential signed by an accepted issuer
* credential not revoked under the current validity root
* nullifier unused for this app and epoch

Near-term implementation uses Poseidon and Merkle-based credential
circuits. BBS / BBS+ is strategically important for standards-aligned
selective disclosure and is positioned as an incubating off-chain
credential backend with future on-chain circuit integration.

### 11.2 Privacy-Preserving Digital Product Passport (DPP)

A manufacturer or auditor proves compliance predicates without revealing the
full bill of materials, supplier graph, exact measurements, or pricing data:

* recycled content above a threshold
* carbon impact below a threshold
* origin in an approved set
* no banned material in the committed material list
* temperature kept in range during transport

Cardano stores commitments, proof hashes, policy IDs, and roots. Detailed
documents stay off-chain, disclosed only to authorized parties.

### 11.3 Anonymous Governance

A voter proves:

* eligibility at snapshot `S`
* stake or reputation at least threshold `T`
* the vote has not already been cast for proposal `P`

The validator sees a proposal-scoped nullifier, vote payload, root, and
proof — never the voter's identity or unrelated governance activity.

### 11.4 zk-KYC Gates

A regulated dApp verifies a user satisfies compliance requirements
without collecting identity documents. The dApp learns *policy satisfied,
issuer accepted, credential not revoked, nullifier valid* — never name,
address, passport number, exact birth date, or document image.

### 11.5 Verifiable Reputation

A user proves a reputation statement — `score ≥ X`, top decile, no
unresolved slashing event, member for at least N epochs — without revealing
the underlying history or graph.

---

## 12. Developer Experience and Ecosystem Alignment

### 12.1 DX Pillars

| Pillar              | Target experience                                                                                          |
|---------------------|------------------------------------------------------------------------------------------------------------|
| **Same language**   | Validators, circuits, tests, proof flows, and transaction code all in Java.                                |
| **Same build**      | Gradle and Maven workflows for compile, prove, verify, package, deploy.                                    |
| **Same tests**      | JUnit for circuits, proof generation, verifier behavior, and end-to-end flows on Yaci DevKit.              |
| **Strong types**    | Typed proof envelopes, VK references, public-input schemas, policy identifiers — wrong types fail to compile. |
| **Local proving**   | Default path keeps witnesses on the user's machine; native acceleration is opt-in.                         |
| **GraalVM AOT**     | `META-INF/native-image` configs ship per module; CLIs and proving services can target native image.        |
| **Clear deployment**| Cost estimation and feasibility warnings for on-chain verifier choices.                                    |
| **Privacy templates** | Credential gate, nullifier claim, membership proof, DPP claim, private vote.                             |
| **Audit artifacts** | Constraint hash, VK hash, proof vectors, public-input schema, circuit version.                             |

Target API shape (incubating):

```java
var statement = CredentialPolicy.ageAtLeast(18)
        .issuer("kyc-provider-1")
        .validityRoot(root)
        .nullifierScope("dex-v1", epoch);

var proof = ZeroJ.prove(statement, walletCredential);

txBuilder.attachZkProof(proof)
        .payToContract(appAddress, datum);
```

### 12.2 Ecosystem Alignment

JuLC + ZeroJ extend the existing Bloxbean Java-on-Cardano stack rather than
replace it:

* **Cardano Client Lib (CCL).** Transaction building, signing, metadata,
  redeemers, datums, fee estimation, submission.
* **Yaci DevKit.** Local end-to-end testing of validators, proofs, and
  transaction flows.
* **Yaci Store.** Indexed chain data for roots, snapshots, credential
  registries, governance state, and witness generation.
* **Cardano metadata and token standards.** CIP-25, CIP-68, DPP metadata,
  governance metadata, anchor commitments.
* **Governance alignment.** CIP-1694 use cases — private voting, anonymous
  DRep credentials, stake threshold proofs.
* **Credential standards.** W3C VC compatibility and emerging BBS / BBS+
  standards, with careful distinction between off-chain credential
  presentation and on-chain SNARK verification.

End state — one Java stack from issuance to chain index:

```text
Issuer service → holder wallet/app → ZeroJ proof → CCL transaction
              → JuLC validator → Yaci-indexed state → auditor/verifier tools
```

---

## 13. Roadmap and Success Criteria

### Phase 1 — Production Foundation *(now)*

Ship credible privacy-preserving apps with the proof systems Cardano can
verify today.

* Harden `CircuitSpec`, witness generation, proof envelopes, canonical
  serialization.
* Prioritize Groth16 BLS12-381 for production on-chain verification; keep
  PlonK on the experimental track until the KZG pairing check and cost profile
  are complete.
* Provide privacy templates: credential gates, membership proofs, nullifier
  claims, range proofs, DPP compliance claims.
* Surface on-chain cost estimation and feasibility warnings at build time.
* Keep pure-Java proving the default; native acceleration opt-in.
* Use Yaci DevKit for repeatable end-to-end testing.

### Phase 2 — Privacy Developer Experience *(next 12 months)*

Make privacy workflows ergonomic and hard to misuse.

* Generated types for proof envelopes, public-input schemas, VK references,
  policies.
* `ZeroJ.verify(...)` JuLC bridge and statement-level proof APIs.
* Reference datum VK and VK-hash deployment patterns when governance and
  tests are mature.
* Public-input linting and privacy review tooling.
* Full reference apps: credential-gated access, DPP compliance, anonymous
  voting.
* Mature BBS / BBS+ as off-chain credential presentation, mapped cleanly
  into ZeroJ proof envelopes.

### Phase 3 — Scale, Standards, Advanced Backends *(12–24 months)*

Broaden proof systems and reduce cost without weakening the privacy model.

* Mature PlonK BLS12-381 on-chain verification with audited cost profiles.
* Explore aggregation and recursion for many proofs or high-throughput
  applications.
* Evaluate STARK / AIR backends with explicit Cardano feasibility analysis.
* Enterprise issuance flows: HSM-backed keys, JCA providers, audit logs,
  compliance reporting.
* Align with W3C VC and BBS / BBS+ standards as they stabilize.

### Success Criteria

JuLC + ZeroJ have succeeded when:

1. A Java engineer can build and test a privacy-preserving Cardano dApp
   without learning Haskell, Rust, or a ZK DSL.
2. Default examples reveal statements, not sensitive data.
3. Proofs are bound to application context, nullifier scope, VK identity,
   and Cardano transaction semantics.
4. At least one production issuer or application uses ZeroJ for
   credentials, DPP, governance, compliance, or reputation.
5. Independent teams build on `zeroj-crypto`, `zeroj-circuit-lib`, proof
   envelopes, and verifier tooling without modifying internals.
6. JuLC and ZeroJ become credible reference options for Java-native
   Cardano privacy applications, cited alongside Aiken and Plutus in
   ecosystem documentation and CIPs.

---

## 14. Design Principles and Vision

### Principles

* **Privacy first.** Start from the disclosure policy, not the proof system.
* **Reveal statements, not data.** Public inputs must be intentional and
  minimal.
* **Fail closed.** Unsupported proof systems, malformed public inputs,
  unknown VKs, and ambiguous policies must reject.
* **Local-first proving.** Private witnesses stay with the user whenever
  possible.
* **Typed boundaries.** Public inputs, proof envelopes, VK references, and
  policy IDs are structured and versioned.
* **Backend-aware deployment.** Hide backend complexity from business
  logic; expose feasibility, cost, and audit details at deployment time.
* **Composable with Cardano.** CCL, Yaci, metadata standards, reference
  scripts, UTxO patterns, and governance workflows are first-class.
* **Candid maturity.** Distinguish shipping features, target DX, incubating
  features, and research clearly.

### Vision

JuLC lets Java developers build Cardano validators.

ZeroJ lets Java developers build, prove, and verify zero-knowledge
statements.

Together they can make Cardano a natural home for privacy-preserving
programmable trust — applications where users, businesses, and
institutions prove what matters without exposing what should remain
private.

The north star:

```text
Cardano privacy applications should be practical for Java teams,
auditable by security teams,
and safe for users by default.
```
