# JuLC + ZeroJ - Privacy-First Programmable Trust on Cardano

> **Write validators and zero-knowledge applications in Java.**
> **Ship privacy-preserving Cardano systems where disclosure is intentional,
> verifiable, and minimal.**

JuLC and ZeroJ are complementary Java-first projects for Cardano.

**JuLC** compiles a deterministic subset of Java into UPLC validators.
**ZeroJ** lets Java developers define zero-knowledge circuits, generate proofs,
verify them off-chain, and verify selected proofs on-chain through Plutus V3.

Together, JuLC and ZeroJ form a JVM-native platform for privacy-preserving
Cardano applications: credentials, gated dApps, digital product passports,
anonymous governance, reputation, compliance, and verifiable computation.

The goal is not only "Java for Cardano" or "Java for ZK." The goal is:

```text
Privacy as a first-class application primitive.

Developers should express what must be proven, what may be revealed,
what must remain hidden, and how proofs bind to Cardano transactions
without writing cryptographic plumbing.
```

---

## 1. The Opportunity

Cardano has strong foundations for verifiable computation: UTXO accounting,
script validation, metadata anchoring, native assets, governance, and Plutus V3
BLS12-381 builtins. But the developer story is still dominated by specialist
languages and ecosystems: Aiken, Plutus, Plutarch, Helios, OpShin, Circom,
Noir, Halo2, arkworks, and custom Rust or Haskell infrastructure.

That is a barrier for enterprises, identity providers, governments, supply-chain
operators, and Java teams that already run production systems on the JVM.

At the same time, privacy requirements are becoming normal product
requirements:

* prove eligibility without revealing identity
* prove compliance without revealing trade secrets
* prove a credential is valid without exposing the credential
* prove a vote is authorized without linking it to a voter
* prove a threshold, range, membership, or state transition without revealing
  the underlying data

Zero-knowledge systems can solve these problems, but the current developer
surface is still too close to cryptography research: fields, circuits, witness
assignment, constraint systems, proving keys, verifier keys, ceremonies,
serialization formats, and backend-specific behavior.

JuLC + ZeroJ should make this accessible to Java engineers.

**Thesis:**

```text
Java is one of the largest production software ecosystems in the world.
Cardano needs a serious JVM path for enterprise adoption.
Privacy-preserving applications need a higher-level developer surface.
JuLC + ZeroJ can provide that surface by combining validators, circuits,
transaction tooling, and privacy patterns in one Java-native stack.
```

---

## 2. Who This Is For

| Audience | Why they care |
|----------|---------------|
| Enterprise Java teams | Build Cardano applications without retraining teams in Haskell, Rust, or ZK DSLs. |
| Identity and credential issuers | Issue credentials and support selective disclosure with JVM tooling. |
| Supply-chain and DPP integrators | Anchor product claims while hiding sensitive supplier, material, and pricing data. |
| Regulated dApp builders | Enforce KYC, accreditation, residency, or age policies without collecting raw user data. |
| Governance researchers | Prototype private voting, anonymous DRep proofs, stake thresholds, and nullifier-based participation. |
| Bloxbean ecosystem users | Extend Cardano Client Lib, Yaci Store, and Yaci DevKit with native validator and ZK workflows. |

---

## 3. Product Positioning

JuLC + ZeroJ should be positioned as:

```text
The Java-native privacy layer for Cardano applications.
```

The differentiation is strongest when the product is framed around developer
workflow and privacy outcomes, not only compiler architecture.

| Dimension | Current Cardano/ZK norm | JuLC + ZeroJ target |
|-----------|--------------------------|---------------------|
| Application language | Haskell, DSLs, Rust, TypeScript-like languages, Python-like languages | Standard Java subset and JVM tooling |
| Privacy model | Hand-built per application | Reusable commitments, nullifiers, roots, proof envelopes, and disclosure policies |
| On-chain integration | Custom Plutus/Aiken verifier logic | JuLC-generated validators and reusable on-chain verifier libraries |
| Off-chain proving | Native tools, CLIs, sidecars, or backend-specific APIs | Pure Java proving first, optional native acceleration |
| Developer experience | Cryptography concepts exposed early | Business statement first, cryptographic details behind typed APIs |
| Enterprise fit | Fragmented language and deployment stack | Gradle/Maven, IntelliJ, JUnit, GraalVM, CCL, Yaci |

The platform should not claim that every proof system is equally supported
on-chain. Cardano's current Plutus V3 capabilities make some combinations
practical and others infeasible. The developer experience can be backend-aware
without leaking unnecessary cryptographic machinery into application code.

---

## 4. Privacy Model

Privacy must be an explicit part of the architecture. A proof system alone does
not make an application private. The application must define what is public,
what is private, who learns what, and how correlation is controlled.

### 4.1 What May Be Public

Public values are the minimum data needed by validators, indexers, verifiers,
and auditors:

* proof bytes or proof hash
* public inputs
* verification key hash or reference
* policy identifier or circuit identifier
* Merkle or accumulator root
* scoped nullifier
* commitment
* validity interval or epoch
* application-specific statement, such as `eligible = true`

Public values must be assumed visible forever once they are on-chain.

### 4.2 What Must Remain Private

Private values are never placed on-chain and should not be sent to dApps unless
the product explicitly requires disclosure:

* age, country, salary, identity attributes, documents
* credential body and credential subject
* issuer signature or credential secret
* supply-chain bill of materials and exact measurements
* Merkle paths, unless the path itself is intended to be disclosed
* randomness used for commitments
* voting identity, stake credential, or delegation identity
* reputation history or graph data

ZeroJ circuits should make this distinction obvious at the Java boundary:
public inputs are declared as public, witness values are declared as private,
and generated or helper APIs should prevent accidental disclosure.

### 4.3 Adversaries

The platform should document privacy against these observers:

| Observer | What they can see | Privacy goal |
|----------|-------------------|--------------|
| Chain observer | Transactions, scripts, metadata, public inputs, timing | Cannot recover private witness data. |
| dApp operator | Submitted proof and public statement | Learns eligibility or compliance, not raw credential/data. |
| Issuer | Credential issuance event and issuer records | Cannot track every future use unless app design reveals it. |
| Verifier | Proof, roots, nullifier, policy | Cannot link unrelated presentations unless nullifier scope allows it. |
| Colluding apps | Shared public values across apps | Cannot correlate users when nullifiers are app-scoped. |
| Prover service | Witness, if outsourced | Must be avoided or treated as trusted; local proving is preferred. |

### 4.4 Guarantees

JuLC + ZeroJ should aim to provide:

* **Data minimization:** reveal statements, not source data.
* **Soundness:** a valid proof means the statement is true under the accepted
  circuit and verification key.
* **Replay protection:** nullifiers or transaction-bound public inputs prevent
  proof reuse where reuse is unsafe.
* **Scoped unlinkability:** different dApps, policies, or epochs can use
  different nullifier scopes.
* **Auditability:** public roots, commitments, proof hashes, and VK hashes make
  claims tamper-evident.
* **Local-first proving:** users can generate proofs without sending secrets to
  dApps or hosted provers.

### 4.5 Non-Guarantees

The platform should also be candid about what it does not solve by itself:

* ZK does not prove that an issuer was honest when issuing a credential.
* ZK does not hide transaction timing, wallet funding patterns, IP addresses, or
  wallet fingerprinting.
* ZK does not prevent credential sharing unless the credential is bound to a
  hardware key, biometric process, or external trust mechanism.
* ZK does not make public inputs private. Poor public input design can fully
  defeat application privacy.
* ZK does not remove the need for audits of circuits, cryptographic libraries,
  setup ceremonies, or verifier code.

Privacy-first application templates should include warnings and defaults for
these failure modes.

---

## 5. Core Privacy Primitives

ZeroJ should provide reusable building blocks so every application does not
invent its own privacy protocol.

| Primitive | Purpose |
|-----------|---------|
| Commitments | Bind to private data while revealing only a commitment. |
| Scoped nullifiers | Prevent replay or double-use without revealing identity. |
| Merkle and accumulator roots | Prove membership, non-membership, or state inclusion against public roots. |
| Revocation roots | Support expired, revoked, or refreshed credentials without exposing credential data. |
| Range and comparison gadgets | Prove predicates such as `age >= 18`, `stake >= T`, or `carbon < limit`. |
| Signature verification gadgets | Prove an issuer signed private data. |
| Proof envelopes | Carry proof bytes, proof system, curve, VK reference, public inputs, and metadata consistently. |
| Policy binding | Bind a proof to an application, validator, circuit, chain, epoch, or transaction context. |

The highest-value abstraction is not a raw proof. It is a typed statement such
as:

```text
This holder has a valid credential from issuer I,
satisfies policy P,
is not revoked under root R,
and has not used this claim before under nullifier N.
```

---

## 6. Project Responsibilities

### 6.1 JuLC - Java to UPLC

JuLC compiles a deterministic, functional subset of Java into UPLC validators.

Responsibilities:

* spending, minting, withdrawal, and certificate validators
* Cardano ledger abstractions such as `ScriptContext`, `TxInfo`, values,
  datums, redeemers, signatories, validity intervals, and reference inputs
* deterministic and bounded execution
* Plutus interop and reference-script-friendly composition
* validator-side proof verification wrappers for supported ZeroJ proof formats

Example validator:

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

### 6.2 ZeroJ - Java to ZK Circuits and Proofs

ZeroJ provides Java APIs for defining circuits, generating witnesses, proving,
verifying, and preparing Cardano-compatible verification artifacts.

Current and near-term responsibilities:

* `CircuitSpec` and `CircuitBuilder` Java circuit DSL
* public/private signal declarations
* R1CS and Groth16 flows
* PlonK flows where supported
* BLS12-381 and BN254 off-chain verification
* BLS12-381 on-chain verification paths for Cardano
* standard circuit library: Poseidon, MiMC, Merkle proofs, comparisons, binary
  operations, Pedersen/Jubjub-related primitives where supported
* witness generation
* proof envelopes, canonical hashing, and Cardano anchoring helpers
* verifier orchestration through pluggable backend SPI

Example circuit in the current style:

```java
public class AgeCredentialCircuit implements CircuitSpec {

    @Override
    public void define(SignalBuilder c) {
        Signal minAge = c.publicInput("minAge");
        Signal age = c.privateInput("age");
        Signal credentialHash = c.publicInput("credentialHash");
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

### 6.3 Shared Foundation - `zeroj-crypto`

`zeroj-crypto` should be the common cryptographic substrate for ZeroJ proving,
verification, and off-chain dApp code.

Important capabilities:

* BLS12-381 field and group operations
* pairing operations
* Groth16 and PlonK support where implemented
* Poseidon, MiMC, Pedersen, Merkle, and related primitives
* pure Java first, with optional native acceleration where useful
* GraalVM-compatible design, avoiding unnecessary reflection and runtime code
  loading

This substrate should be auditable, reusable, and boring in the best sense:
stable APIs, deterministic serialization, test vectors, and clear versioning.

---

## 7. Joint Architecture

```text
                 Java Application Code
        validators, circuits, policies, tests
                         |
          +--------------+--------------+
          |                             |
          v                             v
        JuLC                         ZeroJ
   Java -> UPLC              Java -> Constraint Systems
          |                             |
          v                             v
   Cardano Validator         R1CS / PlonK / future IRs
          |                             |
          |                             v
          |                 Proving Key / Verification Key
          |                             |
          |                             v
          |                 Proof Envelope + Public Inputs
          |                             |
          +--------------+--------------+
                         |
                         v
              Cardano Transaction Layout
        validator, datum, redeemer, metadata,
        proof, public inputs, VK reference/hash,
        commitment, root, scoped nullifier
                         |
                         v
                    Cardano Ledger
```

The architecture should treat transaction layout as part of the privacy design.
A technically valid proof can still leak data if public inputs, metadata, roots,
or nullifiers are chosen badly.

---

## 8. Golden Path: A Privacy-Preserving dApp

A target end-to-end flow should look like this:

1. **Issuer creates a private claim**
   * Example: a KYC provider, auditor, government agency, DPP auditor, or DAO
     registry signs or commits to user/product attributes.

2. **Application publishes policy**
   * The dApp defines a circuit, accepted issuer keys, accepted roots, required
     thresholds, nullifier scope, and verifier/VK references.

3. **User proves locally**
   * The wallet or local application generates a witness and proof without
     sending private attributes to the dApp.

4. **Transaction carries only public privacy artifacts**
   * Proof or proof hash
   * Public inputs
   * Verification key hash/reference
   * Root or commitment
   * Scoped nullifier
   * Policy identifier

5. **JuLC validator verifies the statement**
   * The validator checks the proof, binds it to the expected policy, validates
     the nullifier or root, and enforces business logic.

6. **Observers learn the statement, not the source data**
   * Example: "eligible", "not revoked", "stake threshold met", "product claim
     compliant", or "vote authorized."

This should become the default user journey for privacy-enabled Java Cardano
apps.

---

## 9. zk-Enabled Validators

The target developer experience is:

```text
Application code verifies a privacy statement.
Generated or library code handles proof decoding, VK lookup, public input
binding, backend selection, and pairing/transcript details.
```

Today, applications can use concrete verifier classes and Cardano preparation
helpers. The aspirational JuLC bridge is a one-line business API:

```java
@SpendingValidator
public class PrivateClaimValidator {

    @Entrypoint
    static boolean validate(ClaimDatum datum,
                            ClaimRedeemer redeemer,
                            ScriptContext ctx) {

        return ZeroJ.verify(
                AgeCredentialCircuit.class,
                redeemer.proof(),
                redeemer.publicInputs()
        ) && ctx.txInfo().validRange().contains(datum.deadline());
    }
}
```

This should be documented as **target DX** until the generated artifacts and
JuLC bridge are implemented end to end.

Under the hood, the bridge should:

* resolve the circuit identity to an accepted VK hash or reference
* bind public inputs to the validator, policy, datum, redeemer, chain, and
  transaction context
* verify proof bytes with the supported on-chain verifier
* enforce nullifier scope and replay rules where configured
* fail closed on unknown proof systems, unknown curves, malformed public inputs,
  or unsupported verifier layouts

---

## 10. Verification Key Lifecycle

Verification keys are part of application governance and privacy. A bad VK
lifecycle can break upgrades, confuse auditors, or allow downgrade attacks.

Recommended lifecycle:

| Stage | Description |
|-------|-------------|
| Compile | Circuit build produces constraints and VK material. |
| Identify | VK is canonically encoded and hashed. |
| Register | Issuer or app registry signs and publishes accepted VK hashes. |
| Deploy | App chooses VK-in-script, reference datum VK, or hash commitment pattern. |
| Consume | Validators accept only configured VK hashes/references. |
| Rotate | New VKs are introduced through explicit transition windows. |
| Retire | Old VKs expire after pending proofs and users have migrated. |

Current on-chain flows can bake the VK at deploy time. Reference datum VK and
hash-commitment patterns are important for upgradeability, but should be
described as deployment patterns with different maturity and tradeoffs:

| Pattern | Strength | Tradeoff |
|---------|----------|----------|
| VK in script | Simple and concrete | Validator redeploy needed for VK changes. |
| Reference datum VK | Smaller reusable logic and rotatable VK | More complex UTXO governance. |
| VK hash commitment | Small script commitment | Full VK must be supplied or resolved elsewhere. |

---

## 11. Public Inputs vs Private Witnesses

ZeroJ should make the public/private boundary impossible to miss.

| Public Inputs | Private Witnesses |
|---------------|-------------------|
| issuer public key or issuer id | credential body |
| policy parameters | age, country, salary, identifiers |
| Merkle or accumulator root | Merkle path |
| nullifier | nullifier secret |
| commitment | commitment randomness |
| threshold or range limit | exact value |
| validity epoch | raw document or event history |
| proof context hash | user secret or wallet binding secret |

Rule of thumb:

```text
Anything the validator needs to read is public.
Anything that would harm the user, issuer, or business if disclosed is private.
```

A privacy-first SDK should provide linting or review tools that flag suspicious
public inputs, such as raw identifiers, exact birth dates, unscoped nullifiers,
stable cross-app commitments, or unnecessary metadata.

---

## 12. Proof System Abstraction and Feasibility

Developer APIs should hide backend details where practical, but the platform
must remain honest about what can run on Cardano today.

| Capability | Feasibility | Notes |
|------------|-------------|-------|
| Java circuit definition with `CircuitSpec` | High | Current core developer path. |
| Pure Java Groth16 proving | High | Strong fit for zero native dependency workflows. |
| Pure Java PlonK proving | High/medium | Useful off-chain; exact maturity depends on circuit/backend path. |
| Groth16 BLS12-381 on-chain verification | High | Best near-term Cardano verification target. |
| PlonK BLS12-381 on-chain verification | Medium/experimental | Feasible but more complex and budget-sensitive. |
| BN254 on-chain verification | Not feasible today | Plutus V3 does not provide BN254 pairing builtins. |
| Halo2/Pallas on-chain verification | Not feasible today | No Pallas builtins in Plutus. |
| BBS/BBS+ selective disclosure | Medium off-chain | Strong credential backend; not a generic on-chain verifier or circuit gadget yet. |
| STARK/AIR on-chain verification | Research/future | Needs careful proof-size, verifier-cost, and builtin analysis. |
| Recursion and aggregation | Research/future | Valuable for scale, but not a Phase 1 dependency. |

The right abstraction is:

```text
Backend-agnostic at the application boundary.
Backend-explicit at deployment, cost estimation, and audit boundaries.
```

---

## 13. Showcase Use Cases

### 13.1 Selective-Disclosure Credentials

A user proves they satisfy a policy without revealing the credential:

* age is at least 18
* country is in an allow-list
* credential is signed by an accepted issuer
* credential is not revoked under the current validity root
* nullifier has not been used for this app and epoch

Near-term implementation can use Poseidon or EdDSA-style credential circuits.
BBS/BBS+ is strategically important for standards-aligned selective disclosure,
but should be positioned as an off-chain credential backend or future circuit
work until implementation and audit maturity justify stronger claims.

### 13.2 Privacy-Preserving Digital Product Passport

A manufacturer or auditor proves compliance predicates without revealing the
full bill of materials, supplier graph, exact measurements, or pricing data.

Examples:

* recycled content is above a threshold
* carbon impact is below a threshold
* origin is in an approved set
* no banned material appears in a committed material list
* temperature remained in range during transport

Cardano stores commitments, proof hashes, policy IDs, and roots. Detailed
documents remain off-chain and are disclosed only to authorized parties.

### 13.3 Anonymous Governance

A voter proves:

* they were eligible at snapshot `S`
* stake or reputation was at least threshold `T`
* their vote has not already been cast for proposal `P`

The validator sees a proposal-scoped nullifier, vote payload, root, and proof.
It should not learn the voter's identity or unrelated governance activity.

### 13.4 zk-KYC Gates

A regulated dApp verifies that a user satisfies compliance requirements without
collecting identity documents.

The dApp learns:

* policy satisfied
* issuer accepted
* credential not revoked
* nullifier valid for this app/session

The dApp does not learn name, address, passport number, exact birth date, or
document image.

### 13.5 Verifiable Reputation

A user proves a reputation statement without revealing the full history:

* score >= X
* top decile
* no unresolved slashing event
* member for at least N epochs

The reputation graph or raw event history remains private or selectively
disclosed.

---

## 14. Developer Experience

The product should feel like Java application development, not cryptography
assembly.

| Pillar | Target experience |
|--------|-------------------|
| Same language | Validators, circuits, tests, proof flows, and transaction code in Java. |
| Same build | Gradle and Maven workflows for compile, prove, verify, package, and deploy. |
| Same tests | JUnit tests for circuits, proof generation, verifier behavior, and Yaci DevKit flows. |
| Strong types | Generated or helper types for public inputs, proof envelopes, VK references, and policies. |
| Local proving | Default path keeps witnesses on the user's machine. |
| Clear deployment | Cost estimation and feasibility warnings for on-chain verifier choices. |
| Privacy templates | Credential gate, nullifier claim, membership proof, DPP claim, private vote. |
| Audit artifacts | Constraint hash, VK hash, proof vectors, public input schema, and circuit version. |

Example target API shape:

```java
var statement = CredentialPolicy.ageAtLeast(18)
        .issuer("kyc-provider-1")
        .validityRoot(root)
        .nullifierScope("dex-v1", epoch);

var proof = ZeroJ.prove(statement, walletCredential);

txBuilder.attachZkProof(proof)
        .payToContract(appAddress, datum);
```

This API is aspirational. It describes the product direction: policy-level
privacy APIs built on top of the existing circuit/proof/verifier layers.

---

## 15. Ecosystem Alignment

JuLC + ZeroJ should extend the existing Bloxbean Java-on-Cardano stack:

* **Cardano Client Lib (CCL):** transaction building, signing, metadata,
  redeemers, datums, fee estimation, and submission helpers.
* **Yaci DevKit:** local end-to-end testing of validators, proofs, and
  transaction flows.
* **Yaci Store:** indexed chain data for roots, snapshots, credential
  registries, governance state, and witness generation.
* **Cardano metadata and token standards:** CIP-25, CIP-68, DPP metadata,
  governance metadata, and anchor commitments.
* **Governance alignment:** CIP-1694 use cases such as private voting,
  anonymous DRep credentials, and stake threshold proofs.
* **Credential standards:** W3C VC compatibility and emerging BBS/BBS+
  standards, with careful distinction between off-chain credential presentation
  and on-chain SNARK verification.

The end state should be one Java stack from issuance to proof to transaction to
chain index:

```text
Issuer service -> holder wallet/app -> ZeroJ proof -> CCL transaction
-> JuLC validator -> Yaci indexed state -> auditor/verifier tools
```

---

## 16. Roadmap

### Phase 1 - Production Foundation

Focus: ship credible privacy-preserving apps with the proof systems Cardano can
verify today.

* Harden `CircuitSpec`, witness generation, proof envelopes, and canonical
  serialization.
* Prioritize Groth16 BLS12-381 for Cardano on-chain verification.
* Provide privacy templates for credential gates, membership proofs,
  nullifier claims, range proofs, and DPP compliance claims.
* Provide clear on-chain cost estimation and feasibility warnings.
* Keep pure Java proving and verification as the default developer path.
* Use Yaci DevKit for repeatable end-to-end testing.

### Phase 2 - Privacy Developer Experience

Focus: make privacy workflows ergonomic and hard to misuse.

* Add generated or helper types for proof envelopes, public input schemas, VK
  references, and policies.
* Add target JuLC bridge APIs for statement-level proof verification.
* Promote reference datum VK and VK hash deployment patterns when governance and
  tests are mature.
* Add public-input linting and privacy review helpers.
* Provide full reference apps for credential-gated access, DPP compliance, and
  anonymous voting.
* Mature BBS/BBS+ as an off-chain credential presentation backend and map it
  cleanly into ZeroJ proof envelopes where appropriate.

### Phase 3 - Scale, Standards, and Advanced Backends

Focus: broaden proof systems and reduce cost without weakening the privacy
model.

* Mature PlonK BLS12-381 on-chain verification if budgets and audits support it.
* Explore aggregation and recursion for many proofs or high-throughput apps.
* Evaluate STARK/AIR backends with explicit Cardano feasibility analysis.
* Support enterprise issuance flows: HSM-backed keys, audit logs, JCA providers,
  and compliance reporting.
* Align credential formats with W3C VC and BBS/BBS+ standards as those
  standards and implementations stabilize.

---

## 17. Success Criteria

JuLC + ZeroJ succeed when:

1. A Java engineer can build and test a privacy-preserving Cardano dApp without
   learning Haskell, Rust, or a ZK-specific DSL.
2. The default examples reveal statements, not sensitive data.
3. Proofs are bound to application context, nullifier scope, VK identity, and
   Cardano transaction semantics.
4. At least one production issuer or application uses ZeroJ for credentials,
   DPP, governance, compliance, or reputation.
5. Independent teams can use `zeroj-crypto`, proof envelopes, and verifier
   tooling without modifying internals.
6. JuLC and ZeroJ become credible reference options for Java-native Cardano
   privacy applications.

---

## 18. Design Principles

* **Privacy first:** start from the disclosure policy, not from the proof system.
* **Reveal statements, not data:** public inputs must be intentional and minimal.
* **Fail closed:** unsupported proof systems, malformed public inputs, unknown
  VKs, and ambiguous policies must reject.
* **Local-first proving:** private witnesses should stay with the user whenever
  possible.
* **Typed boundaries:** public inputs, proof envelopes, VK references, and
  policy IDs should be structured and versioned.
* **Backend-aware deployment:** hide backend complexity from business logic, but
  expose feasibility, cost, and audit details at deployment time.
* **Composable with Cardano:** CCL, Yaci, metadata standards, reference scripts,
  UTXO patterns, and governance workflows are first-class.
* **Candid maturity:** distinguish working features, target DX, incubating
  features, and research clearly.

---

## 19. Feasibility Summary

The core vision is feasible now:

```text
Java circuit -> pure Java proof -> Cardano transaction -> JuLC/Plutus V3
on-chain verification for BLS12-381 proofs.
```

The strongest near-term product path is:

* Groth16 BLS12-381 on-chain verification
* pure Java proving and verification
* privacy templates for credentials, DPP claims, voting, membership, and
  nullifier claims
* CCL/Yaci integration for transactions and tests
* clear public/private input schemas and proof envelopes

The ambitious roadmap is also plausible, but should be staged:

* PlonK on-chain verification: promising but budget-sensitive
* BBS/BBS+: strong for off-chain credential presentation, future for deeper
  circuit/on-chain integration
* STARK/AIR: research until Cardano verifier costs and proof sizes are proven
* recursion/aggregation: valuable for scale, not required for the first wave of
  privacy applications

---

## 20. Vision

JuLC lets Java developers build Cardano validators.

ZeroJ lets Java developers build, prove, and verify zero-knowledge statements.

Together, they can make Cardano a natural home for privacy-preserving
programmable trust: applications where users, businesses, and institutions prove
what matters without exposing what should remain private.

The north star is simple:

```text
Cardano privacy applications should be practical for Java teams,
auditable by security teams,
and safe for users by default.
```
