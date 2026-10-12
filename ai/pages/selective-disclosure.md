# Choose how to disclose

> Six ways to share private data on Cardano with ZeroJ, and what each party learns: reveal signed values, prove a rule, hide a number, tell chosen readers, encrypt for an auditor, or split the trust.

Canonical URL: https://zeroj.dev/selective-disclosure/

**Selective disclosure** means showing each party exactly what it needs and nothing more. A
landlord needs to know you earn enough, not your payslip. A tax authority needs every salary, but
the public needs none. An election needs the total, and nobody should see a single ballot.

ZeroJ gives you six tools for this. They differ in **who learns what**, what they need (an
issuer, a circuit, a key) and how mature they are. This page compares them on one example. Each
option has its own page with simple code and real use cases.

## One salary, six ways

Carol earns 5,000 a month. Pick an option to see what Carol, a landlord, the tax authority and
everyone else learn. Not sure where to start? Press **Help me choose**.

_The web version of this page has an interactive illustration here._

| Option | Landlord learns | Tax authority learns | Everyone else sees |
|---|---|---|---|
| Reveal the value (BBS) | salary = 5,000, signed by the employer | — | nothing |
| Prove a rule (Groth16) | "salary ≥ 3,000": yes | — | the proof and the threshold |
| Hide a number (Pedersen) | "the commitment hides ≥ 3,000": yes | can add commitments up; learns a total only if given its opening | a 32-byte commitment |
| Tell chosen readers (confidential note) | nothing unless Carol shares | 5,000 from its own delivery, if the sender delivered honestly (not enforced) | commitment + 89 bytes per reader |
| Encrypt for an auditor (ElGamal + proof) | — | 5,000, guaranteed to match | commitment, ciphertext, proof |
| Split the trust (threshold ElGamal) | — | only what 2 of 3 trustees agree to decrypt (by policy, the total) | ciphertexts, then the total |

## Which one do I need?

Start from the question "does anyone need the exact value?"

| You need… | Use | Needs | Maturity |
|---|---|---|---|
| The verifier to see **some signed attributes exactly** ("country = NZ") and nothing else | [Reveal the value](https://zeroj.dev/selective-disclosure/reveal-attributes/) with **BBS** | An issuer; no circuit, no trusted setup | Beta (IRTF draft) |
| A **yes/no answer** about private data ("over 21", "income ≥ 50,000") | [Prove a rule](https://zeroj.dev/selective-disclosure/prove-a-rule/) with a **Groth16 predicate** | A circuit and a trusted setup | Beta |
| A **number kept sealed on-chain** that can be checked, added up or opened later | [Hide a number](https://zeroj.dev/selective-disclosure/hide-a-number/) with a **Pedersen commitment** | A circuit for each statement | Ready (pending external review) in-circuit; sums experimental |
| **Named parties** (the owner, an auditor) to read the value from the chain | [Tell chosen readers](https://zeroj.dev/selective-disclosure/share-with-chosen-readers/) with a **confidential note** | A viewing key per reader | Experimental |
| An **authority to read it, with no way for the sender to lie** | [Encrypt for an auditor](https://zeroj.dev/selective-disclosure/encrypt-for-an-auditor/) with **ElGamal plus a proof** | An auditor key and a circuit | Experimental |
| **No single party** to see individual values; a quorum decrypts only the agreed result (a policy, not a guarantee) | [Split the trust](https://zeroj.dev/selective-disclosure/split-trust/) with **threshold ElGamal** | A key-generation ceremony among trustees | Experimental |

Two quick rules of thumb:

- **BBS reveals, circuits compute.** If the verifier only needs a fact *about* a value, don't reveal
  the value: prove the fact.
- **Commitments are for the owner, encryption is for someone else.** Only the person holding the
  **opening** (the value and its random blinding) can open a commitment. If a third party must read the value without the owner's help,
  encrypt it to them.

> **Caution: Experimental and new**
>
> Everything except BBS and Groth16 predicates is new in ZeroJ 0.1.0-pre13 and is either
> **experimental** or **pending external review**. None of it has been externally audited. See
> [Status & maturity](https://zeroj.dev/start/status/).

## They combine

Real applications use several options at once:

- **Confidential payroll** hides each salary in a commitment, delivers it to the employee and the
  tax authority, and encrypts it to the tax authority with a proof so the employer can't
  under-report. ([use case](https://zeroj.dev/use-cases/confidential-payroll/))
- **A private vote** encrypts each ballot to a key shared by trustees, proves each ballot is a 0
  or a 1, and decrypts only the total. The demo needs all three trustees (n-of-n); threshold
  key generation is the t-of-n upgrade. ([use case](https://zeroj.dev/use-cases/private-voting/))
- **KYC** could reveal a country with BBS and prove an age rule with a small circuit; the two demos
  show each half. ([use case](https://zeroj.dev/use-cases/selective-disclosure/))

## What disclosure doesn't cover

Choosing what to reveal is half the job. Every option above also needs the usual application
checks:

- **Replay.** A presentation or proof can be copied. Bind it to a fresh challenge or to the UTxO
  being spent.
- **Authorization.** A valid proof says nothing about who may spend or receive funds.
- **Metadata.** Transaction graphs, timing and fees can reveal more than the data you hid.

See [Application security](https://zeroj.dev/guides/verifying/application-security/).

## The options

  - [Reveal the value](https://zeroj.dev/selective-disclosure/reveal-attributes/): BBS credentials: show chosen signed attributes, hide the rest.
  - [Prove a rule](https://zeroj.dev/selective-disclosure/prove-a-rule/): Groth16 predicates over a signed or committed credential: the verifier learns yes or no.
  - [Hide a number](https://zeroj.dev/selective-disclosure/hide-a-number/): Pedersen commitments: seal a value on-chain, prove facts about it, add commitments up.
  - [Tell chosen readers](https://zeroj.dev/selective-disclosure/share-with-chosen-readers/): Confidential notes: the opening sealed on-chain for the owner and an auditor.
  - [Encrypt for an auditor](https://zeroj.dev/selective-disclosure/encrypt-for-an-auditor/): ElGamal plus a proof: the auditor can always read the real value.
  - [Split the trust](https://zeroj.dev/selective-disclosure/split-trust/): Threshold ElGamal: no single trustee can decrypt; a quorum decrypts the agreed result.

New to the underlying ideas? Read [Commitments & encryption, explained](https://zeroj.dev/learn/commitments-and-encryption/).
