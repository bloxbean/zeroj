# Use cases

> What zero-knowledge proofs unlock on Cardano — nine worked use cases, the building block behind each, and runnable demos.

Canonical URL: https://zeroj.dev/use-cases/overview/

A zero-knowledge proof lets you prove a fact without revealing the data behind it. "I'm over 18"
without a birth date. "I'm on the voter list" without saying which voter. "Our reserves cover every
deposit" without publishing a single balance. A Cardano validator can check that kind of proof in
one transaction. The secret inputs never leave the prover's machine.

This section walks through what that makes possible. Each page explains the real-world problem, the
statement being proven, what stays private, how the proof reaches the chain, and the security
questions you still have to answer. Most pages also link a runnable demo.

> **Caution: Research software**
>
> ZeroJ is experimental and has not been externally audited. The demos run against a local
> [Yaci DevKit](https://github.com/bloxbean/yaci-devkit) devnet with development-only trusted setups.
> Treat them as blueprints to learn from, not as systems for real identities, votes or funds. See
> [Status & maturity](https://zeroj.dev/start/status/).

## Identity & compliance

  - [Age & KYC eligibility](https://zeroj.dev/use-cases/age-and-kyc/): Prove you're old enough and live in an approved country, using an issuer-signed credential, without revealing either value.
  - [Selective disclosure & reusable KYC](https://zeroj.dev/use-cases/selective-disclosure/): Do KYC once, then show each service only the attributes or predicates it needs, with Groth16 predicates or BBS verified on-chain.

## DeFi & finance

  - [Proof of reserves](https://zeroj.dev/use-cases/proof-of-reserves/): A custodian proves reserves cover all customer balances without publishing any balance.
  - [Private token transfers](https://zeroj.dev/use-cases/private-payments/): A design walkthrough of a shielded pool: deposit, then withdraw to a fresh address that can't be linked to the deposit.

## Governance & communities

  - [Private voting](https://zeroj.dev/use-cases/private-voting/): An eligible member votes exactly once, and nobody can tell which member cast which ballot.
  - [One claim per person](https://zeroj.dev/use-cases/sybil-resistant-airdrop/): A Sybil-resistant airdrop: a personhood credential claims once per epoch, and the payout is bound to a recipient.

## Ownership & assets

  - [Private NFT ownership](https://zeroj.dev/use-cases/nft-ownership/): Prove you hold an NFT from a collection for token-gated access without revealing your wallet.
  - [Prove you own a Cardano account](https://zeroj.dev/use-cases/account-recovery/): Prove you know the root key behind an address, without revealing the seed, so a refund can reach the real owner after a hack.

## Supply chain

  - [Digital product passport](https://zeroj.dev/use-cases/digital-product-passport/): Prove a product meets carbon, recycled-content and origin rules without exposing supplier data.

## Pick the right tool

Almost every use case is built from a small set of patterns. Start from what you need to prove:

| You need to… | Approach | ZeroJ building blocks |
|---|---|---|
| Prove a predicate over a hidden value (age ≥ 18, carbon ≤ 50 kg, reserves ≥ liabilities) | Groth16 circuit | `ZkUInt` with `@UInt(bits = …)` and `gte` / `lte` comparisons |
| Reveal some issuer-signed attributes and hide the rest | BBS selective disclosure (no circuit, no trusted setup) | `BbsService` in `zeroj-bbs`; `BbsProofVerify` for on-chain checks |
| Prove you're in a set without saying which member | Merkle tree + Poseidon | `ZkMerkle.verifyProofPoseidon` with `PoseidonParamsBLS12_381T3.INSTANCE` |
| Allow one action per person, credential or NFT | Nullifier | `ZkPoseidon.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, secret, contextId)`, stored on-chain (sorted list, spent UTxO) |
| Rely on a fact someone else attested | Issuer signature checked inside the circuit | `ZkEdDSAJubjub.verifyWithRegisteredKey` |
| Stop a copied proof from paying someone else | Bind the recipient or the spent UTxO into the public inputs | recipient public input; a spend reference computed from `ScriptContext` in your validator |
| Prove facts about large private state (millions of entries) | Poseidon MPF / JMT (**experimental**) | `zeroj-mpf-poseidon`, `zeroj-jmt-poseidon` |

Groth16 on BLS12-381 is the default proof system for everything above. Circuits use Poseidon with
explicit BLS12-381 parameters. For the concepts behind these patterns, read
[Circuits, constraints & witnesses](https://zeroj.dev/learn/circuits-and-witnesses/) and
[ZK on Cardano](https://zeroj.dev/learn/zk-on-cardano/).

> **Note: A proof is not a permission slip**
>
> A valid proof only shows that the math checks out. Every validator in these use cases also has to
> bind the proof to its `ScriptContext` (who gets paid, which UTxO is spent), prevent replay and
> enforce its own business rules. [Application security](https://zeroj.dev/guides/verifying/application-security/)
> covers this in depth.

## Run the demos

The [zeroj-usecases](https://github.com/bloxbean/zeroj-usecases) repository has complete Spring Boot
apps for most pages here. Each one covers the circuit, proof generation, a Cardano transaction and
on-chain verification, with a small web UI.

You need Docker (with Compose v2) and a Yaci DevKit devnet running on your machine:

```bash
# 1. Start a local Cardano devnet (outside the demos repo)
devkit start
# then, at the yaci-cli prompt:
#   create-node -o --start

# 2. Run a demo end to end
git clone https://github.com/bloxbean/zeroj-usecases
cd zeroj-usecases
./demo.sh proof-of-reserves --run

# 3. Stop it (Yaci keeps running)
./demo.sh proof-of-reserves --stop
```

`demo.sh` tops up a devnet-only demo wallet, starts the app, opens its UI and, with `--run`, runs
the happy path. The demo names are `proof-of-reserves`, `identity-kyc`, `nft-ownership`, `voting`,
`airdrop`, `dpp`, `selective-disclosure` and `reusable-kyc`. The account-ownership demo ships
separately as a desktop app and CLI; see [its page](https://zeroj.dev/use-cases/account-recovery/#try-it).

The demos use a single-party development trusted setup (they run with
`-Dzeroj.allowInsecureTrustedSetup=true`, and cached setup files are generated the same way). Real
deployments need keys from a multi-party ceremony; see
[Trusted setup, explained](https://zeroj.dev/learn/trusted-setup/).

## Ideas to explore

These ideas are **not implemented as demos**. They show how the same building blocks carry over to
new problems.

- **Private credit score for lending.** A borrower proves "score ≥ 700" from a credit bureau's
  signed credential. That needs an in-circuit issuer signature (`ZkEdDSAJubjub`), a `ZkUInt.gte`
  range check and a public input bound to the loan UTxO. BBS is an option if revealing a score band
  is acceptable.
- **Sealed-bid auctions.** Bidders publish `Poseidon(bid, salt)` during bidding, then prove their
  bid clears the reserve price without revealing it. ZeroJ's integration tests include sealed-bid
  example circuits: an annotation-style
  [`AnnotatedSealedBid`](https://github.com/bloxbean/zeroj/blob/main/zeroj-integration-tests/src/test/java/org/zeroj/examples/annotation/AnnotatedSealedBid.java)
  and a DSL version with a Yaci DevKit on-chain test. That's a starting point, not a full auction
  protocol.
- **Anonymous feedback and whistleblowing.** An employee proves membership in a Merkle tree of staff
  keys and publishes one nullifier per topic. The report's hash is bound as a public input, so
  every report is from a real member and nobody can flood a topic. The shape is the
  [private voting](https://zeroj.dev/use-cases/private-voting/) circuit.
- **Payroll or treasury solvency.** A DAO proves that a batch of private salaries or grants sums to
  no more than the treasury balance, and that each payment falls within an approved band. That uses
  `ZkUInt` sums and comparisons plus a Poseidon commitment to the batch, as in
  [proof of reserves](https://zeroj.dev/use-cases/proof-of-reserves/).

## Next steps

- New to ZK? Start with [Zero-knowledge in plain English](https://zeroj.dev/learn/zero-knowledge-basics/).
- Build the core patterns yourself: [Prove you're over 18](https://zeroj.dev/tutorials/age-check/) and
  [Private allowlist with a Merkle tree](https://zeroj.dev/tutorials/private-allowlist/).
- Take a proof on-chain: [Verify your proof on Cardano](https://zeroj.dev/tutorials/verify-on-cardano/).
