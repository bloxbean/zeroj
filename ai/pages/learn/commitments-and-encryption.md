# Commitments & encryption, explained

> Sealed envelopes, lockboxes and shared keys: what Pedersen commitments, ElGamal encryption, confidential notes and threshold decryption do, in plain English.

Canonical URL: https://zeroj.dev/learn/commitments-and-encryption/

A zero-knowledge proof answers a question about secret data. Often that's all you need: "is this
person over 18?" But many applications also have to **keep a secret value on a public ledger**: a
balance, a salary, a bid, a vote. Somebody needs to check it now, somebody else may need to read it
later, and everyone else should see nothing.

Four tools cover almost every case. This page explains each one with an everyday picture, and
[Choose how to disclose](https://zeroj.dev/selective-disclosure/) helps you pick between them.

| Tool | Everyday picture | What it gives you |
|---|---|---|
| **Commitment** | A sealed envelope | Publish a value without revealing it; prove facts about it; open it later |
| **Encryption to a key** | A lockbox with a slot | Anyone can put a value in; only the key holder can read it |
| **Encrypted delivery** | A letter to named readers | Hand the opening of a commitment to the owner and an auditor, on-chain |
| **Shared key (threshold)** | A safe that needs two of three keys | Nobody alone can decrypt; a quorum can |

## Commitments: a sealed envelope

A **commitment** lets you fix a value now and reveal it later, or never. ZeroJ uses **Pedersen
commitments**. To commit to a value `v`, you pick a large random number `r`, the **blinding**, and
publish one point on an elliptic curve:

```text
C = v·G + r·H
```

`G` and `H` are two fixed public points. You don't need to follow the math to use it; three
properties matter:

- **Hiding.** Because `r` is random, `C` reveals nothing about `v`. Two commitments to the same
  amount look unrelated.
- **Binding.** Once you publish `C`, you can't later claim it held a different value. Finding a
  second opening is as hard as breaking the curve.
- **Adding.** Commitments add up: `C(a, r) + C(b, s) = C(a + b, r + s)`. A ledger can total
  balances, or check that inputs equal outputs, without seeing any single amount.

Step through it. Drag the amount, roll a new blinding, and try opening the envelope to a different
number.

_The web version of this page has an interactive illustration here._

```text
 Alice                          Public ledger                     Verifier
  v = 4,200 (secret)              C = v·G + r·H                    sees only C
  r = random (secret)  ─── C ──▶  (32 bytes)
                                                                   later, given (v, r):
                       ─── (v, r) ───────────────────────────────▶ recompute C, compare
                                  C + D = commitment to the total
  proves "v ≥ 1,000"   ─── π ───────────────────────────────────▶ checks π against C
```

A commitment on its own only lets you open or not open. Its real power comes with a
zero-knowledge proof over the hidden value: "the amount in `C` is at least 1,000", "these three
commitments add up to that one", "this commitment holds a 0 or a 1". The proof reveals nothing
else, and `C` stays sealed.

> **Caution: Sums wrap around**
>
> Commitment arithmetic wraps around at a huge number, about 2²⁵². A cheat could hide a "negative"
> amount that looks like an enormous positive one, so a sum of commitments proves nothing about
> real totals until every value is proven to be in range. ZeroJ's circuit gadgets check ranges and
> refuse layouts that could wrap. See [Pedersen commitments](https://zeroj.dev/guides/confidential/pedersen/#2-add-commitments).

## Encryption to a key: a lockbox with a slot

A commitment can only be opened by someone who knows the opening. Sometimes a third party must be
able to read the value **without the owner's cooperation**: a tax authority reading salaries, an
auctioneer reading bids, election trustees counting votes. For that you encrypt the value to their
public key.

ZeroJ uses **exponential ElGamal** on the same curve. A ciphertext is two points, and it has two
useful properties:

- **Fresh randomness every time**, so the same value encrypted twice gives unrelated ciphertexts.
- **Adding.** Ciphertexts add up like commitments, so a ledger can keep an encrypted running total.

The catch: decrypting ends with a lookup, so it only works for **small numbers**, such as votes or
amounts split into 32-bit pieces (called **limbs**). Decrypting a 64-bit amount directly would
take too long.

_The web version of this page has an interactive illustration here._

```text
 Senders                    Public ledger                      Auditor (holds sk)
  Alice: 4,200 ── Enc ──▶   PK, Enc(4,200)
  Bob:   2,500 ── Enc ──▶   Enc(2,500)
                            Enc(4,200) + Enc(2,500) = Enc(6,700) ──▶ decrypts 6,700

 Split key: trustees T1, T2, T3 each hold a share; any 2 of 3 together decrypt, 1 alone can't.
```

Encryption and commitments work well together. A proof can show "this ciphertext encrypts the same
amount as this commitment", so the auditor's copy can't be faked. That's how the
[sealed-bid auction](https://zeroj.dev/use-cases/sealed-bid-auction/) forces every bid to be readable by the
auctioneer, and how [confidential payroll](https://zeroj.dev/use-cases/confidential-payroll/) stops an employer
from under-reporting a salary.

## Encrypted delivery: a letter to named readers

Suppose a payment is a commitment on-chain. Its owner needs the opening, `(v, r)`, to spend it
later, and an auditor may need it too. You could send it privately, but then a lost message means
lost money. A **confidential note** puts the opening on-chain, encrypted separately to each reader.

- Each reader has a **viewing key**. The sender seals the opening for each reader with a fresh
  one-time key, the way Zcash notes are encrypted.
- A reader scans the chain, opens the deliveries addressed to them, and **accepts a note only if
  the opening recomputes the commitment**. A garbage delivery can't trick them; it shows up as
  "unopenable".
- Everyone else sees the commitment and a few bytes of ciphertext per reader (89 bytes each).

Delivery is about *convenience and recovery*: a lost wallet can rebuild its balance from the
chain. On its own it doesn't *force* the sender to tell the auditor the truth; pair it with an
encrypted amount and a proof when that matters. See [Confidential notes](https://zeroj.dev/guides/confidential/confidential-notes/).

## Shared keys: no single reader

A single auditor or trustee is a single point of failure: they could read everything, or lose the
key. **Threshold decryption** splits the secret key among `n` trustees so that any `t + 1` of
them can decrypt together, and `t` or fewer learn nothing.

The trustees create the key together with a **distributed key generation** (DKG): each one deals
shares to the others, and the full secret key never exists anywhere. ZeroJ implements a
well-studied DKG (Gennaro, Jarecki, Krawczyk and Rabin) and delivers the private shares over a
public board with HPKE (RFC 9180) encryption. A typical policy is: decrypt only the final total,
never a single ballot. See [Threshold decryption](https://zeroj.dev/guides/confidential/threshold-elgamal/).

## Putting them together

Real applications combine the tools:

| Use case | Commitment | Encryption | Delivery | Threshold |
|---|---|---|---|---|
| [Private voting with an encrypted tally](https://zeroj.dev/use-cases/private-voting/) | | ✓ votes to the election key | | Shared key: the demo needs all 3 trustees (n-of-n); a t-of-n DKG is available |
| [Confidential loyalty points](https://zeroj.dev/use-cases/confidential-points/) | ✓ balances | ✓ amounts to an auditor | ✓ to owner and auditor | |
| [Confidential payroll](https://zeroj.dev/use-cases/confidential-payroll/) | ✓ salaries | ✓ to the tax authority, proven | ✓ to employee and tax authority | |
| [Sealed-bid auction](https://zeroj.dev/use-cases/sealed-bid-auction/) | | ✓ bids to the auctioneer, proven | | |
| [Proof of solvency with hidden balances](https://zeroj.dev/use-cases/private-solvency/) | ✓ customer balances | | ✓ to each customer and the auditor | |

## What these tools don't do

- **They don't authorize anything.** A valid opening or proof says nothing about who may spend a
  UTxO. Validators still check signatures, replay and the transaction itself. See
  [Application security](https://zeroj.dev/guides/verifying/application-security/).
- **They don't hide the transaction graph.** Who pays whom, and when, is still visible on Cardano
  unless the application hides it separately.
- **Key holders are trusted with what they can read.** An auditor who can decrypt can also leak.
  Threshold keys reduce that risk; they don't remove it.

## Next steps

- [Choose how to disclose](https://zeroj.dev/selective-disclosure/): BBS, predicates, commitments, deliveries and
  threshold keys compared, with code
- Guides: [Pedersen commitments](https://zeroj.dev/guides/confidential/pedersen/),
  [ElGamal encryption](https://zeroj.dev/guides/confidential/elgamal/),
  [Confidential notes](https://zeroj.dev/guides/confidential/confidential-notes/),
  [Threshold decryption](https://zeroj.dev/guides/confidential/threshold-elgamal/)
- [Glossary](https://zeroj.dev/learn/glossary/)
