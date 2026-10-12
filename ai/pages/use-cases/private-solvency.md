# Proof of solvency with hidden balances

> An exchange proves its locked reserves cover every customer balance while hiding each balance and even the total. Customers and an auditor check their part from on-chain data.

Canonical URL: https://zeroj.dev/use-cases/private-solvency/

The [proof of reserves](https://zeroj.dev/use-cases/proof-of-reserves/) page hides every customer balance but
publishes the total liabilities. Sometimes the total is sensitive too: it tells competitors how big
the exchange is and how fast it's growing. And a Merkle inclusion path shows a customer hashes of
their neighbours' leaves.

This variant hides the total as well. Each customer balance becomes a **Pedersen commitment**, a
sealed number that can still be added up. The exchange proves the hidden balances fit under a
reserve it locks on-chain. Each customer opens their own entry from the chain, and an auditor opens
only the total. It follows the Provisions approach (Dagher et al., CCS 2015).

_The web version of this page has an interactive illustration here._

## The zero-knowledge idea

**The exchange proves "these committed balances are each between 0 and 2⁶⁴, and together they add
up to at most the reserve locked in this vault", without revealing any balance or the total.**

Two properties of Pedersen commitments make this work. (See
[Commitments & encryption](https://zeroj.dev/learn/commitments-and-encryption/) for an interactive introduction.)

- **Hiding and binding.** A commitment `C = v·G + r·H` with a random 252-bit blinding `r` reveals
  nothing about the balance `v`, and the exchange can't later claim it holds a different number.
  The proof opens every commitment inside the circuit, so it sums exactly the published balances.
- **Adding up.** Commitments add: `C₁ + C₂ + C₃ + C₄` is the commitment to the total, with the sum
  of the blindings. Anyone can compute that point from the chain. Only someone given its opening
  can read the total, and the exchange gives that opening to one auditor.

Each customer gets their own opening the same way, as a small encrypted **delivery** next to their
entry in the datum. They read it with their viewing key, so what they check comes from the chain,
not from the exchange's say-so. See
[Share a value with chosen readers](https://zeroj.dev/selective-disclosure/share-with-chosen-readers/).

## What stays private, what's public

| Value | Exchange | Customer | Auditor | Public |
|---|---|---|---|---|
| Each balance `v_i` | Knows | Only their own, from their delivery | No | No |
| Total liabilities `L` | Knows | No | Opens it from its delivery | No |
| Blindings `r_i` | Knows | Their own | Only the sum | No |
| Customer identity | Knows | Their own salted `idHash` | No | Only salted hashes |
| Commitments `C_i`, reserve `R`, customer count `N` | Public | Public | Public | Public |

## How it works

1. **The book.** At the start of a period the exchange has its customer balances. In the demo,
   Alice 500, Bob 1,200, Carol 300 and Dave 0 ADA. Each customer receives a fresh 32-byte salt for
   the period with their account statement.
2. **Commit and deliver.** For each customer the exchange builds an entry: a salted id hash
   `blake2b_256(I2OSP2(len(id)) ‖ id ‖ salt)` (the length as two big-endian bytes), the commitment `C_i` to the balance, and the opening
   `(v_i, r_i)` encrypted to the customer's viewing key (89 bytes). It also encrypts the opening of
   the sum, `(L, Σr_i mod l)`, to the auditor's registered viewing key. Every attestation draws a
   new salt and a new blinding for every customer and shuffles the entries into a fresh random
   order, which the proof and the deliveries follow too.
3. **Prove and lock.** The exchange proves `Σ v_i ≤ R` with Groth16. It then locks `R` lovelace in
   the period's vault with the entries as the inline datum, **before the period starts**. The vault
   verifies the proof against the datum's commitments and the locked amount.
4. **Customers check.** During the period, each customer derives the period's vault script
   themselves, reads every live attestation, and looks for their `idHash`. Then they open their
   delivery with their own key and compare the result with their statement.
5. **The auditor opens the total.** The auditor adds the on-chain commitments and opens the sum
   with its own delivery. It learns `L` and checks it against `R`, without learning any single
   balance.
6. **Release.** Once the period is over, the exchange spends the vault and burns the attestation
   token. Nothing can be added or released while the period runs, so every attestation in the
   period is locked at the same time and the same reserve can't back two of them in turn.

## The circuit

This is the demo's `HiddenLiabilitySolvencyProof`, with the constructor check trimmed. It opens
each commitment in the circuit and sums the hidden balances. The public inputs are
`[R, u₁…u_N, v₁…v_N]`: the reserve and the coordinates of each commitment, read from the datum.

```java title="HiddenLiabilitySolvencyProof.java"
import org.zeroj.circuit.annotation.*;
import org.zeroj.circuit.lib.zk.ZkPedersenCommitment;

@ZKCircuit(name = "hidden-liability-solvency",
           nameTemplate = "hidden-liability-solvency-n{customers}", version = 1)
public class HiddenLiabilitySolvencyProof {
    private final int customers;

    public HiddenLiabilitySolvencyProof(@CircuitParam("customers") int customers) {
        this.customers = customers;   // the demo allows 1 to 16
    }

    @Prove
    void prove(ZkContext zk,
               @Public @UInt(bits = 64) ZkUInt reserves,
               @Public @FixedSize(param = "customers") ZkArray<ZkField> liabilityU,
               @Public @FixedSize(param = "customers") ZkArray<ZkField> liabilityV,
               @Secret @UInt(bits = 64) @FixedSize(param = "customers") ZkArray<ZkUInt> balances,
               @Secret @UInt(bits = 252) @FixedSize(param = "customers") ZkArray<ZkUInt> blindings) {
        ZkUInt total = null;
        for (int i = 0; i < customers; i++) {
            // C_i opens to (balance_i, blinding_i)
            ZkPedersenCommitment.commit(zk, balances.get(i), blindings.get(i))
                    .assertAffineEquals(zk, liabilityU.get(i), liabilityV.get(i));
            total = total == null ? balances.get(i) : total.add(balances.get(i));
        }
        total.lte(reserves).assertTrue();   // Σ balances ≤ R
    }
}
```

- `@UInt(bits = 64)` on the balances rules out a negative "balance" that would quietly shrink the
  total. With at most 16 balances below 2⁶⁴, the sum can't wrap around the field.
- The blinding is a 252-bit secret, as ZeroJ requires for a hiding commitment. See the
  [Pedersen guide](https://zeroj.dev/guides/confidential/pedersen/).
- With four customers the circuit has 10,042 constraints.

## Customers and the auditor check

Both checks use only chain data and the reader's own viewing key. They run with ZeroJ's
confidential-note API, `NoteScanner`. The result of a customer's check is one of five outcomes:

| Result | Meaning |
|---|---|
| `LISTED_ONCE_CORRECT` | Their `idHash` appears exactly once, and the delivery opens to their balance |
| `MISSING` | No entry with their `idHash`: they were left out |
| `LISTED_TWICE` | Their `idHash` appears more than once in the period |
| `UNOPENABLE` | The entry is there, but its delivery doesn't open with their key |
| `WRONG_BALANCE` | The delivery opens, but to a different balance |

Anything other than `LISTED_ONCE_CORRECT` is evidence against the exchange. In particular the vault
can only check that a delivery is 89 bytes long, not that it decrypts. An exchange can attest with a
garbage delivery, but the customer it targets finds out.

These snippets are simplified from the demo's `SolvencyAttestation`. The commitments and deliveries
come from the attestation datum.

```java title="SolvencyChecks.java"
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteScanner;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

public final class SolvencyChecks {

    // Customer: open my own entry's delivery against its commitment.
    static Optional<BigInteger> myBalance(JubjubPoint commitment, byte[] delivery, NoteViewingKey me) {
        JubjubPoint c = commitment.normalized();
        return NoteScanner.of(me).open(delivery, c.affineU(), c.affineV()).map(NoteOpening::value);
    }

    // Auditor: add up every commitment, then open the sum with the auditor's delivery.
    static Optional<BigInteger> totalLiabilities(List<JubjubPoint> commitments, byte[] auditorDelivery,
                                                 NoteViewingKey auditor) {
        JubjubPoint sum = JubjubPoint.IDENTITY;
        for (JubjubPoint c : commitments) sum = sum.add(c);
        JubjubPoint s = sum.normalized();
        return NoteScanner.of(auditor).open(auditorDelivery, s.affineU(), s.affineV()).map(NoteOpening::value);
    }
}
```

`open` returns empty when the delivery doesn't open, or when the decrypted opening doesn't
recompute the commitment. The exchange side builds each delivery with `ConfidentialNotes.seal`.
See the [confidential notes guide](https://zeroj.dev/guides/confidential/confidential-notes/).

## On Cardano

The demo's `SolvencyVault` is a JuLC multi-validator. One script is both the attestation minting
policy and the vault address. Its parameters fix the exchange's key hash, the number of entries,
the period `[periodStart, periodEnd]` and the verification key, so each period has its own vault
script.

- **Attest (mint).** The validity range must end at or before `periodStart`, and the exchange must
  sign. Exactly one attestation token goes to one output at the vault's exact address, holding
  only lovelace plus the token. The vault checks the datum
  `Attestation([Entry(idHash, u, v, delivery)] × N, auditorDelivery)`: 32-byte id hashes, canonical
  coordinates and 89-byte deliveries. It then builds the public inputs from the locked lovelace and
  the datum's coordinates and runs `Groth16BLS12381Lib.verify`.
- **Release (spend and burn).** The validity range must start at or after `periodEnd`, the exchange
  signs, and the attestation token is burned.

The demo measured the attest transaction with four customers at about 4.41 billion CPU steps and
1.25 million memory units in the JuLC VM. That was before two later cost reductions: the demo's
datum-access optimization (zeroj-usecases commit `814b2f0`) and ZeroJ's cheaper on-chain Groth16
verifier (ZeroJ PRs #85 and #86). Each extra customer adds two public inputs, and the demo's own
estimate puts the per-transaction limit at about 19 customers per attestation. A larger book needs
batching.

Like every validator, this one checks a proof against the data it can see. It doesn't know where
the reserves came from or that every customer was included. Those gaps are listed below. See
[Application security](https://zeroj.dev/guides/verifying/application-security/).

## Security considerations

- **Borrowed reserves.** The vault proves the funds are locked for the period, not that the
  exchange owns them. It could borrow them for exactly that window.
- **Who ran the setup matters.** If the exchange ran the Groth16 setup itself, it could forge a
  proof. The verification key must come from a ceremony the exchange can't subvert. The demo uses
  a single-party development setup ([Trusted setup, explained](https://zeroj.dev/learn/trusted-setup/)).
- **Omissions are caught only by customers who check.** Leaving someone out, or understating them,
  is detected only if that customer runs their check. Make the check easy and automatic in the
  wallet.
- **The customer count is public.** Pad with commitments to 0, which look like any other
  commitment, to hide the real `N`.
- **The auditor learns one subtotal per attestation.** If a period were split into several
  attestations, the auditor would learn each one's total, and an attestation holding one real
  customer plus zero-padding would reveal that customer's balance. The demo makes exactly one
  attestation per period.
- **Fresh per attestation.** Reusing a salt, a blinding or an entry's position would link a
  customer's entries across periods. An earlier version of the demo reused every salt and blinding
  when it re-attested, and kept entries in book order. Now each attestation draws fresh salts and
  blindings and shuffles the entries with `SecureRandom`, so two attestations of the same book
  share no id hash, no commitment and no position. A customer finds their entry by this period's
  salted id hash, never by position.
- **Outside the period the attestation proves nothing.** It covers `[periodStart, periodEnd]`
  only.
- **The exchange's key.** The exchange's signature makes an attestation the exchange's, so the
  demo generates its wallet key randomly and keeps it, owner-only, in the data directory next to its
  deployment state. If that state exists but the key is missing or doesn't match, the demo stops
  instead of creating a new key.
- **Demo custody and operator view.** The demo server holds every wallet's keys and scans the chain
  on everyone's behalf, and its API is unauthenticated. `GET /api/solvency` is the public view (the
  period, the vault and its on-chain entries, with no customer ids or balances). `GET
  /api/solvency/operator` is the exchange's private book, shown in the UI's "Private" panel. That
  is the demo operator's view: privacy here holds against chain and mempool observers, not against
  the demo server. Real customers scan in their own wallet. The off-circuit
  commitment and sealing code is for offline, isolated use; see the guides for the exact rules.
- **Maturity.** ZeroJ's Pedersen and confidential-note APIs are experimental and haven't been
  externally audited. Treat this as a blueprint, not a production system.

## Try it

The demo is tab "C. Hidden-liability solvency" in the [`pedersen-commitments`](https://github.com/bloxbean/zeroj-usecases/tree/main/pedersen-commitments) app in zeroj-usecases. With Yaci
DevKit running (see [Run the demos](https://zeroj.dev/use-cases/overview/#run-the-demos)):

```bash
./demo.sh pedersen
# opens http://localhost:8093; pick the solvency tab
```

To run it without Docker, use Java 25 and `./gradlew -p pedersen-commitments bootRun -PwithFrontend`
from the repository root.

The first start compiles the circuits and runs development setups, which takes a few minutes. In the
tab you can edit the book, attest with locked reserves for a period that starts about 45 seconds
later and lasts 180 seconds, run each customer's check, and let the auditor open the total. Try to
cheat: lock less than the book (no proof exists), give one customer a garbage delivery (their check
reports `UNOPENABLE`), or attest again or release inside the period (the vault rejects it).

Design notes: ADR-0006 (demo C) and ADR-0007 (on-chain deliveries) in the zeroj-usecases
[`docs/adr`](https://github.com/bloxbean/zeroj-usecases/tree/main/docs/adr) directory.

## Related

- [Proof of reserves](https://zeroj.dev/use-cases/proof-of-reserves/): the Merkle-tree version, with a public total
- [Commitments & encryption](https://zeroj.dev/learn/commitments-and-encryption/): Pedersen commitments, explained
- [Hide a number, prove facts about it](https://zeroj.dev/selective-disclosure/hide-a-number/)
- [Share a value with chosen readers](https://zeroj.dev/selective-disclosure/share-with-chosen-readers/)
- [Pedersen commitments guide](https://zeroj.dev/guides/confidential/pedersen/)
- [Confidential notes guide](https://zeroj.dev/guides/confidential/confidential-notes/)
