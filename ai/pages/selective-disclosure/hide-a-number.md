# Hide a number (Pedersen commitments)

> Publish a number as a sealed commitment, prove facts about it, add commitments together and open them later, so balances, bids and totals stay private on a public ledger.

Canonical URL: https://zeroj.dev/selective-disclosure/hide-a-number/

**Use this when a number has to live on a public ledger but stay private**: a balance, a salary, a
customer's deposit. People can still check facts about it ("at least 1,000", "inputs equal outputs")
and add many of them up, without ever seeing one.

A **Pedersen commitment** is a sealed envelope: a 32-byte curve point made from the value and a
random **blinding**. It hides the value completely, it can't be reopened as a different value, and
commitments add up. A Groth16 proof can show facts about the hidden value.

_The web version of this page has an interactive illustration here._

## Who learns what

| Party | Learns |
|---|---|
| The committer | The value and its blinding (the **opening**) |
| A verifier given a proof | Only the proven fact, such as "at least 1,000" |
| Someone given the opening | The value; they can check it matches the commitment |
| Everyone else | A 32-byte commitment that reveals nothing |

## In code

Commit, publish 32 bytes, and open later:

```java title="CommitAndOpen.java (core)"
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;

// Committer (offline): a fresh random blinding for every commitment
BigInteger value = BigInteger.valueOf(1_000);
BigInteger blinding = PedersenCommitment.randomBlinding(new SecureRandom());
byte[] published = PedersenCommitment.commit(value, blinding).toBytes();       // 32 bytes

// Verifier, later, given the opening (value, blinding). verify is variable-time: run it where the
// opening is already public or nobody it is still secret from can time you.
JubjubPoint received = PedersenCommitment.decode(published);                    // checks the point
boolean opens = PedersenCommitment.verify(received, value, blinding);           // true
boolean lies = PedersenCommitment.verify(received, BigInteger.valueOf(1_001), blinding);  // false
```

Prove a fact without opening. This circuit proves "the committed value is at least the threshold":

```java title="CommittedThreshold.java"
import org.zeroj.circuit.annotation.*;
import org.zeroj.circuit.lib.zk.ZkPedersen;

@ZKCircuit(name = "committed-threshold", version = 1)
public class CommittedThreshold {
    @Prove
    ZkBool prove(ZkContext zk,
                 @Public ZkField commitmentU,                 // the commitment, as affine (u, v)
                 @Public ZkField commitmentV,
                 @Public @UInt(bits = 64) ZkUInt threshold,
                 @Secret @UInt(bits = 64) ZkUInt value,       // never revealed
                 @Secret @UInt(bits = 252) ZkUInt blinding) { // must be exactly 252 bits
        ZkPedersen.commit(zk, value, blinding).assertAffineEquals(zk, commitmentU, commitmentV);
        return value.gte(threshold);
    }
}
```

The [Pedersen guide](https://zeroj.dev/guides/confidential/pedersen/) has both as complete, runnable programs, plus
adding commitments and proving that amounts balance.

## Real-world uses

- **Proof of solvency.** An exchange commits to every customer balance, proves the hidden total is
  covered by locked reserves, and each customer checks their own entry.
  ([use case](https://zeroj.dev/use-cases/private-solvency/))
- **Confidential balances and transfers.** Loyalty points or tokens move between holders, and a
  proof shows inputs equal outputs, with no amounts on the ledger.
  ([use case](https://zeroj.dev/use-cases/confidential-points/))
- **Commit now, reveal later.** Lock in a prediction, a price quote or a design hash today; open it
  after the deadline, and nobody can claim you changed it.
- **Committed credentials.** A bureau commits to a credit profile; the holder proves "income ≥
  50,000" from it. ([Prove a rule](https://zeroj.dev/selective-disclosure/prove-a-rule/#over-a-committed-credential))
- **Product passports.** An auditor commits to each measurement; the manufacturer proves "carbon ≤
  50 kg" without revealing it. ([use case](https://zeroj.dev/use-cases/digital-product-passport/))

## When not to use it

- **Someone else has to read the value without the owner's help.** A commitment opens only with
  the opening. Add [chosen readers](https://zeroj.dev/selective-disclosure/share-with-chosen-readers/) or
  [encrypt for an auditor](https://zeroj.dev/selective-disclosure/encrypt-for-an-auditor/).
- **The value is a one-off answer.** If nothing is stored on-chain, a plain
  [predicate](https://zeroj.dev/selective-disclosure/prove-a-rule/) is simpler.

## Watch out for

- **Sums wrap around.** Commitment arithmetic is modulo a 252-bit number, so an unchecked sum can
  hide a "negative" amount. Prove every value's range, and use `ZkPedersen.assertBalanced`, which
  refuses layouts that could wrap.
- **The blinding must be fresh, random and 252 bits.** ZeroJ refuses circuits whose blinding is
  narrower, public or constant, but it can't check that yours is random.
- **Create commitments offline.** `commit` and `randomBlinding` run variable-time arithmetic on
  secrets; keep them on the user's device or in an isolated process.
- **Decode received commitments with `PedersenCommitment.decode`**, which checks the point is in
  the right subgroup.
- **Maturity.** In-circuit commitments are *ready, pending external review*; sums and vector
  commitments are *experimental*.

## Next steps

- [Pedersen commitments guide](https://zeroj.dev/guides/confidential/pedersen/)
- [Tell chosen readers](https://zeroj.dev/selective-disclosure/share-with-chosen-readers/): deliver the opening
  on-chain
- [Choose how to disclose](https://zeroj.dev/selective-disclosure/)
