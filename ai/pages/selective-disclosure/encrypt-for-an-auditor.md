# Encrypt for an auditor (ElGamal + proof)

> Encrypt a value to an auditor's key and prove the ciphertext matches the hidden amount, so the auditor can always read the real value and the sender can't under-report.

Canonical URL: https://zeroj.dev/selective-disclosure/encrypt-for-an-auditor/

**Use this when an authority must be able to read a value, and the sender must not be able to lie
about it**: a tax authority reading salaries, an auctioneer reading bids, a regulator reading
transfer amounts.

The sender encrypts the value to the auditor's public key with **exponential ElGamal**, and a
Groth16 proof shows the ciphertext holds the same value as the public commitment (or satisfies a
rule, such as "a bid between the reserve and the deposit"). A validator checks the proof, so a
transaction with a fake auditor copy never lands on-chain.

_The web version of this page has an interactive illustration here._

## Who learns what

| Party | Learns |
|---|---|
| Sender | The value |
| Auditor | The value, by decrypting; guaranteed to match the commitment |
| Everyone else | A 64-byte ciphertext and a proof; never the value |

## In code

The circuit ties one secret amount to both the public commitment and the public ciphertext:

```java title="AuditedAmount.java"
import org.zeroj.circuit.annotation.*;
import org.zeroj.circuit.lib.zk.ZkElGamal;
import org.zeroj.circuit.lib.zk.ZkElGamalPublicKey;
import org.zeroj.circuit.lib.zk.ZkPedersenCommitment;

/** "The ciphertext encrypts, under the auditor's key, the amount the commitment hides." */
@ZKCircuit(name = "audited-amount", version = 1)
public class AuditedAmount {
    @Prove
    void prove(ZkContext zk,
               @Public ZkField commitU, @Public ZkField commitV,
               @Public ZkField auditorU, @Public ZkField auditorV,
               @Public ZkField handleU, @Public ZkField handleV,
               @Public ZkField blindedU, @Public ZkField blindedV,
               @Secret @UInt(bits = 32) ZkUInt amount,
               @Secret @UInt(bits = 252) ZkUInt blinding,
               @Secret @UInt(bits = 252) ZkUInt randomness) {
        ZkPedersenCommitment.commit(zk, amount, blinding).assertAffineEquals(zk, commitU, commitV);
        var auditor = ZkElGamalPublicKey.fromVerifierFixedPublic(zk, auditorU, auditorV);
        ZkElGamal.encrypt(zk, amount, randomness, auditor)
                .assertAffineEquals(zk, handleU, handleV, blindedU, blindedV);
    }
}
```

On the host, the sender encrypts with `ElGamal.encryptWithOpening`, and the auditor admits the
ciphertext only after checking that exact proof, then decrypts:

```java title="AuditorSide.java (core)"
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;

// Sender: encrypt the same 250 to the auditor's key (its key context, built from a verified key),
// declaring a 32-bit message width
ElGamalEncryption enc = ElGamal.encryptWithOpening(auditor, BigInteger.valueOf(250), 32, random);

// Auditor: bytes from the chain re-enter the safe API only with a verified proof
RawElGamalCiphertext raw = RawElGamalCiphertext.decode(enc.ciphertext().encode());
ElGamalCiphertext admitted = ElGamal.admit(raw, auditor, 32,
        statement -> statement.width() == 32 && proofVerifies(commitment, statement.publicInputs()));
long amount = ElGamal.decryptWithSecret(admitted, auditorSecret, (1L << 32) - 1);   // 250
```

If the sender encrypts 1 instead of 250, no proof can be made. The full program, which shows that
refusal, is in the [ElGamal guide](https://zeroj.dev/guides/confidential/elgamal/).

## Real-world uses

- **Confidential payroll.** The tax authority reads every salary from the chain, and the employer
  can't under-report one. ([use case](https://zeroj.dev/use-cases/confidential-payroll/))
- **Sealed-bid auctions.** Each bid is encrypted to the auctioneer with a proof that it's between
  the reserve and the deposit, so no bidder can back out by refusing to reveal.
  ([use case](https://zeroj.dev/use-cases/sealed-bid-auction/))
- **Audited transfers.** Every confidential transfer carries the amount for a regulator, enforced
  by the transfer proof. ([use case](https://zeroj.dev/use-cases/confidential-points/))

## When not to use it

- **No single party should read individual values.** Use [split trust](https://zeroj.dev/selective-disclosure/split-trust/).
- **The value is a large number.** Decryption ends in a search that only works for small values
  (up to about 2⁴³). Split amounts into 32-bit pieces (limbs) and encrypt each one, as the payroll
  and points demos do.

## Watch out for

- **Verify the auditor's key.** Encrypt only to a key that came with a proof its owner knows the
  secret (`VerifiedKeyShare.verify`), or a rogue key could lock the auditor out.
- **Never admit ciphertexts with `s -> true`** unless the ledger already verified that exact
  statement. The verifier lambda is what makes the guarantee.
- **The auditor can leak.** Anyone who can decrypt can also share. Rotate keys, and consider a
  threshold key for high-value data.
- **Maturity.** Experimental. Secret operations are offline/isolated only.

## Next steps

- [ElGamal encryption guide](https://zeroj.dev/guides/confidential/elgamal/)
- [Split the trust](https://zeroj.dev/selective-disclosure/split-trust/)
- [Choose how to disclose](https://zeroj.dev/selective-disclosure/)
