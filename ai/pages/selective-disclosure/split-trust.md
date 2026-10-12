# Split the trust (threshold decryption)

> Encrypt values to a key that no single party holds, so only a quorum of trustees can decrypt, and agree to decrypt only the result, such as an election tally.

Canonical URL: https://zeroj.dev/selective-disclosure/split-trust/

**Use this when nobody should be able to see individual values on their own**, but a group must be
able to reveal an agreed result: an election tally, a total of private bids, an aggregate statistic.

Trustees run a **distributed key generation** (DKG) together. It produces one public key, and each
trustee keeps a share of the secret key; the full secret key never exists anywhere. Values are
encrypted to the public key and added up while still encrypted. At the end, any `t + 1` of the `n`
trustees publish decryption shares of the **total**, each with a proof it was computed honestly,
and the total comes out. Fewer than `t + 1` learn nothing.

_The web version of this page has an interactive illustration here._

Step 5 of the illustration is this page's idea: pick trustees and see when the total decrypts.

## Who learns what

| Party | Learns |
|---|---|
| Each sender | Their own value |
| Any single trustee | Nothing beyond the public data |
| `t + 1` trustees together | Whatever they agree to decrypt; the policy is to decrypt only the total |
| Everyone else | Ciphertexts, then the total once decrypted |

## In code

A 2-of-3 setup (`t = 1`, `n = 3`) with an in-process key generation and a five-vote tally:

```java title="ThresholdTally.java (core)"
import org.zeroj.circuit.lib.jubjub.DkgConfig;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ThresholdKeyContext;
import org.zeroj.circuit.lib.jubjub.VerifiedDecryptionShare;

// Agreed by everyone, e.g. in an election manifest: tolerate t = 1 fault, so any 2 of 3 decrypt
DkgConfig config = DkgConfig.create(1, 3, roster, "demo-election-2026".getBytes(UTF_8), 1);
// ... the trustees run the 7-round key generation (see the guide) and each keeps its share ...
ThresholdKeyContext election = shares.get(0).context();

// Voters encrypt 0 or 1 (width 1); anyone adds the ciphertexts
List<ElGamalCiphertext> ballots = new ArrayList<>();
for (int vote : new int[] {1, 0, 1, 1, 0}) ballots.add(ElGamal.encrypt(election, vote, 1, random));
ElGamalCiphertext total = ElGamalCiphertext.sum(ballots);

// After the deadline, trustees 1 and 3 publish decryption shares of the total only
List<VerifiedDecryptionShare> published = List.of(
        ElGamal.decryptionShare(shares.get(0), total),
        ElGamal.decryptionShare(shares.get(2), total));
long yes = ElGamal.decrypt(total, published, total.bound().longValueExact());   // 3
```

The full program, including the key generation and the HPKE-encrypted delivery of trustee shares
over a public board, is in the [Threshold decryption guide](https://zeroj.dev/guides/confidential/threshold-elgamal/).

## Real-world uses

- **Private voting.** Each ballot is encrypted to the election key with a proof it's a 0 or a 1;
  trustees decrypt only the final count. The demo shares the key n-of-n among three trustees, so
  all three must take part; the threshold key generation here is the t-of-n upgrade.
  ([use case](https://zeroj.dev/use-cases/private-voting/))
- **Sealed-bid totals and statistics.** A consortium learns the total or average of private
  submissions, and no member sees another's.
- **Key escrow with a quorum.** Recovery data is readable only when, say, 3 of 5 custodians agree.

## Choose `t` and `n`

| Policy | `t` | `n` |
|---|---|---|
| Any 2 of 3 | 1 | 3 |
| Any 3 of 5 | 2 | 5 |
| Any 4 of 7 | 3 | 7 |

Any `t + 1` trustees decrypt. The rule `2t + 1 ≤ n ≤ 64` is about faults, not the quorum: at most
`t` trustees may misbehave during key generation, so the honest ones must outnumber them. It allows
"2 of 5" (`t = 1`, `n = 5`) but not "4 of 5", which would need `n ≥ 7`.

## Watch out for

- **A quorum can read anything.** `t + 1` colluding trustees can decrypt any single ciphertext, not
  just the total. The "decrypt only the total" rule is a policy the library can't enforce; publish
  it, and pick independent trustees.
- **Decrypt once.** Decrypting a running total twice and subtracting reveals the values in between.
- **Verify every share.** Accept decryption shares only with `VerifiedDecryptionShare.verify` and a
  DLEQ proof (a proof that the share was made with the trustee's real key share); an unverified share lets a trustee choose the result.
- **Small results reveal.** A unanimous vote, or a total of one, reveals the individual values.
- **Maturity.** Experimental. Secret operations are offline/isolated only, and the encrypted share
  delivery's assumption A1 awaits external review.

## Next steps

- [Threshold decryption guide](https://zeroj.dev/guides/confidential/threshold-elgamal/)
- [ElGamal encryption guide](https://zeroj.dev/guides/confidential/elgamal/)
- [Choose how to disclose](https://zeroj.dev/selective-disclosure/)
