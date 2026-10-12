# Confidential notes

> Put a Pedersen commitment on-chain together with its opening, encrypted separately for the owner and each auditor, then recover notes by scanning the chain with a viewing key.

Canonical URL: https://zeroj.dev/guides/confidential/confidential-notes/

A [Pedersen commitment](https://zeroj.dev/guides/confidential/pedersen/) hides an amount, but whoever owns it needs
the **opening**, the amount and the blinding `(v, r)`, to spend it or prove anything about it later.
Sending that opening over a private channel is fragile: lose the message and the money is stuck.

A **confidential note** puts the opening on-chain too, encrypted separately for each reader. The
owner comes first, then any auditors. Each reader holds a **viewing key**: a key that can read
deliveries but can't spend anything. The rest of the world sees the commitment and a few
random-looking bytes per reader.

That gives you two things:

- **Recovery from the chain.** A wallet that knows only its viewing key can rebuild its balance by
  scanning the ledger. No side channel, no backup of every opening.
- **Chosen readers.** The owner and the named auditors can read the amount. Nobody else can.

ZeroJ's profile is [`confidential-note-jubjub-v1`](https://github.com/bloxbean/zeroj/blob/main/docs/specs/confidential-note-jubjub-v1.md),
designed in [ADR-0055](https://github.com/bloxbean/zeroj/blob/main/docs/adr/0055-confidential-notes-jubjub.md).

_The web version of this page has an interactive illustration here._

## Status

| Area | Status |
|---|---|
| Notes: seal, open, scan (`ConfidentialNotes`, `NoteScanner`, `NoteViewingKey`, `NoteReaderKey`, `NoteOpening`) | **Experimental**, pending review and external review |
| Secret operations (sealing, opening, viewing keys) | **Offline/isolated only**: variable-time arithmetic on secrets |
| Assumptions A1–A3 (see [below](#assumptions-in-plain-words)) | Unproved; external review is a production gate |

The delivery format is checked against all 10 Zcash Sapling note-encryption test vectors, an
independent Python reference written from the spec, BouncyCastle's personalized BLAKE2b and the
Wycheproof ChaCha20-Poly1305 vectors. It behaves identically in a GraalVM native image.

## How a delivery works

The construction follows Zcash Sapling's note encryption on the Jubjub curve:

1. For each reader, the sender picks a **fresh one-time key** `e` and publishes `E = e·G`.
2. Sender and reader agree on a shared secret from `e` and the reader's public **reader key**
   (Diffie–Hellman on Jubjub).
3. A BLAKE2b-256 key-derivation step, personalized with `ZeroJ_NoteKDF_v1`, turns that secret into
   a one-time encryption key.
4. ChaCha20-Poly1305 encrypts the 41-byte plaintext `0x01 ‖ v (8 bytes) ‖ r (32 bytes)` into a
   57-byte ciphertext. Because each key encrypts exactly one message, the fixed all-zero nonce is
   safe.

A delivery is `E ‖ ciphertext`, **89 bytes per reader**. A reader who decrypts it doesn't trust the
result blindly: it **accepts the opening only if `commit(v, r)` recomputes the note's commitment**.
A delivery that doesn't decrypt, or decrypts to a wrong opening, is rejected.

## 1. Create, deliver, open, scan

This program plays every party: an owner, an auditor and a stranger make viewing keys, a sender
creates a note for 250, and each reader tries to open it. It needs only `zeroj-circuit-lib`
(plus `zeroj-bom-core`); see [Pedersen commitments](https://zeroj.dev/guides/confidential/pedersen/#add-the-dependency).

```java title="ConfidentialNoteDemo.java"
import org.zeroj.circuit.lib.jubjub.ConfidentialNotes;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteReaderKey;
import org.zeroj.circuit.lib.jubjub.NoteScanner;
import org.zeroj.circuit.lib.jubjub.NoteScanner.Candidate;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;

/**
 * A confidential note: a Pedersen commitment to an amount, plus its opening (amount, blinding)
 * encrypted to each reader. The owner and an auditor can open it; nobody else can.
 */
public class ConfidentialNoteDemo {

    public static void main(String[] args) {
        SecureRandom random = new SecureRandom();

        // 1. Each reader makes a viewing key in its own wallet and publishes the reader key.
        NoteViewingKey ownerKey = NoteViewingKey.generate(random);
        NoteViewingKey auditorKey = NoteViewingKey.generate(random);
        NoteViewingKey strangerKey = NoteViewingKey.generate(random);
        byte[] ownerPublished = ownerKey.readerKey().encode();       // 32 bytes
        byte[] auditorPublished = auditorKey.readerKey().encode();

        // 2. The sender validates the received reader keys, then creates the note:
        //    the commitment C goes in the datum, one 89-byte delivery per reader next to it.
        List<NoteReaderKey> readers = List.of(                         // order: owner, then auditors
                NoteReaderKey.decode(ownerPublished),
                NoteReaderKey.decode(auditorPublished));
        NoteOpening opening = NoteOpening.random(BigInteger.valueOf(250), random);
        JubjubPoint c = opening.commitment();
        BigInteger u = c.affineU();
        BigInteger v = c.affineV();
        List<byte[]> deliveries = ConfidentialNotes.seal(opening, readers, random);
        System.out.println("Deliveries: " + deliveries.size() + " x " + deliveries.get(0).length + " bytes");

        // 3. The owner opens the delivery at its position (0) against the note's (u, v).
        NoteScanner owner = NoteScanner.of(ownerKey);
        Optional<NoteOpening> mine = owner.open(deliveries.get(0), u, v);
        System.out.println("Owner reads amount: " + mine.map(NoteOpening::value).orElse(null));

        // 4. The auditor opens its own delivery (position 1).
        Optional<NoteOpening> audited = NoteScanner.of(auditorKey).open(deliveries.get(1), u, v);
        System.out.println("Auditor reads amount: " + audited.map(NoteOpening::value).orElse(null));

        // 5. Anyone else gets "not mine", for every delivery.
        NoteScanner stranger = NoteScanner.of(strangerKey);
        System.out.println("Stranger opens delivery 0? " + stranger.open(deliveries.get(0), u, v).isPresent());
        System.out.println("Stranger opens delivery 1? " + stranger.open(deliveries.get(1), u, v).isPresent());

        // 6. A wallet scans many notes at once. `ownedByMe` is the wallet's own owner check
        //    (e.g. the datum's owner credential). An owned note that does not open is value the
        //    wallet cannot spend: report it, never drop it silently.
        NoteOpening other = NoteOpening.random(BigInteger.valueOf(99), random);
        JubjubPoint c2 = other.commitment();
        byte[] badDelivery = ConfidentialNotes.seal(other, List.of(readers.get(1)), random).get(0); // not to the owner
        NoteScanner.Scan scan = owner.scan(List.of(
                Candidate.of(deliveries.get(0), u, v, true),
                Candidate.of(badDelivery, c2.affineU(), c2.affineV(), true)));
        System.out.println("Scan: opened " + scan.opened().size()
                + ", owned but unopenable at indices " + scan.unopenableOwned());
    }
}
```

```text
Deliveries: 2 x 89 bytes
Owner reads amount: 250
Auditor reads amount: 250
Stranger opens delivery 0? false
Stranger opens delivery 1? false
Scan: opened 1, owned but unopenable at indices [1]
```

A few details:

- **Readers are positional.** The application fixes the order (owner first, then auditors) and
  each reader opens only the delivery at its own position.
- **Open with the datum's coordinates.** `open` and `Candidate.of` take the commitment's affine
  `(u, v)` as `BigInteger`s, exactly as they appear in the note's datum.
- **`ownedByMe` is your check, not the library's.** The scanner can't know who owns a UTxO. Your
  wallet decides that from the datum's owner credential and the script address before it scans.

## Viewing keys

- **Generate in the wallet.** `NoteViewingKey.generate(new SecureRandom())` creates the secret; publish
  only `readerKey().encode()`, 32 bytes.
- **Back it up.** `exportSecret()` and `NoteViewingKey.restore(bytes)` move the key between devices.
  Call `destroy()` when you're done with an in-memory copy.
- **Verify keys you receive from a registry.** `NoteReaderKey.decode(bytes)` checks that the bytes
  are a valid key. When keys come from a public registry, use
  `NoteReaderKey.verified(bytes, verifier)` with a **proof of possession**, so nobody can register
  a key they don't control. The proof statement carries no context, so the registry itself must
  bind each key to its registrant.
- **A viewing key is only a viewing key.** It can't spend, sign or decrypt ElGamal ciphertexts. An
  auditor that also receives [ElGamal-encrypted amounts](https://zeroj.dev/guides/confidential/elgamal/) has a
  separate ElGamal key.
- **No forward secrecy.** A leaked viewing key reads every past delivery addressed to it.

## What a delivery does and doesn't guarantee

**A validator can only check the length.** Plutus has no Jubjub operations, so an on-chain
validator can require "an 89-byte delivery for each reader" but can't check that it decrypts. A
careless or hostile sender can fill a delivery with random bytes. The owner's wallet then finds a
note it owns but can't open. It must **report** that note as unopenable, never drop it silently,
because it's value the owner can't spend.

**Delivery alone doesn't make the sender honest with the auditor.** The sender writes the
auditor's delivery too, and could put a different (valid-looking) opening there. When the auditor's
view must be *enforced*, add the amount a second time as ElGamal ciphertext to the auditor's
key, and prove inside the transfer's Groth16 proof that it matches the commitment. ADR-0055 calls
this **D3a**:

- the amount is split into two 32-bit **limbs**, so the auditor can decrypt each one quickly;
- each limb is ElGamal-encrypted to the auditor's separate key;
- the transfer circuit proves `limb0 + 2³²·limb1` is the committed amount and that both
  ciphertexts are correct.

D3a is **not a library API**. It's a pattern, with a test-only reference validator
([`AuditedConfidentialNoteValidator`](https://github.com/bloxbean/zeroj/blob/main/zeroj-integration-tests/src/test/java/org/zeroj/examples/notes/onchain/AuditedConfidentialNoteValidator.java)
and [`AuditedConfidentialNoteOnChainTest`](https://github.com/bloxbean/zeroj/blob/main/zeroj-integration-tests/src/test/java/org/zeroj/examples/notes/AuditedConfidentialNoteOnChainTest.java)).
In ZeroJ's test validator, a two-output transfer with one auditor measured 34,184 constraints and
73.4% of the per-transaction step limit in the JuLC VM, before the verifier savings in ZeroJ PRs
#85 and #86. A real ledger script does more work: the points demo's transfer, on the same circuit,
used 75.8% on Yaci DevKit. It covers only notes created by
proof-checked transitions such as transfers. Newly **issued** notes carry whatever audit data the
issuer supplied, unless issuance is proved too, as in
[confidential payroll](https://zeroj.dev/use-cases/confidential-payroll/).

## Wallet rules

- **Open only your own position**, and only notes your owner check selected.
- **Check the owner credential and the script address yourself**, so a copied note can't pass as
  one of yours.
- **Report unopenable owned notes**; never drop them.
- **Scan only in the user's own wallet process**, never as a shared or network service: a scanner
  holds the viewing key and learns every amount.
- **Run sealing and opening offline or isolated.** They use variable-time arithmetic on secrets.

## Assumptions in plain words

The construction reuses Sapling's components, but ZeroJ's use of them has not been externally
reviewed. Three assumptions carry the security, and all three are open:

- **A1, confidentiality.** A delivery reveals nothing about the amount to anyone without the
  reader's viewing key.
- **A2, integrity.** An opening a reader accepts really opens the note's commitment, and a sender
  can't make two readers accept different openings of the same note. This rests on the
  commitment being binding.
- **A3, no useful multi-key partitioning.** A delivery is accepted under at most one reader key,
  whatever its contents, except with negligible probability. ChaCha20-Poly1305 isn't
  key-committing, so this doesn't follow from the cipher alone. If two keys accepted different
  openings, A2 would be broken; the case where two keys accept the *same* opening rests on ZeroJ's
  own argument about the key derivation. A3 is unproved, and that argument hasn't been reviewed.

## Sizes and timings

| Item | Value | Source |
|---|---|---|
| Delivery | 89 bytes per reader (32-byte `E` + 57-byte ciphertext) | spec |
| Reader key | 32 bytes | spec |
| Extra minimum ADA, owner + one auditor | about 0.8 ADA (estimate) | ADR-0055 |
| Seal for 2 readers | about 5.6 ms | [benchmark](https://github.com/bloxbean/zeroj/blob/main/docs/benchmarks/confidential-note-jubjub-2026-10-09.md) |
| Accept a delivery (decrypt + recompute C) | about 5 ms | benchmark |
| Reject a delivery that isn't yours | about 1.7 ms | benchmark |
| Scan, one thread, every delivery rejected | about 660 deliveries per second (accepting one costs more; threads scale sublinearly) | benchmark |

Timings are from one Apple M4 Max laptop and are only a rough guide.

## Next steps

- Use cases: [Confidential loyalty points](https://zeroj.dev/use-cases/confidential-points/),
  [Confidential payroll](https://zeroj.dev/use-cases/confidential-payroll/),
  [Proof of solvency with hidden balances](https://zeroj.dev/use-cases/private-solvency/)
- [Share a value with chosen readers](https://zeroj.dev/selective-disclosure/share-with-chosen-readers/): when to use notes
- [ElGamal encryption](https://zeroj.dev/guides/confidential/elgamal/) and [Pedersen commitments](https://zeroj.dev/guides/confidential/pedersen/)
