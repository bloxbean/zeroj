# Reveal the value (BBS)

> Show a verifier some attributes of an issuer-signed credential exactly as issued, and hide the rest, with BBS signatures. No circuit, no trusted setup.

Canonical URL: https://zeroj.dev/selective-disclosure/reveal-attributes/

**Use this when the verifier needs to see a value exactly as an issuer signed it**, such as "country
= NZ" or "licence class = B", and should learn nothing about the other attributes.

An issuer signs a list of attributes once with **BBS**, a signature scheme built for credentials.
The holder can then show any subset of the attributes, together with a proof that the issuer
signed the whole list. Hidden attributes stay hidden, and two presentations of the same credential
can't be linked by the proof alone.

_The web version of this page has an interactive illustration here._

## Who learns what

| Party | Learns |
|---|---|
| Issuer | Everything, once, at issuance |
| Holder | Their own credential |
| Verifier | The revealed attributes, and that the issuer signed them |
| Everyone else | Nothing, unless the presentation is published (for example in a Cardano transaction, where revealed values become public) |

## In code

```java title="RevealCountry.java (core)"
import org.zeroj.bbs.BbsKeyPair;
import org.zeroj.bbs.BbsPresentation;
import org.zeroj.bbs.BbsService;
import org.zeroj.bbs.BbsSignature;

BbsService bbs = BbsService.pureJava();

// Issuer: sign five attributes once (keyMaterial: at least 32 secret random bytes)
BbsKeyPair issuer = bbs.keyPair(keyMaterial, keyInfo);
List<byte[]> attributes = List.of(name, dob, country, kycLevel, docId);
BbsSignature signature = bbs.sign(issuer.secretKey(), issuer.publicKey(), attributes, header);

// Holder: reveal country (2) and kycLevel (3), bound to the verifier's fresh challenge
BbsPresentation presentation = bbs.derivePresentation(
        issuer.publicKey(), signature, attributes, header, challenge, new int[] {2, 3});

// Verifier: check the proof, then that the challenge is the one it issued, then its policy
boolean valid = bbs.verifyPresentation(issuer.publicKey(), presentation);
```

The complete, runnable program, plus key handling, headers and on-chain verification, is in the
[BBS guide](https://zeroj.dev/guides/credentials/bbs/).

## Real-world uses

- **Reusable KYC.** Do identity checks once; show each service only the country and KYC level.
  ([use case](https://zeroj.dev/use-cases/selective-disclosure/), demo `reusable-kyc`)
- **Professional licences.** A doctor shows "licensed physician, valid until 2027" to a pharmacy
  portal, without a home address or registration number.
- **Event and membership passes.** A member shows "tier = gold" to get in, and nothing else.
- **Supply-chain certificates.** A shipper reveals "origin = EU" and "certified organic" from an
  auditor-signed product credential.

## When not to use it

- **The verifier needs a fact, not the value.** "Over 21" shouldn't reveal a birth date. Use
  [Prove a rule](https://zeroj.dev/selective-disclosure/prove-a-rule/).
- **The value lives on-chain and changes**, like a balance. BBS signs a fixed credential; use
  [Hide a number](https://zeroj.dev/selective-disclosure/hide-a-number/).
- **A rare revealed value identifies the person.** A unique combination of attributes can
  re-identify someone; reveal the minimum.

## Watch out for

- **Replay.** A presentation stays valid forever. The verifier must pick a fresh challenge and
  mark it used, or derive it from the UTxO being spent on-chain.
- **On-chain shape.** ZeroJ's on-chain BBS verifier supports one fixed shape: a five-attribute
  credential revealing positions 2 and 3, at about 2.43 billion CPU steps.
- **Maturity.** BBS is **Beta** and follows an IRTF draft, not yet an RFC. The default pure-Java
  provider isn't constant-time, so prefer the blst provider for issuer keys.

## Next steps

- [BBS credentials guide](https://zeroj.dev/guides/credentials/bbs/)
- [Prove a rule](https://zeroj.dev/selective-disclosure/prove-a-rule/): combine with a small circuit when one
  attribute needs a range check
- [Choose how to disclose](https://zeroj.dev/selective-disclosure/)
