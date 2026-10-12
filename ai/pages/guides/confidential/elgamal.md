# ElGamal encryption

> Encrypt small amounts to someone's public key, add ciphertexts without decrypting them, and prove in a Groth16 circuit what a ciphertext contains, with ZeroJ's elgamal-jubjub-v1 profile.

Canonical URL: https://zeroj.dev/guides/confidential/elgamal/

A [Pedersen commitment](https://zeroj.dev/guides/confidential/pedersen/) can only be opened by someone who knows
its opening. **Encryption** solves a different problem: a value that a named party, such as an
auditor, an auctioneer or a group of election trustees, must be able to read later **without
the sender's help**.

Think of a lockbox with a slot. Anyone can drop a value in using the public key; only the holder
of the secret key can open it. ZeroJ uses **exponential ElGamal** on the Jubjub curve, which adds
one more property: ciphertexts under the same key **add up**. A ledger can keep an encrypted
running total, and the key holder decrypts only the total.

The trade-off is that decryption ends in a search, so it only works for **small numbers**: votes,
counters, or a large amount split into 32-bit pieces called **limbs**. The profile is
[`elgamal-jubjub-v1`](https://github.com/bloxbean/zeroj/blob/main/docs/specs/elgamal-jubjub-v1.md),
designed in [ADR-0052](https://github.com/bloxbean/zeroj/blob/main/docs/adr/0052-exponential-elgamal-jubjub.md).

_The web version of this page has an interactive illustration here._

## Status

| Area | Status |
|---|---|
| Host API: keys, encryption, homomorphic addition, decryption (`ElGamal`, `ElGamalCiphertext`, key contexts) | **Experimental**, pending review and external review |
| In-circuit encryption and DLEQ proofs (`ZkElGamal`, `ZkElGamalPublicKey`) | **Experimental**, pending review and external review |
| Secret operations (encrypting, decryption shares, decrypting) | **Offline/isolated only**: variable-time arithmetic, no constant-time claim |

"Offline/isolated only" means: run code that touches secret keys or plaintexts on the user's own
device or in a separate process, never in a shared service an attacker can time. See
[Status & maturity](https://zeroj.dev/start/status/).

## Add the dependency

The host API is in `zeroj-circuit-lib`:

```groovy title="build.gradle"
dependencies {
    implementation platform('org.zeroj:zeroj-bom-core:<version>')
    implementation 'org.zeroj:zeroj-circuit-lib'   // ElGamal, ElGamalCiphertext, JubjubDiscreteLog, ...
}
```

Example 4 below also proves a circuit, so it needs the annotation, crypto, codec and verifier
modules listed in the [Pedersen guide](https://zeroj.dev/guides/confidential/pedersen/#add-the-dependency). Use
`0.1.0-pre13` or later for `<version>`.

## 1. Encrypt, add, decrypt

```java title="ElGamalBasics.java"
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.JubjubDiscreteLog;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;

import java.security.SecureRandom;

/** Exponential ElGamal on Jubjub: encrypt two amounts, add the ciphertexts, decrypt only the sum. */
public class ElGamalBasics {

    public static void main(String[] args) {
        SecureRandom random = new SecureRandom();

        // 1. A key pair. The context is "the key a ciphertext belongs to"; n-of-n with n = 1 here.
        ElGamalSecretKey secretKey = ElGamalSecretKey.generate(random);
        NOfNKeyContext key = NOfNKeyContext.singleKey(secretKey);

        // 2. Encrypt two amounts. The width (16 bits here) is a promise: 0 <= m < 2^16.
        int width = 16;
        ElGamalCiphertext a = ElGamal.encrypt(key, 1200, width, random);
        ElGamalCiphertext b = ElGamal.encrypt(key, 345, width, random);
        System.out.println("Ciphertext size: " + a.encode().length + " bytes");
        System.out.println("Bound of each ciphertext: " + a.bound());

        // 3. Add without decrypting. The library tracks the bound of the sum.
        ElGamalCiphertext sum = a.add(b);
        System.out.println("Bound of the sum: " + sum.bound());

        // 4. Decrypt the sum: a bounded discrete-log search over [0, bound].
        //    Build the search table once and reuse it for many decryptions.
        long maxPlaintext = sum.bound().longValueExact();
        JubjubDiscreteLog table = JubjubDiscreteLog.forBound(maxPlaintext);
        long total = ElGamal.decryptWithSecret(sum, secretKey, maxPlaintext, table);
        System.out.println("Decrypted sum: " + total);

        // What the safe API refuses:
        try {
            ElGamal.decryptWithSecret(sum, secretKey, 1000);  // search limit below the bound
        } catch (IllegalArgumentException e) {
            System.out.println("Refused: " + e.getMessage());
        }
        try {
            ElGamalSecretKey other = ElGamalSecretKey.generate(random);
            a.add(ElGamal.encrypt(NOfNKeyContext.singleKey(other), 1, 1, random)); // different keys
        } catch (IllegalArgumentException e) {
            System.out.println("Refused: " + e.getMessage());
        }
        try {
            ElGamal.encrypt(key, 70_000, width, random);      // does not fit in 16 bits
        } catch (IllegalArgumentException e) {
            System.out.println("Refused: " + e.getMessage());
        }

        // Bytes carry no key and no bound: decoding gives a *raw* ciphertext, which has no
        // decrypt method. It re-enters the safe layer only through ElGamal.admit(...) with a
        // verifier that checks an encryption proof.
        RawElGamalCiphertext raw = RawElGamalCiphertext.decode(sum.encode());
        System.out.println("Decoded from bytes: " + raw.getClass().getSimpleName());
    }
}
```

```text
Ciphertext size: 64 bytes
Bound of each ciphertext: 65535
Bound of the sum: 131070
Decrypted sum: 1545
Refused: the ciphertext's plaintext bound 131070 exceeds the search limit 1000
Refused: ciphertexts are under different key contexts; homomorphic operations need one key
Refused: message must satisfy 0 <= m < 2^16
Decoded from bytes: RawElGamalCiphertext
```

What to notice:

- **Every encryption carries a width.** `encrypt(key, 1200, 16, random)` promises that the
  message fits in 16 bits. The ciphertext remembers the largest value it can hold, its **bound**
  (65,535 here), and adding two ciphertexts adds their bounds.
- **Decryption is a search** over `[0, bound]`. `JubjubDiscreteLog.forBound(...)` builds a lookup
  table once; reuse it for many decryptions.
- **The safe API refuses mistakes** instead of returning a wrong answer: a search limit below the
  bound, ciphertexts under different keys, a message that doesn't fit its width.
- **Bytes carry no key and no bound.** `RawElGamalCiphertext.decode` gives you a *raw* ciphertext,
  which has no decrypt method. Section 3 shows how it gets back in.

## 2. Encrypt to someone else's key

In example 1 one process owns the key, so `NOfNKeyContext.singleKey(secretKey)` is fine. A real
sender only has the recipient's **published** key, and must check a **possession proof** before
using it: a zero-knowledge proof (a DLEQ proof) that whoever published the key knows its secret.

Why bother? Without it, an attacker can publish a "rogue" key crafted from other people's keys,
so that a combined key ends up decryptable by the attacker alone. ZeroJ makes the check part of
the type system: the only way from bytes to a usable key goes through `VerifiedKeyShare.verify`,
which hands your verifier the exact statement to check.

```java title="Admit a published key (shape)"
import org.zeroj.circuit.lib.jubjub.DleqStatement;
import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.VerifiedKeyShare;

import java.util.List;

// keyBytes and proof come from the auditor's registry entry (or a trustee's announcement).
VerifiedKeyShare share = VerifiedKeyShare.verify(keyBytes, statement ->
        statement.kind() == DleqStatement.Kind.POSSESSION
                && verifyDleqProof(proof, statement.publicInputs()));   // YOUR Groth16 check
NOfNKeyContext auditor = ElGamalPublicKey.aggregate(List.of(share));

// Several key holders (n-of-n): aggregate all their verified shares into one joint key.
// NOfNKeyContext trustees = ElGamalPublicKey.aggregate(List.of(share1, share2, share3));
```

`verifyDleqProof` stands for your own Groth16 verification of the possession proof, over a DLEQ
circuit built with `ZkElGamal.assertDiscreteLogEquality`. The full proven flow (possession
proofs, joint key, proved ballots, proved decryption shares, tally) is the `endToEnd` test in
[`AnnotatedElGamalTest`](https://github.com/bloxbean/zeroj/blob/main/zeroj-integration-tests/src/test/java/org/zeroj/examples/annotation/AnnotatedElGamalTest.java).

> **Danger: A verifier that returns `true` disables the check**
>
> Every `...Verifier` lambda is a promise that *you* checked a proof. `s -> true` compiles, runs and
> silently turns off the protection.

## 3. Receive ciphertexts: admit them with a proof

A ciphertext you receive could encrypt anything: a negative number, a huge number, a value under
the wrong key. Adding it to your total would corrupt the total. So received bytes start as a
`RawElGamalCiphertext`, and become a usable `ElGamalCiphertext` only through `ElGamal.admit`:

```java title="Admit a received ciphertext"
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;

RawElGamalCiphertext raw = RawElGamalCiphertext.decode(ciphertextBytes);   // 64 bytes
ElGamalCiphertext ballot = ElGamal.admit(raw, electionKey, 1, statement ->
        statement.width() == 1
                && verifyEncryptionProof(proof, statement.publicInputs()));   // YOUR Groth16 check
```

The statement's public inputs are exactly `PK.u, PK.v, A.u, A.v, B.u, B.v`: the key and the
ciphertext's two points. Your proof must be over those values and that width, for example a
circuit that calls `ZkElGamal.encrypt` and `assertAffineEquals`, as in example 4.

When is `s -> true` acceptable? Only when something else already verified a proof for that exact
statement, for example a Cardano validator that refused the transaction unless the proof
verified. The [confidential points](https://zeroj.dev/use-cases/confidential-points/) auditor does this for
ciphertexts it reads from validated ledger outputs, and says so in a comment.

## 4. Prove what a ciphertext contains

The most useful pattern combines a commitment and a ciphertext: "this ciphertext, encrypted to the
auditor, holds **the same amount** as this commitment". Then the auditor's copy can't be faked,
even by the sender. This circuit is a minimal illustration of that idea for one 32-bit amount; it
is not the reference circuit ZeroJ measured on-chain.

```java title="AuditedAmount.java"
import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkElGamal;
import org.zeroj.circuit.lib.zk.ZkElGamalPublicKey;
import org.zeroj.circuit.lib.zk.ZkPedersenCommitment;

/**
 * "The public ElGamal ciphertext encrypts, under the auditor's key, the same amount the public
 * Pedersen commitment hides." One secret amount feeds both relations.
 */
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

The program commits to 250, encrypts 250 to the auditor, proves the circuit, lets the auditor admit
and decrypt the ciphertext, then plays a cheating sender who encrypts 1 instead. Run it with
`-Dzeroj.allowInsecureTrustedSetup=true` (development setup):

```java title="AuditedAmountMain.java"
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class AuditedAmountMain {

    public static void main(String[] args) {
        SecureRandom random = new SecureRandom();
        var circuit = AuditedAmountCircuit.build();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        System.out.println("Public inputs: " + AuditedAmountCircuit.schema().publicInputs().names());
        System.out.println("Constraints: " + r1cs.numConstraints());

        // DEV-ONLY single-party setup. Production keys come from an MPC ceremony.
        BigInteger tau = PowersOfTauBLS381.generate(6).tauScalar();
        Groth16Keys keys = Groth16Keys.setupInMemory(r1cs.constraints(), r1cs.numWires(),
                r1cs.numPublicInputs(), tau);
        String vkJson = SnarkjsGroth16Json.verificationKeyJson(keys);

        // The auditor's ElGamal key (a separate key from any note viewing key).
        // Demo shortcut: one process plays both parties. A real sender builds this context from
        // the auditor's published key and possession proof:
        //   ElGamalPublicKey.aggregate(List.of(VerifiedKeyShare.verify(keyBytes, proofVerifier)))
        ElGamalSecretKey auditorSecret = ElGamalSecretKey.generate(random);
        NOfNKeyContext auditor = NOfNKeyContext.singleKey(auditorSecret);

        // Sender: commit to 250 and encrypt the same 250 to the auditor, then prove it.
        long amount = 250;
        NoteOpening opening = NoteOpening.random(BigInteger.valueOf(amount), random);
        JubjubPoint c = opening.commitment();
        ElGamalEncryption enc = ElGamal.encryptWithOpening(auditor, BigInteger.valueOf(amount), 32, random);
        List<BigInteger> keyAndCiphertext = enc.statement().publicInputs(); // PK.u, PK.v, A.u, A.v, B.u, B.v
        var inputs = AuditedAmountCircuit.inputs()
                .commitU(c.affineU()).commitV(c.affineV())
                .auditorU(keyAndCiphertext.get(0)).auditorV(keyAndCiphertext.get(1))
                .handleU(keyAndCiphertext.get(2)).handleV(keyAndCiphertext.get(3))
                .blindedU(keyAndCiphertext.get(4)).blindedV(keyAndCiphertext.get(5))
                .amount(amount).blinding(opening.blinding()).randomness(enc.randomness());
        String proofJson = SnarkjsGroth16Json.proofJson(
                keys.prove(inputs.calculateWitness(circuit, CurveId.BLS12_381), r1cs.constraints()));
        byte[] ciphertextBytes = enc.ciphertext().encode();   // what goes on chain, 64 bytes

        // Auditor: admit the ciphertext only if the proof verifies for exactly
        // (this commitment, my key, this ciphertext, width 32), then decrypt it.
        RawElGamalCiphertext raw = RawElGamalCiphertext.decode(ciphertextBytes);
        ElGamalCiphertext admitted = ElGamal.admit(raw, auditor, 32, statement -> {
            List<BigInteger> pub = new ArrayList<>(List.of(c.affineU(), c.affineV()));
            pub.addAll(statement.publicInputs());
            return statement.width() == 32 && verify(vkJson, proofJson, pub);
        });
        System.out.println("Auditor decrypts: " + ElGamal.decryptWithSecret(admitted, auditorSecret, (1L << 32) - 1));

        // A cheating sender: commitment hides 250, ciphertext encrypts 1. No witness exists.
        ElGamalEncryption lie = ElGamal.encryptWithOpening(auditor, BigInteger.ONE, 32, random);
        List<BigInteger> liePub = lie.statement().publicInputs();
        try {
            inputs.handleU(liePub.get(2)).handleV(liePub.get(3)).blindedU(liePub.get(4)).blindedV(liePub.get(5))
                    .randomness(lie.randomness()).calculateWitness(circuit, CurveId.BLS12_381);
            System.out.println("Cheating witness accepted?!");
        } catch (ArithmeticException e) {
            System.out.println("Cheating sender: witness rejected (" + e.getMessage() + ")");
        }
    }

    static boolean verify(String vkJson, String proofJson, List<BigInteger> publicInputs) {
        var circuitId = AuditedAmountCircuit.circuitId();
        String publicJson = SnarkjsGroth16Json.publicJson(publicInputs.toArray(BigInteger[]::new));
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson, circuitId);
        var material = VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, circuitId);
        return new Groth16BLS12381PureJavaVerifier().verify(envelope, material).proofValid();
    }
}
```

```text
Public inputs: [commitU, commitV, auditorU, auditorV, handleU, handleV, blindedU, blindedV]
Constraints: 8893
Auditor decrypts: 250
Cheating sender: witness rejected (Constraint violation: w30527=2541…7612 != w30513=1358…0935)
```

The cheating sender can't even produce a witness: no secret amount makes both the commitment and
the ciphertext check out. The circuit has 8,893 constraints. Production applications split a
64-bit amount into two 32-bit limbs and encrypt each, so the auditor can decrypt it; the
[confidential payroll](https://zeroj.dev/use-cases/confidential-payroll/) and
[confidential points](https://zeroj.dev/use-cases/confidential-points/) demos do exactly that, inside their
transfer and issue proofs.

## Bounds and decryption cost

Decryption recovers `m·G` and then searches for `m`. How far it can search decides what you can
encrypt:

- **Widths are 1 to 64 bits**, and a message must satisfy `0 ≤ m < 2^width`.
- **Bounds add up.** A sum of 1,000 ciphertexts of width 16 has a bound of about 65 million, even
  if the real total is small. Use the narrowest width that fits.
- **`maxPlaintext` must be at least the bound**, not just the value you expect, or `decrypt`
  refuses. If no value in range matches, it throws `ElGamalDecryptionException` instead of
  guessing.
- **The default table reaches about 2⁴³.** A width-64 ciphertext can be admitted and added, but
  not decrypted. Split amounts into 32-bit limbs.

| Operation (Apple M4 Max) | Time |
|---|---|
| Encrypt | 4.7 ms |
| Decryption share | 1.65 ms |
| Decode a ciphertext | 0.22 ms |
| Add, per ciphertext | 1.6 µs |
| Discrete log up to 2³²: build table / solve | 21 ms / 7–19 ms |
| Discrete log up to 2⁴⁰: build table / solve | 108 ms / 0.55–0.9 s |

Source: [ElGamal benchmark](https://github.com/bloxbean/zeroj/blob/main/docs/benchmarks/elgamal-jubjub-2026-10-05.md).
These are measurements on one machine, not performance claims.

## Rules to follow

- **Verify every key you didn't make** with `VerifiedKeyShare.verify` and a real possession-proof
  check.
- **Admit every ciphertext you didn't make** with `ElGamal.admit` and a real encryption-proof
  check, for exactly that key and width.
- **Verify every decryption share you didn't make** with `VerifiedDecryptionShare.verify` and a
  DLEQ proof. An unchecked share lets a key holder choose the result.
- **Keep widths small** and decrypt only bounded values.
- **Run secret operations offline or isolated.** Encrypting, decryption shares and decrypting
  handle secrets with variable-time code.
- **The key holder can read everything encrypted to them.** If that's too much trust in one
  party, split the key: see [Threshold decryption](https://zeroj.dev/guides/confidential/threshold-elgamal/).
- **Fixed randomness is test-only.** Never pass your own encryption randomness; the API draws it
  from `SecureRandom`.
- **A proof is not a permission.** Binding ciphertexts to transactions, replay and authorization
  are application rules. See [Application security](https://zeroj.dev/guides/verifying/application-security/).

## Cost

| Circuit | Constraints |
|---|---|
| Encrypt to a fixed public key, width 1 / 16 / 64 | 6,558 / 6,650 / 6,938 |
| Encrypt to a key witnessed in the circuit | 12,105 |
| DLEQ (possession or decryption-share proof) | 6,546 |
| Commitment + ciphertext of the same 32-bit amount (example 4) | 8,893 |

A 64-byte ciphertext is two curve points. On Cardano, its four coordinates are public inputs of
an ordinary Groth16 proof; see [Verify proofs on Cardano](https://zeroj.dev/guides/verifying/on-chain/).

## Next steps

- [Threshold decryption](https://zeroj.dev/guides/confidential/threshold-elgamal/): split the key among trustees
- [Confidential notes](https://zeroj.dev/guides/confidential/confidential-notes/): deliver commitment openings
  on-chain
- [Encrypt for an auditor](https://zeroj.dev/selective-disclosure/encrypt-for-an-auditor/): the pattern, with use
  cases
- Use cases: [Sealed-bid auction](https://zeroj.dev/use-cases/sealed-bid-auction/),
  [Confidential payroll](https://zeroj.dev/use-cases/confidential-payroll/),
  [Private voting](https://zeroj.dev/use-cases/private-voting/)
