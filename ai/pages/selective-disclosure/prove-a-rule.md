# Prove a rule (Groth16 predicates)

> Prove a yes/no fact about private data, such as an age, income or score threshold, from a signed or committed credential, without revealing the data. The verifier learns only the answer.

Canonical URL: https://zeroj.dev/selective-disclosure/prove-a-rule/

**Use this when the verifier needs an answer, not the data**: "over 21", "income at least 50,000",
"credit score at least 650", "resident of an approved country".

The holder runs a small circuit on their own device. It checks that the data came from a trusted
issuer, then checks the rule, and outputs a Groth16 proof. The verifier, an app or a Cardano
validator, checks the proof against the issuer's key and its own policy values. It learns that the
rule holds, and nothing else.

_The web version of this page has an interactive illustration here._

## Who learns what

| Party | Learns |
|---|---|
| Issuer | The data, once, at issuance |
| Holder | Their own data |
| Verifier | The rule's answer, plus the public policy values it chose (the threshold, the current year) |
| Everyone else | The same as the verifier, if the proof goes on-chain |

## Over a signed credential

The issuer signs a Poseidon hash of all the fields with EdDSA on Jubjub. The circuit recomputes
the hash, checks the signature against the issuer's public key, then applies the rule. This one,
from the `selective-disclosure` demo, answers "a doctor, born at least 30 years before
`currentYear`?" in its public `eligible` output and reveals nothing else. The verifier must
require `eligible = 1`; a proof with `eligible = 0` is a valid proof of "no".

```java title="SeniorDoctorProof.java"
import org.zeroj.circuit.annotation.*;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkEdDSAJubjub;
import org.zeroj.circuit.lib.zk.ZkPoseidonN;

@ZKCircuit(name = "senior-doctor", version = 1)
public class SeniorDoctorProof {
    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;
    private static final int MIN_AGE = 30;
    private static final long DOCTOR_ROLE_ID = 1001L;

    @Prove
    ZkBool prove(ZkContext zk,
                 @Public ZkField pkU,
                 @Public ZkField pkV,
                 @Public @UInt(bits = 16) ZkUInt currentYear,
                 @Public ZkBool eligible,
                 @Secret @UInt(bits = 16) ZkUInt dobYear,
                 @Secret @UInt(bits = 16) ZkUInt country,
                 @Secret ZkField roleId,
                 @Secret @UInt(bits = 8) ZkUInt salaryBracket,
                 @Secret ZkField nameHash,
                 @Secret ZkField sigRU,
                 @Secret ZkField sigRV,
                 @Secret @UInt(bits = 252) ZkUInt sigS,
                 @Secret @UInt(bits = 252) ZkUInt kModL,
                 @Secret @UInt(bits = 4) ZkUInt kQuotient) {

        // Every predicate recomputes the same signed message over all five fields
        var claims = ZkPoseidonN.hash(zk, POSEIDON, dobYear.asField(), country.asField(),
                roleId, salaryBracket.asField(), nameHash);
        ZkEdDSAJubjub.verifyWithRegisteredKey(zk, pkU, pkV, claims, sigRU, sigRV, sigS, kModL, kQuotient);

        // The predicate: role == doctor AND born no later than currentYear - 30
        var maxDobYear = ZkUInt.wrap(zk, currentYear.asField().sub(zk.constant(MIN_AGE)).signal(), 16);
        var roleOk = roleId.isEqual(zk.constant(DOCTOR_ROLE_ID));
        return roleOk.and(eligible.isEqual(dobYear.lte(maxDobYear)));
    }
}
```

This is the pattern of the [age and KYC](https://zeroj.dev/use-cases/age-and-kyc/) and
[selective disclosure](https://zeroj.dev/use-cases/selective-disclosure/) demos. The tutorial
[Prove you're over 18](https://zeroj.dev/tutorials/age-check/) builds one step by step, including setup, proving and
verification.

## Over a committed credential

Instead of a signature, an issuer can publish a **Pedersen vector commitment** to a whole profile:
income, score, birth year and country in one 32-byte point. The holder gets the opening. A proof can
then check a rule over any of the fields while all of them stay sealed:

```java title="CreditProfileCheck.java (core)"
import org.zeroj.circuit.lib.zk.ZkPedersenVector;

// SCHEMA: income/64, credit_score/16, birth_year/16, country/16 bits
var binding = ZkPedersenVector.bindSchema(zk, SCHEMA, schemaDigest);   // schemaDigest is @Public
ZkPedersenVector.commit(zk, binding, List.of(income, creditScore, birthYear, country), blinding)
        .assertAffineEquals(zk, u, v);                                  // (u, v) is the public commitment
income.gte(minIncome).assertTrue();
creditScore.gte(minScore).assertTrue();
```

The [pedersen-commitments demo](https://github.com/bloxbean/zeroj-usecases/tree/main/pedersen-commitments)
uses this as a **credit gate**: a bureau commits to Alice's profile (income 85,000, score 720), and
she proves "income ≥ 50,000 and score ≥ 650" to a lender, who mints her a badge on-chain. If Mallory
copies Alice's commitment and proof, the validator refuses, because the bureau's issuance record
names Alice, and Alice has to sign.

Two rules come with vector commitments: bind the public **schema digest** in every proof, and
accept a commitment only with an authenticated **issuance record**. See
[Pedersen commitments](https://zeroj.dev/guides/confidential/pedersen/#5-commit-to-several-values-at-once).

| | Signed credential | Committed credential |
|---|---|---|
| Issuer publishes | A signature, held by the holder | A commitment, often on-chain |
| Unlinkable across verifiers | Yes, if the proof hides the signature | No: the same commitment is reused |
| Circuit size | Signature check plus the rule | About 3,000 constraints for the credit gate |
| Maturity | Beta | Experimental |

## Real-world uses

- **Age-restricted services.** "Over 18" for a game, "over 21" for a venue.
  ([use case](https://zeroj.dev/use-cases/age-and-kyc/))
- **Lending.** "Income at least 50,000 and score at least 650" without a payslip or a credit
  report.
- **Professional access.** "A doctor, licensed for 10 years or more", from a medical board's
  credential.
- **Allowlists.** "My key is in this approved set", with a Merkle proof.
  ([tutorial](https://zeroj.dev/tutorials/private-allowlist/))

## When not to use it

- **The verifier must see the value itself.** Use [Reveal the value](https://zeroj.dev/selective-disclosure/reveal-attributes/).
- **The value has to stay on-chain and be added up.** Use [Hide a number](https://zeroj.dev/selective-disclosure/hide-a-number/).
- **You can't run a trusted setup per circuit.** Every new rule is a new circuit; consider BBS if
  revealing is acceptable.

## Watch out for

- **Pin the policy values.** The verifier, not the prover, chooses the threshold and the current
  year. On Cardano, make them script parameters.
- **Replay.** These proofs carry no nonce. Bind them to the UTxO being spent or to a session.
- **Trusted setup.** Production keys come from a multi-party ceremony. See
  [Trusted setup, explained](https://zeroj.dev/learn/trusted-setup/).

## Next steps

- [Prove you're over 18](https://zeroj.dev/tutorials/age-check/) (tutorial)
- [Hide a number](https://zeroj.dev/selective-disclosure/hide-a-number/)
- [Choose how to disclose](https://zeroj.dev/selective-disclosure/)
