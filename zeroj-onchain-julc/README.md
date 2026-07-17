# zeroj-onchain-julc

Reusable Julc validators and on-chain helpers for Cardano Plutus V3 proof
verification.

This module is the Cardano on-chain verification layer for ZeroJ. It contains
Julc-compiled spending validators, proof/VK conversion helpers, and feasibility
tools for estimating whether a proof system and curve are practical on Plutus
V3.

## Current Status

| Package | Contents | Status | Notes |
|---------|----------|--------|-------|
| `com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator` | `Groth16BLS12381Verifier` | Working crypto-only validator | Default BLS12-381 Groth16 spending validator using Plutus V3 BLS builtins; supports arbitrary public-input counts, but does not bind `ScriptContext` |
| `com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator` | `Groth16BLS12381TxOutRefBindingVerifier` | Working bound validator example | Binds the first public input to `blake2b_256(spentTxId || spentOutputIndex32) mod Fr` to reject proof replay across UTxOs |
| `com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib` | `Groth16BLS12381Lib` | Working on-chain library | Reusable `@OnchainLibrary` proof verification helper for custom validators |
| `com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec` | `SnarkjsToCardano`, `ProverToCardano` | Working off-chain helpers | Convert snarkjs and ZeroJ Groth16 artifacts to Cardano-compatible compressed bytes and Plutus data shapes |
| `com.bloxbean.cardano.zeroj.onchain.julc.plonk.lib` | `PlonkBLS12381Lib` | Experimental opt-in on-chain library | Reusable `@OnchainLibrary` PlonK verification helper for custom validators; supports one-input and bounded MPI Cardano profiles |
| `com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator` | `PlonkBLS12381Verifier` | Experimental opt-in validator | Cardano-profile compressed-transcript verifier with full KZG batch-opening pairing check for the current one-public-input shape; third-party audit still pending |
| `com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator` | `PlonkBLS12381MultiInputVerifier` | Experimental opt-in validator | Bounded MPI Cardano profile verifier for `1..8` datum-supplied public inputs with profile/count transcript binding and verified inverse witnesses; third-party audit still pending |
| `com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator` | `PlonkBLS12381MultiInputParamVerifier` | Experimental opt-in validator | Bounded MPI Cardano profile verifier for `1..8` script-parameter public inputs; use when statement values should be pinned by the script hash |
| `com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec` | `PlonKProverToCardano` | Working off-chain helper | Converts ZeroJ BLS12-381 PlonK proofs/VKs to compressed Cardano redeemer/parameter bytes |
| `com.bloxbean.cardano.zeroj.onchain.julc.bbs.lib` | `BbsHashToScalar` | Working on-chain library | Reusable `@OnchainLibrary` BBS `hash_to_scalar` (`expand_message_xmd(SHA-256)`); ciphersuite-generic, composable by any BBS validator |
| `com.bloxbean.cardano.zeroj.onchain.julc.bbs.lib` | `BbsProofVerify` | Working on-chain library (fixed profile) | Reusable `@OnchainLibrary` native BBS `ProofVerify` (T1/T2 + Fiat–Shamir challenge + pairing) for the SHA-256 ciphersuite. Current profile: 5-message credential disclosing 2 (~2.4×10⁹ CPU / 0.18M mem); arbitrary-disclosure generalization tracked as follow-up |
| `com.bloxbean.cardano.zeroj.onchain.julc.analysis` | `ScriptBudgetEstimator`, `OnChainFeasibility` | Planning helpers | Estimate Plutus CPU/memory budgets and report proof system / curve feasibility |
| `com.bloxbean.cardano.zeroj.onchain.julc.deployment` | `ReferenceScriptDeployer` | Config helper | Describes CIP-0033 reference-script deployment patterns; does not submit transactions |

## Why It Is Useful

- Bridges ZeroJ off-chain proof generation with Cardano on-chain verification.
- Keeps Groth16 BLS12-381 as the reliable Plutus V3 path.
- Provides reusable Groth16, PlonK, and BBS `@OnchainLibrary` helpers for custom
  validators that need application-specific policy.
- Adds native on-chain **BBS selective-disclosure** verification (`BbsProofVerify`)
  and its `hash_to_scalar` primitive, paired with the `BbsToCardano` off-chain
  codec in `zeroj-bbs`.
- Makes PlonK status explicit and measurable without overstating production
  readiness.
- Provides budget and deployment metadata for applications using CCL or other
  Cardano transaction builders.

## Testing

```bash
./gradlew :zeroj-onchain-julc:test
```

The tests run validators in the Julc VM and include Groth16 positive/negative
checks, pure Java Groth16 prover to on-chain verification, budget estimation,
test-scope PlonK transcript regression coverage, deployable-source guardrails,
and the reusable PlonK library plus Cardano-profile PlonK verifier
positive/negative/budget gates, including the bounded MPI profile for 1, 2, 4,
and 8 public inputs and the script-parameter MPI variant. The BBS gadgets are
differential-tested against `zeroj-bbs`: `hash_to_scalar` byte-exactness across
message shapes (`BbsHashToScalarVmTest`) and the full `ProofVerify`
accept/tampered-header paths against a real presentation
(`BbsProofVerifyVmTest`).

## Imports

Use package names by role:

```java
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator.Groth16BLS12381Verifier;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator.Groth16BLS12381TxOutRefBindingVerifier;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.lib.PlonkBLS12381Lib;
import com.bloxbean.cardano.zeroj.onchain.julc.bbs.lib.BbsHashToScalar;
import com.bloxbean.cardano.zeroj.onchain.julc.bbs.lib.BbsProofVerify;
// off-chain codec (zeroj-bbs):
import com.bloxbean.cardano.zeroj.bbs.cardano.BbsToCardano;
```

Custom validators should define their own local redeemer record, compose the
shared library, and enforce the `ScriptContext` policy needed by the
application. The bare verifier below is crypto-only and should not be used by
itself to protect value:

```java
@SpendingValidator
public class MyVerifier {
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        return Groth16BLS12381Lib.verify(datum, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }
}
```

The proof record is kept validator-local because Julc record decoding is
validator-local today. Sharing `Groth16BLS12381Lib` still avoids duplicating the
pairing and public-input folding logic.

## BBS selective disclosure (on-chain)

`BbsProofVerify` verifies a **BBS presentation natively on-chain** — proof that an
issuer signed a set of attributes while revealing only a chosen subset, with the
undisclosed attributes staying hidden. `BbsHashToScalar` is the reusable
`hash_to_scalar` primitive it (and any other BBS validator) composes.

The off-chain half lives in `zeroj-bbs` as
`com.bloxbean.cardano.zeroj.bbs.cardano.BbsToCardano`: it derives the issuer
verification material (validator `@Param`s) and flattens a `BbsPresentation` into
the redeemer values. End-to-end:

```java
// --- off-chain (application JVM), using zeroj-bbs ---
var bbs   = BbsService.pureJava();
var kp    = bbs.keyPair(keyMaterial, issuerId);
var sig   = bbs.sign(kp.secretKey(), kp.publicKey(), messages, header);   // 5 attributes
var pres  = bbs.derivePresentation(kp.publicKey(), sig, messages, header,
                                   presentationHeader, new int[] {2, 3}); // reveal country+kycLevel

var params = BbsToCardano.verifierParams(kp.publicKey(), header, messages.size());
var proof  = BbsToCardano.onChainProof(pres);
// params.* → validator @Param bytes;  proof.* → redeemer fields

// --- on-chain: a custom validator composing BbsProofVerify ---
@SpendingValidator
public class MyBbsClaim {
    @Param static byte[] w, bp2, p1, q1, h0, h1, h2, h3, h4, domainBytes, dstH2S, dstMap;
    record Claim(byte[] abar, byte[] bbar, byte[] d,
                 BigInteger eHat, BigInteger r1Hat, BigInteger r3Hat,
                 BigInteger mHat0, BigInteger mHat1, BigInteger mHat2, BigInteger c,
                 byte[] msg2, byte[] msg3, byte[] ph) {}

    @Entrypoint
    static boolean validate(ClaimDatum datum, Claim r, ScriptContext ctx) {
        boolean proofOk = BbsProofVerify.verify(
                w, bp2, p1, q1, h0, h1, h2, h3, h4,
                Builtins.byteStringToInteger(true, domainBytes), dstH2S, dstMap,
                r.abar(), r.bbar(), r.d(),
                r.eHat(), r.r1Hat(), r.r3Hat(), r.mHat0(), r.mHat1(), r.mHat2(), r.c(),
                r.msg2(), r.msg3(), r.ph());
        // ...then your own policy: disclosed values match the datum, payout, and bind `ph`
        //    to the spend so a captured presentation can't be replayed.
        return proofOk && /* policy */ true;
    }
}
```

**Profile note.** `BbsProofVerify.verify` is unrolled for a 5-message credential
disclosing indexes `{2,3}` (undisclosed `{0,1,4}`) — Plutus has no cheap dynamic
loop, so the disclosure shape is fixed for ExUnits efficiency. Other
`(L, disclosed-set)` shapes compose the same primitive with a different unrolling;
a parameterised arbitrary-disclosure variant is the tracked follow-up. A worked
claim validator (policy + payout + replay-safe `ph` binding to the spent UTxO) is
in `zeroj-usecases` reusable-kyc.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-onchain-julc'
}
```
