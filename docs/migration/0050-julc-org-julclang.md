# Migration 0050: JuLC `0.1.0-pre18` and `org.julclang`

[ADR-0050](../adr/0050-julc-pre17-org-julclang-and-typed-bls.md) moves `zeroj-onchain-julc` from
JuLC `0.1.0-pre16` to `0.1.0-pre18`, starting with ZeroJ `0.1.0-pre12`. JuLC `0.1.0-pre17` changed
its Maven group, package root and Gradle plugin id, gave BLS12-381 values their own types, and
started rejecting overloaded methods. `0.1.0-pre18` is `0.1.0-pre17` plus a Gradle-plugin fix and
compiles the same bytes. Use `0.1.0-pre18`.

Off-chain code does not change. `ProverToCardano`, `SnarkjsToCardano`, `PlonKProverToCardano`
and the verification-key codec produce the same bytes. The redeemer, datum and parameter
encodings are the same. Proofs, keys, transcripts, domain separators and public-input order are
unchanged. No maturity, audit or production claim is upgraded.

On-chain code **does** change: compiled validators have new bytes, script hashes and costs. See
[New script hashes](#new-script-hashes).

## Who needs to act

You need to act if your project does any of these:

- compiles its own validators with JuLC;
- calls ZeroJ's on-chain libraries (`Groth16BLS12381Lib`, `PlonkBLS12381Lib`, `BbsProofVerify`,
  `BbsHashToScalar`) from a validator;
- deploys ZeroJ's validators, or builds authenticated-state release manifests.

Your JuLC compiles the ZeroJ libraries' source, and that source now uses the pre17 BLS types, so
ZeroJ `0.1.0-pre12` needs JuLC `0.1.0-pre18`. If you only prove and verify off-chain, nothing
changes for you.

## 1. Coordinates

| Before | After |
|--------|-------|
| `com.bloxbean.cardano:julc-*:0.1.0-pre16` | `org.julclang:julc-*:0.1.0-pre18` |
| `com.bloxbean.cardano:julc-gradle-plugin` | `org.julclang:julc-gradle-plugin` |
| `plugins { id 'com.bloxbean.cardano.julc' }` | `plugins { id 'org.julclang.julc' }` |
| `import com.bloxbean.cardano.julc.…` | `import org.julclang.…` (subpackages unchanged) |

```bash
# Maven coordinates (build files)
grep -rl 'com\.bloxbean\.cardano:julc-' . | xargs sed -i '' 's#com\.bloxbean\.cardano:julc-#org.julclang:julc-#g'
# plugin id and packages
grep -rl 'com\.bloxbean\.cardano\.julc' . | xargs sed -i '' \
  -e "s#'com\.bloxbean\.cardano\.julc'#'org.julclang.julc'#g" \
  -e 's#com\.bloxbean\.cardano\.julc\.#org.julclang.#g'
```

On GNU `sed` (Linux), drop the `''` after `-i`. Then set the JuLC version to `0.1.0-pre18`.
Cardano Client Lib keeps `com.bloxbean.cardano`, so don't replace that group wholesale.

## 2. `publicInputs` builders

`Groth16BLS12381Lib.publicInputs(...)` had six overloads, one for each count of 1 to 6 public
inputs. They are now separate methods: `publicInputs1(pub0)` through
`publicInputs6(pub0, …, pub5)`.

JuLC compiles calls by method name. With JuLC `0.1.0-pre16`, every call ran the **last**
overload, the 6-input one. ZeroJ reproduced this for ADR-0050: a validator that called
`publicInputs` with 1, 2 or 3 inputs failed at evaluation and rejected every spend. The 6-input
call worked. The failure rejected spends rather than accepting them, but a validator using it
with fewer than 6 inputs could never be spent. JuLC `0.1.0-pre17` rejects overloads
(`JULC0054`).

## 3. Typed BLS12-381 values

If your validator holds uncompressed points or Miller-loop results, change their declared type
from `byte[]`:

| Value | Type (`org.julclang.core.types`) |
|-------|------|
| G1 point: `*_G1_uncompress`, `*_G1_add`, `*_G1_neg`, `*_G1_scalarMul`, `*_G1_hashToGroup` | `JulcG1` |
| G2 point: the same operations on G2 | `JulcG2` |
| `bls12_381_millerLoop`, `bls12_381_mulMlResult` | `JulcMlResult` |

`var` also works. Compressed points stay `byte[]`: parameters, datum and redeemer fields, and
`*_compress` results. JuLC reports `JULC0041` where a `byte[]` still holds a point, and `JULC0042`
for a point at a validator boundary. Helper methods that take or return points need the same
change in their signatures.

JuLC `0.1.0-pre17` also rejects a few other shapes that earlier versions miscompiled, including
compound assignment in loops, multi-variable declarations and field updates in loops. Its release
notes list each diagnostic with its fix.

## 4. The Gradle plugin's `compileJulc` task

Use `0.1.0-pre18`, not `0.1.0-pre17`. The `compileJulc` task compiles validator Java sources kept in
`src/main/plutus`. In `0.1.0-pre17` it fails `build` when that directory doesn't exist, even if
your validators are in `src/main/java` and compiled by the annotation processor, as ZeroJ's are
([bloxbean/julc#216](https://github.com/bloxbean/julc/issues/216)). `0.1.0-pre18` skips the task
again, as `0.1.0-pre16` did, so no workaround is needed.

## New script hashes

JuLC `0.1.0-pre17` optimizes differently from `0.1.0-pre16`, and `0.1.0-pre18` compiles the same
bytes as `0.1.0-pre17`. Recompiled validators have new bytes even where their source is unchanged.
All six ZeroJ validators are now 5 to 292 bytes smaller. A new script means a new script hash and a
new address:

- Scripts already on-chain keep working. On-chain bytes never change.
- Redeploy reference scripts, and use the new addresses for new locks.
- Regenerate authenticated-state release manifests. They now bind
  `julc-0.1.0-pre18/plutus-v3`, and an older bundle is refused rather than relabelled.
- Re-measure your budgets. ZeroJ measured Groth16 and PlonK spends at 0.6–3% less CPU and 20–31%
  less memory. BBS got more expensive: `hash_to_scalar` uses 17% more CPU and 37% more memory, and
  `ProofVerify` 17% more memory.

ADR-0050 records the evidence: identical accept/reject verdicts on pre16 and pre17 for all 84
on-chain test checks, per-validator sizes, costs measured on a Yaci DevKit node, and byte-identical
scripts from pre17 and pre18.
