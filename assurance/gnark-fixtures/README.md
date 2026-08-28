# gnark fixture generator (assurance only)

Pinned **gnark v0.14.0** PlonK BLS12-381 test-vector generator, preserved by
[ADR-0044](../../docs/adr/0044-focused-module-surface-and-optional-provider-isolation.md).

## Why this exists

ADR-0044 removes `zeroj-prover-gnark` — the Java/FFM Groth16 and PlonK runtime
provider — because both proof systems now have Java product paths and no use case
consumes the binding.

The gnark *implementation* still supplies assurance value that nothing else in
the repository does. Two tests in the default build depend on artifacts produced
by this generator:

| Test | What the gnark fixture proves |
|---|---|
| `zeroj-verifier-plonk` → `GnarkTranscriptCompatTest` | ZeroJ's Fiat-Shamir transcript derives **byte-identical** gamma, beta, alpha and zeta challenges to gnark's verifier. |
| `zeroj-verifier-plonk` → PlonK BLS12-381 vector tests | ZeroJ's pure-Java PlonK verifier accepts a proof produced by an independent implementation. |

Those vectors are committed under
`zeroj-test-vectors/src/main/resources/test-vectors/plonk-bls12381/`, so the
evidence survives without Go. This directory keeps that evidence **reproducible**
rather than merely asserted.

## What this is not

- Not a runtime provider. It builds no shared library and exposes no Java FFM API.
- Not part of the Gradle build, the default build, any BOM, or any published artifact.
- Not required to build or test ZeroJ. `./gradlew build` needs no Go toolchain.

## Usage

```bash
# emit a fresh independent gnark v0.14.0 proof into build/vectors
make gen-scratch

# regenerate the committed vectors in place
make gen
```

**The output is not byte-reproducible.** The PlonK setup uses gnark's
`unsafekzg` test SRS, which is randomized per run, so every invocation emits a
different SRS and a different proof. A `git diff` after `make gen` is expected
and is not a regression.

The assurance property is therefore not "the bytes match". It is:

> an artifact produced by an implementation ZeroJ does not control is still
> accepted by ZeroJ's pure-Java PlonK verifier, and still yields the same
> Fiat-Shamir challenges.

Check that on the Java side after regenerating:

```bash
make gen
cd ../.. && ./gradlew :zeroj-verifier-plonk:test
```

A failure there is a real finding — either ZeroJ's verifier or transcript
diverged from gnark, or the pinned gnark version changed behavior. Investigate
before committing regenerated vectors.

Circuit: `Multiplier` — proves knowledge of X, Y with X * Y = Z, Z public
(3 * 11 = 33). SRS is `unsafekzg`, test-only, and must never be treated as a
ceremony artifact.
