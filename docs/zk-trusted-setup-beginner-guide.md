# ZK Trusted Setup Beginner Guide

This guide explains the words that appear around Groth16 and PlonK setup:
`tau`, `Powers of Tau`, `SRS`, `phase 1`, `phase 2`, proving keys, verifying
keys, and BLS12-381 curve points.

It is intentionally beginner-friendly. It avoids most algebra and focuses on
what a developer needs to understand before using the ZeroJ proving stack.

## 30-Second Summary

For Groth16 and PlonK, proof generation needs setup artifacts.

The common setup artifact is usually called **Powers of Tau** or a **universal
SRS**. It is generated once for a curve and a maximum circuit size, then reused
for many circuits.

```text
Powers of Tau / universal SRS
  common, reusable, expensive/trusted setup artifact
```

Groth16 and PlonK differ in what happens after that:

```text
Groth16:
  common Powers of Tau
  + circuit-specific trusted phase 2 setup
  = proving key + verifying key for one circuit

PlonK:
  common Powers of Tau / KZG SRS
  + circuit-specific public setup
  = proving key + verifying key/material for one circuit
```

The important difference:

```text
Groth16 has a circuit-specific trusted setup step.
PlonK reuses the universal trusted setup and does not need a new ceremony per circuit.
```

## What Is BLS12-381?

`BLS12-381` is an elliptic curve used by many pairing-based proof systems.

For ZeroJ and Cardano, BLS12-381 matters because Cardano Plutus V3 has
BLS12-381 builtins. That makes BLS12-381 the practical curve for Cardano
on-chain verification. BN254 can still be useful off-chain, but Cardano does not
currently provide BN254 pairing builtins.

You will see these terms:

| Term | Beginner meaning |
| --- | --- |
| Field element | A number modulo a large prime. Circuit values, public inputs, and secret witness values are usually field elements. |
| Scalar | A field element used to multiply a curve point. |
| Curve point | A point on the elliptic curve. It is not just a normal `(x, y)` point from school geometry; it belongs to a cryptographic group. |
| G1 | One BLS12-381 curve group. Groth16 and PlonK proofs contain G1 points. |
| G2 | Another BLS12-381 curve group. Verifying keys and setup artifacts often contain G2 points. |
| Pairing | A special operation that checks relationships between G1 and G2 points. Groth16 and PlonK verification rely on pairings. |

A curve point can be multiplied by a scalar:

```text
scalar * G1_point = another G1 point
```

For example:

```text
tau * G1
tau^2 * G1
tau^3 * G1
```

These are public curve points. The secret number `tau` should not be known.

## What Is Tau?

`tau` is a secret random number used during setup.

You can think of it as a hidden ingredient used to create many public curve
points:

```text
G1
tau * G1
tau^2 * G1
tau^3 * G1
...

G2
tau * G2
```

The public sees the curve points. The public must not know `tau`.

Why? Because if someone knows `tau`, they may be able to create fake proofs for
systems that rely on that setup. This secret is often called **toxic waste**.

Production setup ceremonies are designed so that no one person knows the final
`tau`. A multi-party ceremony lets many people contribute randomness. If at
least one participant honestly destroys their secret contribution, the final
setup can be safe.

## What Is Powers of Tau?

**Powers of Tau** is the setup output containing powers of the hidden `tau`.

It is called "powers" because it contains values based on:

```text
tau^0, tau^1, tau^2, tau^3, ...
```

In curve-point form, that looks like:

```text
[tau^0]G1, [tau^1]G1, [tau^2]G1, [tau^3]G1, ...
[tau^0]G2, [tau^1]G2, ...
```

The notation `[x]G1` means "multiply the G1 generator point by scalar `x`."

The Powers of Tau artifact is usually stored in a file such as `.ptau`.

## Why Is Powers of Tau Called an SRS?

`SRS` means **Structured Reference String**.

Breakdown:

| Word | Meaning |
| --- | --- |
| Structured | The values follow a mathematical pattern, such as powers of `tau`. |
| Reference | Provers and verifiers both reference these public parameters. |
| String | Cryptography often calls a sequence of bytes or values a string. |

So Powers of Tau is an SRS because it is a public set of structured parameters:

```text
G1, tau*G1, tau^2*G1, ...
G2, tau*G2, ...
```

People use "SRS" in two common ways:

| Phrase | Usually means |
| --- | --- |
| Universal SRS | The common Powers of Tau / KZG setup reused across circuits. |
| Circuit-specific setup | Proving/verifying key material derived for one circuit. Some people also loosely call this setup material an SRS. |

In ZeroJ docs, "SRS" usually means the common Powers of Tau style artifact
unless the text explicitly says circuit-specific setup.

## Can One Powers of Tau Be Used for Many Circuits?

Yes, if the circuits are compatible with it.

A Powers of Tau artifact is reusable when these are the same:

- curve, for example `BLS12-381`
- proof-system commitment assumptions, for example KZG-style setup
- maximum supported circuit size is large enough
- ceremony artifact is trusted and pinned

If a Powers of Tau has size `2^20`, it can support circuits up to that setup's
supported size. If your circuit becomes larger than the SRS supports, you need a
larger Powers of Tau artifact.

You do not create a new Powers of Tau for every circuit in production.

## Groth16 Setup, in Plain Language

Groth16 has two setup phases.

### Groth16 Phase 1: Powers of Tau

Phase 1 is common and reusable.

```text
Powers of Tau for BLS12-381
  -> reusable across many Groth16 circuits up to the supported size
```

This is the universal starting point.

### Groth16 Phase 2: Circuit-Specific Setup

Phase 2 is specific to one circuit.

```text
Powers of Tau
  + Circuit A
  -> Proving key A
  -> Verifying key A

Powers of Tau
  + Circuit B
  -> Proving key B
  -> Verifying key B
```

If Circuit A changes, its Groth16 phase 2 setup must be redone.

In standard Groth16, this circuit-specific setup is also trusted. That means it
can introduce circuit-specific toxic waste. A production Groth16 phase 2 should
therefore use an audited setup flow or ceremony.

### Groth16 Artifacts

| Artifact | Reused? | Safe to publish? | Notes |
| --- | --- | --- | --- |
| Powers of Tau | Yes, across compatible circuits | Yes | But the hidden `tau` must not be known. |
| Proving key | Yes, for the same circuit | Usually not secret, but large and operationally sensitive | Used by prover to create proofs. |
| Verifying key | Yes, for the same circuit | Yes | Used by verifier or embedded in on-chain validator parameters. |
| Proof | No | Yes | Generated per witness/user/action. |
| Witness | No | No | Contains private inputs. |

## PlonK Setup, in Plain Language

PlonK also uses a common Powers of Tau / KZG SRS.

The difference is that PlonK is designed around a **universal setup**:

```text
One trusted Powers of Tau / KZG SRS
  -> many PlonK circuits
```

Each PlonK circuit still needs circuit-specific material, but that material is
computed from public circuit information and the SRS. It does not require a new
toxic-waste ceremony per circuit.

For example, a PlonK circuit setup may create:

- selector polynomial commitments
- permutation polynomial commitments
- proving key material
- verifying key material

These are circuit-specific, but they are not a new trusted ceremony in the same
way Groth16 phase 2 is.

### PlonK Artifacts

| Artifact | Reused? | Safe to publish? | Notes |
| --- | --- | --- | --- |
| Powers of Tau / KZG SRS | Yes, across compatible circuits | Yes | If the hidden `tau` is compromised, all circuits using it are at risk. |
| PlonK proving key | Yes, for the same circuit/profile | Usually not secret, but large and operationally sensitive | Used by prover. |
| PlonK verifying key/material | Yes, for the same circuit/profile | Yes | Must match the exact circuit statement being verified. |
| Proof | No | Yes | Generated per witness/user/action. |
| Witness | No | No | Contains private inputs. |

## Groth16 vs PlonK Setup

| Question | Groth16 | PlonK |
| --- | --- | --- |
| Uses Powers of Tau? | Yes, as phase 1 | Yes, as universal/KZG SRS |
| Is Powers of Tau common across circuits? | Yes | Yes |
| Needs circuit-specific setup? | Yes | Yes |
| Does the circuit-specific setup need a new trusted ceremony? | Yes, in standard Groth16 | No, assuming the universal SRS is trusted |
| If the circuit changes? | Redo phase 2 setup | Recompute circuit-specific keys/material |
| If public input values change? | No setup change | No setup change |
| If witness values change? | No setup change | No setup change |
| Main benefit | Very small proofs and efficient verification | Universal setup, easier circuit iteration |
| Main setup drawback | Per-circuit trusted setup | Universal SRS must be trusted by every circuit using it |

The shortest version:

```text
Groth16 = common phase 1 + circuit-specific trusted phase 2
PlonK   = common trusted SRS + circuit-specific public setup
```

## What Changes Require New Setup?

Changing these usually requires new circuit-specific setup:

- circuit constraints
- circuit gates
- number or ordering of public inputs
- domain size
- proving system profile
- curve
- SRS size if the circuit no longer fits

Changing these does not require new setup:

- private witness values
- public input values
- user account data
- generated proof bytes
- transaction id

Example:

```text
Same circuit, new user balance:
  no new setup
  generate a new proof

Changed circuit logic:
  new circuit-specific setup
  then generate proofs against the new keys
```

## What Is Cached?

Setup is expensive, so applications should cache setup artifacts.

ZeroJ exposes two public setup-cache classes:

- `Groth16SetupCache`
- `PlonkSetupCache`

It can cache:

| ZeroJ cache API | What it caches |
| --- | --- |
| `Groth16SetupCache.saveBls12381Srs(...)` / `loadBls12381Srs(...)` | BLS12-381 Powers of Tau / SRS for Groth16 phase-1 reuse |
| `Groth16SetupCache.saveBls12381Setup(...)` / `loadBls12381Setup(...)` | Groth16 BLS12-381 circuit-specific phase-2 setup |
| `PlonkSetupCache.saveBls12381Srs(...)` / `loadBls12381Srs(...)` | BLS12-381 Powers of Tau / KZG SRS for PlonK reuse |
| `PlonkSetupCache.saveBls12381ProvingKey(...)` / `loadBls12381ProvingKey(...)` | PlonK BLS12-381 circuit-specific proving key |

Cache files are authenticated and re-validated on load. ZeroJ binds the cache
payload to a SHA-256 digest, checks cached BLS12-381 points are on curve and in
the correct subgroup, and re-checks SRS pairing consistency for Powers of Tau /
SRS material. Subgroup validation uses projective/Jacobian point arithmetic so
the checks remain practical for larger proving keys.

It does not cache:

- private witnesses
- generated proofs
- user secrets
- toxic waste such as `tau` in the default public cache APIs
- Cardano transactions
- on-chain verification results

Caching only avoids recomputation. It does not make setup trusted, and it does
not replace pinning the original ceremony artifact or verifying its source.

## Do Custom Apps Need To Do Anything Special?

Yes. A custom app must choose how to load, create, and cache setup artifacts.

At a high level:

```text
1. Compile the circuit.
2. Build a stable setup cache key.
3. Try to load setup/proving key from cache.
4. If missing, load trusted SRS and run setup.
5. Save setup/proving key to cache.
6. For each user/action, calculate witness and generate a proof.
```

A good cache key should include:

- proof system, for example `Groth16` or `PlonK`
- curve, for example `BLS12-381`
- circuit name and version
- circuit shape, constraints, gates, or a circuit hash
- number and order of public inputs
- SRS identity or SRS hash
- setup profile, such as domain size or PoT power

If any of these changes, do not reuse the old circuit-specific setup.

Applications should also verify that a loaded setup matches the circuit they just
compiled. At minimum, check the expected wire count and public-input count before
reusing a cached Groth16 setup or PlonK proving key. For production deployments,
pin a circuit hash, SRS hash, and verifying-key hash in addition to these shape
checks.

## Development vs Production

ZeroJ includes helpers such as:

```java
PowersOfTauBLS381.generate(...)
```

This is for development and testing only. It creates a single-party setup where
the local process knows `tau`. That is not acceptable for value-bearing
production systems. ZeroJ disables this by default; local tests or demos must
explicitly opt in with:

```text
-Dzeroj.allowInsecureTrustedSetup=true
```

For production:

- use a trusted multi-party ceremony artifact
- pin the artifact hash
- record the ceremony source and verification procedure
- cache setup artifacts after verifying them
- pin verifying keys or script parameters
- do not rely on locally generated toxic waste

Default `saveBls12381Srs(...)` cache files do not store `tauScalar`. If a local
development flow really needs to persist `tau`, use the explicitly named
`saveBls12381InsecureDevSrsWithTau(...)` method and treat that file as an unsafe
test artifact only.

## Cardano-Specific Note

For Cardano on-chain verification, the practical curve is currently BLS12-381
because Plutus V3 provides BLS12-381 builtins.

That means a Cardano-oriented ZeroJ application should usually target:

```text
BLS12-381 + Groth16
```

or, when the PlonK verifier profile is appropriate for the application:

```text
BLS12-381 + PlonK
```

BN254 can be useful for off-chain ecosystems, but it is not a current Cardano
on-chain target in ZeroJ because Cardano does not provide BN254 pairing builtins.

## Mental Model

Use this simple model:

```text
SRS / Powers of Tau:
  shared public setup material
  generated once for curve + size

Groth16 phase 2:
  circuit-specific trusted setup
  redo when circuit changes

PlonK circuit setup:
  circuit-specific public setup
  redo when circuit changes

Witness:
  private inputs for one proof
  never cached as setup

Proof:
  generated for one witness
  verified off-chain or on-chain
```

The most important rule:

```text
Do not regenerate setup per proof.
Generate or load setup once, cache it, and generate a new proof for each witness.
```
