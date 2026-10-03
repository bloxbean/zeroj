# Migration 0051: hiding-safe Pedersen API

ADR-0051 decision D2 (milestone M1) changes the Pedersen circuit API so a circuit can no
longer declare a blinding that cannot hide. This is a breaking change for any circuit that
used a narrow blinding, or the removed shared-width overloads.

## Why

A Pedersen commitment `C = [v]·G + [r]·H` hides `v` only if `r` is a full-entropy scalar. A
circuit that declares a `k`-bit blinding forces every honest committer to use one. Anyone can
then recover `(v, r)` from the public commitment by trying `2^k` blindings for each candidate
value. At 16 bits this takes seconds (see `PedersenHidingSafeApiTest`).

## What changed

| Before | After |
|---|---|
| `ZkPedersen.commit(zk, value, blinding, scalarBits)` | removed; use `ZkPedersen.commit(zk, value, blinding)` |
| `ZkPedersen.verifyOpening(zk, c, value, blinding, scalarBits)` | removed; use `verifyOpening(zk, c, value, blinding)` |
| `InCircuitPedersen.commit(api, value, blinding, numBits)` | replaced by `InCircuitPedersen.commit(api, value, valueBits, blinding)` |
| any blinding width | the blinding must be exactly **252** bits (`ZkPedersen.BLINDING_BITS`) |
| any blinding wire | a blinding that is directly a public input or a circuit constant is rejected |
| — | new `PedersenCommitment.randomBlinding(SecureRandom)` |

The value keeps its own declared width (1–252), which is also its range proof.

All new checks run at circuit-definition time and throw `IllegalArgumentException`.

## How to migrate

1. Declare the blinding at 252 bits:

   ```java
   @Secret @UInt(bits = 64)  ZkUInt amount,
   @Secret @UInt(bits = 252) ZkUInt blinding,
   ...
   ZkPedersen.commit(zk, amount, blinding)
   ```

2. Sample the blinding off-circuit with `PedersenCommitment.randomBlinding(new SecureRandom())`.
   Like `PedersenCommitment.commit`, it uses variable-time `BigInteger` arithmetic on a secret,
   so run it offline or in an isolated process (ADR-0038).

3. Regenerate keys for any circuit whose blinding width changed: its constraint system is
   different. A circuit that already used a 252-bit blinding through the two-argument `commit`
   keeps an identical constraint system (pinned in `PedersenHidingSafeApiTest`).

## What the provenance check does not do

It rejects only a blinding wired *directly* to a public input or a constant. A secret or
intermediate wire derived from public data passes. Hiding still depends on the committer
sampling a fresh, uniform blinding.
