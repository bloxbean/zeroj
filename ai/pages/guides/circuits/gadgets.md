# Gadget library

> The circuit building blocks in zeroj-circuit-lib (hashes, Merkle proofs, ranges, Jubjub, and Cardano key derivation), with status and cost.

Canonical URL: https://zeroj.dev/guides/circuits/gadgets/

A *gadget* is a reusable piece of circuit: a hash, a Merkle path check, a comparison. ZeroJ's
gadgets live in `zeroj-circuit-lib`. Reusing them saves you from re-deriving constraint systems
that already have tests, but each one has a field it works in, a cost, and a maturity status.
This page catalogs them and ends with rules for choosing gadgets for Cardano.

```groovy
implementation 'org.zeroj:zeroj-circuit-lib'   // version from zeroj-bom-core
```

## Three API flavors

Most gadgets come in up to three shapes, one per [authoring style](https://zeroj.dev/guides/circuits/circuit-dsl/#which-layer-should-you-use):

| Flavor | Package | Example | Used from |
|--------|---------|---------|-----------|
| `Zk*` adapters | `org.zeroj.circuit.lib.zk` | `ZkPoseidon.hash(zk, params, a, b)` | Annotated circuits |
| `Signal*` helpers | `org.zeroj.circuit.lib` | `SignalPoseidon.hash(c, params, a, b)` | `CircuitSpec` / `defineSignals` |
| `CircuitAPI` gadgets | `org.zeroj.circuit.lib` | `Poseidon.hash(api, params, a, b)` | Inline `define(api -> ...)` |

The `Zk*` adapters delegate to the same underlying gadgets and reject values that belong to a
different circuit.

## Hashing: Poseidon

Poseidon is the hash to use inside Cardano circuits. It's designed for arithmetic circuits: a
two-input hash compiles to roughly 240 R1CS constraints on BLS12-381 with the current compiler,
while bit-oriented hashes such as SHA-512 cost around a hundred thousand per block.

**Always pass BLS12-381 parameters explicitly.** The no-parameter overloads use BN254 constants
for backward compatibility. If you mix them with a BLS12-381 compile, `CircuitBuilder` refuses to
compile, but the explicit form keeps the intent obvious.

```java
// Two inputs (in-circuit)
ZkField h = ZkPoseidon.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, left, right);

// N inputs, folded pairwise (in-circuit)
ZkField c = ZkPoseidonN.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, owner, assetId, nonce);

// The same values off-circuit, for commitments and expected public inputs
BigInteger h2 = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, a, b);
BigInteger c2 = PoseidonHash.hashN(PoseidonParamsBLS12_381T3.INSTANCE, owner, asset, nonce);
```

`PoseidonN` / `ZkPoseidonN` is a left fold of the two-input hash, not a wider Poseidon
permutation, so its outputs differ from a native `t = N + 1` Poseidon. `ZkPoseidonN` has no
no-parameter overload at all. `PoseidonHash` is host-side code: it computes values, it doesn't
constrain anything.

**MiMC is BN254-only.** `MiMC`, `SignalMiMC`, `ZkMiMC` and `MiMCSponge` require the BN254 field
and refuse to compile for BLS12-381. Treat them as legacy, off-chain gadgets.

## Merkle membership

`ZkMerkle` proves that a leaf sits under a public root. For Cardano, use the
params-aware Poseidon helpers:

```java
@ZKCircuit(name = "allowlist", nameTemplate = "allowlist-d{depth}")
public class Allowlist {
    public Allowlist(@CircuitParam("depth") int depth) {
    }

    @Prove
    ZkBool prove(ZkContext zk,
                 @Secret ZkField leaf,
                 @Public ZkField root,
                 @Secret @FixedSize(param = "depth") ZkArray<ZkField> siblings,
                 @Secret @FixedSize(param = "depth") ZkArray<ZkBool> pathBits) {
        return ZkMerkle.isMemberPoseidon(zk, PoseidonParamsBLS12_381T3.INSTANCE,
                leaf, root, siblings, pathBits);
    }
}
```

`isMemberPoseidon` returns a `ZkBool`, `verifyPoseidon` asserts directly, and
`computeRootPoseidon` returns the root for further use. Path bits are constrained boolean:
bit `0` means the current node is the left child (`hash(current, sibling)`), and `1` means it's
the right child (`hash(sibling, current)`). Build the matching root off-circuit with the same
convention:

```java
BigInteger current = leaf;
for (int i = 0; i < siblings.size(); i++) {
    current = pathBits.get(i).signum() == 0
            ? PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, current, siblings.get(i))
            : PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, siblings.get(i), current);
}
```

`ZkMerkle.HashType.MIMC` and the enum `HashType.POSEIDON` path are BN254-oriented conveniences.
Avoid them for Cardano. For large, updatable state (millions of entries, inclusion and
non-inclusion, updates), see the experimental Poseidon MPF/JMT modules in
[Authenticated state](https://zeroj.dev/guides/credentials/authenticated-state/).

## Comparisons and ranges

For annotated circuits, `ZkUInt` is the comparator: `@UInt(bits = N)` adds the range check, and
`lt`, `lte`, `gt`, `gte`, and `inRange(lo, hi)` compare. At the Signal level, use
`SignalComparators` (`lessThan`, `lessOrEqual`, `greaterThan`, `greaterOrEqual`, `inRange`,
`min`, `max`), or `Comparators` for raw `Variable`s.

```java
Signal ok = SignalComparators.greaterOrEqual(c, balance, threshold, 64);
c.assertEqual(ok, c.constant(1));
```

A comparison over `n` bits range-checks **both** operands to `n` bits, and rejects a constant
operand that doesn't fit when the circuit is defined. Widths must stay below 253 bits. Size `n`
to the real domain of your values; an oversized width costs constraints, and an undersized one
makes honest witnesses fail.

## Bits, selection and aliasing

| Need | Use |
|------|-----|
| Decompose or recompose bits | `SignalBinary.num2Bits` / `bits2Num`, `Binary.*`; `ZkBits` for fixed bit-vector inputs |
| Bitwise logic | `SignalBinary.bitAnd/bitOr/bitXor`, `rotateLeft` (a free re-indexing) |
| Choose between values | `ZkBool.select(a, b)`; `Mux.mux1`, `Mux.mux2` |
| Dynamic array lookup | `Mux.arrayAccess(api, array, index)` or `SignalBuilder.arrayAccess` (cost grows with length) |
| Canonical field representation | `AliasCheck.check(c, value, nBits)`, a decomposition that proves `value < 2^nBits` |

## Jubjub, Pedersen and EdDSA

Jubjub is an elliptic curve defined over the BLS12-381 scalar field, so its arithmetic is cheap
inside BLS12-381 circuits. These gadgets require `CurveId.BLS12_381`. Their in-circuit
verification side is marked ready pending external review; the off-circuit secret operations
have tighter restrictions (see the status table).

**Bind every prover-supplied point.** `ZkJubjubPoint.witnessAffine(zk, u, v)` asserts the curve
equation and fixes the extended coordinates (5 constraints). Without it, a prover can inject an
off-curve point such as `(1, 1)`. Neither `witnessAffine` nor `assertWellFormed()` proves
prime-order subgroup membership; that is a separate, much more expensive check.

**Pedersen commitments.** `ZkPedersen.commit(zk, value, blinding, scalarBits)` commits two
`ZkUInt` scalars and returns a `ZkJubjubPoint`, and `verifyOpening(...)` checks an opening. Both
scalars are constrained to canonical values below the subgroup order. Two 252-bit scalars cost
3,020 constraints. Range-limit business amounts separately.

**EdDSA-Jubjub verification** comes in two named entry points, because whether the public key
needs an in-circuit subgroup check depends on your protocol:

| Entry point | Use when | Approx. constraints |
|-------------|----------|--------------------|
| `ZkEdDSAJubjub.verifyStrict(...)` | The public key is secret or chosen by the prover | ~14,500 |
| `ZkEdDSAJubjub.verifyWithRegisteredKey(...)` | The public key is a public input or constant (the DSL enforces this) | ~8,962 |

Both reject small-order keys, including the identity. With `verifyWithRegisteredKey`, binding
the public key to a subgroup-checked registry entry is your verifier's job. Both also need two
reduction witnesses, computed off-circuit with
`ZkEdDSAJubjub.witnessComputeKReduction(signature.r(), publicKey, message)`:

```java
@Prove
void prove(ZkContext zk,
           @Public ZkField pkU, @Public ZkField pkV, @Public ZkField msg,
           @Public ZkField rU, @Public ZkField rV,
           @Public @UInt(bits = 252) ZkUInt s,
           @Secret @UInt(bits = 252) ZkUInt kModL,
           @Secret @UInt(bits = 4) ZkUInt kQuotient) {
    ZkEdDSAJubjub.verifyWithRegisteredKey(zk, pkU, pkV, msg, rU, rV, s, kModL, kQuotient);
}
```

> **Danger: Off-circuit signing and commitment generation**
>
> `EdDSAJubjub.sign` and `PedersenCommitment.commit` run secret-dependent, variable-time Java
> `BigInteger` arithmetic. They are approved only for local, offline, or isolated use, not for
> value-bearing issuance on shared or network-reachable machines. The in-circuit gadgets are not
> affected. The normative scheme is
> [jubjub-eddsa-v1](https://github.com/bloxbean/zeroj/blob/main/docs/specs/jubjub-eddsa-v1.md).

## Real-world crypto: Cardano key derivation

These gadgets reproduce standard wallet primitives *inside* a circuit, so a proof can show "I know
the root key behind this Cardano address" without revealing it. They're bit-oriented and
independent of the circuit field, so they run on BLS12-381 Groth16, but they are **large**.

| Gadget | Adapter | What it's for | Measured size |
|--------|---------|---------------|---------------|
| BLAKE2b (RFC 7693) | `ZkBlake2b.hash224` / `hash256` / `hash` | Cardano key hashes (blake2b-224) | 76,832 constraints per block |
| SHA-512 (FIPS 180-4) | `ZkSha512.hash` | Building block for HMAC and BIP32 | ~109,000 constraints per block |
| HMAC-SHA512 (RFC 2104) | `ZkHmacSha512.hmac` | BIP32-Ed25519 child derivation | ~454,000 constraints at the BIP32 input shape |
| GF(2²⁵⁵−19) field, Ed25519 points | `Fe25519`, `Ed25519Point` (no `Zk*` adapter) | Non-native Ed25519 arithmetic, fixed-base scalar multiplication | Building blocks |
| BIP32-Ed25519 | `Bip32Ed25519` (no `Zk*` adapter) | Hardened and soft child-key derivation, Icarus style | Building block |
| CIP-1852 derivation | `ZkCip1852.paymentKeyHash`, `leafKeyHash` | Root key → `m/1852'/1815'/account'/role/index` → 28-byte payment key hash | On the order of 19 million constraints for the full path |

Sizes are ZeroJ's own measurements from the gadget design work
([ADR-0027](https://github.com/bloxbean/zeroj/blob/main/docs/adr/0027-real-world-crypto-gadgets-sha512-hmac-blake2b-ed25519.md),
[ADR-0028](https://github.com/bloxbean/zeroj/blob/main/docs/adr/0028-dsl-optimization-and-hint-soundness.md))
and may change as the gadgets are optimized. `ZkCip1852.paymentKeyHash` has overloads that take
the account, role, and index as Java constants or as `ZkBytes` circuit inputs; with all three as
inputs, one circuit and one setup cover every address of a root key. A proof of this size needs
the large-circuit proving path in [Performance & large circuits](https://zeroj.dev/guides/proving/performance/).
See [Account recovery](https://zeroj.dev/use-cases/account-recovery/) for the application built on it.

## Status at a glance

"Ready" below means what the library documents: the gadget can be used in a circuit compiled for
BLS12-381, proved with Groth16, and checked by ZeroJ's reusable Plutus V3 verifier. It is not a
claim of audit, and a reusable verifier checks only the math, not your application's
authorization or replay rules.

| Gadget | Field | Cardano status (from the library's table) |
|--------|-------|-------------------------------------------|
| Field arithmetic, `ZkBool`, `ZkUInt`, arrays and matrices | Any | Ready on BLS12-381 Groth16 |
| `ZkBits`, `ZkBytes` | Any | Ready for binding and equality |
| Binary decomposition, comparators, selection | Any | Ready on BLS12-381 Groth16 |
| Poseidon T3, folded Poseidon N | BN254 default; BLS12-381 with explicit params | Ready with `PoseidonParamsBLS12_381T3.INSTANCE` |
| Merkle membership | Hash-dependent | Ready with the params-aware Poseidon helpers |
| MiMC, MiMC sponge | BN254 only | Not Cardano-ready |
| Jubjub point arithmetic | BLS12-381 only | Ready for algebraic and public-data use, pending external review |
| Pedersen commitment (in-circuit) | BLS12-381 only | Ready, pending external review |
| Pedersen commitment (off-circuit generation) | Jubjub | Offline or isolated use only |
| EdDSA-Jubjub | BLS12-381 only | Verification ready pending external review; legacy signing offline only |
| BLAKE2b, CIP-1852 derivation | Field-agnostic | Ready on BLS12-381 Groth16 |
| SHA-512, HMAC-SHA512, BIP32-Ed25519 | Field-agnostic | Ready as building blocks |
| Poseidon MPF/JMT authenticated state | BLS12-381 Poseidon profile | Experimental (separate modules) |

The authoritative, detailed table is in the
[`zeroj-circuit-lib` README](https://github.com/bloxbean/zeroj/blob/main/zeroj-circuit-lib/README.md#gadget-status).

## Choosing a gadget for Cardano

1. **Compile for `CurveId.BLS12_381` and prove with Groth16.** That is the verified on-chain path.
2. **Hash with Poseidon and explicit `PoseidonParamsBLS12_381T3.INSTANCE`.** Never MiMC, never the
   no-parameter overloads.
3. **Use `ZkMerkle.*Poseidon(...)` for membership.** The `HashType` enum paths are BN254-oriented.
4. **Use `ZkUInt` for every quantity,** with the tightest honest width.
5. **Bind every witness-supplied curve point** with `witnessAffine`, and pick the EdDSA entry
   point that matches who controls the key.
6. **Reach for SHA-512, HMAC, BLAKE2b, or Ed25519 only when a protocol demands them.** They cost
   orders of magnitude more than Poseidon.
7. **Match off-circuit and in-circuit hashing exactly.** Same parameters, same argument order,
   same path-bit convention, or honest proofs will fail.

## Next steps

- [Test your circuits for soundness](https://zeroj.dev/guides/circuits/testing-circuits/)
- [Private allowlist with a Merkle tree](https://zeroj.dev/tutorials/private-allowlist/)
- [Prove with Groth16](https://zeroj.dev/guides/proving/groth16/)
