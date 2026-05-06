# Poseidon Parameter Generation — Authoritative Reference

This directory contains the authoritative Sage script that generates Poseidon
round constants and MDS matrices. It is the **source of truth** for ZeroJ's
Poseidon parameters — the Java `PoseidonGrainLFSR` implementation ports this
script, and conformance is verified byte-for-byte against its output.

## Source

- Repository: `https://extgit.isec.tugraz.at/krypto/hadeshash`
- File: `code/generate_parameters_grain.sage`
- Pinned commit: `208b5a164c6a252b137997694d90931b2bb851c5` (2023-05-02)
- Paper: Grassi, Khovratovich, Rechberger, Roy, Schofnegger — *Poseidon: A New
  Hash Function for Zero-Knowledge Proof Systems* (USENIX Security 2021).

## Reproducing ZeroJ's Poseidon parameters

### Prerequisites

```
brew install sagemath   # or your platform's SageMath
```

### BN254 (scalar field), t=3, α=5, RF=8, RP=57

Primary sanity-check target — matches iden3/circomlibjs constants currently
committed at `zeroj-circuit-lib/.../PoseidonConstants.java`.

```
sage generate_parameters_grain.sage 1 0 254 3 8 57 \
    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
```

### BLS12-381 (scalar field), t=3, α=5, RF=8, RP=57

Target for `PoseidonParams.BLS12_381_T3` — the standards-compatible BLS Poseidon
used by arkworks, zkcrypto, and the Jubjub ecosystem.

```
sage generate_parameters_grain.sage 1 0 255 3 8 57 \
    0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

### BLS12-381 (scalar field), t=5, α=5, RF=8, RP=60

Reserved for ADR-0016 (Jubjub-in-circuit), 4-ary Merkle trees.

```
sage generate_parameters_grain.sage 1 0 255 5 8 60 \
    0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

## CLI argument legend

```
sage generate_parameters_grain.sage <field> <sbox> <field_size> <num_cells> <R_F> <R_P> <prime_hex>
```

- `field = 1` → GF(p) (always for ZeroJ targets)
- `sbox  = 0` → x^α (standard Poseidon)
- `field_size` → bit-length of the prime (254 for BN254, 255 for BLS12-381)
- `num_cells` → state width `t` (2+1 = 3 for two-to-one hash)
- `R_F, R_P` → full / partial round counts
- `prime_hex` → scalar field modulus, hex-encoded

## How this is consumed in ZeroJ

1. **Java port**: `PoseidonGrainLFSR.java` implements the same algorithm as
   this Sage script. Any divergence is a bug in the Java port.
2. **Cross-verification test** (`PoseidonGrainLFSRTest`): regenerates the BN254
   t=3 constants from the Grain LFSR and asserts byte-equality with the
   committed `PoseidonConstants.C` and `PoseidonConstants.M`. This is a
   regression test that catches any drift in the Java port.
3. **Generated BLS12-381 constants**: checked into source as
   `PoseidonParamsBLS12_381.java`, produced by running the Java generator with
   the BLS arguments listed above.

## Security algorithms (algorithm_1/2/3)

The Sage script includes three MDS-matrix security checks (Algorithms 1, 2, 3
from the Poseidon paper). If the first-generated Cauchy matrix fails any check,
Sage resamples — advancing the LFSR state and changing subsequent outputs.

For the parameter sets ZeroJ targets (BN254 t=3, BLS12-381 t=3, BLS12-381 t=5
with RF=8 and standard RP values), the **first-generated Cauchy matrix passes
all three algorithms**. This is verifiable empirically:

- The committed BN254 constants/MDS match the Java port's first-matrix output
  (proving first-pass acceptance holds for BN254 t=3).
- The BLS12-381 outputs match arkworks, zkcrypto, and the Sage script output
  when all three are cross-checked.

Because of this, the Java port does **not** implement Algorithms 1/2/3. If we
ever target non-standard parameters where first-pass acceptance doesn't hold,
porting Algorithms 1/2/3 becomes required. Today it's not.

## Audit trail

Any change to committed constants must re-run the Sage script offline and
update the fixture files. The Java test asserts byte-equality, so drift is
caught at build time.
