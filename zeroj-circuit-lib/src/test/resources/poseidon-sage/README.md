# Poseidon Sage Cross-Check

External reference implementation of Poseidon over BLS12-381 scalar field,
used to independently verify the pure-Java `PoseidonHash` implementation.

## Files

- `poseidon_bls12_381_reference.sage` — SageMath reference. Self-contained:
  includes the hadeshash Grain LFSR generator (pinned commit
  `208b5a164c6a252b137997694d90931b2bb851c5`) and a Poseidon permutation
  implementation matching the paper spec (Grassi et al., 2021) §4 for
  `t=3, α=5, RF=8, RP=57`.
- `sage-reference-output.txt` — captured output from running the Sage script
  once, used as a golden reference in `PoseidonCrossVerificationTest`.

## Reproducing

Requires Docker (or a local SageMath install).

```
docker pull --platform linux/amd64 sagemath/sagemath:latest

docker run --rm --platform linux/amd64 \
    -v "$(pwd)/zeroj-circuit-lib/src/test/resources/poseidon-sage:/work" \
    sagemath/sagemath:latest \
    sage /work/poseidon_bls12_381_reference.sage
```

Output must match `sage-reference-output.txt` byte-for-byte. Any drift
indicates either (a) the Sage script itself changed, or (b) SageMath's
field arithmetic behavior changed — neither of which should happen.

## What this proves

`PoseidonCrossVerificationTest.bls12_381_regressionFixtures` asserts that
ZeroJ's `PoseidonHash.hash(PoseidonParamsBLS12_381T3, a, b)` produces hashes
that byte-match `sage-reference-output.txt`. The chain of trust is:

1. `generate_parameters_grain.sage` (pinned hadeshash commit) is the
   authoritative Poseidon parameter generator per the paper.
2. Running it in an isolated SageMath Docker container produces constants
   that, applied via a straightforward Poseidon permutation, yield the
   hashes in `sage-reference-output.txt`.
3. ZeroJ's pure-Java `PoseidonGrainLFSR` + `PoseidonHash` produce the same
   constants and the same hashes.
4. Therefore ZeroJ's BLS12-381 Poseidon is correct per the Poseidon paper
   spec.

Closes the last ADR-0015 §6 test-suite gap.
