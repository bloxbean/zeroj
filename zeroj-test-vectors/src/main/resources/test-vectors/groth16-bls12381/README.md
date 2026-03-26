# Groth16 BLS12-381 Test Vectors

## Circuit

Simple multiplier circuit (`a * b = c`) compiled with circom using the BLS12-381 prime field:

```circom
pragma circom 2.0.0;

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;

    c <== a * b;
}

component main {public [a]} = Multiplier();
```

## Inputs

- `a = 3` (public)
- `b = 11` (private)
- `c = 33` (public output)

## Public Signals

The `public.json` contains `[33, 3]` which corresponds to `[c, a]` (output first, then public inputs).

## Generation

These vectors were generated using:

- **circom** 2.x with `--prime bls12381` flag
- **snarkjs** (powers of tau ceremony with BLS12-381 curve, Groth16 protocol)

### Steps

1. Compile circuit: `circom multiplier.circom --r1cs --wasm --sym -o . --prime bls12381`
2. Powers of tau: `snarkjs powersoftau new bls12-381 12 pot12_0000.ptau`
3. Contribute and prepare phase 2
4. Groth16 setup and zkey contribution
5. Generate witness with `a=3, b=11`
6. Generate proof and verify with snarkjs (`OK!`)

## Files

| File | Description |
|------|-------------|
| `proof.json` | Groth16 proof (pi_a, pi_b, pi_c) on BLS12-381 curve |
| `verification_key.json` | Verification key (vk_alpha, vk_beta, vk_gamma, vk_delta, IC) |
| `public.json` | Public signals `[33, 3]` |

## Curve

BLS12-381 -- the proof elements use affine coordinates over the BLS12-381 base field. The `pi_b` and `vk_beta_2`, `vk_gamma_2`, `vk_delta_2` points are on the G2 group (represented as pairs of field elements for Fp2).

## Purpose

These test vectors are used to validate the blst-based BLS12-381 Groth16 verifier in ZeroJ.
