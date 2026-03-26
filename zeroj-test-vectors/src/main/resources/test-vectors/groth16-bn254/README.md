# Groth16 BN254 Test Vectors

These test vectors were generated using **snarkjs v0.7.6** and **circom v2.2.3**.

## Circuit

A simple multiplier circuit (`multiplier.circom`):

```
c = a * b
```

- `a` is a **public** input
- `b` is a **private** input (witness)
- `c` is the **public** output

## Test Case

| Parameter | Value |
|-----------|-------|
| a (public input) | 3 |
| b (private input) | 11 |
| c (public output) | 33 |

## Files

| File | Description |
|------|-------------|
| `verification_key.json` | Groth16 verification key for the multiplier circuit (BN128/BN254 curve) |
| `proof.json` | Groth16 proof for a=3, b=11, c=33 |
| `public.json` | Public signals: `["33", "3"]` (output c, then public input a) |

## Curve

All points are on the **BN128** (also known as **BN254** or **alt_bn128**) curve.

- Field order (r): `21888242871839275222246405745257275088548364400416034343698204186575808495617`
- Base field order (q): `21888242871839275222246405745257275088696311157297823662689037894645226208583`

## Coordinate Format

- G1 points: `[x, y, "1"]` (projective coordinates, affine when z=1)
- G2 points: `[[x_c0, x_c1], [y_c0, y_c1], ["1", "0"]]` (Fp2 extension field)
- All coordinates are decimal string representations of field elements

## Regeneration

To regenerate these vectors, run from the project root:

```bash
cd zeroj-test-vectors/scripts
./generate-vectors.sh
```

Requires: Node.js, circom (Rust, v2.x), snarkjs (v0.7+).
