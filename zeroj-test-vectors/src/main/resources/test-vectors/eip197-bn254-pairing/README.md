# EIP-197 BN254 Pairing Test Vectors

Low-level BN254 pairing precompile test vectors from the Ethereum test suite.

These test the `bn256Pairing` precompile (address 0x08) which computes:
`e(P1,Q1) * e(P2,Q2) * ... * e(Pk,Qk) == 1`

## Format

Each entry in `pairing_vectors.json` has:
- `name`: test case name
- `input`: hex-encoded concatenated pairs (each pair = 192 bytes: G1 64 bytes + G2 128 bytes)
- `expected`: `"0000...01"` (pairing product == 1) or `"0000...00"` (not equal to 1)

## Input encoding per pair (192 bytes)

| Bytes | Content |
|-------|---------|
| 0-31 | G1.x (big-endian, 256-bit) |
| 32-63 | G1.y (big-endian, 256-bit) |
| 64-95 | G2.x imaginary part (big-endian) — **NOTE: EIP-197 puts imaginary first** |
| 96-127 | G2.x real part (big-endian) |
| 128-159 | G2.y imaginary part (big-endian) |
| 160-191 | G2.y real part (big-endian) |

## Important: Fp2 coordinate order

EIP-197 uses `(imaginary, real)` ordering for Fp2 elements.
snarkjs uses `(real, imaginary)` ordering.
When converting between formats, swap the two components.

## Source

go-ethereum: `core/vm/testdata/precompiles/bn256Pairing.json`
