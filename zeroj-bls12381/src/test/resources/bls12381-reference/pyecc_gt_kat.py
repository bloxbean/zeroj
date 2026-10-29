#!/usr/bin/env python3
"""ADR-0062 D9: external GT known-answer vectors from py_ecc 8.0.0.

Prints e(G1, G2) and e([a]G1, [b]G2) in ZeroJ's Fp12 layout, for PairingExternalKatTest.

Run (py_ecc pinned):
    python3 -m venv venv && venv/bin/pip install py_ecc==8.0.0
    venv/bin/python -I pyecc_gt_kat.py

Two conventions differ between py_ecc and ZeroJ, and both are mapped here, not in Java:

1. Orientation. BLS12-381's ate parameter x is negative. ZeroJ conjugates the Miller loop
   output for the negative x (the standard orientation, as in blst and zkcrypto); py_ecc does
   not. The two final-exponentiated results are therefore inverses: ZeroJ = py_ecc^-1.

2. Basis. py_ecc represents Fp12 as Fp[w]/(w^12 - 2 w^6 + 2). ZeroJ uses the tower
   Fp2 = Fp[u]/(u^2 + 1), Fp6 = Fp2[v]/(v^3 - (1 + u)), Fp12 = Fp6[w]/(w^2 - v).
   With v = w^2, w^6 = 1 + u, so u = w^6 - 1 and u^2 = -1 is exactly w^12 - 2 w^6 + 2 = 0:
   both use the same w. A ZeroJ coefficient (x + y u) on w^k (k < 6) contributes
   (x - y) to py_ecc's w^k and y to its w^(k+6). Inverting: y = c[k+6], x = c[k] + y.
   ZeroJ's (c_j, a_i) slot holds w^(2i + j).
"""
from py_ecc.bls12_381 import G1, G2, multiply, pairing, field_modulus as P
from importlib.metadata import version

assert version("py_ecc") == "8.0.0", version("py_ecc")

A = 0x2a5e3c6f1b0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f
B = 0x1f2e3d4c5b6a79881726354453627180fedcba9876543210f0e1d2c3b4a59687


def zeroj_layout(f):
    """Return the 12 Fp coefficients of f in ZeroJ order:
    c0.c0.c0, c0.c0.c1, c0.c1.c0, c0.c1.c1, c0.c2.c0, c0.c2.c1, c1.c0.c0, ..., c1.c2.c1."""
    c = [int(x) % P for x in f.coeffs]
    out = []
    for j in (0, 1):          # Fp12 = c0 + c1 w
        for i in (0, 1, 2):   # Fp6 = a0 + a1 v + a2 v^2
            k = 2 * i + j     # power of w
            y = c[k + 6]
            x = (c[k] + y) % P
            out += [x, y]
    return out


def gt(g1, g2):
    return pairing(g2, g1).inv()  # py_ecc takes (G2, G1); invert for ZeroJ's orientation


for name, value in (("e(G1,G2)", gt(G1, G2)),
                    ("e([a]G1,[b]G2)", gt(multiply(G1, A), multiply(G2, B)))):
    print(name)
    for x in zeroj_layout(value):
        print("    %x" % x)
print("a = %x" % A)
print("b = %x" % B)
