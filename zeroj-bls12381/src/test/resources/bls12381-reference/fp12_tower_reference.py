#!/usr/bin/env python3
"""ADR-0062 D9: independent Fp6 / Fp12 reference vectors for zeroj-bls12381.

ZeroJ's tower is Fp2 = Fp[u]/(u^2 + 1), Fp6 = Fp2[v]/(v^3 - (1 + u)), Fp12 = Fp6[w]/(w^2 - v)
with Karatsuba-style formulas. This reference shares none of those formulas: it models Fp12 as
the single polynomial ring Fp[w]/(w^12 - 2 w^6 + 2) with schoolbook multiplication and reduction,
and computes inverses by Fermat exponentiation a^(p^12 - 2). The two rings are the same field:
with v = w^2 and u = w^6 - 1, the relation u^2 = -1 is exactly w^12 - 2 w^6 + 2 = 0.

Fp6 elements are the Fp12 elements whose odd powers of w vanish (Fp6 = Fp2[v], v = w^2).

Output: fp12_tower_vectors.json (deterministic; Python's random with a fixed seed is used only to
pick inputs). Standard library only.

    python3 -I fp12_tower_reference.py > fp12_tower_vectors.json
"""
import json
import random

P = int("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
MOD = {12: 1, 6: -2, 0: 2}  # w^12 - 2 w^6 + 2


def mul(a, b):
    prod = [0] * 23
    for i in range(12):
        if a[i]:
            for j in range(12):
                prod[i + j] += a[i] * b[j]
    for k in range(22, 11, -1):  # w^k = w^(k-12) * (2 w^6 - 2)
        c = prod[k]
        if c:
            prod[k] = 0
            prod[k - 6] += 2 * c
            prod[k - 12] -= 2 * c
    return [x % P for x in prod[:12]]


def power(a, e):
    result = [1] + [0] * 11
    for bit in bin(e)[2:]:
        result = mul(result, result)
        if bit == "1":
            result = mul(result, a)
    return result


def inv(a):
    return power(a, P ** 12 - 2)


def from_zeroj(c):
    """12 Fp coefficients in ZeroJ order (c0.c0.c0, c0.c0.c1, c0.c1.c0, ..., c1.c2.c1) -> w-poly.
    Slot (j, i) holds w^(2i + j); an Fp2 value x + y u = (x - y) + y w^6."""
    out = [0] * 12
    idx = 0
    for j in (0, 1):
        for i in (0, 1, 2):
            k = 2 * i + j
            x, y = c[idx], c[idx + 1]
            idx += 2
            out[k] = (out[k] + x - y) % P
            out[k + 6] = (out[k + 6] + y) % P
    return out


def to_zeroj(a):
    out = []
    for j in (0, 1):
        for i in (0, 1, 2):
            k = 2 * i + j
            y = a[k + 6]
            out += [(a[k] + y) % P, y]
    return out


def hexes(c):
    return ["%x" % x for x in c]


def main():
    rng = random.Random(0x0062_0009)
    rand12 = lambda: [rng.randrange(P) for _ in range(12)]
    rand6 = lambda: [rng.randrange(P) for _ in range(6)] + [0] * 6  # c1 = 0: an Fp6 element

    fp12 = []
    for _ in range(8):
        a, b = rand12(), rand12()
        pa, pb = from_zeroj(a), from_zeroj(b)
        fp12.append({"a": hexes(a), "b": hexes(b),
                     "mul": hexes(to_zeroj(mul(pa, pb))),
                     "square": hexes(to_zeroj(mul(pa, pa))),
                     "inv": hexes(to_zeroj(inv(pa)))})
    fp6 = []
    for _ in range(8):
        a, b = rand6(), rand6()
        pa, pb = from_zeroj(a), from_zeroj(b)
        prod, sq, iv = to_zeroj(mul(pa, pb)), to_zeroj(mul(pa, pa)), to_zeroj(inv(pa))
        assert prod[6:] == [0] * 6 and sq[6:] == [0] * 6 and iv[6:] == [0] * 6
        fp6.append({"a": hexes(a[:6]), "b": hexes(b[:6]),
                    "mul": hexes(prod[:6]), "square": hexes(sq[:6]), "inv": hexes(iv[:6])})
    print(json.dumps({"source": "fp12_tower_reference.py (ADR-0062 D9)", "fp6": fp6, "fp12": fp12}, indent=2))


if __name__ == "__main__":
    main()
