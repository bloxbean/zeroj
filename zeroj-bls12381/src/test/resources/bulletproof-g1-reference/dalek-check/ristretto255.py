#!/usr/bin/env python3
"""ristretto255 (RFC 9496 Section 4), written from the RFC text only.

Standard library only.  NOT constant-time: Python integers and data-dependent
branches throughout.  Test use only (ADR-0061 M2 dalek algebra check); it must
never handle real secrets.

Points are kept in extended twisted Edwards coordinates (X, Y, Z, T) on
Curve25519's Edwards form -x^2 + y^2 = 1 + d*x^2*y^2 (a = -1), as RFC 9496
Section 2 describes.  Internal representations are compared only through the
RFC 9496 Section 4.3.3 equality, never coordinate by coordinate.

Implemented: SQRT_RATIO_M1 (4.2), Decode with every validity rule (4.3.1),
Encode (4.3.2), Equals (4.3.3), the element derivation function /
from_uniform_bytes with its MAP (4.3.4), the scalar field (4.4), and group
addition, negation and scalar multiplication on the internal representation.

Usage:
    python3 -I -B ristretto255.py --self-test [--rfc9496 PATH]
    python3 -I -B ristretto255.py --emit-vectors PATH   # parse RFC text -> JSON
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys

# --------------------------------------------------------------------------
# Constants (RFC 9496 Sections 4 and 4.1).  The decimal values are copied from
# the RFC text; the self-test checks each against its defining relation.
# --------------------------------------------------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  # group order l (Section 4)

D = 37095705934669439343138083508754565189542113879843219016388785533085940283555
SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752
SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235
INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578
ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838
D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952

# Encoding of the canonical generator (Section 4).
GENERATOR_ENCODING = bytes.fromhex(
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")

RFC9496_SHA256 = "d875c6e703827da487eae8f0656fd25e4a278f1dcb0f06041669adad27c03ff3"

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.path.join(HERE, "rfc9496-appendix-a.json")


class DecodeError(ValueError):
    """Raised when an encoding is rejected by RFC 9496 Section 4.3.1."""


# --------------------------------------------------------------------------
# Field helpers (Section 2, 2.1, 2.2)
# --------------------------------------------------------------------------

def is_negative(e: int) -> bool:
    return (e % P) & 1 == 1


def ct_abs(u: int) -> int:
    u %= P
    return (-u) % P if is_negative(u) else u


def sqrt_ratio_m1(u: int, v: int):
    """Section 4.2.  Returns (was_square, r)."""
    u %= P
    v %= P
    v3 = v * v % P * v % P
    v7 = v3 * v3 % P * v % P
    r = (u * v3) % P * pow(u * v7 % P, (P - 5) // 8, P) % P
    check = v * r % P * r % P
    correct_sign_sqrt = check == u
    flipped_sign_sqrt = check == (-u) % P
    flipped_sign_sqrt_i = check == (-u * SQRT_M1) % P
    r_prime = SQRT_M1 * r % P
    if flipped_sign_sqrt or flipped_sign_sqrt_i:
        r = r_prime
    r = ct_abs(r)
    was_square = correct_sign_sqrt or flipped_sign_sqrt
    return was_square, r


# --------------------------------------------------------------------------
# Internal representation: extended coordinates (X, Y, Z, T), x = X/Z,
# y = Y/Z, x*y = T/Z.  Addition is the complete a = -1 extended formula
# (Hisil-Wong-Carter-Dawson 2008, "add-2008-hwcd-3"), valid for doubling too.
# --------------------------------------------------------------------------

IDENTITY = (0, 1, 1, 0)
_D2 = 2 * D % P


def point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * _D2 % P * t2 % P
    d = 2 * z1 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_double(p1):
    # dbl-2008-hwcd for a = -1.
    x1, y1, z1, _ = p1
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    h = a + b
    e = (h - (x1 + y1) * (x1 + y1)) % P
    g = (a - b) % P
    f = (c + g) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_neg(p1):
    x, y, z, t = p1
    return ((-x) % P, y, z, (-t) % P)


def scalar_mul(k: int, p1):
    """Left-to-right double-and-add; k is reduced mod l first.  NOT constant-time."""
    k %= L
    acc = IDENTITY
    for bit in bin(k)[2:] if k else "":
        acc = point_double(acc)
        if bit == "1":
            acc = point_add(acc, p1)
    return acc


def equals(p1, p2) -> bool:
    """Section 4.3.3."""
    x1, y1, _, _ = p1
    x2, y2, _, _ = p2
    return (x1 * y2 - y1 * x2) % P == 0 or (y1 * y2 - x1 * x2) % P == 0


def is_identity(p1) -> bool:
    return equals(p1, IDENTITY)


# --------------------------------------------------------------------------
# Decode / Encode (Sections 4.3.1, 4.3.2)
# --------------------------------------------------------------------------

def decode(b: bytes):
    b = bytes(b)
    # Step 1: length, little-endian, s < p (most significant bit NOT masked).
    if len(b) != 32:
        raise DecodeError("length")
    s = int.from_bytes(b, "little")
    if s >= P:
        raise DecodeError("non-canonical field element")
    # Step 2.
    if is_negative(s):
        raise DecodeError("negative field element")
    # Step 3.
    ss = s * s % P
    u1 = (1 - ss) % P
    u2 = (1 + ss) % P
    u2_sqr = u2 * u2 % P
    v = (-(D * u1 % P * u1) - u2_sqr) % P
    was_square, invsqrt = sqrt_ratio_m1(1, v * u2_sqr % P)
    den_x = invsqrt * u2 % P
    den_y = invsqrt * den_x % P * v % P
    x = ct_abs(2 * s * den_x)
    y = u1 * den_y % P
    t = x * y % P
    # Step 4.
    if not was_square:
        raise DecodeError("non-square")
    if is_negative(t):
        raise DecodeError("negative x*y")
    if y == 0:
        raise DecodeError("y = 0")
    return (x, y, 1, t)


def encode(p1) -> bytes:
    x0, y0, z0, t0 = p1
    u1 = (z0 + y0) * (z0 - y0) % P
    u2 = x0 * y0 % P
    _, invsqrt = sqrt_ratio_m1(1, u1 * u2 % P * u2 % P)
    den1 = invsqrt * u1 % P
    den2 = invsqrt * u2 % P
    z_inv = den1 * den2 % P * t0 % P
    ix0 = x0 * SQRT_M1 % P
    iy0 = y0 * SQRT_M1 % P
    enchanted_denominator = den1 * INVSQRT_A_MINUS_D % P
    rotate = is_negative(t0 * z_inv % P)
    if rotate:
        x, y, den_inv = iy0, ix0, enchanted_denominator
    else:
        x, y, den_inv = x0, y0, den2
    z = z0
    if is_negative(x * z_inv % P):
        y = (-y) % P
    s = ct_abs(den_inv * (z - y))
    return s.to_bytes(32, "little")


# --------------------------------------------------------------------------
# Element derivation (Section 4.3.4)
# --------------------------------------------------------------------------

def _map(b32: bytes):
    r0 = int.from_bytes(b32, "little") & ((1 << 255) - 1)  # mask the top bit
    t = r0 % P
    r = SQRT_M1 * t % P * t % P
    u = (r + 1) * ONE_MINUS_D_SQ % P
    v = (-1 - r * D) * (r + D) % P
    was_square, s = sqrt_ratio_m1(u, v)
    s_prime = (-ct_abs(s * t)) % P
    if not was_square:
        s = s_prime
    c = (P - 1) if was_square else r
    n = (c * (r - 1) % P * D_MINUS_ONE_SQ - v) % P
    w0 = 2 * s * v % P
    w1 = n * SQRT_AD_MINUS_ONE % P
    w2 = (1 - s * s) % P
    w3 = (1 + s * s) % P
    return (w0 * w3 % P, w2 * w1 % P, w1 * w3 % P, w0 * w2 % P)


def from_uniform_bytes(b64: bytes):
    b64 = bytes(b64)
    if len(b64) != 64:
        raise ValueError("element derivation takes 64 octets")
    return point_add(_map(b64[0:32]), _map(b64[32:64]))


# --------------------------------------------------------------------------
# Scalar field (Section 4.4)
# --------------------------------------------------------------------------

def scalar_from_canonical_bytes(b: bytes) -> int:
    b = bytes(b)
    if len(b) != 32:
        raise DecodeError("scalar length")
    s = int.from_bytes(b, "little")
    if s >= L:
        raise DecodeError("non-canonical scalar")
    return s


def scalar_to_bytes(s: int) -> bytes:
    return (s % L).to_bytes(32, "little")


def scalar_from_wide(b64: bytes) -> int:
    return int.from_bytes(bytes(b64), "little") % L


GENERATOR = decode(GENERATOR_ENCODING)


class Ristretto255Group:
    """The duck-typed group interface used by bulletproof_generic."""

    name = "ristretto255"
    order = L

    def identity(self):
        return IDENTITY

    def add(self, p1, p2):
        return point_add(p1, p2)

    def double(self, p1):
        return point_double(p1)

    def neg(self, p1):
        return point_neg(p1)

    def mul(self, k, p1):
        return scalar_mul(k, p1)

    def eq(self, p1, p2):
        return equals(p1, p2)

    def is_identity(self, p1):
        return is_identity(p1)

    def encode(self, p1):
        return encode(p1)


# --------------------------------------------------------------------------
# RFC 9496 Appendix A: parser (from the RFC text) and vector checks
# --------------------------------------------------------------------------

def parse_rfc9496_appendix_a(text: str) -> dict:
    a = text.index("Appendix A.  Test Vectors for ristretto255\n\n   This section")
    b = text.index("Appendix B.  Test Vectors for decaf448\n\n")
    s = text[a:b]
    s1 = s[s.index("A.1.  Multiples"):s.index("A.2.  Invalid")]
    s2 = s[s.index("A.2.  Invalid"):s.index("A.3.  Group")]
    s3 = s[s.index("A.3.  Group"):s.index("A.4.  Square")]
    s4 = s[s.index("A.4.  Square"):]
    mult = [re.sub(r"\s", "", m.group(2))
            for m in re.finditer(r"B\[\s*(\d+)\]:((?:\s+[0-9a-f]{8})+)", s1)]
    invalid = [re.sub(r"\s", "", blk)
               for blk in re.findall(r"\n((?:   [0-9a-f]{8}(?: [0-9a-f]{8})*\n)+)", s2)]
    head, tail = s3.split("all produce the same", 1)
    uniform = [[m.group(1) + m.group(2), re.sub(r"\s", "", m.group(3))]
               for m in re.finditer(
                   r"I: ([0-9a-f]{64})\s+([0-9a-f]{64})\s+O: ((?:[0-9a-f]{8}\s+){7}[0-9a-f]{8})",
                   head)]
    same_in = [x + y for x, y in re.findall(r"I: ([0-9a-f]{64})\s+([0-9a-f]{64})", tail)]
    same_out = re.sub(r"\s", "", re.search(r"O: ((?:[0-9a-f]{8}\s+){7}[0-9a-f]{8})", tail).group(1))
    sqrt_ratio = [[u, v, w == "TRUE", r] for u, v, w, r in re.findall(
        r"u: ([0-9a-f]{64})\s+v: ([0-9a-f]{64})\s+was_square: (TRUE|FALSE)\s+r: ([0-9a-f]{64})", s4)]
    return {
        "source": "RFC 9496 Appendix A (rfc-editor.org/rfc/rfc9496.txt)",
        "sourceSha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "multiples": mult,
        "invalid": invalid,
        "uniform": uniform,
        "sameOutputInputs": same_in,
        "sameOutput": same_out,
        "sqrtRatio": sqrt_ratio,
    }


def load_vectors(path: str = VECTORS_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def run_self_test(results, rfc_path: str | None = None) -> None:
    """results: an object with .check(name, bool, detail='')."""
    chk = results.check
    # Constants against their defining relations (independent of transcription).
    chk("r255 const D = -121665/121666", D * 121666 % P == (-121665) % P)
    chk("r255 const SQRT_M1^2 = -1", SQRT_M1 * SQRT_M1 % P == P - 1)
    chk("r255 const SQRT_AD_MINUS_ONE^2 = a*d - 1", SQRT_AD_MINUS_ONE ** 2 % P == (-D - 1) % P)
    chk("r255 const INVSQRT_A_MINUS_D^2 * (a - d) = 1",
        INVSQRT_A_MINUS_D ** 2 * (-1 - D) % P == 1)
    chk("r255 const ONE_MINUS_D_SQ", ONE_MINUS_D_SQ == (1 - D * D) % P)
    chk("r255 const D_MINUS_ONE_SQ", D_MINUS_ONE_SQ == (D - 1) ** 2 % P)
    chk("r255 [l]B = identity", is_identity(scalar_mul(0, GENERATOR))
        and is_identity(_mul_raw(L, GENERATOR)))

    vec = load_vectors()
    if rfc_path is not None:
        with open(rfc_path, "r", encoding="utf-8") as fh:
            text = fh.read()
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        raw_digest = hashlib.sha256(open(rfc_path, "rb").read()).hexdigest()
        chk("RFC 9496 file SHA-256 pinned", raw_digest == RFC9496_SHA256, raw_digest)
        parsed = parse_rfc9496_appendix_a(text)
        same = all(parsed[k] == vec[k] for k in
                   ("multiples", "invalid", "uniform", "sameOutputInputs", "sameOutput", "sqrtRatio"))
        chk("RFC 9496 Appendix A re-parsed == rfc9496-appendix-a.json", same, digest)
    chk("vector file counts (16 multiples, 29 invalid, 7+4 uniform, 6 sqrt)",
        len(vec["multiples"]) == 16 and len(vec["invalid"]) == 29
        and len(vec["uniform"]) == 7 and len(vec["sameOutputInputs"]) == 4
        and len(vec["sqrtRatio"]) == 6)

    # A.1: multiples of the generator; encode, add, decode round trip.
    acc = IDENTITY
    ok_all = True
    for i, h in enumerate(vec["multiples"]):
        enc = encode(acc)
        ok = enc.hex() == h
        if i > 0:
            dec = decode(bytes.fromhex(h))
            ok = ok and equals(dec, acc) and encode(dec).hex() == h
            ok = ok and encode(scalar_mul(i, GENERATOR)).hex() == h
        else:
            ok = ok and is_identity(decode(bytes.fromhex(h)))
        ok_all &= ok
        acc = point_add(acc, GENERATOR)
    chk("RFC 9496 A.1 generator multiples 0..15 (encode, add, decode, scalar_mul)", ok_all)

    # A.2: every invalid encoding must be rejected.
    # The RFC groups them: 4 non-canonical, 8 negative, 8 non-square x^2,
    # 8 negative x*y, 1 with s = -1 (y = 0).  Each must fail for its reason.
    expected = (["non-canonical field element"] * 4 + ["negative field element"] * 8
                + ["non-square"] * 8 + ["negative x*y"] * 8 + ["y = 0"])
    rejected = 0
    reasons_ok = True
    for h, want in zip(vec["invalid"], expected):
        try:
            decode(bytes.fromhex(h))
        except DecodeError as e:
            rejected += 1
            reasons_ok &= (str(e) == want)
    chk("RFC 9496 A.2 all 29 invalid encodings rejected", rejected == len(vec["invalid"]) == 29,
        f"{rejected}/{len(vec['invalid'])}")
    chk("RFC 9496 A.2 each rejected at the rule its RFC group names", reasons_ok)

    # A.3: element derivation.
    ok_all = all(encode(from_uniform_bytes(bytes.fromhex(i))).hex() == o for i, o in vec["uniform"])
    chk("RFC 9496 A.3 from_uniform_bytes (7 vectors)", ok_all)
    ok_all = all(encode(from_uniform_bytes(bytes.fromhex(i))).hex() == vec["sameOutput"]
                 for i in vec["sameOutputInputs"])
    chk("RFC 9496 A.3 four inputs with the same output", ok_all)

    # A.4: SQRT_RATIO_M1.
    ok_all = True
    for u, v, ws, r in vec["sqrtRatio"]:
        got_ws, got_r = sqrt_ratio_m1(int.from_bytes(bytes.fromhex(u), "little"),
                                      int.from_bytes(bytes.fromhex(v), "little"))
        ok_all &= (got_ws == ws and got_r.to_bytes(32, "little").hex() == r)
    chk("RFC 9496 A.4 SQRT_RATIO_M1 (6 vectors)", ok_all)

    # Scalar codec.
    try:
        scalar_from_canonical_bytes(L.to_bytes(32, "little"))
        rej = False
    except DecodeError:
        rej = True
    chk("scalar l rejected as non-canonical; l-1 accepted",
        rej and scalar_from_canonical_bytes((L - 1).to_bytes(32, "little")) == L - 1)


def _mul_raw(k: int, p1):
    # scalar_mul without reducing k, to check the group order.
    acc = IDENTITY
    for bit in bin(k)[2:]:
        acc = point_double(acc)
        if bit == "1":
            acc = point_add(acc, p1)
    return acc


class _Res:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            print(f"PASS {name}")
        else:
            self.failed += 1
            print(f"FAIL {name} {detail}")


def main(argv):
    if len(argv) >= 2 and argv[0] == "--emit-vectors":
        rfc = argv[1]
        out = argv[2] if len(argv) > 2 else VECTORS_PATH
        with open(rfc, "r", encoding="utf-8") as fh:
            d = parse_rfc9496_appendix_a(fh.read())
        d["sourceSha256"] = hashlib.sha256(open(rfc, "rb").read()).hexdigest()
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=1)
            fh.write("\n")
        print(out)
        return 0
    if argv and argv[0] == "--self-test":
        rfc = argv[argv.index("--rfc9496") + 1] if "--rfc9496" in argv else None
        r = _Res()
        run_self_test(r, rfc)
        print(f"SUMMARY ristretto255: {r.passed} passed, {r.failed} failed")
        return 0 if r.failed == 0 else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
