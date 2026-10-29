#!/usr/bin/env python3
"""Independent reference for ADR-0060 (Pedersen commitments over BLS12-381 G1).

Written from RFC 9380 (hash-to-curve), CIP-0381 (Zcash compressed point
encoding, curve constants) and ADR-0060 sections D1-D5 only.  No ZeroJ Java
source and no other repository file was read while writing it.  Standard
library only; deterministic; Python 3.13.

This is a PUBLIC reference.  It is not constant-time and must never be used
with secret values outside of tests.

Usage:
    python3 -I -B bls12_381_g1_reference.py --self-test
    python3 -I -B bls12_381_g1_reference.py            # JSON report on stdout
"""

from __future__ import annotations

import hashlib
import json
import sys

# ---------------------------------------------------------------------------
# Constants.  Every value is copied from (or cross-checked against) the cited
# document section.
# ---------------------------------------------------------------------------

# RFC 9380 Section 8.8.1 "p"; equal to CIP-0381 "Base field modulus".
P_381 = int(
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f"
    "6241eabfffeb153ffffb9feffffffffaaab", 16)

# ADR-0060 notation and CIP-0381 "Main subgroup order".
Q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

# RFC 9380 Section 8.8.1: E: y^2 = x^3 + 4.  CIP-0381 "B coefficient" = 4.
B_E = 4

# RFC 9380 Section 8.8.1: Z, A', B', h_eff.
SSWU_Z = 11
A_PRIME = int(
    "144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aef"
    "d881ac98936f8da0e0f97f5cf428082d584c1d", 16)
B_PRIME = int(
    "12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14f"
    "cef35ef55a23215a316ceaa5d1cc48e98e172be0", 16)
H_EFF = 0xd201000000010001

# RFC 9380 Section 8.8.1: L = 64, k = 128, m = 1.
L_FIELD = 64

# ADR-0060 D1: G1 cofactor (used only as a cross-check of the group order).
G1_COFACTOR = 0x396c8c005555e1568c00aaab0000aaab

# RFC 9380 Appendix E.2: 11-isogeny map constants, index i = coefficient of x'^i.
ISO_XNUM = [int(h, 16) for h in (
    "11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7",
    "17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb",
    "d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0",
    "1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861",
    "e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9",
    "1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983",
    "d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84",
    "17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e",
    "80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317",
    "169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e",
    "10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b",
    "6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229",
)]
ISO_XDEN = [int(h, 16) for h in (
    "8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c",
    "12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff",
    "b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19",
    "3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8",
    "13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e",
    "e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5",
    "772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a",
    "14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e",
    "a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641",
    "95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a",
)] + [1]  # x'^10 is monic
ISO_YNUM = [int(h, 16) for h in (
    "90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33",
    "134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696",
    "cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6",
    "1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb",
    "8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb",
    "16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0",
    "4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2",
    "987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29",
    "9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587",
    "e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30",
    "19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132",
    "18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e",
    "b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8",
    "245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133",
    "5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b",
    "15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604",
)]
ISO_YDEN = [int(h, 16) for h in (
    "16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1",
    "1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d",
    "58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2",
    "16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416",
    "be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d",
    "8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac",
    "166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c",
    "16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9",
    "1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a",
    "167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55",
    "4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8",
    "accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092",
    "ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc",
    "2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7",
    "e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f",
)] + [1]  # x'^15 is monic

# CIP-0381 "Generators: G1" (affine coordinates) and its compressed byte list.
G1_GEN_X = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
G1_GEN_Y = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
G1_GEN_CIP0381_BYTES = bytes([
    151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140, 79, 151, 116, 185,
    5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187])
# From the author's own knowledge (cross-checked against the CIP-0381 list above).
G1_GEN_COMPRESSED_HEX = (
    "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac58"
    "6c55e83ff97a1aeffb3af00adb22c6bb")

# ADR-0060 D2 and D4 tags.
DST_B = b"ZeroJ-pedersen-bls12-381-g1-basis-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_"
DST_S = b"ZeroJ-pedersen-bls12-381-g1-bytes-v1-H2S-XMD:SHA-256"
assert len(DST_B) == 68, len(DST_B)
assert len(DST_S) == 52, len(DST_S)

# Zcash / CIP-0381 flag bits (most significant three bits of octet 0).
FLAG_COMPRESSED = 0x80
FLAG_INFINITY = 0x40
FLAG_SORT = 0x20

IDENTITY_ENCODING = bytes([0xC0]) + bytes(47)

MALFORMED = "MALFORMED_ENCODING"
NOT_IN_SUBGROUP = "NOT_IN_SUBGROUP"


# ---------------------------------------------------------------------------
# Byte-string utilities (RFC 9380 Section 4)
# ---------------------------------------------------------------------------

def i2osp(value: int, length: int) -> bytes:
    if value < 0 or value >= 1 << (8 * length):
        raise ValueError("I2OSP: integer too large")
    return value.to_bytes(length, "big")


def os2ip(octets: bytes) -> int:
    return int.from_bytes(octets, "big")


def strxor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("strxor: length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# GF(P_381) arithmetic
# ---------------------------------------------------------------------------

def fp(x: int) -> int:
    return x % P_381


def inv0(x: int) -> int:
    """RFC 9380 Section 4: inv0(0) == 0, else x^(p-2)."""
    x %= P_381
    return 0 if x == 0 else pow(x, P_381 - 2, P_381)


def is_square(x: int) -> bool:
    """RFC 9380 Section 4: True iff x^((p-1)/2) is 0 or 1."""
    t = pow(x % P_381, (P_381 - 1) // 2, P_381)
    return t == 0 or t == 1


def sqrt(x: int) -> int:
    """Square root for p = 3 mod 4 (RFC 9380 Appendix I.1); caller ensures is_square."""
    assert P_381 % 4 == 3
    r = pow(x % P_381, (P_381 + 1) // 4, P_381)
    if (r * r - x) % P_381 != 0:
        raise ValueError("sqrt: not a square")
    return r


def sgn0(x: int) -> int:
    """RFC 9380 Section 4.1, m == 1."""
    return (x % P_381) % 2


# ---------------------------------------------------------------------------
# expand_message_xmd with SHA-256 (RFC 9380 Section 5.3.1)
# ---------------------------------------------------------------------------

SHA256_B_IN_BYTES = 32
SHA256_S_IN_BYTES = 64


def expand_message_xmd_trace(msg: bytes, dst: bytes, len_in_bytes: int):
    """Returns (uniform_bytes, b_0, [b_1, ..., b_ell], dst_prime, msg_prime)."""
    if not isinstance(msg, (bytes, bytearray)) or not isinstance(dst, (bytes, bytearray)):
        raise TypeError("msg and DST must be bytes")
    if len(dst) == 0:
        # RFC 9380 Section 3.1 item 2: tags MUST have nonzero length.
        raise ValueError("ABORT: empty DST")
    if len_in_bytes < 0:
        raise ValueError("ABORT: negative len_in_bytes")
    ell = -(-len_in_bytes // SHA256_B_IN_BYTES)  # ceil
    if ell > 255 or len_in_bytes > 65535 or len(dst) > 255:
        raise ValueError("ABORT: expand_message_xmd parameter out of range")
    dst_prime = bytes(dst) + i2osp(len(dst), 1)
    z_pad = i2osp(0, SHA256_S_IN_BYTES)
    l_i_b_str = i2osp(len_in_bytes, 2)
    msg_prime = z_pad + bytes(msg) + l_i_b_str + i2osp(0, 1) + dst_prime
    b0 = hashlib.sha256(msg_prime).digest()
    b = [hashlib.sha256(b0 + i2osp(1, 1) + dst_prime).digest()]
    for i in range(2, ell + 1):
        b.append(hashlib.sha256(strxor(b0, b[-1]) + i2osp(i, 1) + dst_prime).digest())
    uniform = b"".join(b)[:len_in_bytes]
    return uniform, b0, b, dst_prime, msg_prime


def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    return expand_message_xmd_trace(msg, dst, len_in_bytes)[0]


# ---------------------------------------------------------------------------
# hash_to_field (RFC 9380 Section 5.2), m = 1, L = 64
# ---------------------------------------------------------------------------

def hash_to_field(msg: bytes, count: int, dst: bytes) -> list[int]:
    len_in_bytes = count * 1 * L_FIELD
    uniform = expand_message_xmd(msg, dst, len_in_bytes)
    return [os2ip(uniform[L_FIELD * i: L_FIELD * (i + 1)]) % P_381 for i in range(count)]


# ---------------------------------------------------------------------------
# Affine curve arithmetic.  None is the point at infinity.
# ---------------------------------------------------------------------------

def on_curve_e(pt) -> bool:
    if pt is None:
        return True
    x, y = pt
    return 0 <= x < P_381 and 0 <= y < P_381 and (y * y - (x * x * x + B_E)) % P_381 == 0


def on_curve_e_prime(pt) -> bool:
    x, y = pt
    return (y * y - (x * x * x + A_PRIME * x + B_PRIME)) % P_381 == 0


def point_neg(pt):
    if pt is None:
        return None
    x, y = pt
    return (x, (-y) % P_381)


def point_add(p1, p2, a: int = 0):
    """Affine addition on y^2 = x^3 + a*x + b (b is not needed)."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P_381 == 0:
            return None  # P + (-P), including doubling a point with y == 0
        lam = (3 * x1 * x1 + a) * inv0(2 * y1) % P_381
    else:
        lam = (y2 - y1) * inv0(x2 - x1) % P_381
    x3 = (lam * lam - x1 - x2) % P_381
    y3 = (lam * (x1 - x3) - y1) % P_381
    return (x3, y3)


def scalar_mul(k: int, pt):
    """Left-to-right double-and-add on E.  Public reference only, NOT constant-time."""
    if k < 0:
        raise ValueError("scalar_mul: negative scalar")
    acc = None
    for bit in bin(k)[2:] if k else "":
        acc = point_add(acc, acc)
        if bit == "1":
            acc = point_add(acc, pt)
    return acc


def in_subgroup(pt) -> bool:
    return scalar_mul(Q, pt) is None


# ---------------------------------------------------------------------------
# map_to_curve: simplified SWU on E' (Section 6.6.2) + 11-isogeny (Appendix E.2)
# ---------------------------------------------------------------------------

def map_to_curve_simple_swu(u: int):
    a, b, z = A_PRIME, B_PRIME, SSWU_Z
    u %= P_381
    tv1 = inv0(z * z * pow(u, 4, P_381) + z * u * u)
    x1 = (-b * inv0(a)) * (1 + tv1) % P_381
    if tv1 == 0:
        x1 = b * inv0(z * a) % P_381
    gx1 = (pow(x1, 3, P_381) + a * x1 + b) % P_381
    x2 = z * u * u * x1 % P_381
    gx2 = (pow(x2, 3, P_381) + a * x2 + b) % P_381
    if is_square(gx1):
        x, y = x1, sqrt(gx1)
    else:
        x, y = x2, sqrt(gx2)
    if sgn0(u) != sgn0(y):
        y = (-y) % P_381
    return (x, y)


def _poly(coeffs: list[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % P_381
    return acc


def iso_map(pt_prime):
    xp, yp = pt_prime
    x_num = _poly(ISO_XNUM, xp)
    x_den = _poly(ISO_XDEN, xp)
    y_num = _poly(ISO_YNUM, xp)
    y_den = _poly(ISO_YDEN, xp)
    if x_den == 0 or y_den == 0:
        return None  # Section 6.6.3: exceptional case returns the identity
    x = x_num * inv0(x_den) % P_381
    y = yp * y_num % P_381 * inv0(y_den) % P_381
    return (x, y)


def map_to_curve(u: int):
    pt_prime = map_to_curve_simple_swu(u)
    assert on_curve_e_prime(pt_prime), "SSWU output not on E'"
    pt = iso_map(pt_prime)
    assert on_curve_e(pt), "iso_map output not on E"
    return pt


def clear_cofactor(pt):
    return scalar_mul(H_EFF, pt)


def hash_to_curve_trace(msg: bytes, dst: bytes):
    """Returns (P, u0, u1, Q0, Q1) for BLS12381G1_XMD:SHA-256_SSWU_RO_."""
    u0, u1 = hash_to_field(msg, 2, dst)
    q0 = map_to_curve(u0)
    q1 = map_to_curve(u1)
    r = point_add(q0, q1)
    p_out = clear_cofactor(r)
    return p_out, u0, u1, q0, q1


def hash_to_curve(msg: bytes, dst: bytes):
    return hash_to_curve_trace(msg, dst)[0]


# ---------------------------------------------------------------------------
# Zcash compressed encoding (CIP-0381) and the ADR-0060 D3 strict decoder
# ---------------------------------------------------------------------------

HALF_P = (P_381 - 1) // 2


def compress(pt) -> bytes:
    if pt is None:
        return IDENTITY_ENCODING
    x, y = pt
    out = bytearray(i2osp(x, 48))
    out[0] |= FLAG_COMPRESSED
    if y > HALF_P:  # y is the lexicographically largest of {y, p - y}
        out[0] |= FLAG_SORT
    return bytes(out)


def strict_decode(b):
    """ADR-0060 D3, steps in table order.

    Returns ("ok", point) with point None for the identity, or
    ("MALFORMED_ENCODING", step) / ("NOT_IN_SUBGROUP", 7).
    """
    # Step 1: null.  Python analogue of NullPointerException.
    if b is None:
        raise TypeError("step 1: null encoding")
    b = bytes(b)
    # Step 2: length.
    if len(b) != 48:
        return (MALFORMED, 2)
    flags = b[0] & 0xE0
    # Step 3: compression flag must be set.
    if not flags & FLAG_COMPRESSED:
        return (MALFORMED, 3)
    # Step 4: infinity flag.  Exact 0xC0 || 0^47 is the identity; anything else is malformed.
    if flags & FLAG_INFINITY:
        if b == IDENTITY_ENCODING:
            return ("ok", None)
        return (MALFORMED, 4)
    # Steps 5-7: finite encodings only.
    x = os2ip(bytes([b[0] & 0x1F]) + b[1:])
    if x >= P_381:
        return (MALFORMED, 5)
    rhs = (pow(x, 3, P_381) + B_E) % P_381
    if not is_square(rhs):
        return (MALFORMED, 6)
    y = sqrt(rhs)
    # rhs == 0 would mean a 2-torsion point; impossible because #E = h*q is odd.
    want_large = bool(flags & FLAG_SORT)
    if (y > HALF_P) != want_large:
        y = (-y) % P_381
    pt = (x, y)
    assert on_curve_e(pt)
    if not in_subgroup(pt):
        return (NOT_IN_SUBGROUP, 7)
    return ("ok", pt)


# ---------------------------------------------------------------------------
# ADR-0060 D2 basis, D4 byte mapping, D1/D5 commitment
# ---------------------------------------------------------------------------

def derive_basis(dst: bytes = DST_B, msg_g: bytes = b"G", msg_h: bytes = b"H"):
    g = hash_to_curve(msg_g, dst)
    h = hash_to_curve(msg_h, dst)
    if g is None or h is None:
        raise AssertionError("basis point is the identity")
    if not (on_curve_e(g) and on_curve_e(h)):
        raise AssertionError("basis point not on curve")
    if not (in_subgroup(g) and in_subgroup(h)):
        raise AssertionError("basis point not in the prime-order subgroup")
    if g == h or g == point_neg(h):
        raise AssertionError("G == +/-H")
    return g, h


def hash_bytes_to_scalar_g1_trace(payload: bytes, dst: bytes = DST_S):
    """ADR-0060 D4.  Returns dict with b0, b1, b2 (full 32 octets), uniform (48), scalar."""
    payload = bytes(payload)
    msg = payload + i2osp(len(payload), 8)
    uniform, b0, bs, _, _ = expand_message_xmd_trace(msg, dst, 48)
    assert len(bs) == 2 and uniform == bs[0] + bs[1][:16]
    s = os2ip(uniform) % Q
    return {"b0": b0, "b1": bs[0], "b2": bs[1], "uniform": uniform, "scalar": s}


def hash_bytes_to_scalar_g1(payload: bytes, dst: bytes = DST_S) -> int:
    return hash_bytes_to_scalar_g1_trace(payload, dst)["scalar"]


def _check1(name: str, v) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise TypeError(f"{name} must be an int")
    if not 0 <= v < Q:
        raise ValueError(f"NON_CANONICAL_SCALAR: {name} outside [0, q)")
    return v


def commit(m: int, r: int, basis=None):
    """C = [m]G + [r]H, check 1 on m and r (never reduced)."""
    _check1("m", m)
    _check1("r", r)
    g, h = basis if basis is not None else derive_basis()
    return point_add(scalar_mul(m, g), scalar_mul(r, h))


def commit_bytes(payload: bytes, r: int, basis=None):
    _check1("r", r)
    s = hash_bytes_to_scalar_g1(payload)
    g, h = basis if basis is not None else derive_basis()
    return point_add(scalar_mul(s, g), scalar_mul(r, h))


# ---------------------------------------------------------------------------
# RFC 9380 vectors (copied from the RFC text; hex whitespace removed)
# ---------------------------------------------------------------------------

J91_DST = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"
J91_VECTORS = [
    {
        "msg": b"",
        "Px": "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
        "Py": "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
        "u0": "0ba14bd907ad64a016293ee7c2d276b8eae71f25a4b941eece7b0d89f17f75cb3ae5438a614fb61d6835ad59f29c564f",
        "u1": "019b9bd7979f12657976de2884c7cce192b82c177c80e0ec604436a7f538d231552f0d96d9f7babe5fa3b19b3ff25ac9",
        "Q0x": "11a3cce7e1d90975990066b2f2643b9540fa40d6137780df4e753a8054d07580db3b7f1f03396333d4a359d1fe3766fe",
        "Q0y": "0eeaf6d794e479e270da10fdaf768db4c96b650a74518fc67b04b03927754bac66f3ac720404f339ecdcc028afa091b7",
        "Q1x": "160003aaf1632b13396dbad518effa00fff532f604de1a7fc2082ff4cb0afa2d63b2c32da1bef2bf6c5ca62dc6b72f9c",
        "Q1y": "0d8bb2d14e20cf9f6036152ed386d79189415b6d015a20133acb4e019139b94e9c146aaad5817f866c95d609a361735e",
    },
    {
        "msg": b"abc",
        "Px": "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
        "Py": "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d",
        "u0": "0d921c33f2bad966478a03ca35d05719bdf92d347557ea166e5bba579eea9b83e9afa5c088573c2281410369fbd32951",
        "u1": "003574a00b109ada2f26a37a91f9d1e740dffd8d69ec0c35e1e9f4652c7dba61123e9dd2e76c655d956e2b3462611139",
        "Q0x": "125435adce8e1cbd1c803e7123f45392dc6e326d292499c2c45c5865985fd74fe8f042ecdeeec5ecac80680d04317d80",
        "Q0y": "0e8828948c989126595ee30e4f7c931cbd6f4570735624fd25aef2fa41d3f79cfb4b4ee7b7e55a8ce013af2a5ba20bf2",
        "Q1x": "11def93719829ecda3b46aa8c31fc3ac9c34b428982b898369608e4f042babee6c77ab9218aad5c87ba785481eff8ae4",
        "Q1y": "0007c9cef122ccf2efd233d6eb9bfc680aa276652b0661f4f820a653cec1db7ff69899f8e52b8e92b025a12c822a6ce6",
    },
    {
        "msg": b"abcdef0123456789",
        "Px": "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
        "Py": "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709",
        "u0": "062d1865eb80ebfa73dcfc45db1ad4266b9f3a93219976a3790ab8d52d3e5f1e62f3b01795e36834b17b70e7b76246d4",
        "u1": "0cdc3e2f271f29c4ff75020857ce6c5d36008c9b48385ea2f2bf6f96f428a3deb798aa033cd482d1cdc8b30178b08e3a",
        "Q0x": "08834484878c217682f6d09a4b51444802fdba3d7f2df9903a0ddadb92130ebbfa807fffa0eabf257d7b48272410afff",
        "Q0y": "0b318f7ecf77f45a0f038e62d7098221d2dbbca2a394164e2e3fe953dc714ac2cde412d8f2d7f0c03b259e6795a2508e",
        "Q1x": "158418ed6b27e2549f05531a8281b5822b31c3bf3144277fbb977f8d6e2694fedceb7011b3c2b192f23e2a44b2bd106e",
        "Q1y": "1879074f344471fac5f839e2b4920789643c075792bec5af4282c73f7941cda5aa77b00085eb10e206171b9787c4169f",
    },
    {
        "msg": b"q128_" + b"q" * 128,
        "Px": "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
        "Py": "1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38",
        "u0": "010476f6a060453c0b1ad0b628f3e57c23039ee16eea5e71bb87c3b5419b1255dc0e5883322e563b84a29543823c0e86",
        "u1": "0b1a912064fb0554b180e07af7e787f1f883a0470759c03c1b6509eb8ce980d1670305ae7b928226bb58fdc0a419f46e",
        "Q0x": "0cbd7f84ad2c99643fea7a7ac8f52d63d66cefa06d9a56148e58b984b3dd25e1f41ff47154543343949c64f88d48a710",
        "Q0y": "052c00e4ed52d000d94881a5638ae9274d3efc8bc77bc0e5c650de04a000b2c334a9e80b85282a00f3148dfdface0865",
        "Q1x": "06493fb68f0d513af08be0372f849436a787e7b701ae31cb964d968021d6ba6bd7d26a38aaa5a68e8c21a6b17dc8b579",
        "Q1y": "02e98f2ccf5802b05ffaac7c20018bc0c0b2fd580216c4aa2275d2909dc0c92d0d0bdc979226adeb57a29933536b6bb4",
    },
    {
        "msg": b"a512_" + b"a" * 512,
        "Px": "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
        "Py": "05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8",
        "u0": "0a8ffa7447f6be1c5a2ea4b959c9454b431e29ccc0802bc052413a9c5b4f9aac67a93431bd480d15be1e057c8a08e8c6",
        "u1": "05d487032f602c90fa7625dbafe0f4a49ef4a6b0b33d7bb349ff4cf5410d297fd6241876e3e77b651cfc8191e40a68b7",
        "Q0x": "0cf97e6dbd0947857f3e578231d07b309c622ade08f2c08b32ff372bd90db19467b2563cc997d4407968d4ac80e154f8",
        "Q0y": "127f0cddf2613058101a5701f4cb9d0861fd6c2a1b8e0afe194fccf586a3201a53874a2761a9ab6d7220c68661a35ab3",
        "Q1x": "092f1acfa62b05f95884c6791fba989bbe58044ee6355d100973bf9553ade52b47929264e6ae770fb264582d8dce512a",
        "Q1y": "028e6d0169a72cfedb737be45db6c401d3adfb12c58c619c82b93a5dfcccef12290de530b0480575ddc8397cda0bbebf",
    },
]

K1_DST = b"QUUX-V01-CS02-with-expander-SHA256-128"
K1_DST_PRIME = "515555582d5630312d435330322d776974682d657870616e6465722d5348413235362d31323826"
K1_ZPAD_HEX = "00" * 64
K1_VECTORS = [
    # (msg, len_in_bytes, msg_prime hex or None when not transcribed, uniform_bytes hex)
    (b"", 0x20,
     K1_ZPAD_HEX + "002000" + K1_DST_PRIME,
     "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"),
    (b"abc", 0x20,
     K1_ZPAD_HEX + "616263" + "002000" + K1_DST_PRIME,
     "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"),
    (b"abcdef0123456789", 0x20,
     K1_ZPAD_HEX + "61626364656630313233343536373839" + "002000" + K1_DST_PRIME,
     "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"),
    (b"q128_" + b"q" * 128, 0x20, None,
     "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9"),
    (b"a512_" + b"a" * 512, 0x20, None,
     "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c"),
    (b"", 0x80,
     K1_ZPAD_HEX + "008000" + K1_DST_PRIME,
     "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbee0d121587713a3e0dd4d5e69e93eb7cd4f5df4"
     "cd103e188cf60cb02edc3edf18eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dcc541708d3491184472"
     "c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced"),
    (b"abc", 0x80,
     K1_ZPAD_HEX + "616263" + "008000" + K1_DST_PRIME,
     "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b"
     "664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425"
     "cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"),
    (b"abcdef0123456789", 0x80,
     K1_ZPAD_HEX + "61626364656630313233343536373839" + "008000" + K1_DST_PRIME,
     "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9ebd0df635cd1f208e2038e760c4994984ce73f"
     "0d55ea9f22af83ba4734569d4bc95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be14cf489b37fe1a72f7d"
     "e2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df"),
    (b"q128_" + b"q" * 128, 0x80, None,
     "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bbd88fd75d8b9a09486c60123dfa1d73c1cc3169"
     "761b17476d3c6b7cbbd727acd0e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b29fa7fabb3ea7d520e"
     "e603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a"),
    (b"a512_" + b"a" * 512, 0x80, None,
     "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d06d6792f8a7d12794e90efed817d96920d72889"
     "6a4510864370c207f99bd4a608ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4a45d22e86f6db5dd43"
     "d98a294bebb9125d5b794e9d2a81181066eb954966a487"),
]


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

class _Results:
    def __init__(self, verbose: bool):
        self.verbose = verbose
        self.passed: list[str] = []
        self.failed: list[str] = []

    def check(self, name: str, cond: bool, detail: str = "") -> None:
        if cond:
            self.passed.append(name)
            if self.verbose:
                print(f"PASS {name}")
        else:
            self.failed.append(name)
            if self.verbose:
                print(f"FAIL {name} {detail}".rstrip())


def _h48(v: int) -> str:
    return i2osp(v, 48).hex()


def _msg_label(msg: bytes) -> str:
    if len(msg) > 16:
        return repr(msg[:5].decode() + f"<{len(msg) - 5} x {chr(msg[-1])}>")
    return repr(msg.decode())


def run_self_test(verbose: bool = True) -> _Results:
    res = _Results(verbose)
    chk = res.check

    # Constant sanity cross-checks.
    chk("const: P_381 = 3 mod 4", P_381 % 4 == 3)
    chk("const: P_381 bit length 381", P_381.bit_length() == 381)
    chk("const: q bit length 255", Q.bit_length() == 255)
    chk("const: len(DST_B) == 68", len(DST_B) == 68)
    chk("const: len(DST_S) == 52", len(DST_S) == 52)
    chk("const: Z = 11 is a non-square in GF(p)", not is_square(SSWU_Z))
    chk("const: isogeny coefficient counts (12, 11, 16, 16)",
        (len(ISO_XNUM), len(ISO_XDEN), len(ISO_YNUM), len(ISO_YDEN)) == (12, 11, 16, 16))

    # RFC 9380 Appendix K.1.
    for i, (msg, n, msg_prime_hex, want) in enumerate(K1_VECTORS):
        name = f"RFC9380 K.1 expand_message_xmd SHA-256 msg={_msg_label(msg)} len=0x{n:02x}"
        try:
            uniform, _, _, dst_prime, msg_prime = expand_message_xmd_trace(msg, K1_DST, n)
            ok = uniform.hex() == want and dst_prime.hex() == K1_DST_PRIME
            if msg_prime_hex is not None:
                ok = ok and msg_prime.hex() == msg_prime_hex
            chk(name + (" (DST_prime, msg_prime, uniform_bytes)" if msg_prime_hex
                        else " (DST_prime, uniform_bytes)"), ok, uniform.hex())
        except Exception as e:  # pragma: no cover - reported as failure
            chk(name, False, repr(e))

    # expand_message_xmd ABORT conditions.
    def aborts(fn) -> bool:
        try:
            fn()
        except ValueError:
            return True
        return False
    chk("xmd ABORT: ell > 255 (len_in_bytes = 8161)", aborts(lambda: expand_message_xmd(b"", K1_DST, 255 * 32 + 1)))
    chk("xmd accepts ell == 255 (len_in_bytes = 8160)", len(expand_message_xmd(b"", K1_DST, 255 * 32)) == 8160)
    chk("xmd ABORT: len_in_bytes > 65535", aborts(lambda: expand_message_xmd(b"", K1_DST, 65536)))
    chk("xmd ABORT: len(DST) > 255", aborts(lambda: expand_message_xmd(b"", b"x" * 256, 32)))
    chk("xmd accepts len(DST) == 255", len(expand_message_xmd(b"", b"x" * 255, 32)) == 32)
    chk("xmd ABORT: empty DST (RFC 9380 Section 3.1)", aborts(lambda: expand_message_xmd(b"", b"", 32)))

    # RFC 9380 Appendix J.9.1.
    for v in J91_VECTORS:
        label = _msg_label(v["msg"])
        try:
            p_out, u0, u1, q0, q1 = hash_to_curve_trace(v["msg"], J91_DST)
            chk(f"RFC9380 J.9.1 msg={label} u[0]", _h48(u0) == v["u0"], _h48(u0))
            chk(f"RFC9380 J.9.1 msg={label} u[1]", _h48(u1) == v["u1"], _h48(u1))
            chk(f"RFC9380 J.9.1 msg={label} Q0", q0 is not None and
                (_h48(q0[0]), _h48(q0[1])) == (v["Q0x"], v["Q0y"]))
            chk(f"RFC9380 J.9.1 msg={label} Q1", q1 is not None and
                (_h48(q1[0]), _h48(q1[1])) == (v["Q1x"], v["Q1y"]))
            chk(f"RFC9380 J.9.1 msg={label} P", p_out is not None and
                (_h48(p_out[0]), _h48(p_out[1])) == (v["Px"], v["Py"]))
            chk(f"RFC9380 J.9.1 msg={label} P on E and in G1",
                p_out is not None and on_curve_e(p_out) and in_subgroup(p_out))
            enc = compress(p_out)
            chk(f"RFC9380 J.9.1 msg={label} P compress/strict_decode round trip",
                strict_decode(enc) == ("ok", p_out))
        except Exception as e:  # pragma: no cover
            chk(f"RFC9380 J.9.1 msg={label}", False, repr(e))

    # Generator.
    gen = (G1_GEN_X, G1_GEN_Y)
    chk("g1: CIP-0381 generator on E", on_curve_e(gen))
    chk("g1: CIP-0381 generator in prime-order subgroup ([q]g1 == O)", in_subgroup(gen))
    chk("g1: (0, 2) has order 3 and [h*q](0, 2) == O (ADR cofactor h is a multiple of 3)",
        scalar_mul(G1_COFACTOR * Q, (0, 2)) is None and scalar_mul(3, (0, 2)) is None)
    chk("g1: compressed hex (author knowledge) == CIP-0381 byte list",
        bytes.fromhex(G1_GEN_COMPRESSED_HEX) == G1_GEN_CIP0381_BYTES)
    chk("g1: compress(CIP-0381 X, Y) == CIP-0381 bytes", compress(gen) == G1_GEN_CIP0381_BYTES)
    chk("g1: strict_decode(CIP-0381 bytes) == (X, Y)", strict_decode(G1_GEN_CIP0381_BYTES) == ("ok", gen))
    neg_enc = compress(point_neg(gen))
    chk("g1: -g1 differs only in sort flag and decodes to -g1",
        neg_enc[0] ^ G1_GEN_CIP0381_BYTES[0] == FLAG_SORT and neg_enc[1:] == G1_GEN_CIP0381_BYTES[1:]
        and strict_decode(neg_enc) == ("ok", point_neg(gen)))

    # ADR-0060 D3 decoder cases.
    chk("D3 positive: identity 0xC0||0^47 -> identity", strict_decode(IDENTITY_ENCODING) == ("ok", None))
    chk("D3 compress(identity) == 0xC0||0^47", compress(None) == IDENTITY_ENCODING)
    chk("D3 negative: infinity + sort flag 0xE0||0^47 -> MALFORMED step 4",
        strict_decode(bytes([0xE0]) + bytes(47)) == (MALFORMED, 4))
    chk("D3 negative: infinity + nonzero last coordinate bit -> MALFORMED step 4",
        strict_decode(bytes([0xC0]) + bytes(46) + b"\x01") == (MALFORMED, 4))
    chk("D3 negative: infinity + nonzero coordinate bit in octet 0 (0xC1) -> MALFORMED step 4",
        strict_decode(bytes([0xC1]) + bytes(47)) == (MALFORMED, 4))
    chk("D3 negative: 0x80||0^47 (x=0, order-3 point) -> NOT_IN_SUBGROUP step 7",
        strict_decode(bytes([0x80]) + bytes(47)) == (NOT_IN_SUBGROUP, 7))
    chk("D3 negative: 0xA0||0^47 (x=0, other y) -> NOT_IN_SUBGROUP step 7",
        strict_decode(bytes([0xA0]) + bytes(47)) == (NOT_IN_SUBGROUP, 7))
    chk("D3 negative: 47-octet input -> MALFORMED step 2", strict_decode(G1_GEN_CIP0381_BYTES[:47]) == (MALFORMED, 2))
    chk("D3 negative: 49-octet input -> MALFORMED step 2", strict_decode(G1_GEN_CIP0381_BYTES + b"\x00") == (MALFORMED, 2))
    chk("D3 negative: empty input -> MALFORMED step 2", strict_decode(b"") == (MALFORMED, 2))
    chk("D3 negative: generator with compression flag cleared -> MALFORMED step 3",
        strict_decode(bytes([G1_GEN_CIP0381_BYTES[0] & 0x7F]) + G1_GEN_CIP0381_BYTES[1:]) == (MALFORMED, 3))
    chk("D3 negative: 0x40||0^47 (infinity without compression) -> MALFORMED step 3",
        strict_decode(bytes([0x40]) + bytes(47)) == (MALFORMED, 3))
    chk("D3 negative: 0x00||0^47 -> MALFORMED step 3", strict_decode(bytes(48)) == (MALFORMED, 3))
    p_enc = bytearray(i2osp(P_381, 48))
    p_enc[0] |= FLAG_COMPRESSED
    chk("D3 negative: x == P_381 -> MALFORMED step 5", strict_decode(bytes(p_enc)) == (MALFORMED, 5))
    max_enc = bytes([0x9F]) + b"\xff" * 47
    chk("D3 negative: x == 2^381 - 1 -> MALFORMED step 5", strict_decode(max_enc) == (MALFORMED, 5))
    x_ns = 1
    while is_square(x_ns ** 3 + B_E):
        x_ns += 1
    ns_enc = bytearray(i2osp(x_ns, 48))
    ns_enc[0] |= FLAG_COMPRESSED
    chk(f"D3 negative: x = {x_ns} (x^3+4 non-square) -> MALFORMED step 6",
        strict_decode(bytes(ns_enc)) == (MALFORMED, 6))
    # Added with the spec's decoder table (ADR-0060 M0 review): a curve point outside the subgroup
    # with x != 0, and a mixed-order point. Both use only this module's own decoder and arithmetic.
    x4 = bytes([0x80]) + bytes(46) + b"\x04"
    chk("D3 negative: x = 4 (smallest positive x on E) -> NOT_IN_SUBGROUP step 7",
        strict_decode(x4) == (NOT_IN_SUBGROUP, 7))
    g_basis, _ = derive_basis()
    mixed = compress(point_add(g_basis, (0, 2)))
    chk("D3 negative: G + (0, 2) (mixed order) -> NOT_IN_SUBGROUP step 7",
        mixed.hex() == "b6ee2defa35097e6bbaea5ab251479b37157dedfcbc4b319181bf28298f048a66eb93dc0230190c18ae135644c2d3df4"
        and strict_decode(mixed) == (NOT_IN_SUBGROUP, 7))
    nc = bytearray(i2osp(P_381 + 1, 48))  # non-canonical alias of x = 1; fits in 381 bits
    nc[0] |= FLAG_COMPRESSED
    chk("D3 negative: x = P_381 + 1 (non-canonical alias of 1) -> MALFORMED step 5",
        strict_decode(bytes(nc)) == (MALFORMED, 5))
    try:
        strict_decode(None)
        chk("D3 step 1: None raises", False)
    except TypeError:
        chk("D3 step 1: None raises", True)

    # Commitment scalar check 1.
    def rejects(fn) -> bool:
        try:
            fn()
        except (ValueError, TypeError):
            return True
        return False
    basis = derive_basis()
    chk("check 1: m == q rejected", rejects(lambda: commit(Q, 0, basis)))
    chk("check 1: r == q rejected", rejects(lambda: commit(0, Q, basis)))
    chk("check 1: m == -1 rejected", rejects(lambda: commit(-1, 0, basis)))
    chk("check 1: r == -1 rejected", rejects(lambda: commit(0, -1, basis)))
    chk("check 1: bool rejected", rejects(lambda: commit(True, 0, basis)))
    chk("check 1 (bytes profile): r == q rejected", rejects(lambda: commit_bytes(b"x", Q, basis)))

    # Mutation sanity: outputs must change.
    g, h = basis
    g_v2, h_v2 = derive_basis(DST_B.replace(b"-v1-", b"-v2-"))
    chk("mutation: DST_B '-v1-' -> '-v2-' changes G and H", g_v2 != g and h_v2 != h)
    chk("mutation: swapping messages G<->H swaps the points (G != H)",
        derive_basis(DST_B, b"H", b"G") == (h, g) and g != h)
    s_abc = hash_bytes_to_scalar_g1(b"abc")
    chk("mutation: DST_S '-v1-' -> '-v2-' changes s",
        hash_bytes_to_scalar_g1(b"abc", DST_S.replace(b"-v1-", b"-v2-")) != s_abc)
    chk("mutation: payload 'abc' -> 'abd' changes s", hash_bytes_to_scalar_g1(b"abd") != s_abc)
    chk("mutation: length suffix matters (s(B) != OS2IP(xmd(B, DST_S, 48)) mod q)",
        s_abc != os2ip(expand_message_xmd(b"abc", DST_S, 48)) % Q)
    chk("mutation: commit(1, 0) != commit(0, 1)", commit(1, 0, basis) != commit(0, 1, basis))
    chk("homomorphism: commit(2,3) == commit(1,1) + commit(1,2)",
        commit(2, 3, basis) == point_add(commit(1, 1, basis), commit(1, 2, basis)))
    chk("bytes profile: commit_bytes(B, r) == commit(s(B), r)",
        commit_bytes(b"abc", 7, basis) == commit(s_abc, 7, basis))
    return res


# ---------------------------------------------------------------------------
# Default JSON report
# ---------------------------------------------------------------------------

def _pattern(n: int) -> bytes:
    return bytes((131 * i + 17) % 256 for i in range(n))


def _point_json(pt) -> dict:
    if pt is None:
        return {"compressedHex": IDENTITY_ENCODING.hex(), "xHex": None, "yHex": None}
    return {"compressedHex": compress(pt).hex(), "xHex": _h48(pt[0]), "yHex": _h48(pt[1])}


def build_report() -> dict:
    res = run_self_test(verbose=False)
    if res.failed:
        raise SystemExit("self-test failed: " + "; ".join(res.failed))
    g, h = derive_basis()
    payloads = [("empty", b"")]
    payloads += [(f"pattern-{n}", _pattern(n)) for n in (1, 55, 56, 64, 129, 1024)]
    payloads.append(("ascii-abc", b"abc"))
    bytes_map = []
    for label, payload in payloads:
        t = hash_bytes_to_scalar_g1_trace(payload)
        bytes_map.append({
            "label": label,
            "length": len(payload),
            "payloadSha256Hex": hashlib.sha256(payload).hexdigest(),
            "b0Hex": t["b0"].hex(),
            "b1Hex": t["b1"].hex(),
            "b2Hex": t["b2"].hex(),
            "uniformHex": t["uniform"].hex(),
            "scalar": str(t["scalar"]),
        })
    commitments = []
    for m, r in ((0, 0), (1, 0), (0, 1), (Q - 1, Q - 1), (12345, 67890)):
        c = commit(m, r, (g, h))
        commitments.append({"m": str(m), "r": str(r), "compressedHex": compress(c).hex()})
    assert commitments[0]["compressedHex"] == IDENTITY_ENCODING.hex()
    assert commitments[1]["compressedHex"] == compress(g).hex()
    assert commitments[2]["compressedHex"] == compress(h).hex()
    assert commit(Q - 1, Q - 1, (g, h)) == point_neg(point_add(g, h))
    for e in commitments:
        st, pt = strict_decode(bytes.fromhex(e["compressedHex"]))
        assert st == "ok"
    checks = [
        "len(DST_B) == 68 and len(DST_S) == 52",
        "G and H are not the identity",
        "G and H are on E: y^2 = x^3 + 4",
        "[q]G == O and [q]H == O (prime-order subgroup)",
        "G != H and G != -H",
        "compress/strict_decode round trip for G, H and every commitment",
        "commit(0,0) == identity 0xC0||0^47, commit(1,0) == G, commit(0,1) == H",
        "commit(q-1, q-1) == -(G + H)",
        "uniform == b1 || b2[0:16] for every bytesMap entry",
        f"self-test: {len(res.passed)} checks passed, 0 failed "
        "(RFC 9380 J.9.1 x5, K.1 x10, xmd ABORT rules, g1, D3 decoder cases, check 1, mutations)",
    ]
    return {
        "pythonVersion": sys.version.split()[0],
        "DST_B": DST_B.decode("ascii"),
        "DST_S": DST_S.decode("ascii"),
        "G": _point_json(g),
        "H": _point_json(h),
        "checks": checks,
        "bytesMap": bytes_map,
        "commitments": commitments,
    }


def main(argv: list[str]) -> int:
    if len(argv) == 1 and argv[0] == "--self-test":
        res = run_self_test(verbose=True)
        print(f"SUMMARY passed={len(res.passed)} failed={len(res.failed)}")
        return 1 if res.failed else 0
    if argv:
        print("usage: bls12_381_g1_reference.py [--self-test]", file=sys.stderr)
        return 2
    print(json.dumps(build_report(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
