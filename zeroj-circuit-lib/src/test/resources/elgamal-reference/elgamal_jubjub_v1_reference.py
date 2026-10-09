#!/usr/bin/env python3
"""Independent reference for the ZeroJ ``elgamal-jubjub-v1`` profile.

Written from ``docs/specs/elgamal-jubjub-v1.md`` and ``docs/specs/pedersen-jubjub-v1.md``
alone (curve constants, the base G and the point encoding come from the latter). No Java
source, no other Python file and no other repository file was read while writing it.

Python 3, standard library only. The algorithms are deliberately simple and direct:

* affine twisted-Edwards arithmetic (a = -1) with the unified addition law, one Fermat
  inversion per addition, and doubling done by the same addition;
* right-to-left double-and-add on the raw (unreduced) integer scalar;
* subgroup membership as ``[l]P == O``;
* a generic Tonelli-Shanks square root;
* linear search for small discrete logarithms.

Usage, from this directory::

    python3 elgamal_jubjub_v1_reference.py [--prototype PATH]

Prints ``key=value`` lines and rewrites ``reference-output.txt`` next to this script.
Exit status 0 means every check and every spec comparison passed, 1 means at least one did
not (the failing keys go to stderr; the output is still written).

``--prototype PATH`` parses a prototype output file instead of the embedded verbatim copy
(see ``PROTOTYPE_OUTPUT`` below).
"""

import hashlib
import math
import os
import platform
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(HERE, "reference-output.txt")
PROFILE = "elgamal-jubjub-v1"

# ---------------------------------------------------------------------------------------------
# Inputs: pedersen-jubjub-v1.md §1 (p, l, a, cofactor) and §2.1 (G_full), which
# elgamal-jubjub-v1.md §1 adopts. d is NOT taken from the spec: it is derived below.
# ---------------------------------------------------------------------------------------------
P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
L = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7
COFACTOR = 8
G_FULL = (0x62EDCBB8BF3787C88B0F03DDD60A8187CAF55D1B29BF81AFE4B3D35DF1A7ADFE, 11)

# ---------------------------------------------------------------------------------------------
# Comparison targets typed by hand from the specs. They are never used as inputs.
# ---------------------------------------------------------------------------------------------
PIN_D = 0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1
PIN_G_U = 0x3EA5C4673A121CA35ED37EE3B172F5EE04315C657FBE375F512DFEA318D56FE5
PIN_G_V = 0x57137B83EA6EDB4F78F7D30D3F616CB3B9AA6E8E40808413C10CEA38D50C55CB
PIN_G_ENC = "cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7"

# BLS12-381 curve parameter z (public knowledge). Used only to sanity-check that p is the
# BLS12-381 scalar-field order r = z^4 - z^2 + 1; never used to compute anything else.
BLS12_381_Z = -0xD201000000010000

# This reference's published plaintext-search limit (spec §6.3): linear search only, and
# refused above this many steps.
SEARCH_LIMIT = 1 << 18

# Verbatim copy of the prototype output
# zeroj-usecases/private-voting/src/test/resources/elgamal-reference/reference-output.txt
# (only this output file was read; the script beside it was not). Used only for the
# cross-check: its scalars and votes are inputs, its points are comparison targets.
PROTOTYPE_OUTPUT = """\
scalar sk1 04d1fe8403d794ac8a0fe6f27351172e9cf52c88a20b8bfa38c669863feba815
scalar sk2 0adb993226bc73a2a0927947921cfbd46192367b85593b6814c5fe540be6ccd1
scalar sk3 091d973e9f4d748a2f020a3ae9255fddd539b6d655c53f070745931367e01334
scalar k1 04b512806ac40491de91873fa67782988e8d2317c86f96b4985a74ebcdefc491
vote v1 1
A1 24d731b3830db22bf1cbbb3db05d3111e18c7f6ea9c090bb8893fe180bc46ad8 411c4ecbbc73c6621df6c5458f1d5cb392f5c9f7f184c1138cf0a5699e66cd8e
B1 490ca1f82d3b0b96eed6dbc31c7ee6694f6a286e6eb6b4be774ccca3a3300d87 1244b9618a2b8a7e86c60d9435ec6980cf294fd8f2939dfdc91eff06a817bf65
scalar k2 09d48660dd773ec05603a58385f10dfced84ab70ed3eaaa4e4ba4803b643913b
vote v2 0
A2 553bb6274ab11ee832f9fa88652dc3e904bd203d9edc1e26cb96ff75e616567a 3ceddb8180321eb518f830a6d2d03279d375c30a8cd51027ae7594ee58651f1f
B2 4a39ecadcf2baef72147d0d08019d8c62a5bdeceba5802eb134612b5e1c0c88c 352548776e293258ec855bf79237e5df7cf484cdef430bba70677e194164e0a0
scalar k3 054b224581dda63e334cbd7aa0f5fa97634f1619aab470616ab027e9fdb7bb86
vote v3 1
A3 32a6eb2c19d9ff249cbd20d7970379e358e082ede99edadfc2940d1d6dc5f771 0daf199a04bd4f17e9baccbfc7c59046bd6f7ae165e853d9792495f87d1dc191
B3 5ba3434a20e5dae7ebf1044c59449e797927d76c51d0fdc2b2114d1e57b973ce 29ddf232c514d9bd5c499c51fe1c8ad700e40d70109a0508473481c5fec909a9
scalar k4 037e5e72b592bd8e471b67da883551d5a15888cdc152e0ec9a15611ed479a817
vote v4 1
A4 0c739b0ce3bbd3a3e509a472f0fc75d5681c7dc5b334f21b036d4475f429e9e3 0db99b500c94e1f83c21f7c4dc6eda603d0176147378e08d7e4e69eb2a02a338
B4 4c4f27a3fdd76f5827a55c0126a470f1e5cbc8dea6bbc1e170180296cdae7596 55ba08dac449d3597eef19b0601b1ca8dfc2372afdc707bfa73f7043f2d6b98a
scalar k5 0a450d0c462a440d23d7237f4dac4998b32a59fe39c581cc6f11c3dc62c6c45a
vote v5 0
A5 08cbcc3baac32302d8671d7ab4a3b5ce08576f434ef7a772319825ccd5d026ad 636dc2dcdcbec5d808f256a91b09cc8a4b1c97bac56a47c2e0cd99ef03518ca1
B5 27d24473e8aa0147a230106896f4fa05121b155ff912f71a0a5939f93164e232 5209b4ec195cb6d9493a4c52d5dc8e63fd67418c7a0d598721c91b2d0fc93bb9
G 3ea5c4673a121ca35ed37ee3b172f5ee04315c657fbe375f512dfea318d56fe5 57137b83ea6edb4f78f7d30d3f616cb3b9aa6e8e40808413c10cea38d50c55cb
PK1 61e9605e8e899913a3574190e9b1aed1ef55a3575da061f70f30b7ed2f9cea00 0055cce24c827d50115bc27023d94c275f55990bee85632b62ad3e7b92d54a38
PK2 1b6178a8b72e239c26f48e4196302e14bdb3c354c238e42dd7c1256ef99a8beb 050631fa38402eb82c2790500914f40c2c2c38bd9edc2efbe47f5961142da369
PK3 488680c743d2b2d8e3a2019da7da251142fd3ea142df7cc85c447f85ceaea517 28ef135a3a5fd1e6846f022395e87b5c5de548c16dd08ebb0569aaf1e845e7a6
PK 0b367e0af00b1dc8a199e6c3d7ed5a3f1f5f37194e1f7f13735a5e1073d680da 3c67122a56a1850eef6c62bd4ff2672c7a620fccf12c6dd9fbe3389fd68abb61
sumA 0df6b80a173c5cffb3c9cf05bd3805028592eae889877e7b8059e137515cfc58 3dd9f7a4985085fa95f3f0fe5485c5260fa3b886cab184d82a9a7fc9d2a7f1f7
sumB 1d1d38f09c128c6c0aae25033745f812ddd60a93239df7acc9bc034e06b19fc0 5f5a83574d99a1f8c1aca599166dff242ed0162b62224a96c72c4b8295daabdb
D1 62c9843c3610e667d8374b9fa5f6c1d735d29240b02231f155b5a44b07b8a54a 6e693554f6e43d899cc19124ad7e5aaf4b54b959852308fcb14a3546dcc3d849
D2 4cd539431dc2e2a8eaf14676fe69f32abb3b0534812d647ebab3ab5dd7849a3f 47a25e10fbf83d5b583e6fa4f54ba6b3c123d022087eb17ae87ba2aa0f8616e0
D3 255b6920222d31de0447ee8e761fc63cfad102e0f6cbc0e0f54692652fc43662 61d4e52c477b588ff0f0bdba376b5feede3652253ac49bc7dc9bc99d609d2d8a
M 13d8c3c67691262cc869a019d5cbe5b22257879e46c56955beee75fcb689bbcd 479c33dba2949dba817ee156520e1df08d959c01c75a0058aea437cbd15d29c5
tally T 3
"""


# =============================================================================================
# Field F_p
# =============================================================================================

def inv(x):
    """Inverse in F_p by Fermat's little theorem (p is prime)."""
    x %= P
    if x == 0:
        raise ZeroDivisionError("inverse of zero in F_p")
    return pow(x, P - 2, P)


def legendre(x):
    """Euler's criterion: 0, 1 or p - 1."""
    return pow(x % P, (P - 1) // 2, P)


def is_square(x):
    x %= P
    return x == 0 or legendre(x) == 1


def sqrt_mod_p(x):
    """Generic Tonelli-Shanks. Returns some root r with r^2 = x, or raises."""
    x %= P
    if x == 0:
        return 0
    if legendre(x) != 1:
        raise ValueError("not a square")
    q, s = P - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while legendre(z) != P - 1:
        z += 1
    m = s
    c = pow(z, q, P)
    t = pow(x, q, P)
    r = pow(x, (q + 1) // 2, P)
    while t != 1:
        i = 1
        t2 = t * t % P
        while t2 != 1:
            t2 = t2 * t2 % P
            i += 1
        b = pow(c, 1 << (m - i - 1), P)
        m = i
        c = b * b % P
        t = t * c % P
        r = r * b % P
    if r * r % P != x:
        raise AssertionError("Tonelli-Shanks produced a wrong root")
    return r


def is_probable_prime(n):
    """Miller-Rabin with the first 20 primes as bases."""
    if n < 2:
        return False
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]
    for q in bases:
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# d = -10240 / 10241 mod p, derived here and compared with the pinned value later.
D = (-10240 * inv(10241)) % P
A_COEF = P - 1  # a = -1


# =============================================================================================
# Jubjub, affine twisted Edwards: -u^2 + v^2 = 1 + d u^2 v^2
# =============================================================================================

IDENTITY = (0, 1)


def on_curve(pt):
    u, v = pt
    if not (0 <= u < P and 0 <= v < P):
        return False
    uu = u * u % P
    vv = v * v % P
    return (A_COEF * uu + vv - 1 - D * uu % P * vv) % P == 0


def add(p1, p2):
    """Unified affine addition for a = -1:
    u3 = (u1 v2 + v1 u2) / (1 + d u1 u2 v1 v2)
    v3 = (v1 v2 + u1 u2) / (1 - d u1 u2 v1 v2)
    Complete on Jubjub (d non-square, a square); both denominators are inverted together."""
    u1, v1 = p1
    u2, v2 = p2
    t = D * u1 % P * u2 % P * v1 % P * v2 % P
    num_u = (u1 * v2 + v1 * u2) % P
    num_v = (v1 * v2 + u1 * u2) % P
    den_u = (1 + t) % P
    den_v = (1 - t) % P
    z = inv(den_u * den_v)
    return (num_u * den_v % P * z % P, num_v * den_u % P * z % P)


def neg(pt):
    return ((-pt[0]) % P, pt[1])


def sub(p1, p2):
    return add(p1, neg(p2))


def mul(k, pt):
    """Right-to-left double-and-add on the integer k itself (never reduced)."""
    if k < 0:
        return mul(-k, neg(pt))
    result = IDENTITY
    addend = pt
    while k:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        k >>= 1
    return result


def in_subgroup(pt):
    return on_curve(pt) and mul(L, pt) == IDENTITY


def point_sum(points):
    acc = IDENTITY
    for q in points:
        acc = add(acc, q)
    return acc


# =============================================================================================
# Encoding (pedersen-jubjub-v1 §4, adopted by elgamal-jubjub-v1 §7.1)
# =============================================================================================

def encode(pt):
    u, v = pt
    b = bytearray(v.to_bytes(32, "little"))
    if u & 1:
        b[31] |= 0x80
    return bytes(b)


def raw_v_bytes(v, sign):
    """32 bytes holding the integer v little-endian (v < 2^255) and the given sign bit."""
    b = bytearray(v.to_bytes(32, "little"))
    if b[31] & 0x80:
        raise ValueError("v does not fit below the sign bit")
    if sign:
        b[31] |= 0x80
    return bytes(b)


def decode_point(data):
    """Returns (status, point). status 'ok' or one of the reject_* outcomes of pedersen §4."""
    if len(data) != 32:
        return "reject_length", None
    sign = data[31] >> 7
    b = bytearray(data)
    b[31] &= 0x7F
    v = int.from_bytes(bytes(b), "little")
    if v >= P:
        return "reject_noncanonical_v", None
    vv = v * v % P
    den = (D * vv + 1) % P
    if den == 0:
        return "reject_den_zero", None  # unreachable on Jubjub
    w = (vv - 1) * inv(den) % P
    if not is_square(w):
        return "reject_non_square", None
    u = sqrt_mod_p(w)
    if u == 0 and sign == 1:
        return "reject_u_zero_sign_set", None
    if (u & 1) != sign:
        u = (P - u) % P
    pt = (u, v)
    if not on_curve(pt):
        raise AssertionError("decoded point is off the curve")
    return "ok", pt


def decode_ciphertext(data):
    """§7.2: exactly 64 bytes; each half decodes and lies in the subgroup; identity allowed.
    Halves are examined in order A then B (precedence is not specified by the spec)."""
    if len(data) != 64:
        return "reject_length", None
    halves = []
    for chunk in (data[:32], data[32:]):
        status, pt = decode_point(chunk)
        if status != "ok":
            return status, None
        if not in_subgroup(pt):
            return "reject_not_in_subgroup", None
        halves.append(pt)
    return "accept", (halves[0], halves[1])


def decode_public_key(data):
    """§7.3: §7.1 decoding, subgroup membership, not the identity."""
    status, pt = decode_point(data)
    if status != "ok":
        return status, None
    if not in_subgroup(pt):
        return "reject_not_in_subgroup", None
    if pt == IDENTITY:
        return "reject_identity_key", None
    return "accept", pt


def validate_affine(u, v, is_key):
    """§7.4 rules 1-4, in order."""
    if not (0 <= u < P and 0 <= v < P):
        return "reject_noncanonical"
    if not on_curve((u, v)):
        return "reject_off_curve"
    if not in_subgroup((u, v)):
        return "reject_not_in_subgroup"
    if is_key and (u, v) == IDENTITY:
        return "reject_identity_key"
    return "accept"


# =============================================================================================
# Profile objects: key context (§3.2), ciphertexts (§4, §5), decryption (§6)
# =============================================================================================

class Refused(Exception):
    pass


class DecryptionFailed(Exception):
    pass


class Context:
    """Joint-key context over possession-verified shares (§3.2). The shares passed here are
    computed locally from secrets held by this script, which is possession (§3.3)."""

    def __init__(self, shares):
        if not shares:
            raise Refused("empty share list")
        for s in shares:
            if s == IDENTITY or not in_subgroup(s):
                raise Refused("share is the identity or not in the subgroup")
        encs = [encode(s) for s in shares]
        if len(set(encs)) != len(encs):
            raise Refused("duplicate share")
        pk = point_sum(shares)
        if pk == IDENTITY:
            raise Refused("joint key is the identity")
        self.pk = pk
        self.shares = list(shares)
        self.sorted_encodings = sorted(encs)  # bytes compare as unsigned lexicographic

    def __eq__(self, other):
        return (isinstance(other, Context) and self.pk == other.pk
                and self.sorted_encodings == other.sorted_encodings)

    def __hash__(self):
        return hash((self.pk, tuple(self.sorted_encodings)))


class Ciphertext:
    def __init__(self, a, b, ctx, bound):
        self.A = a
        self.B = b
        self.ctx = ctx
        self.bound = bound

    def encoding(self):
        return encode(self.A) + encode(self.B)


def encrypt(ctx, m, w, k):
    """§4 with explicit randomness k (test vectors only; real k comes from §2)."""
    if not (1 <= w <= 64):
        raise Refused("width out of range")
    if not (0 <= m < (1 << w)):
        raise Refused("message out of range for width")
    if not (0 <= k < L):
        raise Refused("k out of range")
    a = mul(k, G)
    b = add(mul(m, G), mul(k, ctx.pk))
    return Ciphertext(a, b, ctx, (1 << w) - 1)


def ct_add(c1, c2):
    """§5 add: same context only; result bound b1 + b2 must stay below l."""
    if c1.ctx != c2.ctx:
        raise Refused("different key contexts")
    bound = c1.bound + c2.bound
    if bound >= L:
        raise Refused("result bound >= l")
    return Ciphertext(add(c1.A, c2.A), add(c1.B, c2.B), c1.ctx, bound)


def ct_scale(c, ct):
    """§5 scale: 1 <= c < l; result bound c*b must stay below l."""
    if not (1 <= c < L):
        raise Refused("scale factor out of range")
    bound = c * ct.bound
    if bound >= L:
        raise Refused("result bound >= l")
    return Ciphertext(mul(c, ct.A), mul(c, ct.B), ct.ctx, bound)


def recover(m_point, bound, max_plaintext):
    """§6.3 by linear search: the unique t in [0, bound] with [t]G = M, or failure."""
    if bound > max_plaintext:
        raise Refused("bound exceeds maxPlaintext")
    if max_plaintext > SEARCH_LIMIT:
        raise Refused("beyond this reference's search limit")
    cur = IDENTITY
    for t in range(bound + 1):
        if cur == m_point:
            return t
        cur = add(cur, G)
    raise DecryptionFailed("no t in [0, bound]")


def decrypt_single(ct, sk, max_plaintext):
    """§6.1: the secret's public key must equal the ciphertext's joint key."""
    if mul(sk, G) != ct.ctx.pk:
        raise Refused("secret does not match the joint key")
    return recover(sub(ct.B, mul(sk, ct.A)), ct.bound, max_plaintext)


def decrypt_nofn(ct, verified_shares, max_plaintext):
    """§6.2: verified_shares maps encode(PK_j) -> D_j; exactly one per registered trustee."""
    if sorted(verified_shares.keys()) != ct.ctx.sorted_encodings:
        raise Refused("share set differs from the registered set")
    m_point = sub(ct.B, point_sum(verified_shares[e] for e in ct.ctx.sorted_encodings))
    return recover(m_point, ct.bound, max_plaintext)


def dleq_holds(x_scalar, base_x, p_point, d_point):
    """The R_dleq relation (§9.2) checked directly with the witness: P = [x]G, D = [x]X."""
    return mul(x_scalar, G) == p_point and mul(x_scalar, base_x) == d_point


def test_scalar(tag):
    """§12: OS2IP(SHA-256(UTF-8("zeroj.elgamal.v1.test." + tag))) mod l."""
    digest = hashlib.sha256(("zeroj.elgamal.v1.test." + tag).encode("utf-8")).digest()
    return int.from_bytes(digest, "big") % L


# =============================================================================================
# Output helpers
# =============================================================================================

OUT = []
FAILURES = []


def emit(key, value):
    OUT.append("%s=%s" % (key, value))


def tf(b):
    return "true" if b else "false"


def fe(x):
    """Field element / coordinate: 0x + 64 lowercase hex digits (sign prefix if negative)."""
    return ("-" if x < 0 else "") + "0x%064x" % abs(x)


def check(name, cond):
    cond = bool(cond)
    emit("check." + name, tf(cond))
    if not cond:
        FAILURES.append("check." + name)
    return cond


def spec_match(name, cond):
    cond = bool(cond)
    emit("spec_match." + name, tf(cond))
    if not cond:
        FAILURES.append("spec_match." + name)
    return cond


def emit_point(prefix, pt, with_encoding=True):
    emit(prefix + ".u", fe(pt[0]))
    emit(prefix + ".v", fe(pt[1]))
    if with_encoding:
        emit(prefix + ".encoding", encode(pt).hex())


def emit_ct(prefix, a, b):
    emit_point(prefix + ".A", a, False)
    emit_point(prefix + ".B", b, False)
    emit(prefix + ".encoding", (encode(a) + encode(b)).hex())


def pub_inputs(*points):
    vals = []
    for pt in points:
        vals.extend([pt[0], pt[1]])
    return ",".join(fe(x) for x in vals)


ROUNDTRIP_OK = []


def roundtrip_point(pt):
    status, q = decode_point(encode(pt))
    ok = status == "ok" and q == pt
    ROUNDTRIP_OK.append(ok)
    return ok


def roundtrip_ct(a, b):
    status, q = decode_ciphertext(encode(a) + encode(b))
    ok = status == "accept" and q == (a, b)
    ROUNDTRIP_OK.append(ok)
    return ok


def refuses(fn, *args):
    try:
        fn(*args)
    except Refused:
        return True
    return False


# =============================================================================================
# Main
# =============================================================================================

G = None  # set in main() after derivation


def main(argv):
    global G
    proto_text = PROTOTYPE_OUTPUT
    proto_source = "embedded"
    if len(argv) >= 3 and argv[1] == "--prototype":
        with open(argv[2], "r", encoding="utf-8") as fh:
            proto_text = fh.read()
        proto_source = "file"

    OUT.append("# Independent reference output for profile %s" % PROFILE)
    OUT.append("# Command: python3 elgamal_jubjub_v1_reference.py")
    OUT.append("# Python: %s" % platform.python_version())
    OUT.append("# Independence: written from docs/specs/elgamal-jubjub-v1.md and "
               "docs/specs/pedersen-jubjub-v1.md only; no Java source or other script was read.")
    OUT.append("# Formats: field elements 0x+64 hex; .m/.w/.bound/.dec/tally decimal; "
               "byte strings bare hex.")
    emit("profile", PROFILE)

    # ---------------------------------------------------------------- §1 curve and constants
    emit("curve.p", fe(P))
    emit("curve.l", fe(L))
    emit("curve.d", fe(D))
    emit("curve.cofactor", COFACTOR)
    check("p_probable_prime", is_probable_prime(P))
    check("l_probable_prime", is_probable_prime(L))
    z = BLS12_381_Z
    check("p_is_bls12_381_scalar_order", P == z ** 4 - z ** 2 + 1)
    check("p_1_mod_4_minus_one_is_square", P % 4 == 1 and is_square(P - 1))
    check("d_is_nonsquare", not is_square(D))
    check("d_times_10241_is_minus_10240", D * 10241 % P == (-10240) % P)
    check("decode_rule3_unreachable", not is_square((-inv(D)) % P))
    check("l_between_2pow251_and_2pow252", (1 << 251) < L < (1 << 252))
    check("max_w64_message_below_l", (1 << 64) - 1 < L)
    check("sampler_bias_below_2pow_minus259", L * (1 << 259) < (1 << 512))
    spec_match("d", D == PIN_D)

    # ---------------------------------------------------------------- generator
    check("g_full_on_curve", on_curve(G_FULL))
    G = mul(COFACTOR, G_FULL)
    emit_point("G_full", G_FULL, False)
    emit_point("G", G)
    check("g_full_order_is_8l", mul(8 * L, G_FULL) == IDENTITY
          and mul(4 * L, G_FULL) != IDENTITY and mul(8, G_FULL) != IDENTITY)
    # #E lies in the Hasse interval |#E - (p + 1)| <= 2 sqrt(p), which has width < 8l, and is
    # a multiple of the order 8l of G_full, so #E = 8l iff 8l itself is in the interval.
    hasse_t = P + 1 - 8 * L
    check("curve_order_is_8l_by_hasse", hasse_t * hasse_t <= 4 * P
          and 4 * math.isqrt(P) + 4 < 8 * L)
    check("g_on_curve", on_curve(G))
    check("g_not_identity", G != IDENTITY)
    check("g_in_subgroup", in_subgroup(G))
    spec_match("G", G == (PIN_G_U, PIN_G_V))
    spec_match("G_encoding", encode(G).hex() == PIN_G_ENC)
    check("roundtrip.G", roundtrip_point(G))

    # Small-order torsion points derived from G_full.
    t8 = mul(L, G_FULL)
    t4 = add(t8, t8)
    t2 = add(t4, t4)
    check("torsion_t8_order_8", mul(8, t8) == IDENTITY and mul(4, t8) != IDENTITY)
    check("torsion_t4_has_v_zero", t4[1] == 0 and t4[0] * t4[0] % P == P - 1)
    check("torsion_t2_is_0_minus1", t2 == (0, P - 1))

    # Arithmetic sanity.
    check("arith_l_plus_1_times_G_is_G", mul(L + 1, G) == G)
    check("arith_linearity", add(mul(123456789, G), mul(987654321, G)) == mul(1111111110, G))
    check("arith_neg", add(G, neg(G)) == IDENTITY)

    # ---------------------------------------------------------------- §12 test scalars
    tags = ["sk", "k0", "k1", "k16", "k64", "share1", "share2", "share3",
            "ballot1", "ballot2", "ballot3", "ballot4", "ballot5", "wrap1", "wrap2"]
    sc = {}
    for tag in tags:
        sc[tag] = test_scalar(tag)
        emit("scalar." + tag, fe(sc[tag]))
    check("secret_scalars_nonzero", all(sc[t] != 0 for t in ("sk", "share1", "share2", "share3")))

    # ---------------------------------------------------------------- single key
    sk = sc["sk"]
    pk = mul(sk, G)
    single = Context([pk])
    emit_point("single.pk", pk)
    check("roundtrip.single.pk", roundtrip_point(pk))
    status, dpk = decode_public_key(encode(pk))
    check("single.pk_decodes_as_key", status == "accept" and dpk == pk)

    cases = [("m0w1", 0, 1, "k0"), ("m1w1", 1, 1, "k1"),
             ("m12345w16", 12345, 16, "k16"), ("mmaxw64", (1 << 64) - 1, 64, "k64")]
    cts = {}
    for name, m, w, ktag in cases:
        k = sc[ktag]
        ct = encrypt(single, m, w, k)
        cts[name] = ct
        pre = "single.enc." + name
        emit(pre + ".m", m)
        emit(pre + ".w", w)
        emit(pre + ".k", fe(k))
        emit_ct(pre, ct.A, ct.B)
        emit(pre + ".bound", ct.bound)
        m_point = sub(ct.B, mul(sk, ct.A))
        emit(pre + ".dec_point_ok", tf(m_point == mul(m, G)))
        if m_point != mul(m, G):
            FAILURES.append(pre + ".dec_point_ok")
        if ct.bound <= SEARCH_LIMIT:
            dec = decrypt_single(ct, sk, ct.bound)
            emit(pre + ".dec", dec)
            check(name + "_decrypts", dec == m)
        check("roundtrip." + pre, roundtrip_ct(ct.A, ct.B))
        check(name + "_A_is_kG", ct.A == mul(k, G))

    # Homomorphism.
    c01 = ct_add(cts["m0w1"], cts["m1w1"])
    emit_ct("single.add01", c01.A, c01.B)
    emit("single.add01.bound", c01.bound)
    d01 = decrypt_single(c01, sk, c01.bound)
    emit("single.add01.dec", d01)
    k01 = (sc["k0"] + sc["k1"]) % L
    check("homomorphism_add", c01.A == mul(k01, G) and c01.B == add(mul(1, G), mul(k01, pk))
          and d01 == 1 and c01.bound == 2)
    check("roundtrip.single.add01", roundtrip_ct(c01.A, c01.B))

    c3 = ct_scale(3, cts["m12345w16"])
    emit_ct("single.scale3_12345", c3.A, c3.B)
    emit("single.scale3_12345.bound", c3.bound)
    d3 = decrypt_single(c3, sk, c3.bound)
    emit("single.scale3_12345.dec", d3)
    k3 = 3 * sc["k16"] % L
    check("homomorphism_scale", c3.A == mul(k3, G) and c3.B == add(mul(37035, G), mul(k3, pk))
          and d3 == 37035 and c3.bound == 3 * ((1 << 16) - 1))
    check("roundtrip.single.scale3_12345", roundtrip_ct(c3.A, c3.B))
    check("decrypt_refuses_bound_above_max", refuses(decrypt_single, c3, sk, c3.bound - 1))
    check("encrypt_refuses_m_out_of_width", refuses(encrypt, single, 2, 1, sc["k1"]))
    check("encrypt_refuses_w65", refuses(encrypt, single, 0, 65, sc["k1"]))
    check("encrypt_refuses_w0", refuses(encrypt, single, 0, 0, sc["k1"]))

    # ---------------------------------------------------------------- n-of-n
    share_sk = {j: sc["share%d" % j] for j in (1, 2, 3)}
    share_pk = {j: mul(share_sk[j], G) for j in (1, 2, 3)}
    for j in (1, 2, 3):
        emit("nofn.share%d.sk" % j, fe(share_sk[j]))
        emit_point("nofn.share%d.pk" % j, share_pk[j])
        check("roundtrip.nofn.share%d.pk" % j, roundtrip_point(share_pk[j]))
    ctx = Context([share_pk[1], share_pk[2], share_pk[3]])
    emit_point("nofn.pk", ctx.pk)
    check("roundtrip.nofn.pk", roundtrip_point(ctx.pk))
    check("nofn_pk_is_sum_of_secret_shares", ctx.pk == mul(sum(share_sk.values()) % L, G))

    order = sorted((1, 2, 3), key=lambda j: encode(share_pk[j]))
    emit("nofn.registered_order", ",".join(str(j) for j in order))
    emit("nofn.registered_encodings", ",".join(encode(share_pk[j]).hex() for j in order))

    # Independent comparator: explicit byte loop, unsigned.
    def lex_less(x, y):
        for bx, by in zip(x, y):
            if bx != by:
                return bx < by
        return len(x) < len(y)
    ordered_ok = all(lex_less(encode(share_pk[order[i]]), encode(share_pk[order[i + 1]]))
                     for i in range(len(order) - 1))
    check("registered_order_unsigned_lexicographic", ordered_ok
          and [encode(share_pk[j]) for j in order] == ctx.sorted_encodings)
    numeric_v_order = sorted((1, 2, 3), key=lambda j: share_pk[j][1])
    signed_order = sorted((1, 2, 3), key=lambda j: [b - 256 if b >= 128 else b
                                                     for b in encode(share_pk[j])])
    emit("info.registered_order_if_sorted_by_numeric_v",
         ",".join(str(j) for j in numeric_v_order))
    emit("info.registered_order_if_sorted_by_signed_bytes",
         ",".join(str(j) for j in signed_order))
    le_int_order = sorted((1, 2, 3), key=lambda j: int.from_bytes(encode(share_pk[j]), "little"))
    emit("info.registered_order_if_sorted_by_le_integer_of_encoding",
         ",".join(str(j) for j in le_int_order))
    permuted = Context([share_pk[3], share_pk[1], share_pk[2]])
    check("context_equal_under_share_permutation", permuted == ctx)

    # Supplementary sort vector (not in spec §12): keys [i]G for the first triple of small
    # multiples whose unsigned-lexicographic order differs from every plausible wrong order.
    # The §12 shares do not separate unsigned-lexicographic from "little-endian integer of the
    # 32 encoding bytes" (the sign bit at 2^255 dominates both ways for them).
    wrong_orders = {
        "numeric_v": lambda q: q[1],
        "numeric_u": lambda q: q[0],
        "signed_bytes": lambda q: [b - 256 if b >= 128 else b for b in encode(q)],
        "le_integer_of_encoding": lambda q: int.from_bytes(encode(q), "little"),
    }
    sort_triple = None
    for i1 in range(1, 16):
        for i2 in range(i1 + 1, 16):
            for i3 in range(i2 + 1, 16):
                pts = {i: mul(i, G) for i in (i1, i2, i3)}
                good = sorted(pts, key=lambda i: encode(pts[i]))
                if all(sorted(pts, key=lambda i, f=f: f(pts[i])) != good
                       for f in wrong_orders.values()):
                    sort_triple = (i1, i2, i3)
                    break
            if sort_triple:
                break
        if sort_triple:
            break
    sv_pts = {i: mul(i, G) for i in sort_triple}
    sv_order = sorted(sort_triple, key=lambda i: encode(sv_pts[i]))
    emit("sortvec.multiples", ",".join(str(i) for i in sort_triple))
    emit("sortvec.encodings", ",".join(encode(sv_pts[i]).hex() for i in sort_triple))
    emit("sortvec.registered_order", ",".join(str(i) for i in sv_order))
    for wname, f in wrong_orders.items():
        emit("info.sortvec.order_if_sorted_by_" + wname,
             ",".join(str(i) for i in sorted(sort_triple, key=lambda i, f=f: f(sv_pts[i]))))
    sv_ctx = Context([sv_pts[i] for i in sort_triple])
    sv_lex_ok = all(lex_less(encode(sv_pts[sv_order[n]]), encode(sv_pts[sv_order[n + 1]]))
                    for n in range(2))
    check("sortvec_registered_order", sv_lex_ok
          and sv_ctx.sorted_encodings == [encode(sv_pts[i]) for i in sv_order])

    # §3.2 refusal rules.
    check("context_refuses_empty", refuses(Context, []))
    check("context_refuses_identity_share", refuses(Context, [share_pk[1], IDENTITY]))
    check("context_refuses_non_subgroup_share", refuses(Context, [share_pk[1], add(G, t2)]))
    check("context_refuses_duplicate_share", refuses(Context, [share_pk[1], share_pk[1]]))
    check("context_refuses_identity_sum", refuses(Context, [share_pk[1], neg(share_pk[1])]))

    messages = [1, 0, 1, 1, 0]
    ballots = []
    for i, m in enumerate(messages, start=1):
        k = sc["ballot%d" % i]
        ct = encrypt(ctx, m, 1, k)
        ballots.append(ct)
        pre = "nofn.ballot%d" % i
        emit(pre + ".m", m)
        emit(pre + ".w", 1)
        emit(pre + ".k", fe(k))
        emit_ct(pre, ct.A, ct.B)
        check("roundtrip." + pre, roundtrip_ct(ct.A, ct.B))

    total = ballots[0]
    for ct in ballots[1:]:
        total = ct_add(total, ct)
    emit_ct("nofn.sum", total.A, total.B)
    emit("nofn.sum.bound", total.bound)
    check("roundtrip.nofn.sum", roundtrip_ct(total.A, total.B))
    ksum = sum(sc["ballot%d" % i] for i in range(1, 6)) % L
    check("nofn_sum_homomorphic", total.A == mul(ksum, G)
          and total.B == add(mul(3, G), mul(ksum, ctx.pk)) and total.bound == 5)

    dshares = {}
    for j in (1, 2, 3):
        dj = mul(share_sk[j], total.A)
        dshares[j] = dj
        emit_point("nofn.D%d" % j, dj)
        check("roundtrip.nofn.D%d" % j, roundtrip_point(dj))
        check("nofn_D%d_dleq_relation" % j, dleq_holds(share_sk[j], total.A, share_pk[j], dj))
        check("nofn_pop%d_dleq_relation" % j,
              dleq_holds(share_sk[j], G, share_pk[j], share_pk[j]))
    m_point = sub(total.B, point_sum(dshares[j] for j in (1, 2, 3)))
    emit_point("nofn.M", m_point, False)
    verified = {encode(share_pk[j]): dshares[j] for j in (1, 2, 3)}
    tally = decrypt_nofn(total, verified, total.bound)
    emit("nofn.tally", tally)
    check("nofn_tally_is_3", tally == 3 and m_point == mul(3, G))
    check("nofn_joint_secret_decrypts_same",
          decrypt_single(total, sum(share_sk.values()) % L, total.bound) == 3)
    missing = {encode(share_pk[j]): dshares[j] for j in (1, 2)}
    check("nofn_refuses_missing_share", refuses(decrypt_nofn, total, missing, 5))
    foreign = dict(missing)
    foreign[encode(mul(7, G))] = mul(7, total.A)
    check("nofn_refuses_foreign_share", refuses(decrypt_nofn, total, foreign, 5))

    for j in (1, 2, 3):
        emit("nofn.dleq%d.publicInputs" % j, pub_inputs(total.A, share_pk[j], dshares[j]))
    for j in (1, 2, 3):
        emit("nofn.pop%d.publicInputs" % j, pub_inputs(G, share_pk[j], share_pk[j]))
    emit("nofn.encstmt.ballot1.w", 1)
    emit("nofn.encstmt.ballot1.publicInputs", pub_inputs(ctx.pk, ballots[0].A, ballots[0].B))

    # ---------------------------------------------------------------- counterexamples
    # §6.1: (G, 4G) under PK = 3G (k = 1, m = 1).
    ctx3 = Context([mul(3, G)])
    cw = encrypt(ctx3, 1, 1, 1)
    check("cx_wrongsecret_is_G_4G", cw.A == G and cw.B == mul(4, G))
    emit_point("cx.wrongsecret.PK", ctx3.pk, False)
    emit_point("cx.wrongsecret.A", cw.A, False)
    emit_point("cx.wrongsecret.B", cw.B, False)
    emit("cx.wrongsecret.secret_wrong", 4)
    m_wrong = sub(cw.B, mul(4, cw.A))
    emit_point("cx.wrongsecret.M_wrong", m_wrong, False)
    emit("cx.wrongsecret.M_wrong_is_identity", tf(m_wrong == IDENTITY))
    dec_wrong = recover(m_wrong, cw.bound, cw.bound)
    emit("cx.wrongsecret.dec_wrong", dec_wrong)
    emit("cx.wrongsecret.secret_right", 3)
    m_right = sub(cw.B, mul(3, cw.A))
    emit_point("cx.wrongsecret.M_right", m_right, False)
    dec_right = decrypt_single(cw, 3, cw.bound)
    emit("cx.wrongsecret.dec_right", dec_right)
    emit("cx.wrongsecret.wrong_secret_pk_matches", tf(mul(4, G) == ctx3.pk))
    check("cx_wrongsecret", m_wrong == IDENTITY and dec_wrong == 0 and dec_right == 1
          and m_right == G)
    check("cx_wrongsecret_refused_by_key_check", refuses(decrypt_single, cw, 4, 1))

    # §12: Enc(1; k=1, 3G) + Enc(1; k=1, 2G), decrypted under secret 3.
    ctx2 = Context([mul(2, G)])
    cm1 = encrypt(ctx3, 1, 1, 1)
    cm2 = encrypt(ctx2, 1, 1, 1)
    emit_point("cx.mixed.PK1", ctx3.pk, False)
    emit_point("cx.mixed.PK2", ctx2.pk, False)
    emit_ct("cx.mixed.c1", cm1.A, cm1.B)
    emit_ct("cx.mixed.c2", cm2.A, cm2.B)
    mixed_a = add(cm1.A, cm2.A)
    mixed_b = add(cm1.B, cm2.B)
    emit_ct("cx.mixed.sum", mixed_a, mixed_b)
    emit("cx.mixed.secret", 3)
    mixed_m = sub(mixed_b, mul(3, mixed_a))
    emit_point("cx.mixed.M", mixed_m, False)
    mixed_dec = recover(mixed_m, 2, 2)
    emit("cx.mixed.dec", mixed_dec)
    emit("cx.mixed.sum_of_messages", 2)
    check("cx_mixed", mixed_a == mul(2, G) and mixed_b == mul(7, G) and mixed_dec == 1)
    check("cx_mixed_add_refused_by_context", refuses(ct_add, cm1, cm2))

    # §10.2: keys 3G, 5G; m = 1, k = 7; forged D2 = 36G.
    ctxf = Context([mul(3, G), mul(5, G)])
    cf = encrypt(ctxf, 1, 1, 7)
    d1 = mul(3, cf.A)
    d2 = mul(5, cf.A)
    d2_forged = mul(36, G)
    emit_point("cx.forged.PK1", mul(3, G), False)
    emit_point("cx.forged.PK2", mul(5, G), False)
    emit_point("cx.forged.PK", ctxf.pk, False)
    emit("cx.forged.m", 1)
    emit("cx.forged.k", 7)
    emit_point("cx.forged.A", cf.A, False)
    emit_point("cx.forged.B", cf.B, False)
    emit_point("cx.forged.D1", d1, False)
    emit_point("cx.forged.D2", d2, False)
    emit_point("cx.forged.D2_forged", d2_forged, False)
    m_honest = sub(sub(cf.B, d1), d2)
    m_forged = sub(sub(cf.B, d1), d2_forged)
    emit_point("cx.forged.M_honest", m_honest, False)
    emit_point("cx.forged.M_forged", m_forged, False)
    r_honest = decrypt_nofn(cf, {encode(mul(3, G)): d1, encode(mul(5, G)): d2}, 1)
    r_forged = recover(m_forged, 1, 1)
    emit("cx.forged.result_honest", r_honest)
    emit("cx.forged.result_forged", r_forged)
    forged_ok = dleq_holds(5, cf.A, mul(5, G), d2_forged)
    emit("cx.forged.D2_forged_satisfies_dleq", tf(forged_ok))
    check("cx_forged", cf.A == mul(7, G) and cf.B == mul(57, G) and d1 == mul(21, G)
          and d2 == mul(35, G) and r_honest == 1 and r_forged == 0 and not forged_ok)

    # §5 wraparound: raw Enc(l - 1) + Enc(1) under single.pk decrypts to 0.
    kw1, kw2 = sc["wrap1"], sc["wrap2"]
    wa1, wb1 = mul(kw1, G), add(mul(L - 1, G), mul(kw1, pk))  # raw formula, outside §4
    wa2, wb2 = mul(kw2, G), add(mul(1, G), mul(kw2, pk))
    emit("cx.wrap.m1", fe(L - 1))
    emit("cx.wrap.k1", fe(kw1))
    emit_ct("cx.wrap.c1", wa1, wb1)
    emit("cx.wrap.m2", 1)
    emit("cx.wrap.k2", fe(kw2))
    emit_ct("cx.wrap.c2", wa2, wb2)
    ws_a, ws_b = add(wa1, wa2), add(wb1, wb2)
    emit_ct("cx.wrap.sum", ws_a, ws_b)
    wm = sub(ws_b, mul(sk, ws_a))
    emit_point("cx.wrap.M", wm, False)
    emit("cx.wrap.M_is_identity", tf(wm == IDENTITY))
    wdec = recover(wm, 1, 1)
    emit("cx.wrap.dec", wdec)
    fits = (L - 1) < (1 << 64)
    emit("cx.wrap.lminus1_fits_w64", tf(fits))
    emit("cx.wrap.encrypt_lminus1_refused", tf(refuses(encrypt, single, L - 1, 64, kw1)))
    raw1 = Ciphertext(wa1, wb1, single, L - 1)  # a bound the profile can never attach
    raw2 = Ciphertext(wa2, wb2, single, 1)
    emit("cx.wrap.add_refused_by_bound_rule", tf(refuses(ct_add, raw1, raw2)))
    check("cx_wrap", wm == IDENTITY and wdec == 0 and not fits
          and refuses(encrypt, single, L - 1, 64, kw1) and refuses(ct_add, raw1, raw2))

    # ---------------------------------------------------------------- §5 bound rule (w = 64)
    b64 = (1 << 64) - 1
    max_c = (L - 1) // b64
    emit("bound.w64.b", b64)
    emit("bound.w64.max_scale_accepted", max_c)
    emit("bound.w64.min_scale_refused", max_c + 1)
    accepted = not refuses(ct_scale, max_c, cts["mmaxw64"])
    refused = refuses(ct_scale, max_c + 1, cts["mmaxw64"])
    check("bound_rule_scale_w64", accepted and refused and max_c * b64 < L <= (max_c + 1) * b64)

    # ---------------------------------------------------------------- §7 decoding negatives
    # A non-canonical alias of a subgroup point: the smallest i >= 1 with v([i]G) + p < 2^255,
    # so that a decoder that reduced v mod p would accept a valid point.
    i_alias = 1
    while True:
        q = mul(i_alias, G)
        if q[1] + P < (1 << 255):
            break
        i_alias += 1
    alias_pt = mul(i_alias, G)
    alias_bytes = raw_v_bytes(alias_pt[1] + P, alias_pt[0] & 1)
    emit("info.noncanonical_alias.multiple_of_G", i_alias)
    # Smallest v >= 2 whose (v^2 - 1)/(d v^2 + 1) is a non-square.
    v_ns = 2
    while is_square((v_ns * v_ns - 1) * inv(D * v_ns * v_ns + 1)):
        v_ns += 1
    emit("info.smallest_nonsquare_v", v_ns)

    valid = cts["m1w1"]
    va, vb = encode(valid.A), encode(valid.B)
    vct = va + vb
    g_plus_t2 = add(G, t2)
    g_plus_t8 = add(G, t8)
    dneg = [
        ("ct_len63", "ciphertext", vct[:63], "reject_length"),
        ("ct_len65", "ciphertext", vct + b"\x00", "reject_length"),
        ("ct_A_noncanonical_v", "ciphertext", alias_bytes + vb, "reject_noncanonical_v"),
        ("ct_B_noncanonical_v_identity_alias", "ciphertext", va + raw_v_bytes(P + 1, 0),
         "reject_noncanonical_v"),
        ("ct_B_non_square", "ciphertext", va + raw_v_bytes(v_ns, 0), "reject_non_square"),
        ("ct_A_u_zero_sign_set", "ciphertext", raw_v_bytes(1, 1) + vb, "reject_u_zero_sign_set"),
        ("ct_A_order2", "ciphertext", encode(t2) + vb, "reject_not_in_subgroup"),
        ("ct_B_order4", "ciphertext", va + encode(t4), "reject_not_in_subgroup"),
        ("ct_B_order8", "ciphertext", va + encode(t8), "reject_not_in_subgroup"),
        ("ct_A_G_plus_order2", "ciphertext", encode(g_plus_t2) + vb, "reject_not_in_subgroup"),
        ("ct_identity_both", "ciphertext", encode(IDENTITY) + encode(IDENTITY), "accept"),
        ("ct_valid_m1w1", "ciphertext", vct, "accept"),
        ("pk_len31", "publickey", encode(G)[:31], "reject_length"),
        ("pk_len33", "publickey", encode(G) + b"\x00", "reject_length"),
        ("pk_noncanonical_v", "publickey", alias_bytes, "reject_noncanonical_v"),
        ("pk_non_square", "publickey", raw_v_bytes(v_ns, 0), "reject_non_square"),
        ("pk_identity_sign_set", "publickey", raw_v_bytes(1, 1), "reject_u_zero_sign_set"),
        ("pk_identity", "publickey", encode(IDENTITY), "reject_identity_key"),
        ("pk_order2", "publickey", encode(t2), "reject_not_in_subgroup"),
        ("pk_order4", "publickey", encode(t4), "reject_not_in_subgroup"),
        ("pk_G_plus_order8", "publickey", encode(g_plus_t8), "reject_not_in_subgroup"),
        ("pk_G", "publickey", encode(G), "accept"),
        ("pk_single", "publickey", encode(pk), "accept"),
    ]
    all_match = True
    for name, kind, data, expected in dneg:
        if kind == "ciphertext":
            observed, _ = decode_ciphertext(data)
        else:
            observed, _ = decode_public_key(data)
        pre = "decode_neg." + name
        emit(pre + ".input", data.hex())
        emit(pre + ".kind", kind)
        emit(pre + ".expected", expected)
        emit(pre + ".observed", observed)
        if observed != expected:
            all_match = False
            FAILURES.append(pre)
    check("decode_neg_all_match", all_match)
    # The alias really is an alias, and the order-2 encoding carries no sign bit.
    check("noncanonical_alias_reduces_to_subgroup_point",
          int.from_bytes(bytes(alias_bytes[:31]) + bytes([alias_bytes[31] & 0x7F]),
                         "little") % P == alias_pt[1] and in_subgroup(alias_pt))
    check("g_plus_order2_in_full_group_only", on_curve(g_plus_t2) and not in_subgroup(g_plus_t2)
          and mul(2 * L, g_plus_t2) == IDENTITY)

    # ---------------------------------------------------------------- §7.4 affine negatives
    aneg = [
        ("u_plus_p", G[0] + P, G[1], "point", "reject_noncanonical"),
        ("v_plus_p", G[0], G[1] + P, "point", "reject_noncanonical"),
        ("u_negative_alias", G[0] - P, G[1], "point", "reject_noncanonical"),
        ("off_curve_1_1", 1, 1, "point", "reject_off_curve"),
        ("order2", 0, P - 1, "point", "reject_not_in_subgroup"),
        ("order4", t4[0], t4[1], "point", "reject_not_in_subgroup"),
        ("G_plus_order8", g_plus_t8[0], g_plus_t8[1], "point", "reject_not_in_subgroup"),
        ("identity_point", 0, 1, "point", "accept"),
        ("identity_key", 0, 1, "publickey", "reject_identity_key"),
        ("G_point", G[0], G[1], "point", "accept"),
        ("G_key", G[0], G[1], "publickey", "accept"),
    ]
    all_match = True
    for name, u, v, kind, expected in aneg:
        observed = validate_affine(u, v, kind == "publickey")
        pre = "affine_neg." + name
        emit(pre + ".u", fe(u))
        emit(pre + ".v", fe(v))
        emit(pre + ".kind", kind)
        emit(pre + ".expected", expected)
        emit(pre + ".observed", observed)
        if observed != expected:
            all_match = False
            FAILURES.append(pre)
    check("affine_neg_all_match", all_match)
    check("affine_aliases_reduce_to_G", ((G[0] + P) % P, (G[1] + P) % P) == G
          and (G[0] - P) % P == G[0])

    # ---------------------------------------------------------------- prototype cross-check
    emit("info.prototype_source", proto_source)
    scal, votes, points, tallies, order_names = {}, {}, {}, {}, []
    parse_ok = True
    for line in proto_text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "scalar" and len(parts) == 3:
            scal[parts[1]] = int(parts[2], 16)
        elif parts[0] == "vote" and len(parts) == 3:
            votes[parts[1]] = int(parts[2])
        elif parts[0] == "tally" and len(parts) == 3:
            tallies[parts[1]] = int(parts[2])
        elif len(parts) == 3:
            points[parts[0]] = (int(parts[1], 16), int(parts[2], 16))
            order_names.append(parts[0])
        else:
            parse_ok = False
    check("prototype_parsed", parse_ok and points and tallies)

    trustees = sorted(int(n[2:]) for n in scal if n.startswith("sk"))
    voters = sorted(int(n[1:]) for n in votes if n.startswith("v"))
    rec = {"G": G}
    p_shares = [mul(scal["sk%d" % j], G) for j in trustees]
    for j, s in zip(trustees, p_shares):
        rec["PK%d" % j] = s
    p_ctx = Context(p_shares)
    rec["PK"] = p_ctx.pk
    p_cts = []
    for i in voters:
        ct = encrypt(p_ctx, votes["v%d" % i], 1, scal["k%d" % i])
        rec["A%d" % i] = ct.A
        rec["B%d" % i] = ct.B
        p_cts.append(ct)
    p_sum = p_cts[0]
    for ct in p_cts[1:]:
        p_sum = ct_add(p_sum, ct)
    rec["sumA"] = p_sum.A
    rec["sumB"] = p_sum.B
    p_d = {}
    for j in trustees:
        p_d[j] = mul(scal["sk%d" % j], p_sum.A)
        rec["D%d" % j] = p_d[j]
    rec["M"] = sub(p_sum.B, point_sum(p_d[j] for j in trustees))
    p_tally = decrypt_nofn(p_sum, {encode(rec["PK%d" % j]): p_d[j] for j in trustees},
                           p_sum.bound)
    for name in order_names:
        check("prototype." + name, rec.get(name) == points[name])
    check("prototype.tally", tallies.get("T") == p_tally == sum(votes.values()))
    check("prototype.all_points_listed_were_recomputed", set(order_names) <= set(rec))
    spec_tags = set(sc.values())
    emit("info.prototype_scalars_equal_spec12_scalars",
         tf(any(v in spec_tags for v in scal.values())))

    # ---------------------------------------------------------------- summary
    check("roundtrip_all_positive_encodings", all(ROUNDTRIP_OK))
    result = "pass" if not FAILURES else "fail"
    emit("result", result)
    return result


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as exc:  # a crash is a failure; the partial output is still written
        FAILURES.append("exception %s: %s" % (type(exc).__name__, exc))
        emit("error", type(exc).__name__)
        emit("result", "fail")
    text = "\n".join(OUT) + "\n"
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        fh.write(text)
    sys.stdout.write(text)
    if FAILURES:
        for f in FAILURES:
            sys.stderr.write("FAILED: %s\n" % f)
        sys.exit(1)
    sys.exit(0)
