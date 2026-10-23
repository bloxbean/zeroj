#!/usr/bin/env python3
"""Independent emitter of the BLS12-381 G1 `zeroj-commitment-vectors-v1` files (ADR-0060 M3).

Writes, in the format of docs/specs/commitment-profiles-v1.md §13 (r6):

    zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1/
        pedersen-bls12-381-g1-v1.json         (kind scalar)
        pedersen-bls12-381-g1-bytes-v1.json   (kind bytes)

Written from the specifications only: docs/specs/pedersen-bls12-381-g1-v1.md (r1),
docs/specs/commitment-profiles-v1.md (r6; §7, §8.4, §9, §10, §11, §13),
docs/specs/pedersen-jubjub-bytes-v1.md (§3, §6 stream rules) and
docs/adr/0060-pedersen-bls12-381-g1-profiles.md. No ZeroJ Java source, Java test, Java test
resource or build output was read. The Jubjub emitter and the existing Jubjub JSON files were read
only to match the file format and conventions.

Two implementations are involved:

  * the PRIMARY implementation in this file (Jacobian-coordinate G1 arithmetic, the §4 strict
    decoder, the octet-by-octet §5 byte mapping, check 1/2, the delta rule, openings, envelope,
    the §13.3 execution order). It produces every emitted value;
  * the sibling stand-alone reference `bls12_381_g1_reference.py` (written from RFC 9380 without
    the Java), IMPORTED by path and never modified. It derives G and H by hash_to_curve, and
    --self-test re-verifies every emitted case with its affine arithmetic, strict decoder and
    generic expand_message_xmd.

Python 3 standard library only. Deterministic: fixed constants, no randomness.

    python3 -I -B emit_g1_commitment_vectors_v1.py [--out-dir DIR]   # write both files
    python3 -I -B emit_g1_commitment_vectors_v1.py --check            # byte-for-byte compare
    python3 -I -B emit_g1_commitment_vectors_v1.py --self-test        # re-verify + mutations

--repo-root DIR overrides the repository root (default: five directories above this file);
--out-dir DIR overrides the output directory (default: <repo-root>/zeroj-test-vectors/src/main/
resources/test-vectors/commitment-profiles-v1). Exit status 0 on success, non-zero on any pin,
case-intent, --check or self-test failure.
"""

import sys

sys.dont_write_bytecode = True  # never leave __pycache__ next to the imported reference

import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import platform  # noqa: E402
import re  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT_REL = ("zeroj-bls12381/src/test/resources/pedersen-g1-reference/"
              "emit_g1_commitment_vectors_v1.py")
OUT_REL = "zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1"
REFERENCE_FILE = "bls12_381_g1_reference.py"


def _import_reference():
    path = os.path.join(HERE, REFERENCE_FILE)
    if not os.path.isfile(path):
        raise SystemExit("missing imported reference: " + path)
    spec = importlib.util.spec_from_file_location("bls12_381_g1_reference", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ref = _import_reference()


# =============================================================================================
# Constants transcribed by hand from the specifications
# =============================================================================================

# pedersen-bls12-381-g1-v1.md §1
P = int("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9fe"
        "ffffffffaaab", 16)
Q = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
COFACTOR = 0x396C8C005555E1568C00AAAB0000AAAB
HALF_P = (P - 1) // 2
# commitment-profiles-v1.md §1 (Jubjub order l): used ONLY by the "use l instead of q" mutation
# and one seeded-fault fixture; never by the profile itself.
L_JUBJUB = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7

# pedersen-bls12-381-g1-v1.md §5
DST_S = b"ZeroJ-pedersen-bls12-381-g1-bytes-v1-H2S-XMD:SHA-256"
DST_S_HEX = ("5a65726f4a2d706564657273656e2d626c7331322d3338312d67312d62797465732d76312d4832532d"
             "584d443a5348412d323536")
DST_B = b"ZeroJ-pedersen-bls12-381-g1-basis-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_"
DST_B_HEX = ("5a65726f4a2d706564657273656e2d626c7331322d3338312d67312d62617369732d76312d424c533132"
             "3338314731"
             "5f584d443a5348412d3235365f535357555f524f5f")
MAX_PAYLOAD_BYTES = 2 ** 61 - 256
LONG_MIN, LONG_MAX = -2 ** 63, 2 ** 63 - 1
INT_MIN, INT_MAX = -2 ** 31, 2 ** 31 - 1

# commitment-profiles-v1.md §2.3, §9
PROFILE_SCALAR = "pedersen-bls12-381-g1-v1"
PROFILE_BYTES = "pedersen-bls12-381-g1-bytes-v1"
BASIS_ID = "pedersen-bls12-381-g1-basis-v1"
JUBJUB_IDS = ["pedersen-jubjub-v1", "pedersen-jubjub-vector-v1", "pedersen-jubjub-bytes-v1"]
ENVELOPE_LENGTH = {PROFILE_SCALAR: 74, PROFILE_BYTES: 80}
POINT_LENGTH = 48
PROFILE_OF = {"scalar": PROFILE_SCALAR, "bytes": PROFILE_BYTES}

# pedersen-bls12-381-g1-v1.md §2.2
PIN_G_COMPRESSED = ("80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76"
                    "ba9869e960e3fd5c2f3e")
PIN_H_COMPRESSED = ("92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc"
                    "6b64875b9a2256b6ab65")
PIN_G_X = ("00453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e9"
           "60e3fd5c2f3e")
PIN_G_Y = ("0ab307006d17731edfeef508a959c6c43f6ad8f72d27af8aa0645356ffe864fd0ced6dfa806e5b2b63c8"
           "850f7cfb691c")
PIN_H_X = ("12e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b"
           "9a2256b6ab65")
PIN_H_Y = ("01e0f1bf4e0e4e344cb2779b2dc6adec8b0b07caf8a9812c3b6f4b056af2d0fda0e7b05ffb16008ca855"
           "ffe55686184e")

# pedersen-bls12-381-g1-v1.md §10.2: (label, payload, uniform_bytes, s)
PIN_H2S = [
    ("empty", ("hex", ""),
     "62afac35dff21f5a55ff2569ca3c589ef5401cfc94aafe1110981e7c11b89a13d931cede053d24094deda3524a"
     "53b80e",
     36315447437668222813564192209050807153821375512821708312164585800119004767398),
    ("pattern-1", ("pattern", 1),
     "8bf9523b8cfad53f2a64e7c124b637a4a7dc7665d60ccf16e2f3e260b04ddbf366a510869c7e787d331c35a922"
     "2f28cc",
     17446826573447758279414620354847772216162392386874241427805739007456445167270),
    ("pattern-55", ("pattern", 55),
     "e219c89968b49b2d930e377d427b7e56c65473ea36c92f6ce02e5efc83974e69fbba34909f18fe9c76d6147d1a"
     "65c7cc",
     4769885727161205208895793752532058125538937305946508790125793345496789763442),
    ("pattern-56", ("pattern", 56),
     "91f731ee2e033609f3f27e1fcfac8202c8d415cc5ac5597eee949f5a96dfb4965d739d0a583b4273d5dae005a9"
     "cc45e0",
     44447803342360626358699221713325796379764762051949152351159963802212607565535),
    ("pattern-64", ("pattern", 64),
     "d4acbd20d83ed5a47394b62c6e2301b5cdca43e1dabcbe10a0999adb71f7becdcc3fc44e845702440a04e54975"
     "607dfd",
     21158407019535989839516034496492483749423603674815396635618901986493989358291),
    ("pattern-129", ("pattern", 129),
     "90293fbe6622a3d8ed03f6f733dd36eba35919771d85be7e2dc88aac08c8c365a6eeaaee7a536bc38b40d5eac6"
     "2c06df",
     10636700515201835153547363743684853122590858874478588016559740395075199699391),
    ("pattern-1024", ("pattern", 1024),
     "d968d99d55ccb4300830c9ca5bf4a5e7e352e71f2b43a1e7357487eab5259b1b7a1540a8bb690e50009d8b4b2f"
     "a12797",
     51032631804351372587695208740820262018544153677477339797817422801122177762967),
    ("ascii-abc", ("hex", "616263"),
     "0648a88bce794163caa6686ba5d3bbf550c02d8e842a550642ef33832468ead60428b888e585dfe40c33f79db5"
     "f2b3e7",
     425016933681726855004915202875618514367841089254790273686098534787449164925),
]

# pedersen-bls12-381-g1-v1.md §10.3: (m, r, compressed C(m, r))
PIN_COMMITMENTS = [
    (0, 0, "c0" + "00" * 47),
    (1, 0, PIN_G_COMPRESSED),
    (0, 1, PIN_H_COMPRESSED),
    (Q - 1, Q - 1, "830c22c1792dae9774b23f9c31801a964094bef7734745f4012b4e5c133a5d608636f1e020d68c"
                   "b2688ad276369b8650"),
    (12345, 67890, "8c5b1e42a3912ecf2a2fc27a26ef67afd30799614ebfbd5dc7a2cb00e43b063a60a4d516007352"
                   "cddecd632d2b758fc4"),
]

# pedersen-bls12-381-g1-v1.md §10.4 (mixed-order point G + (0, 2))
PIN_MIXED_G_PLUS_ORDER3 = ("b6ee2defa35097e6bbaea5ab251479b37157dedfcbc4b319181bf28298f048a66eb9"
                           "3dc0230190c18ae135644c2d3df4")


class PinError(Exception):
    pass


def require(cond, message):
    if not cond:
        raise PinError(message)


# commitment-profiles-v1.md §11 error classes
MAL = "MALFORMED_ENCODING"
NIS = "NOT_IN_SUBGROUP"
NCS = "NON_CANONICAL_SCALAR"
OOR = "OUT_OF_RANGE"
LOR = "LENGTH_OUT_OF_RANGE"
PMM = "PROFILE_MISMATCH"
INV = "INVALID_CONFIGURATION"
OMM = "OPENING_MISMATCH"
ERROR_CLASSES = {MAL, NIS, NCS, OOR, LOR, PMM, INV, OMM}


class Fail(Exception):
    def __init__(self, cls):
        super().__init__(cls)
        self.cls = cls


# =============================================================================================
# Mutations (--self-test switches one on at a time; empty in normal operation)
# =============================================================================================

MUTATIONS = [
    ("check1_accepts_q", "check 1 accepts q"),
    ("check1_reduces", "check 1 reduces mod q instead of rejecting"),
    ("decode_skip_subgroup", "decoder skips the subgroup check (step 7)"),
    ("decode_cofactor_clear", "decoder cofactor-clears a received point"),
    ("decode_infinity_lenient", "any encoding with the infinity flag decodes to the identity"),
    ("decode_reduce_x", "decoder reduces x >= P_381 instead of rejecting"),
    ("decode_ignore_sort", "decoder ignores the sort flag"),
    ("decode_no_compression_check", "decoder does not require the compression flag"),
    ("compress_sort_inverted", "encoder sets the sort flag for the smaller y"),
    ("envelope_no_id_compare", "envelope does not compare the identifier"),
    ("envelope_any_version", "envelope accepts any version octet"),
    ("envelope_length_before_id", "envelope checks the point length before the identifier"),
    ("amount_bits_255", "amountBits 255 accepted"),
    ("amount_bits_before_point", "amountBits validated before the point is decoded"),
    ("check2_inclusive", "check 2 accepts m = 2^k"),
    ("check2_before_check1", "check 2 applied before check 1"),
    ("delta_bits_254", "deltaBits 254 accepted (two congruent deltas would pass)"),
    ("delta_bits_before_point", "deltaBits validated before the point is decoded"),
    ("delta_bound_before_bits", "|delta| bound checked before deltaBits is validated"),
    ("delta_bound_inclusive", "|delta| = 2^deltaBits accepted"),
    ("delta_not_negated", "negative delta adds [|delta|]G instead of subtracting it"),
    ("swap_g_h", "G and H swapped in the commitment"),
    ("h2s_length_prefix", "HashBytesToScalarG1 length as a prefix instead of a suffix"),
    ("h2s_no_length", "HashBytesToScalarG1 drops the length suffix"),
    ("h2s_mod_l", "HashBytesToScalarG1 reduces modulo the Jubjub order l instead of q"),
    ("h2s_no_zero_prefix", "HashBytesToScalarG1 omits the 64-octet zero prefix of b0"),
    ("opening_little_endian", "opening scalars little-endian"),
    ("subtract_reversed", "relation subtract computes P1 - P0"),
    ("bytes_equation_before_blinding", "bytes verifyOpening evaluates the equation before check 1"),
    ("opening_r_before_length", "scalar opening decoder checks r before the length"),
]
MUTATION_NAMES = {n for n, _ in MUTATIONS}
MUT = set()


def mut(name):
    require(name in MUTATION_NAMES, "unknown mutation " + name)
    return name in MUT


# =============================================================================================
# Primary G1 arithmetic: Jacobian coordinates on E: y^2 = x^3 + 4 over GF(P_381)
# (affine points are (x, y) tuples; None is the identity O)
# =============================================================================================

_INF = (1, 1, 0)


def _jac(pt):
    return _INF if pt is None else (pt[0], pt[1], 1)


def _dbl(p1):
    x, y, z = p1
    if z == 0 or y == 0:
        return _INF
    a = x * x % P
    b = y * y % P
    c = b * b % P
    d = 2 * ((x + b) * (x + b) - a - c) % P
    e = 3 * a % P
    f = e * e % P
    x3 = (f - 2 * d) % P
    y3 = (e * (d - x3) - 8 * c) % P
    z3 = 2 * y * z % P
    return (x3, y3, z3)


def _add(p1, p2):
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    z1s, z2s = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2s % P, x2 * z1s % P
    s1, s2 = y1 * z2s * z2 % P, y2 * z1s * z1 % P
    if u1 == u2:
        return _dbl(p1) if s1 == s2 else _INF
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h2 = h * h % P
    h3 = h2 * h % P
    u1h2 = u1 * h2 % P
    x3 = (r * r - h3 - 2 * u1h2) % P
    y3 = (r * (u1h2 - x3) - s1 * h3) % P
    z3 = h * z1 * z2 % P
    return (x3, y3, z3)


def _aff(p1):
    x, y, z = p1
    if z == 0:
        return None
    zi = pow(z, P - 2, P)
    zi2 = zi * zi % P
    return (x * zi2 % P, y * zi2 * zi % P)


def mul(k, pt):
    # §6.4 / §9: a negative or out-of-range integer never reaches a scalar multiplication.
    require(isinstance(k, int) and not isinstance(k, bool) and k >= 0,
            "negative or non-integer scalar passed to mul")
    acc, base = _INF, _jac(pt)
    for bit in bin(k)[2:] if k else "":
        acc = _dbl(acc)
        if bit == "1":
            acc = _add(acc, base)
    return _aff(acc)


def add(a, b):
    return _aff(_add(_jac(a), _jac(b)))


def neg(a):
    return None if a is None else (a[0], (-a[1]) % P)


def sub(a, b):
    return add(a, neg(b))


def on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - 4) % P == 0


IDENTITY_ENC = bytes([0xC0]) + bytes(47)


def compress(pt):                                       # §4 encoding
    if pt is None:
        return IDENTITY_ENC
    x, y = pt
    out = bytearray(x.to_bytes(48, "big"))
    out[0] |= 0x80
    larger = y > HALF_P
    if mut("compress_sort_inverted"):
        larger = not larger
    if larger:
        out[0] |= 0x20
    return bytes(out)


_DECODE_CACHE = {}


def strict_decode(data):
    """pedersen-bls12-381-g1-v1.md §4, steps 2-7 in order (step 1, null, is outside the files)."""
    key = bytes(data)
    if key in _DECODE_CACHE:
        res = _DECODE_CACHE[key]
        if isinstance(res, Fail):
            raise Fail(res.cls)
        return res
    try:
        res = _strict_decode(key)
    except Fail as e:
        _DECODE_CACHE[key] = e
        raise
    _DECODE_CACHE[key] = res
    return res


def _strict_decode(data):
    if len(data) != 48:                                                  # step 2
        raise Fail(MAL)
    flags = data[0] & 0xE0
    if not flags & 0x80 and not mut("decode_no_compression_check"):     # step 3
        raise Fail(MAL)
    if flags & 0x40:                                                    # step 4
        if data == IDENTITY_ENC or mut("decode_infinity_lenient"):
            return None
        raise Fail(MAL)
    x = int.from_bytes(bytes([data[0] & 0x1F]) + data[1:], "big")
    if x >= P:                                                          # step 5
        if not mut("decode_reduce_x"):
            raise Fail(MAL)
        x %= P
    rhs = (x * x * x + 4) % P
    y = pow(rhs, (P + 1) // 4, P)                                       # P = 3 mod 4
    if y * y % P != rhs:                                                # step 6
        raise Fail(MAL)
    want_larger = bool(flags & 0x20) and not mut("decode_ignore_sort")
    if (y > HALF_P) != want_larger:
        y = (-y) % P
    pt = (x, y)
    require(on_curve(pt), "decoder produced an off-curve point")
    if mut("decode_cofactor_clear"):
        return mul(COFACTOR, pt)
    if mul(Q, pt) is not None and not mut("decode_skip_subgroup"):      # step 7
        raise Fail(NIS)
    return pt


# =============================================================================================
# Bases (§2), commitments (§3), byte mapping (§5)
# =============================================================================================

class Bases:
    G = None
    H = None


B = Bases()


def setup_bases():
    g = _strict_decode(bytes.fromhex(PIN_G_COMPRESSED))
    h = _strict_decode(bytes.fromhex(PIN_H_COMPRESSED))
    require(g == (int(PIN_G_X, 16), int(PIN_G_Y, 16)), "pinned G affine coordinates")
    require(h == (int(PIN_H_X, 16), int(PIN_H_Y, 16)), "pinned H affine coordinates")
    require(DST_S.hex() == DST_S_HEX and len(DST_S) == 52, "DST_S")
    require(DST_B.hex() == DST_B_HEX and len(DST_B) == 68, "DST_B")
    # §2.3 rule 1 and rule 2 ("a test recomputes them"): RFC 9380 hash_to_curve by the reference.
    rg, rh = ref.derive_basis(DST_B, b"G", b"H")
    require((rg, rh) == (g, h), "reference hash_to_curve(\"G\"/\"H\", DST_B) != pinned G/H")
    require(g is not None and h is not None and g != h and g != neg(h), "G/H distinctness")
    require(mul(Q, g) is None and mul(Q, h) is None, "G/H subgroup")
    B.G, B.H = g, h


_COMMIT_CACHE = {}


def commit_raw(m, r):
    require(0 <= m < Q and 0 <= r < Q, "commit_raw: non-canonical scalar reached arithmetic")
    key = (m, r)
    if key not in _COMMIT_CACHE:
        g, h = (B.H, B.G) if mut("swap_g_h") else (B.G, B.H)
        _COMMIT_CACHE[key] = add(mul(m, g), mul(r, h))
    return _COMMIT_CACHE[key]


_H2S_CACHE = {}


def hash_to_scalar(payload):
    """pedersen-bls12-381-g1-v1.md §5, in its octet-by-octet form."""
    payload = bytes(payload)
    if payload in _H2S_CACHE:
        return _H2S_CACHE[payload]
    n = len(payload)
    require(n <= MAX_PAYLOAD_BYTES, "payload too long")
    suffix = n.to_bytes(8, "big")
    prefix = b"" if mut("h2s_no_zero_prefix") else bytes(64)
    if mut("h2s_length_prefix"):
        framed = suffix + payload
    elif mut("h2s_no_length"):
        framed = payload
    else:
        framed = payload + suffix
    dst_prime = DST_S + b"\x34"
    b0 = hashlib.sha256(prefix + framed + b"\x00\x30" + b"\x00" + dst_prime).digest()
    b1 = hashlib.sha256(b0 + b"\x01" + dst_prime).digest()
    b2 = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, b1)) + b"\x02" + dst_prime).digest()
    uniform = b1 + b2[:16]
    modulus = L_JUBJUB if mut("h2s_mod_l") else Q
    s = int.from_bytes(uniform, "big") % modulus
    out = {"b0": b0, "b1": b1, "b2": b2, "u": uniform, "s": s}
    _H2S_CACHE[payload] = out
    return out


def reset_caches():
    _DECODE_CACHE.clear()
    _COMMIT_CACHE.clear()
    _H2S_CACHE.clear()


# =============================================================================================
# Checks (§6.3 / commitment-profiles-v1 §7), openings (§6.1, §6.2), envelope (§9)
# =============================================================================================

def check1(x):
    if mut("check1_reduces"):
        return x % Q
    upper = Q + 1 if mut("check1_accepts_q") else Q
    if not 0 <= x < upper:
        raise Fail(NCS)
    return x


def amount_bits_valid(k):
    return 1 <= k <= (255 if mut("amount_bits_255") else 254)


def delta_bits_valid(k):
    # Spec §6.4 (r2): 1 <= k <= 253, so that (-2^k, 2^k) holds at most q integers and an accepted
    # delta is unique mod q; at 254 both delta and delta - q could pass.
    return 1 <= k <= (254 if mut("delta_bits_254") else 253)


def check2(m, k):
    if m > 2 ** k if mut("check2_inclusive") else m >= 2 ** k:
        raise Fail(OOR)


def i2osp32(x):
    return x.to_bytes(32, "little" if mut("opening_little_endian") else "big")


def os2ip32(b):
    return int.from_bytes(b, "little" if mut("opening_little_endian") else "big")


def scalar_opening_encode(m, r):          # G1PedersenOpening.of, then encode()
    m = check1(m)
    r = check1(r)
    return i2osp32(m) + i2osp32(r)


def scalar_opening_decode(data):          # §6.1: length, then m, then r
    if mut("opening_r_before_length") and len(data) >= 64:
        check1(os2ip32(data[32:64]))
    if len(data) != 64:
        raise Fail(MAL)
    m, r = os2ip32(data[:32]), os2ip32(data[32:])
    return check1(m), check1(r)


def blinding_encode(r):                   # G1PedersenBlinding.encode
    return i2osp32(check1(r))


def blinding_decode(data):                # §6.2: length, then r
    if len(data) != 32:
        raise Fail(MAL)
    return check1(os2ip32(data))


def envelope_encode(profile_id, point_bytes):
    raw = profile_id.encode("ascii")
    return bytes([0x01, len(raw)]) + raw + point_bytes


def envelope_decode(data, expected_id):
    """commitment-profiles-v1.md §9 steps 1-5. Step 6 (concrete class/descriptor) cannot fail for
    a codec that only builds its own type, so the files have no step-6 case."""
    exp = expected_id.encode("ascii")
    if len(data) < 2 or (data[0] != 0x01 and not mut("envelope_any_version")):  # step 1
        raise Fail(MAL)
    idlen = data[1]
    if 2 + idlen > len(data):                                                  # step 2
        raise Fail(MAL)
    rest = data[2 + idlen:]
    if mut("envelope_length_before_id") and len(rest) != POINT_LENGTH:
        raise Fail(MAL)
    if data[2:2 + idlen] != exp and not mut("envelope_no_id_compare"):         # step 3
        raise Fail(PMM)
    if len(rest) != POINT_LENGTH:                                              # step 4
        raise Fail(MAL)
    return strict_decode(rest)                                                 # step 5


_ID_RE = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*-v[1-9][0-9]*")


def valid_identifier(s):
    return 4 <= len(s) <= 64 and s.isascii() and _ID_RE.fullmatch(s) is not None


# =============================================================================================
# JSON value helpers (§13.2)
# =============================================================================================

def dec(x):
    return str(x)


def hx(b):
    return b.hex()


def h48(x):
    return x.to_bytes(48, "big").hex()


def pattern(n):
    return bytes((131 * i + 17) % 256 for i in range(n))


def payload_bytes(obj):
    if "hex" in obj:
        return bytes.fromhex(obj["hex"])
    require(obj.get("pattern") == "131i+17" and set(obj) == {"pattern", "length"},
            "unknown payload form")
    return pattern(int(obj["length"]))


def pattern_payload(n):
    return {"pattern": "131i+17", "length": dec(n)}


def hex_payload(b):
    return {"hex": hx(b)}


def point_json(pt):
    if pt is None:
        return {"identity": "true"}
    return {"xHex": h48(pt[0]), "yHex": h48(pt[1])}


# =============================================================================================
# Case execution: commitment-profiles-v1.md §13.3 table and execution order
#   1 configuration (amountBits / deltaBits are READ here, validated in step 3)
#   2 points (pointHex, pointsHex in index order; envelopeHex under §9)
#   3 the operation's own order (§6 / pedersen-bls12-381-g1-v1.md §8)
#   4 the equation or arithmetic
# =============================================================================================

def run_case(kind, op, inp):
    """Returns the `expected` object, or raises Fail(error class)."""
    # ---- step 1: configuration ---------------------------------------------------------------
    amount_bits = int(inp["amountBits"]) if "amountBits" in inp else None
    delta_bits = int(inp["deltaBits"]) if "deltaBits" in inp else None
    for v in (amount_bits, delta_bits):
        require(v is None or INT_MIN <= v <= INT_MAX, "fixture: 32-bit field out of range")
    if mut("amount_bits_before_point") and amount_bits is not None:
        if not amount_bits_valid(amount_bits):
            raise Fail(INV)
    if mut("delta_bits_before_point") and delta_bits is not None:
        if not delta_bits_valid(delta_bits):
            raise Fail(INV)

    if op == "decodePoint":
        return point_json(strict_decode(bytes.fromhex(inp["pointHex"])))

    if op == "commit" and kind == "scalar":                 # strict commitScalar
        m = check1(int(inp["value"]))
        r = check1(int(inp["blinding"]))
        return {"pointHex": hx(compress(commit_raw(m, r)))}

    if op == "commit" and kind == "bytes":                  # commitBytes*
        payload = payload_bytes(inp["payload"])
        declared = int(inp["declaredLength"]) if "declaredLength" in inp else None
        max_bytes = int(inp["maxBytes"]) if "maxBytes" in inp else None
        for v in (declared, max_bytes):
            require(v is None or LONG_MIN <= v <= LONG_MAX, "fixture: 64-bit field out of range")
        r = check1(int(inp["blinding"]))
        for lim in (declared, max_bytes):
            if lim is not None and not 0 <= lim <= MAX_PAYLOAD_BYTES:
                raise Fail(LOR)
        if declared is not None:
            require(declared == len(payload), "fixture: declaredLength != payload length")
        if max_bytes is not None:
            require(max_bytes >= len(payload), "fixture: maxBytes < payload length")
        s = hash_to_scalar(payload)["s"]
        return {"pointHex": hx(compress(commit_raw(s, r)))}

    if op == "hashToScalar":
        require(kind == "bytes", "hashToScalar outside bytes")
        h = hash_to_scalar(payload_bytes(inp["payload"]))
        return {"b0Hex": hx(h["b0"]), "b1Hex": hx(h["b1"]), "b2Hex": hx(h["b2"]),
                "uniformBytesHex": hx(h["u"]), "scalar": dec(h["s"])}

    if op == "verifyOpening":
        point = strict_decode(bytes.fromhex(inp["pointHex"]))          # step 2
        if kind == "scalar":
            if amount_bits is not None and not amount_bits_valid(amount_bits):
                raise Fail(INV)
            m, r = int(inp["value"]), int(inp["blinding"])
            if mut("check2_before_check1") and amount_bits is not None and m >= 0:
                check2(m, amount_bits)
            m = check1(m)
            r = check1(r)
            if amount_bits is not None:
                check2(m, amount_bits)
            ok = compress(commit_raw(m, r)) == compress(point)
        else:
            require(amount_bits is None, "fixture: amountBits on bytes")
            payload = payload_bytes(inp["payload"])
            if mut("bytes_equation_before_blinding"):
                s = hash_to_scalar(payload)["s"]
                if compress(commit_raw(s, int(inp["blinding"]) % Q)) != compress(point):
                    raise Fail(OMM)
            r = check1(int(inp["blinding"]))
            s = hash_to_scalar(payload)["s"]
            ok = compress(commit_raw(s, r)) == compress(point)
        if not ok:
            raise Fail(OMM)
        return {"result": "true"}

    if op == "encodeOpening":
        if kind == "scalar":
            return {"openingHex": hx(scalar_opening_encode(int(inp["value"]), int(inp["blinding"])))}
        return {"openingHex": hx(blinding_encode(int(inp["blinding"])))}

    if op == "decodeOpening":
        data = bytes.fromhex(inp["openingHex"])
        if kind == "scalar":
            m, r = scalar_opening_decode(data)
            return {"value": dec(m), "blinding": dec(r)}
        return {"blinding": dec(blinding_decode(data))}

    if op == "encodeEnvelope":
        pt = strict_decode(bytes.fromhex(inp["pointHex"]))   # build the typed commitment
        return {"envelopeHex": hx(envelope_encode(PROFILE_OF[kind], compress(pt)))}

    if op == "decodeEnvelope":
        expected = inp["expectedProfileId"]
        require(valid_identifier(expected), "fixture: expectedProfileId is not an identifier")
        pt = envelope_decode(bytes.fromhex(inp["envelopeHex"]), expected)
        return {"pointHex": hx(compress(pt))}

    if op == "relation":
        require(kind == "scalar", "relation outside the scalar profile (§6.4: bytes has none)")
        pts = [strict_decode(bytes.fromhex(h)) for h in inp["pointsHex"]]
        o = inp["op"]
        if o == "negate":
            require(len(pts) == 1, "fixture: negate cardinality")
            res = neg(pts[0])
        else:
            require(len(pts) == 2, "fixture: add/subtract cardinality")
            if o == "add":
                res = add(pts[0], pts[1])
            elif o == "subtract":
                res = sub(pts[1], pts[0]) if mut("subtract_reversed") else sub(pts[0], pts[1])
            else:
                raise PinError("fixture: unknown relation op")
        return {"pointHex": hx(compress(res))}

    if op == "publicDelta":                     # G1PedersenCommitment.withPublicDelta (§6.4)
        require(kind == "scalar", "publicDelta outside the scalar profile")
        point = strict_decode(bytes.fromhex(inp["pointHex"]))          # step 2
        delta = int(inp["delta"])
        if mut("delta_bound_before_bits") and (delta_bits < 0 or abs(delta).bit_length() > delta_bits):
            raise Fail(OOR)
        if not delta_bits_valid(delta_bits):                           # step 3: deltaBits
            raise Fail(INV)
        bound = 2 ** delta_bits
        if abs(delta) > bound if mut("delta_bound_inclusive") else abs(delta) >= bound:
            raise Fail(OOR)
        term = mul(abs(delta), B.G)                                    # canonical |delta| only
        if delta < 0 and not mut("delta_not_negated"):
            term = neg(term)
        return {"pointHex": hx(compress(add(point, term)))}

    raise PinError("unknown operation %s/%s" % (kind, op))


# =============================================================================================
# Fixtures
# =============================================================================================

OPENINGS = {}   # compressed hex -> (m, r) for every point built from a known opening (self-test)


def cpt(m, r):
    """C(m, r) for canonical m, r; records the opening for the --self-test homomorphism checks."""
    pt = commit_raw(m % Q, r % Q)
    OPENINGS.setdefault(hx(compress(pt)), (m % Q, r % Q))
    return pt


def enc_hex(pt):
    return hx(compress(pt))


def with_flag(enc, flag):
    return bytes([enc[0] | flag]) + enc[1:]


def x_encoding(x, flags=0x80):
    raw = bytearray(x.to_bytes(48, "big"))
    raw[0] |= flags
    return bytes(raw)


ORDER3 = (0, 2)            # §4: 0x80 || 0^47 decodes to (0, 2), a point of order 3
ORDER3_NEG = (0, P - 2)


def point_negatives():
    """(name, encoding, class): every G1 point negative of §13.4 and pedersen-bls12-381-g1-v1 §10.4."""
    g_enc = compress(B.G)
    x4_y = pow(4 ** 3 + 4, (P + 1) // 4, P)
    require(x4_y * x4_y % P == 68 % P, "x = 4 is not on the curve")
    mixed_h = compress(add(B.H, ORDER3_NEG))
    return [
        ("length-0", b"", MAL),
        ("length-47", g_enc[:47], MAL),
        ("length-49", g_enc + b"\x00", MAL),
        ("length-32-jubjub-identity", bytes([1]) + bytes(31), MAL),
        ("length-96-uncompressed-g", B.G[0].to_bytes(48, "big") + B.G[1].to_bytes(48, "big"), MAL),
        ("compression-flag-clear-g", bytes([g_enc[0] & 0x7F]) + g_enc[1:], MAL),
        ("compression-flag-clear-all-zero", bytes(48), MAL),
        ("compression-flag-clear-infinity-flag", bytes([0x40]) + bytes(47), MAL),
        ("infinity-with-sort-flag", bytes([0xE0]) + bytes(47), MAL),
        ("infinity-nonzero-last-bit", bytes([0xC0]) + bytes(46) + b"\x01", MAL),
        ("infinity-nonzero-bit-in-octet-0", bytes([0xC1]) + bytes(47), MAL),
        ("infinity-flag-on-g", with_flag(g_enc, 0x40), MAL),
        ("x-equals-p", x_encoding(P), MAL),
        ("x-equals-p-sort-flag", x_encoding(P, 0xA0), MAL),
        ("x-equals-p-plus-1", x_encoding(P + 1), MAL),
        ("x-max-381-bit", bytes([0x9F]) + b"\xff" * 47, MAL),
        ("x-1-not-square", x_encoding(1), MAL),
        ("x-1-not-square-sort-flag", x_encoding(1, 0xA0), MAL),
        ("order-3-x-0", x_encoding(0), NIS),
        ("order-3-x-0-sort-flag", x_encoding(0, 0xA0), NIS),
        ("x-4-outside-subgroup", x_encoding(4), NIS),
        ("x-4-outside-subgroup-sort-flag", x_encoding(4, 0xA0), NIS),
        ("mixed-order-g-plus-order-3", bytes.fromhex(PIN_MIXED_G_PLUS_ORDER3), NIS),
        ("mixed-order-h-plus-other-order-3", mixed_h, NIS),
    ]


class CaseList:
    def __init__(self):
        self.cases = []
        self.names = set()

    def add(self, name, op, inp, intent):
        require(name not in self.names, "duplicate case name " + name)
        require(intent == "ok" or intent in ERROR_CLASSES, "bad intent " + intent)
        self.names.add(name)
        self.cases.append((name, op, inp, intent))


def add_point_cases(cl, profile):
    for name, data, cls in point_negatives():
        cl.add("decode-point-" + name, "decodePoint", {"pointHex": hx(data)}, cls)
        cl.add("envelope-decode-point-" + name, "decodeEnvelope",
               {"envelopeHex": hx(envelope_encode(profile, data)), "expectedProfileId": profile}, cls)


def add_decode_positive(cl, name, pt):
    cl.add("decode-point-" + name, "decodePoint", {"pointHex": enc_hex(pt)}, "ok")


def add_envelope_round_trip(cl, profile, name, pt):
    env = envelope_encode(profile, compress(pt))
    require(len(env) == ENVELOPE_LENGTH[profile], "envelope length")
    cl.add("envelope-encode-" + name, "encodeEnvelope", {"pointHex": enc_hex(pt)}, "ok")
    cl.add("envelope-decode-" + name, "decodeEnvelope",
           {"envelopeHex": hx(env), "expectedProfileId": profile}, "ok")


def add_envelope_negatives(cl, profile, good_pt):
    good = compress(good_pt)
    env = envelope_encode(profile, good)
    other = PROFILE_BYTES if profile == PROFILE_SCALAR else PROFILE_SCALAR
    pid = profile.encode("ascii")

    def de(name, data, cls):
        cl.add("envelope-decode-" + name, "decodeEnvelope",
               {"envelopeHex": hx(data), "expectedProfileId": profile}, cls)

    de("empty", b"", MAL)
    de("version-only", b"\x01", MAL)
    de("version-0x00", b"\x00" + env[1:], MAL)
    de("version-0x02", b"\x02" + env[1:], MAL)
    de("version-0xff", b"\xff" + env[1:], MAL)
    de("truncated-in-identifier", env[:10], MAL)
    de("truncated-by-one", env[:-1], MAL)
    de("trailing-octet", env + b"\x00", MAL)
    de("point-mismatch-47-octets", envelope_encode(profile, good[:47]), MAL)
    de("point-mismatch-49-octets", envelope_encode(profile, good + b"\x00"), MAL)
    de("point-mismatch-32-octets", envelope_encode(profile, good[:32]), MAL)
    de("point-mismatch-96-octets-uncompressed",
       envelope_encode(profile, good_pt[0].to_bytes(48, "big") + good_pt[1].to_bytes(48, "big")), MAL)
    de("point-mismatch-no-point", envelope_encode(profile, b""), MAL)
    de("id-length-exceeds-envelope", bytes([0x01, len(env)]) + env[2:], MAL)
    de("other-g1-profile-" + other, envelope_encode(other, good), PMM)
    de("basis-set-identifier", envelope_encode(BASIS_ID, good), PMM)
    jubjub_identity = bytes([1]) + bytes(31)
    for jid in JUBJUB_IDS:
        de("jubjub-profile-" + jid, envelope_encode(jid, jubjub_identity), PMM)
    de("jubjub-profile-pedersen-jubjub-v1-with-g1-point", envelope_encode(JUBJUB_IDS[0], good), PMM)
    de("id-differs-in-one-octet", envelope_encode(profile[:-1] + "2", good), PMM)
    de("id-uppercase-first-octet", envelope_encode(profile[0].upper() + profile[1:], good), PMM)
    de("id-length-octet-minus-one", bytes([0x01, len(pid) - 1]) + pid + good, PMM)
    de("id-length-octet-plus-one", bytes([0x01, len(pid) + 1]) + pid + good, PMM)
    de("id-empty", bytes([0x01, 0x00]) + good, PMM)
    # Multi-defect cases pinning the §9 step order.
    de("order-version-before-identifier", b"\x02" + envelope_encode(other, good)[1:], MAL)
    de("order-id-length-before-identifier", bytes([0x01, 200]) + envelope_encode(other, good)[2:], MAL)
    de("order-identifier-before-point-length", envelope_encode(other, good[:47]), PMM)
    de("order-identifier-before-point", envelope_encode(other, x_encoding(0)), PMM)


BAD_SCALARS = [("q", Q), ("q-plus-1", Q + 1), ("minus-1", -1)]


# =============================================================================================
# Scalar profile cases
# =============================================================================================

def build_scalar():
    cl = CaseList()
    prof = PROFILE_SCALAR
    O = None
    G, H = B.G, B.H
    c1 = cpt(12345, 67890)
    cq = cpt(Q - 1, Q - 1)

    # ---- decodePoint positives
    add_decode_positive(cl, "identity", O)
    add_decode_positive(cl, "base-g", G)
    add_decode_positive(cl, "base-h", H)
    add_decode_positive(cl, "minus-g-sort-flag", neg(G))
    add_decode_positive(cl, "minus-h", neg(H))
    add_decode_positive(cl, "commitment-12345-67890", c1)
    add_decode_positive(cl, "commitment-qm1-qm1", cq)

    # ---- commit positives (strict commitScalar); includes every §10.3 row
    commits = [
        ("zero-zero", 0, 0), ("one-zero", 1, 0), ("zero-one", 0, 1), ("qm1-qm1", Q - 1, Q - 1),
        ("12345-67890", 12345, 67890), ("zero-qm1", 0, Q - 1), ("qm1-zero", Q - 1, 0),
        ("two-zero", 2, 0), ("negated-12345-67890", Q - 12345, Q - 67890),
        ("2pow64m1-12345", 2 ** 64 - 1, 12345), ("2pow254m1-12345", 2 ** 254 - 1, 12345),
        ("2pow254-12345", 2 ** 254, 12345), ("qm1-12345", Q - 1, 12345),
    ]
    for name, m, r in commits:
        cpt(m, r)
        cl.add("commit-" + name, "commit", {"value": dec(m), "blinding": dec(r)}, "ok")

    # ---- verifyOpening positives
    def vo(name, pt, m, r, intent="ok", amount_bits=None):
        inp = {"pointHex": _pt_hex(pt), "value": dec(m), "blinding": dec(r)}
        if amount_bits is not None:
            inp["amountBits"] = dec(amount_bits)
        cl.add(name, "verifyOpening", inp, intent)

    vo("verify-identity-zero-zero", O, 0, 0)
    vo("verify-base-g-one-zero", G, 1, 0)
    vo("verify-base-h-zero-one", H, 0, 1)
    vo("verify-12345-67890", c1, 12345, 67890)
    vo("verify-qm1-qm1", cq, Q - 1, Q - 1)
    vo("verify-zero-qm1", cpt(0, Q - 1), 0, Q - 1)
    vo("verify-qm1-zero", cpt(Q - 1, 0), Q - 1, 0)
    for k in (1, 64, 252, 253, 254):
        vo("verify-amount-bits-%d-max" % k, cpt(2 ** k - 1, 12345), 2 ** k - 1, 12345, "ok", k)
    vo("verify-amount-bits-64-zero", cpt(0, 12345), 0, 12345, "ok", 64)
    vo("verify-amount-bits-254-qm1-blinding", cpt(7, Q - 1), 7, Q - 1, "ok", 254)
    # A bytes commitment C_bytes(B, r) is the scalar commitment C(s, r) (§3, commitment-profiles §6.3):
    # a scalar opening of s = HashBytesToScalarG1("abc") verifies against it (and authenticates s only).
    s_abc = hash_to_scalar(b"abc")["s"]
    vo("verify-bytes-commitment-abc-as-scalar-opening-of-s", cpt(s_abc, 12345), s_abc, 12345)

    # ---- verifyOpening negatives
    for k in (1, 64, 252, 253, 254):
        vo("verify-amount-bits-%d-overflow" % k, cpt(2 ** k, 12345), 2 ** k, 12345, OOR, k)
    for k, label in ((0, "0"), (255, "255"), (-1, "minus-1"), (INT_MAX, "int-max"),
                     (INT_MIN, "int-min"), (256, "256")):
        vo("verify-amount-bits-" + label, c1, 12345, 67890, INV, k)
    vo("verify-wrong-value", c1, 12346, 67890, OMM)
    vo("verify-wrong-blinding", c1, 12345, 67891, OMM)
    vo("verify-swapped-value-blinding", c1, 67890, 12345, OMM)
    vo("verify-negated-point", neg(c1), 12345, 67890, OMM)
    swapped = add(mul(12345, H), mul(67890, G))           # seeded fault: G and H swapped
    vo("verify-swapped-bases-point", swapped, 12345, 67890, OMM)
    vo("verify-identity-wrong-opening", O, 1, 0, OMM)
    vo("verify-amount-bits-64-wrong-value", c1, 12346, 67890, OMM, 64)
    vo("verify-value-12345-plus-q-not-reduced", c1, 12345 + Q, 67890, NCS)
    vo("verify-blinding-67890-plus-q-not-reduced", c1, 12345, 67890 + Q, NCS)
    vo("verify-value-minus-qm1-not-reduced", G, 1 - Q, 0, NCS)   # -(q-1) = 1 mod q

    # ---- check 1 on every strict operation (§13.4 scalar negatives)
    for label, bad in BAD_SCALARS:
        cl.add("commit-value-" + label, "commit", {"value": dec(bad), "blinding": "67890"}, NCS)
        cl.add("commit-blinding-" + label, "commit", {"value": "12345", "blinding": dec(bad)}, NCS)
        vo("verify-value-" + label, c1, bad, 67890, NCS)
        vo("verify-blinding-" + label, c1, 12345, bad, NCS)
        cl.add("encode-opening-value-" + label, "encodeOpening",
               {"value": dec(bad), "blinding": "67890"}, NCS)
        cl.add("encode-opening-blinding-" + label, "encodeOpening",
               {"value": "12345", "blinding": dec(bad)}, NCS)
    cl.add("commit-value-2pow256", "commit", {"value": dec(2 ** 256), "blinding": "0"}, NCS)
    cl.add("commit-blinding-minus-q", "commit", {"value": "0", "blinding": dec(-Q)}, NCS)

    # ---- opening encodings (§6.1)
    for name, m, r in (("zero-zero", 0, 0), ("12345-67890", 12345, 67890),
                       ("qm1-qm1", Q - 1, Q - 1), ("1-2", 1, 2), ("2pow254-0", 2 ** 254, 0)):
        opening = m.to_bytes(32, "big") + r.to_bytes(32, "big")
        cl.add("encode-opening-" + name, "encodeOpening", {"value": dec(m), "blinding": dec(r)}, "ok")
        cl.add("decode-opening-" + name, "decodeOpening", {"openingHex": hx(opening)}, "ok")
    q32 = Q.to_bytes(32, "big")
    q1_32 = (Q + 1).to_bytes(32, "big")
    one32 = (1).to_bytes(32, "big")

    def do(name, data, cls):
        cl.add("decode-opening-" + name, "decodeOpening", {"openingHex": hx(data)}, cls)

    do("value-q", q32 + one32, NCS)
    do("blinding-q", one32 + q32, NCS)
    do("value-q-plus-1", q1_32 + one32, NCS)
    do("blinding-q-plus-1", one32 + q1_32, NCS)
    do("value-all-ones", b"\xff" * 32 + one32, NCS)
    do("blinding-all-ones", one32 + b"\xff" * 32, NCS)
    for n in (0, 32, 63, 65, 96, 128):
        do("length-%d" % n, bytes(n), MAL)
    do("length-63-order-before-scalars", (q32 + q32)[:63], MAL)
    do("length-65-order-before-scalars", one32 + q32 + b"\x00", MAL)

    # ---- envelopes (§9, 74 octets)
    add_envelope_round_trip(cl, prof, "identity", O)
    add_envelope_round_trip(cl, prof, "commitment-12345-67890", c1)
    add_envelope_round_trip(cl, prof, "base-g", G)
    add_envelope_round_trip(cl, prof, "commitment-qm1-qm1", cq)
    add_envelope_negatives(cl, prof, c1)
    cl.add("envelope-encode-order-3", "encodeEnvelope", {"pointHex": hx(x_encoding(0))}, NIS)
    cl.add("envelope-encode-x-1-not-square", "encodeEnvelope", {"pointHex": hx(x_encoding(1))}, MAL)
    cl.add("envelope-encode-infinity-with-sort-flag", "encodeEnvelope",
           {"pointHex": hx(bytes([0xE0]) + bytes(47))}, MAL)

    # ---- relation (V3 sums)
    def rel(name, o, pts, intent="ok"):
        cl.add(name, "relation", {"op": o, "pointsHex": [p if isinstance(p, str) else enc_hex(p)
                                                          for p in pts]}, intent)

    a5, b7 = cpt(Q - 1, 5), cpt(2, 7)
    s12 = cpt(1, 12)
    rel("relation-add-wraparound", "add", [a5, b7])                      # = C(1, 12)
    rel("relation-subtract", "subtract", [s12, b7])                      # = C(q-1, 5)
    rel("relation-subtract-to-negative", "subtract", [O, c1])            # = C(q-12345, q-67890)
    rel("relation-negate", "negate", [c1])
    rel("relation-negate-base-g", "negate", [G])
    rel("relation-negate-identity", "negate", [O])
    rel("relation-add-identity", "add", [c1, O])
    rel("relation-add-identity-first", "add", [O, c1])
    rel("relation-add-doubling", "add", [c1, c1])                        # P + P
    rel("relation-add-inverse-to-identity", "add", [c1, neg(c1)])        # P + (-P) = O
    rel("relation-subtract-self-to-identity", "subtract", [c1, c1])
    rel("relation-add-g-h", "add", [G, H])                               # = -C(q-1, q-1)
    vo("verify-relation-result-1-12", s12, 1, 12)
    vo("verify-relation-result-negated-12345-67890", neg(c1), Q - 12345, Q - 67890)
    vo("verify-relation-result-doubling", cpt(24690, 135780), 24690, 135780)
    rel("relation-add-second-order-3", "add", [c1, hx(x_encoding(0))], NIS)
    rel("relation-negate-mixed-order", "negate", [PIN_MIXED_G_PLUS_ORDER3], NIS)
    rel("relation-subtract-infinity-sort-flag", "subtract", [c1, hx(bytes([0xE0]) + bytes(47))], MAL)
    rel("relation-order-first-point-first", "add", [hx(x_encoding(0)), ""], NIS)
    rel("relation-order-empty-then-order-3", "add", ["", hx(x_encoding(0))], MAL)

    # ---- publicDelta (V3, §6.4)
    def pdelta(name, pt, delta, bits, intent="ok"):
        cl.add(name, "publicDelta", {"pointHex": pt if isinstance(pt, str) else enc_hex(pt),
                                     "delta": dec(delta), "deltaBits": dec(bits)}, intent)

    for k in (1, 64, 252, 253):
        pdelta("public-delta-bits-%d-plus-max" % k, c1, 2 ** k - 1, k)
        pdelta("public-delta-bits-%d-minus-max" % k, c1, -(2 ** k - 1), k)
        pdelta("public-delta-bits-%d-plus-2pow" % k, c1, 2 ** k, k, OOR)
        pdelta("public-delta-bits-%d-minus-2pow" % k, c1, -(2 ** k), k, OOR)
    pdelta("public-delta-zero", c1, 0, 64)
    pdelta("public-delta-plus-1", c1, 1, 1)
    pdelta("public-delta-minus-1", c1, -1, 1)
    pdelta("public-delta-wrap-qm1-plus-1", cpt(Q - 1, 67890), 1, 1)      # = C(0, 67890)
    pdelta("public-delta-wrap-zero-minus-1", cpt(0, 67890), -1, 1)       # = C(q-1, 67890)
    pdelta("public-delta-wrap-qm1-plus-2pow253m1", cq, 2 ** 253 - 1, 253)
    # Width 254 is invalid: delta = 2^254 - 1 and its alias delta - q would both pass that bound.
    pdelta("public-delta-bits-254-plus-max", c1, 2 ** 254 - 1, 254, INV)
    pdelta("public-delta-bits-254-alias", c1, 2 ** 254 - 1 - Q, 254, INV)
    pdelta("public-delta-bits-253-alias", c1, 2 ** 253 - 1 - Q, 253, OOR)
    pdelta("public-delta-identity-plus-5", O, 5, 8)                     # = [5]G
    pdelta("public-delta-identity-minus-5", O, -5, 8)                   # = -[5]G
    pdelta("public-delta-to-identity", cpt(1000, 0), -1000, 16)         # = O
    vo("verify-public-delta-result-wrap", cpt(0, 67890), 0, 67890)
    for k, label in ((0, "0"), (254, "254"), (255, "255"), (-1, "minus-1"), (INT_MAX, "int-max"),
                     (INT_MIN, "int-min")):
        pdelta("public-delta-bits-" + label, c1, 1, k, INV)
    pdelta("public-delta-q", c1, Q, 253, OOR)
    pdelta("public-delta-minus-q", c1, -Q, 253, OOR)
    pdelta("public-delta-2pow300", c1, 2 ** 300, 253, OOR)
    pdelta("public-delta-minus-2pow300", c1, -(2 ** 300), 253, OOR)
    pdelta("public-delta-order-3-point", hx(x_encoding(0)), 1, 1, NIS)
    pdelta("public-delta-mixed-order-point", PIN_MIXED_G_PLUS_ORDER3, 1, 1, NIS)
    pdelta("public-delta-infinity-with-sort-flag", hx(bytes([0xE0]) + bytes(47)), 1, 1, MAL)
    pdelta("public-delta-order-point-before-delta-bits", hx(x_encoding(1)), 1, 0, MAL)
    pdelta("public-delta-order-subgroup-before-delta-bits", hx(x_encoding(0)), 2 ** 300, 255, NIS)
    pdelta("public-delta-order-delta-bits-before-delta", c1, 2 ** 300, 0, INV)

    # ---- multi-defect cases pinning the §13.3 execution order
    vo("verify-order-bad-point-before-value", hx(x_encoding(0)), Q, 67890, NIS)
    vo("verify-order-short-point-before-value", enc_hex(c1)[:94], -1, 67890, MAL)
    vo("verify-order-point-before-amount-bits", hx(x_encoding(1)), 12345, 67890, MAL, 255)
    vo("verify-order-amount-bits-before-value", c1, Q, 67890, INV, 0)
    vo("verify-order-check1-before-check2", c1, 2 ** 64, Q, NCS, 64)
    vo("verify-order-blinding-check1-before-equation", c1, 12346, Q, NCS)
    vo("verify-order-check2-before-equation", c1, 2 ** 64, 67890, OOR, 64)

    # ---- point negatives under decodePoint and decodeEnvelope
    add_point_cases(cl, prof)
    return cl


# vo() in build_scalar accepts a raw hex string for multi-defect points; normalize here.
def _pt_hex(pt):
    return pt if isinstance(pt, str) else enc_hex(pt)


# =============================================================================================
# Bytes profile cases
# =============================================================================================

H2S_PAYLOADS = [("empty", hex_payload(b"")), ("octet-00", hex_payload(b"\x00")),
                ("ascii-abc", hex_payload(b"abc"))] + \
               [("pattern-%d" % n, pattern_payload(n))
                for n in (1, 55, 56, 63, 64, 65, 119, 120, 128, 129, 1024, 65536)]


def build_bytes():
    cl = CaseList()
    prof = PROFILE_BYTES
    O = None
    G, H = B.G, B.H

    def cb(payload_obj, r):
        s = hash_to_scalar(payload_bytes(payload_obj))["s"]
        return cpt(s, r)

    abc = hex_payload(b"abc")
    empty = hex_payload(b"")
    p1024 = pattern_payload(1024)
    p65536 = pattern_payload(65536)
    c_e0 = cb(empty, 0)
    c_eq = cb(empty, Q - 1)
    c_abc = cb(abc, 12345)
    c_1024 = cb(p1024, 67890)
    c_64k = cb(p65536, 12345)

    # ---- decodePoint positives
    add_decode_positive(cl, "identity", O)
    add_decode_positive(cl, "base-g", G)
    add_decode_positive(cl, "base-h", H)
    add_decode_positive(cl, "commitment-empty-0", c_e0)
    add_decode_positive(cl, "commitment-abc-12345", c_abc)

    # ---- hashToScalar (§5), including every §10.2 payload
    for name, payload in H2S_PAYLOADS:
        cl.add("hash-to-scalar-" + name, "hashToScalar", {"payload": payload}, "ok")

    # ---- commit positives (array, declared-length and ToEnd forms)
    def cm(name, payload, r, intent="ok", **extra):
        inp = {"payload": payload, "blinding": dec(r)}
        for k, v in extra.items():
            inp[k] = dec(v)
        cl.add("commit-" + name, "commit", inp, intent)

    cm("empty-zero", empty, 0)
    cm("empty-qm1", empty, Q - 1)
    cm("empty-one", empty, 1)
    cm("abc-12345", abc, 12345)
    cm("abc-qm1", abc, Q - 1)
    cm("abc-12345-declared-length", abc, 12345, declaredLength=3)
    cm("abc-12345-max-bytes-3", abc, 12345, maxBytes=3)
    cm("abc-12345-max-bytes-4096", abc, 12345, maxBytes=4096)
    cm("empty-zero-declared-length-0", empty, 0, declaredLength=0)
    cm("empty-zero-max-bytes-0", empty, 0, maxBytes=0)
    cm("empty-zero-max-bytes-max", empty, 0, maxBytes=MAX_PAYLOAD_BYTES)
    cm("pattern-1024-67890", p1024, 67890)
    cm("pattern-1024-67890-declared-length", p1024, 67890, declaredLength=1024)
    cm("pattern-1024-67890-max-bytes", p1024, 67890, maxBytes=1025)
    cm("pattern-65536-12345", p65536, 12345)
    cm("pattern-65536-12345-declared-length", p65536, 12345, declaredLength=65536)
    cm("pattern-65536-12345-max-bytes", p65536, 12345, maxBytes=65536)

    # ---- LENGTH_OUT_OF_RANGE (§5.1: before any read; empty payload per §13.3 "Streams")
    for field in ("declaredLength", "maxBytes"):
        stem = "declared-length" if field == "declaredLength" else "max-bytes"
        for label, v in (("minus-1", -1), ("max-plus-1", MAX_PAYLOAD_BYTES + 1),
                         ("long-min", LONG_MIN), ("long-max", LONG_MAX)):
            cm("%s-%s" % (stem, label), empty, 12345, LOR, **{field: v})

    # ---- verifyOpening
    def vo(name, pt, payload, r, intent="ok"):
        cl.add(name, "verifyOpening", {"pointHex": _pt_hex(pt), "payload": payload,
                                       "blinding": dec(r)}, intent)

    vo("verify-empty-zero", c_e0, empty, 0)
    vo("verify-empty-qm1", c_eq, empty, Q - 1)
    vo("verify-abc-12345", c_abc, abc, 12345)
    vo("verify-pattern-1024-67890", c_1024, p1024, 67890)
    vo("verify-pattern-65536-12345", c_64k, p65536, 12345)
    vo("verify-wrong-payload", c_abc, hex_payload(b"abd"), 12345, OMM)
    vo("verify-wrong-payload-trailing-zero", c_abc, hex_payload(b"abc\x00"), 12345, OMM)
    vo("verify-wrong-payload-truncated", c_abc, hex_payload(b"ab"), 12345, OMM)
    vo("verify-wrong-blinding", c_abc, abc, 12346, OMM)
    vo("verify-pattern-length-off-by-one", c_1024, pattern_payload(1023), 67890, OMM)
    vo("verify-identity-empty-zero", O, empty, 0, OMM)
    vo("verify-scalar-commitment-of-payload-integer", cpt(int.from_bytes(b"abc", "big"), 12345),
       abc, 12345, OMM)
    # Seeded faults of ADR-0060 (as points a faulty generator would produce): each is a mismatch.
    s_nolen = _h2s_variant(b"abc", "h2s_no_length")
    s_prefix = _h2s_variant(b"abc", "h2s_length_prefix")
    s_mod_l = _h2s_variant(b"abc", "h2s_mod_l")
    s_nozero = _h2s_variant(b"abc", "h2s_no_zero_prefix")
    vo("verify-fault-length-suffix-dropped", cpt(s_nolen, 12345), abc, 12345, OMM)
    vo("verify-fault-length-as-prefix", cpt(s_prefix, 12345), abc, 12345, OMM)
    vo("verify-fault-reduced-mod-jubjub-l", cpt(s_mod_l, 12345), abc, 12345, OMM)
    vo("verify-fault-zero-prefix-dropped", cpt(s_nozero, 12345), abc, 12345, OMM)
    s_abc = hash_to_scalar(b"abc")["s"]
    vo("verify-fault-swapped-bases", add(mul(s_abc, H), mul(12345, G)), abc, 12345, OMM)

    # ---- check 1 on the blinding (every strict operation)
    for label, bad in BAD_SCALARS:
        cm("blinding-" + label, abc, bad, NCS)
        vo("verify-blinding-" + label, c_abc, abc, bad, NCS)
        cl.add("encode-opening-blinding-" + label, "encodeOpening", {"blinding": dec(bad)}, NCS)
    cm("blinding-12345-plus-q-not-reduced", abc, 12345 + Q, NCS)
    vo("verify-blinding-12345-plus-q-not-reduced", c_abc, abc, 12345 + Q, NCS)

    # ---- blinding encoding (§6.2)
    for name, r in (("zero", 0), ("one", 1), ("12345", 12345), ("qm1", Q - 1), ("2pow254", 2 ** 254)):
        cl.add("encode-opening-" + name, "encodeOpening", {"blinding": dec(r)}, "ok")
        cl.add("decode-opening-" + name, "decodeOpening", {"openingHex": hx(r.to_bytes(32, "big"))}, "ok")

    def do(name, data, cls):
        cl.add("decode-opening-" + name, "decodeOpening", {"openingHex": hx(data)}, cls)

    do("blinding-q", Q.to_bytes(32, "big"), NCS)
    do("blinding-q-plus-1", (Q + 1).to_bytes(32, "big"), NCS)
    do("blinding-all-ones", b"\xff" * 32, NCS)
    for n in (0, 31, 33, 48, 64):
        do("length-%d" % n, bytes(n), MAL)
    do("length-33-order-before-scalar", Q.to_bytes(32, "big") + b"\x00", MAL)

    # ---- envelopes (§9, 80 octets)
    add_envelope_round_trip(cl, prof, "identity", O)
    add_envelope_round_trip(cl, prof, "commitment-empty-0", c_e0)
    add_envelope_round_trip(cl, prof, "commitment-abc-12345", c_abc)
    add_envelope_negatives(cl, prof, c_abc)
    cl.add("envelope-encode-order-3", "encodeEnvelope", {"pointHex": hx(x_encoding(0))}, NIS)
    cl.add("envelope-encode-x-1-not-square", "encodeEnvelope", {"pointHex": hx(x_encoding(1))}, MAL)

    # ---- multi-defect cases pinning the §13.3 execution order
    vo("verify-order-blinding-before-equation", c_abc, hex_payload(b"abd"), Q, NCS)
    vo("verify-order-off-curve-before-blinding", hx(x_encoding(1)), abc, Q, MAL)
    vo("verify-order-order-3-before-blinding", hx(x_encoding(0)), abc, -1, NIS)
    vo("verify-order-mixed-order-before-mismatch", PIN_MIXED_G_PLUS_ORDER3, abc, 12345, NIS)
    vo("verify-order-short-point-before-blinding", enc_hex(c_abc)[:94], abc, -1, MAL)

    add_point_cases(cl, prof)
    return cl


def _h2s_variant(payload, mutation):
    """A seeded-fault scalar: the primary mapping with one mutation switched on (fixtures only)."""
    saved = set(MUT)
    MUT.clear()
    MUT.add(mutation)
    _H2S_CACHE.clear()
    try:
        return hash_to_scalar(payload)["s"]
    finally:
        MUT.clear()
        MUT.update(saved)
        _H2S_CACHE.clear()


# =============================================================================================
# File assembly and provenance
# =============================================================================================

def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


SPECS = {
    "commitment-profiles-v1.md": "docs/specs/commitment-profiles-v1.md",
    "pedersen-bls12-381-g1-v1.md": "docs/specs/pedersen-bls12-381-g1-v1.md",
    "pedersen-jubjub-bytes-v1.md": "docs/specs/pedersen-jubjub-bytes-v1.md",
}
SPECS_FOR = {
    "scalar": ["commitment-profiles-v1.md", "pedersen-bls12-381-g1-v1.md"],
    "bytes": ["commitment-profiles-v1.md", "pedersen-bls12-381-g1-v1.md",
              "pedersen-jubjub-bytes-v1.md"],
}
# The revisions these vectors implement (pinned here, not read from the documents). A later
# metadata-only revision changes a document's date and SHA-256 but not this label.
IMPLEMENTED_REVISION = {"commitment-profiles-v1.md": "r7", "pedersen-bls12-381-g1-v1.md": "r2"}
_DATE_RE = re.compile(r"^\*\*Date:\*\*\s+(\d{4}-\d{2}-\d{2})(?:\s+\((r\d+)\))?", re.M)


def spec_entry(repo_root, key):
    rel = SPECS[key]
    path = os.path.join(repo_root, rel)
    if not os.path.isfile(path):
        raise SystemExit("specification not found: %s (use --repo-root)" % path)
    with open(path, "rb") as fh:
        raw = fh.read()
    m = _DATE_RE.search(raw.decode("utf-8"))
    require(m is not None, "no **Date:** line in " + rel)
    entry = {"path": rel}
    if key in IMPLEMENTED_REVISION:
        entry["revision"] = IMPLEMENTED_REVISION[key]
        if m.group(2) != IMPLEMENTED_REVISION[key]:
            sys.stderr.write("warning: %s is %s on disk; the vectors implement %s\n"
                             % (rel, m.group(2), IMPLEMENTED_REVISION[key]))
    entry["date"] = m.group(1)
    entry["sha256"] = hashlib.sha256(raw).hexdigest()
    return entry


def python_version():
    return "%s %s" % (platform.python_implementation(), platform.python_version())


def build_file(kind, cl, repo_root, strict=True):
    reset_caches()
    positive, negative = [], []
    for name, op, inp, intent in cl.cases:
        try:
            expected = run_case(kind, op, inp)
            outcome = "ok"
        except Fail as e:
            outcome = e.cls
        except (PinError, ValueError, OverflowError, ZeroDivisionError) as e:
            if strict:
                raise
            outcome = "PYTHON:" + type(e).__name__  # only reachable under a mutation
        if strict and outcome != intent:
            raise PinError("case %s: intended %s, implementation gave %s" % (name, intent, outcome))
        if outcome == "ok":
            positive.append({"name": name, "operation": op, "input": inp, "expected": expected})
        else:
            negative.append({"name": name, "operation": op, "input": inp, "error": outcome})
    doc = {
        "schema": "zeroj-commitment-vectors-v1",
        "profileId": PROFILE_OF[kind],
        "spec": [spec_entry(repo_root, k) for k in SPECS_FOR[kind]],
        "generator": {"script": SCRIPT_REL, "scriptSha256": sha256_file(os.path.abspath(__file__)),
                      "python": python_version()},
        "positive": positive,
        "negative": negative,
    }
    if strict:
        check_format(kind, doc)
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


BUILDERS = [("scalar", build_scalar), ("bytes", build_bytes)]
_BASELINE_CASES = {}


def generate_all(repo_root, strict=True):
    out = {}
    for kind, _ in BUILDERS:
        out[PROFILE_OF[kind]] = build_file(kind, _BASELINE_CASES[kind], repo_root, strict)
    return out


# =============================================================================================
# Format checks (§13.1-§13.3) applied to every generated document
# =============================================================================================

ALLOWED_OPS = {
    "scalar": {"decodePoint", "commit", "verifyOpening", "encodeOpening", "decodeOpening",
               "encodeEnvelope", "decodeEnvelope", "relation", "publicDelta"},
    "bytes": {"decodePoint", "commit", "hashToScalar", "verifyOpening", "encodeOpening",
              "decodeOpening", "encodeEnvelope", "decodeEnvelope"},
}
INPUT_FIELDS = {
    ("scalar", "decodePoint"): ({"pointHex"}, set()),
    ("scalar", "commit"): ({"value", "blinding"}, set()),
    ("scalar", "verifyOpening"): ({"pointHex", "value", "blinding"}, {"amountBits"}),
    ("scalar", "encodeOpening"): ({"value", "blinding"}, set()),
    ("scalar", "decodeOpening"): ({"openingHex"}, set()),
    ("scalar", "encodeEnvelope"): ({"pointHex"}, set()),
    ("scalar", "decodeEnvelope"): ({"envelopeHex", "expectedProfileId"}, set()),
    ("scalar", "relation"): ({"op", "pointsHex"}, set()),
    ("scalar", "publicDelta"): ({"pointHex", "delta", "deltaBits"}, set()),
    ("bytes", "decodePoint"): ({"pointHex"}, set()),
    ("bytes", "commit"): ({"payload", "blinding"}, {"declaredLength", "maxBytes"}),
    ("bytes", "hashToScalar"): ({"payload"}, set()),
    ("bytes", "verifyOpening"): ({"pointHex", "payload", "blinding"}, set()),
    ("bytes", "encodeOpening"): ({"blinding"}, set()),
    ("bytes", "decodeOpening"): ({"openingHex"}, set()),
    ("bytes", "encodeEnvelope"): ({"pointHex"}, set()),
    ("bytes", "decodeEnvelope"): ({"envelopeHex", "expectedProfileId"}, set()),
}
_HEX_RE = re.compile(r"(?:[0-9a-f]{2})*")
_INT_RE = re.compile(r"-?(0|[1-9][0-9]*)")


def check_no_numbers(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            require(isinstance(k, str), "non-string key")
            if k.endswith("Hex"):
                items = v if isinstance(v, list) else [v]
                require(all(isinstance(x, str) and _HEX_RE.fullmatch(x) for x in items),
                        "bad Hex field " + k)
            check_no_numbers(v)
    elif isinstance(obj, list):
        for v in obj:
            check_no_numbers(v)
    else:
        require(isinstance(obj, str), "non-string JSON value: %r" % (obj,))


def check_format(kind, doc):
    check_no_numbers(doc)
    require(list(doc) == ["schema", "profileId", "spec", "generator", "positive", "negative"],
            "top-level keys")
    names = set()
    for side in ("positive", "negative"):
        for c in doc[side]:
            require(c["name"] not in names, "duplicate name " + c["name"])
            names.add(c["name"])
            op = c["operation"]
            require(op in ALLOWED_OPS[kind], "operation %s not defined for %s" % (op, kind))
            req, opt = INPUT_FIELDS[(kind, op)]
            keys = set(c["input"])
            require(req <= keys <= req | opt, "input fields of " + c["name"])
            require(not {"declaredLength", "maxBytes"} <= keys, "both length fields in " + c["name"])
            for f in ("value", "blinding", "delta", "amountBits", "deltaBits", "declaredLength",
                      "maxBytes"):
                if f in c["input"]:
                    require(_INT_RE.fullmatch(c["input"][f]) is not None, "integer field " + f)
            if side == "negative":
                require(c["error"] in ERROR_CLASSES, "error class " + c["error"])
                require(set(c) == {"name", "operation", "input", "error"}, "negative keys")
            else:
                require(set(c) == {"name", "operation", "input", "expected"}, "positive keys")
                if op == "decodePoint":
                    e = c["expected"]
                    require(e == {"identity": "true"} or
                            (set(e) == {"xHex", "yHex"} and len(e["xHex"]) == 96 and
                             len(e["yHex"]) == 96), "G1 decodePoint expected form")
            if op == "relation":
                n = len(c["input"]["pointsHex"])
                require(n == (1 if c["input"]["op"] == "negate" else 2), "relation cardinality")
            if op == "decodeEnvelope":
                require(c["input"]["expectedProfileId"] == PROFILE_OF[kind], "expectedProfileId")
    if kind == "bytes":
        check_streams_rule(doc["positive"], doc["negative"])


def check_streams_rule(positive, negative):
    """§13.3 "Streams": declaredLength equals the payload length and maxBytes is at least the
    payload length, except in LENGTH_OUT_OF_RANGE cases (value outside [0, MAX], empty payload)."""
    for case in positive + negative:
        inp = case["input"]
        fields = [f for f in ("declaredLength", "maxBytes") if f in inp]
        if not fields:
            continue
        require(case["operation"] == "commit", "Streams: length field outside commit")
        value = int(inp[fields[0]])
        n = len(payload_bytes(inp["payload"]))
        if case.get("error") == LOR:
            require(n == 0 and not 0 <= value <= MAX_PAYLOAD_BYTES, "Streams: " + case["name"])
        elif fields[0] == "declaredLength":
            require(value == n, "Streams: declaredLength != length in " + case["name"])
        else:
            require(value >= n, "Streams: maxBytes < length in " + case["name"])


# =============================================================================================
# Pin checks (every mode): the values transcribed from the spec text
# =============================================================================================

def pin_checks():
    for (m, r, want) in PIN_COMMITMENTS:
        require(enc_hex(commit_raw(m, r)) == want, "§10.3 C(%d, %d)" % (m, r))
    require(commit_raw(Q - 1, Q - 1) == neg(add(B.G, B.H)), "§10.3 C(q-1, q-1) = -(G + H)")
    for label, (form, val), uniform, s in PIN_H2S:
        payload = bytes.fromhex(val) if form == "hex" else pattern(val)
        h = hash_to_scalar(payload)
        require(hx(h["u"]) == uniform and h["s"] == s, "§10.2 " + label)
    table = [
        (IDENTITY_ENC, "ok"), (bytes([0xE0]) + bytes(47), MAL),
        (bytes([0xC0]) + bytes(46) + b"\x01", MAL), (x_encoding(0), NIS),
        (bytes([0x00]) + compress(B.G)[1:], MAL), (compress(B.G)[:47], MAL),
        (compress(B.G) + b"\x00", MAL), (x_encoding(P), MAL), (x_encoding(1), MAL),
        (x_encoding(0, 0xA0), NIS), (x_encoding(4), NIS),
        (bytes.fromhex(PIN_MIXED_G_PLUS_ORDER3), NIS),
    ]
    for data, want in table:
        try:
            _strict_decode(data)
            got = "ok"
        except Fail as e:
            got = e.cls
        require(got == want, "§10.4 decoder case %s: %s" % (data.hex()[:16], got))
    require(enc_hex(add(B.G, ORDER3)) == PIN_MIXED_G_PLUS_ORDER3, "§10.4 G + (0, 2)")
    require(mul(3, ORDER3) is None and ORDER3 is not None, "(0, 2) has order 3")


# =============================================================================================
# --self-test part 1: independent re-verification of every emitted case with the reference
# =============================================================================================

class RFail(Exception):
    def __init__(self, cls):
        super().__init__(cls)
        self.cls = cls


class Reverifier:
    """Recomputes each case from its JSON with the imported reference's primitives
    (affine double-and-add, its own strict decoder, generic expand_message_xmd)."""

    def __init__(self):
        self.g, self.h = ref.derive_basis()
        self.dec_cache = {}
        self.commit_cache = {}

    def decode(self, hexstr):
        if hexstr not in self.dec_cache:
            st = ref.strict_decode(bytes.fromhex(hexstr))
            self.dec_cache[hexstr] = st
        st, val = self.dec_cache[hexstr]
        if st == "ok":
            return val
        if st == ref.MALFORMED:
            raise RFail(MAL)
        if st == ref.NOT_IN_SUBGROUP:
            raise RFail(NIS)
        raise PinError("reference decoder returned " + repr(st))

    def commit(self, m, r):
        key = (m, r)
        if key not in self.commit_cache:
            self.commit_cache[key] = ref.commit(m, r, (self.g, self.h))
        return self.commit_cache[key]

    @staticmethod
    def c1(x):
        if not 0 <= x < ref.Q:
            raise RFail(NCS)
        return x

    def h2s(self, payload):
        return ref.hash_bytes_to_scalar_g1_trace(payload)

    def envelope(self, data, expected):
        hdr = b"\x01" + bytes([len(expected)]) + expected.encode("ascii")
        if len(data) < 2 or data[0] != 1:
            raise RFail(MAL)
        if data[1] + 2 > len(data):
            raise RFail(MAL)
        if data[2:2 + data[1]] != hdr[2:]:
            raise RFail(PMM)
        if len(data) != len(hdr) + 48:
            raise RFail(MAL)
        return self.decode(data[len(hdr):].hex())

    def run(self, kind, op, inp):
        bits_ok = lambda k: 1 <= k <= 254  # noqa: E731  (amountBits, spec §6.3)
        delta_bits_ok = lambda k: 1 <= k <= 253  # noqa: E731  (deltaBits, spec §6.4 r2)
        if op == "decodePoint":
            pt = self.decode(inp["pointHex"])
            return {"identity": "true"} if pt is None else {"xHex": ref._h48(pt[0]),
                                                           "yHex": ref._h48(pt[1])}
        if op == "commit" and kind == "scalar":
            m, r = self.c1(int(inp["value"])), self.c1(int(inp["blinding"]))
            return {"pointHex": ref.compress(self.commit(m, r)).hex()}
        if op == "commit":
            r = self.c1(int(inp["blinding"]))
            for f in ("declaredLength", "maxBytes"):
                if f in inp and not 0 <= int(inp[f]) <= 2 ** 61 - 256:
                    raise RFail(LOR)
            pb = payload_bytes(inp["payload"])
            s = self.h2s(pb)["scalar"]
            pt = self.commit(s, r)
            if len(pb) <= 4096:
                require(ref.commit_bytes(pb, r, (self.g, self.h)) == pt, "commit_bytes != commit(s)")
            return {"pointHex": ref.compress(pt).hex()}
        if op == "hashToScalar":
            t = self.h2s(payload_bytes(inp["payload"]))
            return {"b0Hex": t["b0"].hex(), "b1Hex": t["b1"].hex(), "b2Hex": t["b2"].hex(),
                    "uniformBytesHex": t["uniform"].hex(), "scalar": str(t["scalar"])}
        if op == "verifyOpening":
            pt = self.decode(inp["pointHex"])
            if kind == "scalar":
                k = int(inp["amountBits"]) if "amountBits" in inp else None
                if k is not None and not bits_ok(k):
                    raise RFail(INV)
                m, r = self.c1(int(inp["value"])), self.c1(int(inp["blinding"]))
                if k is not None and m.bit_length() > k:
                    raise RFail(OOR)
                calc = self.commit(m, r)
            else:
                r = self.c1(int(inp["blinding"]))
                calc = self.commit(self.h2s(payload_bytes(inp["payload"]))["scalar"], r)
            if calc != pt:
                raise RFail(OMM)
            return {"result": "true"}
        if op == "encodeOpening":
            if kind == "scalar":
                m, r = self.c1(int(inp["value"])), self.c1(int(inp["blinding"]))
                return {"openingHex": ref.i2osp(m, 32).hex() + ref.i2osp(r, 32).hex()}
            return {"openingHex": ref.i2osp(self.c1(int(inp["blinding"])), 32).hex()}
        if op == "decodeOpening":
            data = bytes.fromhex(inp["openingHex"])
            want = 64 if kind == "scalar" else 32
            if len(data) != want:
                raise RFail(MAL)
            vals = [self.c1(ref.os2ip(data[i:i + 32])) for i in range(0, want, 32)]
            if kind == "scalar":
                return {"value": str(vals[0]), "blinding": str(vals[1])}
            return {"blinding": str(vals[0])}
        if op == "encodeEnvelope":
            pt = self.decode(inp["pointHex"])
            pid = PROFILE_OF[kind]
            out = b"\x01" + bytes([len(pid)]) + pid.encode() + ref.compress(pt)
            require(len(out) == ENVELOPE_LENGTH[pid], "envelope length")
            return {"envelopeHex": out.hex()}
        if op == "decodeEnvelope":
            pt = self.envelope(bytes.fromhex(inp["envelopeHex"]), inp["expectedProfileId"])
            return {"pointHex": ref.compress(pt).hex()}
        if op == "relation":
            pts = [self.decode(h) for h in inp["pointsHex"]]
            o = inp["op"]
            if o == "negate":
                res = ref.point_neg(pts[0])
            elif o == "add":
                res = ref.point_add(pts[0], pts[1])
            else:
                res = ref.point_add(pts[0], ref.point_neg(pts[1]))
            return {"pointHex": ref.compress(res).hex()}
        if op == "publicDelta":
            pt = self.decode(inp["pointHex"])
            k = int(inp["deltaBits"])
            if not delta_bits_ok(k):
                raise RFail(INV)
            d = int(inp["delta"])
            if not -(2 ** k) < d < 2 ** k:
                raise RFail(OOR)
            # Residue path: [d mod q]G (the primary uses [|d|]G and negates).
            return {"pointHex": ref.compress(ref.point_add(pt, ref.scalar_mul(d % ref.Q, self.g))).hex()}
        raise PinError("reverify: unknown operation " + op)


def opening_of(hexstr):
    return OPENINGS.get(hexstr)


def homomorphism_check(rv, c, problems):
    """For relation/publicDelta/commit/verify positives whose inputs have known openings, the
    output must equal C(opening combination) computed by the reference."""
    op, inp = c["operation"], c["input"]
    want_open = None
    if op == "relation":
        ops = [opening_of(h) for h in inp["pointsHex"]]
        if all(o is not None for o in ops):
            if inp["op"] == "negate":
                want_open = ((-ops[0][0]) % Q, (-ops[0][1]) % Q)
            elif inp["op"] == "add":
                want_open = ((ops[0][0] + ops[1][0]) % Q, (ops[0][1] + ops[1][1]) % Q)
            else:
                want_open = ((ops[0][0] - ops[1][0]) % Q, (ops[0][1] - ops[1][1]) % Q)
    elif op == "publicDelta":
        o = opening_of(inp["pointHex"]) if inp["pointHex"] != hx(IDENTITY_ENC) else (0, 0)
        if o is not None:
            want_open = ((o[0] + int(inp["delta"])) % Q, o[1])
    if want_open is None:
        return 0
    got = c["expected"]["pointHex"]
    calc = ref.compress(rv.commit(*want_open)).hex()
    if got != calc:
        problems.append("%s: homomorphism C%r gives %s, file has %s" % (c["name"], want_open,
                                                                       calc[:16], got[:16]))
    return 1


def identity_checks(rv, problems):
    """§10.3 identities and §2.3 rule 1, by the reference."""
    g, h = rv.g, rv.h
    checks = [
        ("C(0,0) = O", rv.commit(0, 0) is None),
        ("C(1,0) = G", rv.commit(1, 0) == g),
        ("C(0,1) = H", rv.commit(0, 1) == h),
        ("C(q-1,q-1) = -(G+H)", rv.commit(Q - 1, Q - 1) == ref.point_neg(ref.point_add(g, h))),
        ("C(q-1,0) = -G", rv.commit(Q - 1, 0) == ref.point_neg(g)),
        ("C(0,q-1) = -H", rv.commit(0, Q - 1) == ref.point_neg(h)),
        ("compress(G) pinned", ref.compress(g).hex() == PIN_G_COMPRESSED),
        ("compress(H) pinned", ref.compress(h).hex() == PIN_H_COMPRESSED),
        ("G != +-H", g != h and g != ref.point_neg(h)),
    ]
    for (m, r, want) in PIN_COMMITMENTS:
        checks.append(("§10.3 C(%d..,%d..) by reference" % (m % 1000, r % 1000),
                       ref.compress(rv.commit(m, r)).hex() == want))
    for name, ok in checks:
        if not ok:
            problems.append("identity check failed: " + name)
    return len(checks)


def reverify_doc(kind, doc, rv):
    problems = []
    counts = {"cases": 0, "homomorphism": 0, "pins": 0}
    pins_h2s = {}
    for label, (form, val), uniform, s in PIN_H2S:
        pins_h2s[json.dumps(hex_payload(bytes.fromhex(val)) if form == "hex"
                            else pattern_payload(val), sort_keys=True)] = (uniform, s)
    pins_commit = {(str(m), str(r)): want for m, r, want in PIN_COMMITMENTS}
    for side in ("positive", "negative"):
        for c in doc[side]:
            counts["cases"] += 1
            try:
                got = rv.run(kind, c["operation"], c["input"])
                outcome = "ok"
            except RFail as e:
                got, outcome = None, e.cls
            if side == "positive":
                if outcome != "ok":
                    problems.append("%s: file positive, reference gives %s" % (c["name"], outcome))
                elif got != c["expected"]:
                    problems.append("%s: expected differs from reference %s" % (c["name"], got))
                else:
                    counts["homomorphism"] += homomorphism_check(rv, c, problems)
                    if c["operation"] == "hashToScalar":
                        key = json.dumps(c["input"]["payload"], sort_keys=True)
                        if key in pins_h2s:
                            counts["pins"] += 1
                            u, s = pins_h2s[key]
                            if (c["expected"]["uniformBytesHex"], c["expected"]["scalar"]) != (u, str(s)):
                                problems.append("%s: differs from spec §10.2" % c["name"])
                    if c["operation"] == "commit" and kind == "scalar":
                        key = (c["input"]["value"], c["input"]["blinding"])
                        if key in pins_commit:
                            counts["pins"] += 1
                            if c["expected"]["pointHex"] != pins_commit[key]:
                                problems.append("%s: differs from spec §10.3" % c["name"])
            else:
                if outcome != c["error"]:
                    problems.append("%s: file says %s, reference gives %s" % (c["name"], c["error"],
                                                                              outcome))
    return problems, counts


# §13.4 / ADR-0060 coverage: names that must exist in each file (positive "+", negative "-").
REQUIRED = {
    "scalar": [
        "+decode-point-identity", "+decode-point-commitment-12345-67890", "+commit-zero-zero",
        "+commit-qm1-qm1", "+commit-one-zero", "+commit-zero-one", "+commit-12345-67890",
        "+verify-identity-zero-zero", "+verify-qm1-qm1", "+encode-opening-qm1-qm1",
        "+decode-opening-qm1-qm1", "+envelope-encode-identity", "+envelope-decode-identity",
        "+verify-amount-bits-254-max", "+verify-amount-bits-252-max", "+verify-amount-bits-253-max",
        "-verify-amount-bits-254-overflow", "-verify-amount-bits-0", "-verify-amount-bits-255",
        "+public-delta-bits-64-plus-max", "+public-delta-bits-64-minus-max",
        "-public-delta-bits-64-plus-2pow", "-public-delta-bits-64-minus-2pow",
        "-public-delta-bits-0", "-public-delta-bits-254", "-public-delta-bits-255", "+public-delta-zero",
        "-public-delta-bits-254-alias", "-public-delta-bits-253-alias",
        "+public-delta-wrap-qm1-plus-1", "+public-delta-wrap-zero-minus-1",
        "-public-delta-bits-int-min", "-public-delta-bits-int-max",
        "+relation-add-wraparound", "+relation-subtract", "+relation-negate",
        "-verify-wrong-value", "-decode-opening-length-63", "-decode-opening-length-65",
        "-decode-opening-value-q", "-decode-opening-blinding-q", "-decode-opening-value-q-plus-1",
        "-decode-opening-blinding-q-plus-1",
        "-envelope-decode-other-g1-profile-pedersen-bls12-381-g1-bytes-v1",
    ] + ["-%s-%s-%s" % (op, f, b) for op in ("commit", "verify", "encode-opening")
         for f in ("value", "blinding") for b in ("q", "q-plus-1", "minus-1")],
    "bytes": [
        "+decode-point-identity", "+decode-point-commitment-abc-12345", "+commit-empty-zero",
        "+commit-empty-qm1", "+verify-empty-zero", "+verify-empty-qm1",
        "+encode-opening-qm1", "+decode-opening-qm1", "+envelope-encode-identity",
        "+envelope-decode-identity", "+hash-to-scalar-empty", "+hash-to-scalar-pattern-129",
        "+hash-to-scalar-pattern-1024", "-commit-declared-length-minus-1",
        "-commit-declared-length-max-plus-1", "-commit-max-bytes-minus-1",
        "-commit-max-bytes-max-plus-1", "-verify-wrong-payload", "-decode-opening-length-31",
        "-decode-opening-length-33", "-decode-opening-blinding-q",
        "-decode-opening-blinding-q-plus-1",
        "-envelope-decode-other-g1-profile-pedersen-bls12-381-g1-v1",
    ] + ["+hash-to-scalar-pattern-%d" % n for n in (1, 55, 56, 63, 64, 65, 119, 120, 128)] +
        ["-%s-%s" % (op, b) for op in ("commit-blinding", "verify-blinding", "encode-opening-blinding")
         for b in ("q", "q-plus-1", "minus-1")],
    "both": [
        "-decode-point-length-0", "-decode-point-length-47", "-decode-point-length-49",
        "-decode-point-compression-flag-clear-g", "-decode-point-infinity-with-sort-flag",
        "-decode-point-infinity-nonzero-last-bit", "-decode-point-x-equals-p",
        "-decode-point-x-1-not-square", "-decode-point-order-3-x-0",
        "-decode-point-x-4-outside-subgroup", "-decode-point-mixed-order-g-plus-order-3",
        "-envelope-decode-point-order-3-x-0", "-envelope-decode-point-mixed-order-g-plus-order-3",
        "-envelope-decode-version-0x00", "-envelope-decode-version-0x02",
        "-envelope-decode-truncated-by-one", "-envelope-decode-trailing-octet",
        "-envelope-decode-jubjub-profile-pedersen-jubjub-v1", "-envelope-decode-id-differs-in-one-octet",
        "-envelope-decode-point-mismatch-47-octets", "-envelope-decode-point-length-47",
        "+decode-point-base-g",
    ],
}


def coverage_check(kind, doc):
    have = {("+" if s == "positive" else "-") + c["name"] for s in ("positive", "negative")
            for c in doc[s]}
    missing = [n for n in REQUIRED[kind] + REQUIRED["both"] if n not in have]
    ops = {c["operation"] for s in ("positive", "negative") for c in doc[s]}
    multi = [c for c in doc["negative"] if "-order-" in c["name"]]
    if len(multi) < 2:
        missing.append("(at least two multi-defect order cases)")
    return missing, sorted(ops)


# =============================================================================================
# --self-test part 2: mutations (each must change at least one emitted case)
# =============================================================================================

def mutation_test(repo_root, baseline):
    results = []
    for name, desc in MUTATIONS:
        MUT.clear()
        MUT.add(name)
        try:
            mutated = generate_all(repo_root, strict=False)
        finally:
            MUT.clear()
            reset_caches()
        changed = {}
        for pid, text in baseline.items():
            if mutated[pid] != text:
                a, b = json.loads(text), json.loads(mutated[pid])
                old = {c["name"]: c for c in a["positive"] + a["negative"]}
                new = {c["name"]: c for c in b["positive"] + b["negative"]}
                changed[pid] = sum(1 for k in old if old[k] != new.get(k))
        results.append((name, desc, changed))
    return results


# =============================================================================================
# --check
# =============================================================================================

_MISSING = object()


def _diff(a, b, where, out, limit=20):
    if len(out) >= limit:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for key in list(a) + [k for k in b if k not in a]:
            va, vb = a.get(key, _MISSING), b.get(key, _MISSING)
            path = "%s.%s" % (where, key)
            if va is _MISSING:
                out.append("%s present only in the regenerated file" % path)
            elif vb is _MISSING:
                out.append("%s present only in the file on disk" % path)
            else:
                _diff(va, vb, path, out, limit)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append("%s has %d entries on disk, %d regenerated" % (where, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            _diff(x, y, "%s[%d]" % (where, i), out, limit)
    elif type(a) is not type(b) or a != b:
        out.append("%s: %s on disk, %s regenerated" % (where, json.dumps(a)[:80], json.dumps(b)[:80]))


PROVENANCE_PATH = re.compile(r"^\$\.(generator\.python|spec\[\d+\]\.(sha256|date))(:| )")


def compare_texts(disk_text, text):
    """Byte-for-byte comparison. Returns a list of differences (empty iff identical). Each
    structural difference is named and marked when it is a provenance-only field."""
    if disk_text == text:
        return []
    try:
        disk = json.loads(disk_text)
    except ValueError as exc:
        return ["not identical; cannot parse the file on disk (%s)" % exc]
    details = []
    _diff(disk, json.loads(text), "$", details)
    out = []
    for d in details:
        m = re.match(r"\$\.(positive|negative)\[(\d+)\]", d)
        if m:
            try:
                d += " (case %s)" % disk[m.group(1)][int(m.group(2))]["name"]
            except (KeyError, IndexError, TypeError):
                pass
        if PROVENANCE_PATH.match(d):
            d += " [provenance field]"
        out.append(d)
    return out or ["not byte-identical (formatting or key order only)"]


def check_regression(texts):
    """The comparator must flag each tampered copy and accept the untouched text."""
    pid, text = sorted(texts.items())[0]
    flip = text.replace('"pointHex": "c0', '"pointHex": "c1', 1)
    require(flip != text, "regression fixture")
    copies = [
        ("unchanged", text, False),
        ("one hex digit changed", flip, True),
        ("trailing newline removed", text[:-1], True),
        ("python version changed", text.replace('"python": "', '"python": "X', 1), True),
        ("case removed", json.dumps(dict(json.loads(text), negative=json.loads(text)["negative"][:-1]),
                                    indent=2, ensure_ascii=True) + "\n", True),
        ("extra null key", json.dumps(dict(json.loads(text), unexpected=None), indent=2,
                                      ensure_ascii=True) + "\n", True),
    ]
    failures = []
    for label, t, want in copies:
        if bool(compare_texts(t, text)) != want:
            failures.append(label)
    return failures, len(copies)


def summarize(texts):
    lines = []
    for pid, text in texts.items():
        doc = json.loads(text)
        lines.append("%s: %d positive, %d negative" % (pid, len(doc["positive"]), len(doc["negative"])))
        ops = {}
        for side in ("positive", "negative"):
            for c in doc[side]:
                ops.setdefault(c["operation"], [0, 0])[0 if side == "positive" else 1] += 1
        for op, (p_, n_) in ops.items():
            lines.append("    %-16s +%-3d -%d" % (op, p_, n_))
        errs = {}
        for c in doc["negative"]:
            errs[c["error"]] = errs.get(c["error"], 0) + 1
        lines.append("    errors: " + ", ".join("%s=%d" % kv for kv in sorted(errs.items())))
    return "\n".join(lines)


# =============================================================================================
# Main
# =============================================================================================

def main(argv):
    args = list(argv)
    repo_root = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", ".."))
    out_dir = None
    mode = "write"
    while args:
        a = args.pop(0)
        if a == "--repo-root" and args:
            repo_root = os.path.abspath(args.pop(0))
        elif a == "--out-dir" and args:
            out_dir = os.path.abspath(args.pop(0))
        elif a == "--check":
            mode = "check"
        elif a == "--self-test":
            mode = "self-test"
        else:
            raise SystemExit("unknown argument: " + a)
    if out_dir is None:
        out_dir = os.path.join(repo_root, OUT_REL)

    setup_bases()
    pin_checks()
    for kind, builder in BUILDERS:
        _BASELINE_CASES[kind] = builder()
    texts = generate_all(repo_root, strict=True)
    again = generate_all(repo_root, strict=True)
    require(texts == again, "generation is not deterministic within one process")
    print(summarize(texts))

    if mode == "write":
        os.makedirs(out_dir, exist_ok=True)
        for pid, text in texts.items():
            with open(os.path.join(out_dir, pid + ".json"), "w", encoding="ascii", newline="\n") as fh:
                fh.write(text)
        print("wrote %d files to %s" % (len(texts), out_dir))
        return 0

    regression, total = check_regression(texts)
    for f in regression:
        print("check-regression FAILED: " + f)
    print("check-regression: %d tampered copies, %d judged correctly" % (total, total - len(regression)))
    if regression:
        return 1

    if mode == "check":
        bad = 0
        for pid, text in texts.items():
            path = os.path.join(out_dir, pid + ".json")
            try:
                with open(path, encoding="ascii") as fh:
                    disk_text = fh.read()
            except (OSError, UnicodeDecodeError) as exc:
                print("%s: DIFFERS: cannot read (%s)" % (path, exc))
                bad += 1
                continue
            diffs = compare_texts(disk_text, text)
            for d in diffs:
                print("%s: DIFFERS: %s" % (path, d))
            if not diffs:
                print("%s: byte-identical" % path)
            bad += 1 if diffs else 0
        return 1 if bad else 0

    # ---- self-test
    failed = 0
    rv = Reverifier()
    problems = []
    n_ident = identity_checks(rv, problems)
    print("reference identity checks (§2.3, §10.3): %d run" % n_ident)
    sources = [("generated", texts)]
    on_disk = {}
    for pid in texts:
        path = os.path.join(out_dir, pid + ".json")
        if os.path.isfile(path):
            with open(path, encoding="ascii") as fh:
                on_disk[pid] = fh.read()
    if on_disk:
        sources.append(("on-disk", on_disk))
    for label, docs in sources:
        for pid, text in docs.items():
            kind = "scalar" if pid == PROFILE_SCALAR else "bytes"
            doc = json.loads(text)
            p, counts = reverify_doc(kind, doc, rv)
            problems.extend("%s %s: %s" % (label, pid, x) for x in p)
            missing, ops = coverage_check(kind, doc)
            problems.extend("%s %s: missing required case %s" % (label, pid, x) for x in missing)
            print("reverify %-9s %s: %d cases re-run with the reference, %d homomorphism checks, "
                  "%d spec-table pins, %d mismatches, %d required cases missing; operations: %s"
                  % (label, pid, counts["cases"], counts["homomorphism"], counts["pins"], len(p),
                     len(missing), ", ".join(ops)))
    for p in problems[:50]:
        print("REVERIFY FAILED: " + p)
    failed += len(problems)

    results = mutation_test(repo_root, texts)
    survived = 0
    for name, desc, changed in results:
        status = "KILLED" if changed else "SURVIVED"
        survived += 0 if changed else 1
        detail = ", ".join("%s: %d case(s)" % kv for kv in sorted(changed.items()))
        print("mutation %-32s %-8s %s  [%s]" % (name, status, desc, detail))
    print("mutations: %d run, %d killed, %d survived" % (len(results), len(results) - survived, survived))
    failed += survived
    print("self-test: %s" % ("PASS" if not failed else "FAIL (%d problem(s))" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except PinError as exc:
        sys.stderr.write("FAILED: %s\n" % exc)
        sys.exit(1)
