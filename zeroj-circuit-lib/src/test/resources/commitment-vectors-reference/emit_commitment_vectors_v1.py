#!/usr/bin/env python3
"""Independent emitter of `zeroj-commitment-vectors-v1` files (commitment-profiles-v1.md §13).

Written from docs/specs/commitment-profiles-v1.md (r3; primary), pedersen-jubjub-v1.md,
pedersen-jubjub-vector-v1.md and pedersen-jubjub-bytes-v1.md, and the three existing
independent Python references, which are IMPORTED (never copied or modified) for:

  ../pedersen-reference/         Jubjub affine arithmetic, Poseidon, the derivation of G and H
  ../pedersen-vector-reference/  FindGroupHash^J and the bases G_0..G_15, H_V; schema encoding
  ../pedersen-bytes-reference/   HashBytesToScalar (RFC 9380 hash_to_field) and extended-
                                 coordinate arithmetic

Everything §2-§13 of commitment-profiles-v1.md adds is implemented HERE: identifiers, the
envelope (§9), the opening encodings (§8), scalar checks 1/2/3 (§7), the strict point decoder
classes (§10), the strict-path check orders (§12.3) and the §13.3 execution order. No ZeroJ
Java source, Java test or build output was read. See README.md.

Python 3 standard library only. Run in this directory:

    python3 -I -B emit_commitment_vectors_v1.py              # write the three JSON files
    python3 -I -B emit_commitment_vectors_v1.py --check      # compare with the files on disk
    python3 -I -B emit_commitment_vectors_v1.py --self-test  # mutation self-test (no writes)

Options: --repo-root DIR (default: five directories above this file), --out-dir DIR (default:
<repo-root>/zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1).
Exit status 0 on success; non-zero if a pinned value, an internal cross-check, a case's
intended outcome, --check or the self-test fails.
"""

import sys

sys.dont_write_bytecode = True  # never leave __pycache__ next to the imported references

import hashlib  # noqa: E402
import importlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import platform  # noqa: E402
import re  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT_REL = ("zeroj-circuit-lib/src/test/resources/commitment-vectors-reference/"
              "emit_commitment_vectors_v1.py")
OUT_REL = "zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1"


def _import_reference(dirname, module):
    path = os.path.normpath(os.path.join(HERE, "..", dirname))
    if not os.path.isfile(os.path.join(path, module + ".py")):
        raise SystemExit("missing imported reference: %s/%s.py" % (path, module))
    sys.path.insert(0, path)
    try:
        return importlib.import_module(module)
    finally:
        sys.path.remove(path)


# Import order matters only in that the bytes reference re-imports the scalar reference by
# the same module name, so all three share one `pedersen_jubjub_v1_reference` module object.
sref = _import_reference("pedersen-reference", "pedersen_jubjub_v1_reference")
vref = _import_reference("pedersen-vector-reference", "pedersen_jubjub_vector_v1_reference")
bref = _import_reference("pedersen-bytes-reference", "pedersen_jubjub_bytes_v1_reference")


# =============================================================================================
# Constants transcribed by hand from the specs (comparison targets and profile constants)
# =============================================================================================

# commitment-profiles-v1.md §1 / pedersen-jubjub-v1.md §1
P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
Q = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7  # q = l
D_EDW = 0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1
FLOOR_LOG2_Q = 251  # §7 check 2: k <= floor(log2 q); 2^251 < l < 2^252

# pedersen-jubjub-bytes-v1.md §2
MAX_PAYLOAD_BYTES = 2 ** 61 - 256
BYTES_DST = b"ZeroJ-pedersen-jubjub-bytes-v1-H2S-XMD:SHA-256"

# commitment-profiles-v1.md §2.3 and §9
PROFILE_SCALAR = "pedersen-jubjub-v1"
PROFILE_VECTOR = "pedersen-jubjub-vector-v1"
PROFILE_BYTES = "pedersen-jubjub-bytes-v1"
REGISTRY = ["pedersen-jubjub-basis-v1", "pedersen-jubjub-vector-basis-v1", PROFILE_SCALAR,
            PROFILE_VECTOR, PROFILE_BYTES, "pedersen-bls12-381-g1-v1",
            "pedersen-bls12-381-g1-bytes-v1"]
ENVELOPE_LENGTH = {PROFILE_SCALAR: 52, PROFILE_VECTOR: 59, PROFILE_BYTES: 58}
POINT_LENGTH = 32  # every Jubjub profile (§4.2)

PIN = {
    # commitment-profiles-v1 §3.1 / pedersen-jubjub-v1 §2
    "G": "cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7",
    "H": "7de3c894779099fe9b13d141c992003ba2fab89eeb4a190345e05917d897bb60",
    # pedersen-jubjub-v1 §2.2
    "poseidon_0_0": 0x57C7E6CEA4C40C3956E13AE6F8D644EDFF6F14577A581058EAA651B4675C7156,
    "poseidon_1_2": 0x28CE19420FC246A05553AD1E8C98F5C9D67166BE2C18E9E4CB4B4E317DD2A78A,
    "poseidon_123_456": 0x6EADB49364FF22D841D40765EF4AC418F19467E8511541850AEBF2936338A0FA,
    # pedersen-jubjub-v1 §8
    "C_42_12345": "57d3e074295e7feb8231baa675b3da817c6d45929590ce747b17b7e73bc387e3",
    "C_42_12345_u": 0x478A0BD6A0EEBDFFC610618AD979B39D6237F240125534886D38720CBD76A025,
    "C_42_12345_v": 0x6387C33BE7B7177B74CE909592456D7C81DAB375A6BA3182EB7F5E2974E0D357,
    # pedersen-jubjub-vector-v1 §3.1
    "V_1000_7_12345": "b8489c565ff87efb8cf50e92b6b0cadba7489efa17c55a6a5bcc81eb3a900643",
    "V_1000_12345": "258119dd13e51c79d80b108918c6bc3d2117b83eb0a9068e4ce8b158d7a1ffe7",
    # pedersen-jubjub-vector-v1 §4.3 (sigma of balance v1)
    "sigma_balance_v1": 0x26A0F201BD5AF51641A74A2B9193D2A361DFA1B629E358F99AE97FF72FE2870D,
    # pedersen-jubjub-bytes-v1 §10
    "s_empty": 0x061F05A7E9920513846BC5F0DD366C71A5ED2C35C6CDC88BA6F71D0F355F4181,
    "b0_empty": "d8a576b8db82c95dac7246e17f5cee19e4aa715e06e0c6a7f26b8c30aec62481",
    "uniform_empty": ("0806e94e86b0513631c07b6aba359c462afe5fae6338f2b8a9f8f9070c67b61f"
                      "c8b5cd7a9ee1f3d2739001762e0b7f17"),
    "s_00": 0x0DCA70C85AE4D9C8E22F6FF09A66FD81291C89763679C0C4ACC2957942B53294,
    "s_hello": 0x01021BCE20E1CA8D71CC9CE2BBE988EEE0335A559A8E7E65574E1049224D674F,
    "Cb_empty_0": "9f0d942a712d02e78959e4899908bfd3d8fff8f871f42ae4ace3d1f336e9789d",
    "Cb_empty_lm1": "0f2b6778c98d4623d8312c6d7cb02dc7892ce94927c04dd064adcfb7e7912489",
    "Cb_hello_lm1": "4e66485131af3603f96f18003966a30793f1c78492c27d644c1e12d0a941852d",
    # commitment-profiles-v1 §10
    "alias_identity": "0100000000000000000000000000000000000000000000000000000000000080",
    "alias_order2": "00000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7edf3",
    # commitment-profiles-v1 §13.3.1
    "identity": "0100000000000000000000000000000000000000000000000000000000000000",
}

# pedersen-jubjub-vector-v1 §2: encode(G_0) .. encode(G_15), encode(H_V)
PIN_VECTOR_BASES = [
    "6340819918a01a65b1a4fb95b81fe4fbac79194018db6fa68ca8bcb063988d99",
    "1cb3dc08c90d50710216ace4f69069e8fb4c28d3842d4157c7a669d900a8af18",
    "95341b6e25fc2733d722cdd530f0d8be5fec9bae3193aa91a56a18cfd26e710e",
    "b0669c801579c3a922eb966163fb0abf2a068269a4aeb7a9fe84faa70113d444",
    "72b2c76f6525aeeeaa73b041dcf02a74a598b3d1ebabe4b1797ceefa52967b3f",
    "2c3eeeed933bacc9be6ca7700de7327f46de2329596f1a3465ab6d3cb51a9013",
    "0f430b49a926fe8157ac99403c2e96a34851ffea6dbd1d7b6b3154ccae42a70d",
    "1a2486ee01ea106c68e2ec42c3d9247229221160d26e5063ec3e71f83c30dc25",
    "4346512ca3e3aeab29f37c0d3d1725c4f62aa9882ffc6b0a602d3f5bb505b4bf",
    "2d2bebf365558544cf047ae640d2f9510fbf14a365e695ee391a2cc7c7191994",
    "cb8eb59fe27a2b217dd2b8bc49a280ed9e9d67b74756a75a54dc4259a8793e45",
    "7198697f49f220e8b92375508642a9be3566131ef560ea24276e91300a85850d",
    "7bb76b2028cc93ec10a0eff8ea3fe054cf14ed801dc05ea801ede40cc96eb6e3",
    "76bc64ca01a712d7439d66fb6b26d3e95ad33b24aa11a3f3d38b70c4f2582460",
    "575d66801d5f01f2d39be971a8ea811383d8976c4a0033c1b579a3055dba4d18",
    "9f16abaeb98d298b4d226f2feea61db1a84ebc839045e0243ff00ce321116c1d",
    "751c48f5e1bcf364adf457db5066c93eb254dc3838421d57df418256233baebb",  # H_V
]


class PinError(Exception):
    pass


def require(cond, message):
    if not cond:
        raise PinError(message)


# =============================================================================================
# Error classes (§11) and the mutation switchboard used only by --self-test
# =============================================================================================

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


MUT = set()  # empty in normal operation; --self-test activates one mutation at a time


def mut(name):
    return name in MUT


# =============================================================================================
# Group arithmetic (imported: extended coordinates from the bytes reference)
# =============================================================================================

def to_ext(pt):
    return bref.to_ext(pt)


def mul(k, pt):
    if k < 0:
        raise ValueError("negative scalar passed to mul")
    return bref.to_affine(bref.ext_mul(k, to_ext(pt)))


def add(a, b):
    return bref.to_affine(bref.ext_add(to_ext(a), to_ext(b)))


def neg(pt):
    return ((-pt[0]) % P, pt[1])


def sub(a, b):
    return add(a, neg(b))


def enc(pt):
    return sref.encode(pt)


IDENTITY = (0, 1)
_SUBGROUP_CACHE = {}


def in_subgroup(pt):
    if pt not in _SUBGROUP_CACHE:
        _SUBGROUP_CACHE[pt] = bref.in_prime_subgroup(pt)
    return _SUBGROUP_CACHE[pt]


# =============================================================================================
# §10 strict point decoder (implemented here; uses only an imported square root)
# =============================================================================================

def strict_decode_point(data):
    """pedersen-jubjub-v1 §4 rules 1-5 in order -> MALFORMED_ENCODING; then the prime-order
    subgroup check -> NOT_IN_SUBGROUP. Never cofactor-clears; the identity is accepted."""
    if len(data) != POINT_LENGTH:                                   # rule 1
        raise Fail(MAL)
    sign = data[31] >> 7
    v = int.from_bytes(data, "little") & ((1 << 255) - 1)
    if v >= P:                                                      # rule 2
        if not mut("decoder_reduces_v"):
            raise Fail(MAL)
        v %= P
    vv = v * v % P
    den = (D_EDW * vv + 1) % P
    if den == 0:                                                    # rule 3
        raise Fail(MAL)
    w = (vv - 1) * pow(den, P - 2, P) % P
    u = sref.sqrt_mod(w)
    if u is None:                                                   # rule 4
        raise Fail(MAL)
    if u == 0 and sign == 1 and not mut("decoder_accepts_sign_alias"):  # rule 5
        raise Fail(MAL)
    if (u & 1) != sign:
        u = (P - u) % P
    pt = (u, v)
    if not mut("decoder_skips_subgroup") and not in_subgroup(pt):
        if mut("decoder_cofactor_clears"):
            return mul(8, pt)
        raise Fail(NIS)
    return pt


# =============================================================================================
# §2.1 identifiers
# =============================================================================================

_ID_RE = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*-v[1-9][0-9]*")


def valid_identifier(s):
    raw = s.encode("ascii") if isinstance(s, str) else s
    if not 4 <= len(raw) <= 64:
        return False
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    return _ID_RE.fullmatch(text) is not None


# =============================================================================================
# §7 scalar checks
# =============================================================================================

def check1(x):
    """Canonical residue: x in [0, q), never reduced."""
    if mut("check1_accepts_q"):
        ok = 0 <= x <= Q
    elif mut("check1_reduces_negative"):
        ok = x < Q  # a negative x would then be reduced by the caller
    else:
        ok = 0 <= x < Q
    if not ok:
        raise Fail(NCS)
    return x % Q


def check1_decoded(x):
    """Check 1 on a scalar read from 32 octets (always >= 0) by an opening decoder."""
    if x >= Q and not (mut("check1_accepts_q") and x == Q):
        raise Fail(NCS)
    return x


def amount_bits_valid(k):
    hi = 252 if mut("amount_bits_allows_252") else FLOOR_LOG2_Q
    return 1 <= k <= hi


def ceil_log2(n):
    if mut("widened_floor_log2"):
        return n.bit_length() - 1
    return (n - 1).bit_length()


class Schema:
    """pedersen-jubjub-vector-v1 §4; validated with the imported schema encoder."""

    def __init__(self, sid, version, entries):
        self.sid = sid
        self.version = version
        self.entries = list(entries)  # [(label, width)]
        self.encoding = vref.schema_encode(sid.encode("ascii"), version,
                                           [(lb.encode("ascii"), k) for lb, k in entries])

    @property
    def n(self):
        return len(self.entries)

    def widths(self):
        return [k for _, k in self.entries]

    def to_json(self):
        return {"id": self.sid, "version": str(self.version),
                "entries": [{"label": lb, "width": str(k)} for lb, k in self.entries]}


def schema_from_json(obj):
    return Schema(obj["id"], int(obj["version"]),
                  [(e["label"], int(e["width"])) for e in obj["entries"]])


class Policy:
    """§7 check 3: exactly one configured policy bound to one schema."""

    def __init__(self, kind, schema, added_terms=None):
        self.kind = kind
        self.schema = schema
        self.added_terms = added_terms
        if kind == "widened":
            n = added_terms
            lo = 1 if mut("widened_allows_one") else 2
            hi_ok = mut("widened_no_upper_limit") or n <= 65536
            if not (lo <= n and hi_ok):
                raise Fail(INV)
            c = ceil_log2(n)
            widths = schema.widths()[:1] if mut("widened_first_entry_only") else schema.widths()
            for k in widths:
                if 2 ** (k + c) > Q:
                    raise Fail(INV)
            self.extra = c
        elif kind not in ("schema-widths", "residue-only"):
            raise Fail(INV)

    def bound(self, i):
        k = self.schema.widths()[i]
        if self.kind == "schema-widths":
            if mut("schema_widths_off_by_one"):
                return min(2 ** k + 1, Q)
            return min(2 ** k, Q)
        if self.kind == "residue-only":
            return Q
        return 2 ** (k + self.extra)

    def check3(self, values):
        for i, v in enumerate(values):
            if v >= self.bound(i):
                raise Fail(OOR)


def policy_from_json(obj, schema):
    kind = obj["kind"]
    added = int(obj["addedTerms"]) if kind == "widened" else None
    return Policy(kind, schema, added)


# =============================================================================================
# §8 opening encodings
# =============================================================================================

def i2osp32(x):
    if mut("opening_little_endian"):
        return x.to_bytes(32, "little")
    return x.to_bytes(32, "big")


def os2ip32(b):
    if mut("opening_little_endian"):
        return int.from_bytes(b, "little")
    return int.from_bytes(b, "big")


def scalar_opening_encode(value, blinding):          # §12.3 PedersenScalarOpening.of
    value = check1(value)
    blinding = check1(blinding)
    return i2osp32(value) + i2osp32(blinding)


def scalar_opening_decode(data):                      # §8.1
    if len(data) != 64:
        raise Fail(MAL)
    m, r = os2ip32(data[:32]), os2ip32(data[32:])
    check1_decoded(m)
    check1_decoded(r)
    return m, r


def blinding_encode(r):                               # §8.2 PedersenBlinding.encode
    r = check1(r)
    return i2osp32(r)


def blinding_decode(data):                            # §8.2
    if len(data) != 32:
        raise Fail(MAL)
    return check1_decoded(os2ip32(data))


def vector_values_checks(policy, values, blinding):
    """§12.3 order shared by verifyOpening (after the schema comparison) and Opening.of:
    dimension -> each v_i check 1 -> blinding check 1 -> each v_i check 3."""
    if len(values) != policy.schema.n:
        raise Fail(MAL)
    if mut("vector_check3_before_check1"):
        policy.check3(values)
    values = [check1(v) for v in values]
    blinding = check1(blinding)
    policy.check3(values)
    return values, blinding


def vector_opening_encode(policy, values, blinding):  # §8.3 via PedersenVectorOpening.of
    values, blinding = vector_values_checks(policy, values, blinding)
    out = bytes([len(values)])
    for v in values:
        out += i2osp32(v)
    return out + i2osp32(blinding)


def vector_opening_decode(data, policy):              # §8.3 decoding order
    n = policy.schema.n
    if len(data) < 1:
        raise Fail(MAL)
    if mut("vector_decode_skips_n_check"):
        if len(data) != 33 + 32 * n:
            raise Fail(MAL)
    else:
        if data[0] != n or len(data) != 33 + 32 * data[0]:
            raise Fail(MAL)
    values = [os2ip32(data[1 + 32 * i:33 + 32 * i]) for i in range(n)]
    r = os2ip32(data[1 + 32 * n:33 + 32 * n])
    if mut("vector_check3_before_check1"):
        policy.check3(values)
    for v in values:
        check1_decoded(v)
    check1_decoded(r)
    policy.check3(values)
    return values, r


# =============================================================================================
# §9 envelope v1
# =============================================================================================

def envelope_encode(profile_id, point_bytes):
    raw = profile_id.encode("ascii")
    return bytes([0x01, len(raw)]) + raw + point_bytes


def envelope_decode(data, expected_id):
    """Steps 1-5 of §9 in order. Step 6 (concrete class / descriptor) cannot fail for a codec
    that only builds its own type, so files have no step-6 case."""
    exp = expected_id.encode("ascii")
    if len(data) < 2 or (data[0] != 0x01 and not mut("envelope_any_version")):   # step 1
        raise Fail(MAL)
    idlen = data[1]
    if 2 + idlen > len(data):                                                   # step 2
        raise Fail(MAL)
    rest = data[2 + idlen:]
    if mut("envelope_length_before_id") and len(rest) != POINT_LENGTH:
        raise Fail(MAL)
    if data[2:2 + idlen] != exp and not mut("envelope_no_id_compare"):          # step 3
        raise Fail(PMM)
    if len(rest) != POINT_LENGTH:                                               # step 4
        raise Fail(MAL)
    return strict_decode_point(rest)                                            # step 5


# =============================================================================================
# Bases and commitments
# =============================================================================================

class Bases:
    pass


B = Bases()


def setup_bases():
    # pedersen-jubjub-v1 §2.1: G = [8]·G_full (imported affine arithmetic)
    B.G = sref.scalar_mul(8, sref.G_FULL)
    require(enc(B.G).hex() == PIN["G"], "encode(G) differs from the pinned value")
    # §2.2 Poseidon known answers, then §2.3 H (imported derivation)
    constants, mds = sref.poseidon_parameters()
    require(sref.poseidon2(0, 0, constants, mds) == PIN["poseidon_0_0"], "Poseidon(0,0)")
    require(sref.poseidon2(1, 2, constants, mds) == PIN["poseidon_1_2"], "Poseidon(1,2)")
    require(sref.poseidon2(123, 456, constants, mds) == PIN["poseidon_123_456"],
            "Poseidon(123,456)")
    _a, counter, _pre, h_point, _trace = sref.derive_h(constants, mds)
    B.H = h_point
    require(counter == 1, "H counter is not 1")
    require(enc(B.H).hex() == PIN["H"], "encode(H) differs from the pinned value")
    # pedersen-jubjub-vector-v1 §2 (imported FindGroupHash^J)
    gs, hv = vref.derive_bases()
    B.GS = [pt for pt, _ in gs]
    B.HV = hv[0]
    got = [enc(pt).hex() for pt in B.GS + [B.HV]]
    require(got == PIN_VECTOR_BASES, "vector bases differ from the pinned table")
    for pt in [B.G, B.H] + B.GS + [B.HV]:
        require(in_subgroup(pt) and pt != IDENTITY, "a base is not a subgroup non-identity point")


def commit_scalar_raw(m, r):
    return add(mul(m, B.G), mul(r, B.H))


def commit_vector_raw(values, r):
    acc = IDENTITY
    for i, v in enumerate(values):
        base = B.GS[i % 2] if mut("vector_wrong_base_high_index") else B.GS[i]
        acc = add(acc, mul(v, base))
    return add(acc, mul(r, B.HV))


def h2s_octet_form(payload, length_prefix=False):
    """pedersen-jubjub-bytes-v1 §3.1 'octet by octet', written here (cross-check / mutation)."""
    n = len(payload)
    tail = BYTES_DST + bytes([len(BYTES_DST)])
    framed = (n.to_bytes(8, "big") + payload) if length_prefix else (payload + n.to_bytes(8, "big"))
    b0 = hashlib.sha256(bytes(64) + framed + b"\x00\x30" + b"\x00" + tail).digest()
    b1 = hashlib.sha256(b0 + b"\x01" + tail).digest()
    b2 = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, b1)) + b"\x02" + tail).digest()
    uniform = b1 + b2[:16]
    return {"b0": b0, "b1": b1, "b2": b2, "u": uniform,
            "s": int.from_bytes(uniform, "big") % Q}


def hash_to_scalar(payload):
    if mut("hash_length_prefix"):
        return h2s_octet_form(payload, length_prefix=True)
    return bref.hash_bytes_to_scalar(payload)  # imported RFC 9380 hash_to_field


# =============================================================================================
# JSON value helpers (§13.2)
# =============================================================================================

def dec(x):
    return str(x)


def hx(b):
    return b.hex()


def coord_hex(x):
    return x.to_bytes(32, "big").hex()


def payload_bytes(obj):
    if "hex" in obj:
        return bytes.fromhex(obj["hex"])
    require(obj.get("pattern") == "131i+17", "unknown payload pattern")
    n = int(obj["length"])
    return bytes((131 * i + 17) % 256 for i in range(n))


def pattern_payload(n):
    return {"pattern": "131i+17", "length": dec(n)}


def hex_payload(b):
    return {"hex": hx(b)}


# =============================================================================================
# Case execution: §13.3 table and execution order
#   1 configuration (schema, policySchema, policy, amountBits read, codec)
#   2 points (pointHex, pointsHex in index order; envelopeHex under §9)
#   3 the operation's own order (§8 / §12.3)
#   4 the equation or arithmetic
# =============================================================================================

def ints(lst):
    return [int(x) for x in lst]


def run_case(kind, op, inp):
    """Returns the `expected` object, or raises Fail(error class)."""
    # ---- step 1: configuration -------------------------------------------------------------
    schema = schema_from_json(inp["schema"]) if "schema" in inp else None
    policy_schema = schema_from_json(inp["policySchema"]) if "policySchema" in inp else None
    policy = None
    if "policy" in inp:
        policy = policy_from_json(inp["policy"], policy_schema or schema)
    amount_bits = int(inp["amountBits"]) if "amountBits" in inp else None
    if mut("amount_bits_check_before_point") and amount_bits is not None:
        if not amount_bits_valid(amount_bits):
            raise Fail(INV)
    if kind == "vector" and op not in ("configurePolicy",):
        require(schema is not None, "vector case without schema")

    # ---- operations ------------------------------------------------------------------------
    if op == "configurePolicy":
        return {"result": "ok"}

    if op == "decodePoint":
        pt = strict_decode_point(bytes.fromhex(inp["pointHex"]))
        return {"uHex": coord_hex(pt[0]), "vHex": coord_hex(pt[1])}

    if op == "commitLegacy":                       # scalar legacy commit: any integers, reduced
        m, r = int(inp["value"]), int(inp["blinding"])
        return {"pointHex": hx(enc(commit_scalar_raw(m % Q, r % Q)))}

    if op == "commit" and kind == "scalar":        # strict commitScalar
        m, r = int(inp["value"]), int(inp["blinding"])
        m = check1(m)
        r = check1(r)
        return {"pointHex": hx(enc(commit_scalar_raw(m, r)))}

    if op == "commit" and kind == "vector":        # legacy commit, canonical inputs only
        values, r = ints(inp["values"]), int(inp["blinding"])
        require(len(values) == schema.n, "fixture: legacy vector commit dimension")
        for v, k in zip(values, schema.widths()):
            require(0 <= v < 2 ** k and v < Q, "fixture: legacy vector commit width")
        require(0 <= r < Q, "fixture: legacy vector commit blinding")
        return {"pointHex": hx(enc(commit_vector_raw(values, r)))}

    if op == "commit" and kind == "bytes":
        payload = payload_bytes(inp["payload"])
        r = int(inp["blinding"])
        declared = int(inp["declaredLength"]) if "declaredLength" in inp else None
        max_bytes = int(inp["maxBytes"]) if "maxBytes" in inp else None

        def length_check():
            for lim in (declared, max_bytes):
                if lim is not None and not 0 <= lim <= MAX_PAYLOAD_BYTES:
                    raise Fail(LOR)

        r = check1(r)
        length_check()
        if declared is not None:
            require(declared == len(payload), "fixture: declaredLength != payload length")
        if max_bytes is not None:
            require(max_bytes >= len(payload), "fixture: maxBytes < payload length")
        s = hash_to_scalar(payload)["s"]
        return {"pointHex": hx(enc(commit_scalar_raw(s, r)))}

    if op == "hashToScalar":
        h = hash_to_scalar(payload_bytes(inp["payload"]))
        return {"b0Hex": hx(h["b0"]), "b1Hex": hx(h["b1"]), "b2Hex": hx(h["b2"]),
                "uniformBytesHex": hx(h["u"]), "scalar": dec(h["s"])}

    if op == "verifyOpening":
        point = strict_decode_point(bytes.fromhex(inp["pointHex"]))      # step 2
        if kind == "scalar":
            if amount_bits is not None and not amount_bits_valid(amount_bits):
                raise Fail(INV)
            m = check1(int(inp["value"]))
            r = check1(int(inp["blinding"]))
            if amount_bits is not None and m >= 2 ** amount_bits:
                raise Fail(OOR)
            ok = enc(commit_scalar_raw(m, r)) == enc(point)
        elif kind == "bytes":
            if mut("bytes_equation_before_blinding"):
                s = hash_to_scalar(payload_bytes(inp["payload"]))["s"]
                if enc(commit_scalar_raw(s, int(inp["blinding"]) % Q)) != enc(point):
                    raise Fail(OMM)
            r = check1(int(inp["blinding"]))
            s = hash_to_scalar(payload_bytes(inp["payload"]))["s"]
            ok = enc(commit_scalar_raw(s, r)) == enc(point)
        else:
            values, r = ints(inp["values"]), int(inp["blinding"])
            same = policy.schema.encoding == schema.encoding
            if mut("vector_schema_compare_after_dimension"):
                if len(values) != policy.schema.n:
                    raise Fail(MAL)
            if not same and not mut("vector_no_schema_compare"):
                raise Fail(PMM)
            values, r = vector_values_checks(policy, values, r)
            ok = enc(commit_vector_raw(values, r)) == enc(point)
        if not ok:
            raise Fail(OMM)
        return {"result": "true"}

    if op == "encodeOpening":
        if kind == "scalar":
            data = scalar_opening_encode(int(inp["value"]), int(inp["blinding"]))
        elif kind == "bytes":
            data = blinding_encode(int(inp["blinding"]))
        else:
            data = vector_opening_encode(policy, ints(inp["values"]), int(inp["blinding"]))
        return {"openingHex": hx(data)}

    if op == "decodeOpening":
        data = bytes.fromhex(inp["openingHex"])
        if kind == "scalar":
            m, r = scalar_opening_decode(data)
            return {"value": dec(m), "blinding": dec(r)}
        if kind == "bytes":
            return {"blinding": dec(blinding_decode(data))}
        values, r = vector_opening_decode(data, policy)
        out = {"schema": inp["schema"], "policy": inp["policy"],
               "values": [dec(v) for v in values], "blinding": dec(r)}
        return out

    if op == "encodeEnvelope":
        pt = strict_decode_point(bytes.fromhex(inp["pointHex"]))  # build the typed commitment
        return {"envelopeHex": hx(envelope_encode(PROFILE_OF[kind], enc(pt)))}

    if op == "decodeEnvelope":
        expected = inp["expectedProfileId"]
        require(valid_identifier(expected), "fixture: expectedProfileId is not an identifier")
        pt = envelope_decode(bytes.fromhex(inp["envelopeHex"]), expected)
        return {"pointHex": hx(enc(pt))}

    if op == "relation":
        pts = [strict_decode_point(bytes.fromhex(h)) for h in inp["pointsHex"]]
        o = inp["op"]
        if o == "negate":
            require(kind == "scalar" and len(pts) == 1, "fixture: negate cardinality/kind")
            res = neg(pts[0])
        else:
            require(len(pts) == 2, "fixture: add/subtract cardinality")
            if o == "add":
                res = add(pts[0], pts[1])
            elif o == "subtract":
                res = sub(pts[1], pts[0]) if mut("subtract_reversed") else sub(pts[0], pts[1])
            else:
                raise PinError("fixture: unknown relation op")
        return {"pointHex": hx(enc(res))}

    raise PinError("unknown operation %s/%s" % (kind, op))


PROFILE_OF = {"scalar": PROFILE_SCALAR, "vector": PROFILE_VECTOR, "bytes": PROFILE_BYTES}


# =============================================================================================
# Fixture points
# =============================================================================================

class Fx:
    pass


F = Fx()


def setup_fixtures():
    F.identity = IDENTITY
    require(enc(IDENTITY).hex() == PIN["identity"], "identity encoding")
    F.T2 = (0, P - 1)
    # order 4: v = 0, u^2 = -1 ; take the even root (sign bit 0)
    i = sref.sqrt_mod(P - 1)
    F.T4 = (i if i % 2 == 0 else P - i, 0)
    # order 8: [l]·X for the first X = decode(v, sign 0), v = 2, 3, ... with torsion order 8
    v = 2
    while True:
        try:
            x = strict_decode_point_nosub(v)
        except Fail:
            v += 1
            continue
        t = mul(Q, x)
        if bref.small_order(t) == 8:
            F.T8 = t
            break
        v += 1
    # off-curve: the first v >= 2 whose (v^2-1)/(d v^2+1) is a non-square
    v = 2
    while True:
        w = (v * v - 1) * pow((D_EDW * v * v + 1) % P, P - 2, P) % P
        if sref.sqrt_mod(w) is None:
            F.off_curve = v.to_bytes(32, "little")
            break
        v += 1
    for pt, order in ((F.T2, 2), (F.T4, 4), (F.T8, 8)):
        require(sref.on_curve(pt) and bref.small_order(pt) == order, "torsion order %d" % order)
    F.alias_identity = bytes.fromhex(PIN["alias_identity"])
    F.alias_order2 = bytes(bytearray(enc(F.T2)[:31]) + bytes([enc(F.T2)[31] | 0x80]))
    require(F.alias_order2.hex() == PIN["alias_order2"], "order-2 alias differs from §10")
    F.v_eq_p = P.to_bytes(32, "little")
    F.v_eq_p1 = (P + 1).to_bytes(32, "little")
    F.v_max = ((1 << 255) - 1).to_bytes(32, "little")


def strict_decode_point_nosub(v):
    """Curve decoding of (v, sign 0) without the subgroup check (fixture search only)."""
    vv = v * v % P
    w = (vv - 1) * pow((D_EDW * vv + 1) % P, P - 2, P) % P
    u = sref.sqrt_mod(w)
    if u is None:
        raise Fail(MAL)
    if u & 1:
        u = P - u
    return (u, v)


def point_negative_fixtures(commitment_pt):
    """(name suffix, octets, intended class): §13.4 point negatives."""
    ident = enc(IDENTITY)
    mixed8 = add(commitment_pt, F.T8)
    mixed2 = add(commitment_pt, F.T2)
    require(not in_subgroup(mixed8) and bref.small_order(mixed8) is None, "mixed-order point")
    return [
        ("length-0", b"", MAL),
        ("length-31", ident[:31], MAL),
        ("length-33", ident + b"\x00", MAL),
        ("v-equals-p", F.v_eq_p, MAL),
        ("v-equals-p-plus-1", F.v_eq_p1, MAL),
        ("v-max-255-bit", F.v_max, MAL),
        ("sign-alias-identity", F.alias_identity, MAL),
        ("sign-alias-order-2", F.alias_order2, MAL),
        ("off-curve", F.off_curve, MAL),
        ("order-2", enc(F.T2), NIS),
        ("order-4", enc(F.T4), NIS),
        ("order-8", enc(F.T8), NIS),
        ("mixed-order-8", enc(mixed8), NIS),
        ("mixed-order-2", enc(mixed2), NIS),
    ]


# =============================================================================================
# Case builders
# =============================================================================================

class CaseList:
    def __init__(self, kind):
        self.kind = kind
        self.cases = []  # (name, op, input, intent)
        self.names = set()

    def add(self, name, op, inp, intent="ok"):
        require(name not in self.names, "duplicate case name " + name)
        self.names.add(name)
        self.cases.append((name, op, inp, intent))

    def expected_of(self, op, inp):
        """Run a positive helper case and return its expected object (used to chain points)."""
        return run_case(self.kind, op, inp)


def envelope_negatives(cl, profile, good_point_hex, schema_json=None):
    pid = profile.encode("ascii")
    good = bytes.fromhex(good_point_hex)
    env = envelope_encode(profile, good)
    require(len(env) == ENVELOPE_LENGTH[profile], "envelope length for " + profile)

    def case(name, data, intent):
        inp = {"envelopeHex": hx(data), "expectedProfileId": profile}
        if schema_json is not None:
            inp["schema"] = schema_json
        cl.add("envelope-decode-" + name, "decodeEnvelope", inp, intent)

    case("empty", b"", MAL)
    case("version-only", b"\x01", MAL)
    case("version-0x00", b"\x00" + env[1:], MAL)
    case("version-0x02", b"\x02" + env[1:], MAL)
    case("truncated-in-identifier", env[:10], MAL)
    case("truncated-by-one", env[:-1], MAL)
    case("trailing-octet", env + b"\x00", MAL)
    case("point-mismatch-31-octets", env[:2 + len(pid)] + good[:31], MAL)
    case("point-mismatch-33-octets", env[:2 + len(pid)] + good + b"\x00", MAL)
    case("point-mismatch-no-point", env[:2 + len(pid)], MAL)
    case("id-length-exceeds-envelope", bytes([0x01, len(env)]) + env[2:], MAL)
    others = [x for x in (PROFILE_SCALAR, PROFILE_VECTOR, PROFILE_BYTES) if x != profile]
    for other in others:
        case("other-profile-" + other, envelope_encode(other, good), PMM)
    case("reserved-profile-pedersen-bls12-381-g1-v1",
         envelope_encode("pedersen-bls12-381-g1-v1", good), PMM)
    one_off = profile[:-1] + "2"
    case("id-differs-in-one-octet", envelope_encode(one_off, good), PMM)
    case("id-uppercase-first-octet", envelope_encode(profile[0].upper() + profile[1:], good), PMM)
    case("id-length-octet-minus-one", bytes([0x01, len(pid) - 1]) + pid + good, PMM)
    case("id-length-octet-plus-one", bytes([0x01, len(pid) + 1]) + pid + good, PMM)
    case("id-empty", bytes([0x01, 0x00]) + good, PMM)
    # multi-defect order cases (§13.3)
    case("order-version-before-identifier", b"\x02" + envelope_encode(one_off, good)[1:], MAL)
    case("order-identifier-before-point-length", envelope_encode(one_off, good[:31]), PMM)
    case("order-identifier-before-point", envelope_encode(others[0], F.off_curve), PMM)


def point_negative_cases(cl, commitment_pt, schema_json=None):
    profile = PROFILE_OF[cl.kind]
    for suffix, data, intent in point_negative_fixtures(commitment_pt):
        inp = {"pointHex": hx(data)}
        if schema_json is not None:
            inp["schema"] = schema_json
        cl.add("decode-point-" + suffix, "decodePoint", inp, intent)
        env_inp = {"envelopeHex": hx(envelope_encode(profile, data)),
                   "expectedProfileId": profile}
        if schema_json is not None:
            env_inp["schema"] = schema_json
        cl.add("envelope-decode-point-" + suffix, "decodeEnvelope", env_inp, intent)


def decode_point_positive(cl, name, pt, schema_json=None):
    inp = {"pointHex": hx(enc(pt))}
    if schema_json is not None:
        inp["schema"] = schema_json
    cl.add("decode-point-" + name, "decodePoint", inp)


def envelope_round_trip(cl, name, pt, schema_json=None, decode_schema_json=None):
    profile = PROFILE_OF[cl.kind]
    inp = {"pointHex": hx(enc(pt))}
    if schema_json is not None:
        inp["schema"] = schema_json
    cl.add("envelope-encode-" + name, "encodeEnvelope", inp)
    env = cl.expected_of("encodeEnvelope", inp)["envelopeHex"]
    dinp = {"envelopeHex": env, "expectedProfileId": profile}
    if schema_json is not None:
        dinp["schema"] = schema_json
    cl.add("envelope-decode-" + name, "decodeEnvelope", dinp)
    if decode_schema_json is not None:
        d2 = {"envelopeHex": env, "expectedProfileId": profile, "schema": decode_schema_json}
        cl.add("envelope-decode-" + name + "-under-other-schema", "decodeEnvelope", d2)


BAD_SCALARS = [("q", Q), ("q-plus-1", Q + 1), ("minus-1", -1)]


# ---------------------------------------------------------------------------------------------
# pedersen-jubjub-v1 (scalar)
# ---------------------------------------------------------------------------------------------

def build_scalar():
    cl = CaseList("scalar")
    c42 = commit_scalar_raw(42, 12345)
    require(enc(c42).hex() == PIN["C_42_12345"], "C(42,12345) pinned encoding")
    require(c42 == (PIN["C_42_12345_u"], PIN["C_42_12345_v"]), "C(42,12345) pinned coordinates")
    c_max = commit_scalar_raw(Q - 1, Q - 1)

    # decodePoint positives
    decode_point_positive(cl, "identity", IDENTITY)
    decode_point_positive(cl, "base-g", B.G)
    decode_point_positive(cl, "base-h", B.H)
    decode_point_positive(cl, "commitment-42-12345", c42)
    decode_point_positive(cl, "commitment-qm1-qm1", c_max)

    # strict commit
    for name, m, r in (("zero-zero", 0, 0), ("42-12345", 42, 12345), ("qm1-qm1", Q - 1, Q - 1),
                       ("zero-qm1", 0, Q - 1), ("qm1-zero", Q - 1, 0), ("one-zero", 1, 0),
                       ("zero-one", 0, 1), ("2pow64-12345", 2 ** 64, 12345),
                       ("2pow64m1-12345", 2 ** 64 - 1, 12345),
                       ("2pow251-12345", 2 ** 251, 12345),
                       ("2pow251m1-12345", 2 ** 251 - 1, 12345)):
        cl.add("commit-" + name, "commit", {"value": dec(m), "blinding": dec(r)})
    # commitLegacy: reduces mod q (value = q equals value = 0, etc.)
    for name, m, r in (("value-q", Q, 12345), ("value-zero", 0, 12345),
                       ("value-minus-1", -1, 12345), ("value-qm1", Q - 1, 12345),
                       ("value-q-plus-42", Q + 42, 12345), ("value-42", 42, 12345),
                       ("blinding-minus-1", 42, -1), ("blinding-qm1", 42, Q - 1),
                       ("both-q", Q, Q), ("value-minus-q", -Q, 0)):
        cl.add("commit-legacy-" + name, "commitLegacy", {"value": dec(m), "blinding": dec(r)})
    require(run_case("scalar", "commitLegacy", {"value": dec(Q), "blinding": "12345"}) ==
            run_case("scalar", "commitLegacy", {"value": "0", "blinding": "12345"}),
            "commitLegacy q != 0")

    # verifyOpening positives
    def vo(name, pt, m, r, bits=None, intent="ok"):
        inp = {"pointHex": hx(pt if isinstance(pt, bytes) else enc(pt)), "value": dec(m),
               "blinding": dec(r)}
        if bits is not None:
            inp["amountBits"] = dec(bits)
        cl.add("verify-" + name, "verifyOpening", inp, intent)

    vo("identity-zero", IDENTITY, 0, 0)
    vo("42-12345", c42, 42, 12345)
    vo("qm1-qm1", c_max, Q - 1, Q - 1)
    vo("zero-qm1", commit_scalar_raw(0, Q - 1), 0, Q - 1)
    vo("qm1-zero", commit_scalar_raw(Q - 1, 0), Q - 1, 0)
    for k in (1, 64, 251):
        vo("amount-bits-%d-max" % k, commit_scalar_raw(2 ** k - 1, 12345), 2 ** k - 1, 12345, k)
        vo("amount-bits-%d-overflow" % k, commit_scalar_raw(2 ** k, 12345), 2 ** k, 12345, k, OOR)
    vo("amount-bits-64-zero", commit_scalar_raw(0, 12345), 0, 12345, 64)
    vo("amount-bits-0", c42, 42, 12345, 0, INV)
    vo("amount-bits-252", c42, 42, 12345, 252, INV)
    vo("amount-bits-minus-1", c42, 42, 12345, -1, INV)
    # OPENING_MISMATCH
    vo("wrong-value", c42, 43, 12345, None, OMM)
    vo("wrong-blinding", c42, 42, 12346, None, OMM)
    vo("swapped-value-blinding", c42, 12345, 42, None, OMM)
    vo("value-42-plus-q-not-reduced", c42, 42 + Q, 12345, None, NCS)
    vo("amount-bits-64-wrong-value", c42, 43, 12345, 64, OMM)

    # scalar negatives on the strict operations
    for sname, bad in BAD_SCALARS:
        cl.add("commit-value-" + sname, "commit", {"value": dec(bad), "blinding": "12345"}, NCS)
        cl.add("commit-blinding-" + sname, "commit", {"value": "42", "blinding": dec(bad)}, NCS)
        vo("value-" + sname, c42, bad, 12345, None, NCS)
        vo("blinding-" + sname, c42, 42, bad, None, NCS)
        cl.add("encode-opening-value-" + sname, "encodeOpening",
               {"value": dec(bad), "blinding": "12345"}, NCS)
        cl.add("encode-opening-blinding-" + sname, "encodeOpening",
               {"value": "42", "blinding": dec(bad)}, NCS)
    for sname, bad in BAD_SCALARS[:2]:
        cl.add("decode-opening-value-" + sname, "decodeOpening",
               {"openingHex": hx(bad.to_bytes(32, "big") + (12345).to_bytes(32, "big"))}, NCS)
        cl.add("decode-opening-blinding-" + sname, "decodeOpening",
               {"openingHex": hx((42).to_bytes(32, "big") + bad.to_bytes(32, "big"))}, NCS)
    cl.add("decode-opening-value-all-ones", "decodeOpening",
           {"openingHex": "ff" * 32 + (12345).to_bytes(32, "big").hex()}, NCS)

    # opening round trips and wrong lengths
    for name, m, r in (("zero-zero", 0, 0), ("42-12345", 42, 12345), ("qm1-qm1", Q - 1, Q - 1),
                       ("1-2", 1, 2)):
        inp = {"value": dec(m), "blinding": dec(r)}
        cl.add("encode-opening-" + name, "encodeOpening", inp)
        oh = cl.expected_of("encodeOpening", inp)["openingHex"]
        cl.add("decode-opening-" + name, "decodeOpening", {"openingHex": oh})
    good_opening = (42).to_bytes(32, "big") + (12345).to_bytes(32, "big")
    for n in (0, 32, 63, 65, 96):
        data = (good_opening + b"\x00" * 32)[:n]
        cl.add("decode-opening-length-%d" % n, "decodeOpening", {"openingHex": hx(data)}, MAL)
    cl.add("decode-opening-length-63-order-before-scalars", "decodeOpening",
           {"openingHex": hx(Q.to_bytes(32, "big") + Q.to_bytes(32, "big")[:31])}, MAL)

    # envelope round trips and negatives
    envelope_round_trip(cl, "identity", IDENTITY)
    envelope_round_trip(cl, "commitment-42-12345", c42)
    envelope_round_trip(cl, "base-g", B.G)
    envelope_negatives(cl, PROFILE_SCALAR, hx(enc(c42)))
    cl.add("envelope-encode-order-8", "encodeEnvelope", {"pointHex": hx(enc(F.T8))}, NIS)
    cl.add("envelope-encode-off-curve", "encodeEnvelope", {"pointHex": hx(F.off_curve)}, MAL)

    # relation (V3): pedersen-jubjub-v1 §7 example C(l-1,17) + C(1,23) = C(0,40)
    a = commit_scalar_raw(Q - 1, 17)
    b = commit_scalar_raw(1, 23)
    cl.add("relation-add-wraparound", "relation",
           {"op": "add", "pointsHex": [hx(enc(a)), hx(enc(b))]})
    require(enc(add(a, b)) == enc(commit_scalar_raw(0, 40)), "§7 wraparound example")
    cl.add("relation-subtract", "relation",
           {"op": "subtract", "pointsHex": [hx(enc(commit_scalar_raw(0, 40))), hx(enc(b))]})
    cl.add("relation-subtract-to-negative", "relation",
           {"op": "subtract", "pointsHex": [hx(enc(IDENTITY)), hx(enc(c42))]})
    require(enc(sub(IDENTITY, c42)) == enc(commit_scalar_raw(Q - 42, Q - 12345)), "negation")
    cl.add("relation-negate", "relation", {"op": "negate", "pointsHex": [hx(enc(c42))]})
    cl.add("relation-negate-identity", "relation", {"op": "negate", "pointsHex": [hx(enc(IDENTITY))]})
    cl.add("relation-add-identity", "relation",
           {"op": "add", "pointsHex": [hx(enc(c42)), hx(enc(IDENTITY))]})
    vo("relation-result-qm42", commit_scalar_raw(Q - 42, Q - 12345), Q - 42, Q - 12345)
    # relation negatives
    cl.add("relation-add-second-order-8", "relation",
           {"op": "add", "pointsHex": [hx(enc(c42)), hx(enc(F.T8))]}, NIS)
    cl.add("relation-negate-mixed-order", "relation",
           {"op": "negate", "pointsHex": [hx(enc(add(c42, F.T8)))]}, NIS)
    cl.add("relation-subtract-sign-alias", "relation",
           {"op": "subtract", "pointsHex": [hx(F.alias_identity), hx(enc(c42))]}, MAL)

    # point negatives (decodePoint and decodeEnvelope)
    point_negative_cases(cl, c42)

    # multi-defect order cases (§13.3)
    vo("order-bad-point-before-value", enc(F.T2), Q, 12345, None, NIS)
    vo("order-short-point-before-value", enc(IDENTITY)[:31], -1, 12345, None, MAL)
    vo("order-point-before-amount-bits", F.off_curve, 42, 12345, 252, MAL)
    vo("order-amount-bits-before-value", c42, Q, 12345, 0, INV)
    vo("order-check1-before-check2", c42, 2 ** 64, Q, 64, NCS)
    vo("order-blinding-check1-before-equation", c42, 43, Q, None, NCS)
    vo("order-check2-before-equation", c42, 2 ** 64, 12345, 64, OOR)
    cl.add("relation-order-first-point-first", "relation",
           {"op": "add", "pointsHex": [hx(enc(F.T2)), ""]}, NIS)
    cl.add("relation-order-empty-then-order-2", "relation",
           {"op": "add", "pointsHex": ["", hx(enc(F.T2))]}, MAL)
    return cl


# ---------------------------------------------------------------------------------------------
# pedersen-jubjub-bytes-v1
# ---------------------------------------------------------------------------------------------

HELLO = bytes.fromhex("48656c6c6f2c205a65726f4a20e29c93")


def build_bytes():
    cl = CaseList("bytes")
    # pinned values (pedersen-jubjub-bytes-v1 §10) and an independent octet-form cross-check
    he = hash_to_scalar(b"")
    require(he["s"] == PIN["s_empty"] and he["b0"].hex() == PIN["b0_empty"]
            and he["u"].hex() == PIN["uniform_empty"], "HashBytesToScalar(empty) pin")
    require(hash_to_scalar(b"\x00")["s"] == PIN["s_00"], "HashBytesToScalar(00) pin")
    require(hash_to_scalar(HELLO)["s"] == PIN["s_hello"], "HashBytesToScalar(Hello) pin")
    cb0 = commit_scalar_raw(PIN["s_empty"], 0)
    require(enc(cb0).hex() == PIN["Cb_empty_0"], "C_bytes(empty, 0) pin")
    cb_lm1 = commit_scalar_raw(PIN["s_empty"], Q - 1)
    require(enc(cb_lm1).hex() == PIN["Cb_empty_lm1"], "C_bytes(empty, l-1) pin")
    ch_lm1 = commit_scalar_raw(PIN["s_hello"], Q - 1)
    require(enc(ch_lm1).hex() == PIN["Cb_hello_lm1"], "C_bytes(Hello, l-1) pin")
    pat = lambda n: bytes((131 * i + 17) % 256 for i in range(n))  # noqa: E731
    for blob in (b"", b"\x00", HELLO, pat(5), pat(6), pat(55), pat(56), pat(61), pat(62),
                 pat(64), pat(69), pat(70), pat(1000), pat(65536)):
        mine, imported = h2s_octet_form(blob), bref.hash_bytes_to_scalar(blob)
        require(all(mine[k] == imported[k] for k in ("b0", "b1", "b2", "u", "s")),
                "own octet-form HashBytesToScalar disagrees with the imported reference")

    c_hello = commit_scalar_raw(PIN["s_hello"], 12345)
    s_p64k = hash_to_scalar(pat(65536))["s"]
    c_p64k = commit_scalar_raw(s_p64k, 12345)

    decode_point_positive(cl, "identity", IDENTITY)
    decode_point_positive(cl, "base-g", B.G)
    decode_point_positive(cl, "base-h", B.H)
    decode_point_positive(cl, "commitment-empty-0", cb0)
    decode_point_positive(cl, "commitment-empty-qm1", cb_lm1)

    # hashToScalar
    for name, pl in (("empty", hex_payload(b"")), ("octet-00", hex_payload(b"\x00")),
                     ("hello-zeroj-utf8", hex_payload(HELLO)), ("pattern-55", pattern_payload(55)),
                     ("pattern-56", pattern_payload(56)), ("pattern-64", pattern_payload(64)),
                     ("pattern-1000", pattern_payload(1000)),
                     # SHA-256 block boundaries of b0's (n + 122)-octet input: 127/128 octets,
                     # 183/184 (padding spills into a new block), 191/192
                     ("pattern-5", pattern_payload(5)), ("pattern-6", pattern_payload(6)),
                     ("pattern-61", pattern_payload(61)), ("pattern-62", pattern_payload(62)),
                     ("pattern-69", pattern_payload(69)), ("pattern-70", pattern_payload(70)),
                     ("pattern-65536", pattern_payload(65536))):
        cl.add("hash-to-scalar-" + name, "hashToScalar", {"payload": pl})

    # commit (three payload sources) and verifyOpening
    def cm(name, pl, r, extra=None, intent="ok"):
        inp = {"payload": pl, "blinding": dec(r)}
        if extra:
            inp.update(extra)
        cl.add("commit-" + name, "commit", inp, intent)

    cm("empty-zero", hex_payload(b""), 0)
    cm("empty-qm1", hex_payload(b""), Q - 1)
    cm("hello-qm1", hex_payload(HELLO), Q - 1)
    cm("hello-12345", hex_payload(HELLO), 12345)
    cm("hello-12345-declared-length", hex_payload(HELLO), 12345, {"declaredLength": "16"})
    cm("hello-12345-max-bytes-16", hex_payload(HELLO), 12345, {"maxBytes": "16"})
    cm("hello-12345-max-bytes-4096", hex_payload(HELLO), 12345, {"maxBytes": "4096"})
    cm("empty-zero-declared-length-0", hex_payload(b""), 0, {"declaredLength": "0"})
    cm("empty-zero-max-bytes-max", hex_payload(b""), 0, {"maxBytes": dec(MAX_PAYLOAD_BYTES)})
    cm("pattern-65536-12345", pattern_payload(65536), 12345)
    cm("pattern-65536-12345-declared-length", pattern_payload(65536), 12345,
       {"declaredLength": "65536"})
    cm("pattern-65536-12345-max-bytes", pattern_payload(65536), 12345, {"maxBytes": "65537"})
    for lname, lim in (("minus-1", -1), ("max-plus-1", MAX_PAYLOAD_BYTES + 1),
                       ("long-min", -2 ** 63), ("long-max", 2 ** 63 - 1)):
        cm("declared-length-" + lname, hex_payload(b""), 12345, {"declaredLength": dec(lim)}, LOR)
        cm("max-bytes-" + lname, hex_payload(b""), 12345, {"maxBytes": dec(lim)}, LOR)

    def vo(name, pt, pl, r, intent="ok"):
        inp = {"pointHex": hx(pt if isinstance(pt, bytes) else enc(pt)), "payload": pl,
               "blinding": dec(r)}
        cl.add("verify-" + name, "verifyOpening", inp, intent)

    vo("empty-zero", cb0, hex_payload(b""), 0)
    vo("empty-qm1", cb_lm1, hex_payload(b""), Q - 1)
    vo("hello-qm1", ch_lm1, hex_payload(HELLO), Q - 1)
    vo("hello-12345", c_hello, hex_payload(HELLO), 12345)
    vo("pattern-65536-12345", c_p64k, pattern_payload(65536), 12345)
    vo("wrong-payload", c_hello, hex_payload(HELLO[:-1]), 12345, OMM)
    vo("wrong-payload-trailing-zero", c_hello, hex_payload(HELLO + b"\x00"), 12345, OMM)
    vo("wrong-blinding", c_hello, hex_payload(HELLO), 12346, OMM)
    vo("pattern-length-off-by-one", c_p64k, pattern_payload(65535), 12345, OMM)
    vo("identity-empty-zero", IDENTITY, hex_payload(b""), 0, OMM)

    # scalar negatives (blinding only; s is recomputed)
    for sname, bad in BAD_SCALARS:
        cm("blinding-" + sname, hex_payload(HELLO), bad, None, NCS)
        vo("blinding-" + sname, c_hello, hex_payload(HELLO), bad, NCS)
        cl.add("encode-opening-blinding-" + sname, "encodeOpening", {"blinding": dec(bad)}, NCS)
    for sname, bad in BAD_SCALARS[:2]:
        cl.add("decode-opening-blinding-" + sname, "decodeOpening",
               {"openingHex": hx(bad.to_bytes(32, "big"))}, NCS)
    cl.add("decode-opening-blinding-all-ones", "decodeOpening", {"openingHex": "ff" * 32}, NCS)

    for name, r in (("zero", 0), ("one", 1), ("12345", 12345), ("qm1", Q - 1)):
        cl.add("encode-opening-" + name, "encodeOpening", {"blinding": dec(r)})
        oh = cl.expected_of("encodeOpening", {"blinding": dec(r)})["openingHex"]
        cl.add("decode-opening-" + name, "decodeOpening", {"openingHex": oh})
    for n in (0, 31, 33, 64):
        cl.add("decode-opening-length-%d" % n, "decodeOpening",
               {"openingHex": hx(((12345).to_bytes(32, "big") + b"\x00" * 32)[:n])}, MAL)

    envelope_round_trip(cl, "identity", IDENTITY)
    envelope_round_trip(cl, "commitment-empty-0", cb0)
    envelope_round_trip(cl, "commitment-hello-12345", c_hello)
    envelope_negatives(cl, PROFILE_BYTES, hx(enc(c_hello)))
    cl.add("envelope-encode-order-4", "encodeEnvelope", {"pointHex": hx(enc(F.T4))}, NIS)

    point_negative_cases(cl, c_hello)

    # multi-defect order cases (§13.3; bytes-v1 §6 order)
    # (The blinding-before-length order of bytes-v1 §6 is not a file case: such a fixture would
    # break the §13.3 "Streams" rule. It is pinned by the Java tests.)
    vo("order-blinding-before-equation", c_hello, hex_payload(HELLO[:-1]), Q, NCS)
    vo("order-off-curve-before-blinding", F.off_curve, hex_payload(HELLO), Q, MAL)
    vo("order-order-8-before-blinding", enc(F.T8), hex_payload(HELLO), -1, NIS)
    vo("order-point-before-mismatch", enc(add(c_hello, F.T2)), hex_payload(HELLO), 12345, NIS)
    return cl


# ---------------------------------------------------------------------------------------------
# pedersen-jubjub-vector-v1
# ---------------------------------------------------------------------------------------------

def build_vector():
    cl = CaseList("vector")
    s1 = Schema("zeroj.example.balance", 1, [("amount", 64), ("asset", 32)])
    s2 = Schema("zeroj.example.balance", 2, [("amount", 64), ("asset", 32)])
    s_swap = Schema("zeroj.example.balance", 1, [("asset", 64), ("amount", 32)])
    s_one = Schema("zeroj.test.one", 1, [("amount", 64)])
    s_w250 = Schema("zeroj.test.w250", 1, [("x", 250)])
    s_w251 = Schema("zeroj.test.w251", 1, [("x", 251)])
    s_w252 = Schema("zeroj.test.w252", 1, [("x", 252)])
    s_w235 = Schema("zeroj.test.w235", 1, [("x", 235)])
    s_w236 = Schema("zeroj.test.w236", 1, [("x", 236)])
    s_mix = Schema("zeroj.test.mixed", 1, [("small", 8), ("big", 250)])
    require(vref.schema_digest(s1.encoding) == PIN["sigma_balance_v1"], "sigma(balance v1)")
    J1, J2, JSWAP = s1.to_json(), s2.to_json(), s_swap.to_json()

    c1000_7 = commit_vector_raw([1000, 7], 12345)
    require(enc(c1000_7).hex() == PIN["V_1000_7_12345"], "C([1000,7],12345) pin")
    require(enc(commit_vector_raw([1000], 12345)).hex() == PIN["V_1000_12345"], "C([1000]) pin")
    require(enc(commit_vector_raw([1000, 0], 12345)).hex() == PIN["V_1000_12345"], "padding pin")

    SW = {"kind": "schema-widths"}
    RO = {"kind": "residue-only"}

    def WD(n):
        return {"kind": "widened", "addedTerms": dec(n)}

    # decodePoint positives
    decode_point_positive(cl, "identity", IDENTITY, J1)
    decode_point_positive(cl, "base-g0", B.GS[0], J1)
    decode_point_positive(cl, "base-hv", B.HV, J1)
    decode_point_positive(cl, "commitment-1000-7-12345", c1000_7, J1)

    # legacy commit (canonical, width-respecting inputs only)
    def cm(name, sj, values, r):
        inp = {"schema": sj, "values": [dec(v) for v in values], "blinding": dec(r)}
        cl.add("commit-" + name, "commit", inp)
        return bytes.fromhex(cl.expected_of("commit", inp)["pointHex"])

    cm("zero-zero", J1, [0, 0], 0)
    p_1000_7 = cm("1000-7-12345", J1, [1000, 7], 12345)
    cm("1000-0-12345", J1, [1000, 0], 12345)
    cm("one-schema-1000-12345", s_one.to_json(), [1000], 12345)
    cm("max-widths-qm1", J1, [2 ** 64 - 1, 2 ** 32 - 1], Q - 1)
    p_a = cm("2pow64m1-0-5", J1, [2 ** 64 - 1, 0], 5)
    p_b = cm("1-0-0", J1, [1, 0], 0)
    p_a2 = cm("0-2pow32m1-5", J1, [0, 2 ** 32 - 1], 5)
    p_b2 = cm("0-1-0", J1, [0, 1], 0)
    p_x = cm("1001-7-12340", J1, [1001, 7], 12340)
    p_y = cm("1-1-1", J1, [1, 1], 1)
    p_w = cm("w252-1-0", s_w252.to_json(), [1], 0)
    require(p_1000_7 == enc(c1000_7), "commit consistency")

    # relations building derived points
    def rel(name, o, pts, sj=J1, intent="ok"):
        inp = {"op": o, "pointsHex": [hx(p) for p in pts], "schema": sj}
        cl.add("relation-" + name, "relation", inp, intent)
        if intent == "ok":
            return bytes.fromhex(cl.expected_of("relation", inp)["pointHex"])
        return None

    p64 = rel("add-to-2pow64", "add", [p_a, p_b])
    require(p64 == enc(commit_vector_raw([2 ** 64, 0], 5)), "relation 2^64")
    p32 = rel("add-to-2pow32", "add", [p_a2, p_b2])
    require(p32 == enc(commit_vector_raw([0, 2 ** 32], 5)), "relation 2^32")
    p65 = rel("add-to-2pow65", "add", [p64, p64])
    require(p65 == enc(commit_vector_raw([2 ** 65, 0], 10)), "relation 2^65")
    pdiff = rel("subtract-difference", "subtract", [p_1000_7, p_x])
    require(pdiff == enc(commit_vector_raw([Q - 1, 0], 5)), "relation difference")
    pneg = rel("subtract-to-qm1", "subtract", [enc(IDENTITY), p_y])
    require(pneg == enc(commit_vector_raw([Q - 1, Q - 1], Q - 1)), "relation q-1")
    pw = rel("subtract-w252-to-qm1", "subtract", [enc(IDENTITY), p_w], s_w252.to_json())
    require(pw == enc(commit_vector_raw([Q - 1], 0)), "relation w252")

    def vo(name, pt, sj, pol, values, r, intent="ok", policy_schema=None):
        inp = {"pointHex": hx(pt if isinstance(pt, bytes) else enc(pt)), "schema": sj}
        if policy_schema is not None:
            inp["policySchema"] = policy_schema
        inp["policy"] = pol
        inp["values"] = [dec(v) for v in values]
        inp["blinding"] = dec(r)
        cl.add("vector-verify-" + name if not name.startswith("vector-") else name,
               "verifyOpening", inp, intent)

    # §13.3.1 example records, verbatim
    vo("vector-verify-identity-zero", IDENTITY, J1, SW, [0, 0], 0)
    vo("vector-verify-policy-schema-mismatch", IDENTITY, J1, SW, [0, 0], 0, PMM, J2)

    vo("1000-7-schema-widths", p_1000_7, J1, SW, [1000, 7], 12345)
    vo("1000-7-residue-only", p_1000_7, J1, RO, [1000, 7], 12345)
    vo("1000-7-widened-2", p_1000_7, J1, WD(2), [1000, 7], 12345)
    vo("1000-7-widened-65536", p_1000_7, J1, WD(65536), [1000, 7], 12345)
    vo("max-widths-schema-widths", commit_vector_raw([2 ** 64 - 1, 2 ** 32 - 1], Q - 1), J1, SW,
       [2 ** 64 - 1, 2 ** 32 - 1], Q - 1)
    vo("qm1-components-residue-only", pneg, J1, RO, [Q - 1, Q - 1], Q - 1)
    vo("qm1-components-schema-widths", pneg, J1, SW, [Q - 1, Q - 1], Q - 1, OOR)
    vo("difference-residue-only", pdiff, J1, RO, [Q - 1, 0], 5)
    vo("difference-schema-widths", pdiff, J1, SW, [Q - 1, 0], 5, OOR)
    vo("difference-widened-2", pdiff, J1, WD(2), [Q - 1, 0], 5, OOR)
    vo("2pow64-schema-widths", p64, J1, SW, [2 ** 64, 0], 5, OOR)
    vo("2pow64-residue-only", p64, J1, RO, [2 ** 64, 0], 5)
    vo("2pow64-widened-2", p64, J1, WD(2), [2 ** 64, 0], 5)
    vo("2pow32-index-1-schema-widths", p32, J1, SW, [0, 2 ** 32], 5, OOR)
    vo("2pow32-index-1-residue-only", p32, J1, RO, [0, 2 ** 32], 5)
    vo("2pow32-index-1-widened-2", p32, J1, WD(2), [0, 2 ** 32], 5)
    vo("2pow65-widened-2", p65, J1, WD(2), [2 ** 65, 0], 10, OOR)
    vo("2pow65-widened-3-ceil-log2", p65, J1, WD(3), [2 ** 65, 0], 10)
    vo("2pow65-widened-4", p65, J1, WD(4), [2 ** 65, 0], 10)
    vo("w252-qm1-schema-widths", pw, s_w252.to_json(), SW, [Q - 1], 0)
    vo("one-schema-1000", commit_vector_raw([1000], 12345), s_one.to_json(), SW, [1000], 12345)
    # OPENING_MISMATCH
    vo("wrong-value", p_1000_7, J1, SW, [1000, 8], 12345, OMM)
    vo("wrong-blinding", p_1000_7, J1, SW, [1000, 7], 12346, OMM)
    vo("swapped-components", p_1000_7, J1, SW, [7, 1000], 12345, OMM)
    vo("labels-swapped-schema-same-point", p_1000_7, JSWAP, SW, [1000, 7], 12345)
    vo("labels-swapped-policy-schema", p_1000_7, J1, SW, [1000, 7], 12345, PMM, JSWAP)
    # dimension mismatches (MALFORMED_ENCODING)
    vo("dimension-1", p_1000_7, J1, SW, [1000], 12345, MAL)
    vo("dimension-3", p_1000_7, J1, SW, [1000, 7, 0], 12345, MAL)
    vo("dimension-0", p_1000_7, J1, SW, [], 12345, MAL)
    # scalar negatives
    for sname, bad in BAD_SCALARS:
        vo("v0-" + sname, p_1000_7, J1, SW, [bad, 7], 12345, NCS)
        vo("v1-" + sname, p_1000_7, J1, SW, [1000, bad], 12345, NCS)
        vo("blinding-" + sname, p_1000_7, J1, SW, [1000, 7], bad, NCS)
        vo("v0-" + sname + "-residue-only", p_1000_7, J1, RO, [bad, 7], 12345, NCS)

    # encodeOpening / decodeOpening
    def eo(name, sj, pol, values, r, intent="ok"):
        inp = {"schema": sj, "policy": pol, "values": [dec(v) for v in values], "blinding": dec(r)}
        cl.add("encode-opening-" + name, "encodeOpening", inp, intent)
        if intent == "ok":
            oh = cl.expected_of("encodeOpening", inp)["openingHex"]
            cl.add("decode-opening-" + name, "decodeOpening",
                   {"openingHex": oh, "schema": sj, "policy": pol})

    def do(name, sj, pol, data, intent):
        cl.add("decode-opening-" + name, "decodeOpening",
               {"openingHex": hx(data), "schema": sj, "policy": pol}, intent)

    eo("1000-7-schema-widths", J1, SW, [1000, 7], 12345)
    eo("zero-schema-widths", J1, SW, [0, 0], 0)
    eo("qm1-residue-only", J1, RO, [Q - 1, Q - 1], Q - 1)
    eo("2pow64-widened-2", J1, WD(2), [2 ** 64, 0], 5)
    eo("one-schema", s_one.to_json(), SW, [1000], 12345)
    eo("2pow64-schema-widths", J1, SW, [2 ** 64, 0], 5, OOR)
    eo("2pow32-index-1-schema-widths", J1, SW, [0, 2 ** 32], 5, OOR)
    eo("dimension-3", J1, SW, [1, 2, 3], 5, MAL)
    eo("dimension-1", J1, SW, [1], 5, MAL)
    for sname, bad in BAD_SCALARS:
        eo("v0-" + sname, J1, SW, [bad, 7], 12345, NCS)
        eo("v1-" + sname, J1, SW, [1000, bad], 12345, NCS)
        eo("blinding-" + sname, J1, SW, [1000, 7], bad, NCS)

    def vec_open(values, r, n=None):
        out = bytes([len(values) if n is None else n])
        for v in values:
            out += v.to_bytes(32, "big")
        return out + r.to_bytes(32, "big")

    for sname, bad in BAD_SCALARS[:2]:
        do("v0-" + sname, J1, SW, vec_open([bad, 7], 12345), NCS)
        do("v1-" + sname, J1, SW, vec_open([1000, bad], 12345), NCS)
        do("blinding-" + sname, J1, SW, vec_open([1000, 7], bad), NCS)
    good = vec_open([1000, 7], 12345)
    do("length-0", J1, SW, b"", MAL)
    do("length-1", J1, SW, good[:1], MAL)
    do("truncated-by-one", J1, SW, good[:-1], MAL)
    do("trailing-octet", J1, SW, good + b"\x00", MAL)
    do("n-0", J1, SW, b"\x00" + good[1:], MAL)
    do("n-3-with-3-components", J1, SW, vec_open([1000, 7, 0], 12345), MAL)
    do("n-3-with-2-components", J1, SW, b"\x03" + good[1:], MAL)
    do("n-1-with-2-components", J1, SW, b"\x01" + good[1:], MAL)
    do("2pow64-schema-widths", J1, SW, vec_open([2 ** 64, 0], 5), OOR)
    do("2pow32-index-1-schema-widths", J1, SW, vec_open([0, 2 ** 32], 5), OOR)
    do("difference-schema-widths", J1, SW, vec_open([Q - 1, 0], 5), OOR)
    do("2pow65-widened-2", J1, WD(2), vec_open([2 ** 65, 0], 5), OOR)
    do("2pow65-widened-3", J1, WD(3), vec_open([2 ** 65, 0], 5), "ok")

    # configurePolicy
    def cp(name, sj, pol, intent="ok"):
        cl.add("configure-policy-" + name, "configurePolicy", {"schema": sj, "policy": pol}, intent)

    cp("schema-widths", J1, SW)
    cp("residue-only", J1, RO)
    cp("widened-2", J1, WD(2))
    cp("widened-65536-narrow", J1, WD(65536))
    cp("widened-65537", J1, WD(65537), INV)
    cp("widened-1", J1, WD(1), INV)
    cp("widened-0", J1, WD(0), INV)
    cp("widened-minus-1", J1, WD(-1), INV)
    cp("widened-int-max", J1, WD(2 ** 31 - 1), INV)
    cp("widened-reaching-q-w251-2", s_w251.to_json(), WD(2), INV)
    cp("widened-w252-2", s_w252.to_json(), WD(2), INV)
    cp("schema-widths-w252", s_w252.to_json(), SW)
    cp("widened-w250-2", s_w250.to_json(), WD(2))
    cp("widened-w250-3-ceil-log2", s_w250.to_json(), WD(3), INV)
    cp("widened-w235-65536", s_w235.to_json(), WD(65536))
    cp("widened-w236-65536", s_w236.to_json(), WD(65536), INV)
    cp("widened-w236-32768", s_w236.to_json(), WD(32768))
    cp("widened-w236-32769", s_w236.to_json(), WD(32769), INV)
    cp("widened-mixed-2", s_mix.to_json(), WD(2))
    cp("widened-mixed-3-second-entry", s_mix.to_json(), WD(3), INV)

    # dimension 16 (N_MAX): mixed widths, distinct labels
    widths16 = [8] * 16
    widths16[7] = 16
    widths16[15] = 32
    s16 = Schema("zeroj.test.dim16", 1, [("c%d" % i, widths16[i]) for i in range(16)])
    J16 = s16.to_json()
    v16 = [i + 1 for i in range(16)]          # nonzero in every component; v_13 != v_14
    r16 = 987654321
    p16 = cm("dim16-all-nonzero", J16, v16, r16)
    require(p16 == enc(commit_vector_raw(v16, r16)), "dimension-16 commit")
    vo("dim16-schema-widths", p16, J16, SW, v16, r16)
    vo("dim16-residue-only", p16, J16, RO, v16, r16)
    vo("dim16-widened-2", p16, J16, WD(2), v16, r16)
    swapped = list(v16)
    swapped[13], swapped[14] = swapped[14], swapped[13]
    vo("dim16-swap-13-14", p16, J16, SW, swapped, r16, OMM)
    vo("dim16-dimension-15", p16, J16, SW, v16[:15], r16, MAL)
    eo("dim16-schema-widths", J16, SW, v16, r16)
    open16 = vec_open(v16, r16)
    require(len(open16) == 545, "dimension-16 opening length")
    do("dim16-n-0x0f", J16, SW, b"\x0f" + open16[1:], MAL)
    do("dim16-n-0x11", J16, SW, b"\x11" + open16[1:], MAL)
    do("dim16-truncated-by-one", J16, SW, open16[:-1], MAL)
    # v_15 at 2^32 (= 2^{k_15}) via relation: C(v16 with v_15 = 2^32 - 1) + C(e_15)
    hi = list(v16)
    hi[15] = 2 ** 32 - 1
    p_hi = cm("dim16-v15-2pow32m1", J16, hi, r16)
    e15 = [0] * 16
    e15[15] = 1
    p_e15 = cm("dim16-unit-15", J16, e15, 0)
    p16_top = rel("dim16-add-to-v15-2pow32", "add", [p_hi, p_e15], J16)
    top = list(v16)
    top[15] = 2 ** 32
    require(p16_top == enc(commit_vector_raw(top, r16)), "dimension-16 relation")
    vo("dim16-v15-2pow32-schema-widths", p16_top, J16, SW, top, r16, OOR)
    vo("dim16-v15-2pow32-residue-only", p16_top, J16, RO, top, r16)
    eo("dim16-v15-2pow32-schema-widths", J16, SW, top, r16, OOR)
    do("dim16-v15-2pow32-schema-widths", J16, SW, vec_open(top, r16), OOR)
    for sname, bad in BAD_SCALARS[:2]:
        bad16 = list(v16)
        bad16[15] = bad
        vo("dim16-v15-" + sname, p16, J16, SW, bad16, r16, NCS)
        eo("dim16-v15-" + sname, J16, SW, bad16, r16, NCS)
        do("dim16-v15-" + sname, J16, SW, vec_open(bad16, r16), NCS)

    # envelope
    envelope_round_trip(cl, "identity", IDENTITY, J1)
    envelope_round_trip(cl, "commitment-1000-7-12345", c1000_7, J1, J2)
    envelope_negatives(cl, PROFILE_VECTOR, hx(enc(c1000_7)), J1)
    cl.add("envelope-encode-mixed-order", "encodeEnvelope",
           {"pointHex": hx(enc(add(c1000_7, F.T8))), "schema": J1}, NIS)

    # relation negatives
    rel("add-second-order-4", "add", [p_1000_7, enc(F.T4)], J1, NIS)
    rel("subtract-off-curve", "subtract", [F.off_curve, p_1000_7], J1, MAL)

    point_negative_cases(cl, c1000_7, J1)

    # multi-defect order cases (§13.3 execution order; §12.3 verifyOpening order)
    vo("order-schema-before-dimension", p_1000_7, J1, SW, [Q, 7, 0], 12345, PMM, J2)
    vo("order-dimension-before-check1", p_1000_7, J1, SW, [Q, 7, 0], 12345, MAL)
    vo("order-check1-blinding-before-check3", p64, J1, SW, [2 ** 64, 0], Q, NCS)
    vo("order-check1-all-components-before-check3", p64, J1, SW, [2 ** 64, -1], 5, NCS)
    vo("order-point-before-schema-comparison", F.off_curve, J1, SW, [0, 0], 0, MAL, J2)
    vo("order-policy-config-before-point", F.off_curve, J1, WD(1), [0, 0], 0, INV)
    vo("order-policy-on-policy-schema-before-comparison", p_1000_7, J1, WD(2), [1000, 7],
       12345, INV, s_w251.to_json())
    vo("order-order-8-before-check1", enc(F.T8), J1, SW, [Q, Q], Q, NIS)
    do("order-n-before-check1", J1, SW, vec_open([Q, Q, Q], Q), MAL)
    do("order-blinding-check1-before-check3", J1, SW, vec_open([2 ** 64, 0], Q), NCS)
    do("order-v1-check1-before-v0-check3", J1, SW, vec_open([2 ** 64, Q], 5), NCS)
    eo("order-dimension-before-blinding", J1, SW, [1, 2, 3], -1, MAL)
    eo("order-check1-before-check3", J1, SW, [2 ** 64, 0], -1, NCS)
    rel("order-first-point-first", "add", [enc(F.T2), b""], J1, NIS)
    rel("order-empty-then-order-2", "add", [b"", enc(F.T2)], J1, MAL)
    return cl


# =============================================================================================
# File assembly
# =============================================================================================

def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


SPECS = {
    "commitment-profiles-v1.md": "docs/specs/commitment-profiles-v1.md",
    "pedersen-jubjub-v1.md": "docs/specs/pedersen-jubjub-v1.md",
    "pedersen-jubjub-vector-v1.md": "docs/specs/pedersen-jubjub-vector-v1.md",
    "pedersen-jubjub-bytes-v1.md": "docs/specs/pedersen-jubjub-bytes-v1.md",
}
SPECS_FOR = {
    "scalar": ["commitment-profiles-v1.md", "pedersen-jubjub-v1.md"],
    "vector": ["commitment-profiles-v1.md", "pedersen-jubjub-v1.md", "pedersen-jubjub-vector-v1.md"],
    "bytes": ["commitment-profiles-v1.md", "pedersen-jubjub-v1.md", "pedersen-jubjub-bytes-v1.md"],
}
# The revision these vectors implement. A later metadata-only revision of the document changes
# its date and SHA-256 (provenance, warnings under --check) but not this label.
IMPLEMENTED_REVISION = {"commitment-profiles-v1.md": "r3"}
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
    check_no_numbers(doc)
    if strict and kind == "bytes":
        check_streams_rule(positive, negative)
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def check_streams_rule(positive, negative):
    """§13.3 "Streams", literally: declaredLength equals the payload length and maxBytes is at
    least the payload length, except in LENGTH_OUT_OF_RANGE cases, where the value is outside
    [0, MAX_PAYLOAD_BYTES] and the payload is empty."""
    for case in positive + negative:
        inp = case["input"]
        fields = [f for f in ("declaredLength", "maxBytes") if f in inp]
        if not fields:
            continue
        require(case["operation"] == "commit", "Streams: length field outside commit")
        require(len(fields) == 1, "Streams: both declaredLength and maxBytes in " + case["name"])
        value = int(inp[fields[0]])
        n = len(payload_bytes(inp["payload"]))
        if case.get("error") == LOR:
            require(n == 0 and not 0 <= value <= MAX_PAYLOAD_BYTES,
                    "Streams: LENGTH_OUT_OF_RANGE case not empty/out of range: " + case["name"])
        elif fields[0] == "declaredLength":
            require(value == n, "Streams: declaredLength != payload length in " + case["name"])
        else:
            require(value >= n, "Streams: maxBytes < payload length in " + case["name"])


def check_no_numbers(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            require(isinstance(k, str), "non-string key")
            if k.endswith("Hex"):  # a hex string, or (pointsHex) an array of hex strings
                items = v if isinstance(v, list) else [v]
                require(all(isinstance(x, str) and re.fullmatch(r"(?:[0-9a-f]{2})*", x)
                            is not None for x in items), "bad Hex field " + k)
            check_no_numbers(v)
    elif isinstance(obj, list):
        for v in obj:
            check_no_numbers(v)
    else:
        require(isinstance(obj, str), "non-string JSON value: %r" % (obj,))


BUILDERS = [("scalar", build_scalar), ("bytes", build_bytes), ("vector", build_vector)]


def generate_all(repo_root, strict=True):
    out = {}
    for kind, builder in BUILDERS:
        cl = builder() if strict else _with_strict_builder(builder)
        out[PROFILE_OF[kind]] = build_file(kind, cl, repo_root, strict)
    return out


_BASELINE_CASES = {}


def _with_strict_builder(builder):
    """Case INPUTS are always built with the unmutated implementation (cached), so a mutation
    can only change outcomes, never which inputs are emitted."""
    return _BASELINE_CASES[builder.__name__]


def cross_checks():
    """Independent differentials between this file and the imported references."""
    pts = [IDENTITY, B.G, B.H, F.T2, F.T4, F.T8, add(B.G, F.T8)]
    for pt in pts:  # imported affine vs extended arithmetic
        require(enc(sref.scalar_mul(12345, pt)) == enc(mul(12345, pt)), "affine vs extended")
        require(enc(vref.pt_add(pt, B.H)) == enc(add(pt, B.H)), "vector-ref add vs extended")
    fixtures = [enc(p) for p in pts] + [F.off_curve, F.alias_identity, F.alias_order2,
                                         F.v_eq_p, F.v_eq_p1, F.v_max, b"", b"\x01"]
    for data in fixtures:  # own strict decoder vs both imported decoders
        try:
            mine = strict_decode_point(data)
        except Fail as e:
            mine = e.cls
        s_pt, _ = sref.decode(data)
        b_pt, b_reason = bref.receive(data)
        if s_pt is None:
            require(mine == MAL and b_pt is None and b_reason != "not_in_prime_subgroup",
                    "decoder class disagrees (malformed) for " + data.hex())
        elif b_pt is None:
            require(mine == NIS and b_reason == "not_in_prime_subgroup",
                    "decoder class disagrees (subgroup) for " + data.hex())
        else:
            require(mine == s_pt == b_pt, "decoded point disagrees for " + data.hex())
    for ident in ("a-v1", PROFILE_SCALAR, PROFILE_VECTOR, PROFILE_BYTES) + tuple(REGISTRY):
        require(valid_identifier(ident), "identifier grammar rejects " + ident)
    for bad in ("a-v0", "A-v1", "a-v1\n", "a--b-v1", "-a-v1", "a-v01", "av1", "a-v1 ", "x" * 62 + "-v1"):
        require(not valid_identifier(bad), "identifier grammar accepts %r" % bad)
    for pid, n in ENVELOPE_LENGTH.items():
        require(len(envelope_encode(pid, bytes(32))) == n, "envelope length table")


# =============================================================================================
# Mutation self-test
# =============================================================================================

MUTATIONS = [
    ("check1_accepts_q", "check 1 accepts q"),
    ("check1_reduces_negative", "check 1 reduces -1 instead of rejecting it"),
    ("decoder_skips_subgroup", "point decoder skips the prime-order subgroup check"),
    ("decoder_cofactor_clears", "point decoder cofactor-clears instead of rejecting"),
    ("decoder_accepts_sign_alias", "point decoder accepts the u = 0 sign aliases (no rule 5)"),
    ("decoder_reduces_v", "point decoder reduces v mod p instead of rejecting v >= p"),
    ("envelope_no_id_compare", "envelope decoder does not compare the identifier"),
    ("envelope_any_version", "envelope decoder accepts any version octet"),
    ("envelope_length_before_id", "envelope decoder checks point length before the identifier"),
    ("widened_floor_log2", "widened(n) uses floor(log2 n)"),
    ("widened_first_entry_only", "widened(n) configuration checks only the first entry"),
    ("widened_no_upper_limit", "widened(n) accepts n > 65536"),
    ("widened_allows_one", "widened(n) accepts n = 1"),
    ("schema_widths_off_by_one", "schema-widths accepts v_i = 2^k_i"),
    ("opening_little_endian", "opening encodings use little-endian scalars"),
    ("amount_bits_allows_252", "amountBits accepts 252"),
    ("amount_bits_check_before_point", "amountBits validated before the point (step 1)"),
    ("vector_schema_compare_after_dimension", "vector verifyOpening checks dimension first"),
    ("vector_no_schema_compare", "vector verifyOpening skips the policy-schema comparison"),
    ("vector_check3_before_check1", "vector check 3 runs before check 1"),
    ("vector_decode_skips_n_check", "vector opening decoder ignores the n octet"),
    ("bytes_equation_before_blinding", "bytes verifyOpening checks the equation before check 1"),
    ("subtract_reversed", "relation subtract computes P1 - P0"),
    ("vector_wrong_base_high_index", "vector commitment uses G_(i mod 2) for component i"),
    ("hash_length_prefix", "HashBytesToScalar frames the length as a prefix"),
]


def self_test(repo_root, baseline):
    results = []
    for name, desc in MUTATIONS:
        MUT.clear()
        MUT.add(name)
        try:
            mutated = generate_all(repo_root, strict=False)
        finally:
            MUT.clear()
        changed = {}
        for pid, text in baseline.items():
            if mutated[pid] != text:
                a = json.loads(text)
                b = json.loads(mutated[pid])
                old = {c["name"]: c for c in a["positive"] + a["negative"]}
                new = {c["name"]: c for c in b["positive"] + b["negative"]}
                changed[pid] = sum(1 for k in old if old[k] != new.get(k))
        results.append((name, desc, changed))
    return results


# =============================================================================================
# Main
# =============================================================================================

def _strip_provenance(doc):
    """A copy without the provenance-only fields: generator.python and each spec entry's
    sha256 and date. Everything else (cases, paths, revisions, script hash) is compared."""
    d = json.loads(json.dumps(doc))
    if isinstance(d.get("generator"), dict):
        d["generator"].pop("python", None)
    if isinstance(d.get("spec"), list):
        for e in d["spec"]:
            if isinstance(e, dict):
                e.pop("sha256", None)
                e.pop("date", None)
    return d


_MISSING = object()  # distinguishes an absent key from a JSON null


def _diff(a, b, where, out, limit=20):
    """Structural differences between two JSON values, with absent keys distinct from null."""
    if len(out) >= limit:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for key in list(a) + [k for k in b if k not in a]:
            va, vb = a.get(key, _MISSING), b.get(key, _MISSING)
            path = "%s.%s" % (where, key)
            if va is _MISSING:
                out.append("%s present only in the regenerated file" % path)
            elif vb is _MISSING:
                out.append("%s present only in the file on disk (value %s)"
                           % (path, json.dumps(va)[:100]))
            else:
                _diff(va, vb, path, out, limit)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append("%s has %d entries on disk, %d regenerated" % (where, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            _diff(x, y, "%s[%d]" % (where, i), out, limit)
    elif type(a) is not type(b) or a != b:
        out.append("%s: %s on disk, %s regenerated" % (where, json.dumps(a)[:100], json.dumps(b)[:100]))


def _case_label(doc, side, i):
    try:
        return doc[side][i]["name"]
    except (KeyError, IndexError, TypeError):
        return "#%d" % i


def compare_texts(disk_text, text):
    """Returns (errors, warnings) for a file on disk against the regenerated text.

    The two documents are normalized by removing only the provenance fields (generator.python,
    and each spec entry's sha256 and date). Any inequality of the normalized documents is an
    error; an absent key and a null value are different. Differences in the provenance fields,
    or in formatting alone, are warnings."""
    if disk_text == text:
        return [], []
    try:
        disk = json.loads(disk_text)
    except ValueError as exc:
        return ["cannot parse (%s)" % exc], []
    new = json.loads(text)
    if not isinstance(disk, dict):
        return ["top level is not a JSON object"], []
    errors, warnings = [], []
    a, b = _strip_provenance(disk), _strip_provenance(new)
    if a != b or _diff_any(a, b):
        details = []
        _diff(a, b, "$", details)
        for side in ("positive", "negative"):  # name the cases involved
            for d in list(details):
                m = re.match(r"\$\.%s\[(\d+)\]" % side, d)
                if m:
                    details[details.index(d)] = "%s (case %s)" % (d, _case_label(disk, side, int(m.group(1))))
        errors.extend(details or ["normalized documents differ"])
    old_gen = disk.get("generator") if isinstance(disk.get("generator"), dict) else {}
    if old_gen.get("python", _MISSING) != new["generator"]["python"]:
        warnings.append("generator.python %s on disk, %r now"
                        % (json.dumps(old_gen.get("python")), new["generator"]["python"]))
    old_spec = disk.get("spec") if isinstance(disk.get("spec"), list) else []
    for i, entry in enumerate(new["spec"]):
        o = old_spec[i] if i < len(old_spec) and isinstance(old_spec[i], dict) else {}
        for f in ("date", "sha256"):
            if o.get(f, _MISSING) != entry[f]:
                warnings.append("spec[%d] %s %s: %s on disk, %r now"
                                % (i, entry["path"], f, json.dumps(o.get(f)), entry[f]))
    if not errors and not warnings:
        warnings.append("formatting differs; content identical")
    return errors, warnings


def _diff_any(a, b):
    out = []
    _diff(a, b, "$", out, limit=1)
    return bool(out)


def compare_files(path, text):
    try:
        with open(path, encoding="ascii") as fh:
            disk_text = fh.read()
    except OSError as exc:
        return ["cannot read (%s)" % exc], []
    return compare_texts(disk_text, text)


def check_regression(texts):
    """--check regression: in-memory tampered copies of the regenerated files must be judged
    correctly. Returns a list of failures (empty when every expectation holds)."""
    failures = []
    pid, text = sorted(texts.items())[0]
    base = json.loads(text)

    def tamper(fn):
        d = json.loads(text)
        fn(d)
        return json.dumps(d, indent=2, ensure_ascii=True) + "\n"

    def first_case(d):
        return (d["positive"] + d["negative"])[0]

    def set_key(obj, key, value):
        obj[key] = value

    def swap_first_keys(d):
        g = d["generator"]
        d["generator"] = dict(reversed(list(g.items())))

    expectations = [
        ("unchanged", text, False, False),
        ("extra top-level key with null", tamper(lambda d: set_key(d, "unexpected", None)), True, None),
        ("extra key with null in a case input",
         tamper(lambda d: set_key(first_case(d)["input"], "unexpected", None)), True, None),
        ("extra key with null in a case", tamper(lambda d: set_key(first_case(d), "note", None)),
         True, None),
        ("extra key with null in generator", tamper(lambda d: set_key(d["generator"], "x", None)),
         True, None),
        ("extra key with null in a spec entry", tamper(lambda d: set_key(d["spec"][0], "x", None)),
         True, None),
        ("header value replaced by null", tamper(lambda d: set_key(d, "profileId", None)), True, None),
        ("revision removed", tamper(lambda d: d["spec"][0].pop("revision", None) if "revision"
                                    in d["spec"][0] else d["spec"][0].update(revision="r9")), True, None),
        ("scriptSha256 changed", tamper(lambda d: set_key(d["generator"], "scriptSha256", "00" * 32)),
         True, None),
        ("case error changed", tamper(lambda d: set_key(d["negative"][0], "error", "OUT_OF_RANGE")),
         True, None),
        ("case removed", tamper(lambda d: d["negative"].pop()), True, None),
        ("case duplicated", tamper(lambda d: d["positive"].append(d["positive"][0])), True, None),
        ("cases reordered", tamper(lambda d: d["positive"].reverse()), True, None),
        ("number instead of string", tamper(lambda d: set_key(d["positive"][0]["input"], "pointHex", 1)),
         True, None),
        ("python version differs", tamper(lambda d: set_key(d["generator"], "python", "CPython 0.0")),
         False, True),
        ("python removed", tamper(lambda d: d["generator"].pop("python")), False, True),
        ("spec sha256/date differ", tamper(lambda d: d["spec"][0].update(sha256="00" * 32,
                                                                       date="2099-01-01")), False, True),
        ("key order only", tamper(swap_first_keys), False, True),
    ]
    for label, disk_text, want_error, want_warning in expectations:
        errs, warns = compare_texts(disk_text, text)
        if bool(errs) != want_error or (want_warning is not None and bool(warns) != want_warning):
            failures.append("%s: errors=%r warnings=%r" % (label, errs[:2], warns[:2]))
    require(json.loads(text) == base, "regression mutated its input")
    return failures, len(expectations)


def summarize(texts):
    lines = []
    for pid, text in texts.items():
        doc = json.loads(text)
        lines.append("%s: %d positive, %d negative" % (pid, len(doc["positive"]),
                                                        len(doc["negative"])))
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


def main(argv):
    args = list(argv)
    repo_root = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", ".."))
    out_dir = None
    mode = "write"
    while args:
        a = args.pop(0)
        if a == "--repo-root":
            repo_root = os.path.abspath(args.pop(0))
        elif a == "--out-dir":
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
    setup_fixtures()
    cross_checks()
    for kind, builder in BUILDERS:
        _BASELINE_CASES[builder.__name__] = builder()
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
    if mode in ("check", "self-test"):
        regression, total = check_regression(texts)
        for f in regression:
            print("check-regression FAILED: " + f)
        print("check-regression: %d tampered copies, %d judged correctly"
              % (total, total - len(regression)))
        if regression:
            return 1
    if mode == "check":
        bad = 0
        for pid, text in texts.items():
            path = os.path.join(out_dir, pid + ".json")
            errors, warnings = compare_files(path, text)
            for w in warnings:
                print("%s: warning: %s" % (path, w))
            for e in errors:
                print("%s: DIFFERS: %s" % (path, e))
            if not errors:
                print("%s: %s" % (path, "identical" if not warnings else
                                  "cases identical (provenance warnings only)"))
            bad += 1 if errors else 0
        return 1 if bad else 0
    results = self_test(repo_root, texts)
    survived = 0
    for name, desc, changed in results:
        status = "KILLED" if changed else "SURVIVED"
        survived += 0 if changed else 1
        detail = ", ".join("%s: %d case(s)" % kv for kv in sorted(changed.items()))
        print("mutation %-40s %-8s %s  [%s]" % (name, status, desc, detail))
    print("self-test: %d mutations, %d killed, %d survived"
          % (len(results), len(results) - survived, survived))
    return 1 if survived else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except PinError as exc:
        sys.stderr.write("FAILED: %s\n" % exc)
        sys.exit(1)
