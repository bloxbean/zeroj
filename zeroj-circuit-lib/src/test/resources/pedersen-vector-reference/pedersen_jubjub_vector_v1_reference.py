#!/usr/bin/env python3
"""Independent reference implementation of the ZeroJ profile `pedersen-jubjub-vector-v1`.

Written only from:
  docs/specs/pedersen-jubjub-vector-v1.md   (the profile under test, normative)
  docs/specs/pedersen-jubjub-v1.md          (§1 curve constants and §4 point encoding,
                                             which the vector profile incorporates; its pinned
                                             G, H and §8 vector are used as extra cross-checks)

No ZeroJ source code was read. Standard library only (hashlib for BLAKE2s and SHA-256).

Usage:  python3 pedersen_jubjub_vector_v1_reference.py
Prints key=value lines and writes the same lines, with a '#' header, to reference-output.txt
next to this script. Exit status 0 iff every spec-pinned value matched and every check held.
See README.md for the output format.
"""

import hashlib
import os
import platform
import sys

# ---------------------------------------------------------------------------
# Curve and field: pedersen-jubjub-v1 §1
# ---------------------------------------------------------------------------

P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001  # base field = BLS12-381 Fr
L = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7  # prime-order subgroup order
A = P - 1  # twisted Edwards a = -1
D = 0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1
COFACTOR = 8
IDENTITY = (0, 1)


# ---------------------------------------------------------------------------
# Field arithmetic mod P
# ---------------------------------------------------------------------------

def f_inv(x):
    x %= P
    if x == 0:
        raise ZeroDivisionError("inverse of zero in F_p")
    return pow(x, P - 2, P)  # Fermat


def f_is_square(x):
    x %= P
    return x == 0 or pow(x, (P - 1) // 2, P) == 1  # Euler's criterion


def _tonelli_shanks_setup():
    q, s = P - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (P - 1) // 2, P) != P - 1:
        z += 1
    return q, s, z


_TS_Q, _TS_S, _TS_Z = _tonelli_shanks_setup()


def f_sqrt(x):
    """Some square root of x mod P, or None if x is a non-square (Tonelli-Shanks)."""
    x %= P
    if x == 0:
        return 0
    if not f_is_square(x):
        return None
    m = _TS_S
    c = pow(_TS_Z, _TS_Q, P)
    t = pow(x, _TS_Q, P)
    r = pow(x, (_TS_Q + 1) // 2, P)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % P
            i += 1
        b = pow(c, 1 << (m - i - 1), P)
        m, c, t, r = i, b * b % P, t * b % P * b % P, r * b % P
    if r * r % P != x:
        raise ArithmeticError("square root self-check failed")
    return r


# ---------------------------------------------------------------------------
# Jubjub affine arithmetic (complete unified twisted Edwards addition)
# ---------------------------------------------------------------------------

def on_curve(pt):
    u, v = pt
    if not (0 <= u < P and 0 <= v < P):
        return False
    uu, vv = u * u % P, v * v % P
    return (A * uu + vv - 1 - D * uu % P * vv) % P == 0


def pt_add(p1, p2):
    u1, v1 = p1
    u2, v2 = p2
    t = D * u1 % P * u2 % P * v1 % P * v2 % P
    u3 = (u1 * v2 + v1 * u2) * f_inv(1 + t) % P
    v3 = (v1 * v2 - A * u1 * u2) * f_inv(1 - t) % P
    return (u3, v3)


def pt_double(pt):
    return pt_add(pt, pt)


def pt_mul(k, pt):
    """[k]pt for an integer k >= 0, MSB-first double-and-add."""
    if k < 0:
        raise ValueError("negative scalar")
    acc = IDENTITY
    for bit in bin(k)[2:]:
        acc = pt_double(acc)
        if bit == "1":
            acc = pt_add(acc, pt)
    return acc


def clear_cofactor(pt):
    return pt_double(pt_double(pt_double(pt)))  # [8]pt


def in_prime_subgroup(pt):
    return pt_mul(L, pt) == IDENTITY


# ---------------------------------------------------------------------------
# Point encoding: pedersen-jubjub-v1 §4 (ZIP 216 strict decode)
# ---------------------------------------------------------------------------

class PointDecodeError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def pt_encode(pt):
    u, v = pt
    out = bytearray(v.to_bytes(32, "little"))
    if u & 1:
        out[31] |= 0x80
    return bytes(out)


def pt_decode(data):
    if len(data) != 32:
        raise PointDecodeError("length")
    sign = data[31] >> 7
    v = int.from_bytes(data, "little") & ((1 << 255) - 1)
    if v >= P:
        raise PointDecodeError("v_not_canonical")
    vv = v * v % P
    den = (D * vv + 1) % P
    if den == 0:
        raise PointDecodeError("denominator_zero")
    w = (vv - 1) * f_inv(den) % P
    u = f_sqrt(w)
    if u is None:
        raise PointDecodeError("not_square")
    if u == 0 and sign == 1:
        raise PointDecodeError("zip216_zero_u_with_sign")
    if (u & 1) != sign:
        u = P - u
    return (u, v)


# ---------------------------------------------------------------------------
# Group hash: vector spec §1 (Zcash GroupHash^J / FindGroupHash^J)
# ---------------------------------------------------------------------------

URS = b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0"
GH_COUNTER_MAX = 254


class FindGroupHashFailure(Exception):
    pass


def blake2s_256(personalisation, data):
    if len(personalisation) != 8:
        raise ValueError("BLAKE2s personalisation must be exactly 8 bytes")
    return hashlib.blake2s(data, digest_size=32, person=personalisation).digest()


def group_hash(personalisation, message, decode=pt_decode):
    h = blake2s_256(personalisation, URS + message)
    try:
        pt = decode(h)
    except PointDecodeError:
        return None
    q = clear_cofactor(pt)
    if q == IDENTITY:
        return None
    return q


def find_group_hash(personalisation, message, gh=group_hash):
    """Returns (point, counter)."""
    for j in range(0, GH_COUNTER_MAX + 1):
        q = gh(personalisation, message + bytes([j]))
        if q is not None:
            return q, j
    raise FindGroupHashFailure("no point for counters 0..254")


def le32(i):
    return i.to_bytes(4, "little")


# ---------------------------------------------------------------------------
# Profile: bases (§2) and commitment (§3)
# ---------------------------------------------------------------------------

D_PV = b"ZeroJ_PV"
N_MAX = 16


def derive_bases():
    gs = [find_group_hash(D_PV, le32(i)) for i in range(N_MAX)]
    hv = find_group_hash(D_PV, b"r")
    return gs, hv


def commit(values, r, bases_g, h_v):
    n = len(values)
    if not 1 <= n <= N_MAX:
        raise ValueError("dimension out of range")
    acc = IDENTITY
    for i in range(n):
        acc = pt_add(acc, pt_mul(values[i] % L, bases_g[i]))
    return pt_add(acc, pt_mul(r % L, h_v))


# ---------------------------------------------------------------------------
# Vector schema: §4.1 encoding, strict decoder, §4.2 digest
# ---------------------------------------------------------------------------

SCHEMA_TAG = "pedersen-jubjub-vector-v1".encode("utf-8") + b"\x00"
_LOWER_DIGIT = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789")
_NAME_CHARS = _LOWER_DIGIT | frozenset(b"._-")


class SchemaError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _check_id(sid):
    if not 1 <= len(sid) <= 64:
        raise SchemaError("id_length")
    if any(c not in _NAME_CHARS for c in sid):
        raise SchemaError("id_bad_char")
    if sid[0] not in _LOWER_DIGIT:
        raise SchemaError("id_bad_first_char")


def _check_label(label):
    if not 1 <= len(label) <= 32:
        raise SchemaError("label_length")
    if any(c not in _NAME_CHARS for c in label):
        raise SchemaError("label_bad_char")


def _check_width(k):
    if not 1 <= k <= 252:
        raise SchemaError("width_range")


def schema_encode(sid, version, entries):
    """entries: list of (label bytes, width int) in index order."""
    _check_id(sid)
    if not 0 <= version <= 0xFFFF:
        raise SchemaError("version_range")
    if not 1 <= len(entries) <= N_MAX:
        raise SchemaError("n_range")
    out = bytearray(SCHEMA_TAG)
    out.append(len(sid))
    out += sid
    out += version.to_bytes(2, "big")
    out.append(len(entries))
    seen = set()
    for label, width in entries:
        _check_width(width)
        _check_label(label)
        if label in seen:
            raise SchemaError("duplicate_label")
        seen.add(label)
        out.append(width)
        out.append(len(label))
        out += label
    return bytes(out)


class _Reader:
    def __init__(self, data, pos):
        self.data = data
        self.pos = pos

    def take(self, n):
        if self.pos + n > len(self.data):
            raise SchemaError("truncated")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self):
        return self.take(1)[0]


def schema_decode(data):
    """Strict decoder. Returns (id, version, entries) or raises SchemaError(reason).

    Fields are checked in wire order; the first violation found is the reason reported.
    """
    tag_len = len(SCHEMA_TAG)
    if data[:tag_len] != SCHEMA_TAG:
        if len(data) < tag_len and SCHEMA_TAG.startswith(data):
            raise SchemaError("truncated")
        raise SchemaError("bad_tag")
    rd = _Reader(data, tag_len)
    id_len = rd.u8()
    if not 1 <= id_len <= 64:
        raise SchemaError("id_length")
    sid = rd.take(id_len)
    _check_id(sid)
    version = int.from_bytes(rd.take(2), "big")
    n = rd.u8()
    if not 1 <= n <= N_MAX:
        raise SchemaError("n_range")
    entries = []
    seen = set()
    for _ in range(n):
        width = rd.u8()
        _check_width(width)
        label_len = rd.u8()
        if not 1 <= label_len <= 32:
            raise SchemaError("label_length")
        label = rd.take(label_len)
        _check_label(label)
        if label in seen:
            raise SchemaError("duplicate_label")
        seen.add(label)
        entries.append((label, width))
    if rd.pos != len(data):
        raise SchemaError("trailing_bytes")
    return sid, version, entries


def schema_digest(encoding):
    return int.from_bytes(hashlib.sha256(encoding).digest(), "big") % P


def raw_schema(sid, version, entries, tag=SCHEMA_TAG, n=None):
    """Lays out schema bytes WITHOUT validation (used to build negative vectors)."""
    out = bytearray(tag)
    out.append(len(sid))
    out += sid
    out += version.to_bytes(2, "big")
    out.append(len(entries) if n is None else n)
    for label, width in entries:
        out.append(width)
        out.append(len(label))
        out += label
    return bytes(out)


# ---------------------------------------------------------------------------
# Spec-pinned values
# ---------------------------------------------------------------------------

# pedersen-jubjub-v1 §2 (used only to check distinctness and as arithmetic cross-checks)
PJV1_G_FULL = (0x62EDCBB8BF3787C88B0F03DDD60A8187CAF55D1B29BF81AFE4B3D35DF1A7ADFE, 11)
PJV1_G = (0x3EA5C4673A121CA35ED37EE3B172F5EE04315C657FBE375F512DFEA318D56FE5,
          0x57137B83EA6EDB4F78F7D30D3F616CB3B9AA6E8E40808413C10CEA38D50C55CB)
PJV1_G_ENC = "cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7"
PJV1_H = (0x72963E7766B3CD553A1525A17DA810E6B4CDEB70541DAC5B52A3210F5C372DB6,
          0x60BB97D81759E04503194AEB9EB8FAA23B0092C941D1139BFE99907794C8E37D)
PJV1_H_ENC = "7de3c894779099fe9b13d141c992003ba2fab89eeb4a190345e05917d897bb60"
PJV1_C42 = (0x478A0BD6A0EEBDFFC610618AD979B39D6237F240125534886D38720CBD76A025,
            0x6387C33BE7B7177B74CE909592456D7C81DAB375A6BA3182EB7F5E2974E0D357)
PJV1_C42_ENC = "57d3e074295e7feb8231baa675b3da817c6d45929590ce747b17b7e73bc387e3"

# vector spec §1.1: (key, D, M, counter, u, v)
ZCASH_KATS = [
    ("value_commitment_value_generator", b"Zcash_cv", b"v", 0,
     0x273F910D9ECC1615D8618ED1D15FEF4E9472C89AC043042D36183B2CB4D7EF51,
     0x466A7E3A82F67AB1D32294FD89774AD6BC3332D0FA1CCD18A77A81F50667C8D7),
    ("value_commitment_randomness_generator", b"Zcash_cv", b"r", 0,
     0x6800F4FA0F001CFC7FF6826AD58004B4D1D8DA41AF03744E3BCE3B7793664337,
     0x6D81D3A9CB45DEDBE6FB2A6E1E22AB50AD46F1B0473B803B3CAEFAB9380B6A8B),
    ("note_commitment_randomness_generator", b"Zcash_PH", b"r", 4,
     0x26EB9F8A9EC72A8CA1409AA1F33BEC2CF0919D06FFB1ECDAA5143B34A8E36462,
     0x114B7501AD104C57949D77476E262C9596B78BEAFA9CC44CD4FC6365796C77AC),
    ("pedersen_hash_generators_0", b"Zcash_PH", le32(0), 5,
     0x73C016A42DED9578B5EA25DE7EC0E3782F0C718F6F0FBADD194E42926F661B51,
     0x289E87A2D3521B5779C9166B837EDC5EF9472E8BC04E463277BFABD432243CCA),
    ("pedersen_hash_generators_1", b"Zcash_PH", le32(1), 0,
     0x15A36D1F0F390D8852A35A8C1908DD87A361EE3FD48FDF77B9819DC82D90607E,
     0x015D8C7F5B43FE33F7891142C001D9251F3ABEEB98FAD3E87B0DC53C4EBF1891),
    ("pedersen_hash_generators_2", b"Zcash_PH", le32(2), 0,
     0x664321A58246E2F6EB69AE39F5C84210BAE8E5C46641AE5C76D6F7C2B67FC475,
     0x362E1500D24EEE9EE000A46C8E8CE8538BB22A7F1784B49880ED502C9793D457),
    ("pedersen_hash_generators_3", b"Zcash_PH", le32(3), 0,
     0x323A6548CE9D9876EDC5F4A9CFF29FD57D02D50E654B87F24C767804C1C4A2CC,
     0x2F7EE40C4B56CAD891070ACBD8D947B75103AFA1A11F6A8584714BECA33570E9),
    ("pedersen_hash_generators_4", b"Zcash_PH", le32(4), 0,
     0x3BD2666000B5479689B64B4E03362796EFD5931305F2F0BF46809430657F82D1,
     0x494BC52103AB9D0A397832381406C9E5B3B9D8095859D14C99968299C3658AEF),
    ("pedersen_hash_generators_5", b"Zcash_PH", le32(5), 0,
     0x63447B2BA31BB28ADA049746D76D3EE51D9E5CA21135FF6FCB3C023258D32079,
     0x64EC4689E8BFB6E564CDB1070A136A28A80200D2C66B13A7436082119F8D629A),
    ("spending_key_generator", b"Zcash_G_", b"", 2,
     0x0926D4F32059C712D418A7FF26753B6AD5B9A7D3EF8E282747BF46920A95A753,
     0x57A1019E6DE9B67553BB37D0C21CFD056D65674DCEDBDDBC305632ADAAF2B530),
    ("proof_generation_key_generator", b"Zcash_H_", b"", 1,
     0x1457A50231CDE2DF704303F1E8906081ADF2D038F2FBB8203AF2DBEFB96E2571,
     0x54B6D10718DF2A7ADEC901840F4948CC50DF51EAF5A149D2467AF9F7E05DE8E7),
    ("nullifier_position_generator", b"Zcash_J_", b"", 1,
     0x2400C2E2E3362644DB56B6DB8D8075EDE81CEE09A561229E2CE33921888D30DB,
     0x61369D5440BF84A5FC9E8A15A096BA8FE155B8E8FFFF2E42A3F7FA36C72B0065),
]

# vector spec §2: (name, counter, u, v, encode)
BASE_TABLE = [
    ("G_0", 2, 0x205BD2FBEE3A4C6CE5D86E1920570E03BC56A7022824B699F52C1C995BC219CD,
     0x198D9863B0BCA88CA66FDB18401979ACFBE41FB895FBA4B1651AA01899814063,
     "6340819918a01a65b1a4fb95b81fe4fbac79194018db6fa68ca8bcb063988d99"),
    ("G_1", 1, 0x4E02F0535DC84503F2188554692A83C5153081B0B3C28B5C2375783D3AD0B476,
     0x18AFA800D969A6C757412D84D3284CFBE86990F6E4AC160271500DC908DCB31C,
     "1cb3dc08c90d50710216ace4f69069e8fb4c28d3842d4157c7a669d900a8af18"),
    ("G_2", 1, 0x2ADE969EB6C2C98E405C91CBE90CBC8FBF1864C8EAD95251B5D21DDF3E46ED2C,
     0x0E716ED2CF186AA591AA9331AE9BEC5FBED8F030D5CD22D73327FC256E1B3495,
     "95341b6e25fc2733d722cdd530f0d8be5fec9bae3193aa91a56a18cfd26e710e"),
    ("G_3", 0, 0x2CE6D5B335F6CDD1FDD6BE89FBF1AB0D95A61FA9563E19BC617DF9B9B70FCCCC,
     0x44D41301A7FA84FEA9B7AEA46982062ABF0AFB636196EB22A9C37915809C66B0,
     "b0669c801579c3a922eb966163fb0abf2a068269a4aeb7a9fe84faa70113d444"),
    ("G_4", 1, 0x3DD1F3A1F9F3218B7C49B8F469B605AE4BB58856DF54477FBF0F3B85E482096A,
     0x3F7B9652FAEE7C79B1E4ABEBD1B398A5742AF0DC41B073AAEEAE25656FC7B272,
     "72b2c76f6525aeeeaa73b041dcf02a74a598b3d1ebabe4b1797ceefa52967b3f"),
    ("G_5", 0, 0x41CCA7BE1D0DECF9AF9659D8D20A5564345859C3AA991C0D4CBB45105CB851E4,
     0x13901AB53C6DAB65341A6F592923DE467F32E70D70A76CBEC9AC3B93EDEE3E2C,
     "2c3eeeed933bacc9be6ca7700de7327f46de2329596f1a3465ab6d3cb51a9013"),
    ("G_6", 3, 0x3923FBC5240948F5EFA9BF0B57CEBA7DA7BA30E004ED820DB7F12DFE86BFADB4,
     0x0DA742AECC54316B7B1DBD6DEAFF5148A3962E3C4099AC5781FE26A9490B430F,
     "0f430b49a926fe8157ac99403c2e96a34851ffea6dbd1d7b6b3154ccae42a70d"),
    ("G_7", 0, 0x3B40A4262C7D1B97A3A72BBCBDA882FFB7A529E2145E7139A8DE2791B955A72C,
     0x25DC303CF8713EEC63506ED2601122297224D9C342ECE2686C10EA01EE86241A,
     "1a2486ee01ea106c68e2ec42c3d9247229221160d26e5063ec3e71f83c30dc25"),
    ("G_8", 1, 0x6E18437FDFC7340F81E71C9D19E59A44827ADE01E54ABA3C0A14F68618A07D95,
     0x3FB405B55B3F2D600A6BFC2F88A92AF6C425173D0D7CF329ABAEE3A32C514643,
     "4346512ca3e3aeab29f37c0d3d1725c4f62aa9882ffc6b0a602d3f5bb505b4bf"),
    ("G_9", 3, 0x3C653E6B470268A5C5024C6AFD3668FEF4387469C086E54073E981956BF67F6B,
     0x141919C7C72C1A39EE95E665A314BF0F51F9D240E67A04CF44855565F3EB2B2D,
     "2d2bebf365558544cf047ae640d2f9510fbf14a365e695ee391a2cc7c7191994"),
    ("G_10", 1, 0x1EDCBD164E09B7A1A29CB90F892EB41AE2F3047197BB896C55B17524B6C56CA0,
     0x453E79A85942DC545AA75647B7679D9EED80A249BCB8D27D212B7AE29FB58ECB,
     "cb8eb59fe27a2b217dd2b8bc49a280ed9e9d67b74756a75a54dc4259a8793e45"),
    ("G_11", 0, 0x46217B4002CDC01EF2BFD29604C5CA3FF99F891C2F0E92A36E964EB2B9D2D490,
     0x0D85850A30916E2724EA60F51E136635BEA94286507523B9E820F2497F699871,
     "7198697f49f220e8b92375508642a9be3566131ef560ea24276e91300a85850d"),
    ("G_12", 0, 0x3A10CD28295EC714214C39BC4C67C91C594E7DCBA8F2889F27964FF3C595ED01,
     0x63B66EC90CE4ED01A85EC01D80ED14CF54E03FEAF8EFA010EC93CC28206BB77B,
     "7bb76b2028cc93ec10a0eff8ea3fe054cf14ed801dc05ea801ede40cc96eb6e3"),
    ("G_13", 0, 0x126F5E93926D05326023E31F332A85A5440337AF361D486DA32629EF756659C6,
     0x602458F2C4708BD3F3A311AA243BD35AE9D3266BFB669D43D712A701CA64BC76,
     "76bc64ca01a712d7439d66fb6b26d3e95ad33b24aa11a3f3d38b70c4f2582460"),
    ("G_14", 0, 0x0B8A62A6D1AB30AA503EACCFFFE8886185699A8EFCABC02F1CD60F69DEF66358,
     0x184DBA5D05A379B5C133004A6C97D8831381EAA871E99BD3F2015F1D80665D57,
     "575d66801d5f01f2d39be971a8ea811383d8976c4a0033c1b579a3055dba4d18"),
    ("G_15", 3, 0x1DACE0AF9586EA8EEAE2AB9BA2FF30A562E8339726708E4A7B630A54603E2412,
     0x1D6C1121E30CF03F24E0459083BC4EA8B11DA6EE2F6F224D8B298DB9AEAB169F,
     "9f16abaeb98d298b4d226f2feea61db1a84ebc839045e0243ff00ce321116c1d"),
    ("H_V", 0, 0x55DCBA07BDEE766192D665CB67368BED334B2A598E9F16CF56A95C75F862D553,
     0x3BAE3B23568241DF571D423838DC54B23EC96650DB57F4AD64F3BCE1F5481C75,
     "751c48f5e1bcf364adf457db5066c93eb254dc3838421d57df418256233baebb"),
]

# vector spec §3.1
C_1000_7_U = 0x4CE6F49EEC1E5FC89B3D3FC3932C6F6823C240E21A19BB89B580304CB7ED1D36
C_1000_7_V = 0x4306903AEB81CC5B6A5AC517FA9E48A7DBCAB0B6920EF58CFB7EF85F569C48B8
C_1000_7_ENC = "b8489c565ff87efb8cf50e92b6b0cadba7489efa17c55a6a5bcc81eb3a900643"
C_1000_ENC = "258119dd13e51c79d80b108918c6bc3d2117b83eb0a9068e4ce8b158d7a1ffe7"

# vector spec §4.3: (key, id, version, entries, full encode or None, shown suffix or None, digest)
BALANCE_ID = b"zeroj.example.balance"
SCHEMA_VECTORS = [
    ("balance_v1", BALANCE_ID, 1, [(b"amount", 64), (b"asset", 32)],
     "706564657273656e2d6a75626a75622d766563746f722d763100157a65726f6a2e6578616d706c652e"
     "62616c616e63650001024006616d6f756e7420056173736574",
     None, 0x26A0F201BD5AF51641A74A2B9193D2A361DFA1B629E358F99AE97FF72FE2870D),
    ("balance_v2", BALANCE_ID, 2, [(b"amount", 64), (b"asset", 32)],
     None, "0002024006616d6f756e7420056173736574",
     0x1ACBC92525173B9BE489F9EAC5DF349CCCF41DB6A9343D5D8BD2CDC695146857),
    ("balance_v1_labels_swapped", BALANCE_ID, 1, [(b"asset", 64), (b"amount", 32)],
     None, "000102400561737365742006616d6f756e74",
     0x31EC633914DFF2BCDA6E69D694320B168A556D0DE3377B5AA53AABFC5169E7A2),
    ("balance_v1_asset_width_33", BALANCE_ID, 1, [(b"amount", 64), (b"asset", 33)],
     None, "0001024006616d6f756e7421056173736574",
     0x1260C5C7D40C4B2EF61CC43A2B1210006546E6DA4E4EFF625000C785EDD9C6D8),
]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def fe(x):
    return "0x%064x" % x


def hx(x):
    return "0x%x" % x


def tf(b):
    return "true" if b else "false"


class Report:
    def __init__(self):
        self.lines = []
        self.failures = []

    def put(self, key, value):
        self.lines.append("%s=%s" % (key, value))

    def check(self, name, ok):
        self.put("check_" + name, tf(ok))
        if not ok:
            self.failures.append("check_" + name)

    def pin(self, name, computed, expected, fmt):
        ok = computed == expected
        self.put("spec_match_" + name, tf(ok))
        if not ok:
            self.failures.append("spec_match_%s: computed %s, spec %s"
                                 % (name, fmt(computed), fmt(expected)))

    def point(self, prefix, pt):
        self.put(prefix + "_u", fe(pt[0]))
        self.put(prefix + "_v", fe(pt[1]))
        self.put(prefix + "_encode", pt_encode(pt).hex())


def _decode_reason(data):
    try:
        pt_decode(data)
    except PointDecodeError as e:
        return e.reason
    return None


def _schema_reason(data):
    try:
        schema_decode(data)
    except SchemaError as e:
        return e.reason
    return None


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def section_constants(rep):
    rep.put("const_p", hx(P))
    rep.put("const_l", hx(L))
    rep.put("const_d", fe(D))
    rep.put("const_cofactor", hx(COFACTOR))
    rep.put("const_urs", URS.hex())
    rep.put("const_gh_counter_max", hx(GH_COUNTER_MAX))
    rep.put("const_d_pv", D_PV.hex())
    rep.put("const_n_max", hx(N_MAX))
    rep.put("const_schema_tag", SCHEMA_TAG.hex())
    # Completeness of the addition law and pedersen-jubjub-v1 §4 rule 3 rest on these.
    rep.check("curve_minus_one_is_square", f_is_square(P - 1))
    rep.check("curve_d_is_nonsquare", not f_is_square(D))
    rep.check("curve_dv2_plus_1_never_zero", not f_is_square((P - 1) * f_inv(D)))


def section_pjv1_crosscheck(rep):
    """pedersen-jubjub-v1 pinned values: exercises this file's arithmetic and encoding."""
    rep.check("pjv1_G_full_on_curve", on_curve(PJV1_G_FULL))
    g = clear_cofactor(PJV1_G_FULL)
    rep.pin("pjv1_G_u", g[0], PJV1_G[0], fe)
    rep.pin("pjv1_G_v", g[1], PJV1_G[1], fe)
    rep.pin("pjv1_G_encode", pt_encode(PJV1_G).hex(), PJV1_G_ENC, str)
    rep.pin("pjv1_H_encode", pt_encode(PJV1_H).hex(), PJV1_H_ENC, str)
    rep.check("pjv1_H_on_curve", on_curve(PJV1_H))
    rep.check("pjv1_G_in_subgroup", in_prime_subgroup(PJV1_G))
    rep.check("pjv1_H_in_subgroup", in_prime_subgroup(PJV1_H))
    rep.check("curve_l_does_not_annihilate_G_full", pt_mul(L, PJV1_G_FULL) != IDENTITY)
    rep.check("curve_8l_annihilates_G_full", pt_mul(COFACTOR * L, PJV1_G_FULL) == IDENTITY)
    c42 = pt_add(pt_mul(42, PJV1_G), pt_mul(12345, PJV1_H))
    rep.point("pjv1_commit_42_12345", c42)
    rep.pin("pjv1_commit_42_12345_u", c42[0], PJV1_C42[0], fe)
    rep.pin("pjv1_commit_42_12345_v", c42[1], PJV1_C42[1], fe)
    rep.pin("pjv1_commit_42_12345_encode", pt_encode(c42).hex(), PJV1_C42_ENC, str)


def section_point_decoding(rep):
    """pedersen-jubjub-v1 §4 rejection rules and canonical round trips."""
    nonsq_v = 2
    while True:
        vv = nonsq_v * nonsq_v % P
        if not f_is_square((vv - 1) * f_inv(D * vv + 1)):
            break
        nonsq_v += 1
    p_le = P.to_bytes(32, "little")
    neg = [
        ("length_31", bytes(31), "length"),
        ("length_33", bytes(33), "length"),
        ("v_equals_p", p_le, "v_not_canonical"),
        ("v_equals_p_sign_set", p_le[:31] + bytes([p_le[31] | 0x80]), "v_not_canonical"),
        ("v_max_255_bit", b"\xff" * 31 + b"\x7f", "v_not_canonical"),
        ("not_square", nonsq_v.to_bytes(32, "little"), "not_square"),
        ("zero_u_sign_set_v_1", (1).to_bytes(32, "little")[:31] + b"\x80", "zip216_zero_u_with_sign"),
        ("zero_u_sign_set_v_minus_1",
         (P - 1).to_bytes(32, "little")[:31] + bytes([(P - 1).to_bytes(32, "little")[31] | 0x80]),
         "zip216_zero_u_with_sign"),
    ]
    for name, data, reason in neg:
        got = _decode_reason(data)
        rep.put("point_decode_neg_%s_input" % name, data.hex())
        rep.put("point_decode_neg_%s_reason" % name, reason)
        rep.check("point_decode_neg_%s_rejected" % name, got == reason)

    ident_enc = pt_encode(IDENTITY)
    rep.put("point_identity_encode", ident_enc.hex())
    rep.check("point_identity_decode_roundtrip", _safe_decode(ident_enc) == IDENTITY)
    order2 = (0, P - 1)
    order2_enc = pt_encode(order2)
    dec = _safe_decode(order2_enc)
    rep.put("point_order2_encode", order2_enc.hex())
    rep.check("point_order2_decodes", dec == order2)
    rep.check("point_order2_not_in_subgroup", dec is not None and not in_prime_subgroup(dec))
    # Sign bit selects u parity: flipping it on a valid encoding yields the negated point.
    g_enc = bytes.fromhex(PJV1_G_ENC)
    flipped = g_enc[:31] + bytes([g_enc[31] ^ 0x80])
    rep.check("point_sign_flip_negates", _safe_decode(flipped) == ((P - PJV1_G[0]) % P, PJV1_G[1]))


def _safe_decode(data):
    try:
        return pt_decode(data)
    except PointDecodeError:
        return None


def section_group_hash_structure(rep):
    """Exercises GroupHash's bottom/identity branches with stub decoders, and FindGroupHash's
    counter loop with stub group hashes. These branches are not reached by real inputs."""
    def decodes_to(pt):
        return lambda _h: pt

    def rejects(_h):
        raise PointDecodeError("stub")

    order4 = (f_sqrt(P - 1), 0)
    order2 = (0, P - 1)
    rep.check("grouphash_order4_point_on_curve", on_curve(order4))
    rep.check("grouphash_decode_failure_gives_bottom",
              group_hash(b"selftest", b"m", decode=rejects) is None)
    rep.check("grouphash_order2_clears_to_identity_gives_bottom",
              group_hash(b"selftest", b"m", decode=decodes_to(order2)) is None)
    rep.check("grouphash_order4_clears_to_identity_gives_bottom",
              group_hash(b"selftest", b"m", decode=decodes_to(order4)) is None)
    rep.check("grouphash_clears_cofactor",
              group_hash(b"selftest", b"m", decode=decodes_to(PJV1_G_FULL)) == PJV1_G)

    seen = []

    def never(pers, msg):
        seen.append(msg)
        return None

    failed = False
    try:
        find_group_hash(b"selftest", b"msg", gh=never)
    except FindGroupHashFailure:
        failed = True
    rep.check("findgrouphash_tries_counters_0_to_254_appended",
              seen == [b"msg" + bytes([j]) for j in range(255)])
    rep.check("findgrouphash_fails_after_counter_254", failed)

    marker = (123, 456)

    def only_last(pers, msg):
        return marker if msg == b"msg" + bytes([254]) else None

    try:
        res = find_group_hash(b"selftest", b"msg", gh=only_last)
    except FindGroupHashFailure:
        res = None
    rep.check("findgrouphash_accepts_counter_254", res == (marker, 254))


def section_zcash_kats(rep):
    for key, pers, msg, counter, u, v in ZCASH_KATS:
        pt, j = find_group_hash(pers, msg)
        pre = "zcash_" + key
        rep.put(pre + "_personalisation", pers.hex())
        rep.put(pre + "_message", msg.hex())
        rep.put(pre + "_counter", hx(j))
        rep.point(pre, pt)
        rep.pin(pre + "_counter", j, counter, hx)
        rep.pin(pre + "_u", pt[0], u, fe)
        rep.pin(pre + "_v", pt[1], v, fe)


def section_bases(rep):
    gs, hv = derive_bases()
    derived = [(("G_%d" % i), gs[i]) for i in range(N_MAX)] + [("H_V", hv)]
    table = {row[0]: row for row in BASE_TABLE}
    points = []
    for name, (pt, j) in derived:
        _, counter, u, v, enc = table[name]
        pre = "base_" + name
        rep.put(pre + "_counter", hx(j))
        rep.point(pre, pt)
        rep.pin(pre + "_counter", j, counter, hx)
        rep.pin(pre + "_u", pt[0], u, fe)
        rep.pin(pre + "_v", pt[1], v, fe)
        rep.pin(pre + "_encode", pt_encode(pt).hex(), enc, str)
        rep.check(pre + "_on_curve", on_curve(pt))
        rep.check(pre + "_in_subgroup", in_prime_subgroup(pt))
        rep.check(pre + "_not_identity", pt != IDENTITY)
        rep.check(pre + "_spec_encode_decodes_to_spec_point",
                  _safe_decode(bytes.fromhex(enc)) == (u, v))
        points.append(pt)
    rep.check("bases_pairwise_distinct", len(set(points)) == len(points))
    rep.check("bases_distinct_from_pjv1_G_H",
              all(pt not in (PJV1_G, PJV1_H) for pt in points))
    return [pt for pt, _ in gs], hv[0]


def section_commitments(rep, gs, hv):
    def c(values, r):
        return commit(values, r, gs, hv)

    c17 = c([1000, 7], 12345)
    rep.point("commit_1000_7_r12345", c17)
    rep.pin("commit_1000_7_r12345_u", c17[0], C_1000_7_U, fe)
    rep.pin("commit_1000_7_r12345_v", c17[1], C_1000_7_V, fe)
    rep.pin("commit_1000_7_r12345_encode", pt_encode(c17).hex(), C_1000_7_ENC, str)

    c1 = c([1000], 12345)
    c10 = c([1000, 0], 12345)
    rep.point("commit_1000_r12345", c1)
    rep.point("commit_1000_0_r12345", c10)
    rep.pin("commit_1000_r12345_encode", pt_encode(c1).hex(), C_1000_ENC, str)
    rep.pin("commit_1000_0_r12345_encode", pt_encode(c10).hex(), C_1000_ENC, str)
    rep.check("commit_zero_padding_equal", c1 == c10)

    for n in (1, 16):
        z = c([0] * n, 0)
        rep.point("commit_zero_n%d_r0" % n, z)
        rep.check("commit_zero_n%d_r0_is_identity" % n, z == IDENTITY)

    seq = list(range(1, 17))
    r_seq = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCD % L
    cs = c(seq, r_seq)
    rep.put("commit_seq16_values", ",".join(hx(x) for x in seq))
    rep.put("commit_seq16_r", hx(r_seq))
    rep.point("commit_seq16", cs)
    rep.check("commit_seq16_in_subgroup", in_prime_subgroup(cs))

    ca = c([3, 4], 5)
    cb = c([10, 20], 30)
    csum = c([13, 24], 35)
    rep.point("commit_hom_a_3_4_r5", ca)
    rep.point("commit_hom_b_10_20_r30", cb)
    rep.point("commit_hom_13_24_r35", csum)
    rep.check("commit_homomorphism", pt_add(ca, cb) == csum)

    # Binding is to residues mod l (spec §3, "x mod l is the least non-negative residue").
    rep.check("commit_residue_reduction",
              c([1000 + L, 7 - L], 12345 + 2 * L) == c17)
    rep.check("commit_negative_inputs_reduce",
              c([-1, -7], -12345) == c([L - 1, L - 7], L - 12345))


def section_schemas(rep):
    full_first = None
    for key, sid, version, entries, full, suffix, digest in SCHEMA_VECTORS:
        enc = schema_encode(sid, version, entries)
        sig = schema_digest(enc)
        pre = "schema_" + key
        rep.put(pre + "_encode", enc.hex())
        rep.put(pre + "_digest", fe(sig))
        if full is not None:
            rep.pin(pre + "_encode", enc.hex(), full, str)
            full_first = bytes.fromhex(full)
        else:
            # The spec elides a prefix with "..."; verify the shown suffix and that the
            # elided part is the corresponding prefix of the fully pinned first vector.
            suf = bytes.fromhex(suffix)
            rep.pin(pre + "_encode_suffix", enc[-len(suf):].hex(), suffix, str)
            elided = enc[:-len(suf)]
            rep.put(pre + "_elided_prefix", elided.hex())
            rep.check(pre + "_elided_prefix_matches_first_vector",
                      full_first is not None and full_first[:len(elided)] == elided)
        rep.pin(pre + "_digest", sig, digest, fe)
        rep.check(pre + "_decode_roundtrip", _schema_decode_or_none(enc) == (sid, version, entries))

    # Boundary-accept vector (not spec-pinned): every field at its maximum.
    alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789._-"
    max_id = (alphabet * 2)[:64]
    max_entries = []
    for i in range(N_MAX):
        label = (b"%02d.label-with_max_length_" % i).ljust(32, b"z")[:32]
        width = 1 if i == 0 else (252 if i == N_MAX - 1 else 16 * i)
        max_entries.append((label, width))
    enc = schema_encode(max_id, 0xFFFF, max_entries)
    rep.put("schema_boundary_max_encode", enc.hex())
    rep.put("schema_boundary_max_digest", fe(schema_digest(enc)))
    rep.check("schema_boundary_max_decode_roundtrip",
              _schema_decode_or_none(enc) == (max_id, 0xFFFF, max_entries))

    # Literal reading of §4: labels have no first-character rule (unlike id). Informational.
    lit_entries = [(b".amount", 64), (b"-asset", 32), (b"_memo", 8)]
    lit = raw_schema(BALANCE_ID, 1, lit_entries)
    rep.put("schema_literal_label_leading_punct_encode", lit.hex())
    rep.put("schema_literal_label_leading_punct_digest", fe(schema_digest(lit)))
    rep.put("schema_literal_label_leading_punct_accepted",
            tf(_schema_decode_or_none(lit) == (BALANCE_ID, 1, lit_entries)))

    base_entries = [(b"amount", 64), (b"asset", 32)]
    base = raw_schema(BALANCE_ID, 1, base_entries)
    seventeen = [(b"e%d" % i, 64) for i in range(17)]
    neg = [
        ("trailing_byte", base + b"\x00", "trailing_bytes"),
        ("wrong_tag", raw_schema(BALANCE_ID, 1, base_entries,
                                 tag=b"pedersen-jubjub-vector-v2\x00"), "bad_tag"),
        ("tag_separator_nonzero", raw_schema(BALANCE_ID, 1, base_entries,
                                             tag=b"pedersen-jubjub-vector-v1\x01"), "bad_tag"),
        ("id_uppercase", raw_schema(b"zeroj.example.Balance", 1, base_entries), "id_bad_char"),
        ("id_leading_dot", raw_schema(b".zeroj.example.balance", 1, base_entries),
         "id_bad_first_char"),
        ("id_empty", raw_schema(b"", 1, base_entries), "id_length"),
        ("id_65_bytes", raw_schema(b"a" * 65, 1, base_entries), "id_length"),
        ("n_0", raw_schema(BALANCE_ID, 1, []), "n_range"),
        ("n_17", raw_schema(BALANCE_ID, 1, seventeen), "n_range"),
        ("width_0", raw_schema(BALANCE_ID, 1, [(b"amount", 0), (b"asset", 32)]), "width_range"),
        ("width_253", raw_schema(BALANCE_ID, 1, [(b"amount", 253), (b"asset", 32)]),
         "width_range"),
        ("duplicate_label", raw_schema(BALANCE_ID, 1, [(b"amount", 64), (b"amount", 32)]),
         "duplicate_label"),
        ("label_33_bytes", raw_schema(BALANCE_ID, 1, [(b"amount", 64), (b"a" * 33, 32)]),
         "label_length"),
        ("label_empty", raw_schema(BALANCE_ID, 1, [(b"amount", 64), (b"", 32)]), "label_length"),
        ("label_uppercase", raw_schema(BALANCE_ID, 1, [(b"Amount", 64), (b"asset", 32)]),
         "label_bad_char"),
        ("truncated", base[:-1], "truncated"),
    ]
    for name, data, reason in neg:
        got = _schema_reason(data)
        rep.put("schema_neg_%s_input" % name, data.hex())
        rep.put("schema_neg_%s_reason" % name, reason)
        rep.check("schema_neg_%s_rejected" % name, got == reason)


def _schema_decode_or_none(data):
    try:
        return schema_decode(data)
    except SchemaError:
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    rep = Report()
    section_constants(rep)
    section_pjv1_crosscheck(rep)
    section_point_decoding(rep)
    section_group_hash_structure(rep)
    section_zcash_kats(rep)
    gs, hv = section_bases(rep)
    section_commitments(rep, gs, hv)
    section_schemas(rep)
    ok = not rep.failures
    rep.put("result", "pass" if ok else "fail")

    header = [
        "# pedersen-jubjub-vector-v1 independent reference output",
        "# Produced by: python3 pedersen_jubjub_vector_v1_reference.py (standard library only),",
        "#   written from docs/specs/pedersen-jubjub-vector-v1.md and docs/specs/pedersen-jubjub-v1.md",
        "#   without reading any ZeroJ implementation. See README.md.",
        "# Format: key=value; field elements 0x + 64 hex; other integers 0x + minimal hex;",
        "#   byte strings bare lowercase hex; checks true/false.",
        "# Python %s" % platform.python_version(),
    ]
    for line in rep.lines:
        print(line)
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference-output.txt")
    with open(out_path, "w", encoding="ascii", newline="\n") as fh:
        fh.write("\n".join(header + rep.lines) + "\n")
    if not ok:
        for f in rep.failures:
            print("MISMATCH " + f, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
