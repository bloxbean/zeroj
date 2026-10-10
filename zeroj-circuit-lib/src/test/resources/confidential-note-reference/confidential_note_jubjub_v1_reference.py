#!/usr/bin/env python3
"""
Independent reference for the ZeroJ profile `confidential-note-jubjub-v1` (ADR-0055, milestone M0).

Written only from:
  - docs/specs/confidential-note-jubjub-v1.md (the spec under test),
  - docs/adr/0055-confidential-notes-jubjub.md (design context),
  - docs/specs/pedersen-jubjub-v1.md (curve, bases G and H, point encoding) and
    docs/specs/elgamal-jubjub-v1.md (§2, §4, §8, §9.1, §12 pins, for D3a),
  - the Zcash protocol specification text (§4.20.2, §5.4.1.2, §5.4.3, §5.4.5.3, §5.4.5.4),
    the BLAKE2 paper (§2.8, Table 1), RFC 7693 and RFC 8439,
  - the vendored vectors in ../standard-vectors/ (zcash-sapling-note-encryption.json),
  - the existing independent Python references: the Jubjub arithmetic and encode/decode here
    are copy-adapted from ../pedersen-reference/pedersen_jubjub_v1_reference.py, which is also
    imported (never modified) to derive H from its Poseidon port, and the output format follows
    ../dkg-share-delivery-reference/.

No Java source was read. Primitives: Python's hashlib (SHA-256, BLAKE2b with `person=`), an
independent pure-Python BLAKE2b written from RFC 7693 and the BLAKE2 paper's parameter block
(used as a differential), and pyca `cryptography`'s ChaCha20Poly1305 (the only third-party
primitive).

Run (from this directory):

    python3 confidential_note_jubjub_v1_reference.py

It prints key=value lines (sorted by key) and rewrites reference-output.txt next to this file.
Exit status 0 iff every check passes; 1 otherwise (the failing keys are listed on stderr).
"""

import sys

sys.dont_write_bytecode = True        # leave no __pycache__ next to the imported reference

import hashlib
import importlib.util
import json
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

HERE = os.path.dirname(os.path.abspath(__file__))
VEC_DIR = os.path.join(HERE, "..", "standard-vectors")
ZTV_PATH = os.path.join(VEC_DIR, "zcash-sapling-note-encryption.json")
ZTV_SHA256 = "dda3bed301e90915c2bf35209307d6c9e2d0de103a7ca93e5d15a2c00729f294"   # spec §9.2
PREF_PATH = os.path.join(HERE, "..", "pedersen-reference", "pedersen_jubjub_v1_reference.py")

_spec = importlib.util.spec_from_file_location("pedersen_reference", PREF_PATH)
PREF = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(PREF)

# =============================================================================
# Output bookkeeping
# =============================================================================

OUT = {}
FAILED = []
CHECKS = []
CASE_COUNTS = {}


def emit(key, value):
    if key in OUT:
        raise RuntimeError("duplicate output key " + key)
    if "=" in key or "\n" in key:
        raise RuntimeError("bad key " + key)
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, (bytes, bytearray)):
        value = bytes(value).hex()
    elif isinstance(value, int):
        if not 0 <= value < 2 ** 64:
            raise RuntimeError("integer output out of decimal range for " + key)
        value = str(value)
    value = str(value)
    if "\n" in value:
        raise RuntimeError("newline in value of " + key)
    OUT[key] = value


def chk(name, cond):
    key = "check." + name
    cond = bool(cond)
    emit(key, cond)
    CHECKS.append(key)
    if not cond:
        FAILED.append(key)
    return cond


def new_case(family, name):
    for part in (family, name):
        if not part or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in part):
            raise RuntimeError("bad case name %s.%s" % (family, name))
    CASE_COUNTS[family] = CASE_COUNTS.get(family, 0) + 1
    prefix = "case.%s.%s." % (family, name)
    return lambda k, v: emit(prefix + k, v)


def fe(x):
    """Field element / scalar: 0x + 64 lowercase hex digits."""
    if not 0 <= x < 2 ** 256:
        raise RuntimeError("fe out of range")
    return "0x%064x" % x


def i2osp(x, n):
    return x.to_bytes(n, "big")


def os2ip(b):
    return int.from_bytes(b, "big")


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def h(s):
    return bytes.fromhex(s)


# =============================================================================
# Jubjub (pedersen-jubjub-v1 §1, §4). Copy-adapted from the pedersen reference.
# =============================================================================

P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
L = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7
D = 0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1
A_ED = P - 1
COFACTOR = 8
G_FULL = (0x62EDCBB8BF3787C88B0F03DDD60A8187CAF55D1B29BF81AFE4B3D35DF1A7ADFE, 11)
IDENTITY = (0, 1)

# Hand-transcribed pins of pedersen-jubjub-v1 §1, §2.1, §2.3 (compared against, never used as input).
PIN_P = "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
PIN_L = "0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7"
PIN_G_U = "0x3ea5c4673a121ca35ed37ee3b172f5ee04315c657fbe375f512dfea318d56fe5"
PIN_G_V = "0x57137b83ea6edb4f78f7d30d3f616cb3b9aa6e8e40808413c10cea38d50c55cb"
PIN_G_ENC = "cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7"
PIN_H_U = "0x72963e7766b3cd553a1525a17da810e6b4cdeb70541dac5b52a3210f5c372db6"
PIN_H_V = "0x60bb97d81759e04503194aeb9eb8faa23b0092c941d1139bfe99907794c8e37d"
PIN_H_ENC = "7de3c894779099fe9b13d141c992003ba2fab89eeb4a190345e05917d897bb60"
PIN_C42_ENC = "57d3e074295e7feb8231baa675b3da817c6d45929590ce747b17b7e73bc387e3"   # §8


def inv(x):
    x %= P
    if x == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(x, -1, P)


def is_square(x):
    x %= P
    return x == 0 or pow(x, (P - 1) // 2, P) == 1


def sqrt_mod(n):
    return PREF.sqrt_mod(n)           # Tonelli-Shanks from the pedersen reference (self-checking)


def on_curve(pt):
    u, v = pt
    uu, vv = u * u % P, v * v % P
    return (A_ED * uu + vv - 1 - D * uu * vv) % P == 0


def point_add(p1, p2):
    u1, v1 = p1
    u2, v2 = p2
    t = D * u1 * u2 % P * v1 * v2 % P
    u3 = (u1 * v2 + v1 * u2) * inv(1 + t) % P
    v3 = (v1 * v2 - A_ED * u1 * u2) * inv(1 - t) % P
    return (u3, v3)


def point_neg(pt):
    return ((-pt[0]) % P, pt[1])


def scalar_mul(k, pt):
    if k < 0:
        raise ValueError("negative scalar")
    acc = IDENTITY
    for bit in bin(k)[2:]:
        acc = point_add(acc, acc)
        if bit == "1":
            acc = point_add(acc, pt)
    return acc


def in_subgroup(pt):
    return scalar_mul(L, pt) == IDENTITY


def point_order(pt):
    for k in (1, 2, 4, 8, L, 2 * L, 4 * L, 8 * L):
        if scalar_mul(k, pt) == IDENTITY:
            return k
    raise RuntimeError("order does not divide 8l")


def encode(pt):
    u, v = pt
    out = bytearray(v.to_bytes(32, "little"))
    if u & 1:
        out[31] |= 0x80
    return bytes(out)


def decode(data):
    """pedersen-jubjub-v1 §4. Returns (point, "ok") or (None, reason), rules in the spec's order."""
    if len(data) != 32:
        return None, "length"
    sign = data[31] >> 7
    buf = bytearray(data)
    buf[31] &= 0x7F
    v = int.from_bytes(buf, "little")
    if v >= P:
        return None, "noncanonical_v"
    vv = v * v % P
    den = (D * vv + 1) % P
    if den == 0:
        return None, "denominator_zero"
    w = (vv - 1) * inv(den) % P
    u = sqrt_mod(w)
    if u is None:
        return None, "non_square"
    if u == 0 and sign == 1:
        return None, "u_zero_sign_set"
    if (u & 1) != sign:
        u = P - u
    return (u, v), "ok"


G = scalar_mul(COFACTOR, G_FULL)
_PC, _PM = PREF.poseidon_parameters()
H_TAG_INT, H_COUNTER, _H_PRE, H, _H_TRACE = PREF.derive_h(_PC, _PM)


def commit(v, r):
    return point_add(scalar_mul(v % L, G), scalar_mul(r % L, H))


# Small-order points, constructed independently of the decoder.
T2 = (0, P - 1)
_i = sqrt_mod(P - 1)
T4 = (_i if _i % 2 == 0 else P - _i, 0)
T8 = scalar_mul(L, G_FULL)

# =============================================================================
# BLAKE2b: an independent pure-Python implementation from RFC 7693 §2-§3 with the full
# parameter block of [BLAKE2] §2.8 Table 1 (digest length byte 0, key length byte 1, fanout
# byte 2, depth byte 3, salt bytes 32-47, personalization bytes 48-63). Differential only.
# =============================================================================

B2_IV = [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
         0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179]
B2_SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]
M64 = (1 << 64) - 1


def _rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def _b2_compress(hh, block, t, last):
    m = struct.unpack("<16Q", block)
    v = hh[:] + B2_IV[:]
    v[12] ^= t & M64
    v[13] ^= (t >> 64) & M64
    if last:
        v[14] ^= M64

    def g(a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & M64
        v[d] = _rotr(v[d] ^ v[a], 32)
        v[c] = (v[c] + v[d]) & M64
        v[b] = _rotr(v[b] ^ v[c], 24)
        v[a] = (v[a] + v[b] + y) & M64
        v[d] = _rotr(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & M64
        v[b] = _rotr(v[b] ^ v[c], 63)

    for i in range(12):
        s = B2_SIGMA[i % 10]
        g(0, 4, 8, 12, m[s[0]], m[s[1]])
        g(1, 5, 9, 13, m[s[2]], m[s[3]])
        g(2, 6, 10, 14, m[s[4]], m[s[5]])
        g(3, 7, 11, 15, m[s[6]], m[s[7]])
        g(0, 5, 10, 15, m[s[8]], m[s[9]])
        g(1, 6, 11, 12, m[s[10]], m[s[11]])
        g(2, 7, 8, 13, m[s[12]], m[s[13]])
        g(3, 4, 9, 14, m[s[14]], m[s[15]])
    return [hh[i] ^ v[i] ^ v[i + 8] for i in range(8)]


def blake2b_pure(data, nn=64, person=bytes(16), salt=bytes(16)):
    """Unkeyed sequential BLAKE2b with digest length nn."""
    pblock = bytearray(64)
    pblock[0] = nn
    pblock[1] = 0          # key length
    pblock[2] = 1          # fanout (sequential)
    pblock[3] = 1          # depth (sequential)
    pblock[32:48] = salt
    pblock[48:64] = person
    words = struct.unpack("<8Q", bytes(pblock))
    hh = [B2_IV[i] ^ words[i] for i in range(8)]
    n = len(data)
    if n == 0:
        hh = _b2_compress(hh, bytes(128), 0, True)
    else:
        off = 0
        while n - off > 128:
            hh = _b2_compress(hh, data[off:off + 128], off + 128, False)
            off += 128
        tail = data[off:]
        hh = _b2_compress(hh, tail + bytes(128 - len(tail)), n, True)
    return struct.pack("<8Q", *hh)[:nn]


def blake2b_256_pers(pers, data):
    """BLAKE2b-256(pers, x): unkeyed, sequential, 32-byte digest, 16-byte personalization."""
    if len(pers) != 16:
        raise ValueError("personalization must be 16 bytes")
    return hashlib.blake2b(data, digest_size=32, person=pers).digest()


# =============================================================================
# Profile primitives (spec §1)
# =============================================================================

PERS = b"ZeroJ_NoteKDF_v1"
ZCASH_PERS = b"Zcash_SaplingKDF"
NONCE = bytes(12)
TEST_PREFIX = "zeroj.confidential-note.v1.test."
ELG_TEST_PREFIX = "zeroj.elgamal.v1.test."
DELIVERY_LEN = 89
PT_LEN = 41


def ka_agree(sk, X):
    return scalar_mul(COFACTOR * sk, X)


def kdf(pers, shared, E):
    return blake2b_256_pers(pers, encode(shared) + E)


def sym_encrypt(key, pt):
    return ChaCha20Poly1305(key).encrypt(NONCE, pt, b"")


def sym_decrypt(key, ct):
    try:
        return ChaCha20Poly1305(key).decrypt(NONCE, ct, b"")
    except InvalidTag:
        return None


def plaintext(v, r):
    if not (0 <= v < 2 ** 64 and 0 <= r < L):
        raise ValueError("opening out of range")
    return b"\x01" + i2osp(v, 8) + i2osp(r, 32)


def scalar(tag):
    """spec §9.1 test-vector scalars."""
    return os2ip(hashlib.sha256((TEST_PREFIX + tag).encode("ascii")).digest()) % L


def elg_scalar(tag):
    """elgamal-jubjub-v1 §12 test-vector scalars (used only for the §12 pin cross-check)."""
    return os2ip(hashlib.sha256((ELG_TEST_PREFIX + tag).encode("utf-8")).digest()) % L


def reader_key_valid(enc):
    """spec §2.2: (valid, reason)."""
    pt, reason = decode(enc)
    if pt is None:
        return False, "decode_" + reason
    if not in_subgroup(pt):
        return False, "not_in_subgroup"
    if pt == IDENTITY:
        return False, "identity"
    return True, "valid"


def seal_one(pt, P_i, e):
    """spec §4 step 3 for one reader, with a given ephemeral (test seam)."""
    if not 1 <= e < L:
        raise ValueError("ephemeral out of range")
    E = encode(scalar_mul(e, G))
    shared = ka_agree(e, P_i)
    K = kdf(PERS, shared, E)
    return E + sym_encrypt(K, pt)


def seal(v, r, reader_encs, ephemerals):
    """spec §4. reader_encs are encode(P_i); ephemerals the e_i (test seam). Raises on refusal."""
    for enc in reader_encs:
        ok, reason = reader_key_valid(enc)
        if not ok:
            raise ValueError("invalid reader key: " + reason)
    if len(set(reader_encs)) != len(reader_encs):
        raise ValueError("reader keys not pairwise distinct")
    if len(ephemerals) != len(reader_encs):
        raise ValueError("one ephemeral per reader")
    pt = plaintext(v, r)
    return [seal_one(pt, decode(enc)[0], e) for enc, e in zip(reader_encs, ephemerals)]


def open_delivery(sk, delivery, C):
    """spec §5. C is the note's affine (u, v) as integers, taken as given (no reduction).
    Returns dict(outcome, step, reason[, v, r])."""
    # 1
    if len(delivery) != DELIVERY_LEN:
        return {"outcome": "reject", "step": 1, "reason": "length"}
    E, ct = delivery[:32], delivery[32:]
    # 2
    X, reason = decode(E)
    if X is None:
        return {"outcome": "reject", "step": 2, "reason": "decode_" + reason}
    if not in_subgroup(X):
        return {"outcome": "reject", "step": 2, "reason": "not_in_subgroup"}
    if X == IDENTITY:
        return {"outcome": "reject", "step": 2, "reason": "identity"}
    # 3
    shared = ka_agree(sk, X)
    # 4: the received bytes E, not encode(X)
    K = kdf(PERS, shared, E)
    # 5
    pt = sym_decrypt(K, ct)
    if pt is None:
        return {"outcome": "reject", "step": 5, "reason": "aead"}
    # 6
    if pt[0] != 0x01:
        return {"outcome": "reject", "step": 6, "reason": "lead_byte"}
    v = os2ip(pt[1:9])
    r = os2ip(pt[9:41])
    if r >= L:
        return {"outcome": "reject", "step": 6, "reason": "r_not_below_l"}
    # 7
    cu, cv = C
    if not (0 <= cu < P and 0 <= cv < P):
        return {"outcome": "reject", "step": 7, "reason": "commitment_noncanonical"}
    if commit(v, r) != (cu, cv):
        return {"outcome": "reject", "step": 7, "reason": "commitment_mismatch"}
    return {"outcome": "accept", "step": 0, "reason": "none", "v": v, "r": r}


# =============================================================================
# Published known answers
# =============================================================================

def kat_blake2():
    abc = h("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")   # RFC 7693 App. A
    chk("rfc7693.appendix_a.blake2b_512_abc.hashlib", hashlib.blake2b(b"abc").digest() == abc)
    chk("rfc7693.appendix_a.blake2b_512_abc.pure", blake2b_pure(b"abc") == abc)
    x = b"zeroj personalization probe"
    d_plain = hashlib.blake2b(x, digest_size=32).digest()
    d_zero = hashlib.blake2b(x, digest_size=32, person=bytes(16)).digest()
    d_pers = blake2b_256_pers(PERS, x)
    d_zc = blake2b_256_pers(ZCASH_PERS, x)
    chk("blake2.person_all_zero_equals_unpersonalized", d_zero == d_plain)
    chk("blake2.person_changes_output", d_pers != d_plain and d_zc != d_plain and d_pers != d_zc)
    chk("blake2.person_differential_pure",
        blake2b_pure(x, 32, PERS) == d_pers and blake2b_pure(x, 32, ZCASH_PERS) == d_zc
        and blake2b_pure(x, 32) == d_plain)
    # [ZcashSpec] §5.4.1.2 note: BLAKE2b-256 is not BLAKE2b-512 truncated.
    chk("blake2.b256_is_not_truncated_b512",
        hashlib.blake2b(x, person=PERS).digest()[:32] != d_pers)


def kat_rfc8439():
    """RFC 8439 §2.8.2, quoted from the RFC text (refs/rfc/rfc8439.txt)."""
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
          b"the future, sunscreen would be it.")
    aad = h("50515253c0c1c2c3c4c5c6c7")
    key = bytes(range(0x80, 0xa0))
    nonce = h("07000000") + h("4041424344454647")
    ct = h("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
           "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
           "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
           "3ff4def08e4b7a9de576d26586cec64b6116")
    tag = h("1ae10b594f09e26a7e902ecbd0600691")
    a = ChaCha20Poly1305(key)
    chk("rfc8439.s2_8_2.seal", a.encrypt(nonce, pt, aad) == ct + tag)
    chk("rfc8439.s2_8_2.open", a.decrypt(nonce, ct + tag, aad) == pt)
    bad = bytearray(ct + tag)
    bad[-1] ^= 1
    try:
        a.decrypt(nonce, bytes(bad), aad)
        refused = False
    except InvalidTag:
        refused = True
    chk("rfc8439.s2_8_2.modified_tag_refused", refused)


def kat_ztv():
    raw = open(ZTV_PATH, "rb").read()
    chk("ztv.file_sha256_pinned", hashlib.sha256(raw).hexdigest() == ZTV_SHA256)
    rows = json.loads(raw.decode("utf-8"))
    header = [s.strip() for s in rows[1][0].split(",")]
    vecs = [dict(zip(header, r)) for r in rows[2:]]
    chk("ztv.count_10", len(vecs) == 10)
    for i, vec in enumerate(vecs):
        pk_d, ok1 = decode(h(vec["default_pk_d"]))
        epk_b = h(vec["epk"])
        epk, ok2 = decode(epk_b)
        esk = int.from_bytes(h(vec["esk"]), "little")
        ivk = int.from_bytes(h(vec["ivk"]), "little")
        ss = h(vec["shared_secret"])
        k_enc = h(vec["k_enc"])
        p_enc = h(vec["p_enc"])
        c_enc = h(vec["c_enc"])
        s1 = ka_agree(esk, pk_d)
        s2 = ka_agree(ivk, epk)
        chk("ztv.%d.sender_agree_esk_pk_d" % i, ok1 == "ok" and encode(s1) == ss)
        chk("ztv.%d.recipient_agree_ivk_epk" % i, ok2 == "ok" and encode(s2) == ss)
        chk("ztv.%d.kdf" % i, kdf(ZCASH_PERS, s2, epk_b) == k_enc)
        chk("ztv.%d.kdf_is_not_profile_kdf" % i, kdf(PERS, s2, epk_b) != k_enc)
        chk("ztv.%d.sym_encrypt" % i, sym_encrypt(k_enc, p_enc) == c_enc)
        chk("ztv.%d.sym_decrypt" % i, sym_decrypt(k_enc, c_enc) == p_enc)
    emit("info.ztv.vector_count", len(vecs))


# =============================================================================
# Drift checks
# =============================================================================

def drift_checks():
    emit("curve.p", fe(P))
    emit("curve.l", fe(L))
    emit("base.g.u", fe(G[0]))
    emit("base.g.v", fe(G[1]))
    emit("base.g.encoding", encode(G))
    emit("base.h.u", fe(H[0]))
    emit("base.h.v", fe(H[1]))
    emit("base.h.encoding", encode(H))
    chk("drift.p_equals_pedersen_pin", fe(P) == PIN_P)
    chk("drift.l_equals_pedersen_pin", fe(L) == PIN_L)
    chk("drift.d_equals_minus_10240_div_10241", D == (-10240) * inv(10241) % P)
    chk("drift.g_equals_pedersen_pin",
        fe(G[0]) == PIN_G_U and fe(G[1]) == PIN_G_V and encode(G).hex() == PIN_G_ENC)
    chk("drift.h_equals_pedersen_pin",
        fe(H[0]) == PIN_H_U and fe(H[1]) == PIN_H_V and encode(H).hex() == PIN_H_ENC)
    chk("drift.h_counter_1", H_COUNTER == 1)
    chk("drift.commit_42_12345_equals_pedersen_pin", encode(commit(42, 12345)).hex() == PIN_C42_ENC)
    chk("drift.g_h_in_subgroup_not_identity",
        in_subgroup(G) and in_subgroup(H) and G != IDENTITY and H != IDENTITY and G != H)
    chk("drift.torsion_orders_2_4_8",
        (point_order(T2), point_order(T4), point_order(T8)) == (2, 4, 8))
    chk("drift.arithmetic_matches_pedersen_reference",
        all(scalar_mul(k, pt) == PREF.scalar_mul(k, pt)
            for k in (0, 1, 7, 12345, L - 1) for pt in (G, H, G_FULL)))
    chk("drift.decode_roundtrip_g_h", decode(encode(G)) == (G, "ok") and decode(encode(H)) == (H, "ok"))
    chk("drift.pers_is_16_bytes", len(PERS) == 16 and len(ZCASH_PERS) == 16)
    # spec §1: ASCII("ZeroJ_NoteKDF_v1"), transcribed by hand as hex
    chk("drift.pers_hand_transcribed", PERS.hex() == "5a65726f4a5f4e6f74654b44465f7631")


# =============================================================================
# Keys
# =============================================================================

READER_NAMES = ["owner", "auditor1", "auditor2", "auditor3", "other"]
KEYS = {}            # name -> (sk, P, enc)
EPHEMERAL_TAGS = []  # every ephemeral tag used to seal (the reuse family appears once)


def keys_section():
    for name in READER_NAMES:
        sk = scalar("reader." + name)
        if sk == 0:
            raise RuntimeError("test key derived to zero (spec §9.1: vector set invalid)")
        Pk = scalar_mul(sk, G)
        KEYS[name] = (sk, Pk, encode(Pk))
        emit("key.%s.sk" % name, fe(sk))
        emit("key.%s.pk" % name, encode(Pk))
        chk("key.%s.valid" % name, reader_key_valid(encode(Pk)) == (True, "valid"))
    chk("key.all_distinct", len({KEYS[n][2] for n in READER_NAMES}) == len(READER_NAMES))


EPH_TAG_OF = {}


def eph(tag):
    e = scalar(tag)
    if e == 0:
        raise RuntimeError("ephemeral derived to zero: " + tag)
    EPHEMERAL_TAGS.append(tag)
    EPH_TAG_OF[e] = tag
    return e


# =============================================================================
# Family: deliver
# =============================================================================

DELIVER = {}   # case -> dict(readers, v, r, C, deliveries, ephemerals)

# (case, readers, value, blinding tag or literal int, config)
DELIVER_SPECS = [
    ("r1_value0", ["owner"], 0, "tag", "1 reader, value 0"),
    ("r1_blinding0", ["owner"], 42, 0, "1 reader, value 42, blinding 0"),
    ("r1_zero_opening", ["owner"], 0, 0, "1 reader, value 0 and blinding 0, C is the identity"),
    ("r2_value1", ["owner", "auditor1"], 1, "tag", "2 readers, value 1"),
    ("r3_value_max", ["owner", "auditor1", "auditor2"], 2 ** 64 - 1, "tag",
     "3 readers, value 2^64-1"),
    ("r4_value_mid", ["owner", "auditor1", "auditor2", "auditor3"], 123456789012345, "tag",
     "4 readers, mid value"),
]

# Hand-written intended plaintexts (spec §3.1), independent of plaintext().
INTENDED_PT = {
    "r1_blinding0": "01" + "000000000000002a" + "00" * 32,
    "r1_zero_opening": "01" + "00" * 8 + "00" * 32,
    "r3_value_max": None,   # value bytes checked below
}


def deliver_family():
    for name, readers, v, rspec, config in DELIVER_SPECS:
        r = scalar("blinding." + name) if rspec == "tag" else rspec
        C = commit(v, r)
        es = [eph("ephemeral.%s.%d" % (name, i)) for i in range(len(readers))]
        encs = [KEYS[n][2] for n in readers]
        dels = seal(v, r, encs, es)
        DELIVER[name] = dict(readers=readers, v=v, r=r, C=C, deliveries=dels, ephemerals=es)
        e_ = new_case("deliver", name)
        e_("config", config)
        e_("readers", ",".join(readers))
        e_("value", v)
        e_("blinding", fe(r))
        e_("commitment", encode(C))
        e_("commitment_u", fe(C[0]))
        e_("commitment_v", fe(C[1]))
        pt = plaintext(v, r)
        e_("plaintext", pt)
        for i, (e, d) in enumerate(zip(es, dels)):
            e_("ephemeral.%d" % i, fe(e))
            e_("delivery.%d" % i, d)
        chk("deliver.%s.lengths" % name, len(pt) == 41 and all(len(d) == 89 for d in dels))
        chk("deliver.%s.e_i_is_encoded_eG" % name,
            all(d[:32] == encode(scalar_mul(e, G)) for e, d in zip(es, dels)))
        chk("deliver.%s.ephemeral_points_distinct" % name, len({d[:32] for d in dels}) == len(dels))
        chk("deliver.%s.plaintext_layout" % name,
            pt[0] == 1 and pt[1:9] == v.to_bytes(8, "big") and pt[9:] == r.to_bytes(32, "big"))
        if INTENDED_PT.get(name):
            chk("deliver.%s.plaintext_intended" % name, pt.hex() == INTENDED_PT[name])
        if name == "r3_value_max":
            chk("deliver.%s.plaintext_intended" % name, pt[:9].hex() == "01ffffffffffffffff")
        if name == "r1_zero_opening":
            chk("deliver.%s.commitment_is_identity" % name, C == IDENTITY)
        # every reader opens its own delivery; every other key refuses it at step 5
        own = all(open_delivery(KEYS[n][0], d, C) == {"outcome": "accept", "step": 0,
                                                       "reason": "none", "v": v, "r": r}
                  for n, d in zip(readers, dels))
        chk("deliver.%s.each_reader_accepts_own" % name, own)
        cross = all(open_delivery(KEYS[m][0], d, C)["step"] == 5
                    for n, d in zip(readers, dels) for m in READER_NAMES if m != n)
        chk("deliver.%s.every_other_key_rejects_at_step5" % name, cross)


# =============================================================================
# Family: readerkey (spec §2.2 validity; sealing refuses invalid keys, §4 step 1)
# =============================================================================

def noncanonical_plus_p(enc):
    """Same point, v + p written in the 255 bits (None if it does not fit)."""
    v = int.from_bytes(bytes(enc[:31]) + bytes([enc[31] & 0x7F]), "little")
    if v + P >= 2 ** 255:
        return None
    out = bytearray((v + P).to_bytes(32, "little"))
    out[31] |= enc[31] & 0x80
    return bytes(out)


def eph_noncanonical(case):
    """Ephemeral whose point admits a v+p encoding (about 10% do). Tag ephemeral.<case>.0, else
    the first of ephemeral.<case>.0.retry<k>, k = 1, 2, ... (deterministic)."""
    k = 0
    while True:
        tag = "ephemeral.%s.0" % case + ("" if k == 0 else ".retry%d" % k)
        e = scalar(tag)
        X = scalar_mul(e, G)
        Enc = noncanonical_plus_p(encode(X))
        if Enc is not None:
            EPHEMERAL_TAGS.append(tag)
            EPH_TAG_OF[e] = tag
            return e, X, Enc
        k += 1


def first_non_square_v():
    v = 2
    while True:
        vv = v * v % P
        if not is_square((vv - 1) * inv(D * vv + 1)):
            return v
        v += 1


def sign_set(enc):
    b = bytearray(enc)
    b[31] |= 0x80
    return bytes(b)


def readerkey_family():
    nc = None
    for n in READER_NAMES:
        nc = noncanonical_plus_p(KEYS[n][2])
        if nc is not None:
            nc_name = n
            break
    if nc is None:
        raise RuntimeError("no reader key admits a v+p encoding")
    owner_enc = KEYS["owner"][2]
    cases = [
        ("owner", owner_enc, "valid", "valid", "the owner's key"),
        ("auditor1", KEYS["auditor1"][2], "valid", "valid", "auditor1's key"),
        ("identity", encode(IDENTITY), "invalid", "identity", "the identity"),
        ("order2", encode(T2), "invalid", "not_in_subgroup", "order-2 point"),
        ("order4", encode(T4), "invalid", "not_in_subgroup", "order-4 point"),
        ("order8", encode(T8), "invalid", "not_in_subgroup", "order-8 point"),
        ("mixed_order", encode(point_add(KEYS["owner"][1], T8)), "invalid", "not_in_subgroup",
         "owner key plus an order-8 point"),
        ("noncanonical_v_plus_p", nc, "invalid", "decode_noncanonical_v",
         "%s key with v+p (same point)" % nc_name),
        ("not_on_curve", first_non_square_v().to_bytes(32, "little"), "invalid", "decode_non_square",
         "v with non-square u^2"),
        ("identity_sign_set", sign_set(encode(IDENTITY)), "invalid", "decode_u_zero_sign_set",
         "identity with the sign bit set"),
        ("length_31", owner_enc[:31], "invalid", "decode_length", "31 bytes"),
        ("length_33", owner_enc + b"\x00", "invalid", "decode_length", "33 bytes"),
    ]
    for name, enc, expect, reason, config in cases:
        ok, why = reader_key_valid(enc)
        e_ = new_case("readerkey", name)
        e_("config", config)
        e_("pk", enc)
        e_("expect", expect)
        e_("reason", reason)
        chk("readerkey.%s.intended_outcome" % name,
            ("valid" if ok else "invalid") == expect and why == reason)
        try:
            seal(1, 1, [enc], [eph("ephemeral.readerkey_%s.0" % name)])
            sealed = True
        except ValueError:
            sealed = False
        chk("readerkey.%s.seal_%s" % (name, "accepted" if expect == "valid" else "refused"),
            sealed == (expect == "valid"))
    # §4 step 1: pairwise distinct, compared as encodings
    try:
        seal(1, 1, [owner_enc, KEYS["auditor1"][2], owner_enc],
             [eph("ephemeral.duplicate_readers.%d" % i) for i in range(3)])
        dup_ok = False
    except ValueError:
        dup_ok = True
    chk("seal.refuses_duplicate_reader_keys", dup_ok)


# =============================================================================
# Family: open
# =============================================================================

def open_family():
    cases = []   # (name, reader, delivery, C, expect, step, config, extras)

    def add(name, reader, delivery, C, expect, step, config, **extras):
        cases.append((name, reader, delivery, C, expect, step, config, extras))

    # Every reader of every deliver case accepts its own delivery.
    for dname, d in DELIVER.items():
        for i, n in enumerate(d["readers"]):
            add("%s_reader%d" % (dname, i), n, d["deliveries"][i], d["C"], "accept", 0,
                "%s delivery %d opened by its reader %s" % (dname, i, n))

    base = DELIVER["r2_value1"]
    good0 = base["deliveries"][0]          # owner's delivery
    C0 = base["C"]
    sk_owner = KEYS["owner"][0]
    P_owner = KEYS["owner"][1]

    # Step 5: wrong key / another reader's delivery.
    add("wrong_reader_key", "other", good0, C0, "reject", 5, "owner delivery opened by a non-reader")
    add("other_readers_index", "auditor1", good0, C0, "reject", 5,
        "auditor1 opens delivery 0 (owner) of r2_value1")
    r4 = DELIVER["r4_value_mid"]
    add("other_readers_index_r4", "auditor2", r4["deliveries"][3], r4["C"], "reject", 5,
        "auditor2 opens delivery 3 (auditor3) of r4_value_mid")

    # Step 1: length.
    add("len_88_truncated", "owner", good0[:88], C0, "reject", 1, "last tag byte dropped")
    add("len_90_extended", "owner", good0 + b"\x00", C0, "reject", 1, "one zero byte appended")
    add("len_0", "owner", b"", C0, "reject", 1, "empty delivery")
    add("len_57_ct_only", "owner", good0[32:], C0, "reject", 1, "ct without E")
    add("len_32_e_only", "owner", good0[:32], C0, "reject", 1, "E without ct")
    v, r = 1000, scalar("blinding.len_90_valid_aead")
    pt42 = plaintext(v, r) + b"\x00"
    e = eph("ephemeral.len_90_valid_aead.0")
    add("len_90_valid_aead", "owner", seal_one(pt42, P_owner, e), commit(v, r),
        "reject", 1, "42-byte plaintext sealed with a valid tag (90 bytes)", plaintext=pt42,
        ephemeral=e)

    # Step 2: E. Adversarial E values are sealed under the key a defective reader would derive,
    # so only the named check refuses them.
    def adv_seal(case, E_bytes, shared, pt):
        return E_bytes + sym_encrypt(kdf(PERS, shared, E_bytes), pt)

    def opening(case):
        vv, rr = 777, scalar("blinding." + case)
        return vv, rr, plaintext(vv, rr), commit(vv, rr)

    # non-canonical v >= p: same point, sealed under KDF(shared, received non-canonical bytes)
    vv, rr, pt, C = opening("e_noncanonical_v_plus_p")
    e, X, Enc = eph_noncanonical("e_noncanonical_v_plus_p")
    add("e_noncanonical_v_plus_p", "owner", adv_seal("x", Enc, ka_agree(e, P_owner), pt), C,
        "reject", 2, "E = valid point with v+p; sealed under KDF of those bytes",
        plaintext=pt, ephemeral=e)
    # same point but KDF over the re-encoded E (what a reader that re-encodes would accept)
    vv, rr, pt, C = opening("e_noncanonical_reencoded_kdf")
    e, X, Enc = eph_noncanonical("e_noncanonical_reencoded_kdf")
    add("e_noncanonical_reencoded_kdf", "owner",
        Enc + sym_encrypt(kdf(PERS, ka_agree(e, P_owner), encode(X)), pt), C, "reject", 2,
        "E = v+p bytes; sealed under KDF of the canonical re-encoding", plaintext=pt, ephemeral=e)
    add("e_v_all_ones", "owner", b"\xff" * 32 + good0[32:], C0, "reject", 2, "E = 32 bytes 0xff")
    vv, rr, pt, C = opening("e_identity_sign_set")
    Eb = sign_set(encode(IDENTITY))
    add("e_identity_sign_set", "owner", adv_seal("x", Eb, IDENTITY, pt), C, "reject", 2,
        "E = identity with sign bit (u=0); sealed under shared = identity", plaintext=pt)
    vv, rr, pt, C = opening("e_order2_sign_set")
    Eb = sign_set(encode(T2))
    add("e_order2_sign_set", "owner", adv_seal("x", Eb, IDENTITY, pt), C, "reject", 2,
        "E = order-2 point (u=0) with sign bit; sealed under shared = identity", plaintext=pt)
    ns = first_non_square_v().to_bytes(32, "little")
    add("e_not_on_curve", "owner", ns + good0[32:], C0, "reject", 2,
        "E has v with non-square u^2 (no point)")
    for tname, T in (("order2", T2), ("order4", T4), ("order8", T8)):
        cname = "e_small_" + tname
        vv, rr, pt, C = opening(cname)
        add(cname, "owner", adv_seal("x", encode(T), IDENTITY, pt), C, "reject", 2,
            "E = %s point; sealed under shared = [8sk]T = identity" % tname, plaintext=pt)
    vv, rr, pt, C = opening("e_identity")
    add("e_identity", "owner", adv_seal("x", encode(IDENTITY), IDENTITY, pt), C, "reject", 2,
        "E = identity; sealed under shared = identity", plaintext=pt)
    vv, rr, pt, C = opening("e_mixed_order")
    e = eph("ephemeral.e_mixed_order.0")
    Xm = point_add(scalar_mul(e, G), T8)
    add("e_mixed_order", "owner", adv_seal("x", encode(Xm), ka_agree(e, P_owner), pt), C,
        "reject", 2, "E = [e]G + order-8 point; sealed under [8e]P (what [8sk]E gives)",
        plaintext=pt, ephemeral=e)
    vv, rr, pt, C = opening("e_mixed_order_no_cofactor")
    e = eph("ephemeral.e_mixed_order_no_cofactor.0")
    Xm = point_add(scalar_mul(e, G), T8)
    add("e_mixed_order_no_cofactor", "owner",
        adv_seal("x", encode(Xm), scalar_mul(sk_owner, Xm), pt), C, "reject", 2,
        "E = [e]G + order-8 point; sealed under [sk]E (no cofactor)", plaintext=pt, ephemeral=e)

    # Step 5: tampering.
    t = bytearray(good0)
    t[32] ^= 0x01
    add("tampered_ct_byte0", "owner", bytes(t), C0, "reject", 5, "first ct byte flipped")
    t = bytearray(good0)
    t[60] ^= 0x80
    add("tampered_ct_byte28", "owner", bytes(t), C0, "reject", 5, "ct byte 28 high bit flipped")
    t = bytearray(good0)
    t[-1] ^= 0x01
    add("tampered_tag", "owner", bytes(t), C0, "reject", 5, "last tag byte flipped")
    X0, _ = decode(good0[:32])
    add("tampered_e_valid_point", "owner", encode(point_add(X0, G)) + good0[32:], C0, "reject", 5,
        "E replaced by E+G (valid subgroup point)")
    add("tampered_e_negated", "owner", good0[:31] + bytes([good0[31] ^ 0x80]) + good0[32:], C0,
        "reject", 5, "E sign bit flipped (-E, valid subgroup point)")
    add("swapped_ct_between_readers", "owner", good0[:32] + base["deliveries"][1][32:], C0,
        "reject", 5, "owner E with auditor1 ct")

    # Step 6: crafted plaintexts under a valid AEAD.
    for lead in (0x00, 0x02):
        cname = "lead_byte_%02x" % lead
        vv, rr = 555, scalar("blinding." + cname)
        ptc = bytes([lead]) + i2osp(vv, 8) + i2osp(rr, 32)
        e = eph("ephemeral.%s.0" % cname)
        add(cname, "owner", seal_one(ptc, P_owner, e), commit(vv, rr), "reject", 6,
            "lead byte 0x%02x, valid AEAD, opening matches C" % lead, plaintext=ptc, ephemeral=e)
    for cname, rr in (("r_equals_l", L), ("r_l_plus_5", L + 5), ("r_max_256", 2 ** 256 - 1)):
        vv = 555
        ptc = b"\x01" + i2osp(vv, 8) + i2osp(rr, 32)
        e = eph("ephemeral.%s.0" % cname)
        add(cname, "owner", seal_one(ptc, P_owner, e), commit(vv, rr % L), "reject", 6,
            "r >= l, valid AEAD, C = commit(v, r mod l)", plaintext=ptc, ephemeral=e)
    vv, rr = 555, L - 1
    ptc = plaintext(vv, rr)
    e = eph("ephemeral.r_l_minus_1.0")
    add("r_l_minus_1", "owner", seal_one(ptc, P_owner, e), commit(vv, rr), "accept", 0,
        "r = l-1 control, accepted", plaintext=ptc, ephemeral=e)

    # Step 7: valid AEAD, opening does not match C.
    vv, rr = 999, scalar("blinding.opening_mismatch_value")
    ptc = plaintext(vv, rr)
    e = eph("ephemeral.opening_mismatch_value.0")
    add("opening_mismatch_value", "owner", seal_one(ptc, P_owner, e), commit(vv + 1, rr),
        "reject", 7, "C commits to v+1", plaintext=ptc, ephemeral=e)
    add("opening_mismatch_other_note", "owner", good0, DELIVER["r1_value0"]["C"], "reject", 7,
        "r2_value1 owner delivery against r1_value0's C")
    add("opening_mismatch_negated_c", "owner", good0, point_neg(C0), "reject", 7,
        "r2_value1 owner delivery against -C")
    add("opening_mismatch_identity_c", "owner", DELIVER["r1_value0"]["deliveries"][0], IDENTITY,
        "reject", 7, "r1_value0 delivery against the identity C")

    # Step 7: the note's affine coordinates, taken with no reduction (spec §5 step 7).
    for cname, how in (("c_u_plus_p", "u + p"), ("c_v_plus_p", "v + p"),
                       ("c_not_on_curve", "(u + 1, v), not on the curve")):
        vv, rr = 4242, scalar("blinding." + cname)
        ptc = plaintext(vv, rr)
        e = eph("ephemeral.%s.0" % cname)
        cu, cv = commit(vv, rr)
        Cn = {"c_u_plus_p": (cu + P, cv), "c_v_plus_p": (cu, cv + P),
              "c_not_on_curve": ((cu + 1) % P, cv)}[cname]
        add(cname, "owner", seal_one(ptc, P_owner, e), Cn, "reject", 7,
            "valid AEAD and correct opening; C given as %s" % how, plaintext=ptc, ephemeral=e,
            noncanonical_c=True)

    # Application rule: a copied note opens (the owner-credential check is the application's).
    add("copied_note", "owner", good0, C0, "accept", 0,
        "r2_value1 (C, delivery 0) copied into another output; profile accepts",
        app_note="copied")

    for name, reader, delivery, C, expect, step, config, extras in cases:
        res = open_delivery(KEYS[reader][0], delivery, C)
        e_ = new_case("open", name)
        e_("config", config)
        e_("reader", reader)
        e_("delivery", delivery)
        if not extras.get("noncanonical_c"):
            e_("commitment", encode(C))
        e_("commitment_u", fe(C[0]))
        e_("commitment_v", fe(C[1]))
        e_("expect", expect)
        e_("step", step)
        e_("reason", res["reason"])
        if expect == "accept":
            e_("value", res.get("v", 0))
            e_("blinding", fe(res.get("r", 0)))
        if "plaintext" in extras:
            e_("plaintext", extras["plaintext"])
        if "ephemeral" in extras:
            e_("ephemeral", fe(extras["ephemeral"]))
            e_("ephemeral_tag", EPH_TAG_OF[extras["ephemeral"]])
        if "app_note" in extras:
            e_("app_note", extras["app_note"])
        chk("open.%s.intended_outcome" % name, res["outcome"] == expect and res["step"] == step)

    # §5 step 4's "received bytes, not a re-encoding" cannot change any outcome while step 2's
    # decoder is canonical-only: every accepted E re-encodes to itself.
    decoded = [c[2][:32] for c in cases if len(c[2]) == DELIVERY_LEN and decode(c[2][:32])[0]]
    chk("open.accepted_e_reencodes_to_itself",
        len(decoded) > 0 and all(encode(decode(E)[0]) == E for E in decoded))

    # The adversarial E cases are refused only by step 2: a reader that skipped the named
    # check would have accepted them (shows the construction is meaningful).
    def lenient_open(sk, delivery, C, cofactor=True, reencode=False):
        E, ct = delivery[:32], delivery[32:]
        buf = bytearray(E)
        sign = buf[31] >> 7
        buf[31] &= 0x7F
        vv = int.from_bytes(buf, "little") % P
        w = (vv * vv - 1) * inv(D * vv * vv + 1) % P
        u = sqrt_mod(w)
        if u is None:
            return False
        if (u & 1) != sign:
            u = (P - u) % P
        X = (u, vv)
        sh = scalar_mul((COFACTOR if cofactor else 1) * sk, X)
        pt = sym_decrypt(kdf(PERS, sh, encode(X) if reencode else E), ct)
        return pt is not None and pt[0] == 1 and commit(os2ip(pt[1:9]), os2ip(pt[9:41])) == C

    by = {c[0]: c for c in cases}
    for cname, kw in (("e_noncanonical_v_plus_p", {}),
                      ("e_noncanonical_reencoded_kdf", {"reencode": True}),
                      ("e_identity_sign_set", {}), ("e_order2_sign_set", {}),
                      ("e_small_order2", {}), ("e_small_order4", {}), ("e_small_order8", {}),
                      ("e_identity", {}), ("e_mixed_order", {}),
                      ("e_mixed_order_no_cofactor", {"cofactor": False})):
        _, reader, delivery, C, _, _, _, _ = by[cname]
        chk("open.%s.lenient_reader_would_accept" % cname,
            lenient_open(KEYS[reader][0], delivery, C, **kw))
    # A reader that reduced the coordinates mod p would accept the u+p / v+p cases.
    for cname in ("c_u_plus_p", "c_v_plus_p"):
        _, reader, delivery, C, _, _, _, ex = by[cname]
        ptc = ex["plaintext"]
        chk("open.%s.opening_would_match_c_with_reduction" % cname,
            commit(os2ip(ptc[1:9]), os2ip(ptc[9:41])) == (C[0] % P, C[1] % P))
    _, _, _, Cbad, _, _, _, _ = by["c_not_on_curve"]
    chk("open.c_not_on_curve.is_off_curve", not on_curve(Cbad))
    for cname in ("lead_byte_00", "lead_byte_02", "r_equals_l", "r_l_plus_5", "r_max_256"):
        _, reader, delivery, C, _, _, _, ex = by[cname]
        ptc = ex["plaintext"]
        chk("open.%s.opening_would_match_c_without_step6" % cname,
            commit(os2ip(ptc[1:9]), os2ip(ptc[9:41])) == C)


# =============================================================================
# Family: reuse (one use per key, spec §4)
# =============================================================================

def reuse_family():
    for name, reader, v1, v2 in (("same_e_owner", "owner", 5, 1000000),
                                 ("same_e_auditor1", "auditor1", 2 ** 64 - 1, 0)):
        e = scalar("ephemeral.%s.0" % name)
        EPHEMERAL_TAGS.append("ephemeral.%s.0" % name)
        r1 = scalar("blinding.%s.1" % name)
        r2 = scalar("blinding.%s.2" % name)
        pt1, pt2 = plaintext(v1, r1), plaintext(v2, r2)
        Pk = KEYS[reader][1]
        d1, d2 = seal_one(pt1, Pk, e), seal_one(pt2, Pk, e)
        x = xor(pt1, pt2)
        e_ = new_case("reuse", name)
        e_("config", "one ephemeral reused toward %s for two plaintexts (forbidden)" % reader)
        e_("reader", reader)
        e_("ephemeral", fe(e))
        e_("plaintext1", pt1)
        e_("plaintext2", pt2)
        e_("delivery1", d1)
        e_("delivery2", d2)
        e_("xor", x)
        chk("reuse.%s.same_e_bytes" % name, d1[:32] == d2[:32])
        chk("reuse.%s.ct_xor_equals_pt_xor" % name, xor(d1[32:73], d2[32:73]) == x)
        chk("reuse.%s.pt2_recovered_from_pt1" % name, xor(xor(d1[32:73], d2[32:73]), pt1) == pt2)
        chk("reuse.%s.both_open" % name,
            open_delivery(KEYS[reader][0], d1, commit(v1, r1))["outcome"] == "accept"
            and open_delivery(KEYS[reader][0], d2, commit(v2, r2))["outcome"] == "accept")


# =============================================================================
# Family: kdf (personalised BLAKE2b-256)
# =============================================================================

def kdf_family():
    for pname, pers in (("zeroj", PERS), ("zcash", ZCASH_PERS)):
        for n in (0, 64, 127, 128, 129, 300):
            name = "%s_len%d" % (pname, n)
            data = bytes(i & 0xFF for i in range(n))
            out = blake2b_256_pers(pers, data)
            e_ = new_case("kdf", name)
            e_("config", "BLAKE2b-256 with pers %s over %d bytes i mod 256" % (pers.decode(), n))
            e_("pers", pers)
            e_("input", data)
            e_("output", out)
            chk("kdf.%s.pure_differential" % name, blake2b_pure(data, 32, pers) == out)
    # one vector shaped exactly like the profile KDF input: encode(shared) || E
    d = DELIVER["r1_value0"]
    E = d["deliveries"][0][:32]
    shared = ka_agree(KEYS["owner"][0], decode(E)[0])
    data = encode(shared) + E
    e_ = new_case("kdf", "profile_shape_r1_value0")
    e_("config", "profile KDF input encode(shared)||E of r1_value0 delivery 0")
    e_("pers", PERS)
    e_("input", data)
    e_("output", kdf(PERS, shared, E))
    chk("kdf.profile_shape_r1_value0.sender_side_equal",
        kdf(PERS, ka_agree(d["ephemerals"][0], KEYS["owner"][1]), E) == kdf(PERS, shared, E))


# =============================================================================
# Family: d3a (spec §8)
# =============================================================================

def elg_encrypt(m, k, PK):
    return scalar_mul(k, G), point_add(scalar_mul(m, G), scalar_mul(k, PK))


def elgamal_pins():
    """elgamal-jubjub-v1 §12 pinned values (hand-transcribed), to cross-check elg_encrypt."""
    sk = elg_scalar("sk")
    PK = scalar_mul(sk, G)
    a1, b1 = elg_encrypt(1, elg_scalar("k1"), PK)
    a2, b2 = elg_encrypt(12345, elg_scalar("k16"), PK)
    chk("elgamal_pin.sk", fe(sk) == "0x0281799c40fb5bca4f8cc6af4812fae96cdf7113e1ab203ea4d73fb7027e8343")
    chk("elgamal_pin.pk", encode(PK).hex() ==
        "36d7d5a69ac65a6761ac10fd3338bd4692939aefc4f5d5a1eb37477b29423e68")
    chk("elgamal_pin.enc_1_k1", (encode(a1) + encode(b1)).hex() ==
        "5c60657a3d709bbc2e68f03e5146b357b45066b21f21e914decbddefef876ea2"
        "0115a214bbe47745f99a8130d1bd2b48b788883d95d468069d0677081dc5f772")
    chk("elgamal_pin.enc_12345_k16", (encode(a2) + encode(b2)).hex() ==
        "b1998f709303f197722bef1f1105d9b65ad7d9b77d32c8859419a27c53928d5a"
        "38f7c38d98efd9f2f89698d45c5546a17a4a76534a006429bd6af0be8ce93383")


ELG_KEYS = {}


def d3a_serialize(blocks, byteorder="big"):
    return b"".join(c.to_bytes(32, byteorder) for c in blocks)


def split_digest(dg):
    return os2ip(dg[:16]), os2ip(dg[16:])


def d3a_family():
    for name in ("auditor1", "auditor2"):
        sk = scalar("elgamal." + name)
        if sk == 0:
            raise RuntimeError("elgamal test key derived to zero")
        PK = scalar_mul(sk, G)
        ELG_KEYS[name] = (sk, PK)
        emit("elgamal_key.%s.sk" % name, fe(sk))
        emit("elgamal_key.%s.pk" % name, encode(PK))
        emit("elgamal_key.%s.u" % name, fe(PK[0]))
        emit("elgamal_key.%s.v" % name, fe(PK[1]))
        chk("elgamal_key.%s.valid" % name, reader_key_valid(encode(PK)) == (True, "valid"))
        chk("elgamal_key.%s.separate_from_viewing_key" % name,
            name not in KEYS or KEYS[name][0] != sk)

    specs = [
        ("o2_a1", ["auditor1"], [2 ** 64 - 1, 2 ** 32 + 12345], "transfer: 2 outputs, 1 auditor"),
        ("o1_a1", ["auditor1"], [123456789012345], "redeem: 1 output, 1 auditor"),
        ("o2_a2", ["auditor1", "auditor2"], [0, 2 ** 32], "2 outputs, 2 auditors"),
    ]
    for name, auds, values, config in specs:
        m, n = len(auds), len(values)
        e_ = new_case("d3a", name)
        e_("config", config)
        e_("auditors", ",".join(auds))
        pub_keys = []
        for a, an in enumerate(auds, 1):
            PK = ELG_KEYS[an][1]
            e_("pk.%d.u" % a, fe(PK[0]))
            e_("pk.%d.v" % a, fe(PK[1]))
            pub_keys += [PK[0], PK[1]]
        e_("notes", n)
        ct_coords = []
        blocks = {}     # (o, a, j) -> [A.u, A.v, B.u, B.v]
        dec_ok = True
        for o, vo in enumerate(values, 1):
            l0, l1 = vo % 2 ** 32, vo >> 32
            e_("note.%d.value" % o, vo)
            e_("note.%d.limb0" % o, l0)
            e_("note.%d.limb1" % o, l1)
            chk("d3a.%s.note%d.limbs_recombine" % (name, o),
                l0 + 2 ** 32 * l1 == vo and 0 <= l0 < 2 ** 32 and 0 <= l1 < 2 ** 32)
            for a, an in enumerate(auds, 1):
                sk, PK = ELG_KEYS[an]
                for j, limb in ((0, l0), (1, l1)):
                    k = scalar("d3a.%s.k.%d.%d.%d" % (name, o, a, j))
                    A, B = elg_encrypt(limb, k, PK)
                    blk = [A[0], A[1], B[0], B[1]]
                    blocks[(o, a, j)] = blk
                    ct_coords += blk
                    e_("k.%d.%d.%d" % (o, a, j), fe(k))
                    e_("ct.%d.%d.%d" % (o, a, j), ",".join(fe(c) for c in blk))
                    M = point_add(B, point_neg(scalar_mul(sk, A)))
                    dec_ok &= (M == scalar_mul(limb, G)) and in_subgroup(A) and in_subgroup(B)
        chk("d3a.%s.limb_ciphertexts_decrypt" % name, dec_ok)
        pis = pub_keys + ct_coords
        e_("public_inputs", ",".join(fe(c) for c in pis))
        chk("d3a.%s.public_input_count" % name, len(pis) == 2 * m + 8 * m * n)
        # ADR-0055 D3a figures, by hand: transfer 18, redeem 10; 2 outputs x 2 auditors 36
        chk("d3a.%s.public_input_count_intended" % name,
            len(pis) == {"o2_a1": 18, "o1_a1": 10, "o2_a2": 36}[name])
        # §8.2 index formula, written independently of the emitting loops
        chk("d3a.%s.public_input_index_formula" % name,
            all(pis[2 * (a - 1)] == ELG_KEYS[auds[a - 1]][1][0]
                and pis[2 * (a - 1) + 1] == ELG_KEYS[auds[a - 1]][1][1]
                for a in range(1, m + 1))
            and all(pis[2 * m + 8 * ((o - 1) * m + (a - 1)) + 4 * j + t] == blocks[(o, a, j)][t]
                    for o in range(1, n + 1) for a in range(1, m + 1) for j in (0, 1)
                    for t in range(4)))
        chk("d3a.%s.coordinates_canonical" % name, all(0 <= c < P for c in pis))
        data = d3a_serialize(ct_coords)
        dg = hashlib.blake2b(data, digest_size=32).digest()
        hi, lo = split_digest(dg)
        e_("bytes", data)
        e_("digest", dg)
        e_("digest_hi", fe(hi))
        e_("digest_lo", fe(lo))
        chk("d3a.%s.bytes_length" % name, len(data) == 32 * 8 * m * n)
        # ADR-0055 D3a: the transfer hashes about 512 bytes (four BLAKE2b blocks)
        chk("d3a.%s.bytes_length_intended" % name,
            len(data) == {"o2_a1": 512, "o1_a1": 256, "o2_a2": 1024}[name])
        chk("d3a.%s.bytes_are_big_endian_hex_of_coordinates" % name,
            data.hex() == "".join(fe(c)[2:] for c in ct_coords))
        chk("d3a.%s.digest_pure_differential" % name, blake2b_pure(data, 32) == dg)
        chk("d3a.%s.digest_split_lossless" % name,
            hi < 2 ** 128 and lo < 2 ** 128 and ((hi << 128) | lo).to_bytes(32, "big") == dg)

        # Mutations: each must change (digest_hi, digest_lo).
        def order(seq):
            return [c for key in seq for c in blocks[key]]

        canon = [(o, a, j) for o in range(1, n + 1) for a in range(1, m + 1) for j in (0, 1)]
        muts = {}
        if n >= 2:
            sw = [(3 - o if o <= 2 else o, a, j) for (o, a, j) in canon]
            muts["swap_outputs"] = d3a_serialize(order(sw))
        sl = [(o, a, 1 - j) if (o, a) == (1, 1) else (o, a, j) for (o, a, j) in canon]
        muts["swap_limbs_note1"] = d3a_serialize(order(sl))
        if m >= 2:
            sa = [(o, 3 - a if a <= 2 else a, j) if o == 1 else (o, a, j) for (o, a, j) in canon]
            muts["swap_auditors_note1"] = d3a_serialize(order(sa))
        plus = list(ct_coords)
        if plus[0] + 1 >= P:
            raise RuntimeError("coordinate +1 would leave F_p")
        plus[0] += 1
        muts["coord0_plus_one"] = d3a_serialize(plus)
        last = list(ct_coords)
        last[-1] = (last[-1] + 1) % P
        muts["last_coord_plus_one"] = d3a_serialize(last)
        muts["little_endian_i2osp"] = d3a_serialize(ct_coords, "little")
        results = {mk: split_digest(hashlib.blake2b(mb, digest_size=32).digest())
                   for mk, mb in muts.items()}
        results["personalized_blake2b"] = split_digest(blake2b_256_pers(PERS, data))
        results["blake2b512_truncated"] = split_digest(hashlib.blake2b(data).digest()[:32])
        results["swap_digest_halves"] = (lo, hi)
        results["with_public_keys_prefixed"] = split_digest(
            hashlib.blake2b(d3a_serialize(pis), digest_size=32).digest())
        for mk in sorted(results):
            mhi, mlo = results[mk]
            prefix = "case.d3a_mut.%s.%s." % (name, mk)
            CASE_COUNTS["d3a_mut"] = CASE_COUNTS.get("d3a_mut", 0) + 1
            emit(prefix + "config", "%s mutated: %s" % (name, mk))
            emit(prefix + "digest_hi", fe(mhi))
            emit(prefix + "digest_lo", fe(mlo))
            chk("d3a_mut.%s.%s.digest_differs" % (name, mk), (mhi, mlo) != (hi, lo))
        chk("d3a.%s.mutation_digests_distinct" % name,
            len(set(results.values())) == len(results))


# =============================================================================
# Main
# =============================================================================

def main():
    emit("profile", "confidential-note-jubjub-v1")
    emit("profile.pers", PERS)
    emit("profile.test_prefix", TEST_PREFIX)
    emit("profile.delivery_length", DELIVERY_LEN)
    emit("profile.plaintext_length", PT_LEN)

    kat_blake2()
    kat_rfc8439()
    kat_ztv()
    drift_checks()
    keys_section()
    deliver_family()
    readerkey_family()
    open_family()
    reuse_family()
    kdf_family()
    elgamal_pins()
    d3a_family()

    reuse_tags = [t for t in EPHEMERAL_TAGS if ".same_e_" in t]
    other_tags = [t for t in EPHEMERAL_TAGS if ".same_e_" not in t]
    chk("lifecycle.ephemeral_tags_never_reused", len(other_tags) == len(set(other_tags)))
    chk("lifecycle.ephemerals_distinct",
        len({scalar(t) for t in EPHEMERAL_TAGS}) == len(set(EPHEMERAL_TAGS)))
    chk("lifecycle.reuse_family_only_reuse", len(reuse_tags) == len(set(reuse_tags)))

    for fam in sorted(CASE_COUNTS):
        emit("info.case_count.%s" % fam, CASE_COUNTS[fam])
    emit("info.case_count", sum(CASE_COUNTS.values()))
    emit("info.check_count", len(CHECKS))
    emit("info.failed_checks", len(FAILED))
    emit("result", "pass" if not FAILED else "fail")
    text = "".join("%s=%s\n" % (k, OUT[k]) for k in sorted(OUT))
    sys.stdout.write(text)
    with open(os.path.join(HERE, "reference-output.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    for k in FAILED:
        sys.stderr.write("FAILED: %s\n" % k)
    return 1 if FAILED else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
