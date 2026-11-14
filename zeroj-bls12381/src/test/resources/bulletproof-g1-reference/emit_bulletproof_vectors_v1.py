#!/usr/bin/env python3
"""Emitter of the `zeroj-proof-vectors-v1` file of `bulletproof-range-bls12-381-g1-v1` (ADR-0061 M2).

Writes, in the format of docs/specs/bulletproof-range-bls12-381-g1-v1.md §11 under the value
conventions of docs/specs/commitment-profiles-v1.md §13.2:

    zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1/
        bulletproof-range-bls12-381-g1-v1.json

Written from the specifications only (bulletproof-range-bls12-381-g1-v1.md r2,
commitment-profiles-v1.md r8 §2.4, §11, §13.2, pedersen-bls12-381-g1-v1.md r2 §4, ADR-0061 M2).
No ZeroJ Java source, Java test or Java test fixture was read.

Every proof, challenge and expected outcome comes from ZeroJ's own Python second implementation,
`bulletproof_range_reference.py` in this directory, IMPORTED by path and never modified. It is not
an official or third-party reference. On top of it this file adds, for --self-test only:

  * its own transcript (spec §4-§5: SHAKE128 duplex sponge, tag, instance, challenges), which
    re-derives `sessionIdHex` and every challenge from the proof octets;
  * its own check 1 (spec §8.3) in the curve module's affine arithmetic, not the reference's
    Jacobian code; check 2 is re-run with the reference's literal Protocol 1/2 folding verifier
    (`_verify_ipa_recursive`), which does not use the s_i bit rule;
  * a structural "intent" check of every negative case: the defects it claims are present at the
    claimed field, no other defect is present, and the expected class and layer are those of the
    first defect in the spec §8.1 order.

Python 3 standard library only. Deterministic: fixed constants, test-only nonce seeds (spec §7.5),
no randomness.

    python3 -I -B emit_bulletproof_vectors_v1.py                 # write the JSON to stdout
    python3 -I -B emit_bulletproof_vectors_v1.py --out PATH      # write the JSON to PATH
    python3 -I -B emit_bulletproof_vectors_v1.py --check         # byte-for-byte compare
    python3 -I -B emit_bulletproof_vectors_v1.py --self-test     # re-verify + mutations

--repo-root DIR overrides the repository root (default: five directories above this file); the
specifications are read from it (for the `spec` provenance hashes) and --check / --self-test
compare with <repo-root>/zeroj-test-vectors/.../bulletproof-range-bls12-381-g1-v1.json.
Exit status 0 on success, non-zero on any failure.

PUBLIC TEST VECTORS ONLY: the seeds, values and blindings below are public, and the test-only
nonce expansion must never be used for a real proof.
"""

import sys

sys.dont_write_bytecode = True  # never leave __pycache__ next to the imported reference

import copy  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import platform  # noqa: E402
import re  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT_REL = ("zeroj-bls12381/src/test/resources/bulletproof-g1-reference/"
              "emit_bulletproof_vectors_v1.py")
OUT_REL = ("zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1/"
           "bulletproof-range-bls12-381-g1-v1.json")
REFERENCE_FILE = "bulletproof_range_reference.py"
GENERATORS_FILE = "generators-v1.json"


def _import_reference():
    path = os.path.join(HERE, REFERENCE_FILE)
    if not os.path.isfile(path):
        raise SystemExit("missing imported reference: " + path)
    spec = importlib.util.spec_from_file_location("bulletproof_range_reference", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bp = _import_reference()
C = bp.C  # the curve module the reference loaded (../pedersen-g1-reference/bls12_381_g1_reference.py)


class PinError(Exception):
    pass


def require(cond, message):
    if not cond:
        raise PinError(message)


# =============================================================================================
# Constants transcribed by hand from the specifications
# =============================================================================================

# bulletproof-range-bls12-381-g1-v1.md §1
Q = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
P_381 = int("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9fe"
            "ffffffffaaab", 16)
BITS = (16, 32, 64)
LOG2 = {16: 4, 32: 5, 64: 6}
MAX_CTX = 1024
# §6 table
PROOF_LEN = {16: 736, 32: 832, 64: 928}
# §11 / commitment-profiles-v1 §5
SCHEMA = "zeroj-proof-vectors-v1"
PROTOCOL_ID = "bulletproof-range-bls12-381-g1-v1"
PROFILE_ID = "pedersen-bls12-381-g1-v1"
GENSET_ID = "bulletproof-bls12-381-g1-gens-v1"
# Appendix A
PIN_D_GENS_HEX = "69abb9e71b740d9be84f63bb146a63467ee452654340f1b09e8be6101e00ef19"
PIN_G0_HEX = ("82ca0040fdcaae82d1dd666dbddaa09c3cd9546ab3a31150cd56385b167c7e0ac100305d0896a5615281"
              "c9aa8712190b")
# pedersen-bls12-381-g1-v1.md §2 (compressed G and H)
PIN_G_HEX = ("80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e9"
             "60e3fd5c2f3e")
PIN_H_HEX = ("92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b"
             "9a2256b6ab65")
# §5.1 example tag (n = 16, ctx = "hello")
PIN_EXAMPLE_TAG = ("ZeroJ:bulletproof-range-bls12-381-g1-v1/DSFS-fiat-shamir-03-sigma-proofs_Shake128_"
                   "BLS12381/N016/A96S96.A96S48.A96S48.(A96S48)x4/CTX0005:68656c6c6f")
# §4
SESSION_ID_LABEL = b"irtf-cfrg-fiat-shamir/session-id"
SHAKE128_RATE = 168

IDENT = bytes([0xC0]) + bytes(47)         # compress(O)
ORDER3 = bytes([0x80]) + bytes(47)        # (0, 2): x = 0, y = 2 is the smaller root; order 3

MAL = "MALFORMED_ENCODING"
NIS = "NOT_IN_SUBGROUP"
NCS = "NON_CANONICAL_SCALAR"
INV = "INVALID_CONFIGURATION"
OOR = "OUT_OF_RANGE"
IST = "INVALID_STATEMENT"
FALSE = "false"
NEG_EXPECTED = {MAL, NIS, NCS, INV, FALSE}
NEG_LAYERS = {"configuration", "statement", "length", "point", "scalar", "challenge", "check1",
              "check2"}
PROVER_EXPECTED = {INV, NCS, OOR, IST}


# =============================================================================================
# Mutations (--self-test switches one on at a time; empty in normal operation)
# =============================================================================================

GEN_MUTATIONS = [
    ("seed_reuse", "the second positive case reuses the first case's nonce seed"),
    ("scalar_q_minus_1", "a scalar case meant to hold exactly q holds q - 1 (canonical)"),
    ("point_offset_shift", "point defects are written 48 octets after the intended field"),
    ("identity_as_order3", "identity defects use the order-3 encoding instead"),
    ("drop_challenge", "the last x_j is dropped from every positive record"),
    ("swap_y_z", "the y and z challenges are swapped in every positive record"),
    ("layer_last_check", "when both checks fail, the layer names check 2"),
    ("ctx_1025_positive", "the 1,024-octet positive context is one octet longer"),
    ("value_2n_positive", "the 2^n - 1 positive values are 2^n"),
    ("prover_order_range_first", "prover refusal order puts v >= 2^n before check 1"),
    ("reference_transcript_drop_V", "reference seam: V dropped from the instance while generating"),
    ("reference_s_lsb", "reference seam: LSB-first s_i rule while generating"),
]
GEN_MUTATION_NAMES = {n for n, _ in GEN_MUTATIONS}
MUT = set()


def mut(name):
    require(name in GEN_MUTATION_NAMES, "unknown mutation " + name)
    return name in MUT


# =============================================================================================
# Memoised calls into the reference (keyed by their inputs; bypassed under reference seams)
# =============================================================================================

class Memo:
    def __init__(self):
        self.store = {}
        self.enabled = True

    def get(self, key, fn):
        if not self.enabled:
            return fn()
        if key not in self.store:
            self.store[key] = fn()
        return self.store[key]


MEMO = Memo()


def ref_prove(v, gamma, n, ctx, seed):
    """§7.5 test-nonce prover of the reference: (proof octets, trace dict)."""
    return MEMO.get(("prove", v, gamma, n, ctx, seed),
                    lambda: bp._prove_with_test_nonces(v, gamma, n, ctx, seed))


def ref_detail(v_bytes, proof, n, ctx):
    """(outcome, layer, check1, check2): outcome "true", "false" or an error class."""
    def run():
        try:
            d = bp.verify_detailed(v_bytes, proof, n, ctx)
        except bp.BulletproofError as e:
            return (e.error_class, e.layer, None, None)
        return ("true" if d["verdict"] else "false", d["layer"], d.get("check1"), d.get("check2"))
    return MEMO.get(("verify", v_bytes, proof, n, ctx), run)


def ref_classify(v_bytes, proof, n, ctx):
    outcome, layer, c1, c2 = ref_detail(v_bytes, proof, n, ctx)
    if mut("layer_last_check") and layer == "check1" and c2 is False:
        layer = "check2"
    return outcome, layer


def ref_recursive(v_bytes, proof, n, ctx):
    return MEMO.get(("recursive", v_bytes, proof, n, ctx),
                    lambda: bp._verify_ipa_recursive(v_bytes, proof, n, ctx))


def ref_prover_refusal(v, gamma, n, ctx):
    """The reference prover's §7.1 preamble: the refusal class, or None."""
    def run():
        try:
            bp._prover_preamble(v, gamma, n, ctx)
        except bp.BulletproofError as e:
            return e.error_class
        return None
    return MEMO.get(("preamble", v, gamma, n, ctx), run)


def ref_cheat(v, gamma, n, ctx, seed, a_l_override=None):
    """A cheating prover (ADR-0061 test strategy): the reference's §7.2 core with test nonces,
    WITHOUT the §7.1 refusals, so it can be made to prove v >= 2^n or a non-bit a_L."""
    def run():
        V = bp.commit(v, gamma)
        proof, trace = bp._prove_core(v, gamma, n, ctx, V, bp._test_nonces(n, seed),
                                      a_l_override=a_l_override)
        return proof, trace["commitment"]
    return MEMO.get(("cheat", v, gamma, n, ctx, seed, None if a_l_override is None
                     else tuple(a_l_override)), run)


# =============================================================================================
# Own helpers: field layout, encodings, transcript and check 1 (spec §3-§6, §8.3)
# =============================================================================================

def layout(n):
    """The proof's fields in proof order (§6): list of (name, kind, offset, size)."""
    k = LOG2[n]
    names = [("A", "point"), ("S", "point"), ("T1", "point"), ("T2", "point"),
             ("t_hat", "scalar"), ("tau_x", "scalar"), ("mu", "scalar")]
    for j in range(1, k + 1):
        names += [("L_%d" % j, "point"), ("R_%d" % j, "point")]
    names += [("a", "scalar"), ("b", "scalar")]
    out, off = [], 0
    for name, kind in names:
        size = 48 if kind == "point" else 32
        out.append((name, kind, off, size))
        off += size
    require(off == PROOF_LEN[n], "layout length for n = %d" % n)
    return out


def field(n, name):
    for i, (nm, kind, off, size) in enumerate(layout(n)):
        if nm == name:
            return i, kind, off, size
    raise PinError("no field %s at n = %d" % (name, n))


def get_field(proof, n, name):
    _, _, off, size = field(n, name)
    return proof[off:off + size]


def set_field(proof, n, name, new):
    _, kind, off, size = field(n, name)
    require(len(new) == size, "replacement size for " + name)
    if kind == "point" and mut("point_offset_shift") and off + 96 <= len(proof):
        off += 48   # the mutation writes the defect over the next 48 octets instead
    return proof[:off] + new + proof[off + size:]


def i2osp(x, w):
    return x.to_bytes(w, "big")


def os2ip(b):
    return int.from_bytes(b, "big")


def scalar_bytes(s):
    return i2osp(s, 32)


def tweak_scalar(proof, n, name, delta):
    """Re-encode a scalar field canonically as (s + delta) mod q."""
    s = os2ip(get_field(proof, n, name))
    return set_field(proof, n, name, scalar_bytes((s + delta) % Q))


_DECODE_CACHE = {}


def strict_decode_cached(b):
    b = bytes(b)
    if b not in _DECODE_CACHE:
        _DECODE_CACHE[b] = C.strict_decode(b)
    return _DECODE_CACHE[b]


def point_form(b):
    """None for a valid non-identity subgroup point; else "identity", "malformed", "nonsubgroup"."""
    status, val = strict_decode_cached(b)
    if status == "ok":
        return "identity" if val is None else None
    return "nonsubgroup" if status == C.NOT_IN_SUBGROUP else "malformed"


def v_form(b):
    """As point_form, for V (the profile's decoder accepts the identity; §8.1 step 5 makes it false)."""
    return point_form(b)


def scalar_form(b):
    return "noncanonical" if os2ip(b) >= Q else None


def decode_point(b):
    status, val = strict_decode_cached(b)
    require(status == "ok", "decode_point on an invalid encoding")
    return val


def neg_point_bytes(b):
    """compress(-P) for a valid finite point P (the sort flag flips)."""
    x, y = decode_point(b)
    return C.compress((x, (-y) % P_381))


def plus_order3(b):
    """compress(P + (0, 2)): a valid curve point outside the subgroup."""
    return C.compress(C.point_add(decode_point(b), (0, 2)))


def x_encoding(x, flags=0x80):
    out = bytearray(i2osp(x, 48))
    out[0] |= flags
    return bytes(out)


def _find_x(predicate):
    x = 1
    while not predicate(x):
        x += 1
    return x


def malformed_forms():
    """Encodings each rejected by the strict decoder (pedersen-bls12-381-g1-v1.md §4)."""
    off_x = _find_x(lambda x: not C.is_square((x ** 3 + 4) % P_381))
    return {
        "x-ge-p": x_encoding(P_381),
        "x-not-on-curve": x_encoding(off_x),
        "infinity-sort-flag": bytes([0xE0]) + bytes(47),
        "infinity-nonzero": bytes([0xC0]) + bytes(46) + b"\x01",
    }


def other_nonsubgroup():
    """The curve point with the smallest x >= 1 that is outside the subgroup (not order 3)."""
    def ok(x):
        rhs = (x ** 3 + 4) % P_381
        if not C.is_square(rhs):
            return False
        return not C.in_subgroup((x, C.sqrt(rhs)))
    x = _find_x(ok)
    rhs = (x ** 3 + 4) % P_381
    return C.compress((x, C.sqrt(rhs)))


def le(x, w):
    return x.to_bytes(w, "little")


class Sponge:
    """fiat-shamir-03 §3.2 XOF duplex sponge over SHAKE128 (spec §4), written here independently."""

    def __init__(self, sid):
        require(len(sid) == 32, "session id length")
        self.buf = bytearray(sid + bytes(SHAKE128_RATE - 32))
        self.reader = None
        self.pos = 0

    def absorb(self, x):
        if x:
            self.buf += x
            self.reader = None

    def squeeze(self, m):
        if self.reader is None:
            self.reader = bytes(self.buf)
            self.pos = 0
        out = hashlib.shake_128(self.reader).digest(self.pos + m)[self.pos:]
        self.pos += m
        return out


def own_session_id(tag):
    s = Sponge(SESSION_ID_LABEL)
    s.absorb(tag)
    return s.squeeze(32)


def own_tag(n, ctx):
    return (b"ZeroJ:bulletproof-range-bls12-381-g1-v1"
            + b"/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381"
            + b"/N" + ("%03d" % n).encode() + b"/A96S96.A96S48.A96S48.(A96S48)x" + str(LOG2[n]).encode()
            + b"/CTX" + ("%04d" % len(ctx)).encode() + b":" + ctx.hex().encode())


def own_instance(n, v_bytes):
    def varlen(s):
        return le(len(s), 4) + s
    return (varlen(PROFILE_ID.encode()) + bytes.fromhex(PIN_G_HEX) + bytes.fromhex(PIN_H_HEX)
            + varlen(GENSET_ID.encode()) + bytes.fromhex(PIN_D_GENS_HEX) + le(n, 4) + v_bytes)


def own_challenges(n, ctx, v_bytes, proof):
    """(session id, {"y","z","x","xu","xj":[...]}) as integers, from the proof octets (§5.3)."""
    sid = own_session_id(own_tag(n, ctx))
    s = Sponge(sid)
    s.absorb(own_instance(n, v_bytes))

    def dec():
        return int.from_bytes(s.squeeze(48), "little") % Q
    s.absorb(proof[0:96])
    y = dec()
    z = dec()
    s.absorb(proof[96:192])
    x = dec()
    s.absorb(proof[192:288])
    xu = dec()
    xj = []
    for j in range(LOG2[n]):
        s.absorb(proof[288 + 96 * j:288 + 96 * (j + 1)])
        xj.append(dec())
    return sid, {"y": y, "z": z, "x": x, "xu": xu, "xj": xj}


_BASES = {}


def bases():
    if not _BASES:
        g, h = C.derive_basis()
        require(C.compress(g).hex() == PIN_G_HEX and C.compress(h).hex() == PIN_H_HEX,
                "profile bases G, H differ from the pinned encodings")
        _BASES["G"], _BASES["H"] = g, h
    return _BASES["G"], _BASES["H"]


def affine_lincomb(terms):
    acc = None
    for k, pt in terms:
        acc = C.point_add(acc, C.scalar_mul(k % Q, pt))
    return acc


def own_commit(v, gamma):
    g, h = bases()
    return C.compress(affine_lincomb([(v, g), (gamma, h)]))


def own_check1(n, ctx, v_bytes, proof):
    """Spec §8.3 check 1 in the curve module's affine arithmetic.  Inputs must decode."""
    _, ch = own_challenges(n, ctx, v_bytes, proof)
    y, z, x = ch["y"], ch["z"], ch["x"]
    g, h = bases()
    t_hat = os2ip(get_field(proof, n, "t_hat"))
    tau_x = os2ip(get_field(proof, n, "tau_x"))
    sum_y = sum(pow(y, i, Q) for i in range(n)) % Q
    delta = ((z - z * z) * sum_y - pow(z, 3, Q) * ((1 << n) - 1)) % Q
    acc = affine_lincomb([(t_hat - delta, g), (tau_x, h), (-z * z, decode_point(v_bytes)),
                          (-x, decode_point(get_field(proof, n, "T1"))),
                          (-x * x, decode_point(get_field(proof, n, "T2")))])
    return acc is None


# =============================================================================================
# Case definitions
# =============================================================================================

CTX_1 = b"\x00"
CTX_HELLO = b"hello"
CTX_URL = b"https://example.com/payroll/v1"
CTX_1024 = bytes((131 * i + 17) % 256 for i in range(1024))   # the §13.2 pattern 131i+17
CTX_1025 = bytes((131 * i + 17) % 256 for i in range(1025))

SEED_LABEL = b"ZeroJ bulletproof-range-bls12-381-g1-v1 M2 vector nonce seed/"
BLIND_LABEL = b"ZeroJ bulletproof-range-bls12-381-g1-v1 M2 vector blinding/"
# The fixed example of the reference's --print-trace, externally confirmed in M0 (README).
TRACE_ID = "n16-vmid-hello-trace"
TRACE_SEED = bytes(range(32))
TRACE_BLINDING = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF


def seed_for(case_id):
    return hashlib.sha256(SEED_LABEL + case_id.encode()).digest()


def blinding_for(case_id):
    r = int.from_bytes(hashlib.sha512(BLIND_LABEL + case_id.encode()).digest(), "big") % Q
    require(r != 0, "zero derived blinding")
    return r


MID = {16: 12345, 32: 0x89ABCDEF, 64: 0x0123456789ABCDEF}


def positive_specs():
    """(id, n, value, blinding, ctx, seed).  Every case has its own seed (spec §7.5)."""
    rows = [
        # n = 16: 0 -> 1 octet, 1 -> URL, max -> 1,024 octets, mid -> "hello" (the trace example)
        ("n16-v0-ctx1", 16, "0", CTX_1),
        ("n16-v1-url", 16, "1", CTX_URL),
        ("n16-vmax-ctx1024", 16, "max", CTX_1024),
        (TRACE_ID, 16, "mid", CTX_HELLO),
        # n = 32
        ("n32-v0-hello", 32, "0", CTX_HELLO),
        ("n32-v1-ctx1024", 32, "1", CTX_1024),
        ("n32-vmax-ctx1", 32, "max", CTX_1),
        ("n32-vmid-url", 32, "mid", CTX_URL),
        # n = 64
        ("n64-v0-url", 64, "0", CTX_URL),
        ("n64-v1-ctx1", 64, "1", CTX_1),
        ("n64-vmax-hello", 64, "max", CTX_HELLO),
        ("n64-vmid-ctx1024", 64, "mid", CTX_1024),
        # extras: edge blindings and a power of two
        ("n64-v2pow63-blinding-qm1-hello", 64, "2^63", CTX_HELLO),
        ("n32-v0-blinding-1-url", 32, "0", CTX_URL),
    ]
    out = []
    for cid, n, vk, ctx in rows:
        if vk == "0":
            v = 0
        elif vk == "1":
            v = 1
        elif vk == "max":
            v = (1 << n) - 1 if not mut("value_2n_positive") else (1 << n)
        elif vk == "mid":
            v = MID[n]
        else:
            v = 1 << 63
        if ctx is CTX_1024 and mut("ctx_1025_positive"):
            ctx = CTX_1025
        if cid == TRACE_ID:
            gamma, seed = TRACE_BLINDING, TRACE_SEED
        elif cid == "n64-v2pow63-blinding-qm1-hello":
            gamma, seed = Q - 1, seed_for(cid)
        elif cid == "n32-v0-blinding-1-url":
            gamma, seed = 1, seed_for(cid)
        else:
            gamma, seed = blinding_for(cid), seed_for(cid)
        out.append((cid, n, v, gamma, ctx, seed))
    if mut("seed_reuse"):
        c, n, v, g, x, _ = out[1]
        out[1] = (c, n, v, g, x, out[0][5])
    return out


def build_positives(strict):
    cases, raw = [], {}
    for cid, n, v, gamma, ctx, seed in positive_specs():
        try:
            proof, tr = ref_prove(v, gamma, n, ctx, seed)
        except (bp.BulletproofError, bp.TestNonceProverFailure) as e:
            if strict:
                raise PinError("positive %s: prover refused (%s)" % (cid, e))
            continue
        vb = tr["commitment"]
        if strict:
            got = ref_classify(vb, proof, n, ctx)
            require(got == ("true", "accept"), "positive %s: reference verifier gave %s" % (cid, got))
        ch = tr["challenges"]
        xj = [str(ch["x_%d" % j]) for j in range(1, LOG2[n] + 1)]
        if mut("drop_challenge"):
            xj = xj[:-1]
        y, z = str(ch["y"]), str(ch["z"])
        if mut("swap_y_z"):
            y, z = z, y
        cases.append({
            "id": cid, "bits": str(n), "ctxHex": ctx.hex(), "value": str(v), "blinding": str(gamma),
            "commitmentHex": vb.hex(), "nonceSeedHex": seed.hex(),
            "sessionIdHex": tr["sessionId"].hex(),
            "challenges": {"y": y, "z": z, "x": str(ch["x"]), "xu": str(ch["xu"]), "xj": xj},
            "proofHex": proof.hex(),
        })
        raw[cid] = (n, ctx, vb, proof, v, gamma)
    return cases, raw


# ---- negatives ---------------------------------------------------------------------------------
#
# Each negative carries an intent (not written to the file): its declared defects, an optional
# base positive id, and tags.  Defects:
#   ("config",) ("length",) ("field", name, form) ("V", form) ("check1",) ("check2",)
# with form in identity / malformed / nonsubgroup (points, V) or noncanonical (scalars).
# The expected class and layer are those of the first defect in the §8.1 order.

FORM_CLASS = {"identity": MAL, "malformed": MAL, "nonsubgroup": NIS, "noncanonical": NCS}


def defect_rank(n, d):
    if d[0] == "config":
        return 0
    if d[0] == "length":
        return 1
    if d[0] == "field":
        return 2 + field(n, d[1])[0]
    if d[0] == "V":
        return 1001 if d[1] == "identity" else 1000
    return {"check1": 1002, "check2": 1003}[d[0]]


def defect_outcome(n, d):
    if d[0] == "config":
        return INV, "configuration"
    if d[0] == "length":
        return MAL, "length"
    if d[0] == "field":
        return FORM_CLASS[d[2]], field(n, d[1])[1]
    if d[0] == "V":
        return (FALSE, "statement") if d[1] == "identity" else (FORM_CLASS[d[1]], "statement")
    return FALSE, d[0]


def first_outcome(n, defects):
    if any(d[0] == "config" for d in defects):
        return INV, "configuration"
    d = min(defects, key=lambda d: defect_rank(n, d))
    return defect_outcome(n, d)


def identity_bytes():
    return ORDER3 if mut("identity_as_order3") else IDENT


def q_bytes():
    return scalar_bytes(Q - 1) if mut("scalar_q_minus_1") else Q.to_bytes(32, "big")


def build_negative_specs(raw):
    """List of dicts: id, bits, ctx, V, proof, defects, base, tags."""
    out = []

    def add(cid, bits, ctx, vb, proof, defects, base=None, tags=()):
        out.append({"id": cid, "bits": bits, "ctx": ctx, "V": vb, "proof": proof,
                    "defects": list(defects), "base": base, "tags": list(tags)})

    b16 = TRACE_ID
    n, ctx0, V0, P0, v0, g0 = raw[b16]
    _, _, V32, P32, _, _ = raw["n32-vmid-url"]
    n64id = "n64-vmax-hello"
    _, ctx64, V64, P64, _, _ = raw[n64id]
    mal = malformed_forms()
    nonsub = other_nonsubgroup()
    g0_enc = bytes.fromhex(PIN_G0_HEX)
    k16 = LOG2[16]
    last16 = "R_%d" % k16

    # -- configuration (§8.1 step 1)
    for bits in (8, 24, 128, 0):
        add("cfg-bits-%d" % bits, bits, ctx0, V0, P0, [("config",)], b16)
    add("cfg-ctx-empty", 16, b"", V0, P0, [("config",)], b16)
    add("cfg-ctx-1025", 16, CTX_1025, V0, P0, [("config",)], b16)
    add("order-cfg-bits-8-short-proof-v-order3", 8, ctx0, ORDER3, P0[:-1],
        [("config",), ("V", "nonsubgroup")], b16, ["also-length"])
    add("order-cfg-ctx-empty-A-identity", 16, b"", V0, set_field(P0, 16, "A", identity_bytes()),
        [("config",)], b16, ["also-field"])
    add("order-cfg-ctx-1025-v-identity", 16, CTX_1025, IDENT, P0, [("config",), ("V", "identity")],
        b16)

    # -- statement (§8.1 steps 4 and 5): V
    add("stmt-v-empty", 16, ctx0, b"", P0, [("V", "malformed")], b16)
    add("stmt-v-length-47", 16, ctx0, V0[:47], P0, [("V", "malformed")], b16)
    add("stmt-v-length-49", 16, ctx0, V0 + b"\x00", P0, [("V", "malformed")], b16)
    add("stmt-v-no-compression-flag", 16, ctx0, bytes([V0[0] & 0x7F]) + V0[1:], P0,
        [("V", "malformed")], b16)
    for name, enc in mal.items():
        add("stmt-v-" + name, 16, ctx0, enc, P0, [("V", "malformed")], b16)
    add("stmt-v-order3", 16, ctx0, ORDER3, P0, [("V", "nonsubgroup")], b16)
    add("stmt-v-commitment-plus-order3", 16, ctx0, plus_order3(V0), P0, [("V", "nonsubgroup")], b16,
        ["v-plus-order3"])
    v7_11 = own_commit(7, 11)
    add("stmt-v-7G-11H-plus-order3", 16, ctx0, plus_order3(v7_11), P0, [("V", "nonsubgroup")], b16,
        ["v-plus-order3"])
    add("stmt-v-other-nonsubgroup", 16, ctx0, nonsub, P0, [("V", "nonsubgroup")], b16)
    add("stmt-v-identity", 16, ctx0, IDENT, P0, [("V", "identity")], b16)
    add("stmt-v-identity-n64", 64, ctx64, IDENT, P64, [("V", "identity")], n64id)

    # -- length (§8.1 step 2)
    add("len-empty", 16, ctx0, V0, b"", [("length",)], b16)
    add("len-short-1", 16, ctx0, V0, P0[:-1], [("length",)], b16, ["len-short"])
    add("len-long-1", 16, ctx0, V0, P0 + b"\x00", [("length",)], b16, ["len-long"])
    add("len-n32-proof-at-n16", 16, ctx0, V32, P32, [("length",)], "n32-vmid-url", ["len-other-width"])
    add("len-n16-proof-at-n32", 32, ctx0, V0, P0, [("length",)], b16, ["len-other-width"])
    add("len-n64-proof-at-n16", 16, ctx64, V64, P64, [("length",)], n64id, ["len-other-width"])
    add("len-n64-proof-at-n32", 32, ctx64, V64, P64, [("length",)], n64id, ["len-other-width"])
    add("order-len-short-v-order3", 16, ctx0, ORDER3, P0[:-1], [("length",), ("V", "nonsubgroup")], b16)
    add("order-len-long-v-identity", 16, ctx0, IDENT, P0 + b"\x00", [("length",), ("V", "identity")], b16)
    add("order-len-short-v-length-47", 16, ctx0, V0[:47], P0[:-32], [("length",), ("V", "malformed")],
        b16)

    # -- point (§8.1 step 3)
    def pt_cases(prefix, nn, ctx, vb, proof, base, name, forms):
        for form_name in forms:
            if form_name == "identity":
                enc, form = identity_bytes(), "identity"
            elif form_name == "order3":
                enc, form = ORDER3, "nonsubgroup"
            elif form_name == "plus-order3":
                enc, form = plus_order3(get_field(proof, nn, name)), "nonsubgroup"
            elif form_name == "other-nonsubgroup":
                enc, form = nonsub, "nonsubgroup"
            elif form_name == "no-compression-flag":
                orig = get_field(proof, nn, name)
                enc, form = bytes([orig[0] & 0x7F]) + orig[1:], "malformed"
            else:
                enc, form = mal[form_name], "malformed"
            add("%s-%s-%s" % (prefix, name, form_name), nn, ctx, vb, set_field(proof, nn, name, enc),
                [("field", name, form)], base)

    pt_cases("point", 16, ctx0, V0, P0, b16, "A",
             ["identity", "order3", "plus-order3", "other-nonsubgroup", "no-compression-flag",
              "x-ge-p", "x-not-on-curve", "infinity-sort-flag", "infinity-nonzero"])
    pt_cases("point", 16, ctx0, V0, P0, b16, "S", ["identity"])
    pt_cases("point", 16, ctx0, V0, P0, b16, "T1", ["order3"])
    pt_cases("point", 16, ctx0, V0, P0, b16, "T2", ["x-not-on-curve"])
    pt_cases("point", 16, ctx0, V0, P0, b16, "L_1", ["identity"])
    pt_cases("point", 16, ctx0, V0, P0, b16, "L_2", ["identity", "order3", "x-ge-p"])
    pt_cases("point", 16, ctx0, V0, P0, b16, last16,
             ["identity", "order3", "plus-order3", "x-ge-p", "no-compression-flag"])
    pt_cases("point-n32", 32, CTX_URL, V32, P32, "n32-vmid-url", "R_5", ["identity", "order3"])
    pt_cases("point-n64", 64, ctx64, V64, P64, n64id, "L_3", ["identity", "order3", "x-ge-p"])
    pt_cases("point-n64", 64, ctx64, V64, P64, n64id, "R_6", ["identity", "order3", "x-not-on-curve"])

    # -- scalar (§8.1 step 3, check 1 of §3)
    for name in ("t_hat", "tau_x", "mu", "a", "b"):
        orig = os2ip(get_field(P0, 16, name))
        for label, val in (("q", q_bytes()), ("2pow256-minus-1", b"\xff" * 32),
                           ("plus-q", (orig + Q).to_bytes(32, "big"))):
            add("scalar-%s-%s" % (name, label), 16, ctx0, V0, set_field(P0, 16, name, val),
                [("field", name, "noncanonical")], b16)
    add("scalar-n64-a-q", 64, ctx64, V64, set_field(P64, 64, "a", q_bytes()),
        [("field", "a", "noncanonical")], n64id)
    add("scalar-n64-b-2pow256-minus-1", 64, ctx64, V64, set_field(P64, 64, "b", b"\xff" * 32),
        [("field", "b", "noncanonical")], n64id)

    # -- check 1 / check 2 (§8.3): well-formed proofs that fail an equation
    both = [("check1",), ("check2",)]
    add("chk-t_hat-plus-1", 16, ctx0, V0, tweak_scalar(P0, 16, "t_hat", 1), both, b16,
        ["scalar-tamper:t_hat", "both-checks"])
    add("chk-tau_x-plus-1", 16, ctx0, V0, tweak_scalar(P0, 16, "tau_x", 1), both, b16,
        ["scalar-tamper:tau_x"])
    add("chk-mu-plus-1", 16, ctx0, V0, tweak_scalar(P0, 16, "mu", 1), [("check2",)], b16,
        ["scalar-tamper:mu"])
    add("chk-a-plus-1", 16, ctx0, V0, tweak_scalar(P0, 16, "a", 1), [("check2",)], b16,
        ["scalar-tamper:a"])
    add("chk-b-plus-1", 16, ctx0, V0, tweak_scalar(P0, 16, "b", 1), [("check2",)], b16,
        ["scalar-tamper:b"])
    add("chk-a-zero", 16, ctx0, V0, set_field(P0, 16, "a", bytes(32)), [("check2",)], b16,
        ["zero-scalar"])
    add("chk-A-replaced-by-G0", 16, ctx0, V0, set_field(P0, 16, "A", g0_enc), both, b16)
    add("chk-T1-negated", 16, ctx0, V0, set_field(P0, 16, "T1", neg_point_bytes(get_field(P0, 16, "T1"))),
        both, b16)
    add("chk-L_1-negated", 16, ctx0, V0,
        set_field(P0, 16, "L_1", neg_point_bytes(get_field(P0, 16, "L_1"))), [("check2",)], b16)
    swapped = set_field(set_field(P0, 16, "L_1", get_field(P0, 16, "R_1")), 16, "R_1",
                        get_field(P0, 16, "L_1"))
    add("chk-L_1-R_1-swapped", 16, ctx0, V0, swapped, [("check2",)], b16)
    add("chk-%s-replaced-by-G0" % last16, 16, ctx0, V0, set_field(P0, 16, last16, g0_enc),
        [("check2",)], b16)
    add("chk-wrong-ctx-hellp", 16, b"hellp", V0, P0, both, b16, ["same-proof-other-ctx"])
    add("chk-wrong-ctx-1-octet", 16, CTX_1, V0, P0, both, b16, ["same-proof-other-ctx"])
    add("chk-other-commitment", 16, ctx0, own_commit(v0 + 1, g0), P0, both, b16,
        ["same-proof-other-V"])
    add("chk-commitment-negated", 16, ctx0, neg_point_bytes(V0), P0, both, b16, ["same-proof-other-V"])
    add("chk-commitment-of-other-case", 16, ctx0, raw["n16-v1-url"][2], P0, both, b16,
        ["same-proof-other-V"])
    # ADR-0061 test strategy: a test-only prover forcing an out-of-range value
    p_cheat, v_cheat = ref_cheat(1 << 16, g0, 16, ctx0, seed_for("cheat-v-2pow16"))
    add("chk-forced-v-2pow16", 16, ctx0, v_cheat, p_cheat, [("check1",)], None, ["forced-out-of-range"])
    a_bad = [(12346 >> i) & 1 for i in range(16)]
    a_bad[0] += 2   # a non-bit entry: <a_L, 2^n> = 12348 but a_L o a_R != 0
    p_cheat2, v_cheat2 = ref_cheat(12348, g0, 16, ctx0, seed_for("cheat-non-bit"), a_l_override=a_bad)
    add("chk-forced-non-bit-a_L", 16, ctx0, v_cheat2, p_cheat2, [("check1",)], None, ["forced-non-bit"])
    add("chk-n64-t_hat-plus-1", 64, ctx64, V64, tweak_scalar(P64, 64, "t_hat", 1), both, n64id,
        ["scalar-tamper:t_hat"])
    add("chk-n64-a-plus-1", 64, ctx64, V64, tweak_scalar(P64, 64, "a", 1), [("check2",)], n64id,
        ["scalar-tamper:a"])
    add("chk-n64-wrong-ctx", 64, CTX_HELLO + b"!", V64, P64, both, n64id, ["same-proof-other-ctx"])

    # -- first failure in proof order (§8.1 step 3, then step 4)
    def two(p, a, b):
        return set_field(set_field(p, 16, a[0], a[1]), 16, b[0], b[1])
    add("order-A-identity-then-t_hat-q", 16, ctx0, V0,
        two(P0, ("A", identity_bytes()), ("t_hat", q_bytes())),
        [("field", "A", "identity"), ("field", "t_hat", "noncanonical")], b16)
    add("order-S-order3-then-T2-identity", 16, ctx0, V0,
        two(P0, ("S", ORDER3), ("T2", identity_bytes())),
        [("field", "S", "nonsubgroup"), ("field", "T2", "identity")], b16)
    add("order-t_hat-q-then-L_1-identity", 16, ctx0, V0,
        two(P0, ("t_hat", q_bytes()), ("L_1", identity_bytes())),
        [("field", "t_hat", "noncanonical"), ("field", "L_1", "identity")], b16)
    add("order-tau_x-2pow256-minus-1-then-R_1-order3", 16, ctx0, V0,
        two(P0, ("tau_x", b"\xff" * 32), ("R_1", ORDER3)),
        [("field", "tau_x", "noncanonical"), ("field", "R_1", "nonsubgroup")], b16)
    add("order-L_1-order3-then-a-q", 16, ctx0, V0,
        two(P0, ("L_1", ORDER3), ("a", q_bytes())),
        [("field", "L_1", "nonsubgroup"), ("field", "a", "noncanonical")], b16)
    add("order-%s-identity-then-b-q" % last16, 16, ctx0, V0,
        two(P0, (last16, identity_bytes()), ("b", q_bytes())),
        [("field", last16, "identity"), ("field", "b", "noncanonical")], b16)
    add("order-a-q-then-b-q", 16, ctx0, V0, two(P0, ("a", q_bytes()), ("b", q_bytes())),
        [("field", "a", "noncanonical"), ("field", "b", "noncanonical")], b16)
    add("order-v-length-47-and-mu-q", 16, ctx0, V0[:47], set_field(P0, 16, "mu", q_bytes()),
        [("field", "mu", "noncanonical"), ("V", "malformed")], b16)
    add("order-v-order3-and-A-identity", 16, ctx0, ORDER3, set_field(P0, 16, "A", identity_bytes()),
        [("field", "A", "identity"), ("V", "nonsubgroup")], b16)
    add("order-v-plus-order3-and-L_2-order3", 16, ctx0, plus_order3(V0),
        set_field(P0, 16, "L_2", ORDER3), [("field", "L_2", "nonsubgroup"), ("V", "nonsubgroup")], b16)
    add("order-v-identity-and-b-q", 16, ctx0, IDENT, set_field(P0, 16, "b", q_bytes()),
        [("field", "b", "noncanonical"), ("V", "identity")], b16)
    add("order-v-order3-and-a-plus-1", 16, ctx0, ORDER3, tweak_scalar(P0, 16, "a", 1),
        [("V", "nonsubgroup")], b16, ["scalar-tamper:a"])
    add("order-v-length-47-and-t_hat-plus-1", 16, ctx0, V0[:47], tweak_scalar(P0, 16, "t_hat", 1),
        [("V", "malformed")], b16, ["scalar-tamper:t_hat"])
    add("order-v-identity-and-a-plus-1", 16, ctx0, IDENT, tweak_scalar(P0, 16, "a", 1),
        [("V", "identity")], b16, ["scalar-tamper:a"])
    return out


def build_negatives(raw, strict):
    specs = build_negative_specs(raw)
    cases, intents = [], {}
    for s in specs:
        n = s["bits"]
        intended = first_outcome(n, s["defects"])
        got = ref_classify(s["V"], s["proof"], n, s["ctx"])
        if strict:
            require(got == intended, "negative %s: intended %s, reference gave %s"
                    % (s["id"], intended, got))
        cases.append({"id": s["id"], "bits": str(n), "ctxHex": s["ctx"].hex(),
                      "commitmentHex": s["V"].hex(), "proofHex": s["proof"].hex(),
                      "expected": got[0], "layer": got[1]})
        intents[s["id"]] = s
    return cases, intents


# ---- prover refusals (§7.1) --------------------------------------------------------------------
#
# Java binding constraint (from the integrator): the Java opening type rejects a non-canonical
# value or blinding when it is constructed, before the prover's configuration check.  So a
# non-canonical case is otherwise valid (bits 16, a normal ctx), and every configuration case has
# a canonical value and blinding.

def own_prover_refusal(v, gamma, n, ctx):
    """§7.1, written here independently: the refusal class, or None."""
    if n not in BITS or not 1 <= len(ctx) <= MAX_CTX:
        return INV
    order = ["ncs", "range"] if not mut("prover_order_range_first") else ["range", "ncs"]
    for step in order:
        if step == "ncs" and not (0 <= v < Q and 0 <= gamma < Q):
            return NCS
        if step == "range" and v >= (1 << n):
            return OOR
    g, h = bases()
    if affine_lincomb([(v, g), (gamma, h)]) is None:
        return IST
    return None


def prover_specs():
    gb = blinding_for("prover-negative")
    rows = [
        ("prove-cfg-bits-8", 8, CTX_HELLO, 1, gb, INV),
        ("prove-cfg-bits-24", 24, CTX_HELLO, 1, gb, INV),
        ("prove-cfg-bits-128", 128, CTX_HELLO, 1, gb, INV),
        ("prove-cfg-bits-0", 0, CTX_HELLO, 1, gb, INV),
        ("prove-cfg-ctx-empty", 16, b"", 1, gb, INV),
        ("prove-cfg-ctx-1025", 16, CTX_1025, 1, gb, INV),
        ("prove-cfg-bits-8-and-v-2pow16", 8, CTX_HELLO, 1 << 16, gb, INV),
        ("prove-cfg-ctx-empty-and-identity", 16, b"", 0, 0, INV),
        ("prove-cfg-bits-24-and-v-2pow64", 24, CTX_HELLO, 1 << 64, gb, INV),
        ("prove-ncs-value-q", 16, CTX_HELLO, Q, gb, NCS),
        ("prove-ncs-value-q-plus-1", 16, CTX_HELLO, Q + 1, gb, NCS),
        ("prove-ncs-value-minus-1", 16, CTX_HELLO, -1, gb, NCS),
        ("prove-ncs-blinding-q", 16, CTX_HELLO, 1, Q, NCS),
        ("prove-ncs-blinding-minus-1", 16, CTX_HELLO, 1, -1, NCS),
        ("prove-ncs-value-q-at-n64", 64, CTX_HELLO, Q, gb, NCS),
        ("prove-range-v-2pow16", 16, CTX_HELLO, 1 << 16, gb, OOR),
        ("prove-range-v-2pow32", 32, CTX_HELLO, 1 << 32, gb, OOR),
        ("prove-range-v-2pow64", 64, CTX_HELLO, 1 << 64, gb, OOR),
        ("prove-range-v-q-minus-1-n16", 16, CTX_HELLO, Q - 1, gb, OOR),
        ("prove-range-v-q-minus-1-n64", 64, CTX_HELLO, Q - 1, gb, OOR),
        ("prove-range-v-2pow16-blinding-0", 16, CTX_HELLO, 1 << 16, 0, OOR),
        ("prove-range-v-2pow32-at-n16-ctx1024", 16, CTX_1024, 1 << 32, gb, OOR),
        ("prove-statement-zero-n16", 16, CTX_HELLO, 0, 0, IST),
        ("prove-statement-zero-n32", 32, CTX_1, 0, 0, IST),
        ("prove-statement-zero-n64-ctx1024", 64, CTX_1024, 0, 0, IST),
    ]
    return rows


def build_prover_negatives(strict):
    cases = []
    for cid, n, ctx, v, gamma, intended in prover_specs():
        own = own_prover_refusal(v, gamma, n, ctx)
        got = ref_prover_refusal(v, gamma, n, ctx)
        if strict:
            require(own == intended, "prover %s: intended %s, own §7.1 order gave %s" % (cid, intended, own))
            require(got == intended, "prover %s: intended %s, reference gave %s" % (cid, intended, got))
        cases.append({"id": cid, "bits": str(n), "ctxHex": ctx.hex(), "value": str(v),
                      "blinding": str(gamma), "expected": own if got is None else got})
    return cases


# =============================================================================================
# Header, provenance and the document
# =============================================================================================

def generator_names():
    return ["G_%d" % i for i in range(64)] + ["H_%d" % i for i in range(64)] + ["U"]


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# (path, revision).  The revision is pinned here, not read from the documents. It names the
# revision whose octets are hashed, so it is updated whenever a spec revision lands, even a
# metadata-only one (the registry's r9 admission changed no rule this script implements).
SPECS = [
    ("docs/specs/bulletproof-range-bls12-381-g1-v1.md", "r2"),
    ("docs/specs/pedersen-bls12-381-g1-v1.md", "r2"),
    ("docs/specs/commitment-profiles-v1.md", "r9"),
]
_DATE_LINE = re.compile(r"^\*\*Date:\*\*(.*)$", re.M)
_DATE_REV = re.compile(r"(\d{4}-\d{2}-\d{2})\s+\((r\d+)\)")


def spec_entry(repo_root, rel, revision):
    path = os.path.join(repo_root, rel)
    if not os.path.isfile(path):
        raise SystemExit("specification not found: %s (use --repo-root)" % path)
    with open(path, "rb") as fh:
        raw = fh.read()
    m = _DATE_LINE.search(raw.decode("utf-8"))
    require(m is not None, "no **Date:** line in " + rel)
    pairs = _DATE_REV.findall(m.group(1))
    dates = [d for d, r in pairs if r == revision]
    if not dates:
        sys.stderr.write("warning: %s has no date for %s; using the last date on its Date line\n"
                         % (rel, revision))
        require(pairs, "no dated revision in " + rel)
        dates = [pairs[-1][0]]
    return {"path": rel, "revision": revision, "date": dates[-1],
            "sha256": hashlib.sha256(raw).hexdigest()}


def python_version():
    return "%s %s" % (platform.python_implementation(), platform.python_version())


def build_doc(repo_root, strict=True):
    """Returns (JSON text, doc dict, negative intents)."""
    gens = bp.generators()
    positive, raw = build_positives(strict)
    if strict:
        require(TRACE_ID in raw and "n32-vmid-url" in raw and "n64-vmax-hello" in raw,
                "negative base cases missing")
    negative, intents = build_negatives(raw, strict) if TRACE_ID in raw else ([], {})
    prover_negative = build_prover_negatives(strict)
    doc = {
        "schema": SCHEMA,
        "protocolId": PROTOCOL_ID,
        "profileId": PROFILE_ID,
        "generatorSetId": GENSET_ID,
        "generatorDigestHex": gens.digest.hex(),
        "generators": [{"name": nm, "compressedHex": e.hex()}
                       for nm, e in zip(generator_names(), gens.encodings)],
        "spec": [spec_entry(repo_root, rel, rev) for rel, rev in SPECS],
        "generator": {"script": SCRIPT_REL, "scriptSha256": sha256_file(os.path.abspath(__file__)),
                      "python": python_version()},
        "positive": positive,
        "negative": negative,
        "proverNegative": prover_negative,
    }
    text = json.dumps(doc, indent=2, ensure_ascii=True) + "\n"
    return text, doc, intents


# =============================================================================================
# Pins and re-verification (--self-test)
# =============================================================================================

def pin_checks():
    problems = []

    def chk(cond, msg):
        if not cond:
            problems.append("pin: " + msg)
    gens = bp.generators()
    chk(gens.digest.hex() == PIN_D_GENS_HEX, "D_gens differs from Appendix A")
    chk(hashlib.sha256(b"".join(gens.encodings)).hexdigest() == PIN_D_GENS_HEX,
        "SHA-256 of the 129 encodings differs from Appendix A")
    chk(len(gens.encodings) == 129 and gens.encodings[0].hex() == PIN_G0_HEX, "G_0 encoding")
    with open(os.path.join(HERE, GENERATORS_FILE), encoding="ascii") as fh:
        gf = json.load(fh)
    chk([g["name"] for g in gf["generators"]] == generator_names(), "generators-v1.json names")
    chk([g["compressedHex"] for g in gf["generators"]] == [e.hex() for e in gens.encodings],
        "generators-v1.json encodings")
    chk(gf["D_gens"] == PIN_D_GENS_HEX, "generators-v1.json D_gens")
    g, h = bases()
    chk(C.compress(g).hex() == PIN_G_HEX and C.compress(h).hex() == PIN_H_HEX, "profile G, H")
    chk(own_tag(16, CTX_HELLO).decode() == PIN_EXAMPLE_TAG, "own tag vs the §5.1 example")
    chk(bp.session_tag(16, CTX_HELLO).decode() == PIN_EXAMPLE_TAG, "reference tag vs the §5.1 example")
    chk(len(own_instance(16, IDENT)) == 244, "instance length 244")
    for n in BITS:
        chk(bp.proof_length(n) == PROOF_LEN[n] and layout(n)[-1][2] + 32 == PROOF_LEN[n],
            "proof length at n = %d" % n)
    chk(point_form(ORDER3) == "nonsubgroup" and C.strict_decode(ORDER3)[0] != "ok"
        and C.on_curve_e((0, 2)) and C.scalar_mul(3, (0, 2)) is None, "(0, 2) has order 3")
    chk(point_form(IDENT) == "identity", "identity encoding")
    for name, enc in malformed_forms().items():
        chk(point_form(enc) == "malformed", "malformed form " + name)
    chk(point_form(other_nonsubgroup()) == "nonsubgroup"
        and C.scalar_mul(3, decode_any(other_nonsubgroup())) is not None, "other non-subgroup point")
    # the trace case against the reference's externally confirmed pin
    proof, tr = ref_prove(12345, TRACE_BLINDING, 16, CTX_HELLO, TRACE_SEED)
    chk(proof.hex() == bp.PIN_TRACE["proofHex"] and tr["sessionId"].hex() == bp.PIN_TRACE["sessionIdHex"]
        and tr["commitment"].hex() == bp.PIN_TRACE["commitmentHex"], "trace case vs PIN_TRACE")
    sid, ch = own_challenges(16, CTX_HELLO, tr["commitment"], proof)
    pc = bp.PIN_TRACE["challenges"]
    chk(sid.hex() == bp.PIN_TRACE["sessionIdHex"] and str(ch["y"]) == pc["y"] and str(ch["z"]) == pc["z"]
        and str(ch["x"]) == pc["x"] and str(ch["xu"]) == pc["xu"]
        and [str(c) for c in ch["xj"]] == pc["xj"], "own transcript vs PIN_TRACE")
    chk(own_instance(16, tr["commitment"]).hex() == bp.PIN_TRACE["instanceHex"], "own instance vs PIN_TRACE")
    return problems


def decode_any(b):
    """Decode a compressed finite curve point WITHOUT the subgroup check (pin checks only)."""
    x = os2ip(bytes([b[0] & 0x1F]) + b[1:])
    rhs = (x ** 3 + 4) % P_381
    y = C.sqrt(rhs)
    if (y > (P_381 - 1) // 2) != bool(b[0] & 0x20):
        y = (-y) % P_381
    return (x, y)


_DEC_RE = re.compile(r"^-?(0|[1-9][0-9]*)$")
_HEX_RE = re.compile(r"^([0-9a-f]{2})*$")


def format_problems(obj, where="$"):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += format_problems(v, "%s.%s" % (where, k))
            if k.endswith("Hex") and isinstance(v, str) and not _HEX_RE.match(v):
                out.append("%s.%s is not lowercase even-length hex" % (where, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += format_problems(v, "%s[%d]" % (where, i))
    elif not isinstance(obj, str):
        out.append("%s is a JSON %s, not a string" % (where, type(obj).__name__))
    return out


def _int(s):
    if not isinstance(s, str) or not _DEC_RE.match(s):
        raise PinError("not a canonical decimal string: %r" % (s,))
    return int(s)


def _hex(s):
    if not isinstance(s, str) or not _HEX_RE.match(s):
        raise PinError("not lowercase hex: %r" % (s,)[:80])
    return bytes.fromhex(s)


POS_KEYS = ["id", "bits", "ctxHex", "value", "blinding", "commitmentHex", "nonceSeedHex",
            "sessionIdHex", "challenges", "proofHex"]
NEG_KEYS = ["id", "bits", "ctxHex", "commitmentHex", "proofHex", "expected", "layer"]
PNEG_KEYS = ["id", "bits", "ctxHex", "value", "blinding", "expected"]
TOP_KEYS = ["schema", "protocolId", "profileId", "generatorSetId", "generatorDigestHex", "generators",
            "spec", "generator", "positive", "negative", "proverNegative"]

_REVERIFY_MEMO = {}


def _memo_case(section, case, fn):
    key = (section, json.dumps(case, sort_keys=True))
    if key not in _REVERIFY_MEMO:
        try:
            _REVERIFY_MEMO[key] = fn()
        except Exception as e:  # noqa: BLE001 -- an unexpected exception is a reported problem
            _REVERIFY_MEMO[key] = ["exception %s: %s" % (type(e).__name__, e)]
    return _REVERIFY_MEMO[key]


def reverify_positive(c):
    p = []
    if list(c) != POS_KEYS:
        return ["keys %s" % list(c)]
    n = _int(c["bits"])
    ctx, vb, proof, seed = _hex(c["ctxHex"]), _hex(c["commitmentHex"]), _hex(c["proofHex"]), _hex(c["nonceSeedHex"])
    v, gamma = _int(c["value"]), _int(c["blinding"])
    if n not in BITS or not 1 <= len(ctx) <= MAX_CTX:
        return ["configuration outside the protocol"]
    if not (0 <= v < (1 << n) and 0 <= gamma < Q):
        return ["value or blinding outside its range"]
    if len(seed) != 32 or len(proof) != PROOF_LEN[n]:
        p.append("seed or proof length")
    if v == 0 and gamma == 0:
        p.append("identity commitment")
    if own_commit(v, gamma) != vb:
        p.append("commitmentHex != [v]G + [gamma]H (affine)")
    ch = c["challenges"]
    if not isinstance(ch, dict) or list(ch) != ["y", "z", "x", "xu", "xj"]:
        return p + ["challenge keys"]
    try:
        rproof, tr = ref_prove(v, gamma, n, ctx, seed)
    except (bp.BulletproofError, bp.TestNonceProverFailure) as e:
        return p + ["reference prover refused: %s" % e]
    if rproof != proof:
        p.append("reference test-nonce prover does not reproduce proofHex")
    if tr["commitment"] != vb:
        p.append("reference commitment differs")
    if tr["sessionId"].hex() != c["sessionIdHex"]:
        p.append("reference sessionId differs")
    rc = tr["challenges"]
    want = {"y": str(rc["y"]), "z": str(rc["z"]), "x": str(rc["x"]), "xu": str(rc["xu"]),
            "xj": [str(rc["x_%d" % j]) for j in range(1, LOG2[n] + 1)]}
    if want != ch:
        p.append("reference challenges differ from the record")
    sid, own = own_challenges(n, ctx, vb, proof)
    own_s = {"y": str(own["y"]), "z": str(own["z"]), "x": str(own["x"]), "xu": str(own["xu"]),
             "xj": [str(x) for x in own["xj"]]}
    if sid.hex() != c["sessionIdHex"] or own_s != ch:
        p.append("own transcript does not reproduce sessionIdHex/challenges from the proof")
    if any(x == 0 for x in [own["y"], own["z"], own["x"], own["xu"]] + own["xj"]):
        p.append("zero challenge")
    if ref_classify(vb, proof, n, ctx) != ("true", "accept"):
        return p + ["reference verifier rejects"]
    if not own_check1(n, ctx, vb, proof):
        p.append("own affine check 1 fails")
    if not ref_recursive(vb, proof, n, ctx):
        p.append("recursive IPA verifier rejects")
    return p


def structural_defects(n, ctx, vb, proof):
    """The defects actually present, by the §8.1 steps, computed from the octets."""
    found = []
    cfg_bad = n not in BITS or not 1 <= len(ctx) <= MAX_CTX
    if cfg_bad:
        found.append(("config",))
    vf = v_form(vb)
    if vf:
        found.append(("V", vf))
    if cfg_bad:
        return found
    if len(proof) != PROOF_LEN[n]:
        found.append(("length",))
        return found
    for name, kind, off, size in layout(n):
        f = point_form(proof[off:off + size]) if kind == "point" else scalar_form(proof[off:off + size])
        if f:
            found.append(("field", name, f))
    if len(found) > 0:
        return found
    _, ch = own_challenges(n, ctx, vb, proof)
    if any(x == 0 for x in [ch["y"], ch["z"], ch["x"], ch["xu"]] + ch["xj"]):
        found.append(("challenge",))
        return found
    if not own_check1(n, ctx, vb, proof):
        found.append(("check1",))
    if not ref_recursive(vb, proof, n, ctx):
        found.append(("check2",))
    return found


def reverify_negative(c, intent, positives_raw):
    p = []
    if list(c) != NEG_KEYS:
        return ["keys %s" % list(c)]
    if intent is None:
        return ["no intent for this id"]
    n = _int(c["bits"])
    ctx, vb, proof = _hex(c["ctxHex"]), _hex(c["commitmentHex"]), _hex(c["proofHex"])
    if c["expected"] not in NEG_EXPECTED or c["layer"] not in NEG_LAYERS:
        p.append("expected/layer outside the §11 sets")
    found = structural_defects(n, ctx, vb, proof)
    declared = intent["defects"]
    if sorted(found) != sorted(declared):
        p.append("defects present %s, declared %s" % (sorted(found), sorted(declared)))
    if not found:
        p.append("no defect: the case would verify")
    intended = first_outcome(n, declared) if declared else None
    if intended and (c["expected"], c["layer"]) != intended:
        p.append("record says %s/%s, first declared defect gives %s" % (c["expected"], c["layer"], intended))
    got = ref_classify(vb, proof, n, ctx)
    if got != (c["expected"], c["layer"]):
        p.append("reference verifier gives %s, record says %s/%s" % (got, c["expected"], c["layer"]))
    # semantic tags, checked against the base positive case
    base = positives_raw.get(intent["base"]) if intent["base"] else None
    for tag in intent["tags"]:
        if tag.startswith("scalar-tamper:"):
            name = tag.split(":", 1)[1]
            if base is None or base[0] != n:
                p.append("tag %s: base missing or another width" % tag)
                continue
            bproof = base[3]
            want = tweak_scalar_plain(bproof, n, name, 1)
            if proof != want:
                p.append("tag %s: proof is not the base proof with %s + 1" % (tag, name))
        elif tag == "same-proof-other-ctx":
            if base is None or proof != base[3] or vb != base[2] or ctx == base[1]:
                p.append("tag %s not satisfied" % tag)
        elif tag == "same-proof-other-V":
            if base is None or proof != base[3] or vb == base[2] or ctx != base[1]:
                p.append("tag %s not satisfied" % tag)
        elif tag == "v-plus-order3":
            sub = C.point_add(decode_any(vb), (0, (-2) % P_381))
            if sub is None or not C.in_subgroup(sub) or C.compress(sub) == vb:
                p.append("tag %s: V - (0, 2) is not a subgroup point" % tag)
        elif tag == "forced-out-of-range":
            if len(proof) != PROOF_LEN.get(n, -1) or vb != own_commit(1 << n, blinding_of_base()):
                p.append("tag %s: V is not a commitment to 2^n" % tag)
    return p


def blinding_of_base():
    return TRACE_BLINDING


def tweak_scalar_plain(proof, n, name, delta):
    """tweak_scalar without the generation mutations (for the self-test)."""
    _, kind, off, size = field(n, name)
    s = os2ip(proof[off:off + size])
    return proof[:off] + scalar_bytes((s + delta) % Q) + proof[off + size:]


def reverify_prover_negative(c):
    if list(c) != PNEG_KEYS:
        return ["keys %s" % list(c)]
    p = []
    n, v, gamma, ctx = _int(c["bits"]), _int(c["value"]), _int(c["blinding"]), _hex(c["ctxHex"])
    if c["expected"] not in PROVER_EXPECTED:
        p.append("expected outside the prover classes")
    saved = set(MUT)
    MUT.clear()
    try:
        own = own_prover_refusal(v, gamma, n, ctx)
    finally:
        MUT.update(saved)
    if own != c["expected"]:
        p.append("own §7.1 order gives %s" % own)
    got = ref_prover_refusal(v, gamma, n, ctx)
    if got != c["expected"]:
        p.append("reference prover gives %s" % got)
    canonical = 0 <= v < Q and 0 <= gamma < Q
    config_ok = n in BITS and 1 <= len(ctx) <= MAX_CTX
    if c["expected"] == NCS and not config_ok:
        p.append("Java-binding constraint: a non-canonical case must have a valid configuration")
    if c["expected"] == INV and not canonical:
        p.append("Java-binding constraint: a configuration case must have a canonical opening")
    return p


def coverage_problems(doc, intents):
    p = []
    pos = doc["positive"]
    if len(pos) < 12:
        p.append("fewer than 12 positive cases")
    seeds = [c.get("nonceSeedHex") for c in pos]
    if len(set(seeds)) != len(seeds):
        p.append("a nonce seed is reused across positive cases (spec §7.5)")
    ids = [c.get("id") for c in pos + doc["negative"] + doc["proverNegative"]]
    if len(set(ids)) != len(ids):
        p.append("duplicate case ids")
    try:
        for n in BITS:
            at = [c for c in pos if c["bits"] == str(n)]
            vals = {_int(c["value"]) for c in at}
            if not {0, 1, (1 << n) - 1} <= vals or not vals - {0, 1, (1 << n) - 1}:
                p.append("n = %d: values 0, 1, 2^n - 1 and a mid value not all present" % n)
            ctxs = [_hex(c["ctxHex"]) for c in at]
            if not (any(len(x) == 1 for x in ctxs) and CTX_HELLO in ctxs and len(ctxs) > 0
                    and any(x.startswith(b"https://") for x in ctxs) and any(len(x) == 1024 for x in ctxs)):
                p.append("n = %d: contexts of 1 octet, hello, a URL and 1,024 octets not all present" % n)
        for c in pos:
            if c["value"] == "0" and c["blinding"] == "0":
                p.append("value 0 with blinding 0")
        if not any(c["id"] == TRACE_ID and c["proofHex"] == bp.PIN_TRACE["proofHex"] for c in pos):
            p.append("the externally confirmed trace case is missing")
    except (PinError, KeyError) as e:
        p.append("positive coverage: %s" % e)
    # negatives: by declared and verified defects, and by bytes
    neg = doc["negative"]
    have = set()
    for c in neg:
        it = intents.get(c["id"])
        if it is None:
            continue
        try:
            n, ctx, vb, proof = _int(c["bits"]), _hex(c["ctxHex"]), _hex(c["commitmentHex"]), _hex(c["proofHex"])
        except PinError:
            continue
        ds = it["defects"]
        if ds == [("config",)]:
            if n in (8, 24, 128):
                have.add("config-bits-%d" % n)
            if len(ctx) == 0:
                have.add("config-ctx-empty")
            if len(ctx) == 1025:
                have.add("config-ctx-1025")
        if ds == [("length",)] and n in PROOF_LEN:
            if len(proof) == PROOF_LEN[n] - 1:
                have.add("length-short")
            if len(proof) == PROOF_LEN[n] + 1:
                have.add("length-long")
            if len(proof) in PROOF_LEN.values() and len(proof) != PROOF_LEN[n]:
                have.add("length-other-width")
        if len(ds) == 1 and ds[0][0] == "V":
            have.add("statement-" + ds[0][1])
            if "v-plus-order3" in it["tags"]:
                have.add("statement-commitment-plus-order3")
        fields = [d for d in ds if d[0] == "field"]
        if len(ds) == 1 and fields and n in LOG2:
            name, form = fields[0][1], fields[0][2]
            k = LOG2[n]
            if name == "A":
                have.add("point-A-" + form)
            if name.startswith("L_") and 1 < int(name[2:]) < k:
                have.add("point-Lmid-" + form)
            if name == "R_%d" % k:
                have.add("point-Rlast-" + form)
            if form == "noncanonical":
                val = os2ip(get_field(proof, n, name))
                if val == Q:
                    have.add("scalar-%s-q" % name)
                if val == 2 ** 256 - 1:
                    have.add("scalar-%s-max" % name)
        if len(fields) >= 2:
            have.add("order-two-fields")
        if fields and any(d[0] == "V" and d[1] != "identity" for d in ds):
            have.add("order-bad-V-and-bad-field")
        if fields and ("V", "identity") in ds:
            have.add("order-identity-V-and-bad-field")
        if ("check1",) in ds and ("check2",) in ds:
            have.add("check-both")
        for tag in it["tags"]:
            if tag.startswith("scalar-tamper:") and ds == [("check2",)]:
                have.add("check2-scalar-tamper")
            if tag.startswith("scalar-tamper:") and ("check1",) in ds:
                have.add("check1-scalar-tamper")
            if tag == "same-proof-other-ctx" and ("check1",) in ds:
                have.add("check1-wrong-ctx")
            if tag == "same-proof-other-V" and ("check1",) in ds:
                have.add("check1-other-commitment")
            if tag == "forced-out-of-range" and ds == [("check1",)]:
                have.add("check1-forced-out-of-range")
    required = {"config-bits-8", "config-bits-24", "config-bits-128", "config-ctx-empty",
                "config-ctx-1025", "length-short", "length-long", "length-other-width",
                "statement-malformed", "statement-nonsubgroup", "statement-identity",
                "statement-commitment-plus-order3", "order-two-fields", "order-bad-V-and-bad-field",
                "order-identity-V-and-bad-field", "check-both", "check1-scalar-tamper",
                "check2-scalar-tamper", "check1-wrong-ctx", "check1-other-commitment",
                "check1-forced-out-of-range"}
    for where in ("A", "Lmid", "Rlast"):
        for form in ("identity", "malformed", "nonsubgroup"):
            required.add("point-%s-%s" % (where, form))
    for name in ("t_hat", "tau_x", "mu", "a", "b"):
        required |= {"scalar-%s-q" % name, "scalar-%s-max" % name}
    for r in sorted(required - have):
        p.append("missing required negative coverage: " + r)
    # prover negatives
    pn = doc["proverNegative"]
    pc = set()
    for c in pn:
        try:
            n, v, gamma = _int(c["bits"]), _int(c["value"]), _int(c["blinding"])
            ctx = _hex(c["ctxHex"])
        except (PinError, KeyError):
            continue
        e = c.get("expected")
        if e == INV and n not in BITS:
            pc.add("bits")
        if e == INV and len(ctx) == 0:
            pc.add("ctx-empty")
        if e == INV and len(ctx) == 1025:
            pc.add("ctx-1025")
        if e == NCS and v == Q:
            pc.add("value-q")
        if e == NCS and gamma == Q:
            pc.add("blinding-q")
        if e == OOR and n in BITS and v == 1 << n:
            pc.add("range-2pow%d" % n)
        if e == OOR and v == Q - 1:
            pc.add("range-q-minus-1")
        if e == IST and v == 0 and gamma == 0:
            pc.add("statement-zero")
    for r in sorted({"bits", "ctx-empty", "ctx-1025", "value-q", "blinding-q", "range-2pow16",
                     "range-2pow32", "range-2pow64", "range-q-minus-1", "statement-zero"} - pc):
        p.append("missing required prover-negative coverage: " + r)
    return p


def reverify_doc(doc, intents, repo_root):
    """All problems found in a parsed document (empty list = accepted)."""
    p = []
    if not isinstance(doc, dict) or list(doc) != TOP_KEYS:
        return ["top-level keys %s" % (list(doc) if isinstance(doc, dict) else type(doc))]
    p += format_problems(doc)
    if (doc["schema"], doc["protocolId"], doc["profileId"], doc["generatorSetId"]) != \
            (SCHEMA, PROTOCOL_ID, PROFILE_ID, GENSET_ID):
        p.append("header identifiers")
    if doc["generatorDigestHex"] != PIN_D_GENS_HEX:
        p.append("generatorDigestHex != Appendix A D_gens")
    gl = doc["generators"]
    gens = bp.generators()
    if [g.get("name") for g in gl] != generator_names():
        p.append("generator names or count")
    elif [g.get("compressedHex") for g in gl] != [e.hex() for e in gens.encodings]:
        p.append("generator encodings differ from the reference derivation")
    else:
        enc = b"".join(bytes.fromhex(g["compressedHex"]) for g in gl)
        if hashlib.sha256(enc).hexdigest() != doc["generatorDigestHex"]:
            p.append("SHA-256 of the listed encodings != generatorDigestHex")
        if any(point_form(bytes.fromhex(g["compressedHex"])) for g in gl):
            p.append("a listed generator does not decode to a subgroup point")
    want_spec = [spec_entry(repo_root, rel, rev) for rel, rev in SPECS]
    if doc["spec"] != want_spec:
        p.append("spec provenance differs from the files under the repository root")
    gen = doc["generator"]
    if gen != {"script": SCRIPT_REL, "scriptSha256": sha256_file(os.path.abspath(__file__)),
               "python": gen.get("python")} or not str(gen.get("python", "")).startswith("CPython 3."):
        p.append("generator provenance")
    positives_raw = {}
    for c in doc["positive"]:
        for x in _memo_case("positive", c, lambda c=c: reverify_positive(c)):
            p.append("positive %s: %s" % (c.get("id"), x))
        try:
            positives_raw[c["id"]] = (_int(c["bits"]), _hex(c["ctxHex"]), _hex(c["commitmentHex"]),
                                      _hex(c["proofHex"]))
        except (PinError, KeyError):
            pass
    for c in doc["negative"]:
        it = intents.get(c.get("id"))
        base = positives_raw.get(it["base"]) if it and it["base"] else None
        key = dict(c, _base=repr(base))
        for x in _memo_case("negative", key,
                            lambda c=c, it=it: reverify_negative(c, it, positives_raw)):
            p.append("negative %s: %s" % (c.get("id"), x))
    for c in doc["proverNegative"]:
        for x in _memo_case("prover", c, lambda c=c: reverify_prover_negative(c)):
            p.append("proverNegative %s: %s" % (c.get("id"), x))
    p += coverage_problems(doc, intents)
    return p


# ---- document mutations: each must be detected by reverify_doc ---------------------------------

def _first(cases, pred):
    for c in cases:
        if pred(c):
            return c
    raise PinError("mutation target not found")


def _flip_hex(h, idx):
    b = bytearray(bytes.fromhex(h))
    b[idx] ^= 0x01
    return b.hex()


def doc_mutations():
    def m_class(d):
        _first(d["negative"], lambda c: c["expected"] == MAL and c["layer"] == "point")["expected"] = NIS

    def m_layer(d):
        _first(d["negative"], lambda c: c["layer"] == "point")["layer"] = "scalar"

    def m_check_layer(d):
        _first(d["negative"], lambda c: c["layer"] == "check1")["layer"] = "check2"

    def m_both_layer(d):
        _first(d["negative"], lambda c: c["id"] == "chk-t_hat-plus-1")["layer"] = "check2"

    def m_false(d):
        _first(d["negative"], lambda c: c["expected"] == FALSE and c["layer"] == "statement")["expected"] = MAL

    def m_neg_valid(d):
        tr = _first(d["positive"], lambda c: c["id"] == TRACE_ID)
        _first(d["negative"], lambda c: c["id"] == "chk-a-plus-1")["proofHex"] = tr["proofHex"]

    def m_neg_bits(d):
        _first(d["negative"], lambda c: c["id"] == "scalar-a-q")["bits"] = "32"

    def m_neg_defect_moved(d):
        c = _first(d["negative"], lambda c: c["id"] == "point-L_2-identity")
        tr = _first(d["positive"], lambda c: c["id"] == TRACE_ID)
        pr = bytes.fromhex(tr["proofHex"])
        _, _, off, _ = field(16, "R_2")
        c["proofHex"] = (pr[:off] + IDENT + pr[off + 48:]).hex()

    def m_pos_flip_A(d):
        c = d["positive"][0]
        c["proofHex"] = _flip_hex(c["proofHex"], 5)

    def m_pos_alter_a(d):
        c = d["positive"][1]
        n = int(c["bits"])
        c["proofHex"] = tweak_scalar_plain(bytes.fromhex(c["proofHex"]), n, "a", 1).hex()

    def m_pos_drop_xj(d):
        d["positive"][2]["challenges"]["xj"].pop()

    def m_pos_y(d):
        ch = d["positive"][3]["challenges"]
        ch["y"] = str((int(ch["y"]) + 1) % Q)

    def m_pos_sid(d):
        c = d["positive"][4]
        c["sessionIdHex"] = _flip_hex(c["sessionIdHex"], 0)

    def m_pos_commit(d):
        d["positive"][5]["commitmentHex"] = d["positive"][6]["commitmentHex"]

    def m_pos_seed(d):
        d["positive"][7]["nonceSeedHex"] = d["positive"][6]["nonceSeedHex"]

    def m_pos_value(d):
        c = d["positive"][1]
        c["value"] = str(int(c["value"]) + 1)

    def m_gens_swap(d):
        g = d["generators"]
        g[0]["compressedHex"], g[1]["compressedHex"] = g[1]["compressedHex"], g[0]["compressedHex"]

    def m_gens_digest(d):
        d["generatorDigestHex"] = _flip_hex(d["generatorDigestHex"], 31)

    def m_gens_drop_u(d):
        d["generators"].pop()

    def m_pneg_class(d):
        _first(d["proverNegative"], lambda c: c["expected"] == OOR)["expected"] = NCS

    def m_pneg_constraint(d):
        _first(d["proverNegative"], lambda c: c["id"] == "prove-ncs-value-q")["bits"] = "8"

    def m_drop_n64(d):
        d["positive"] = [c for c in d["positive"] if c["bits"] != "64"]

    def m_drop_rlast(d):
        d["negative"] = [c for c in d["negative"] if "-R_4-" not in c["id"] and "-R_5-" not in c["id"]
                         and "-R_6-" not in c["id"]]

    def m_number(d):
        d["positive"][0]["bits"] = 16

    def m_upper(d):
        c = d["negative"][0]
        c["proofHex"] = c["proofHex"].upper()

    def m_spec(d):
        d["spec"][0]["sha256"] = _flip_hex(d["spec"][0]["sha256"], 0)

    def m_unknown_id(d):
        d["negative"][0]["id"] += "-x"

    return [
        ("negative: wrong expected class", m_class),
        ("negative: wrong layer (point -> scalar)", m_layer),
        ("negative: check1 recorded as check2", m_check_layer),
        ("negative: both checks fail, layer check2", m_both_layer),
        ("negative: identity-V 'false' recorded as MALFORMED_ENCODING", m_false),
        ("negative: proof replaced by a valid proof", m_neg_valid),
        ("negative: bits changed 16 -> 32", m_neg_bits),
        ("negative: point defect moved from L_2 to R_2", m_neg_defect_moved),
        ("positive: one bit of A flipped", m_pos_flip_A),
        ("positive: a re-encoded as a + 1 (not absorbed)", m_pos_alter_a),
        ("positive: last x_j dropped", m_pos_drop_xj),
        ("positive: y off by one", m_pos_y),
        ("positive: sessionIdHex altered", m_pos_sid),
        ("positive: commitment of another case", m_pos_commit),
        ("positive: nonce seed of another case", m_pos_seed),
        ("positive: value changed", m_pos_value),
        ("generators: G_0 and G_1 swapped", m_gens_swap),
        ("generators: digest altered", m_gens_digest),
        ("generators: U dropped", m_gens_drop_u),
        ("proverNegative: wrong class", m_pneg_class),
        ("proverNegative: non-canonical case with bad bits", m_pneg_constraint),
        ("coverage: n = 64 positives removed", m_drop_n64),
        ("coverage: last R_k point cases removed", m_drop_rlast),
        ("format: a JSON number", m_number),
        ("format: uppercase hex", m_upper),
        ("provenance: spec SHA-256 altered", m_spec),
        ("negative: id without an intent", m_unknown_id),
    ]


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


PROVENANCE_PATH = re.compile(r"^\$\.(generator\.(python|scriptSha256)|spec\[\d+\]\.(sha256|date))(:| )")


def compare_texts(disk_text, text):
    """Byte-for-byte comparison; returns the differences (empty iff identical)."""
    if disk_text == text:
        return []
    try:
        disk = json.loads(disk_text)
    except ValueError as exc:
        return ["not identical; cannot parse the file on disk (%s)" % exc]
    details = []
    _diff(disk, json.loads(text), "$", details)
    out = [d + (" [provenance field]" if PROVENANCE_PATH.match(d) else "") for d in details]
    return out or ["not byte-identical (formatting or key order only)"]


def summarize(doc):
    lines = ["%s: %d positive, %d negative, %d proverNegative, %d generators"
             % (doc["protocolId"], len(doc["positive"]), len(doc["negative"]),
                len(doc["proverNegative"]), len(doc["generators"]))]
    widths = {}
    for c in doc["positive"]:
        widths[c["bits"]] = widths.get(c["bits"], 0) + 1
    lines.append("    positive by bits: " + ", ".join("n=%s: %d" % kv for kv in sorted(widths.items(), key=lambda kv: int(kv[0]))))
    layers = {}
    for c in doc["negative"]:
        key = "%s/%s" % (c["layer"], c["expected"])
        layers[key] = layers.get(key, 0) + 1
    by_layer = {}
    for c in doc["negative"]:
        by_layer[c["layer"]] = by_layer.get(c["layer"], 0) + 1
    lines.append("    negative by layer: " + ", ".join("%s=%d" % kv for kv in sorted(by_layer.items())))
    lines.append("    negative by layer/expected: " + ", ".join("%s=%d" % kv for kv in sorted(layers.items())))
    pe = {}
    for c in doc["proverNegative"]:
        pe[c["expected"]] = pe.get(c["expected"], 0) + 1
    lines.append("    proverNegative by expected: " + ", ".join("%s=%d" % kv for kv in sorted(pe.items())))
    return "\n".join(lines)


# =============================================================================================
# Main
# =============================================================================================

def self_test(repo_root, out_path):
    failures = []

    def log(msg):
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()

    pins = pin_checks()
    failures += pins
    log("pin checks: %d problems" % len(pins))

    text, doc, intents = build_doc(repo_root, strict=True)
    log(summarize(doc))
    log("output SHA-256: " + hashlib.sha256(text.encode("ascii")).hexdigest())

    # determinism: a second build with every memoised reference result discarded
    MEMO.store.clear()
    text2, _, _ = build_doc(repo_root, strict=True)
    if text2 != text:
        failures.append("generation is not deterministic within one process")
    log("determinism (second build, memo cleared): %s" % ("identical" if text2 == text else "DIFFERS"))

    probs = reverify_doc(json.loads(text), intents, repo_root)
    failures += ["generated: " + x for x in probs]
    log("re-verify generated: %d positive, %d negative, %d proverNegative cases; %d problems"
        % (len(doc["positive"]), len(doc["negative"]), len(doc["proverNegative"]), len(probs)))
    for x in probs[:40]:
        log("    " + x)

    if os.path.isfile(out_path):
        with open(out_path, encoding="ascii") as fh:
            disk_text = fh.read()
        try:
            disk_doc = json.loads(disk_text)
            dprobs = reverify_doc(disk_doc, intents, repo_root)
        except ValueError as e:
            dprobs = ["cannot parse: %s" % e]
        failures += ["on-disk: " + x for x in dprobs]
        same = disk_text == text
        log("re-verify on-disk %s: %d problems; byte-identical to regenerated: %s"
            % (out_path, len(dprobs), same))
        for x in dprobs[:40]:
            log("    " + x)
    else:
        log("no file on disk at %s (on-disk re-verification skipped)" % out_path)

    # document mutations
    undetected = 0
    for label, fn in doc_mutations():
        d = copy.deepcopy(json.loads(text))
        fn(d)
        found = reverify_doc(d, intents, repo_root)
        ok = bool(found)
        undetected += 0 if ok else 1
        log("doc mutation %-60s %s" % (label, ("detected (%d)" % len(found)) if ok else "NOT DETECTED"))
        if not ok:
            failures.append("document mutation not detected: " + label)

    # generation mutations: strict generation must refuse, or the output must fail re-verification
    for name, desc in GEN_MUTATIONS:
        MUT.clear()
        MUT.add(name)
        seam = name.startswith("reference_")
        saved_store = MEMO.store
        if seam:
            MEMO.store = {}   # results under a seam are kept apart and discarded afterwards
            if name == "reference_transcript_drop_V":
                bp._TRANSCRIPT_MUTATION = "drop_V"
            else:
                bp._S_BIT_ORDER = "lsb"
        verdict = None
        try:
            try:
                build_doc(repo_root, strict=True)
                strict_refused = False
            except Exception as e:  # noqa: BLE001 -- any refusal of the strict build counts
                strict_refused = True
                verdict = "strict generation refuses (%s: %s)" % (type(e).__name__, str(e)[:70])
            if not strict_refused:
                try:
                    mtext, mdoc, _ = build_doc(repo_root, strict=False)
                except Exception as e:  # noqa: BLE001 -- reported, never counted as detection
                    mtext = text
                    log("gen mutation %s: non-strict build raised %s: %s" % (name, type(e).__name__, e))
        finally:
            MUT.clear()
            bp._TRANSCRIPT_MUTATION = None
            bp._S_BIT_ORDER = "msb"
            MEMO.store = saved_store
        if verdict is None:
            if mtext == text:
                verdict = None
            else:
                found = reverify_doc(json.loads(mtext), intents, repo_root)
                verdict = ("output rejected by re-verification (%d problems)" % len(found)) if found else None
        log("gen mutation %-28s %s" % (name, verdict or "NOT DETECTED"))
        if verdict is None:
            failures.append("generation mutation not detected: " + name)

    # the comparator itself
    tampered = [("one hex digit changed", text.replace('"proofHex": "', '"proofHex": "0', 1)),
                ("trailing newline removed", text[:-1]),
                ("a case removed", json.dumps(dict(doc, negative=doc["negative"][:-1]), indent=2,
                                              ensure_ascii=True) + "\n")]
    cmp_bad = [lbl for lbl, t in tampered if not compare_texts(t, text)] + \
        (["unchanged text flagged"] if compare_texts(text, text) else [])
    failures += ["comparator: " + x for x in cmp_bad]
    log("comparator regression: %d tampered copies, %d misjudged" % (len(tampered), len(cmp_bad)))

    log("")
    if failures:
        log("SELF-TEST FAILED: %d problems" % len(failures))
        for f in failures[:60]:
            log("  " + f)
        return 1
    log("SELF-TEST PASSED")
    return 0


def main(argv):
    args = list(argv)
    repo_root = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", ".."))
    mode, out = "stdout", None
    while args:
        a = args.pop(0)
        if a == "--repo-root" and args:
            repo_root = os.path.abspath(args.pop(0))
        elif a == "--out" and args:
            mode, out = "out", os.path.abspath(args.pop(0))
        elif a == "--check":
            mode = "check"
        elif a == "--self-test":
            mode = "self-test"
        else:
            sys.stderr.write("usage: emit_bulletproof_vectors_v1.py [--repo-root DIR] "
                             "[--out PATH | --check | --self-test]\n")
            return 2
    committed = os.path.join(repo_root, OUT_REL)

    if mode == "self-test":
        return self_test(repo_root, committed)

    pins = pin_checks()
    if pins:
        for x in pins:
            sys.stderr.write(x + "\n")
        return 1
    text, doc, _ = build_doc(repo_root, strict=True)
    sys.stderr.write(summarize(doc) + "\n")
    sys.stderr.write("output SHA-256: %s\n" % hashlib.sha256(text.encode("ascii")).hexdigest())
    if mode == "stdout":
        sys.stdout.write(text)
        return 0
    if mode == "out":
        with open(out, "w", encoding="ascii", newline="\n") as fh:
            fh.write(text)
        sys.stderr.write("wrote %s\n" % out)
        return 0
    try:
        with open(committed, encoding="ascii") as fh:
            disk_text = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        print("%s: DIFFERS: cannot read (%s)" % (committed, exc))
        return 1
    diffs = compare_texts(disk_text, text)
    for d in diffs:
        print("%s: DIFFERS: %s" % (committed, d))
    if not diffs:
        print("%s: byte-identical" % committed)
    return 1 if diffs else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except PinError as exc:
        sys.stderr.write("FAILED: %s\n" % exc)
        sys.exit(1)
