#!/usr/bin/env python3
"""Stand-alone second implementation of `bulletproof-range-bls12-381-g1-v1` (ZeroJ ADR-0061 M0).

Written only from:
  * the ZeroJ specification `bulletproof-range-bls12-381-g1-v1.md` (draft r1 as revised after M0
    review round 1: tag without ".A64", length-first decoding, fully validated decoded V,
    8-attempt restart bound; see its §14 and README.md for the exact file hash) and the profile it
    consumes, `pedersen-bls12-381-g1-v1.md` (r2: bases G, H and the strict point decoder of §4);
  * Bünz et al., *Bulletproofs*, ePrint 2017/1066 (§3 Protocols 1-2, §4.1-§4.2, §6.2);
  * draft-irtf-cfrg-fiat-shamir-03 (duplex sponge, codecs, session identifiers);
  * draft-irtf-cfrg-sigma-protocols-03 (§2-§5 linear relations, §8.2 BLS12-381 codecs, App. A.3);
  * FIPS 202 (SHAKE128, through CPython's hashlib) and RFC 9380 (through the curve module).
No Java source and no other repository file was read.  Standard library only.

This is ZeroJ's own second implementation, not an official or third-party reference.  It is a
PUBLIC TEST REFERENCE: nothing here is constant-time, and it must never be used with real secrets.

Usage (Python 3.13):
    python3 -I -B bulletproof_range_reference.py --self-test
    python3 -I -B bulletproof_range_reference.py --print-generators
    python3 -I -B bulletproof_range_reference.py --print-trace
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import sys

# ---------------------------------------------------------------------------
# The BLS12-381 G1 curve module (ZeroJ's earlier independent reference, imported by path)
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
_CURVE_PATH = os.path.normpath(
    os.path.join(_HERE, "..", "pedersen-g1-reference", "bls12_381_g1_reference.py"))


def _load_curve_module():
    spec = importlib.util.spec_from_file_location("bls12_381_g1_reference", _CURVE_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load curve module from " + _CURVE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


C = _load_curve_module()

P_381 = C.P_381
Q = C.Q  # order of G1 and of the scalar field; spec §1 `q`
assert Q == 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
G1_GEN = (C.G1_GEN_X, C.G1_GEN_Y)

# ---------------------------------------------------------------------------
# Error classes (spec §9).  Each carries its registry class name.
# ---------------------------------------------------------------------------


class BulletproofError(Exception):
    error_class = "ERROR"

    def __init__(self, detail: str = "", layer: str = ""):
        super().__init__(f"{self.error_class}: {detail}" if detail else self.error_class)
        self.detail = detail
        self.layer = layer


class InvalidConfiguration(BulletproofError):
    error_class = "INVALID_CONFIGURATION"


class MalformedEncoding(BulletproofError):
    error_class = "MALFORMED_ENCODING"


class NotInSubgroup(BulletproofError):
    error_class = "NOT_IN_SUBGROUP"


class NonCanonicalScalar(BulletproofError):
    error_class = "NON_CANONICAL_SCALAR"


class OutOfRange(BulletproofError):
    error_class = "OUT_OF_RANGE"


class InvalidStatement(BulletproofError):
    error_class = "INVALID_STATEMENT"


class TestNonceProverFailure(Exception):
    """§7.5: where §7.3 would restart, a test-nonce prover fails instead."""


class CodecError(Exception):
    """A fiat-shamir-03 codec / deserialization failure ("fail" in the drafts' pseudocode)."""


# ---------------------------------------------------------------------------
# Byte/integer conversions (fiat-shamir-03 §2.1; RFC 8017 for I2OSP/OS2IP)
# ---------------------------------------------------------------------------

def LE(n: int, w: int) -> bytes:
    if n < 0 or n >= 256 ** w:
        raise CodecError("LE: integer out of range")
    return n.to_bytes(w, "little")


def LE2IP(x: bytes) -> int:
    return int.from_bytes(x, "little")


def I2OSP(n: int, w: int) -> bytes:
    if n < 0 or n >= 256 ** w:
        raise CodecError("I2OSP: integer out of range")
    return n.to_bytes(w, "big")


def OS2IP(x: bytes) -> int:
    return int.from_bytes(x, "big")


def ns_of(modulus: int) -> int:
    """Smallest Ns with 256^Ns >= M (fiat-shamir-03 §6.1.3)."""
    ns = 0
    while 256 ** ns < modulus:
        ns += 1
    return ns


# fiat-shamir-03 §6.1.1
def serialize_varlen_string(s: bytes) -> bytes:
    return LE(len(s), 4) + bytes(s)


# fiat-shamir-03 §6.2.1
def deserialize_varlen_string(inp: bytes):
    if len(inp) < 4:
        raise CodecError("DeserializeVarLenString: fewer than 4 bytes")
    n = LE2IP(inp[0:4])
    if len(inp) - 4 < n:
        raise CodecError("DeserializeVarLenString: truncated payload")
    return inp[4:4 + n], inp[4 + n:]


# fiat-shamir-03 §6.1.3
def serialize_uint(x: int, modulus: int) -> bytes:
    if not 0 <= x < modulus:
        raise CodecError("SerializeUint: value not in [0, M)")
    return LE(x, ns_of(modulus))


# fiat-shamir-03 §6.2.3
def deserialize_uint(inp: bytes, modulus: int):
    ns = ns_of(modulus)
    if len(inp) < ns:
        raise CodecError("DeserializeUint: fewer than Ns bytes")
    x = LE2IP(inp[0:ns])
    if x >= modulus:
        raise CodecError("DeserializeUint: non-canonical (x >= M)")
    return x, inp[ns:]


# fiat-shamir-03 §4.2.2
def decode_uint(buf: bytes, modulus: int) -> int:
    if len(buf) != ns_of(modulus) + 16:
        raise CodecError("DecodeUint: wrong input length")
    return LE2IP(buf) % modulus


# fiat-shamir-03 §4.2.3 (prime field, m = 1)
def decode_field(buf: bytes, p: int, m: int = 1):
    step = ns_of(p) + 16
    if len(buf) != m * step:
        raise CodecError("DecodeField: wrong input length")
    coords = tuple(decode_uint(buf[i * step:(i + 1) * step], p) for i in range(m))
    return coords[0] if m == 1 else coords


# fiat-shamir-03 §6.1.4 with a standard's pinned big-endian serialization (I2OSP), as B.1.6 uses.
def serialize_field_be(a: int, p: int) -> bytes:
    if not 0 <= a < p:
        raise CodecError("SerializeField: value not in [0, p)")
    return I2OSP(a, ns_of(p))


# ---------------------------------------------------------------------------
# XOF duplex sponge with SHAKE128, R = 168 (fiat-shamir-03 §3.2, §9.1)
#
# hashlib's shake_128.digest(n) is not a streaming reader, so the reader is emulated: at the first
# squeeze after absorbing, the absorbed bytes are frozen (the "Copy().Finalize()"), and each squeeze
# returns the next slice of SHAKE128(frozen bytes) by tracking how many octets were already read.
# ---------------------------------------------------------------------------

SHAKE128_RATE = 168


class DuplexSponge:
    def __init__(self, session_id: bytes):
        session_id = bytes(session_id)
        if len(session_id) != 32:
            raise CodecError("Init: session_id must be 32 bytes")
        self._absorbed = bytearray(session_id + bytes(SHAKE128_RATE - 32))
        self._reader_input = None  # None: absorbing phase (reader == None)
        self._reader_pos = 0

    def absorb(self, x: bytes) -> None:
        x = bytes(x)
        self._absorbed += x
        if len(x) != 0:
            self._reader_input = None

    def squeeze(self, n: int) -> bytes:
        if n < 0:
            raise CodecError("Squeeze: negative length")
        if self._reader_input is None:
            self._reader_input = bytes(self._absorbed)  # Copy().Finalize()
            self._reader_pos = 0
        start = self._reader_pos
        out = hashlib.shake_128(self._reader_input).digest(start + n)[start:]
        self._reader_pos += n
        return out


SESSION_ID_DS = b"irtf-cfrg-fiat-shamir/session-id"
assert len(SESSION_ID_DS) == 32


def derive_session_id(tag: bytes) -> bytes:
    """fiat-shamir-03 §5.1 DeriveSessionID."""
    ds = DuplexSponge(SESSION_ID_DS)
    ds.absorb(tag)
    return ds.squeeze(32)


# ---------------------------------------------------------------------------
# Jacobian arithmetic on E: y^2 = x^3 + 4 (own code; cross-checked against the curve module's
# affine arithmetic in the self-test).  Affine points are (x, y) tuples, None is O.
# ---------------------------------------------------------------------------

JINF = (1, 1, 0)


def to_jac(pt):
    if pt is None:
        return JINF
    return (pt[0], pt[1], 1)


def to_affine(pj):
    x, y, z = pj
    if z % P_381 == 0:
        return None
    zi = pow(z, P_381 - 2, P_381)
    zi2 = zi * zi % P_381
    return (x * zi2 % P_381, y * zi2 * zi % P_381)


def is_inf(pj) -> bool:
    return pj[2] % P_381 == 0


def jdbl(pj):
    x1, y1, z1 = pj
    if z1 == 0 or y1 == 0:
        return JINF
    p = P_381
    a = x1 * x1 % p
    b = y1 * y1 % p
    c = b * b % p
    d = 2 * ((x1 + b) * (x1 + b) - a - c) % p
    e = 3 * a % p
    f = e * e % p
    x3 = (f - 2 * d) % p
    y3 = (e * (d - x3) - 8 * c) % p
    z3 = 2 * y1 * z1 % p
    return (x3, y3, z3)


def jadd(p1, p2):
    if p1[2] == 0:
        return p2
    if p2[2] == 0:
        return p1
    p = P_381
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    z1z1 = z1 * z1 % p
    z2z2 = z2 * z2 % p
    u1 = x1 * z2z2 % p
    u2 = x2 * z1z1 % p
    s1 = y1 * z2 * z2z2 % p
    s2 = y2 * z1 * z1z1 % p
    h = (u2 - u1) % p
    r = (s2 - s1) % p
    if h == 0:
        if r == 0:
            return jdbl(p1)
        return JINF
    hh = h * h % p
    hhh = h * hh % p
    v = u1 * hh % p
    x3 = (r * r - hhh - 2 * v) % p
    y3 = (r * (v - x3) - s1 * hhh) % p
    z3 = h * z1 * z2 % p
    return (x3, y3, z3)


def jneg(pj):
    return (pj[0], (-pj[1]) % P_381, pj[2])


def jmul(pj, k: int):
    """[k]P for P in the order-q subgroup (k reduced mod q).  4-bit fixed window, variable time."""
    k %= Q
    if k == 0 or pj[2] == 0:
        return JINF
    table = [JINF, pj]
    for _ in range(14):
        table.append(jadd(table[-1], pj))
    acc = JINF
    nibbles = []
    while k:
        nibbles.append(k & 15)
        k >>= 4
    for nib in reversed(nibbles):
        acc = jdbl(jdbl(jdbl(jdbl(acc))))
        if nib:
            acc = jadd(acc, table[nib])
    return acc


def msm(scalars, points):
    """Naive multi-scalar multiplication: sum of [s_i]P_i, term by term."""
    if len(scalars) != len(points):
        raise ValueError("msm: length mismatch")
    acc = JINF
    for s, pt in zip(scalars, points):
        acc = jadd(acc, jmul(pt, s))
    return acc


def jeq(p1, p2) -> bool:
    return to_affine(p1) == to_affine(p2)


def inv_q(x: int) -> int:
    x %= Q
    if x == 0:
        raise ZeroDivisionError("inverse of 0 mod q")
    return pow(x, Q - 2, Q)


# ---------------------------------------------------------------------------
# Codecs of sigma-03 §8.2 (`sigma-proofs_Shake128_BLS12381`), spec §3
# ---------------------------------------------------------------------------

NE = 48
NS = 32
assert ns_of(Q) == NS


def g1_serialize(pt) -> bytes:
    """compress(P); never produced for O (sigma-03 §2.3.1, §8.2.1)."""
    if pt is None:
        raise ValueError("serialize: identity is never serialized")
    return C.compress(pt)


def g1_decode_profile(b: bytes):
    """The strict decoder of pedersen-bls12-381-g1-v1.md §4 (identity ACCEPTED)."""
    status, val = C.strict_decode(bytes(b))
    if status == "ok":
        return val
    if status == C.NOT_IN_SUBGROUP:
        raise NotInSubgroup(f"decoder step {val}")
    raise MalformedEncoding(f"decoder step {val}")


def g1_deserialize(b: bytes):
    """Group element deserializer of spec §3: the profile's strict decoder, then reject O."""
    pt = g1_decode_profile(b)
    if pt is None:
        raise MalformedEncoding("identity encoding is not accepted for a proof point")
    return pt


def scalar_serialize(s: int) -> bytes:
    if not 0 <= s < Q:
        raise ValueError("scalar_serialize: value not in [0, q)")
    return I2OSP(s, NS)


def scalar_deserialize(b: bytes) -> int:
    b = bytes(b)
    if len(b) != NS:
        raise MalformedEncoding("scalar: wrong length")
    s = OS2IP(b)
    if s >= Q:
        raise NonCanonicalScalar("scalar not in [0, q)")
    return s


def challenge_decode(buf: bytes) -> int:
    """DecodeField(buf, q, 1) = LE2IP(buf) mod q over 48 octets (spec §3)."""
    return decode_field(buf, Q, 1)


# ---------------------------------------------------------------------------
# fiat-shamir-03 Appendix B conformance runner
# ---------------------------------------------------------------------------

FS_CODEC_IN_SCOPE = {
    "serialize_varlen", "serialize_uint", "varlen_empty", "decode_uint_wraparound",
    "serialize_field_be", "deserialize_uint_reject_modulus", "deserialize_uint_reject_short",
    "deserialize_varlen_reject_truncated", "deserialize_varlen_reject_overflow",
}
FS_CODEC_OUT_OF_SCOPE = {
    "deserialize_field": "extension field (B.1.3)",
    "deserialize_field_reject_second_coordinate": "extension field (B.1.9)",
    "sumcheck_reject_noncanonical_coefficient": "sumcheck example (B.1.12)",
    "sumcheck_reject_round_identity": "sumcheck example (B.1.13)",
}
FS_SHAKE_IN_SCOPE = {
    "init_squeeze", "absorb_squeeze", "absorb_split", "stream", "empty_absorb", "interleave",
    "multiblock", "rate_block", "squeeze_zero", "derive_sid", "decode_uint",
}
FS_SHAKE_OUT_OF_SCOPE = {
    "sumcheck": "sumcheck example (B.2.12)",
    "sumcheck_reject_trailing_bytes": "sumcheck example (B.2.13)",
}


def _hexint(s: str) -> int:
    return int(s, 16)


def run_fs_codec_vector(v: dict) -> tuple[bool, str]:
    name = v["Name"]
    fn = v["Function"]
    expected_reject = v.get("Expected") == "reject"
    try:
        if name in ("serialize_varlen", "varlen_empty"):
            assert fn == "SerializeVarLenString"
            inp = bytes.fromhex(v["Input"])
            out = serialize_varlen_string(inp)
            # round trip through the deserializer as well
            back, rest = deserialize_varlen_string(out)
            ok = out.hex() == v["Output"] and back == inp and rest == b""
            return ok, out.hex()
        if name == "serialize_uint":
            out = serialize_uint(_hexint(v["Value"]), _hexint(v["Modulus"]))
            back, rest = deserialize_uint(out, _hexint(v["Modulus"]))
            return out.hex() == v["Output"] and back == _hexint(v["Value"]) and rest == b"", out.hex()
        if name == "decode_uint_wraparound":
            ch = decode_uint(bytes.fromhex(v["Input"]), _hexint(v["Modulus"]))
            return ch == _hexint(v["Challenge"]), hex(ch)
        if name == "serialize_field_be":
            assert v.get("ByteOrder") == "big-endian"
            out = serialize_field_be(_hexint(v["Value"]), _hexint(v["Modulus"]))
            return out.hex() == v["Output"], out.hex()
        if name in ("deserialize_uint_reject_modulus", "deserialize_uint_reject_short"):
            try:
                deserialize_uint(bytes.fromhex(v["Input"]), _hexint(v["Modulus"]))
            except CodecError as e:
                return expected_reject, f"rejected ({e})"
            return False, "accepted"
        if name in ("deserialize_varlen_reject_truncated", "deserialize_varlen_reject_overflow"):
            try:
                deserialize_varlen_string(bytes.fromhex(v["Input"]))
            except CodecError as e:
                return expected_reject, f"rejected ({e})"
            return False, "accepted"
    except (CodecError, AssertionError) as e:
        return False, f"exception {e!r}"
    return False, "no runner"


def run_fs_shake_vector(v: dict) -> tuple[bool, str]:
    fn = v["Function"]
    if v.get("Hash") != "SHAKE128":
        return False, "not SHAKE128"
    if fn == "DeriveSessionID":
        out = derive_session_id(bytes.fromhex(v["Tag"]))
        return out.hex() == v["Output"], out.hex()
    ds = DuplexSponge(bytes.fromhex(v["SessionId"]))
    out = b""
    for op in v["Operations"]:
        if op["type"] == "absorb":
            ds.absorb(bytes.fromhex(op["data"]))
        elif op["type"] == "squeeze":
            out += ds.squeeze(int(op["length"]))
        else:
            return False, "unknown op"
    ok = out.hex() == v["Output"]
    # independent comparison with a one-shot CPython SHAKE128 evaluation of the whole stream
    # (fiat-shamir-03 §3.2's XOF(session_id || zeros(R-32) || ..., len) form) for the simple shapes
    if fn == "DecodeUint":
        ch = decode_uint(out, _hexint(v["Modulus"]))
        ok = ok and ch == _hexint(v["Challenge"])
        return ok, f"{out.hex()} challenge={hex(ch)}"
    return ok, out.hex()


# ---------------------------------------------------------------------------
# sigma-03: linear relations (§3), the sigma protocol (§4), NARG strings (§5)
#
# The A.3.2 adversarial file contains a `dleq` statement (two equations) and malformed instances,
# so a small generic sparse-relation verifier is implemented (parse of the §3.6 encoding, §3.5
# validation, map/image, batchable and compact verification).  No prover is implemented.
# ---------------------------------------------------------------------------


class SigmaReject(Exception):
    def __init__(self, layer: str, detail: str):
        super().__init__(f"{layer}: {detail}")
        self.layer = layer
        self.detail = detail


class LinearRelation:
    def __init__(self, elements, equations):
        self.elements = elements  # affine points or None; elements[0] = generator
        self.equations = equations  # list of (image[(elem, coeff)], terms[(scalar, elem, coeff)])

    def num_scalars(self) -> int:
        return 1 + max(s for (_, terms) in self.equations for (s, _, _) in terms)


def parse_linear_relation(data: bytes) -> LinearRelation:
    """Inverse of SerializeLinearRelation (sigma-03 §3.6).  The draft defines no deserializer;
    this one is ours: counts and indices LE 4 octets, coefficients via the scalar deserializer, the
    remaining octets are the elements at indices 1.. (48 octets each, profile strict decoder; the
    identity is parsed so that §3.5 check 8 can report it)."""
    pos = 0

    def take(n):
        nonlocal pos
        if len(data) - pos < n:
            raise SigmaReject("instance-parse", "truncated instance")
        out = data[pos:pos + n]
        pos += n
        return out

    neq = LE2IP(take(4))
    equations = []
    for _ in range(neq):
        nimg = LE2IP(take(4))
        image = []
        for _ in range(nimg):
            ei = LE2IP(take(4))
            try:
                co = scalar_deserialize(take(NS))
            except BulletproofError as e:
                raise SigmaReject("instance-parse", f"coefficient: {e}")
            image.append((ei, co))
        nterms = LE2IP(take(4))
        terms = []
        for _ in range(nterms):
            si = LE2IP(take(4))
            ei = LE2IP(take(4))
            try:
                co = scalar_deserialize(take(NS))
            except BulletproofError as e:
                raise SigmaReject("instance-parse", f"coefficient: {e}")
            terms.append((si, ei, co))
        equations.append((image, terms))
    rest = data[pos:]
    if len(rest) % NE != 0:
        raise SigmaReject("instance-parse", "element section not a multiple of Ne")
    elements = [G1_GEN]
    for i in range(0, len(rest), NE):
        try:
            elements.append(g1_decode_profile(rest[i:i + NE]))
        except BulletproofError as e:
            raise SigmaReject("instance-parse", f"element {1 + i // NE}: {e}")
    return LinearRelation(elements, equations)


def serialize_linear_relation(inst: LinearRelation) -> bytes:
    out = LE(len(inst.equations), 4)
    for image, terms in inst.equations:
        out += LE(len(image), 4)
        for ei, co in image:
            out += LE(ei, 4) + scalar_serialize(co)
        out += LE(len(terms), 4)
        for si, ei, co in terms:
            out += LE(si, 4) + LE(ei, 4) + scalar_serialize(co)
    for el in inst.elements[1:]:
        out += C.compress(el)
    return out


def sigma_image(inst: LinearRelation):
    out = []
    for image, _ in inst.equations:
        acc = JINF
        for ei, co in image:
            acc = jadd(acc, jmul(to_jac(inst.elements[ei]), co))
        out.append(acc)
    return out


def sigma_map(inst: LinearRelation, scalars):
    out = []
    for _, terms in inst.equations:
        acc = JINF
        for si, ei, co in terms:
            acc = jadd(acc, jmul(to_jac(inst.elements[ei]), co * scalars[si] % Q))
        out.append(acc)
    return out


def validate_instance(inst: LinearRelation):
    """sigma-03 §3.5; returns None if valid, else the number of the failed check."""
    if len(inst.equations) == 0:
        return 1
    for image, terms in inst.equations:
        if not image or not terms:
            return 2
    # check 3 holds by construction (4-octet LE fields)
    ne = len(inst.elements)
    for image, terms in inst.equations:
        if any(ei >= ne for ei, _ in image) or any(ei >= ne for _, ei, _ in terms):
            return 4
    used = set()
    for image, terms in inst.equations:
        used.update(ei for ei, _ in image)
        used.update(ei for _, ei, _ in terms)
    for idx in range(1, ne):
        if idx not in used:
            return 5
    nsc = inst.num_scalars()
    sused = {si for _, terms in inst.equations for si, _, _ in terms}
    if any(s not in sused for s in range(nsc)):
        return 6
    if ne == 0 or inst.elements[0] != G1_GEN:
        return 7
    if any(el is None for el in inst.elements):
        return 8
    if any(is_inf(im) for im in sigma_image(inst)):
        return 9
    for s in range(nsc):
        nonzero = False
        for _, terms in inst.equations:
            acc = JINF
            for si, ei, co in terms:
                if si == s:
                    acc = jadd(acc, jmul(to_jac(inst.elements[ei]), co))
            if not is_inf(acc):
                nonzero = True
        if not nonzero:
            return 10
    return None


_SIGMA_CHALLENGES_DERIVED = 0
_SIGMA_CHALLENGE_OFFSET = 0  # TEST-ONLY seam: added to every derived challenge (mod q)


def sigma_derive_challenge(tag: bytes, inst: LinearRelation, commitment_bytes: bytes) -> int:
    """sigma-03 §5.2 DeriveChallenge."""
    global _SIGMA_CHALLENGES_DERIVED
    _SIGMA_CHALLENGES_DERIVED += 1
    ds = DuplexSponge(derive_session_id(tag))
    ds.absorb(serialize_linear_relation(inst))
    ds.absorb(commitment_bytes)
    return (decode_field(ds.squeeze(NS + 16), Q, 1) + _SIGMA_CHALLENGE_OFFSET) % Q


def sigma_verify(tag: bytes, instance_bytes: bytes, narg: bytes, flavor: str):
    """Returns (accepted, layer, detail, challenge).  Order: instance parse, §3.5 validation, length,
    deserialization (points then scalars), challenge, verification."""
    inst = parse_linear_relation(instance_bytes)
    if serialize_linear_relation(inst) != instance_bytes:
        raise SigmaReject("instance-parse", "instance does not re-serialize to its input")
    bad = validate_instance(inst)
    if bad is not None:
        raise SigmaReject("instance-validation", f"sigma-03 §3.5 check {bad}")
    neq = len(inst.equations)
    nsc = inst.num_scalars()
    if flavor == "batchable":
        if len(narg) != NE * neq + NS * nsc:
            raise SigmaReject("length", f"NARG length {len(narg)} != {NE * neq + NS * nsc}")
        commitment = []
        for i in range(neq):
            try:
                commitment.append(g1_deserialize(narg[NE * i:NE * (i + 1)]))
            except BulletproofError as e:
                raise SigmaReject("deserialize-point", f"commitment[{i}]: {e}")
        off = NE * neq
        response = []
        for i in range(nsc):
            try:
                response.append(scalar_deserialize(narg[off + NS * i:off + NS * (i + 1)]))
            except BulletproofError as e:
                raise SigmaReject("deserialize-scalar", f"response[{i}]: {e}")
        ch = sigma_derive_challenge(tag, inst, narg[:off])
        expected = sigma_map(inst, response)
        img = sigma_image(inst)
        got = [jadd(to_jac(commitment[i]), jmul(img[i], ch)) for i in range(neq)]
        if all(jeq(expected[i], got[i]) for i in range(neq)):
            return True, "accept", "", ch
        raise SigmaReject("verification", "commitment + c*image != map(response)")
    if flavor == "compact":
        if len(narg) != NS + NS * nsc:
            raise SigmaReject("length", f"NARG length {len(narg)} != {NS + NS * nsc}")
        try:
            ch = scalar_deserialize(narg[0:NS])
        except BulletproofError as e:
            raise SigmaReject("deserialize-scalar", f"challenge: {e}")
        response = []
        for i in range(nsc):
            try:
                response.append(scalar_deserialize(narg[NS + NS * i:NS + NS * (i + 1)]))
            except BulletproofError as e:
                raise SigmaReject("deserialize-scalar", f"response[{i}]: {e}")
        mapped = sigma_map(inst, response)
        img = sigma_image(inst)
        commitment = [jadd(mapped[i], jneg(jmul(img[i], ch))) for i in range(neq)]
        if any(is_inf(c) for c in commitment):
            raise SigmaReject("simulated-commitment-identity", "SimulateCommitment gave O (§5.5 step 7)")
        cb = b"".join(g1_serialize(to_affine(c)) for c in commitment)
        expected_ch = sigma_derive_challenge(tag, inst, cb)
        if expected_ch == ch:
            return True, "accept", "", ch
        raise SigmaReject("verification", "recomputed challenge differs")
    raise ValueError("flavor")


# ---------------------------------------------------------------------------
# Bulletproof range proof: constants and generators (spec §2)
# ---------------------------------------------------------------------------

BITS = (16, 32, 64)
LOG2 = {16: 4, 32: 5, 64: 6}
MAX_CTX = 1024
DST_BP = b"ZeroJ-bulletproof-bls12-381-g1-gens-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_"
PROFILE_ID = b"pedersen-bls12-381-g1-v1"
GENSET_ID = b"bulletproof-bls12-381-g1-gens-v1"
PROTOCOL_ID = b"ZeroJ:bulletproof-range-bls12-381-g1-v1"
TEST_NONCE_TAG = b"ZeroJ:bulletproof-range-bls12-381-g1-v1/test-nonces-v1"

# pedersen-bls12-381-g1-v1.md §2.2, transcribed by hand
PINNED_G_HEX = ("80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c1664"
                "4e56e5c43c76ba9869e960e3fd5c2f3e")
PINNED_H_HEX = ("92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d7"
                "72eb1111aafc6b64875b9a2256b6ab65")


def proof_length(n: int) -> int:
    return 48 * (4 + 2 * LOG2[n]) + 32 * 5


class Generators:
    def __init__(self):
        self.Gvec = []
        self.Hvec = []
        self.U = None
        self.G = None  # Pedersen value base
        self.H = None  # Pedersen blinding base
        self.encodings = []  # 129 compressed, G_0..G_63, H_0..H_63, U
        self.digest = b""


class GeneratorCheckFailure(Exception):
    pass


def derive_generators() -> Generators:
    gens = Generators()
    gens.Gvec = [C.hash_to_curve(b"G" + I2OSP(i, 4), DST_BP) for i in range(64)]
    gens.Hvec = [C.hash_to_curve(b"H" + I2OSP(i, 4), DST_BP) for i in range(64)]
    gens.U = C.hash_to_curve(b"U", DST_BP)
    # Pedersen bases: pinned values of the profile, decoded with the strict decoder, and also
    # recomputed with RFC 9380 under the profile's DST (the profile says "a test recomputes them").
    gens.G = g1_deserialize(bytes.fromhex(PINNED_G_HEX))
    gens.H = g1_deserialize(bytes.fromhex(PINNED_H_HEX))
    g_re, h_re = C.derive_basis()
    if g_re != gens.G or h_re != gens.H:
        raise GeneratorCheckFailure("profile bases do not match their RFC 9380 recomputation")
    # §2.2: none of the 131 points is O, and for any two P != Q and P != -Q
    allpts = gens.Gvec + gens.Hvec + [gens.U, gens.G, gens.H]
    if any(p is None for p in allpts):
        raise GeneratorCheckFailure("a generator is the identity")
    xs = set()
    for p in allpts:
        # two affine points on E are equal or negatives of each other iff their x agree
        if p[0] in xs:
            raise GeneratorCheckFailure("two generators are equal or negatives")
        xs.add(p[0])
    gens.encodings = [g1_serialize(p) for p in gens.Gvec + gens.Hvec + [gens.U]]
    gens.digest = hashlib.sha256(b"".join(gens.encodings)).digest()
    return gens


_GENS = None


def generators() -> Generators:
    global _GENS
    if _GENS is None:
        _GENS = derive_generators()
    return _GENS


# ---------------------------------------------------------------------------
# Transcript (spec §5) — with two TEST-ONLY seams used by the self-test:
#   _TRANSCRIPT_MUTATION  (None or one of "drop_V", "drop_ctx", "drop_Dgens", "drop_n", "swap_GH")
#   _CHALLENGE_HOOK       (None or callable(name, value) -> value; used to force a zero challenge)
# ---------------------------------------------------------------------------

_TRANSCRIPT_MUTATION = None
_CHALLENGE_HOOK = None


def session_tag(n: int, ctx: bytes) -> bytes:
    k = LOG2[n]
    tag = (PROTOCOL_ID
           + b"/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381"
           + b"/N" + b"%03d" % n
           + b"/A96S96.A96S48.A96S48.(A96S48)x" + b"%d" % k)
    if _TRANSCRIPT_MUTATION != "drop_ctx":
        tag += b"/CTX" + b"%04d" % len(ctx) + b":" + bytes(ctx).hex().encode("ascii")
    return tag


def encode_instance(n: int, v_bytes: bytes) -> bytes:
    gens = generators()
    g_enc, h_enc = g1_serialize(gens.G), g1_serialize(gens.H)
    if _TRANSCRIPT_MUTATION == "swap_GH":
        g_enc, h_enc = h_enc, g_enc
    out = serialize_varlen_string(PROFILE_ID) + g_enc + h_enc + serialize_varlen_string(GENSET_ID)
    if _TRANSCRIPT_MUTATION != "drop_Dgens":
        out += gens.digest
    if _TRANSCRIPT_MUTATION != "drop_n":
        out += serialize_uint(n, 2 ** 32)
    if _TRANSCRIPT_MUTATION != "drop_V":
        out += v_bytes
    return out


class _Transcript:
    def __init__(self, n: int, ctx: bytes, v_bytes: bytes):
        self.tag = session_tag(n, ctx)
        self.session_id = derive_session_id(self.tag)
        self.instance = encode_instance(n, v_bytes)
        self.ds = DuplexSponge(self.session_id)
        self.ds.absorb(self.instance)
        self.challenges = {}

    def absorb(self, data: bytes) -> None:
        self.ds.absorb(data)

    def challenge(self, name: str) -> int:
        c = challenge_decode(self.ds.squeeze(48))
        if _CHALLENGE_HOOK is not None:
            c = _CHALLENGE_HOOK(name, c)
        self.challenges[name] = c
        return c


def _challenge_dict(ch: dict, k: int) -> dict:
    return {"y": str(ch["y"]), "z": str(ch["z"]), "x": str(ch["x"]), "xu": str(ch["xu"]),
            "xj": [str(ch[f"x_{j}"]) for j in range(1, k + 1)]}


# ---------------------------------------------------------------------------
# Prover (spec §7)
# ---------------------------------------------------------------------------

def _check_configuration(n, ctx) -> None:
    # A wrong argument type is an API-binding error, not a vector case (spec §11): TypeError.
    if isinstance(n, bool) or not isinstance(n, int):
        raise TypeError("n must be an int")
    if not isinstance(ctx, (bytes, bytearray)):
        raise TypeError("ctx must be bytes")
    if n not in BITS:
        raise InvalidConfiguration("n not in {16, 32, 64}", "configuration")
    if not 1 <= len(ctx) <= MAX_CTX:
        raise InvalidConfiguration("len(ctx) not in [1, 1024]", "configuration")


def _check1(name: str, s) -> int:
    if isinstance(s, bool) or not isinstance(s, int):
        raise TypeError(f"{name} must be an int")
    if not 0 <= s < Q:
        raise NonCanonicalScalar(f"{name} outside [0, q)", "scalar")
    return s


def commit(v: int, gamma: int):
    gens = generators()
    return jadd(jmul(to_jac(gens.G), v), jmul(to_jac(gens.H), gamma))


def _prover_preamble(v, gamma, n, ctx):
    """§7.1 refusals, in order, before any curve work; then V and the INVALID_STATEMENT check."""
    _check_configuration(n, ctx)
    _check1("v", v)
    _check1("gamma", gamma)
    if v >= (1 << n):
        raise OutOfRange("v >= 2^n", "range")
    V = commit(v, gamma)
    if is_inf(V):
        raise InvalidStatement("V = O", "statement")
    return V


class _Restart(Exception):
    pass


def _csprng_nonces(n: int):
    def one():
        return OS2IP(secrets.token_bytes(64)) % Q
    alpha, rho = one(), one()
    s_l = [one() for _ in range(n)]
    s_r = [one() for _ in range(n)]
    tau1, tau2 = one(), one()
    return alpha, rho, s_l, s_r, tau1, tau2


def _test_nonces(n: int, seed: bytes):
    """§7.5: package-private test seam (in Python: an underscore name)."""
    seed = bytes(seed)
    if len(seed) != 32:
        raise ValueError("test nonce seed must be exactly 32 octets")
    ds = DuplexSponge(derive_session_id(TEST_NONCE_TAG))
    ds.absorb(seed)

    def one():
        return LE2IP(ds.squeeze(48)) % Q
    alpha = one()
    rho = one()
    s_l = [one() for _ in range(n)]
    s_r = [one() for _ in range(n)]
    tau1 = one()
    tau2 = one()
    return alpha, rho, s_l, s_r, tau1, tau2


def _ip(a, b) -> int:
    return sum(x * y for x, y in zip(a, b)) % Q


def _powers(c: int, n: int):
    out = [1] * n
    for i in range(1, n):
        out[i] = out[i - 1] * c % Q
    return out


def _ser_pt(pj) -> bytes:
    if is_inf(pj):
        raise _Restart("prover point is O")
    return g1_serialize(to_affine(pj))


def _prove_core(v, gamma, n, ctx, V, nonces, a_l_override=None):
    """§7.2.  `a_l_override` is a self-test-only hook to build a cheating prover."""
    gens = generators()
    k = LOG2[n]
    Gv = [to_jac(p) for p in gens.Gvec[:n]]
    Hv = [to_jac(p) for p in gens.Hvec[:n]]
    Gb, Hb, U = to_jac(gens.G), to_jac(gens.H), to_jac(gens.U)
    v_bytes = g1_serialize(to_affine(V))
    alpha, rho, s_l, s_r, tau1, tau2 = nonces

    a_l = [(v >> i) & 1 for i in range(n)] if a_l_override is None else list(a_l_override)
    a_r = [(b - 1) % Q for b in a_l]

    A = msm([alpha] + a_l + a_r, [Hb] + Gv + Hv)
    S = msm([rho] + s_l + s_r, [Hb] + Gv + Hv)
    tr = _Transcript(n, ctx, v_bytes)
    enc_a, enc_s = _ser_pt(A), _ser_pt(S)
    tr.absorb(enc_a + enc_s)
    y = tr.challenge("y")
    z = tr.challenge("z")
    if y == 0 or z == 0:
        raise _Restart("zero challenge y/z")

    yn = _powers(y, n)
    twon = _powers(2, n)
    z2 = z * z % Q
    l0 = [(a - z) % Q for a in a_l]
    l1 = list(s_l)
    r0 = [(yn[i] * (a_r[i] + z) + z2 * twon[i]) % Q for i in range(n)]
    r1 = [yn[i] * s_r[i] % Q for i in range(n)]
    t1 = (_ip(l0, r1) + _ip(l1, r0)) % Q
    t2 = _ip(l1, r1)
    T1 = msm([t1, tau1], [Gb, Hb])
    T2 = msm([t2, tau2], [Gb, Hb])
    enc_t1, enc_t2 = _ser_pt(T1), _ser_pt(T2)
    tr.absorb(enc_t1 + enc_t2)
    x = tr.challenge("x")
    if x == 0:
        raise _Restart("zero challenge x")

    l_vec = [(l0[i] + x * l1[i]) % Q for i in range(n)]
    r_vec = [(r0[i] + x * r1[i]) % Q for i in range(n)]
    t_hat = _ip(l_vec, r_vec)
    tau_x = (tau2 * x * x + tau1 * x + z2 * gamma) % Q
    mu = (alpha + rho * x) % Q
    scal_bytes = scalar_serialize(t_hat) + scalar_serialize(tau_x) + scalar_serialize(mu)
    tr.absorb(scal_bytes)
    xu = tr.challenge("xu")
    if xu == 0:
        raise _Restart("zero challenge x_u")

    # Inner-product argument (Protocol 1 with Protocol 2)
    y_inv = inv_q(y)
    y_inv_pows = _powers(y_inv, n)
    g = Gv
    h = [jmul(Hv[i], y_inv_pows[i]) for i in range(n)]
    u = jmul(U, xu)
    a, b = l_vec, r_vec
    lr_bytes = b""
    j = 0
    while len(a) > 1:
        j += 1
        t = len(a) // 2
        c_l = _ip(a[:t], b[t:])
        c_r = _ip(a[t:], b[:t])
        L = msm(a[:t] + b[t:] + [c_l], g[t:] + h[:t] + [u])
        R = msm(a[t:] + b[:t] + [c_r], g[:t] + h[t:] + [u])
        enc = _ser_pt(L) + _ser_pt(R)
        tr.absorb(enc)
        lr_bytes += enc
        xj = tr.challenge(f"x_{j}")
        if xj == 0:
            raise _Restart(f"zero challenge x_{j}")
        xj_inv = inv_q(xj)
        g = [jadd(jmul(g[i], xj_inv), jmul(g[t + i], xj)) for i in range(t)]
        h = [jadd(jmul(h[i], xj), jmul(h[t + i], xj_inv)) for i in range(t)]
        a = [(a[i] * xj + a[t + i] * xj_inv) % Q for i in range(t)]
        b = [(b[i] * xj_inv + b[t + i] * xj) % Q for i in range(t)]
    assert j == k

    proof = (enc_a + enc_s + enc_t1 + enc_t2 + scal_bytes + lr_bytes
             + scalar_serialize(a[0]) + scalar_serialize(b[0]))
    assert len(proof) == proof_length(n)
    trace = {"tag": tr.tag, "sessionId": tr.session_id, "instance": tr.instance,
             "challenges": dict(tr.challenges), "commitment": v_bytes}
    return proof, trace


MAX_PROVER_ATTEMPTS = 8  # §7.3


class ProverRestartsExhausted(RuntimeError):
    """§7.3: the Python analogue of Java's IllegalStateException; no proof is emitted."""


def prove(v: int, gamma: int, n: int, ctx: bytes):
    """Public prover: CSPRNG nonces (§7.3), restarts with all-fresh nonces, at most 8 attempts.
    Returns (V octets, proof)."""
    V = _prover_preamble(v, gamma, n, ctx)
    for _ in range(MAX_PROVER_ATTEMPTS):
        try:
            proof, trace = _prove_core(v, gamma, n, bytes(ctx), V, _csprng_nonces(n))
            return trace["commitment"], proof
        except _Restart:
            continue
    raise ProverRestartsExhausted(f"prover: {MAX_PROVER_ATTEMPTS} attempts exhausted")


def _prove_with_test_nonces(v: int, gamma: int, n: int, ctx: bytes, seed: bytes):
    """§7.5 test seam: deterministic nonces; fails instead of restarting.  Returns (proof, trace)."""
    V = _prover_preamble(v, gamma, n, ctx)
    try:
        return _prove_core(v, gamma, n, bytes(ctx), V, _test_nonces(n, seed))
    except _Restart as e:
        raise TestNonceProverFailure(str(e))


# ---------------------------------------------------------------------------
# Verifier (spec §8)
# ---------------------------------------------------------------------------

def _point_offsets(n: int):
    k = LOG2[n]
    offs = [0, 48, 96, 144]
    for j in range(k):
        offs += [288 + 96 * j, 288 + 96 * j + 48]
    return offs


def _scalar_offsets(n: int):
    k = LOG2[n]
    end = 288 + 96 * k
    return [192, 224, 256, end, end + 32]


_S_BIT_ORDER = "msb"  # TEST-ONLY seam: "lsb" is a deliberately wrong rule used as a mutant


def _field_layout(n: int):
    """The proof's fields in proof order (§6): (kind, offset)."""
    k = LOG2[n]
    out = [("point", 0), ("point", 48), ("point", 96), ("point", 144),
           ("scalar", 192), ("scalar", 224), ("scalar", 256)]
    for j in range(k):
        out += [("point", 288 + 96 * j), ("point", 288 + 96 * j + 48)]
    end = 288 + 96 * k
    out += [("scalar", end), ("scalar", end + 32)]
    return out


def _s_vector(xs, n: int, k: int):
    """s_i = prod_j x_j^{e(i,j)}, e = +1 iff bit (k - j) of i is 1 (spec §8.3, MSB first)."""
    xinv = [inv_q(x) for x in xs]
    s, s_inv = [], []
    for i in range(n):
        p, pi = 1, 1
        for j in range(1, k + 1):
            bitpos = (k - j) if _S_BIT_ORDER == "msb" else (j - 1)
            if (i >> bitpos) & 1:
                p = p * xs[j - 1] % Q
                pi = pi * xinv[j - 1] % Q
            else:
                p = p * xinv[j - 1] % Q
                pi = pi * xs[j - 1] % Q
        s.append(p)
        s_inv.append(pi)
    return s, s_inv


def _validate_decoded_v(V):
    """§8.1 step 4 for a V given already decoded: an affine tuple is NOT trusted; it must pass the
    full on-curve and prime-order-subgroup checks.  None is O."""
    if V is None:
        return None
    if not (isinstance(V, tuple) and len(V) == 2 and all(isinstance(c, int) and not isinstance(c, bool)
                                                         for c in V)):
        raise TypeError("decoded V must be an affine (x, y) tuple of ints, or None for O")
    if not C.on_curve_e(V):
        raise MalformedEncoding("decoded V is not on the curve", "statement")
    if not C.in_subgroup(V):
        raise NotInSubgroup("decoded V is not in the prime-order subgroup", "statement")
    return V


def verify_detailed(V, proof: bytes, n: int, ctx: bytes) -> dict:
    """Spec §8.  `V` is 48 octets, or an already-decoded commitment (affine tuple, or None for O),
    which is fully validated.  Format failures raise a BulletproofError subclass (with .layer);
    otherwise returns a dict with `verdict` (bool), `layer`, `check1`, `check2` and challenges."""
    # Step 1: configuration
    _check_configuration(n, ctx)
    ctx = bytes(ctx)
    k = LOG2[n]
    # Step 2: proof length, before anything is decoded (including V)
    if not isinstance(proof, (bytes, bytearray)):
        raise TypeError("proof must be bytes")
    proof = bytes(proof)
    if len(proof) != proof_length(n):
        raise MalformedEncoding(f"proof length {len(proof)} != {proof_length(n)}", "length")
    # Step 3: the proof's fields in proof order; first failure reported
    pts, scs = [], []
    for kind, off in _field_layout(n):
        try:
            if kind == "point":
                pts.append(g1_deserialize(proof[off:off + 48]))
            else:
                scs.append(scalar_deserialize(proof[off:off + 32]))
        except BulletproofError as e:
            e.layer = kind
            e.detail = f"{kind} at offset {off}: {e.detail}"
            raise
    # Step 4: V
    if isinstance(V, (bytes, bytearray)):
        try:
            v_pt = g1_decode_profile(bytes(V))
        except BulletproofError as e:
            e.layer = "statement"
            raise
    else:
        v_pt = _validate_decoded_v(V)
    # Step 5: V = O -> false
    if v_pt is None:
        return {"verdict": False, "layer": "statement", "detail": "V = O"}
    v_bytes = g1_serialize(v_pt)
    A, S, T1, T2 = (to_jac(p) for p in pts[:4])
    Ls = [to_jac(pts[4 + 2 * j]) for j in range(k)]
    Rs = [to_jac(pts[5 + 2 * j]) for j in range(k)]
    t_hat, tau_x, mu, a, b = scs

    # §8.2 challenges
    tr = _Transcript(n, ctx, v_bytes)
    tr.absorb(proof[0:96])
    y = tr.challenge("y")
    z = tr.challenge("z")
    tr.absorb(proof[96:192])
    x = tr.challenge("x")
    tr.absorb(proof[192:288])
    xu = tr.challenge("xu")
    xs = []
    for j in range(k):
        tr.absorb(proof[288 + 96 * j:288 + 96 * (j + 1)])
        xs.append(tr.challenge(f"x_{j + 1}"))
    chals = dict(tr.challenges)
    if any(c == 0 for c in [y, z, x, xu] + xs):
        return {"verdict": False, "layer": "challenge", "detail": "zero challenge",
                "challenges": chals, "sessionId": tr.session_id}

    gens = generators()
    Gb, Hb, U = to_jac(gens.G), to_jac(gens.H), to_jac(gens.U)
    Vj = to_jac(v_pt)
    yn = _powers(y, n)
    z2 = z * z % Q
    z3 = z2 * z % Q
    delta = ((z - z2) * sum(yn) - z3 * ((1 << n) - 1)) % Q

    # Check 1 (paper (98)), five terms
    c1 = msm([(t_hat - delta) % Q, tau_x, (-z2) % Q, (-x) % Q, (-x * x) % Q],
             [Gb, Hb, Vj, T1, T2])
    ok1 = is_inf(c1)

    # Check 2 (paper (105) with the independent U), 2n + 2k + 4 terms
    s, s_inv = _s_vector(xs, n, k)
    y_inv_pows = _powers(inv_q(y), n)
    twon = _powers(2, n)
    scalars, points = [], []
    for i in range(n):
        scalars.append((a * s[i] + z) % Q)
        points.append(to_jac(gens.Gvec[i]))
    for i in range(n):
        scalars.append((y_inv_pows[i] * (b * s_inv[i] - z2 * twon[i]) - z) % Q)
        points.append(to_jac(gens.Hvec[i]))
    scalars += [xu * (a * b - t_hat) % Q, mu, Q - 1, (-x) % Q]
    points += [U, Hb, A, S]
    for j in range(k):
        xj = xs[j]
        xj_inv = inv_q(xj)
        scalars += [(-xj * xj) % Q, (-xj_inv * xj_inv) % Q]
        points += [Ls[j], Rs[j]]
    assert len(scalars) == 2 * n + 2 * k + 4
    ok2 = is_inf(msm(scalars, points))

    verdict = ok1 and ok2
    layer = "accept" if verdict else ("check1" if not ok1 else "check2")
    return {"verdict": verdict, "layer": layer, "check1": ok1, "check2": ok2,
            "challenges": chals, "sessionId": tr.session_id}


def verify(V, proof: bytes, n: int, ctx: bytes) -> bool:
    return verify_detailed(V, proof, n, ctx)["verdict"]


def classify(V, proof, n, ctx):
    """(outcome, layer): outcome is "true", "false" or an error class name."""
    try:
        r = verify_detailed(V, proof, n, ctx)
    except BulletproofError as e:
        return e.error_class, e.layer
    return ("true" if r["verdict"] else "false"), r["layer"]


def _verify_ipa_recursive(V_bytes: bytes, proof: bytes, n: int, ctx: bytes) -> bool:
    """Self-test cross-check of check 2: Protocol 1 + Protocol 2 run literally (fold generators and
    P round by round, paper (29)-(31), final check (16)).  Independent of the s_i bit rule."""
    gens = generators()
    k = LOG2[n]
    pts = [g1_deserialize(proof[o:o + 48]) for o in _point_offsets(n)]
    t_hat, tau_x, mu, a, b = (scalar_deserialize(proof[o:o + 32]) for o in _scalar_offsets(n))
    A, S = to_jac(pts[0]), to_jac(pts[1])
    tr = _Transcript(n, ctx, V_bytes)
    tr.absorb(proof[0:96])
    y = tr.challenge("y")
    z = tr.challenge("z")
    tr.absorb(proof[96:192])
    x = tr.challenge("x")
    tr.absorb(proof[192:288])
    xu = tr.challenge("xu")
    xs = []
    for j in range(k):
        tr.absorb(proof[288 + 96 * j:288 + 96 * (j + 1)])
        xs.append(tr.challenge(f"x_{j + 1}"))
    yinv = _powers(inv_q(y), n)
    yn = _powers(y, n)
    twon = _powers(2, n)
    z2 = z * z % Q
    g = [to_jac(p) for p in gens.Gvec[:n]]
    h = [jmul(to_jac(gens.Hvec[i]), yinv[i]) for i in range(n)]
    # paper (66): P = A * S^x * g^-z * h'^(z*y^n + z^2*2^n)
    P = jadd(A, jmul(S, x))
    for i in range(n):
        P = jadd(P, jmul(g[i], (-z) % Q))
        P = jadd(P, jmul(h[i], (z * yn[i] + z2 * twon[i]) % Q))
    # §4.2: IPA on (g, h', P h^-mu, t_hat); Protocol 1 (8): P' = P * u^(x_u * c)
    P = jadd(P, jmul(to_jac(gens.H), (-mu) % Q))
    U = to_jac(gens.U)
    P = jadd(P, jmul(U, xu * t_hat % Q))
    u = jmul(U, xu)
    for j in range(k):
        xj = xs[j]
        xinv = inv_q(xj)
        L, R = to_jac(pts[4 + 2 * j]), to_jac(pts[5 + 2 * j])
        t = len(g) // 2
        g = [jadd(jmul(g[i], xinv), jmul(g[t + i], xj)) for i in range(t)]
        h = [jadd(jmul(h[i], xj), jmul(h[t + i], xinv)) for i in range(t)]
        P = jadd(jadd(jmul(L, xj * xj), P), jmul(R, xinv * xinv))
    final = jadd(jadd(jmul(g[0], a), jmul(h[0], b)), jmul(u, a * b))
    return jeq(final, P)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_BUNDLE_VECTORS = None  # set by --vectors-dir

# spec §10: ZeroJ's unchanged copies of the CFRG files, resolved relative to this script
DEFAULT_VECTORS_DIR = os.path.normpath(os.path.join(
    _HERE, "..", "..", "..", "..", "..",
    "zeroj-test-vectors", "src", "main", "resources", "test-vectors", "cfrg-drafts-03"))

# spec §10 (pinned at mmaker/draft-irtf-cfrg-sigma-protocols 91cc933051af88b58e350af78a8ea961c56a30c6)
VECTOR_SHA256 = {
    "fiatShamirCodecVectors.json": "97d85f96e252111fd01e4147d9ebc48c80203e5783fef1eea2204211d847c821",
    "fiatShamirShake128Vectors.json": "f04cdf455b60239d20392813ffd5dd8d079fb1c0d5b0e07de3e50899bd6f6502",
    "sigma-proofs_Shake128_BLS12381.json": "e9f942c2d76f2086793b771fbb32cc8452e51dcf274cf163258d36b8d9906e94",
    "sigma-proofs-invalid_Shake128_BLS12381.json":
        "1da51dc890c0d9fe550d14c9f0f71c5175c5c5b6c6a698ef53074bb4c58bc740",
}


class _Results:
    def __init__(self):
        self.groups = {}
        self.reported = {}
        self.failures = []

    def check(self, group: str, name: str, cond: bool, detail: str = "") -> bool:
        g = self.groups.setdefault(group, [0, 0])
        if cond:
            g[0] += 1
            print(f"PASS [{group}] {name}" + (f"  ({detail})" if detail else ""))
        else:
            g[1] += 1
            self.failures.append(f"[{group}] {name}: {detail}")
            print(f"FAIL [{group}] {name}  ({detail})")
        sys.stdout.flush()
        return cond

    def guard(self, group: str, name: str, fn) -> bool:
        """Run fn() -> (cond, detail) or bool; an unexpected exception is a counted FAIL line."""
        try:
            r = fn()
        except Exception as e:  # noqa: BLE001
            return self.check(group, name, False, f"unexpected {type(e).__name__}: {e}")
        if isinstance(r, tuple):
            return self.check(group, name, bool(r[0]), str(r[1]))
        return self.check(group, name, bool(r))

    def report(self, group: str, name: str, cond: bool, detail: str = "") -> bool:
        """Reported but not gated (spec §10: the ten extra A.3.1 vectors)."""
        g = self.reported.setdefault(group, [0, 0])
        g[0 if cond else 1] += 1
        print(f"{'INFO-OK' if cond else 'INFO-NO'} [{group}] {name}" + (f"  ({detail})" if detail else ""))
        sys.stdout.flush()
        return cond


def _find_vectors_dir():
    cands = []
    if _BUNDLE_VECTORS:
        cands.append(_BUNDLE_VECTORS)
    cands.append(DEFAULT_VECTORS_DIR)
    for c in cands:
        if os.path.isfile(os.path.join(c, "fiatShamirCodecVectors.json")):
            return c
    return None


def _flip(b: bytes, idx: int, mask: int) -> bytes:
    out = bytearray(b)
    out[idx] ^= mask
    return bytes(out)


def _replace(b: bytes, off: int, new: bytes) -> bytes:
    return b[:off] + new + b[off + len(new):]


# ---------------------------------------------------------------------------
# Known-answer pins (fixed literals).  D_gens and the 129 encodings were independently confirmed
# by py_ecc and the Java implementation (spec Appendix A).  The trace record is this script's own
# output for the fixed example, pinned so that any change to the transcript, codecs or nonce
# expansion fails the self-test; the coordinator re-confirms it with external code.
# ---------------------------------------------------------------------------

PIN_DST_BP_HEX = ("5a65726f4a2d62756c6c657470726f6f662d626c7331322d3338312d67312d67656e732d76312d"
                  "424c53313233383147315f584d443a5348412d3235365f535357555f524f5f")
PIN_D_GENS_HEX = "69abb9e71b740d9be84f63bb146a63467ee452654340f1b09e8be6101e00ef19"
PIN_G0_HEX = ("82ca0040fdcaae82d1dd666dbddaa09c3cd9546ab3a31150cd56385b167c7e0a"
              "c100305d0896a5615281c9aa8712190b")
PIN_H63_HEX = ("82c6faca133082265707f8e2422692c79663999e3e87b919dddccfd3a67c23dc"
               "ff5a5910bf58425b02deebcc56aa327b")
PIN_U_HEX = ("aaf94b4c700852ac8db3659ccfe7b0bbb7157c18ee881878fe1c2222b7eb31d7"
             "3943af9a7d1c341dd2a1eb49eec7696e")
GENERATORS_FILE = os.path.join(_HERE, "generators-v1.json")

PIN_TRACE = {
    "tag": "ZeroJ:bulletproof-range-bls12-381-g1-v1/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381/N016/A96S96.A96S48.A96S48.(A96S48)x4/CTX0005:68656c6c6f",
    "sessionIdHex": "aefa01ae578defec57e942213978543a2e26bdf81ae69ac9e95dd3bda9ec7556",
    "commitmentHex": (
        "8c64f7f6919d77f06e79c9520d3af99c6064884d1bc3e1d8b97b63f0d2841cce045ba9fb77e7080fb5c3dae5"
        "6624701e"),
    "instanceHex": (
        "18000000706564657273656e2d626c7331322d3338312d67312d763180453f5474382da080469962f6e656ba"
        "694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e92e04e91b89753df710400b2"
        "8abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab652000000062756c6c"
        "657470726f6f662d626c7331322d3338312d67312d67656e732d763169abb9e71b740d9be84f63bb146a6346"
        "7ee452654340f1b09e8be6101e00ef19100000008c64f7f6919d77f06e79c9520d3af99c6064884d1bc3e1d8"
        "b97b63f0d2841cce045ba9fb77e7080fb5c3dae56624701e"),
    "challenges": {
        "y": "36209000129655033253065255429180358080765337968981070404285725434891481435214",
        "z": "46633051618233588676975911499950183005061894917303926296959925736837968283823",
        "x": "47228359020218805564661947561577753834407574540194626925198606108420299900437",
        "xu": "22143072433137489460645211340386941818930014091100376110692679921738536006978",
        "xj": ["17735452590663590884174088837940452346824915976231644005372727082559053307244",
               "32939508233770058845369227004198000974479372739028121348871062643559301637578",
               "23879541988904653189122953040323391798477936798697311940928051176925699361449",
               "41826612228844513380365295144238554927794368972212012150612085629501841288776"],
    },
    "proofHex": (
        "adad082dfddd9ed67f1ac22ccc4969c702769d58ba89787a2926cf8c47e5d272f602f9b2fbe8d934cc861b9a"
        "4f537024a7f48ddec6a36c2841d0ca9705e00a7829d2fb4ab35489e38f78049d95b9a9ad26455a25459e89eb"
        "58209867c8fc27faac3886e6dc0a05715afebce3f4539b49577cea41e76a8ff61eeb21b859c25cf41da4407c"
        "1bf3d4ed2da0c1f1e4b4df18912af42a08f1601d89265c1aa4e349f615ed30d32b2a7d8863643ced634bb04e"
        "3236c966c3d5b39f7f0c9785e622b0046b3b50bcd8a594c77d878381f49008fe1142cafc9bc6e1c3c33df220"
        "f1f0fdf2419ccdb4dbaf404b0a61ba44304561bdf7fdc6fd325240b89fde47ad99a84b320d90f8d7c6219272"
        "5f2682f3bebf68f55e0b7662860dc9ace08538fe2af90f8887c36d60e42e7035d6a495baca385c9bb063eb63"
        "31588a5964c52ff5b0bdf2c05146f2aea07094ac66628ad1860215a682c2261fb17700d6ccfd2013a25519d0"
        "4a50fe394a95a6b805b4e473625f0d1fd61ba4019f0ef3b56e1764a76ba735ca84cddf30c5ec832e06b53c72"
        "4efc73144324b89cd08db9610a9dc7dccb99070df9e3ada009cab374ef6da4220a4f0372936a35b480afdd21"
        "2a13739342c19765c3e0beb723fa110839bf3185d75a17b25ceb98143b11d1d9efae7d9773eb3d53b1fa434e"
        "fd1be991dd8074d6b69ee86a7eba8732b72dd3802f6628588fbe5246aa8011e4963ce8ecbfde7cd3454dcddb"
        "95af1dbc6a5f62cd951b91673fead403b214e52d10a48689df063f06ccb062ffe409a3bd61f046457372920d"
        "4b57717aa48f892922c123bb2f0e85bbd0e970631e7091d664477011d78428d0475c8671bee756df4c160f59"
        "66d3a5b4652f1621994df89e6046c08781470de8e6a7a642ac8e4a72d3ca88c5e360c2020f2bb603540318bd"
        "e0a587efac7952d1b11f634f3079f728fb44f75f9aa11a0a287794e5ac374163b9be164487311f236a4649c1"
        "32c22f2a088521aa9c6305e07047ba0786d3e680d20c33ebf9e531bb6588f086"),
}



def selftest_conformance(res: _Results) -> None:
    vdir = _find_vectors_dir()
    if not res.check("conformance", "vector directory found", vdir is not None,
                     os.path.relpath(vdir, _HERE) if vdir else
                     f"not found at {DEFAULT_VECTORS_DIR}; pass --vectors-dir DIR"):
        return
    for fname, want in VECTOR_SHA256.items():
        path = os.path.join(vdir, fname)
        res.guard("conformance", f"{fname} SHA-256 == spec §10 pin",
                  lambda path=path, want=want: (lambda got: (got == want, got))(
                      hashlib.sha256(open(path, "rb").read()).hexdigest()))
    # fiat-shamir-03 B.1
    codec = json.load(open(os.path.join(vdir, "fiatShamirCodecVectors.json")))
    seen = set()
    for v in codec:
        nm = v["Name"]
        if nm in FS_CODEC_IN_SCOPE:
            res.guard("fs-codec", v["Id"], lambda v=v: (lambda r: (r[0], r[1][:80]))(run_fs_codec_vector(v)))
            seen.add(nm)
        elif nm in FS_CODEC_OUT_OF_SCOPE:
            print(f"SKIP [fs-codec] {v['Id']} (out of scope: {FS_CODEC_OUT_OF_SCOPE[nm]})")
        else:
            res.check("fs-codec", v["Id"], False, "unexpected vector")
    res.check("fs-codec", "all 9 in-scope codec vectors present", seen == FS_CODEC_IN_SCOPE,
              str(sorted(FS_CODEC_IN_SCOPE - seen)))
    # fiat-shamir-03 B.2
    shake = json.load(open(os.path.join(vdir, "fiatShamirShake128Vectors.json")))
    seen = set()
    for v in shake:
        nm = v["Name"]
        if nm in FS_SHAKE_IN_SCOPE:
            res.guard("fs-shake128", v["Id"], lambda v=v: (lambda r: (r[0], r[1][:64]))(run_fs_shake_vector(v)))
            seen.add(nm)
        elif nm in FS_SHAKE_OUT_OF_SCOPE:
            print(f"SKIP [fs-shake128] {v['Id']} (out of scope: {FS_SHAKE_OUT_OF_SCOPE[nm]})")
        else:
            res.check("fs-shake128", v["Id"], False, "unexpected vector")
    res.check("fs-shake128", "all 11 in-scope SHAKE128 vectors present", seen == FS_SHAKE_IN_SCOPE,
              str(sorted(FS_SHAKE_IN_SCOPE - seen)))

    def oneshot():
        sid = bytes(range(32))
        ds = DuplexSponge(sid)
        ds.absorb(b"abc")
        s1 = ds.squeeze(100) + ds.squeeze(200)
        ds.absorb(b"def")
        s2 = ds.squeeze(50)
        return (s1 == hashlib.shake_128(sid + bytes(136) + b"abc").digest(300)
                and s2 == hashlib.shake_128(sid + bytes(136) + b"abcdef").digest(50)), ""
    res.guard("fs-shake128", "duplex = XOF(session_id||zeros(136)||inputs) (stream + interleave)", oneshot)

    res.check("sigma-03", "G1 generator compress == sigma-03 §8.2.1 hex",
              C.compress(G1_GEN).hex() == "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f1"
                                          "71bac586c55e83ff97a1aeffb3af00adb22c6bb")
    global _SIGMA_CHALLENGE_OFFSET

    def sigma_outcome(tag, inst_b, narg, flavor):
        try:
            ok, layer, detail, ch = sigma_verify(tag, inst_b, narg, flavor)
            return ok, layer, detail
        except SigmaReject as e:
            return False, e.layer, e.detail

    # A.3.1 valid
    valid = json.load(open(os.path.join(vdir, "sigma-proofs_Shake128_BLS12381.json")))
    wanted = {f"sigma-protocols/bls12381/{r}/{f}" for r in ("discrete_logarithm", "pedersen_commitment")
              for f in ("batchable", "compact")}
    seen = set()
    for v in valid:
        tag = v["Tag"].encode("ascii")
        inst_b = bytes.fromhex(v["Instance"])
        narg = bytes.fromhex(v["NargString"])
        if v["Id"] not in wanted:
            # spec §10: the harness also verifies the other ten; reported, not gated
            try:
                ok = sigma_outcome(tag, inst_b, narg, v["Flavor"])[0] and \
                    derive_session_id(tag).hex() == v["SessionId"]
            except Exception as e:  # noqa: BLE001
                ok = False
            res.report("sigma-valid-extra", v["Id"] + " SessionId + verifies", ok)
            continue
        seen.add(v["Id"])
        vid = v["Id"]
        res.guard("sigma-valid", vid + " SessionId from Tag",
                  lambda tag=tag, v=v: (lambda sid: (sid == v["SessionId"], sid))(derive_session_id(tag).hex()))
        res.guard("sigma-valid", vid + " verifies (challenge re-derived from tag, instance, commitment)",
                  lambda: (lambda r: (r[0] and v["Expected"] == "accept", r[1]))(
                      sigma_outcome(tag, inst_b, narg, v["Flavor"])))

        def under_offset():
            global _SIGMA_CHALLENGE_OFFSET
            _SIGMA_CHALLENGE_OFFSET = 1
            try:
                r = sigma_outcome(tag, inst_b, narg, v["Flavor"])
            finally:
                _SIGMA_CHALLENGE_OFFSET = 0
            return (not r[0] and r[1] == "verification"), r[1]
        res.guard("sigma-valid", vid + " fails when the derived challenge is +1 (challenge is bound)",
                  under_offset)

        def tampered_response():
            inst = parse_linear_relation(inst_b)
            off = NE * len(inst.equations) if v["Flavor"] == "batchable" else NS
            r0 = OS2IP(narg[off:off + NS])
            bad = narg[:off] + scalar_serialize((r0 + 1) % Q) + narg[off + NS:]
            r = sigma_outcome(tag, inst_b, bad, v["Flavor"])
            return (not r[0] and r[1] == "verification"), r[1]
        res.guard("sigma-valid", vid + " fails with response[0] + 1", tampered_response)

        def witness_ok():
            inst = parse_linear_relation(inst_b)
            wb = bytes.fromhex(v["Witness"])
            wit = [OS2IP(wb[i:i + NS]) for i in range(0, len(wb), NS)]
            return all(jeq(m, i) for m, i in zip(sigma_map(inst, wit), sigma_image(inst))), ""
        res.guard("sigma-valid", vid + " published witness satisfies instance", witness_ok)
    res.check("sigma-valid", "all 4 in-scope valid vectors present", seen == wanted)

    # A.3.2 adversarial: expected outcome and layer for every class
    adv = json.load(open(os.path.join(vdir, "sigma-proofs-invalid_Shake128_BLS12381.json")))
    res.check("sigma-invalid", "32 adversarial vectors in file", len(adv) == 32, str(len(adv)))
    controls = {"batchable/F1", "compact/F1", "batchable/F2", "compact/F2"}

    def expected_for(short):
        letter = short.split("/")[1][0]
        if short in controls:
            return "accept", "accept", None
        return {"A": ("reject", "deserialize-point", 0), "B": ("reject", "deserialize-scalar", 0),
                "C": ("reject", "length", 0), "D": ("reject", "simulated-commitment-identity", 0),
                "E": ("reject", "instance-validation", 0), "F": ("reject", "verification", 1),
                "H": ("reject", "verification", 1)}[letter]
    tally = {"accept": 0, "reject": 0}
    for v in adv:
        short = v["Id"].split("/", 3)[3]

        def one(v=v, short=short):
            global _SIGMA_CHALLENGES_DERIVED
            want_out, want_layer, want_derived = expected_for(short)
            before = _SIGMA_CHALLENGES_DERIVED
            ok, layer, detail = sigma_outcome(v["Tag"].encode("ascii"), bytes.fromhex(v["Instance"]),
                                              bytes.fromhex(v["NargString"]), v["Flavor"])
            derived = _SIGMA_CHALLENGES_DERIVED - before
            out = "accept" if ok else "reject"
            tally[out] += 1
            good = (out == v["Expected"] == want_out and layer == want_layer
                    and (want_derived is None or derived == want_derived))
            return good, f"{out} at {layer} (want {want_out} at {want_layer}); challenges derived={derived}"
        res.guard("sigma-invalid", f"{short:<14}", one)
    res.check("sigma-invalid", "28 rejected / 4 accepted", tally == {"accept": 4, "reject": 28}, str(tally))
    for v in adv:
        short = v["Id"].split("/", 3)[3]
        narg = bytes.fromhex(v["NargString"])
        if short[short.index("/") + 1] not in "AB":
            continue

        def direct(short=short, narg=narg):
            try:
                if short.endswith(("A1", "A3", "A4", "A5", "A6")):
                    g1_deserialize(narg[:48])
                elif short == "batchable/B1":
                    scalar_deserialize(narg[48:80])
                else:
                    scalar_deserialize(narg[:32])
                return False, "accepted"
            except BulletproofError as e:
                want = "NON_CANONICAL_SCALAR" if "/B" in short else e.error_class
                return e.error_class == want, e.error_class
        res.guard("sigma-invalid", f"{short} rejected directly by the §3 decoder", direct)


def selftest_generators(res: _Results) -> None:
    res.check("generators", "DST_BP bytes == pinned hex (70 octets)",
              DST_BP.hex() == PIN_DST_BP_HEX and len(DST_BP) == 70, DST_BP.hex()[:24] + "...")
    try:
        gens = generators()
        ok, info = True, ""
    except Exception as e:  # noqa: BLE001
        ok, info = False, f"{type(e).__name__}: {e}"
    res.check("generators", "derivation + §2.2 checks (131 points: none O, pairwise != +-)", ok, info)
    if not ok:
        return
    allpts = gens.Gvec + gens.Hvec + [gens.U, gens.G, gens.H]

    def brute():
        bad = sum(1 for i in range(len(allpts)) for j in range(i + 1, len(allpts))
                  if allpts[i] == allpts[j] or allpts[i] == C.point_neg(allpts[j]))
        return bad == 0, f"{bad} bad pairs"
    res.guard("generators", "pairwise P != Q and P != -Q (brute force, 8515 pairs)", brute)
    res.guard("generators", "every generator on the curve and in G1 ([q]P = O)",
              lambda: (all(C.on_curve_e(p) and C.in_subgroup(p) for p in allpts), ""))
    res.guard("generators", "every encoding strict-decodes back to its point",
              lambda: (all(g1_deserialize(e) == p for e, p in
                           zip(gens.encodings, gens.Gvec + gens.Hvec + [gens.U])), ""))
    res.guard("generators", "profile G, H pinned (pedersen §2.2) == RFC 9380 recomputation",
              lambda: (lambda gh: (gh[0] == gens.G and gh[1] == gens.H
                                   and C.compress(gh[0]).hex() == PINNED_G_HEX
                                   and C.compress(gh[1]).hex() == PINNED_H_HEX, ""))(C.derive_basis()))
    res.guard("generators", "G_5 message is 47 00 00 00 05",
              lambda: (gens.Gvec[5] == C.hash_to_curve(bytes.fromhex("4700000005"), DST_BP), ""))
    res.check("generators", "D_gens == pinned literal (Appendix A)",
              gens.digest.hex() == PIN_D_GENS_HEX, gens.digest.hex())
    res.check("generators", "G_0, H_63, U == pinned literals",
              gens.encodings[0].hex() == PIN_G0_HEX and gens.encodings[127].hex() == PIN_H63_HEX
              and gens.encodings[128].hex() == PIN_U_HEX)

    def vs_file():
        d = json.load(open(GENERATORS_FILE))
        enc = [g["compressedHex"] for g in d["generators"]]
        names = [g["name"] for g in d["generators"]]
        want_names = [f"G_{i}" for i in range(64)] + [f"H_{i}" for i in range(64)] + ["U"]
        mism = [i for i in range(129) if i >= len(enc) or enc[i] != gens.encodings[i].hex()]
        good = (len(enc) == 129 and names == want_names and not mism and d["D_gens"] == PIN_D_GENS_HEX
                and d["DSTHex"] == PIN_DST_BP_HEX
                and hashlib.sha256(b"".join(bytes.fromhex(e) for e in enc)).hexdigest() == PIN_D_GENS_HEX)
        return good, f"mismatches at {mism[:5]}" if mism else "129/129 match"
    res.guard("generators", "all 129 encodings == generators-v1.json (and its digest == pin)", vs_file)

    def arith():
        rnd = [3, 12345, Q - 1, Q - 2, (1 << 200) + 17, OS2IP(hashlib.sha256(b"k").digest()) % Q]
        for p in (G1_GEN, gens.G, gens.U):
            for kk in rnd:
                if to_affine(jmul(to_jac(p), kk)) != C.scalar_mul(kk, p):
                    return False, "jmul"
            if to_affine(jadd(to_jac(p), to_jac(p))) != C.point_add(p, p):
                return False, "dbl"
            if to_affine(jadd(to_jac(p), to_jac(gens.H))) != C.point_add(p, gens.H):
                return False, "add"
            if not is_inf(jadd(to_jac(p), jneg(to_jac(p)))):
                return False, "neg"
        return True, ""
    res.guard("generators", "Jacobian arithmetic == curve module affine arithmetic", arith)


def selftest_transcript_shapes(res: _Results) -> None:
    ex = ("ZeroJ:bulletproof-range-bls12-381-g1-v1/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381"
          "/N016/A96S96.A96S48.A96S48.(A96S48)x4/CTX0005:68656c6c6f")
    res.check("transcript", "§5.1 example tag reproduced (no trailing .A64)",
              session_tag(16, b"hello").decode() == ex)
    res.check("transcript", "1-octet ctx tag ends with /CTX0001:00",
              session_tag(64, b"\x00").endswith(b"/N064/A96S96.A96S48.A96S48.(A96S48)x6/CTX0001:00"))
    inst = encode_instance(16, g1_serialize(generators().G))
    res.check("transcript", "instance length 4+24+96+4+32+32+4+48 = 244", len(inst) == 244, str(len(inst)))
    for n, ln in ((16, 736), (32, 832), (64, 928)):
        res.check("transcript", f"proof_length({n}) == {ln}", proof_length(n) == ln)


def selftest_known_answer(res: _Results) -> None:
    """The fixed --print-trace example against pinned literals."""
    try:
        proof, trace = _prove_with_test_nonces(TRACE_VALUE, TRACE_BLINDING, 16, TRACE_CTX, TRACE_SEED)
    except Exception as e:  # noqa: BLE001
        res.check("known-answer", "trace prover runs", False, f"{type(e).__name__}: {e}")
        return
    ch = _challenge_dict(trace["challenges"], 4)
    res.check("known-answer", "tag == pin", trace["tag"].decode() == PIN_TRACE["tag"])
    res.check("known-answer", "sessionIdHex == pin", trace["sessionId"].hex() == PIN_TRACE["sessionIdHex"],
              trace["sessionId"].hex())
    res.check("known-answer", "commitmentHex == pin", trace["commitment"].hex() == PIN_TRACE["commitmentHex"])
    res.check("known-answer", "instanceHex == pin", trace["instance"].hex() == PIN_TRACE["instanceHex"])
    for name in ("y", "z", "x", "xu"):
        res.check("known-answer", f"challenge {name} == pin", ch[name] == PIN_TRACE["challenges"][name], ch[name])
    for j in range(4):
        res.check("known-answer", f"challenge x_{j + 1} == pin",
                  ch["xj"][j] == PIN_TRACE["challenges"]["xj"][j], ch["xj"][j])
    res.check("known-answer", "proofHex == pin", proof.hex() == PIN_TRACE["proofHex"])
    res.guard("known-answer", "pinned proof verifies against pinned commitment",
              lambda: (lambda d: (d["verdict"] and _challenge_dict(d["challenges"], 4) == PIN_TRACE["challenges"],
                                  d["layer"]))(
                  verify_detailed(bytes.fromhex(PIN_TRACE["commitmentHex"]), bytes.fromhex(PIN_TRACE["proofHex"]),
                                  16, TRACE_CTX)))


def selftest_roundtrips(res: _Results) -> None:
    for n in BITS:
        cases = [("v=0 nonzero blinding", 0, 7777777),
                 ("v=1", 1, 98765),
                 ("v=2^n-1", (1 << n) - 1, Q - 3),
                 ("v=random", secrets.randbelow(1 << n), secrets.randbelow(Q - 1) + 1)]
        ctx = b"ctx-" + bytes([n])
        for label, v, gamma in cases:
            seed = hashlib.sha256(b"selftest-seed" + label.encode() + bytes([n])).digest()

            def rt(v=v, gamma=gamma, seed=seed, label=label):
                proof, trace = _prove_with_test_nonces(v, gamma, n, ctx, seed)
                det = verify_detailed(trace["commitment"], proof, n, ctx)
                ok = (len(proof) == proof_length(n) and det["verdict"]
                      and det["challenges"] == trace["challenges"] and det["sessionId"] == trace["sessionId"])
                if label in ("v=0 nonzero blinding", "v=random"):
                    ok = ok and _prove_with_test_nonces(v, gamma, n, ctx, seed)[0] == proof
                if label == "v=random":
                    ok = ok and _verify_ipa_recursive(trace["commitment"], proof, n, ctx)
                return ok, f"len={len(proof)} layer={det['layer']}"
            res.guard("roundtrip", f"n={n} {label} (v={v}) test nonces: verifies, challenges reproduced"
                      + ("; deterministic" if label in ("v=0 nonzero blinding", "v=random") else "")
                      + ("; recursive IPA agrees" if label == "v=random" else ""), rt)

        def csprng():
            v = secrets.randbelow(1 << n)
            vb, proof = prove(v, secrets.randbelow(Q - 1) + 1, n, b"csprng")
            return (verify(vb, proof, n, b"csprng") and len(proof) == proof_length(n)
                    and verify(g1_decode_profile(vb), proof, n, b"csprng")), f"v={v}"
        res.guard("roundtrip", f"n={n} CSPRNG prover; V as octets and as validated decoded point", csprng)

    def boundary(ctx, seed):
        proof, trace = _prove_with_test_nonces(5, 6, 16, ctx, seed)
        return verify(trace["commitment"], proof, 16, ctx), ""
    res.guard("roundtrip", "ctx of exactly 1024 octets accepted", lambda: boundary(bytes(1024), bytes(32)))
    res.guard("roundtrip", "ctx of exactly 1 octet accepted", lambda: boundary(b"\x00", bytes([7]) * 32))
    res.guard("roundtrip", "different seeds -> different proofs",
              lambda: (_prove_with_test_nonces(5, 6, 16, b"seeds", bytes(32))[0]
                       != _prove_with_test_nonces(5, 6, 16, b"seeds", bytes(31) + b"\x01")[0], ""))


def selftest_refusals(res: _Results) -> None:
    def refusal(label, fn, expected):
        try:
            fn()
            got = "no error"
        except BulletproofError as e:
            got = e.error_class
        except Exception as e:  # noqa: BLE001
            got = type(e).__name__
        res.check("prover-refusal", label, got == expected, got)

    for n in BITS:
        refusal(f"n={n} v = 2^n", lambda n=n: prove(1 << n, 5, n, b"app"), "OUT_OF_RANGE")
        refusal(f"n={n} v = q-1", lambda n=n: prove(Q - 1, 5, n, b"app"), "OUT_OF_RANGE")
    refusal("v = q", lambda: prove(Q, 5, 16, b"app"), "NON_CANONICAL_SCALAR")
    refusal("v = -1", lambda: prove(-1, 5, 16, b"app"), "NON_CANONICAL_SCALAR")
    refusal("gamma = q", lambda: prove(3, Q, 16, b"app"), "NON_CANONICAL_SCALAR")
    refusal("gamma = -1", lambda: prove(3, -1, 16, b"app"), "NON_CANONICAL_SCALAR")
    refusal("(0, 0) opens the identity", lambda: prove(0, 0, 16, b"app"), "INVALID_STATEMENT")
    for bad_n in (0, 8, 17, 128, -16, 63):
        refusal(f"bad n = {bad_n}", lambda bad_n=bad_n: prove(1, 1, bad_n, b"app"), "INVALID_CONFIGURATION")
    refusal("ctx of 1025 octets", lambda: prove(1, 1, 16, bytes(1025)), "INVALID_CONFIGURATION")
    refusal("empty ctx", lambda: prove(1, 1, 16, b""), "INVALID_CONFIGURATION")
    refusal("test-nonce prover empty ctx", lambda: _prove_with_test_nonces(1, 1, 16, b"", bytes(32)),
            "INVALID_CONFIGURATION")
    # wrong argument types are API-binding errors (spec §11), not vector cases
    refusal("API binding: v = True (bool) -> TypeError", lambda: prove(True, 5, 16, b"app"), "TypeError")
    refusal("API binding: n = '16' (str) -> TypeError", lambda: prove(1, 1, "16", b"app"), "TypeError")
    refusal("API binding: ctx = 'app' (str) -> TypeError", lambda: prove(1, 1, 16, "app"), "TypeError")
    # order: configuration, then check 1, then range, then INVALID_STATEMENT
    refusal("order: empty ctx and v = q -> configuration first", lambda: prove(Q, 1, 16, b""),
            "INVALID_CONFIGURATION")
    refusal("order: bad n and v = q -> configuration first", lambda: prove(Q, 1, 8, b"app"),
            "INVALID_CONFIGURATION")
    refusal("order: v = q and gamma = q -> NON_CANONICAL", lambda: prove(Q, Q, 16, b"app"),
            "NON_CANONICAL_SCALAR")
    refusal("order: v = 2^16 and gamma = q -> NON_CANONICAL first", lambda: prove(1 << 16, Q, 16, b"app"),
            "NON_CANONICAL_SCALAR")
    refusal("order: (0,0) with ctx 1025 -> configuration first", lambda: prove(0, 0, 16, bytes(1025)),
            "INVALID_CONFIGURATION")
    refusal("test-nonce prover v = 2^16", lambda: _prove_with_test_nonces(1 << 16, 1, 16, b"app", bytes(32)),
            "OUT_OF_RANGE")

    # §7.1: the refusals happen before any curve work
    def no_curve_work():
        global jmul
        calls = {"n": 0}
        real = jmul

        def counting(pj, k):
            calls["n"] += 1
            return real(pj, k)
        jmul = counting
        try:
            for fn in (lambda: prove(1, 1, 8, b"app"), lambda: prove(Q, 1, 16, b"app"),
                       lambda: prove(1 << 16, 1, 16, b"app")):
                try:
                    fn()
                except BulletproofError:
                    pass
        finally:
            jmul = real
        return calls["n"] == 0, f"{calls['n']} scalar multiplications"
    res.guard("prover-refusal", "configuration/check-1/range refusals do no curve work", no_curve_work)


def selftest_verifier_negatives(res: _Results) -> None:
    global _CHALLENGE_HOOK, _S_BIT_ORDER
    n, ctx = 16, b"negatives"
    k = LOG2[n]
    v, gamma = 40000, 31337
    proof, trace = _prove_with_test_nonces(v, gamma, n, ctx, bytes(range(32)))
    Vb = trace["commitment"]
    res.guard("verifier-neg", "baseline accepts", lambda: (classify(Vb, proof, n, ctx) == ("true", "accept"), ""))

    def expect(label, thunk, allowed, layer=None, group="verifier-neg"):
        def run():
            got = thunk()
            good = got[0] in allowed and got[0] != "true" and (layer is None or got[1] == layer)
            return good, f"{got[0]} at {got[1]}"
        res.guard(group, label, run)

    names = ["A", "S", "T1", "T2"] + [f"{p}_{j}" for j in range(1, k + 1) for p in ("L", "R")]
    poffs = _point_offsets(n)
    snames = ["t_hat", "tau_x", "mu", "a", "b"]
    soffs = _scalar_offsets(n)
    other_pt = g1_serialize(G1_GEN)
    REJ = {"false", "MALFORMED_ENCODING", "NOT_IN_SUBGROUP", "NON_CANONICAL_SCALAR"}
    for nm, off in zip(names, poffs):
        expect(f"substitute {nm} by another valid point",
               lambda off=off: classify(Vb, _replace(proof, off, other_pt), n, ctx), {"false"})
    for nm, off in zip(snames, soffs):
        expect(f"substitute {nm} by {nm}+1",
               lambda off=off: classify(Vb, _replace(proof, off, scalar_serialize(
                   (OS2IP(proof[off:off + 32]) + 1) % Q)), n, ctx), {"false"})
    for nm, off in zip(names, poffs):
        expect(f"flip compression bit of {nm}", lambda off=off: classify(Vb, _flip(proof, off, 0x80), n, ctx),
               {"MALFORMED_ENCODING"}, "point")
        expect(f"flip infinity bit of {nm}", lambda off=off: classify(Vb, _flip(proof, off, 0x40), n, ctx),
               {"MALFORMED_ENCODING"}, "point")
        expect(f"flip sort bit of {nm} (-P)", lambda off=off: classify(Vb, _flip(proof, off, 0x20), n, ctx),
               {"false"})
        expect(f"flip x LSB of {nm}", lambda off=off: classify(Vb, _flip(proof, off + 47, 0x01), n, ctx), REJ)
        expect(f"flip x middle bit of {nm}", lambda off=off: classify(Vb, _flip(proof, off + 24, 0x10), n, ctx),
               REJ)
    for nm, off in zip(snames, soffs):
        expect(f"flip top bit of {nm} (>= q)", lambda off=off: classify(Vb, _flip(proof, off, 0x80), n, ctx),
               {"NON_CANONICAL_SCALAR"}, "scalar")
        expect(f"flip LSB of {nm}", lambda off=off: classify(Vb, _flip(proof, off + 31, 0x01), n, ctx), {"false"})
    expect("truncated by one octet", lambda: classify(Vb, proof[:-1], n, ctx), {"MALFORMED_ENCODING"}, "length")
    expect("extended by one octet", lambda: classify(Vb, proof + b"\x00", n, ctx), {"MALFORMED_ENCODING"}, "length")
    expect("empty proof", lambda: classify(Vb, b"", n, ctx), {"MALFORMED_ENCODING"}, "length")
    expect("proof of n=32 length under n=16", lambda: classify(Vb, proof + bytes(96), n, ctx),
           {"MALFORMED_ENCODING"}, "length")
    for nm, off in (("A", poffs[0]), ("T2", poffs[3]), ("R_4", poffs[-1])):
        expect(f"identity encoding as {nm}",
               lambda off=off: classify(Vb, _replace(proof, off, C.IDENTITY_ENCODING), n, ctx),
               {"MALFORMED_ENCODING"}, "point")
    expect("order-3 point (0x80||0^47) as S",
           lambda: classify(Vb, _replace(proof, poffs[1], b"\x80" + bytes(47)), n, ctx), {"NOT_IN_SUBGROUP"}, "point")
    expect("x = P_381 as L_1",
           lambda: classify(Vb, _replace(proof, poffs[4], bytes([0x80 | (P_381 >> 376)]) + I2OSP(P_381, 48)[1:]),
                            n, ctx), {"MALFORMED_ENCODING"}, "point")
    for nm, off in zip(snames, soffs):
        expect(f"non-canonical {nm} + q",
               lambda off=off: classify(Vb, _replace(proof, off, I2OSP(OS2IP(proof[off:off + 32]) + Q, 32)), n, ctx),
               {"NON_CANONICAL_SCALAR"}, "scalar")
    expect("verified under n = 32", lambda: classify(Vb, proof, 32, ctx), {"MALFORMED_ENCODING"}, "length")
    expect("verified under n = 64", lambda: classify(Vb, proof, 64, ctx), {"MALFORMED_ENCODING"}, "length")
    expect("verified under a different ctx", lambda: classify(Vb, proof, n, ctx + b"!"), {"false"})
    expect("verified under a 1-octet prefix of ctx", lambda: classify(Vb, proof, n, ctx[:1]), {"false"})
    expect("verified under empty ctx", lambda: classify(Vb, proof, n, b""), {"INVALID_CONFIGURATION"},
           "configuration")
    expect("empty ctx + identity V", lambda: classify(C.IDENTITY_ENCODING, proof, n, b""),
           {"INVALID_CONFIGURATION"}, "configuration")
    expect("verified against a different V (v+1)",
           lambda: classify(g1_serialize(to_affine(commit(v + 1, gamma))), proof, n, ctx), {"false"})
    expect("verified against -V", lambda: classify(_flip(Vb, 0, 0x20), proof, n, ctx), {"false"})
    expect("V = identity octets -> false at statement", lambda: classify(C.IDENTITY_ENCODING, proof, n, ctx),
           {"false"}, "statement")
    expect("V = O (decoded None) -> false at statement", lambda: classify(None, proof, n, ctx), {"false"}, "statement")
    expect("V octets outside subgroup -> NOT_IN_SUBGROUP", lambda: classify(b"\x80" + bytes(47), proof, n, ctx),
           {"NOT_IN_SUBGROUP"}, "statement")
    expect("V of 47 octets -> MALFORMED_ENCODING", lambda: classify(Vb[:47], proof, n, ctx),
           {"MALFORMED_ENCODING"}, "statement")
    expect("n = 8 -> INVALID_CONFIGURATION", lambda: classify(Vb, proof, 8, ctx), {"INVALID_CONFIGURATION"},
           "configuration")
    expect("ctx 1025 -> INVALID_CONFIGURATION", lambda: classify(Vb, proof, n, bytes(1025)),
           {"INVALID_CONFIGURATION"}, "configuration")
    lr = proof[288:288 + 96]
    expect("L_1 and R_1 swapped", lambda: classify(Vb, _replace(proof, 288, lr[48:] + lr[:48]), n, ctx), {"false"})

    # §8.1 step 4: a decoded V is not trusted.  Regression: V' = [7]G + [11]H + (0, 2), where (0, 2)
    # has order 3, has no Pedersen opening; it must be NOT_IN_SUBGROUP, never true/false via check 1.
    order3 = (0, 2)
    v_mixed = C.point_add(to_affine(commit(7, 11)), order3)

    def mixed_decoded():
        assert C.on_curve_e(v_mixed) and not C.in_subgroup(v_mixed)
        got = classify(v_mixed, proof, n, ctx)
        return got == ("NOT_IN_SUBGROUP", "statement"), f"{got}"
    res.guard("verifier-neg", "regression: decoded V' = [7]G+[11]H+(0,2) -> NOT_IN_SUBGROUP", mixed_decoded)
    expect("V' = [7]G+[11]H+(0,2) as octets -> NOT_IN_SUBGROUP",
           lambda: classify(C.compress(v_mixed), proof, n, ctx), {"NOT_IN_SUBGROUP"}, "statement")
    expect("decoded V = order-3 point (0,2) -> NOT_IN_SUBGROUP", lambda: classify(order3, proof, n, ctx),
           {"NOT_IN_SUBGROUP"}, "statement")
    expect("decoded V off the curve -> MALFORMED_ENCODING", lambda: classify((1, 1), proof, n, ctx),
           {"MALFORMED_ENCODING"}, "statement")

    def mixed_proof():
        # a proof for the subgroup part [7]G + [11]H, offered against V' (both ways in)
        p7, t7 = _prove_with_test_nonces(7, 11, n, ctx, bytes([9]) * 32)
        a = classify(v_mixed, p7, n, ctx)
        b = classify(C.compress(v_mixed), p7, n, ctx)
        return a == b == ("NOT_IN_SUBGROUP", "statement") and verify(t7["commitment"], p7, n, ctx), f"{a} / {b}"
    res.guard("verifier-neg", "honest proof for [7]G+[11]H offered against V' -> NOT_IN_SUBGROUP", mixed_proof)

    # decoding order (§8.1): configuration, length, proof fields in order, V, V = O
    og = "verifier-order"
    expect("bad n + bad ctx -> INVALID_CONFIGURATION", lambda: classify(Vb, proof, 8, bytes(1025)),
           {"INVALID_CONFIGURATION"}, "configuration", og)
    expect("bad n + bad V -> INVALID_CONFIGURATION", lambda: classify(b"\x80" + bytes(47), proof, 8, ctx),
           {"INVALID_CONFIGURATION"}, "configuration", og)
    expect("bad V + bad length -> length class (length before V)", lambda: classify(Vb[:47], proof[:-1], n, ctx),
           {"MALFORMED_ENCODING"}, "length", og)
    expect("non-subgroup V + identity A -> MALFORMED_ENCODING at point (fields before V)",
           lambda: classify(b"\x80" + bytes(47), _replace(proof, poffs[0], C.IDENTITY_ENCODING), n, ctx),
           {"MALFORMED_ENCODING"}, "point", og)
    expect("47-octet V + non-canonical b -> NON_CANONICAL_SCALAR (fields before V)",
           lambda: classify(Vb[:47], _flip(proof, soffs[4], 0x80), n, ctx), {"NON_CANONICAL_SCALAR"}, "scalar", og)
    expect("decoded non-subgroup V + bad length -> length class",
           lambda: classify(v_mixed, proof[:-1], n, ctx), {"MALFORMED_ENCODING"}, "length", og)
    expect("non-subgroup V + well-formed proof -> NOT_IN_SUBGROUP at statement",
           lambda: classify(b"\x80" + bytes(47), proof, n, ctx), {"NOT_IN_SUBGROUP"}, "statement", og)
    expect("V = O + bad length -> MALFORMED_ENCODING at length", lambda: classify(C.IDENTITY_ENCODING, proof[:-1], n, ctx),
           {"MALFORMED_ENCODING"}, "length", og)
    expect("V = O + identity A -> MALFORMED_ENCODING at point",
           lambda: classify(C.IDENTITY_ENCODING, _replace(proof, poffs[0], C.IDENTITY_ENCODING), n, ctx),
           {"MALFORMED_ENCODING"}, "point", og)
    expect("V = O + non-canonical b -> NON_CANONICAL_SCALAR",
           lambda: classify(C.IDENTITY_ENCODING, _flip(proof, soffs[4], 0x80), n, ctx),
           {"NON_CANONICAL_SCALAR"}, "scalar", og)
    expect("V = O + well-formed proof -> false at statement (step 5 last)",
           lambda: classify(C.IDENTITY_ENCODING, proof, n, ctx), {"false"}, "statement", og)
    expect("bad t_hat (offset 192) + identity R_4 (later) -> NON_CANONICAL_SCALAR",
           lambda: classify(Vb, _replace(_flip(proof, soffs[0], 0x80), poffs[-1], C.IDENTITY_ENCODING), n, ctx),
           {"NON_CANONICAL_SCALAR"}, "scalar", og)
    expect("identity S + bad mu (later) -> MALFORMED_ENCODING at point",
           lambda: classify(Vb, _replace(_flip(proof, soffs[2], 0x80), poffs[1], C.IDENTITY_ENCODING), n, ctx),
           {"MALFORMED_ENCODING"}, "point", og)
    expect("non-subgroup R_4 + bad a (later) -> NOT_IN_SUBGROUP at point",
           lambda: classify(Vb, _replace(_flip(proof, soffs[3], 0x80), poffs[-1], b"\x80" + bytes(47)), n, ctx),
           {"NOT_IN_SUBGROUP"}, "point", og)
    expect("non-subgroup S before identity T2 -> NOT_IN_SUBGROUP at point",
           lambda: classify(Vb, _replace(_replace(proof, poffs[1], b"\x80" + bytes(47)), poffs[3],
                                         C.IDENTITY_ENCODING), n, ctx), {"NOT_IN_SUBGROUP"}, "point", og)

    # zero challenges via the seam
    for cname in ["y", "z", "x", "xu"] + [f"x_{j}" for j in range(1, k + 1)]:
        def zero(cname=cname):
            global _CHALLENGE_HOOK
            _CHALLENGE_HOOK = lambda nm, val: 0 if nm == cname else val  # noqa: E731
            try:
                r = classify(Vb, proof, n, ctx)
                try:
                    _prove_with_test_nonces(v, gamma, n, ctx, bytes(range(32)))
                    pr = "no failure"
                except TestNonceProverFailure:
                    pr = "TestNonceProverFailure"
            finally:
                _CHALLENGE_HOOK = None
            return r == ("false", "challenge") and pr == "TestNonceProverFailure", f"{r} / {pr}"
        res.guard("verifier-neg", f"challenge {cname} forced to 0 -> false at challenge; test prover fails closed",
                  zero)

    def restart_once():
        global _CHALLENGE_HOOK
        state = {"hits": 0}

        def hook(nm, val):
            if nm == "x" and state["hits"] == 0:
                state["hits"] += 1
                return 0
            return val
        _CHALLENGE_HOOK = hook
        try:
            vb2, pr2 = prove(9, 10, 16, b"restart")
        finally:
            _CHALLENGE_HOOK = None
        return state["hits"] == 1 and verify(vb2, pr2, 16, b"restart"), ""
    res.guard("verifier-neg", "CSPRNG prover restarts after a zero challenge", restart_once)

    def restart_bound():
        global _CHALLENGE_HOOK
        state = {"attempts": 0}

        def hook(nm, val):
            if nm == "x":
                state["attempts"] += 1
                return 0
            return val
        _CHALLENGE_HOOK = hook
        try:
            try:
                prove(9, 10, 16, b"restart")
                got = "proof emitted"
            except ProverRestartsExhausted:
                got = "ProverRestartsExhausted"
        finally:
            _CHALLENGE_HOOK = None
        return got == "ProverRestartsExhausted" and state["attempts"] == 8, f"{got} after {state['attempts']} attempts"
    res.guard("verifier-neg", "§7.3 restarts bounded at 8 attempts, then raise (no proof)", restart_bound)

    def cheat1():
        V_cheat = commit(1 << n, gamma)
        proof_c, _ = _prove_core(1 << n, gamma, n, ctx, V_cheat, _test_nonces(n, bytes(32)))
        det = verify_detailed(g1_serialize(to_affine(V_cheat)), proof_c, n, ctx)
        return not det["verdict"] and not det["check1"] and det["check2"], str((det["check1"], det["check2"]))
    res.guard("verifier-neg", "cheating prover v = 2^n: check 1 fails, check 2 holds (both evaluated)", cheat1)

    def cheat2():
        a_bad = [(v >> i) & 1 for i in range(n)]
        a_bad[0] += 2
        V_c2 = commit(v + 2, gamma)
        proof_c2, _ = _prove_core(v + 2, gamma, n, ctx, V_c2, _test_nonces(n, bytes(32)), a_l_override=a_bad)
        det = verify_detailed(g1_serialize(to_affine(V_c2)), proof_c2, n, ctx)
        return not det["verdict"] and not det["check1"] and det["layer"] == "check1", str((det["check1"], det["check2"]))
    res.guard("verifier-neg", "cheating prover with a non-bit a_L entry: rejected, layer check1", cheat2)
    a_off = soffs[3]
    tampered = _replace(proof, a_off, scalar_serialize((OS2IP(proof[a_off:a_off + 32]) + 1) % Q))
    res.guard("verifier-neg", "a + 1 (no later challenge): check 1 holds, check 2 fails, layer check2",
              lambda: (lambda d: (d["check1"] and not d["check2"] and d["layer"] == "check2",
                                  str((d["check1"], d["check2"]))))(verify_detailed(Vb, tampered, n, ctx)))
    res.guard("verifier-neg", "both checks evaluated when check 1 fails (substituted A)",
              lambda: (lambda d: ("check1" in d and "check2" in d and d["layer"] == "check1",
                                  str((d.get("check1"), d.get("check2")))))(
                  verify_detailed(Vb, _replace(proof, poffs[0], other_pt), n, ctx)))
    res.guard("verifier-neg", "recursive IPA verifier rejects a + 1 and accepts the baseline",
              lambda: (not _verify_ipa_recursive(Vb, tampered, n, ctx) and _verify_ipa_recursive(Vb, proof, n, ctx), ""))

    def lsb_mutant():
        global _S_BIT_ORDER
        _S_BIT_ORDER = "lsb"
        try:
            det = verify_detailed(Vb, proof, n, ctx)
        finally:
            _S_BIT_ORDER = "msb"
        return det["check1"] and not det["check2"], str((det["check1"], det["check2"]))
    res.guard("verifier-neg", "mutant LSB-first s_i rule rejects the honest proof at check 2", lsb_mutant)


def _challenges_of(V_bytes: bytes, proof: bytes, n: int, ctx: bytes) -> dict:
    """Recompute the §5.3 challenges from proof bytes without decoding (test helper)."""
    k = LOG2[n]
    tr = _Transcript(n, ctx, V_bytes)
    tr.absorb(proof[0:96])
    tr.challenge("y")
    tr.challenge("z")
    tr.absorb(proof[96:192])
    tr.challenge("x")
    tr.absorb(proof[192:288])
    tr.challenge("xu")
    for j in range(k):
        tr.absorb(proof[288 + 96 * j:288 + 96 * (j + 1)])
        tr.challenge(f"x_{j + 1}")
    return tr.challenges


def selftest_transcript_mutants(res: _Results) -> None:
    n, ctx = 16, b"mutants"
    v, gamma = 4242, 777
    proof, trace = _prove_with_test_nonces(v, gamma, n, ctx, bytes(range(32)))
    Vb = trace["commitment"]
    base = verify_detailed(Vb, proof, n, ctx)
    for mut in ("drop_V", "drop_ctx", "drop_Dgens", "drop_n", "swap_GH"):
        def run(mut=mut):
            global _TRANSCRIPT_MUTATION
            _TRANSCRIPT_MUTATION = mut
            try:
                det = verify_detailed(Vb, proof, n, ctx)
                mproof, _ = _prove_with_test_nonces(v, gamma, n, ctx, bytes(range(32)))
            finally:
                _TRANSCRIPT_MUTATION = None
            changed = all(det["challenges"][c] != base["challenges"][c] for c in base["challenges"])
            ok = changed and not det["verdict"] and mproof != proof and not verify(Vb, mproof, n, ctx)
            return ok, f"all challenges changed={changed}; mutated verifier layer={det['layer']}"
        res.guard("transcript-mutant", f"{mut}: every challenge changes; original proof rejected by the mutated "
                                       "verifier; mutated prover's proof rejected by the real verifier", run)
    # changing one prover message changes every LATER challenge and no earlier one
    order = ["y", "z", "x", "xu"] + [f"x_{j}" for j in range(1, LOG2[n] + 1)]
    other_pt = g1_serialize(G1_GEN)
    t_off = _scalar_offsets(n)[0]
    cases = [("A", 0, other_pt, 0), ("T1", 96, other_pt, 2),
             ("t_hat", t_off, scalar_serialize((OS2IP(proof[t_off:t_off + 32]) + 1) % Q), 3),
             ("L_2", 288 + 96, other_pt, 5), ("R_4", 288 + 96 * 3 + 48, other_pt, 7)]
    for nm, off, new, first_changed in cases:
        def msg(off=off, new=new, first_changed=first_changed):
            ch = _challenges_of(Vb, _replace(proof, off, new), n, ctx)
            same = all(ch[c] == base["challenges"][c] for c in order[:first_changed])
            diff = all(ch[c] != base["challenges"][c] for c in order[first_changed:])
            return same and diff, f"unchanged={order[:first_changed]} changed={order[first_changed:]}"
        res.guard("transcript-mutant", f"change {nm}: every later challenge changes, earlier ones do not", msg)
    res.guard("transcript-mutant", "change a or b: no challenge changes (not absorbed, §5.3)",
              lambda: (_challenges_of(Vb, _flip(proof, len(proof) - 1, 1), n, ctx) == base["challenges"]
                       and _challenges_of(Vb, _flip(proof, len(proof) - 33, 1), n, ctx) == base["challenges"], ""))


def run_self_test() -> int:
    res = _Results()
    for section in (selftest_conformance, selftest_generators, selftest_transcript_shapes,
                    selftest_known_answer, selftest_roundtrips, selftest_refusals,
                    selftest_verifier_negatives, selftest_transcript_mutants):
        try:
            section(res)
        except Exception as e:  # noqa: BLE001  -- an unexpected exception is a counted FAIL
            res.check(section.__name__.replace("selftest_", ""), "section completed without an exception",
                      False, f"{type(e).__name__}: {e}")
    print()
    print("SUMMARY")
    tp = tf = 0
    for g, (p, f) in res.groups.items():
        print(f"  {g:<20} pass={p:<4} fail={f}")
        tp += p
        tf += f
    print(f"  {'TOTAL':<20} pass={tp:<4} fail={tf}")
    for g, (p, f) in res.reported.items():
        print(f"  {g:<20} ok={p:<4} not-ok={f}   (reported, not gated)")
    if res.failures:
        print("FAILURES:")
        for f in res.failures:
            print("  " + f)
    return 0 if tf == 0 else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

TRACE_VALUE = 12345
TRACE_BLINDING = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
TRACE_CTX = b"hello"
TRACE_SEED = bytes(range(32))


def print_generators() -> None:
    gens = generators()
    names = [f"G_{i}" for i in range(64)] + [f"H_{i}" for i in range(64)] + ["U"]
    out = {
        "generatorSetId": GENSET_ID.decode(),
        "DST": DST_BP.decode("ascii"),
        "DSTHex": DST_BP.hex(),
        "order": "G_0..G_63, H_0..H_63, U",
        "generators": [{"name": nm, "compressedHex": e.hex()} for nm, e in zip(names, gens.encodings)],
        "D_gens": gens.digest.hex(),
        "pedersenG": g1_serialize(gens.G).hex(),
        "pedersenH": g1_serialize(gens.H).hex(),
    }
    print(json.dumps(out, indent=2))


def print_trace() -> None:
    n = 16
    proof, trace = _prove_with_test_nonces(TRACE_VALUE, TRACE_BLINDING, n, TRACE_CTX, TRACE_SEED)
    det = verify_detailed(trace["commitment"], proof, n, TRACE_CTX)
    out = {
        "bits": str(n),
        "value": str(TRACE_VALUE),
        "blinding": str(TRACE_BLINDING),
        "blindingHex": "%064x" % TRACE_BLINDING,
        "ctxHex": TRACE_CTX.hex(),
        "nonceSeedHex": TRACE_SEED.hex(),
        "tag": trace["tag"].decode("ascii"),
        "sessionIdHex": trace["sessionId"].hex(),
        "commitmentHex": trace["commitment"].hex(),
        "instanceHex": trace["instance"].hex(),
        "challenges": _challenge_dict(trace["challenges"], LOG2[n]),
        "proofLength": str(len(proof)),
        "proofHex": proof.hex(),
        "verified": "true" if det["verdict"] else "false",
    }
    print(json.dumps(out, indent=2))


def main(argv) -> int:
    global _BUNDLE_VECTORS
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--print-generators", action="store_true")
    ap.add_argument("--print-trace", action="store_true")
    ap.add_argument("--vectors-dir", default=None,
                    help="directory with the CFRG JSON vectors (default: the repository's "
                         "zeroj-test-vectors/.../test-vectors/cfrg-drafts-03)")
    args = ap.parse_args(argv)
    _BUNDLE_VECTORS = args.vectors_dir
    if args.print_generators:
        print_generators()
        return 0
    if args.print_trace:
        print_trace()
        return 0
    if args.self_test:
        return run_self_test()
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
