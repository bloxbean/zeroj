#!/usr/bin/env python3
"""Stand-alone second implementation of `bulletproof-range-bls12-381-g1-v1` (ZeroJ ADR-0061 M0).

Written only from:
  * the ZeroJ specification `bulletproof-range-bls12-381-g1-v1.md` (draft r1 as amended with the
    M0 second-implementation findings: non-empty ctx, proof-order decoding, identity-V verdict
    after the format checks; see its §14) and the profile it
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


def sigma_derive_challenge(tag: bytes, inst: LinearRelation, commitment_bytes: bytes) -> int:
    """sigma-03 §5.2 DeriveChallenge."""
    global _SIGMA_CHALLENGES_DERIVED
    _SIGMA_CHALLENGES_DERIVED += 1
    ds = DuplexSponge(derive_session_id(tag))
    ds.absorb(serialize_linear_relation(inst))
    ds.absorb(commitment_bytes)
    return decode_field(ds.squeeze(NS + 16), Q, 1)


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
#   _TRANSCRIPT_MUTATION  (None or one of "drop_V", "drop_ctx", "drop_Dgens", "swap_GH")
#   _CHALLENGE_HOOK       (None or callable(name, value) -> value; used to force a zero challenge)
# ---------------------------------------------------------------------------

_TRANSCRIPT_MUTATION = None
_CHALLENGE_HOOK = None


def session_tag(n: int, ctx: bytes) -> bytes:
    k = LOG2[n]
    tag = (PROTOCOL_ID
           + b"/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381"
           + b"/N" + b"%03d" % n
           + b"/A96S96.A96S48.A96S48.(A96S48)x" + b"%d" % k + b".A64")
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
    if isinstance(n, bool) or not isinstance(n, int) or n not in BITS:
        raise InvalidConfiguration("n not in {16, 32, 64}", "configuration")
    if not isinstance(ctx, (bytes, bytearray)) or not 1 <= len(ctx) <= MAX_CTX:
        raise InvalidConfiguration("len(ctx) not in [1, 1024]", "configuration")


def _check1(name: str, s) -> int:
    if isinstance(s, bool) or not isinstance(s, int) or not 0 <= s < Q:
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


def prove(v: int, gamma: int, n: int, ctx: bytes, max_attempts: int = 8):
    """Public prover: CSPRNG nonces (§7.3), restarts with all-fresh nonces.  Returns (V, proof)."""
    V = _prover_preamble(v, gamma, n, ctx)
    for _ in range(max_attempts):
        try:
            proof, trace = _prove_core(v, gamma, n, bytes(ctx), V, _csprng_nonces(n))
            return trace["commitment"], proof
        except _Restart:
            continue
    raise RuntimeError("prover: too many restarts (should happen with negligible probability)")


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


def verify_detailed(V, proof: bytes, n: int, ctx: bytes) -> dict:
    """Spec §8 (r1 as amended).  `V` is 48 octets, or an already-decoded commitment (affine tuple,
    or None for O).  Format failures raise a BulletproofError subclass (with .layer); otherwise
    returns a dict with `verdict` (bool), `layer` and the recomputed challenges."""
    # Step 1: configuration
    _check_configuration(n, ctx)
    ctx = bytes(ctx)
    k = LOG2[n]
    # Step 2: V octets through the profile's strict decoder (a decoded V is valid by construction)
    if isinstance(V, (bytes, bytearray)):
        try:
            v_pt = g1_decode_profile(bytes(V))
        except BulletproofError as e:
            e.layer = "statement"
            raise
    else:
        v_pt = V
        if v_pt is not None and not C.on_curve_e(v_pt):
            raise MalformedEncoding("decoded commitment not on curve", "statement")
    # Step 3: proof length
    proof = bytes(proof)
    if len(proof) != proof_length(n):
        raise MalformedEncoding(f"proof length {len(proof)} != {proof_length(n)}", "length")
    # Step 4: the proof's fields in proof order; first failure reported
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
    # Step 5: V = O -> false (after the format checks)
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


def selftest_conformance(res: _Results) -> None:
    vdir = _find_vectors_dir()
    if not res.check("conformance", "vector directory found", vdir is not None,
                     os.path.relpath(vdir, _HERE) if vdir else
                     f"not found at {DEFAULT_VECTORS_DIR}; pass --vectors-dir DIR"):
        return
    for fname, want in VECTOR_SHA256.items():
        path = os.path.join(vdir, fname)
        got = hashlib.sha256(open(path, "rb").read()).hexdigest() if os.path.isfile(path) else "missing"
        res.check("conformance", f"{fname} SHA-256 == spec §10 pin", got == want, got)
    # fiat-shamir-03 B.1
    codec = json.load(open(os.path.join(vdir, "fiatShamirCodecVectors.json")))
    seen = set()
    for v in codec:
        nm = v["Name"]
        if nm in FS_CODEC_IN_SCOPE:
            ok, info = run_fs_codec_vector(v)
            res.check("fs-codec", v["Id"], ok, info[:80])
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
            ok, info = run_fs_shake_vector(v)
            res.check("fs-shake128", v["Id"], ok, info[:64])
            seen.add(nm)
        elif nm in FS_SHAKE_OUT_OF_SCOPE:
            print(f"SKIP [fs-shake128] {v['Id']} (out of scope: {FS_SHAKE_OUT_OF_SCOPE[nm]})")
        else:
            res.check("fs-shake128", v["Id"], False, "unexpected vector")
    res.check("fs-shake128", "all 11 in-scope SHAKE128 vectors present", seen == FS_SHAKE_IN_SCOPE,
              str(sorted(FS_SHAKE_IN_SCOPE - seen)))
    # the emulated reader against one-shot SHAKE128 of the concatenated input (§3.2 XOF form)
    sid = bytes(range(32))
    ds = DuplexSponge(sid)
    ds.absorb(b"abc")
    s1 = ds.squeeze(100) + ds.squeeze(200)
    one = hashlib.shake_128(sid + bytes(136) + b"abc").digest(300)
    ds.absorb(b"def")
    s2 = ds.squeeze(50)
    two = hashlib.shake_128(sid + bytes(136) + b"abcdef").digest(50)
    res.check("fs-shake128", "duplex = XOF(session_id||zeros(136)||inputs) (stream + interleave)",
              s1 == one and s2 == two)

    # sigma-03 §8.2 generator encoding
    res.check("sigma-03", "G1 generator compress == sigma-03 §8.2.1 hex",
              C.compress(G1_GEN).hex() == "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f1"
                                          "71bac586c55e83ff97a1aeffb3af00adb22c6bb")
    # A.3.1 valid
    valid = json.load(open(os.path.join(vdir, "sigma-proofs_Shake128_BLS12381.json")))
    wanted = {f"sigma-protocols/bls12381/{r}/{f}" for r in ("discrete_logarithm", "pedersen_commitment")
              for f in ("batchable", "compact")}
    seen = set()
    for v in valid:
        if v["Id"] not in wanted:
            # Spec §10: the generic sparse-relation harness also verifies the other ten A.3.1
            # vectors; they are reported separately and are not part of the gate.
            tag = v["Tag"].encode("ascii")
            try:
                ok = sigma_verify(tag, bytes.fromhex(v["Instance"]), bytes.fromhex(v["NargString"]),
                                  v["Flavor"])[0]
            except SigmaReject:
                ok = False
            res.report("sigma-valid-extra", v["Id"] + " (not gated) SessionId + verifies",
                      ok and derive_session_id(tag).hex() == v["SessionId"])
            continue
        seen.add(v["Id"])
        tag = v["Tag"].encode("ascii")
        sid = derive_session_id(tag)
        res.check("sigma-valid", v["Id"] + " SessionId from Tag", sid.hex() == v["SessionId"], sid.hex())
        inst_b = bytes.fromhex(v["Instance"])
        narg = bytes.fromhex(v["NargString"])
        try:
            ok, layer, _, ch = sigma_verify(tag, inst_b, narg, v["Flavor"])
        except SigmaReject as e:
            ok, layer, ch = False, e.layer, None
        if v["Flavor"] == "batchable":
            inst = parse_linear_relation(inst_b)
            neq = len(inst.equations)
            ch2 = sigma_derive_challenge(tag, inst, narg[:NE * neq])
            res.check("sigma-valid", v["Id"] + " challenge recomputed", ch == ch2 and ch is not None,
                      f"c={ch2}")
        else:
            res.check("sigma-valid", v["Id"] + " challenge recomputed == NARG challenge",
                      ok and ch == OS2IP(narg[:NS]), f"c={OS2IP(narg[:NS])}")
        res.check("sigma-valid", v["Id"] + " verifies", ok and v["Expected"] == "accept", layer)
        # the published witness satisfies the published instance: map(witness) == image
        inst = parse_linear_relation(inst_b)
        wb = bytes.fromhex(v["Witness"])
        wit = [OS2IP(wb[i:i + NS]) for i in range(0, len(wb), NS)]
        res.check("sigma-valid", v["Id"] + " witness satisfies instance",
                  all(jeq(m, i) for m, i in zip(sigma_map(inst, wit), sigma_image(inst))))
    res.check("sigma-valid", "all 4 in-scope valid vectors present", seen == wanted)

    # A.3.2 adversarial
    global _SIGMA_CHALLENGES_DERIVED
    adv = json.load(open(os.path.join(vdir, "sigma-proofs-invalid_Shake128_BLS12381.json")))
    res.check("sigma-invalid", "32 adversarial vectors in file", len(adv) == 32, str(len(adv)))
    early = {"batchable/A1", "batchable/A3", "batchable/A4", "batchable/A5", "batchable/A6",
             "batchable/B1", "compact/B2"}
    controls = {"batchable/F1", "compact/F1", "batchable/F2", "compact/F2"}
    n_rej = n_acc = 0
    for v in adv:
        short = v["Id"].split("/", 3)[3]
        before = _SIGMA_CHALLENGES_DERIVED
        try:
            ok, layer, detail, _ = sigma_verify(v["Tag"].encode("ascii"), bytes.fromhex(v["Instance"]),
                                                bytes.fromhex(v["NargString"]), v["Flavor"])
        except SigmaReject as e:
            ok, layer, detail = False, e.layer, e.detail
        derived = _SIGMA_CHALLENGES_DERIVED - before
        outcome = "accept" if ok else "reject"
        n_acc += ok
        n_rej += not ok
        good = outcome == v["Expected"]
        if short in early:
            good = good and layer.startswith("deserialize") and derived == 0
        if short in controls:
            good = good and ok
        res.check("sigma-invalid", f"{short:<14} {outcome:<6} layer={layer}",
                  good, f"{detail}; challenges derived={derived}")
    res.check("sigma-invalid", "28 rejected / 4 accepted", n_rej == 28 and n_acc == 4,
              f"rejected={n_rej} accepted={n_acc}")
    # A1, A3-A6 directly against the §3 point decoder and B1/B2 against the scalar decoder
    for v in adv:
        short = v["Id"].split("/", 3)[3]
        narg = bytes.fromhex(v["NargString"])
        if short in ("batchable/A1", "batchable/A3", "batchable/A4", "batchable/A5", "batchable/A6"):
            try:
                g1_deserialize(narg[:48])
                r = "accepted"
            except BulletproofError as e:
                r = e.error_class
            res.check("sigma-invalid", f"{short} direct §3 point decoder rejects", r != "accepted", r)
        if short == "batchable/B1":
            try:
                scalar_deserialize(narg[48:80])
                r = "accepted"
            except BulletproofError as e:
                r = e.error_class
            res.check("sigma-invalid", f"{short} direct §3 scalar decoder rejects",
                      r == "NON_CANONICAL_SCALAR", r)
        if short == "compact/B2":
            try:
                scalar_deserialize(narg[:32])
                r = "accepted"
            except BulletproofError as e:
                r = e.error_class
            res.check("sigma-invalid", f"{short} direct §3 scalar decoder rejects",
                      r == "NON_CANONICAL_SCALAR", r)


def selftest_generators(res: _Results) -> None:
    res.check("generators", "DST_BP is 70 octets", len(DST_BP) == 70, str(len(DST_BP)))
    try:
        gens = generators()
        ok = True
        info = ""
    except GeneratorCheckFailure as e:
        ok, info = False, str(e)
    res.check("generators", "derivation + §2.2 checks (131 points: none O, pairwise != +-)", ok, info)
    if not ok:
        return
    allpts = gens.Gvec + gens.Hvec + [gens.U, gens.G, gens.H]
    # brute-force pairwise check, independent of the x-coordinate shortcut
    bad = 0
    for i in range(len(allpts)):
        for j in range(i + 1, len(allpts)):
            if allpts[i] == allpts[j] or allpts[i] == C.point_neg(allpts[j]):
                bad += 1
    res.check("generators", "pairwise P != Q and P != -Q (brute force, 8515 pairs)", bad == 0)
    res.check("generators", "129 encodings, 6192 octets hashed",
              len(gens.encodings) == 129 and len(b"".join(gens.encodings)) == 6192)
    res.check("generators", "every generator in G1 ([q]P = O, on curve)",
              all(C.on_curve_e(p) and C.in_subgroup(p) for p in allpts))
    res.check("generators", "every encoding strict-decodes back to its point",
              all(g1_deserialize(e) == p for e, p in zip(gens.encodings, gens.Gvec + gens.Hvec + [gens.U])))
    g_re, h_re = C.derive_basis()
    res.check("generators", "profile G, H pinned (pedersen §2.2) == RFC 9380 recomputation",
              g_re == gens.G and h_re == gens.H and C.compress(g_re).hex() == PINNED_G_HEX
              and C.compress(h_re).hex() == PINNED_H_HEX)
    res.check("generators", "G_5 message is 47 00 00 00 05",
              gens.Gvec[5] == C.hash_to_curve(bytes.fromhex("4700000005"), DST_BP))
    res.check("generators", "D_gens = SHA-256(encodings)",
              gens.digest == hashlib.sha256(b"".join(gens.encodings)).digest(), gens.digest.hex())
    # curve arithmetic cross-check: own Jacobian vs module affine
    rnd = [3, 12345, Q - 1, Q - 2, (1 << 200) + 17, OS2IP(hashlib.sha256(b"k").digest()) % Q]
    good = True
    for p in (G1_GEN, gens.G, gens.U):
        for kk in rnd:
            if to_affine(jmul(to_jac(p), kk)) != C.scalar_mul(kk, p):
                good = False
        if to_affine(jadd(to_jac(p), to_jac(p))) != C.point_add(p, p):
            good = False
        if to_affine(jadd(to_jac(p), to_jac(gens.H))) != C.point_add(p, gens.H):
            good = False
        if not is_inf(jadd(to_jac(p), jneg(to_jac(p)))):
            good = False
    res.check("generators", "Jacobian arithmetic == curve module affine arithmetic", good)


def selftest_transcript_shapes(res: _Results) -> None:
    ex = ("ZeroJ:bulletproof-range-bls12-381-g1-v1/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381"
          "/N016/A96S96.A96S48.A96S48.(A96S48)x4.A64/CTX0005:68656c6c6f")
    res.check("transcript", "§5.1 example tag reproduced", session_tag(16, b"hello").decode() == ex)
    res.check("transcript", "1-octet ctx tag ends with /CTX0001:00",
              session_tag(64, b"\x00").endswith(b"/N064/A96S96.A96S48.A96S48.(A96S48)x6.A64/CTX0001:00"))
    inst = encode_instance(16, g1_serialize(generators().G))
    res.check("transcript", "instance length 4+24+96+4+32+32+4+48 = 244", len(inst) == 244, str(len(inst)))
    for n, ln in ((16, 736), (32, 832), (64, 928)):
        res.check("transcript", f"proof_length({n}) == {ln}", proof_length(n) == ln)


def selftest_roundtrips(res: _Results) -> None:
    gens = generators()
    for n in BITS:
        cases = [("v=0 nonzero blinding", 0, 7777777),
                 ("v=1", 1, 98765),
                 ("v=2^n-1", (1 << n) - 1, Q - 3),
                 ("v=random", secrets.randbelow(1 << n), secrets.randbelow(Q - 1) + 1)]
        for label, v, gamma in cases:
            seed = hashlib.sha256(b"selftest-seed" + label.encode() + bytes([n])).digest()
            try:
                proof, trace = _prove_with_test_nonces(v, gamma, n, b"ctx-" + bytes([n]), seed)
            except Exception as e:  # pragma: no cover
                res.check("roundtrip", f"n={n} {label}", False, f"prover raised {e!r}")
                continue
            det = verify_detailed(trace["commitment"], proof, n, b"ctx-" + bytes([n]))
            ok = (len(proof) == proof_length(n) and det["verdict"]
                  and det["challenges"] == trace["challenges"]
                  and det["sessionId"] == trace["sessionId"])
            res.check("roundtrip", f"n={n} {label} (v={v}) test nonces", ok,
                      f"len={len(proof)} layer={det['layer']}")
            if label == "v=0 nonzero blinding" or label == "v=random":
                proof2, _ = _prove_with_test_nonces(v, gamma, n, b"ctx-" + bytes([n]), seed)
                res.check("roundtrip", f"n={n} {label} deterministic for a fixed seed", proof2 == proof)
            if label == "v=random":
                res.check("roundtrip", f"n={n} {label} recursive IPA verifier agrees",
                          _verify_ipa_recursive(trace["commitment"], proof, n, b"ctx-" + bytes([n])))
        # CSPRNG prover
        v = secrets.randbelow(1 << n)
        vb, proof = prove(v, secrets.randbelow(Q - 1) + 1, n, b"csprng")
        res.check("roundtrip", f"n={n} CSPRNG prover (v={v})",
                  verify(vb, proof, n, b"csprng") and len(proof) == proof_length(n))
        # commitment as decoded point
        res.check("roundtrip", f"n={n} V given as decoded commitment",
                  verify(g1_decode_profile(vb), proof, n, b"csprng"))
    # ctx boundary 1024
    proof, trace = _prove_with_test_nonces(5, 6, 16, bytes(1024), bytes(32))
    res.check("roundtrip", "ctx of exactly 1024 octets accepted",
              verify(trace["commitment"], proof, 16, bytes(1024)))
    proof, trace = _prove_with_test_nonces(7, 8, 16, b"\x00", bytes([7]) * 32)
    res.check("roundtrip", "ctx of exactly 1 octet accepted",
              verify(trace["commitment"], proof, 16, b"\x00"))
    # different seeds give different proofs
    p1, _ = _prove_with_test_nonces(5, 6, 16, b"seeds", bytes(32))
    p2, _ = _prove_with_test_nonces(5, 6, 16, b"seeds", bytes(31) + b"\x01")
    res.check("roundtrip", "different seeds -> different proofs", p1 != p2)
    _ = gens


def selftest_refusals(res: _Results) -> None:
    def refusal(label, fn, expected):
        try:
            fn()
            got = "no error"
        except BulletproofError as e:
            got = e.error_class
        except Exception as e:  # noqa
            got = f"other {type(e).__name__}"
        res.check("prover-refusal", label, got == expected, got)

    for n in BITS:
        refusal(f"n={n} v = 2^n", lambda n=n: prove(1 << n, 5, n, b"app"), "OUT_OF_RANGE")
        refusal(f"n={n} v = q-1", lambda n=n: prove(Q - 1, 5, n, b"app"), "OUT_OF_RANGE")
    refusal("v = q", lambda: prove(Q, 5, 16, b"app"), "NON_CANONICAL_SCALAR")
    refusal("v = -1", lambda: prove(-1, 5, 16, b"app"), "NON_CANONICAL_SCALAR")
    refusal("gamma = q", lambda: prove(3, Q, 16, b"app"), "NON_CANONICAL_SCALAR")
    refusal("gamma = -1", lambda: prove(3, -1, 16, b"app"), "NON_CANONICAL_SCALAR")
    refusal("v = True (bool)", lambda: prove(True, 5, 16, b"app"), "NON_CANONICAL_SCALAR")
    refusal("(0, 0) opens the identity", lambda: prove(0, 0, 16, b"app"), "INVALID_STATEMENT")
    for bad_n in (0, 8, 17, 128, -16, 63):
        refusal(f"bad n = {bad_n}", lambda bad_n=bad_n: prove(1, 1, bad_n, b"app"), "INVALID_CONFIGURATION")
    refusal("n = '16' (str)", lambda: prove(1, 1, "16", b"app"), "INVALID_CONFIGURATION")
    refusal("ctx of 1025 octets", lambda: prove(1, 1, 16, bytes(1025)), "INVALID_CONFIGURATION")
    refusal("empty ctx", lambda: prove(1, 1, 16, b""), "INVALID_CONFIGURATION")
    refusal("ctx not bytes (str)", lambda: prove(1, 1, 16, "app"), "INVALID_CONFIGURATION")
    refusal("order: empty ctx and v = q -> configuration first", lambda: prove(Q, 1, 16, b""),
            "INVALID_CONFIGURATION")
    refusal("test-nonce prover empty ctx", lambda: _prove_with_test_nonces(1, 1, 16, b"", bytes(32)),
            "INVALID_CONFIGURATION")
    # order: configuration before scalars before range
    refusal("order: bad n and v = q -> configuration first", lambda: prove(Q, 1, 8, b"app"), "INVALID_CONFIGURATION")
    refusal("order: v = q and gamma = q -> NON_CANONICAL", lambda: prove(Q, Q, 16, b"app"), "NON_CANONICAL_SCALAR")
    refusal("order: v = 2^16 and gamma = q -> NON_CANONICAL first", lambda: prove(1 << 16, Q, 16, b"app"),
            "NON_CANONICAL_SCALAR")
    refusal("order: (0,0) with ctx 1025 -> configuration first", lambda: prove(0, 0, 16, bytes(1025)),
            "INVALID_CONFIGURATION")
    # test-nonce prover: same refusals
    refusal("test-nonce prover v = 2^16", lambda: _prove_with_test_nonces(1 << 16, 1, 16, b"app", bytes(32)),
            "OUT_OF_RANGE")


def selftest_verifier_negatives(res: _Results) -> None:
    global _CHALLENGE_HOOK
    n, ctx = 16, b"negatives"
    k = LOG2[n]
    v, gamma = 40000, 31337
    proof, trace = _prove_with_test_nonces(v, gamma, n, ctx, bytes(range(32)))
    Vb = trace["commitment"]
    res.check("verifier-neg", "baseline accepts", classify(Vb, proof, n, ctx) == ("true", "accept"))

    def expect(label, got, allowed):
        res.check("verifier-neg", label, got[0] in allowed and got[0] != "true", f"{got[0]} at {got[1]}")

    names = ["A", "S", "T1", "T2"] + [f"{p}_{j}" for j in range(1, k + 1) for p in ("L", "R")]
    poffs = _point_offsets(n)
    snames = ["t_hat", "tau_x", "mu", "a", "b"]
    soffs = _scalar_offsets(n)
    other_pt = g1_serialize(G1_GEN)
    REJ = {"false", "MALFORMED_ENCODING", "NOT_IN_SUBGROUP", "NON_CANONICAL_SCALAR"}
    # substitutions
    for nm, off in zip(names, poffs):
        expect(f"substitute {nm} by another valid point", classify(Vb, _replace(proof, off, other_pt), n, ctx),
               {"false"})
    for nm, off in zip(snames, soffs):
        s = OS2IP(proof[off:off + 32])
        expect(f"substitute {nm} by {nm}+1", classify(Vb, _replace(proof, off, scalar_serialize((s + 1) % Q)), n, ctx),
               {"false"})
    # bit flips at each position class
    for nm, off in zip(names, poffs):
        expect(f"flip compression bit of {nm}", classify(Vb, _flip(proof, off, 0x80), n, ctx), {"MALFORMED_ENCODING"})
        expect(f"flip infinity bit of {nm}", classify(Vb, _flip(proof, off, 0x40), n, ctx), {"MALFORMED_ENCODING"})
        expect(f"flip sort bit of {nm} (-P)", classify(Vb, _flip(proof, off, 0x20), n, ctx), {"false"})
        expect(f"flip x LSB of {nm}", classify(Vb, _flip(proof, off + 47, 0x01), n, ctx), REJ)
        expect(f"flip x middle bit of {nm}", classify(Vb, _flip(proof, off + 24, 0x10), n, ctx), REJ)
    for nm, off in zip(snames, soffs):
        expect(f"flip top bit of {nm} (>= q)", classify(Vb, _flip(proof, off, 0x80), n, ctx),
               {"NON_CANONICAL_SCALAR"})
        expect(f"flip LSB of {nm}", classify(Vb, _flip(proof, off + 31, 0x01), n, ctx), {"false"})
    # length
    expect("truncated by one octet", classify(Vb, proof[:-1], n, ctx), {"MALFORMED_ENCODING"})
    expect("extended by one octet", classify(Vb, proof + b"\x00", n, ctx), {"MALFORMED_ENCODING"})
    expect("empty proof", classify(Vb, b"", n, ctx), {"MALFORMED_ENCODING"})
    expect("proof of n=32 length under n=16", classify(Vb, proof + bytes(96), n, ctx), {"MALFORMED_ENCODING"})
    # identity / invalid proof points
    for nm, off in (("A", poffs[0]), ("T2", poffs[3]), ("R_4", poffs[-1])):
        expect(f"identity encoding as {nm}", classify(Vb, _replace(proof, off, C.IDENTITY_ENCODING), n, ctx),
               {"MALFORMED_ENCODING"})
    expect("order-3 point (0x80||0^47) as S", classify(Vb, _replace(proof, poffs[1], b"\x80" + bytes(47)), n, ctx),
           {"NOT_IN_SUBGROUP"})
    expect("x = P_381 as L_1", classify(Vb, _replace(proof, poffs[4], bytes([0x80 | (P_381 >> 376)]) +
                                                    I2OSP(P_381, 48)[1:]), n, ctx), {"MALFORMED_ENCODING"})
    # non-canonical scalars s + q
    for nm, off in zip(snames, soffs):
        s = OS2IP(proof[off:off + 32])
        expect(f"non-canonical {nm} + q", classify(Vb, _replace(proof, off, I2OSP(s + Q, 32)), n, ctx),
               {"NON_CANONICAL_SCALAR"})
    # wrong statement / configuration
    expect("verified under n = 32", classify(Vb, proof, 32, ctx), {"MALFORMED_ENCODING"})
    expect("verified under n = 64", classify(Vb, proof, 64, ctx), {"MALFORMED_ENCODING"})
    expect("verified under a different ctx", classify(Vb, proof, n, ctx + b"!"), {"false"})
    r = classify(Vb, proof, n, b"")
    res.check("verifier-neg", "verified under empty ctx -> INVALID_CONFIGURATION",
              r == ("INVALID_CONFIGURATION", "configuration"), str(r))
    r = classify(C.IDENTITY_ENCODING, proof, n, b"")
    res.check("verifier-neg", "empty ctx + identity V -> INVALID_CONFIGURATION",
              r == ("INVALID_CONFIGURATION", "configuration"), str(r))
    expect("verified under a 1-octet prefix of ctx", classify(Vb, proof, n, ctx[:1]), {"false"})
    other_V = g1_serialize(to_affine(commit(v + 1, gamma)))
    expect("verified against a different V (v+1)", classify(other_V, proof, n, ctx), {"false"})
    expect("verified against -V", classify(_flip(Vb, 0, 0x20), proof, n, ctx), {"false"})
    r = classify(C.IDENTITY_ENCODING, proof, n, ctx)
    res.check("verifier-neg", "V = identity -> false at statement", r == ("false", "statement"), str(r))
    r = classify(None, proof, n, ctx)
    res.check("verifier-neg", "V = O (decoded) -> false at statement", r == ("false", "statement"), str(r))
    r = classify(b"\x80" + bytes(47), proof, n, ctx)
    res.check("verifier-neg", "V outside subgroup -> NOT_IN_SUBGROUP", r[0] == "NOT_IN_SUBGROUP", str(r))
    r = classify(Vb[:47], proof, n, ctx)
    res.check("verifier-neg", "V of 47 octets -> MALFORMED_ENCODING", r[0] == "MALFORMED_ENCODING", str(r))
    r = classify(Vb, proof, 8, ctx)
    res.check("verifier-neg", "n = 8 -> INVALID_CONFIGURATION", r[0] == "INVALID_CONFIGURATION", str(r))
    r = classify(Vb, proof, n, bytes(1025))
    res.check("verifier-neg", "ctx 1025 -> INVALID_CONFIGURATION", r[0] == "INVALID_CONFIGURATION", str(r))
    # swapped L/R
    lr = proof[288:288 + 96]
    expect("L_1 and R_1 swapped", classify(Vb, _replace(proof, 288, lr[48:] + lr[:48]), n, ctx), {"false"})
    # decoding order (§8.1)
    r = classify(Vb, proof, 8, bytes(1025))
    res.check("verifier-order", "bad n + bad ctx -> INVALID_CONFIGURATION", r[0] == "INVALID_CONFIGURATION", str(r))
    r = classify(b"\x80" + bytes(47), proof, 8, ctx)
    res.check("verifier-order", "bad n + bad V -> INVALID_CONFIGURATION (step 1 first)",
              r[0] == "INVALID_CONFIGURATION", str(r))
    r = classify(C.IDENTITY_ENCODING, proof[:-1], n, ctx)
    res.check("verifier-order", "V = O + bad length -> MALFORMED_ENCODING (format before step 5)",
              r == ("MALFORMED_ENCODING", "length"), str(r))
    r = classify(C.IDENTITY_ENCODING, _replace(proof, poffs[0], C.IDENTITY_ENCODING), n, ctx)
    res.check("verifier-order", "V = O + identity A -> MALFORMED_ENCODING at point",
              r == ("MALFORMED_ENCODING", "point"), str(r))
    r = classify(C.IDENTITY_ENCODING, _flip(proof, soffs[4], 0x80), n, ctx)
    res.check("verifier-order", "V = O + non-canonical b -> NON_CANONICAL_SCALAR",
              r == ("NON_CANONICAL_SCALAR", "scalar"), str(r))
    r = classify(C.IDENTITY_ENCODING, proof, n, ctx)
    res.check("verifier-order", "V = O + well-formed proof -> false at statement (step 5)",
              r == ("false", "statement"), str(r))
    r = classify(Vb[:47], proof[:-1], n, ctx)
    res.check("verifier-order", "bad V + bad length -> V's class (step 2 first)",
              r[0] == "MALFORMED_ENCODING" and r[1] == "statement", str(r))
    bad_both = _replace(_flip(proof, soffs[0], 0x80), poffs[-1], C.IDENTITY_ENCODING)
    r = classify(Vb, bad_both, n, ctx)
    res.check("verifier-order", "bad t_hat (offset 192) + identity R_4 (later) -> NON_CANONICAL (proof order)",
              r == ("NON_CANONICAL_SCALAR", "scalar"), str(r))
    bad_mid = _replace(_flip(proof, soffs[2], 0x80), poffs[1], C.IDENTITY_ENCODING)
    r = classify(Vb, bad_mid, n, ctx)
    res.check("verifier-order", "identity S + bad mu (later) -> MALFORMED_ENCODING at point",
              r == ("MALFORMED_ENCODING", "point"), str(r))
    bad_tail = _replace(_flip(proof, soffs[3], 0x80), poffs[-1], b"\x80" + bytes(47))
    r = classify(Vb, bad_tail, n, ctx)
    res.check("verifier-order", "non-subgroup R_4 + bad a (later) -> NOT_IN_SUBGROUP at point",
              r == ("NOT_IN_SUBGROUP", "point"), str(r))
    bad_two = _replace(_replace(proof, poffs[1], b"\x80" + bytes(47)), poffs[3], C.IDENTITY_ENCODING)
    r = classify(Vb, bad_two, n, ctx)
    res.check("verifier-order", "non-subgroup S before identity T2 -> NOT_IN_SUBGROUP (proof order)",
              r[0] == "NOT_IN_SUBGROUP", str(r))
    # zero challenges via the seam
    for cname in ["y", "z", "x", "xu"] + [f"x_{j}" for j in range(1, k + 1)]:
        _CHALLENGE_HOOK = (lambda target: (lambda nm, val: 0 if nm == target else val))(cname)
        try:
            r = classify(Vb, proof, n, ctx)
            try:
                _prove_with_test_nonces(v, gamma, n, ctx, bytes(range(32)))
                pr = "no failure"
            except TestNonceProverFailure:
                pr = "TestNonceProverFailure"
        finally:
            _CHALLENGE_HOOK = None
        res.check("verifier-neg", f"challenge {cname} forced to 0 -> false at challenge; test prover fails",
                  r == ("false", "challenge") and pr == "TestNonceProverFailure", f"{r} / {pr}")
    # CSPRNG prover restarts when a challenge is zero once
    state = {"hits": 0}

    def once_zero(nm, val):
        if nm == "x" and state["hits"] == 0:
            state["hits"] += 1
            return 0
        return val
    _CHALLENGE_HOOK = once_zero
    try:
        vb2, pr2 = prove(9, 10, 16, b"restart")
    finally:
        _CHALLENGE_HOOK = None
    res.check("verifier-neg", "CSPRNG prover restarts after a zero challenge",
              state["hits"] == 1 and verify(vb2, pr2, 16, b"restart"))

    # cheating provers: isolate check 1 and check 2
    V_cheat = commit(1 << n, gamma)  # out of range value 2^n; a_L = its n low bits = 0
    proof_c, _ = _prove_core(1 << n, gamma, n, ctx, V_cheat, _test_nonces(n, bytes(32)))
    det = verify_detailed(g1_serialize(to_affine(V_cheat)), proof_c, n, ctx)
    res.check("verifier-neg", "cheating prover v = 2^n: rejected by check 1 only",
              not det["verdict"] and not det["check1"] and det["check2"], str((det["check1"], det["check2"])))
    a_bad = [(v >> i) & 1 for i in range(n)]
    a_bad[0] += 2  # a_L entry not a bit; <a_L, 2^n> = v + 2
    V_c2 = commit(v + 2, gamma)
    proof_c2, _ = _prove_core(v + 2, gamma, n, ctx, V_c2, _test_nonces(n, bytes(32)), a_l_override=a_bad)
    det = verify_detailed(g1_serialize(to_affine(V_c2)), proof_c2, n, ctx)
    res.check("verifier-neg", "cheating prover with a non-bit a_L entry: rejected by check 1",
              not det["verdict"] and not det["check1"], str((det["check1"], det["check2"])))
    a_off = soffs[3]
    tampered = _replace(proof, a_off, scalar_serialize((OS2IP(proof[a_off:a_off + 32]) + 1) % Q))
    det = verify_detailed(Vb, tampered, n, ctx)
    res.check("verifier-neg", "a + 1 (no later challenge): rejected by check 2 only",
              det["check1"] and not det["check2"], str((det["check1"], det["check2"])))
    res.check("verifier-neg", "recursive IPA verifier also rejects a + 1",
              not _verify_ipa_recursive(Vb, tampered, n, ctx))
    res.check("verifier-neg", "recursive IPA verifier accepts the baseline",
              _verify_ipa_recursive(Vb, proof, n, ctx))
    # mutant: the LSB-first reading of the paper's "j-th bit of i-1" must break check 2 on an
    # honest proof (evidence that §8.3's MSB-first rule is the one matching Protocol 2's folding)
    global _S_BIT_ORDER
    _S_BIT_ORDER = "lsb"
    try:
        det = verify_detailed(Vb, proof, n, ctx)
    finally:
        _S_BIT_ORDER = "msb"
    res.check("verifier-neg", "mutant LSB-first s_i rule rejects the honest proof at check 2",
              det["check1"] and not det["check2"], str((det["check1"], det["check2"])))


def selftest_transcript_mutants(res: _Results) -> None:
    global _TRANSCRIPT_MUTATION
    n, ctx = 16, b"mutants"
    v, gamma = 4242, 777
    proof, trace = _prove_with_test_nonces(v, gamma, n, ctx, bytes(range(32)))
    Vb = trace["commitment"]
    base = verify_detailed(Vb, proof, n, ctx)
    for mut in ("drop_V", "drop_ctx", "drop_Dgens", "swap_GH"):
        _TRANSCRIPT_MUTATION = mut
        try:
            det = verify_detailed(Vb, proof, n, ctx)
            mproof, mtrace = _prove_with_test_nonces(v, gamma, n, ctx, bytes(range(32)))
        finally:
            _TRANSCRIPT_MUTATION = None
        changed = all(det["challenges"][c] != base["challenges"][c] for c in base["challenges"])
        res.check("transcript-mutant", f"{mut}: every challenge changes", changed)
        res.check("transcript-mutant", f"{mut}: original proof rejected by mutated verifier",
                  not det["verdict"], det["layer"])
        res.check("transcript-mutant", f"{mut}: mutated prover's proof rejected by the real verifier",
                  mproof != proof and not verify(Vb, mproof, n, ctx))


def run_self_test() -> int:
    res = _Results()
    selftest_conformance(res)
    selftest_generators(res)
    selftest_transcript_shapes(res)
    selftest_roundtrips(res)
    selftest_refusals(res)
    selftest_verifier_negatives(res)
    selftest_transcript_mutants(res)
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
