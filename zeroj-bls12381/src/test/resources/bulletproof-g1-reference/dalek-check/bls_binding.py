#!/usr/bin/env python3
"""bulletproof-range-bls12-381-g1-v1 binding for bulletproof_generic (ADR-0061 M2 tie-in).

The same group-generic core as the dalek check, instantiated with the protocol of
docs/specs/bulletproof-range-bls12-381-g1-v1.md:

  group        BLS12-381 G1 through ../../pedersen-g1-reference/bls12_381_g1_reference.py
               (imported by path, unmodified; affine points, None = identity)
  generators   G_0..G_63, H_0..H_63, U from ../generators-v1.json (spec Appendix A),
               strictly decoded; D_gens recomputed (spec 2.3)
  bases        G, H of pedersen-bls12-381-g1-basis-v1 (RFC 9380 via the curve module)
  transcript   fiat-shamir-03 XOF duplex sponge on SHAKE128 (spec 4-5), written here on
               hashlib.shake_128 with copy semantics; challenges LE2IP(48 octets) mod q
  IPA base     the independent generator U, challenge x_u (spec 7.2, paper Protocol 1)
  codec        48-octet compressed points (strict decoder, identity rejected) and
               32-octet BIG-endian canonical scalars (spec 3, 6)
  test nonces  spec 7.5 (test only)

Test use only.  Not constant-time.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os

import bulletproof_generic as bp

HERE = os.path.dirname(os.path.abspath(__file__))
# Resolved relative to this file inside the repository; init(resources_dir) overrides
# (resources_dir = zeroj-bls12381/src/test/resources of a checkout).
RESOURCES_DIR = os.path.dirname(os.path.dirname(HERE))
C = None
Q = None
CURVE_PATH = GENS_PATH = None


def init(resources_dir: str | None = None):
    """Load the curve module (by path, unmodified) and locate generators-v1.json."""
    global C, Q, CURVE_PATH, GENS_PATH
    root = resources_dir or RESOURCES_DIR
    CURVE_PATH = os.path.join(root, "pedersen-g1-reference", "bls12_381_g1_reference.py")
    GENS_PATH = os.path.join(root, "bulletproof-g1-reference", "generators-v1.json")
    spec = importlib.util.spec_from_file_location("bls12_381_g1_reference", CURVE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    C = mod
    Q = mod.Q
    G1Group.order = Q
    return mod


ALLOWED_N = (16, 32, 64)

PROTOCOL_ID = b"bulletproof-range-bls12-381-g1-v1"
PROFILE_ID = b"pedersen-bls12-381-g1-v1"
GENSET_ID = b"bulletproof-bls12-381-g1-gens-v1"
D_GENS_PIN = "69abb9e71b740d9be84f63bb146a63467ee452654340f1b09e8be6101e00ef19"
G_PIN = "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e"
H_PIN = "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65"


class G1Group:
    name = "BLS12-381 G1"
    order = None   # set by init()

    def identity(self):
        return None

    def add(self, p1, p2):
        return C.point_add(p1, p2)

    def double(self, p1):
        return C.point_add(p1, p1)

    def neg(self, p1):
        return C.point_neg(p1)

    def mul(self, k, p1):
        return C.scalar_mul(k % Q, p1)

    def eq(self, p1, p2):
        return p1 == p2

    def is_identity(self, p1):
        return p1 is None

    def encode(self, p1):
        return C.compress(p1)


GROUP = G1Group()


# --------------------------------------------------------------------------
# fiat-shamir-03 XOF duplex sponge on SHAKE128 (spec 4; draft 3.2, 5.1)
# --------------------------------------------------------------------------

RATE = 168


class DuplexSponge:
    def __init__(self, session_id: bytes):
        if len(session_id) != 32:
            raise ValueError("session_id must be 32 octets")
        self.ctx = hashlib.shake_128()
        self.ctx.update(bytes(session_id) + bytes(RATE - 32))
        self.reader = None
        self.pos = 0

    def absorb(self, x: bytes) -> None:
        x = bytes(x)
        self.ctx.update(x)
        if len(x) != 0:
            self.reader = None

    def squeeze(self, m: int) -> bytes:
        if self.reader is None:
            self.reader = self.ctx.copy()   # finalize a COPY; keep its output stream
            self.pos = 0
        out = self.reader.digest(self.pos + m)[self.pos:]
        self.pos += m
        return out


def derive_session_id(tag: bytes) -> bytes:
    ds = DuplexSponge(b"irtf-cfrg-fiat-shamir/session-id")
    ds.absorb(tag)
    return ds.squeeze(32)


def le(v: int, w: int) -> bytes:
    if not 0 <= v < 256 ** w:
        raise ValueError("LE overflow")
    return v.to_bytes(w, "little")


def serialize_varlen(s: bytes) -> bytes:
    return le(len(s), 4) + bytes(s)


def session_tag(n: int, ctx: bytes) -> bytes:
    k = n.bit_length() - 1
    return (b"ZeroJ:" + PROTOCOL_ID
            + b"/DSFS-fiat-shamir-03-sigma-proofs_Shake128_BLS12381"
            + b"/N" + b"%03d" % n
            + b"/A96S96.A96S48.A96S48.(A96S48)x" + b"%d" % k
            + b"/CTX" + b"%04d" % len(ctx) + b":" + bytes(ctx).hex().encode("ascii"))


class SpecTranscript:
    """Spec 5: session id from the tag, the instance first, then the prover messages.
    Labels are ignored (the sponge has none); begin_inner_product is a no-op."""

    def __init__(self, ctx: bytes, G, H, d_gens: bytes):
        if not 1 <= len(ctx) <= 1024:
            raise ValueError("INVALID_CONFIGURATION: ctx")
        self.ctx_bytes = bytes(ctx)
        self.G, self.H, self.d_gens = G, H, d_gens
        self.ds = None
        self.session_id = None
        self.instance = None

    def bind_statement(self, n, V):
        self.session_id = derive_session_id(session_tag(n, self.ctx_bytes))
        self.instance = (serialize_varlen(PROFILE_ID) + C.compress(self.G) + C.compress(self.H)
                         + serialize_varlen(GENSET_ID) + self.d_gens + le(n, 4) + C.compress(V))
        self.ds = DuplexSponge(self.session_id)
        self.ds.absorb(self.instance)

    def absorb_point(self, label, P):
        self.ds.absorb(C.compress(P))

    def absorb_scalar(self, label, s):
        self.ds.absorb(C.i2osp(s, 32))

    def challenge(self, label):
        return int.from_bytes(self.ds.squeeze(48), "little") % Q

    def begin_inner_product(self, n):
        pass


# --------------------------------------------------------------------------
# Codec (spec 3, 6)
# --------------------------------------------------------------------------

def decode_group_element(b):
    status, val = C.strict_decode(b)
    if status != "ok":
        raise bp.ProofFormatError(status, "point", f"step {val}")
    if val is None:
        raise bp.ProofFormatError("MALFORMED_ENCODING", "point", "identity")
    return val


def decode_scalar(b):
    s = C.os2ip(bytes(b))
    if len(b) != 32 or s >= Q:
        raise bp.ProofFormatError("NON_CANONICAL_SCALAR", "scalar", "not in [0, q)")
    return s


def codec():
    return bp.FixedLayoutCodec(48, 32, C.compress, decode_group_element,
                               lambda s: C.i2osp(s, 32), decode_scalar)


def load_generators(path: str | None = None):
    path = path or GENS_PATH
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    names = [g["name"] for g in d["generators"]]
    want = [f"G_{i}" for i in range(64)] + [f"H_{i}" for i in range(64)] + ["U"]
    if names != want:
        raise AssertionError("generators-v1.json order/names")
    encs = [bytes.fromhex(g["compressedHex"]) for g in d["generators"]]
    d_gens = hashlib.sha256(b"".join(encs)).digest()
    pts = [decode_group_element(e) for e in encs]   # strict: on curve, subgroup, not O
    return pts[:64], pts[64:128], pts[128], d_gens, d


def setup():
    G_vec, H_vec, U, d_gens, _ = load_generators()
    G, H = C.derive_basis()
    st = bp.Setup(GROUP, tuple(G_vec), tuple(H_vec), G, H, ipa_base=U,
                  allow_identity_commitment=False)
    return st, d_gens


def test_nonces(seed: bytes):
    """Spec 7.5 (test only): one continuous squeeze stream, 48 octets per nonce."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 octets")
    ds = DuplexSponge(derive_session_id(b"ZeroJ:bulletproof-range-bls12-381-g1-v1/test-nonces-v1"))
    ds.absorb(seed)

    def nxt():
        return int.from_bytes(ds.squeeze(48), "little") % Q
    return nxt


def verify_bytes(st, d_gens, ctx: bytes, V_bytes: bytes, proof_bytes: bytes, n: int):
    """Spec 8.1 order: configuration, length, proof fields, V, identity V."""
    if n not in ALLOWED_N or not 1 <= len(ctx) <= 1024:
        return False, "configuration", None
    try:
        proof = codec().decode(proof_bytes, n)
        status, V = C.strict_decode(V_bytes)
        if status != "ok":
            raise bp.ProofFormatError(status, "statement", "V")
    except bp.ProofFormatError as e:
        return False, e.layer, None
    if V is None:
        return False, "statement", None
    res = bp.verify(st, SpecTranscript(ctx, st.B, st.B_blind, d_gens), V, proof, n)
    return res.ok, res.layer, res
