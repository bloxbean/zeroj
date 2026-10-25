#!/usr/bin/env python3
"""dalek/zkcrypto bulletproofs 5.0.0 binding for bulletproof_generic (ADR-0061 M2).

Everything here is read from the oracle's source (bulletproofs-5.0.0 src/generators.rs,
src/transcript.rs, src/range_proof/{mod,dealer,party}.rs, src/inner_product_proof.rs;
merlin-3.0.0; curve25519-dalek-4.1.3 ristretto.rs / scalar.rs):

  group        ristretto255 (RFC 9496), scalars mod l, 32-octet LITTLE-endian scalars
  PedersenGens B = ristretto255 base point,
               B_blinding = from_uniform_bytes(SHA3-512(encode(B)))
  BulletproofGens(64, 1)
               party 0: label = b"G" ‖ LE32(0) (resp. b"H" ‖ LE32(0));
               reader = SHAKE256(b"GeneratorsChain" ‖ label); each generator is
               from_uniform_bytes(next 64 octets)
  transcript   Merlin; rangeproof_domain_sep(n, m = 1); append V; A, S -> y, z;
               T_1, T_2 -> x; t_x, t_x_blinding, e_blinding -> w; ipp domain sep (n);
               per round L, R -> u.  challenge_scalar = 64 PRF octets, LE, mod l.
  IPA base     Q = w·B (generic ipa_base = B, challenge label "w")
  layout       A S T_1 T_2 t_x t_x_blinding e_blinding (L R)^k a b, 32 octets each

Test use only.  Not constant-time.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct

import bulletproof_generic as bp
import merlin
import ristretto255 as r255

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_PROOFS_PATH = os.path.join(HERE, "dalek-test-proofs.json")
ALLOWED_N = (8, 16, 32, 64)

GROUP = r255.Ristretto255Group()


def pedersen_gens():
    B = r255.GENERATOR
    B_blinding = r255.from_uniform_bytes(hashlib.sha3_512(r255.GENERATOR_ENCODING).digest())
    return B, B_blinding


def generators_chain(label: bytes, count: int):
    stream = hashlib.shake_256(b"GeneratorsChain" + label).digest(64 * count)
    return [r255.from_uniform_bytes(stream[64 * i:64 * (i + 1)]) for i in range(count)]


def bulletproof_gens(capacity: int = 64, party: int = 0):
    lab = struct.pack("<I", party)
    return generators_chain(b"G" + lab, capacity), generators_chain(b"H" + lab, capacity)


_LABELS = {
    "A": b"A", "S": b"S", "y": b"y", "z": b"z", "T1": b"T_1", "T2": b"T_2", "x": b"x",
    "t_hat": b"t_x", "tau_x": b"t_x_blinding", "mu": b"e_blinding", "ipa_base": b"w",
    "L": b"L", "R": b"R", "x_j": b"u",
}


class DalekTranscript:
    """The generic transcript interface over Merlin, with dalek's labels and order."""

    def __init__(self, label: bytes):
        self.t = merlin.Transcript(label)
        self.log = []

    def bind_statement(self, n, V):
        # RangeProof::verify_multiple / Dealer::new + receive_bit_commitments, m = 1.
        self.t.append_message(b"dom-sep", b"rangeproof v1")
        self.t.append_u64(b"n", n)
        self.t.append_u64(b"m", 1)
        self.t.append_message(b"V", r255.encode(V))

    def absorb_point(self, label, P):
        self.t.append_message(_LABELS[label], r255.encode(P))

    def absorb_scalar(self, label, s):
        self.t.append_message(_LABELS[label], r255.scalar_to_bytes(s))

    def challenge(self, label):
        c = r255.scalar_from_wide(self.t.challenge_bytes(_LABELS[label], 64))
        self.log.append((label, c))
        return c

    def begin_inner_product(self, n):
        self.t.append_message(b"dom-sep", b"ipp v1")
        self.t.append_u64(b"n", n)


def _decode_proof_point(b):
    try:
        P = r255.decode(b)
    except r255.DecodeError as e:
        raise bp.ProofFormatError("MALFORMED_ENCODING", "point", str(e))
    if r255.is_identity(P):
        # dalek: validate_and_append_point rejects the identity encoding.
        raise bp.ProofFormatError("MALFORMED_ENCODING", "point", "identity")
    return P


def _decode_scalar(b):
    try:
        return r255.scalar_from_canonical_bytes(b)
    except r255.DecodeError as e:
        raise bp.ProofFormatError("NON_CANONICAL_SCALAR", "scalar", str(e))


CODEC = bp.FixedLayoutCodec(32, 32, r255.encode, _decode_proof_point,
                            r255.scalar_to_bytes, _decode_scalar)


def setup(capacity: int = 64) -> bp.Setup:
    B, B_blinding = pedersen_gens()
    G_vec, H_vec = bulletproof_gens(capacity)
    return bp.Setup(GROUP, tuple(G_vec), tuple(H_vec), B, B_blinding, ipa_base=B,
                    allow_identity_commitment=True)


def decode_commitment(b):
    try:
        return r255.decode(b)
    except r255.DecodeError as e:
        raise bp.ProofFormatError("MALFORMED_ENCODING", "statement", str(e))


def verify_bytes(st: bp.Setup, label: bytes, V_bytes: bytes, proof_bytes: bytes, n: int):
    """Returns (ok, layer, result_or_None)."""
    if n not in ALLOWED_N:
        return False, "configuration", None
    try:
        proof = CODEC.decode(proof_bytes, n)
        V = decode_commitment(V_bytes)
    except bp.ProofFormatError as e:
        return False, e.layer, None
    res = bp.verify(st, DalekTranscript(label), V, proof, n)
    return res.ok, res.layer, res


class ShakeNonces:
    """Test-only deterministic nonce stream: SHAKE256(domain ‖ seed), 64 octets each, mod l."""

    DOMAIN = b"ZeroJ-ADR-0061-M2-dalek-direction-2-test-nonces"

    def __init__(self, seed: bytes):
        self.seed = bytes(seed)
        self.i = 0

    def __call__(self):
        out = hashlib.shake_256(self.DOMAIN + self.seed + struct.pack("<Q", self.i)).digest(64)
        self.i += 1
        return int.from_bytes(out, "little") % r255.L


# --------------------------------------------------------------------------
# dalek's published proofs (tests/range_proof.rs, deserialize_and_verify)
# --------------------------------------------------------------------------

def extract_test_proofs(range_proof_rs_text: str) -> dict:
    """proofs[i][0] (n = 8 << i, m = 1) and vc[0] from tests/range_proof.rs."""
    body = range_proof_rs_text[range_proof_rs_text.index("let proofs = ["):]
    body = body[:body.index("let vc")]
    # Each entry is written  b"<hex>".to_vec(),  inside one inner [ ... ] per bit size.
    groups = re.findall(r"\[\s*((?:b\"[0-9a-f]+\"(?:\.to_vec\(\))?,?\s*)+)\]", body)
    proofs = [re.findall(r"b\"([0-9a-f]+)\"", g) for g in groups]
    vc_part = range_proof_rs_text[range_proof_rs_text.index("let vc"):]
    vcs = re.findall(r"hex::decode\(\"([0-9a-f]{64})\"\)", vc_part)
    label = re.search(r"Transcript::new\(b\"([^\"]+)\"\)", range_proof_rs_text).group(1)
    return {
        "label": label,
        "commitmentHex": vcs[0],
        "allCommitments": vcs,
        "proofs": [{"n": 8 << i, "m": 1, "proofHex": proofs[i][0]} for i in range(len(proofs))],
        "matrixShape": [len(proofs), len(proofs[0]) if proofs else 0],
    }


def load_test_proofs(path: str = TEST_PROOFS_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
