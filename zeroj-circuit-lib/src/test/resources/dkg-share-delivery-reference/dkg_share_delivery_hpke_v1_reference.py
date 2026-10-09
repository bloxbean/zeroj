#!/usr/bin/env python3
"""
Independent reference for the ZeroJ profile `dkg-share-delivery-hpke-v1` (ADR-0054, milestone M0).

Written only from:
  - docs/specs/dkg-share-delivery-hpke-v1.md (the spec under test),
  - docs/adr/0054-hpke-dkg-share-delivery.md (design context),
  - docs/specs/elgamal-jubjub-threshold-v1.md (the DKG it transports),
  - the RFC texts of RFC 9180 (HPKE), RFC 7748 (X25519), RFC 8439 (ChaCha20-Poly1305) and
    RFC 5869 (HKDF),
  - the vendored standard vectors in ../standard-vectors/ (RFC 9180 A.2.1, Wycheproof),
  - the existing independent Python reference of the threshold DKG
    (../elgamal-threshold-reference/elgamal_jubjub_threshold_v1_reference.py), which is imported
    for every DKG mechanic (configs, dealing, SHARE encoding, rounds, QUAL, transcript digest,
    complaints and answers).

No Java source was read. HPKE is assembled here from the RFC 9180 text. The only third-party
primitives are pyca `cryptography`'s X25519, HMAC-SHA256 (and HKDF, used only as a
differential), and ChaCha20Poly1305. An independent pure-Python X25519 ladder transcribed from
RFC 7748 §5 is used as a differential and to evaluate small-order inputs, which pyca refuses.

Run:

    python3 dkg_share_delivery_hpke_v1_reference.py

It prints key=value lines (sorted by key) and rewrites reference-output.txt next to this file.
Exit status 0 iff every check passes; 1 otherwise (the failing keys are listed on stderr).
"""

import hashlib
import importlib.util
import itertools
import json
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))
VEC_DIR = os.path.join(HERE, "..", "standard-vectors")
TREF_PATH = os.path.join(HERE, "..", "elgamal-threshold-reference",
                         "elgamal_jubjub_threshold_v1_reference.py")

sys.dont_write_bytecode = True        # leave no __pycache__ next to the imported reference
_spec = importlib.util.spec_from_file_location("elgamal_threshold_reference", TREF_PATH)
T = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(T)

# =============================================================================
# Output bookkeeping
# =============================================================================

OUT = {}
FAILED = []
CHECKS = []


def emit(key, value):
    if key in OUT:
        raise RuntimeError("duplicate output key " + key)
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, (bytes, bytearray)):
        value = bytes(value).hex()
    OUT[key] = str(value)


def chk(name, cond):
    key = "check." + name
    cond = bool(cond)
    emit(key, cond)
    CHECKS.append(key)
    if not cond:
        FAILED.append(key)
    return cond


def ids(xs):
    return ",".join(str(x) for x in xs)


def pairs_str(ps):
    return ",".join("%d->%d" % p for p in ps)


def i2osp(x, k):
    return x.to_bytes(k, "big")


# =============================================================================
# X25519 (RFC 7748 §5)
# =============================================================================

P25519 = 2 ** 255 - 19
A24 = 121665
ZERO32 = bytes(32)
BASE9 = bytes([9]) + bytes(31)


def decode_scalar25519(k):
    kl = bytearray(k)
    kl[0] &= 248
    kl[31] &= 127
    kl[31] |= 64
    return int.from_bytes(kl, "little")


def decode_u(u):
    ul = bytearray(u)
    ul[31] &= 127                                   # mask the unused bit 255
    return int.from_bytes(ul, "little")


def encode_u(x):
    return (x % P25519).to_bytes(32, "little")


def x25519_ladder(k, u):
    """RFC 7748 §5 Montgomery ladder, transcribed (independent of pyca). Never refuses."""
    k = decode_scalar25519(k)
    x1 = decode_u(u) % P25519                        # non-canonical: processed as reduced
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    p = P25519
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % p
        aa = a * a % p
        b = (x2 - z2) % p
        bb = b * b % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = d * a % p
        cb = c * b % p
        x3 = (da + cb) * (da + cb) % p
        z3 = x1 * (da - cb) * (da - cb) % p
        x2 = aa * bb % p
        z2 = e * (aa + A24 * e) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return encode_u(x2 * pow(z2, p - 2, p))


def x25519(k, u):
    """The X25519 function through pyca. Returns None when pyca refuses: it refuses exactly the
    all-zero output (checked against the ladder over every Wycheproof and small-order input)."""
    try:
        return X25519PrivateKey.from_private_bytes(bytes(k)).exchange(
            X25519PublicKey.from_public_bytes(bytes(u)))
    except ValueError:
        return None


def x25519_pub(sk):
    return X25519PrivateKey.from_private_bytes(bytes(sk)).public_key().public_bytes_raw()


# =============================================================================
# HKDF-SHA256 (RFC 5869) on pyca HMAC
# =============================================================================


def hmac_sha256(key, msg):
    h = hmac.HMAC(bytes(key), hashes.SHA256())
    h.update(bytes(msg))
    return h.finalize()


def hkdf_extract(salt, ikm):
    """RFC 5869 §2.2. An empty salt is HMAC with an empty key, which equals HashLen zero bytes."""
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk, info, length):
    """RFC 5869 §2.3."""
    if length > 255 * 32:
        raise ValueError("HKDF-Expand: L > 255*HashLen")
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:length]


# =============================================================================
# ChaCha20-Poly1305 (RFC 8439 §2.8) through pyca
# =============================================================================


class OpenError(Exception):
    pass


def aead_seal(key, nonce, aad, pt):
    return ChaCha20Poly1305(bytes(key)).encrypt(bytes(nonce), bytes(pt), bytes(aad))


def aead_open(key, nonce, aad, ct):
    try:
        return ChaCha20Poly1305(bytes(key)).decrypt(bytes(nonce), bytes(ct), bytes(aad))
    except (InvalidTag, ValueError):
        raise OpenError()


# =============================================================================
# HPKE (RFC 9180), Base mode, suite (0x0020, 0x0001, 0x0003)
# =============================================================================

KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0003
NSECRET, NENC, NPK, NSK, NH, NK, NN, NT = 32, 32, 32, 32, 32, 32, 12, 16
MODE_BASE = 0x00
SUITE_KEM = b"KEM" + i2osp(KEM_ID, 2)                                       # §4.1
SUITE_HPKE = b"HPKE" + i2osp(KEM_ID, 2) + i2osp(KDF_ID, 2) + i2osp(AEAD_ID, 2)  # §5.1


class ValidationError(Exception):
    pass


class MessageLimitReachedError(Exception):
    pass


def labeled_extract(suite, salt, label, ikm):
    """RFC 9180 §4."""
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    """RFC 9180 §4."""
    return hkdf_expand(prk, i2osp(length, 2) + b"HPKE-v1" + suite + label + info, length)


def dh(sk, pk):
    """DH for DHKEM(X25519): RFC 9180 §7.1.4, all-zero output refused (sender and recipient)."""
    if len(pk) != NPK:
        raise ValidationError("public key length")
    out = x25519(sk, pk)
    if out is None or out == ZERO32:
        raise ValidationError("all-zero DH output")
    return out


def extract_and_expand(dh_out, kem_context):
    """RFC 9180 §4.1."""
    eae_prk = labeled_extract(SUITE_KEM, b"", b"eae_prk", dh_out)
    return labeled_expand(SUITE_KEM, eae_prk, b"shared_secret", kem_context, NSECRET)


def derive_key_pair(ikm):
    """RFC 9180 §7.1.3 for X25519: sk = LabeledExpand(dkp_prk, "sk", "", Nsk)."""
    dkp_prk = labeled_extract(SUITE_KEM, b"", b"dkp_prk", ikm)
    sk = labeled_expand(SUITE_KEM, dkp_prk, b"sk", b"", NSK)
    return sk, x25519_pub(sk)


def encap(pkR, skE):
    """RFC 9180 §4.1 Encap with the ephemeral key supplied (deterministic test seam)."""
    pkE = x25519_pub(skE)
    dh_out = dh(skE, pkR)
    enc = pkE                                      # SerializePublicKey is the identity (§7.1.1)
    kem_context = enc + pkR
    return extract_and_expand(dh_out, kem_context), enc


def decap(enc, skR):
    """RFC 9180 §4.1 Decap."""
    if len(enc) != NENC:
        raise ValidationError("enc length")
    dh_out = dh(skR, enc)
    pkRm = x25519_pub(skR)
    return extract_and_expand(dh_out, enc + pkRm)


class Context:
    """RFC 9180 §5.2 context with a sequence number (role-agnostic here; each instance is used
    for one role only)."""

    def __init__(self, key, base_nonce, seq, exporter_secret):
        self.key, self.base_nonce, self.seq, self.exporter_secret = key, base_nonce, seq, exporter_secret

    def compute_nonce(self, seq):
        seq_bytes = i2osp(seq, NN)
        return bytes(a ^ b for a, b in zip(self.base_nonce, seq_bytes))

    def increment_seq(self):
        if self.seq >= (1 << (8 * NN)) - 1:
            raise MessageLimitReachedError()
        self.seq += 1

    def seal(self, aad, pt):
        ct = aead_seal(self.key, self.compute_nonce(self.seq), aad, pt)
        self.increment_seq()
        return ct

    def open(self, aad, ct):
        pt = aead_open(self.key, self.compute_nonce(self.seq), aad, ct)
        self.increment_seq()
        return pt

    def export(self, exporter_context, length):
        """RFC 9180 §5.3 (used only for the A.2.1 known answers; the profile does not export)."""
        return labeled_expand(SUITE_HPKE, self.exporter_secret, b"sec", exporter_context, length)


def verify_psk_inputs(mode, psk, psk_id):
    got_psk, got_psk_id = psk != b"", psk_id != b""
    if got_psk != got_psk_id:
        raise ValueError("Inconsistent PSK inputs")
    if got_psk and mode == MODE_BASE:
        raise ValueError("PSK input provided when not needed")


def key_schedule(mode, shared_secret, info, psk=b"", psk_id=b"", trace=None):
    """RFC 9180 §5.1."""
    verify_psk_inputs(mode, psk, psk_id)
    psk_id_hash = labeled_extract(SUITE_HPKE, b"", b"psk_id_hash", psk_id)
    info_hash = labeled_extract(SUITE_HPKE, b"", b"info_hash", info)
    ksc = bytes([mode]) + psk_id_hash + info_hash
    secret = labeled_extract(SUITE_HPKE, shared_secret, b"secret", psk)
    key = labeled_expand(SUITE_HPKE, secret, b"key", ksc, NK)
    base_nonce = labeled_expand(SUITE_HPKE, secret, b"base_nonce", ksc, NN)
    exporter_secret = labeled_expand(SUITE_HPKE, secret, b"exp", ksc, NH)
    if trace is not None:
        trace.update(key_schedule_context=ksc, secret=secret, key=key, base_nonce=base_nonce,
                     exporter_secret=exporter_secret)
    return Context(key, base_nonce, 0, exporter_secret)


def setup_base_s(pkR, info, skE, trace=None):
    shared_secret, enc = encap(pkR, skE)
    if trace is not None:
        trace["shared_secret"] = shared_secret
    return enc, key_schedule(MODE_BASE, shared_secret, info, trace=trace)


def setup_base_r(enc, skR, info, trace=None):
    shared_secret = decap(enc, skR)
    if trace is not None:
        trace["shared_secret"] = shared_secret
    return key_schedule(MODE_BASE, shared_secret, info, trace=trace)


def seal_base(pkR, info, aad, pt, skE, trace=None):
    """RFC 9180 §6.1 SealBase (single shot: sequence number 0 only)."""
    enc, ctx = setup_base_s(pkR, info, skE, trace)
    return enc, ctx.seal(aad, pt)


def open_base(enc, skR, info, aad, ct):
    """RFC 9180 §6.1 OpenBase."""
    return setup_base_r(enc, skR, info).open(aad, ct)


def seal_with_dh(dh_out, enc, pkRm, info, aad, pt):
    """Adversarial helper (vectors only): what a sender gets for a chosen DH value and enc.
    It skips every validation, so it can build ciphertexts that only the profile's checks
    refuse."""
    ss = extract_and_expand(dh_out, enc + pkRm)
    return key_schedule(MODE_BASE, ss, info).seal(aad, pt)


def open_unchecked(enc, skR, info, aad, ct):
    """Adversarial helper: OpenBase with the ladder, no all-zero check, no canonicality check.
    Used only to show that a check is what refuses a vector ("would open without it")."""
    try:
        dh_out = x25519_ladder(skR, enc)
        ss = extract_and_expand(dh_out, enc + x25519_pub(skR))
        return key_schedule(MODE_BASE, ss, info).open(aad, ct)
    except OpenError:
        return None


# =============================================================================
# Profile constants (spec §1, §3.1, §4.1, §2.2, §9.1)
# =============================================================================

TAG_A = b"zeroj.dkg-share-delivery-hpke.v1.announce"
TAG_I = b"zeroj.dkg-share-delivery-hpke.v1.info"
TAG_E = b"zeroj.dkg-share-delivery-hpke.v1.envelope"
TEST_PREFIX = b"zeroj.dkg-share-delivery-hpke.v1.test."
PROBE = bytes([0x09]) + bytes(31)
ANNOUNCE_LEN = len(TAG_A) + 32 + 1 + 32
ENVELOPE_LEN = len(TAG_E) + 32 + 1 + 1 + 32 + 116
INFO_LEN = len(TAG_I) + 32 + 1 + 1
SHARE_LEN = 100
CT_LEN = SHARE_LEN + NT
# Offsets inside ENVELOPE = TAG_E ‖ session ‖ u8(i) ‖ u8(j) ‖ enc ‖ ct
E_SESSION = len(TAG_E)
E_I = E_SESSION + 32
E_J = E_I + 1
E_ENC = E_J + 1
E_CT = E_ENC + 32

KEY_REGISTRY = {}       # tag -> sk: every §9.1 test key this run derives (uniqueness checks)
EPHEMERAL_TAGS = []     # every ephemeral tag actually used to seal


def sk_tag(tag):
    """§9.1: sk(tag) = SHA-256(ASCII(prefix) ‖ ASCII(tag)), used as a 32-byte X25519 scalar."""
    sk = hashlib.sha256(TEST_PREFIX + tag.encode("ascii")).digest()
    KEY_REGISTRY[tag] = sk
    return sk


def is_canonical(b):
    """§2.1: bit 255 clear and u < p (checked on the bytes, before any X25519 call)."""
    return len(b) == 32 and (b[31] & 0x80) == 0 and int.from_bytes(b, "little") < P25519


def probe_ok(pk):
    """§2.2: X25519(PROBE, pkR) ≠ 0^32 (pyca refusal is the all-zero output)."""
    out = x25519(PROBE, pk)
    return out is not None and out != ZERO32


# ---------------------------------------------------------------- §3 announcements


def make_announce(session, j, pk):
    return TAG_A + session + bytes([j]) + pk


def parse_announce(cfg, b):
    """§3.1 well-formedness. Returns ((j, pk), None) or (None, reason)."""
    if len(b) != ANNOUNCE_LEN or not b.startswith(TAG_A):
        return None, "length_or_tag"
    o = len(TAG_A)
    session, j, pk = b[o:o + 32], b[o + 32], b[o + 33:o + 65]
    if session != cfg.session:
        return None, "session"
    if not 1 <= j <= cfg.n:
        return None, "index"
    if not is_canonical(pk):
        return None, "non_canonical"
    if not probe_ok(pk):
        return None, "small_order"
    return (j, pk), None


def directory(cfg, posts):
    """§3.2 from delivered posts [(authenticated sender, bytes)]: a key for j iff exactly one
    distinct well-formed announcement from j, authenticated as j."""
    per = {j: set() for j in range(1, cfg.n + 1)}
    for auth, raw in posts:
        parsed, _ = parse_announce(cfg, raw)
        if parsed is None or parsed[0] != auth:
            continue
        per[parsed[0]].add(raw)                    # byte-identical copies count once
    out = {}
    for j in range(1, cfg.n + 1):
        out[j] = parse_announce(cfg, next(iter(per[j])))[0][1] if len(per[j]) == 1 else None
    return out


# ---------------------------------------------------------------- §7 recipient keys


class KeyLifecycleError(Exception):
    pass


class RecipientKey:
    """§7: a recipient key pair bound to one (session, j); destroyable (best effort)."""

    def __init__(self, session, j, sk):
        self.session, self.j, self._sk = session, j, sk
        self.pk = x25519_pub(sk)

    def destroy(self):
        self._sk = None

    def open_base(self, session, j, enc, info, ct):
        if self._sk is None:
            raise KeyLifecycleError("destroyed")
        if session != self.session or j != self.j:
            raise KeyLifecycleError("key bound to another (session, j)")
        return open_base(enc, self._sk, info, b"", ct)


# ---------------------------------------------------------------- §4 envelopes


def make_info(session, i, j):
    return TAG_I + session + bytes([i, j])


def envelope_bytes(session, i, j, enc, ct):
    return TAG_E + session + bytes([i, j]) + enc + ct


def seal_envelope(cfg, i, j, pkR, share, eph_tag, trace=None):
    """§4.1 with the ephemeral key sk(eph_tag) (deterministic vectors)."""
    EPHEMERAL_TAGS.append(eph_tag)
    info = make_info(cfg.session, i, j)
    enc, ct = seal_base(pkR, info, b"", share, sk_tag(eph_tag), trace)
    if trace is not None:
        trace.update(info=info, enc=enc, ct=ct)
    return envelope_bytes(cfg.session, i, j, enc, ct)


def open_envelope(cfg, j, rk, env, auth):
    """§4.2, the 6-step acceptance rule. Returns (SHARE bytes, None) or (None, failing step).
    `auth` is the participant the post is authenticated as (None: unauthenticated)."""
    if len(env) != ENVELOPE_LEN or not env.startswith(TAG_E):
        return None, 1
    session, i, jj = env[E_SESSION:E_I], env[E_I], env[E_J]
    if session != cfg.session or not 1 <= i <= cfg.n or jj != j or i == j:
        return None, 2
    if auth != i:
        return None, 3
    enc, ct = env[E_ENC:E_CT], env[E_CT:]
    if not is_canonical(enc):
        return None, 4
    try:
        pt = rk.open_base(cfg.session, j, enc, make_info(cfg.session, i, j), ct)
    except (ValidationError, OpenError, KeyLifecycleError):
        return None, 5
    m, _ = T.parse(cfg, pt)
    if m is None or m.kind != 2 or m.sender != i or m.subject != j:
        return None, 6
    return pt, None


def dedup_bytes_first(items):
    """NEGATIVE CONTROL ONLY: de-duplicate (auth, bytes) items by bytes BEFORE authentication,
    keeping the first in board order. This is the defect the spec's §4.2 rule forbids: an
    unauthentic earlier copy then shadows the genuine post."""
    seen, out = set(), []
    for auth, data in items:
        if data not in seen:
            seen.add(data)
            out.append((auth, data))
    return out


def deliver(cfg, j, rk, envs, dedup_before_auth=False):
    """§4.2 over several envelopes [(auth, bytes)] in board order. Each envelope is authenticated
    (step 3) on its own, and only then are byte-identical accepted envelopes and byte-identical
    plaintexts counted once, so an unauthenticated copy can never shadow the genuine post.
    Returns the sorted distinct SHAREs per header sender."""
    if dedup_before_auth:
        envs = dedup_bytes_first(envs)
    out = {}
    for auth, env in envs:
        pt, _ = open_envelope(cfg, j, rk, env, auth)
        if pt is not None:
            out.setdefault(env[E_I], set()).add(pt)
    return {i: sorted(v) for i, v in out.items()}


# =============================================================================
# §5: a board with windows, cutoffs, processing lags, the barrier and the posting order
# =============================================================================
#
# Time is an integer. Round 0 (announcements) is the window [0, cut0); round 1 (envelopes and
# COMMITMENTS) is [cut0, cut1). A post's time is its inclusion (= finality) time on the board.
# A post outside its round's window belongs to no window (spec §5).
# Processing: participant j finishes processing post p at p.time + lag(j, p.label) (default 0).
#   - barrier on (§5.1): j advances only after processing every post of the final window.
#   - barrier off (negative control): j closes the round at the cutoff by timer and uses only the
#     posts it finished processing before the cutoff.
# Sealing happens at cut0 (timer) or, under the barrier, once round 0 is fully processed.
# Envelope (i, j) is included at seal_time + env_delay(i, j) (default 1).
# COMMITMENTS: with D7a (§5.2), included at (last envelope time) + commit_delay, and not posted at
# all if some envelope is not included before cut1; without D7a, at seal_time + commit_delay.
# Rounds 2-7 of the DKG are run by the threshold reference's `simulate` with timely broadcast.


class Post:
    __slots__ = ("time", "author", "label", "data")

    def __init__(self, time, author, label, data):
        self.time, self.author, self.label, self.data = time, author, label, data

    def sort_key(self):
        return (self.time, self.author or 0, self.label, self.data)


class Scenario:
    def __init__(self, name, cfg, prefix, cut0=10, cut1=20, barrier=True, d7a=True, t1=True,
                 ann_time=None, ann_pk=None, extra0=(), lag=None, env_delay=None,
                 commit_delay=1, corrupted=(), extra_complaints=(), no_t1=(),
                 dedup_before_auth=False, front_run=(), suppress=(), withhold_extraction=()):
        self.name, self.cfg, self.prefix = name, cfg, prefix
        self.cut0, self.cut1 = cut0, cut1
        self.barrier, self.d7a, self.t1 = barrier, d7a, t1
        self.ann_time = ann_time or {}
        self.ann_pk = ann_pk or {}
        self.extra0 = list(extra0)
        self.lag = lag or {}
        self.env_delay = env_delay or {}
        self.commit_delay = commit_delay
        self.corrupted = sorted(corrupted)
        self.extra_complaints = list(extra_complaints)
        self.no_t1 = sorted(no_t1)                      # deviating (corrupted) participants
        self.dedup_before_auth = dedup_before_auth      # NEGATIVE CONTROL of §4.2 / threshold §5
        self.front_run = list(front_run)                # (label, by): earlier copy authenticated as `by`
        self.suppress = set(suppress)                   # labels of honest posts not made
        self.withhold_extraction = sorted(withhold_extraction)
        self.key_tags = {j: "%s.recipient.%d" % (prefix, j) for j in range(1, cfg.n + 1)}
        self.rk = {j: RecipientKey(cfg.session, j, sk_tag(self.key_tags[j]))
                   for j in range(1, cfg.n + 1)}


def lag_of(scn, j, p):
    return scn.lag.get((j, p.label), 0)


def processed(scn, j, window, cutoff):
    if scn.barrier:
        return list(window)
    return [p for p in window if p.time + lag_of(scn, j, p) < cutoff]


_DEALINGS = {}


def dealing(cfg):
    if cfg.session not in _DEALINGS:
        a, b = T.coeffs_from_tags(cfg.n, cfg.t)
        _DEALINGS[cfg.session] = (a, b, T.deal(cfg, a, b, T.H))
    return _DEALINGS[cfg.session]


def round0_views(scn, posts):
    cfg = scn.cfg
    w0 = [p for p in posts if 0 <= p.time < scn.cut0]
    dirs, t1set = {}, set()
    for j in range(1, cfg.n + 1):
        items = [(p.author, p.data) for p in processed(scn, j, w0, scn.cut0)]
        if scn.dedup_before_auth:
            items = dedup_bytes_first(items)
        dirs[j] = directory(cfg, items)
        # §3.3 T1: no key for j, or a key other than the one j announced (the key j holds).
        if scn.t1 and j not in scn.no_t1 and dirs[j][j] != scn.rk[j].pk:
            t1set.add(j)
    return w0, dirs, t1set


def generate_board(scn):
    """The honest behaviour of every participant in rounds 0 and 1, as board posts."""
    cfg = scn.cfg
    _, _, dl = dealing(cfg)
    posts = []
    for j in range(1, cfg.n + 1):
        tm = scn.ann_time.get(j, 1)
        if tm is not None and "announce.%d" % j not in scn.suppress:
            pk = scn.ann_pk.get(j, scn.rk[j].pk)
            posts.append(Post(tm, j, "announce.%d" % j, make_announce(cfg.session, j, pk)))
    posts += scn.extra0
    w0, dirs, t1set = round0_views(scn, posts)
    for i in range(1, cfg.n + 1):
        if i in t1set:
            continue                                   # T1: posts nothing further
        seal_t = scn.cut0
        if scn.barrier:
            seal_t = max([scn.cut0] + [p.time + lag_of(scn, i, p) for p in w0])
        env_times = []
        for j in range(1, cfg.n + 1):
            if j == i or dirs[i][j] is None:
                continue                               # no self-envelope; none without a key
            share = T.m_share(cfg, i, j, dl[i]["s"][j], dl[i]["sp"][j])
            env = seal_envelope(cfg, i, j, dirs[i][j], share, "%s.ephemeral.%d.%d" % (scn.prefix, i, j))
            tm = seal_t + scn.env_delay.get((i, j), 1)
            posts.append(Post(tm, i, "envelope.%d.%d" % (i, j), env))
            env_times.append(tm)
        commit = T.m_commitments(cfg, i, dl[i]["C"])
        if "commitments.%d" % i in scn.suppress:
            continue
        if scn.d7a:
            if all(tm < scn.cut1 for tm in env_times):
                posts.append(Post(max(env_times + [seal_t]) + scn.commit_delay, i, "commitments.%d" % i, commit))
        else:
            posts.append(Post(seal_t + scn.commit_delay, i, "commitments.%d" % i, commit))
    for label, by in scn.front_run:                    # a byte-identical copy, one tick earlier
        orig = next(p for p in posts if p.label == label)
        posts.append(Post(orig.time - 1, by, label + ".copy_by_%d" % by, orig.data))
    return sorted(posts, key=Post.sort_key)


def evaluate_board(scn, posts):
    """Everything that follows from the board: directory, T1, deliveries, then rounds 2-7."""
    cfg = scn.cfg
    a, b, dl = dealing(cfg)
    t, n = cfg.t, cfg.n
    w0, dirs, t1set = round0_views(scn, posts)
    common = directory(cfg, [(p.author, p.data) for p in w0])
    w1 = [p for p in posts if scn.cut0 <= p.time < scn.cut1]
    w1_items = [(p.author, p.data) for p in w1]
    if scn.dedup_before_auth:
        w1_items = dedup_bytes_first(w1_items)
    sc = T.Script()
    for i in range(1, n + 1):
        # Threshold §4/§5: a broadcast counts only if authenticated as its header sender; only
        # then are byte-identical copies counted once.
        raws = sorted({d for a, d in w1_items if a == i and T.parse(cfg, d)[0] is not None
                       and T.parse(cfg, d)[0].kind == 1 and d[34] == i})
        sc.commit[i] = [T.parse(cfg, r)[0].points for r in raws]
    for i in scn.withhold_extraction:
        sc.extraction[i] = []
    for j in range(1, n + 1):
        shares = {}
        if j not in t1set:
            envs = [(p.author, p.data) for p in processed(scn, j, w1, scn.cut1)
                    if p.data.startswith(TAG_E) and len(p.data) > E_J and p.data[E_J] == j]
            shares = deliver(cfg, j, scn.rk[j], envs, scn.dedup_before_auth)
        for i in range(1, n + 1):
            if i != j:
                sc.private_raw[(i, j)] = shares.get(i, [])
    sc.complaint_ok = lambda j, i: j not in t1set
    for d in t1set:
        for c in range(1, n + 1):
            sc.answer[(d, c)] = None
    sc.extra[2] = [T.m_complaint(cfg, c, d) for c, d in scn.extra_complaints]
    sim = T.simulate(cfg, a, b, sc=sc)
    res = sim["res"]
    dv = res["dv"]
    out = {
        "directory": common,
        "t1": sorted(t1set),
        "commitments": [i for i in range(1, n + 1) if sc.commit[i]],
        "complaints": sorted((m.sender, m.subject) for m in dv.ordered(2)),
        "answers": sorted((m.sender, m.subject) for m in dv.ordered(3)),
        "qual": list(res["qual"]),
        "aborts": {j: "T1" if j in t1set else (sim["pab"][j] or "none") for j in range(1, n + 1)},
        "public_abort": res["abort"],
        "digest": res["digest"],
        "y": T.encode(res["y"]) if res.get("y") is not None else None,
        "Y": {j: T.encode(res["Y"][j]) for j in range(1, n + 1)} if res.get("Y") else None,
        "marked": sorted(res.get("marked", {})),
        "reconstructed": sorted(res.get("recon", {})),
        "sim": sim,
        "sc": sc,
    }
    # Coalition analysis (corrupted set): what the corrupted participants can compute.
    C = set(scn.corrupted)
    recovered, wrong = {}, []
    for i in res["qual"]:
        if i in C:
            recovered[i] = dl[i]["a"][0]
            continue
        pts = {}
        for c in C:
            if (i, c) in sim["own"]:
                pts[c] = sim["own"][(i, c)][0]          # received privately or by answer
        for m in dv.ordered(3):
            if m.sender == i:
                pts[m.subject] = m.pair[0]               # public answers
        if len(pts) >= t + 1:
            z = T.interpolate(sorted(pts.items())[:t + 1])[0]
            recovered[i] = z
            if z != dl[i]["a"][0]:
                wrong.append(i)
    x_true = sum(dl[i]["a"][0] for i in res["qual"]) % T.L
    out["recovered_dealers"] = sorted(recovered)
    out["recovered_wrong"] = wrong
    out["coalition_recovers_x"] = (len(res["qual"]) > 0 and all(i in recovered for i in res["qual"])
                                   and sum(recovered.values()) % T.L == x_true)
    honest_qual = [i for i in res["qual"] if i not in C]
    out["honest_answers"] = [(i, c) for (i, c) in out["answers"] if i in honest_qual]
    out["honest_answers_corrupted_only"] = all(c in C for (_, c) in out["honest_answers"])
    return out


def outcome_items(out, n):
    """The expected-outcome keys of a board vector."""
    items = [("expect.directory.%d" % j, out["directory"][j].hex() if out["directory"][j] else "none")
             for j in range(1, n + 1)]
    items += [
        ("expect.t1", ids(out["t1"])),
        ("expect.commitments", ids(out["commitments"])),
        ("expect.complaints", pairs_str(out["complaints"])),
        ("expect.answers", pairs_str(out["answers"])),
        ("expect.qual", ids(out["qual"])),
        ("expect.marked", ids(out["marked"])),
        ("expect.aborts", ",".join("%d:%s" % (j, out["aborts"][j]) for j in range(1, n + 1))),
        ("expect.public_abort", out["public_abort"] or "none"),
        ("expect.digest", out["digest"].hex()),
        ("expect.y", out["y"].hex() if out["y"] else "none"),
        ("expect.coalition_recovers_x", "true" if out["coalition_recovers_x"] else "false"),
        ("expect.honest_answers_at_corrupted_indices_only",
         "true" if out["honest_answers_corrupted_only"] else "false"),
    ]
    return items


def config_str(cfg):
    return "%d,%d,%s,%d" % (cfg.t, cfg.n, cfg.ctx.hex(), cfg.attempt)


def cfg_from_str(s):
    t, n, ctx, att = s.split(",")
    return T.Config(int(t), int(n), bytes.fromhex(ctx), int(att), T.roster(int(n)))


def board_items(scn, posts):
    cfg = scn.cfg
    items = [("config", config_str(cfg)), ("cut0", str(scn.cut0)), ("cut1", str(scn.cut1)),
             ("barrier", "true" if scn.barrier else "false"),
             ("d7a", "true" if scn.d7a else "false"),
             ("t1_rule", "true" if scn.t1 else "false"),
             ("corrupted", ids(scn.corrupted)),
             ("t1_ignored_by", ids(scn.no_t1)),
             ("dedup_before_auth", "true" if scn.dedup_before_auth else "false"),
             ("withhold_extraction", ids(scn.withhold_extraction))]
    items += [("recipient_key_tag.%d" % j, scn.key_tags[j]) for j in range(1, cfg.n + 1)]
    for k, p in enumerate(posts, 1):
        items.append(("post.%d" % k, "%d,%s,%s,%s" % (p.time, p.author, p.label, p.data.hex())))
    for (j, label), v in sorted(scn.lag.items()):
        if v:
            items.append(("lag.%d.%s" % (j, label), str(v)))
    for k, (c, d) in enumerate(scn.extra_complaints, 1):
        items.append(("extra_complaint.%d" % k, "%d->%d" % (c, d)))
    return items


def replay_board(items):
    """Rebuild the scenario from its emitted keys only and re-evaluate it."""
    d = dict(items)
    cfg = cfg_from_str(d["config"])
    scn = Scenario("replay", cfg, "replay", cut0=int(d["cut0"]), cut1=int(d["cut1"]),
                   barrier=d["barrier"] == "true", d7a=d["d7a"] == "true",
                   t1=d["t1_rule"] == "true",
                   corrupted=[int(x) for x in d["corrupted"].split(",") if x],
                   no_t1=[int(x) for x in d["t1_ignored_by"].split(",") if x],
                   dedup_before_auth=d["dedup_before_auth"] == "true",
                   withhold_extraction=[int(x) for x in d["withhold_extraction"].split(",") if x])
    scn.key_tags = {j: d["recipient_key_tag.%d" % j] for j in range(1, cfg.n + 1)}
    scn.rk = {j: RecipientKey(cfg.session, j, sk_tag(scn.key_tags[j])) for j in range(1, cfg.n + 1)}
    posts = []
    for k, v in items:
        if k.startswith("post."):
            tm, au, label, hx = v.split(",")
            posts.append(Post(int(tm), int(au) if au != "None" else None, label, bytes.fromhex(hx)))
        elif k.startswith("lag."):
            _, j, label = k.split(".", 2)
            scn.lag[(int(j), label)] = int(v)
        elif k.startswith("extra_complaint."):
            c, dd = v.split("->")
            scn.extra_complaints.append((int(c), int(dd)))
    out = evaluate_board(scn, posts)
    return dict(outcome_items(out, cfg.n)) == {k: v for k, v in items if k.startswith("expect.")}


# =============================================================================
# Known-answer tests of the primitives, through the exact code paths above
# =============================================================================


def load_vec(name):
    with open(os.path.join(VEC_DIR, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def h(s):
    return bytes.fromhex("".join(s.split()))


def kat_rfc7748():
    # §5.2, transcribed from the RFC text.
    vecs = [
        ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
         "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
         "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
         "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
    ]
    for k, (sc, u, o) in enumerate(vecs, 1):
        chk("rfc7748.s5_2.vector%d.pyca" % k, x25519(h(sc), h(u)) == h(o))
        chk("rfc7748.s5_2.vector%d.ladder" % k, x25519_ladder(h(sc), h(u)) == h(o))
    # Note: the second u-coordinate has bit 255 set (0x93): RFC 7748 masks it. That input is a
    # non-canonical public value, which the profile refuses at the message layer (§2.1).
    emit("info.rfc7748.s5_2.vector2_u_bit255_set", (h(vecs[1][1])[31] & 0x80) != 0)
    emit("info.rfc7748.s5_2.vector2_u_canonical_per_profile", is_canonical(h(vecs[1][1])))
    # §5.2 iterations: 1 and 1,000 (1,000,000 is not run: ~1 minute in pyca, hours in the ladder).
    k_p, u_p = BASE9, BASE9
    k_l, u_l = BASE9, BASE9
    res_p, res_l = {}, {}
    for it in range(1, 1001):
        k_p, u_p = x25519(k_p, u_p), k_p
        k_l, u_l = x25519_ladder(k_l, u_l), k_l
        if it in (1, 1000):
            res_p[it], res_l[it] = k_p, k_l
    exp = {1: "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
           1000: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"}
    for it in (1, 1000):
        chk("rfc7748.s5_2.iterations_%d.pyca" % it, res_p[it] == h(exp[it]))
        chk("rfc7748.s5_2.iterations_%d.ladder" % it, res_l[it] == h(exp[it]))
    emit("info.rfc7748.s5_2.iterations_1000000", "not run (cost); the 1 and 1000 iterations are")
    # §6.1
    a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    KA = h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    KB = h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    K = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    chk("rfc7748.s6_1.alice_public", x25519_pub(a) == KA and x25519_ladder(a, BASE9) == KA)
    chk("rfc7748.s6_1.bob_public", x25519_pub(b) == KB and x25519_ladder(b, BASE9) == KB)
    chk("rfc7748.s6_1.shared_alice", dh(a, KB) == K and x25519_ladder(a, KB) == K)
    chk("rfc7748.s6_1.shared_bob", dh(b, KA) == K and x25519_ladder(b, KA) == K)


def kat_wycheproof_x25519():
    d = load_vec("wycheproof-x25519_test.json")
    cnt = {}
    bad = []
    zero_publics = set()
    nonzero_publics = set()

    def inc(k):
        cnt[k] = cnt.get(k, 0) + 1

    for g in d["testGroups"]:
        for tc in g["tests"]:
            sk, pk, shared, res = h(tc["private"]), h(tc["public"]), h(tc["shared"]), tc["result"]
            inc("total")
            inc("result." + res)
            out_p, out_l = x25519(sk, pk), x25519_ladder(sk, pk)
            try:
                out_dh = dh(sk, pk)
            except ValidationError:
                out_dh = None
            canon = is_canonical(pk)
            ucanon = encode_u(decode_u(pk))
            if shared == ZERO32:
                zero_publics.add(ucanon)
                ok = out_l == ZERO32 and out_p is None and out_dh is None
                inc("%s.zero_shared.dh_refused" % res if ok else "fail")
                inc("%s.zero_shared.profile_refuses_public" % res
                    if not (canon and probe_ok(pk)) else "%s.zero_shared.profile_accepts_public" % res)
            else:
                nonzero_publics.add(ucanon)
                ok = out_l == shared and out_p == shared and out_dh == shared
                inc("%s.nonzero.computed_equal" % res if ok else "fail")
                inc("%s.nonzero.profile_canonical" % res if canon else "%s.nonzero.profile_non_canonical_refused" % res)
            if res == "invalid":
                ok = False                             # none exist in this file; would need a rule
            if not ok:
                bad.append(tc["tcId"])
    for k in sorted(cnt):
        emit("info.wycheproof.x25519.count." + k, cnt[k])
    emit("info.wycheproof.x25519.failed_tcIds", ids(bad))
    emit("info.wycheproof.x25519.acceptable_handling",
         "non-zero shared: X25519 computed and equal (pyca and ladder, RFC 7748 accepts twist and "
         "non-canonical inputs); zero shared: ladder gives 0^32, pyca refuses, the HPKE DH refuses "
         "(RFC 9180 §7.1.4); the profile refuses every non-canonical public value (§2.1) and every "
         "small-order one (§2.2, enc via the zero check)")
    chk("wycheproof.x25519.all_%d_tests" % cnt["total"], not bad and cnt["total"] == d["numberOfTests"])
    return zero_publics, nonzero_publics


def kat_rfc8439_and_wycheproof():
    pt = h("""4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c 65 6d 65 6e 20 6f 66 20 74 68 65 20
              63 6c 61 73 73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63 6f 75 6c 64 20 6f 66 66
              65 72 20 79 6f 75 20 6f 6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20 74 68 65 20
              66 75 74 75 72 65 2c 20 73 75 6e 73 63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69
              74 2e""")
    aad = h("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7")
    key = bytes(range(0x80, 0xa0))
    nonce = h("07 00 00 00") + h("40 41 42 43 44 45 46 47")
    ct = h("""d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2 a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7
              36 ee 62 d6 3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b 1a 71 de 0a 9e 06 0b 29
              05 d6 a5 b6 7e cd 3b 36 92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 fa b3 24 e4
              fa d6 75 94 55 85 80 8b 48 31 d7 bc 3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
              61 16""")
    tag = h("1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91")
    chk("rfc8439.s2_8_2.seal", aead_seal(key, nonce, aad, pt) == ct + tag)
    chk("rfc8439.s2_8_2.open", aead_open(key, nonce, aad, ct + tag) == pt)
    bad_tag = ct + tag[:-1] + bytes([tag[-1] ^ 1])
    try:
        aead_open(key, nonce, aad, bad_tag)
        refused = False
    except OpenError:
        refused = True
    chk("rfc8439.s2_8_2.modified_tag_refused", refused)

    d = load_vec("wycheproof-chacha20_poly1305_test.json")
    cnt, bad = {}, []
    for g in d["testGroups"]:
        for tc in g["tests"]:
            k_, iv, a_, m, c, tg = (h(tc[x]) for x in ("key", "iv", "aad", "msg", "ct", "tag"))
            cnt[tc["result"]] = cnt.get(tc["result"], 0) + 1
            if tc["result"] == "valid":
                try:
                    ok = aead_seal(k_, iv, a_, m) == c + tg and aead_open(k_, iv, a_, c + tg) == m
                except (ValueError, OpenError):
                    ok = False
            else:
                try:
                    aead_open(k_, iv, a_, c + tg)
                    ok = False
                except OpenError:
                    ok = True
            if not ok:
                bad.append(tc["tcId"])
    for k in sorted(cnt):
        emit("info.wycheproof.chacha20_poly1305.count." + k, cnt[k])
    emit("info.wycheproof.chacha20_poly1305.failed_tcIds", ids(bad))
    chk("wycheproof.chacha20_poly1305.all_%d_tests" % sum(cnt.values()),
        not bad and sum(cnt.values()) == d["numberOfTests"])


def kat_rfc5869_and_wycheproof():
    vecs = [
        ("A1", "0b" * 22, "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
         "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
        ("A2", bytes(range(0x00, 0x50)).hex(), bytes(range(0x60, 0xb0)).hex(),
         bytes(range(0xb0, 0x100)).hex(), 82,
         "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
         "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
         "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
         "cc30c58179ec3e87c14c01d5c1f3434f1d87"),
        ("A3", "0b" * 22, "", "", 42,
         "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
    ]
    for name, ikm, salt, info, L_, prk, okm in vecs:
        p_ = hkdf_extract(h(salt), h(ikm))
        chk("rfc5869.%s.prk" % name, p_ == h(prk))
        chk("rfc5869.%s.okm" % name, hkdf_expand(p_, h(info), L_) == h(okm))
    d = load_vec("wycheproof-hkdf_sha256_test.json")
    cnt, bad = {}, []
    for g in d["testGroups"]:
        for tc in g["tests"]:
            ikm, salt, info, size = h(tc["ikm"]), h(tc["salt"]), h(tc["info"]), tc["size"]
            cnt[tc["result"]] = cnt.get(tc["result"], 0) + 1
            try:
                mine = hkdf_expand(hkdf_extract(salt, ikm), info, size)
            except ValueError:
                mine = None
            try:
                theirs = HKDF(algorithm=hashes.SHA256(), length=size, salt=salt, info=info).derive(ikm)
            except ValueError:
                theirs = None
            if tc["result"] == "valid":
                ok = mine == h(tc["okm"]) and theirs == mine
            else:
                ok = mine is None and theirs is None
            if not ok:
                bad.append(tc["tcId"])
    for k in sorted(cnt):
        emit("info.wycheproof.hkdf_sha256.count." + k, cnt[k])
    emit("info.wycheproof.hkdf_sha256.failed_tcIds", ids(bad))
    chk("wycheproof.hkdf_sha256.all_%d_tests" % sum(cnt.values()),
        not bad and sum(cnt.values()) == d["numberOfTests"])


def kat_rfc9180_a21():
    v = load_vec("hpke-x25519-sha256-chacha20poly1305-base.json")
    chk("rfc9180.a21.file_has_one_vector", len(v) == 1)
    v = v[0]
    chk("rfc9180.a21.suite", (v["mode"], v["kem_id"], v["kdf_id"], v["aead_id"]) ==
        (MODE_BASE, KEM_ID, KDF_ID, AEAD_ID))
    skE, pkE = derive_key_pair(h(v["ikmE"]))
    skR, pkR = derive_key_pair(h(v["ikmR"]))
    chk("rfc9180.a21.derive_key_pair.skEm", skE == h(v["skEm"]))
    chk("rfc9180.a21.derive_key_pair.pkEm", pkE == h(v["pkEm"]))
    chk("rfc9180.a21.derive_key_pair.skRm", skR == h(v["skRm"]))
    chk("rfc9180.a21.derive_key_pair.pkRm", pkR == h(v["pkRm"]))
    # RFC 9180 §7.1.2 says SerializePrivateKey MUST clamp; the A.2.1 private keys are the raw
    # DeriveKeyPair outputs (not clamped). The profile never serializes private keys.
    emit("info.rfc9180.a21.skRm_is_clamped", decode_scalar25519(skR).to_bytes(32, "little") == skR)
    emit("info.rfc9180.a21.skEm_is_clamped", decode_scalar25519(skE).to_bytes(32, "little") == skE)
    info = h(v["info"])
    tr = {}
    enc, ctxS = setup_base_s(h(v["pkRm"]), info, h(v["skEm"]), tr)
    chk("rfc9180.a21.encap.enc", enc == h(v["enc"]))
    chk("rfc9180.a21.encap.shared_secret", tr["shared_secret"] == h(v["shared_secret"]))
    chk("rfc9180.a21.decap.shared_secret", decap(h(v["enc"]), h(v["skRm"])) == h(v["shared_secret"]))
    for k in ("key_schedule_context", "secret", "key", "base_nonce", "exporter_secret"):
        chk("rfc9180.a21.key_schedule.%s" % k, tr[k] == h(v[k]))
    ctxR = setup_base_r(h(v["enc"]), h(v["skRm"]), info)
    bad = []
    for seq, e in enumerate(v["encryptions"]):
        ok = ctxS.seq == seq and ctxS.compute_nonce(seq) == h(e["nonce"])
        ok = ok and ctxS.seal(h(e["aad"]), h(e["pt"])) == h(e["ct"])
        try:
            ok = ok and ctxR.open(h(e["aad"]), h(e["ct"])) == h(e["pt"])
        except OpenError:
            ok = False
        if not ok:
            bad.append(seq)
    emit("info.rfc9180.a21.encryptions.count", len(v["encryptions"]))
    emit("info.rfc9180.a21.encryptions.failed_seqs", ids(bad))
    chk("rfc9180.a21.encryptions.all_seq_0_to_256",
        not bad and len(v["encryptions"]) == 257)
    for k, e in enumerate(v["exports"]):
        chk("rfc9180.a21.export.%d" % k,
            ctxS.export(h(e["exporter_context"]), e["L"]) == h(e["exported_value"]) and
            ctxR.export(h(e["exporter_context"]), e["L"]) == h(e["exported_value"]))
    e0 = v["encryptions"][0]
    enc1, ct1 = seal_base(h(v["pkRm"]), info, h(e0["aad"]), h(e0["pt"]), h(v["skEm"]))
    chk("rfc9180.a21.single_shot.seal_base", enc1 == h(v["enc"]) and ct1 == h(e0["ct"]))
    chk("rfc9180.a21.single_shot.open_base",
        open_base(h(v["enc"]), h(v["skRm"]), info, h(e0["aad"]), h(e0["ct"])) == h(e0["pt"]))
    # Negatives on the published vector.
    for name, args in (("wrong_info", (h(v["enc"]), h(v["skRm"]), info + b"x", h(e0["aad"]), h(e0["ct"]))),
                       ("wrong_aad", (h(v["enc"]), h(v["skRm"]), info, b"", h(e0["ct"]))),
                       ("wrong_key", (h(v["enc"]), h(v["skEm"]), info, h(e0["aad"]), h(e0["ct"]))),
                       ("seq1_ct_at_seq0", (h(v["enc"]), h(v["skRm"]), info, h(v["encryptions"][1]["aad"]),
                                            h(v["encryptions"][1]["ct"])))):
        try:
            open_base(*args)
            refused = False
        except (OpenError, ValidationError):
            refused = True
        chk("rfc9180.a21.negative.%s_refused" % name, refused)
    c = Context(b"\0" * 32, b"\0" * 12, (1 << 96) - 1, b"")
    try:
        c.increment_seq()
        over = False
    except MessageLimitReachedError:
        over = True
    chk("rfc9180.s5_2.sequence_overflow_raises", over)
    try:
        key_schedule(MODE_BASE, b"\0" * 32, b"", psk=b"x", psk_id=b"y")
        psk_refused = False
    except ValueError:
        psk_refused = True
    chk("rfc9180.s5_1.base_mode_refuses_psk", psk_refused)


# =============================================================================
# §2.2: small-order points, independently
# =============================================================================

MONT_A = 486662


def sqrt_p25519(a):
    a %= P25519
    if a == 0:
        return 0
    c = pow(a, (P25519 + 3) // 8, P25519)
    if c * c % P25519 == a:
        return c
    c = c * pow(2, (P25519 - 1) // 4, P25519) % P25519
    return c if c * c % P25519 == a else None


def x_double(x):
    """x([2]P) on y^2 = x^3 + A x^2 + x (curve or twist; x-only); None for the point at infinity."""
    den = 4 * x * (x * x + MONT_A * x + 1) % P25519
    if den == 0:
        return None
    return pow(x * x - 1, 2, P25519) * pow(den, P25519 - 2, P25519) % P25519


def halvings(c):
    """Every x in F_p with x([2]P) = c: w = x + 1/x solves w^2 - 4cw - (4 + 4cA) = 0."""
    out = set()
    s = sqrt_p25519(4 * c * c + 4 + 4 * c * MONT_A)
    if s is None:
        return out
    inv2 = pow(2, P25519 - 2, P25519)
    for w in {(2 * c + s) % P25519, (2 * c - s) % P25519}:
        r = sqrt_p25519(w * w - 4)
        if r is None:
            continue
        for x in {(w + r) * inv2 % P25519, (w - r) * inv2 % P25519}:
            if x != 0 and x_double(x) == c:
                out.add(x)
    return out


def small_order_algebraic():
    """All x in F_p of points with [8]P = O on the curve or its twist, by repeated halving."""
    order2 = {0}
    s = sqrt_p25519(MONT_A * MONT_A - 4)
    if s is not None:
        inv2 = pow(2, P25519 - 2, P25519)
        order2 |= {(-MONT_A + s) * inv2 % P25519, (-MONT_A - s) * inv2 % P25519}
    order4 = set().union(*(halvings(c) for c in order2))
    order8 = set().union(*(halvings(c) for c in order4)) if order4 else set()
    order16 = set().union(*(halvings(c) for c in order8)) if order8 else set()
    return order2, order4, order8, order16


def small_order_section(zero_publics, nonzero_publics):
    wy = sorted(int.from_bytes(u, "little") for u in zero_publics)
    o2, o4, o8, o16 = small_order_algebraic()
    alg = sorted(o2 | o4 | o8)
    emit("small_order.wycheproof_canonical_u", ",".join("%064x" % u for u in wy))
    emit("small_order.algebraic.order2", ",".join("%064x" % u for u in sorted(o2)))
    emit("small_order.algebraic.order4", ",".join("%064x" % u for u in sorted(o4)))
    emit("small_order.algebraic.order8", ",".join("%064x" % u for u in sorted(o8)))
    chk("small_order.algebraic_equals_wycheproof_set", alg == wy)
    chk("small_order.no_order16_points", not o16)
    emit("small_order.count", len(wy))
    # The spec's claim: X25519(k, u) = 0^32 for one clamped scalar iff for all of them, iff u is
    # small-order. Checked for PROBE and five other test scalars on every small-order u, and for
    # PROBE on every other public value in the Wycheproof file.
    scalars = [PROBE] + [sk_tag("small-order.scalar.%d" % k) for k in range(1, 6)]
    zero_all = all(x25519_ladder(k, encode_u(u)) == ZERO32 for u in wy for k in scalars)
    chk("small_order.every_scalar_gives_zero_on_every_small_order_u", zero_all)
    chk("small_order.probe_nonzero_on_every_other_wycheproof_public",
        all(x25519_ladder(PROBE, u) != ZERO32 for u in nonzero_publics))
    chk("small_order.pyca_refuses_exactly_the_small_order_u",
        all(x25519(PROBE, encode_u(u)) is None for u in wy) and
        all(x25519(PROBE, u) is not None for u in nonzero_publics))
    chk("small_order.probe_ok_false_on_all", not any(probe_ok(encode_u(u)) for u in wy))
    return wy


# =============================================================================
# Replayable vectors
# =============================================================================

CASES = []          # (family, name, items, replay)


def add_case(family, name, items, replay):
    CASES.append((family, name, list(items), replay))


def set_bit255(b):
    return b[:31] + bytes([b[31] | 0x80])


def le32(x):
    return x.to_bytes(32, "little")


HONEST_CTX = b"zeroj.test.honest"


def make_cfgs():
    return {
        "honest-2of3": T.Config(1, 3, HONEST_CTX, 1, T.roster(3)),
        "honest-3of5": T.Config(2, 5, HONEST_CTX, 1, T.roster(5)),
        "honest-4of7": T.Config(3, 7, HONEST_CTX, 1, T.roster(7)),
        "honest-2of3-attempt2": T.Config(1, 3, HONEST_CTX, 2, T.roster(3)),
        "honest-3of5-attempt2": T.Config(2, 5, HONEST_CTX, 2, T.roster(5)),
    }


# ---------------------------------------------------------------- announce


def replay_announce(items):
    d = dict(items)
    parsed, _ = parse_announce(cfg_from_str(d["config"]), bytes.fromhex(d["bytes"]))
    return ("accept" if parsed is not None else "reject") == d["expect"]


def announce_family(cfgs, small_order_u):
    cfg, cfg2 = cfgs["honest-2of3"], cfgs["honest-2of3-attempt2"]
    pk = {j: x25519_pub(sk_tag("announce.recipient.%d" % j)) for j in (1, 2, 3)}
    good = make_announce(cfg.session, 1, pk[1])
    chk("profile.announce_length_106", len(good) == ANNOUNCE_LEN == 106)
    cases = [
        ("well_formed_j1", good, "accept"),
        ("well_formed_j_n", make_announce(cfg.session, 3, pk[3]), "accept"),
        ("wrong_tag_first_byte", bytes([good[0] ^ 1]) + good[1:], "reject"),
        ("tag_of_envelope", TAG_E + good[len(TAG_A):], "reject"),
        ("length_105", good[:-1], "reject"),
        ("length_107", good + b"\x00", "reject"),
        ("other_session", make_announce(cfg2.session, 1, pk[1]), "reject"),
        ("j_zero", make_announce(cfg.session, 0, pk[1]), "reject"),
        ("j_n_plus_1", make_announce(cfg.session, 4, pk[1]), "reject"),
        ("non_canonical_bit255_set", make_announce(cfg.session, 1, set_bit255(pk[1])), "reject"),
        ("non_canonical_u_p", make_announce(cfg.session, 1, le32(P25519)), "reject"),
        ("non_canonical_u_p_plus_1", make_announce(cfg.session, 1, le32(P25519 + 1)), "reject"),
        ("non_canonical_u_p_plus_9", make_announce(cfg.session, 1, le32(P25519 + 9)), "reject"),
        ("non_canonical_u_2_255_minus_1", make_announce(cfg.session, 1, le32(2 ** 255 - 1)), "reject"),
        ("canonical_u_p_minus_2", make_announce(cfg.session, 1, le32(P25519 - 2)), "accept"),
        ("canonical_base_point_u_9", make_announce(cfg.session, 1, BASE9), "accept"),
    ]
    for k, u in enumerate(small_order_u, 1):
        cases.append(("small_order_%d" % k, make_announce(cfg.session, 1, le32(u)), "reject"))
    ok_all = True
    for name, b, intended in cases:
        parsed, why = parse_announce(cfg, b)
        got = "accept" if parsed is not None else "reject"
        ok_all &= chk("announce.%s" % name, got == intended)
        items = [("config", config_str(cfg)), ("bytes", b.hex()), ("expect", got),
                 ("reason", why or "none")]
        if name.startswith("small_order_"):
            items.append(("u", "%064x" % small_order_u[int(name.rsplit("_", 1)[1]) - 1]))
        add_case("announce", name, items, replay_announce)


# ---------------------------------------------------------------- envelope


def with_header(env, session=None, i=None, j=None):
    s = env[E_SESSION:E_I] if session is None else session
    ii = env[E_I] if i is None else i
    jj = env[E_J] if j is None else j
    return TAG_E + s + bytes([ii, jj]) + env[E_ENC:]


def envelope_outcome(cfg, j, rk, envs):
    got = deliver(cfg, j, rk, envs)
    pts = sorted(pt for v in got.values() for pt in v)
    if not pts:
        return "absent"
    if len(pts) == 1:
        return "share:" + pts[0].hex()
    return "shares:" + ",".join(p.hex() for p in pts)


def envelope_outcome_dedup_first(cfg, j, rk, envs):
    """NEGATIVE CONTROL: the outcome if envelopes were de-duplicated before authentication."""
    got = deliver(cfg, j, rk, envs, dedup_before_auth=True)
    pts = sorted(pt for v in got.values() for pt in v)
    return "absent" if not pts else "share:" + pts[0].hex() if len(pts) == 1 else "shares"


def replay_envelope(items):
    d = dict(items)
    cfg = cfg_from_str(d["config"])
    j = int(d["recipient"])
    rk = RecipientKey(cfg.session, j, sk_tag(d["recipient_key_tag"]))
    envs = []
    for k, v in items:
        if k == "bytes" or k.startswith("bytes."):
            sfx = k[len("bytes"):]
            au = d["auth" + sfx]
            envs.append((None if au == "none" else int(au), bytes.fromhex(v)))
    return envelope_outcome(cfg, j, rk, envs) == d["expect"]


def envelope_family(cfgs, small_order_u):
    cfg, cfg2 = cfgs["honest-2of3"], cfgs["honest-2of3-attempt2"]
    _, _, dl = dealing(cfg)
    tag = {j: "envelope.recipient.%d" % j for j in (1, 2, 3)}
    rk = {j: RecipientKey(cfg.session, j, sk_tag(tag[j])) for j in (1, 2, 3)}
    tag2 = "envelope.attempt2.recipient.2"
    s12, sp12 = dl[1]["s"][2], dl[1]["sp"][2]
    share12 = T.m_share(cfg, 1, 2, s12, sp12)
    info12 = make_info(cfg.session, 1, 2)
    tr = {}
    good = seal_envelope(cfg, 1, 2, rk[2].pk, share12, "envelope.ephemeral.good", tr)
    chk("profile.info_length_71", len(info12) == INFO_LEN == 71)
    chk("profile.share_length_100", len(share12) == SHARE_LEN)
    chk("profile.ct_length_116", len(tr["ct"]) == CT_LEN == 116)
    chk("profile.envelope_length_223", len(good) == ENVELOPE_LEN == 223)
    good_items = [("info", tr["info"].hex()), ("enc", tr["enc"].hex()), ("ct", tr["ct"].hex()),
                  ("plaintext", share12.hex()), ("pkR", rk[2].pk.hex()),
                  ("ephemeral_tag", "envelope.ephemeral.good"),
                  ("shared_secret", tr["shared_secret"].hex()), ("key", tr["key"].hex()),
                  ("base_nonce", tr["base_nonce"].hex()),
                  ("key_schedule_context", tr["key_schedule_context"].hex())]
    skE_good = sk_tag("envelope.ephemeral.good")
    # This profile's §9.3 table (second revision): drift checks against values copied from here.
    s93 = {"pkR": "504988081ce259944f19570f5e350690a094ec9d519d9c41e20c355c4939d96a",
           "enc": "b9886d82301676564de05a8ace89f381e6421f55d634db0194093db4bc733d12",
           "shared_secret": "0af8f73bda0aa3472c9dfc33df93d80647bdd1612bfd2316d83c3c46022bd8e7",
           "key": "a50c772753344ab621250e97d7be47778df5114d1703a701e0ab16c1703e3e6f",
           "base_nonce": "a13c0a5653e198c69e43a28b",
           "ct": "d898640e561c28fa2f1256ff43dbb3f03b61fe44f15577bcf715434119db5be2faf267425d83e29475d62b7a"
                 "3f82fdd98994c385fb537b1d595b67021e048fa21bb4e467e4432ed55d8282edbe3c735ae7e28b54322539f3df"
                 "54d7d31ce761da2028a60045b07987e39b92e44acd84f34431cbf7"}
    gi = dict(good_items)
    for k_, v_ in s93.items():
        chk("spec_match.s9_3.envelope.good.%s" % k_, gi[k_] == v_)
    chk("spec_match.s9_3.envelope.good.info",
        gi["info"] == "7a65726f6a2e646b672d73686172652d64656c69766572792d68706b652e76312e696e666f"
        + cfg.session.hex() + "0102")
    pkR2 = rk[2].pk

    def seal_pt(name, pt, i=1, j=2, pk=None, session_cfg=None):
        c = session_cfg or cfg
        EPHEMERAL_TAGS.append("envelope.ephemeral." + name)
        info = make_info(c.session, i, j)
        enc, ct = seal_base(pk or pkR2, info, b"", pt, sk_tag("envelope.ephemeral." + name))
        return envelope_bytes(c.session, i, j, enc, ct)

    def adversarial(enc, dh_out, pt=share12):
        return envelope_bytes(cfg.session, 1, 2, enc, seal_with_dh(dh_out, enc, pkR2, info12, b"", pt))

    flip = lambda b, pos: b[:pos] + bytes([b[pos] ^ 1]) + b[pos + 1:]
    ok_hex = "share:" + share12.hex()
    alt12 = T.m_share(cfg, 1, 2, (s12 + 1) % T.L, sp12)
    c = []      # (name, cfg, recipient, key_tag, [(auth, bytes)], intended outcome, intended step)
    c.append(("good", cfg, 2, tag[2], [(1, good)], ok_hex, None))
    c.append(("duplicate_byte_identical", cfg, 2, tag[2], [(1, good), (1, good)], ok_hex, None))
    c.append(("duplicate_unauthentic_copy_first", cfg, 2, tag[2], [(3, good), (1, good)], ok_hex, None))
    c.append(("reencrypted_same_share", cfg, 2, tag[2],
              [(1, good), (1, seal_pt("reencrypted", share12))], ok_hex, None))
    c.append(("two_different_shares_conflict", cfg, 2, tag[2],
              [(1, good), (1, seal_pt("conflict", alt12))],
              "shares:" + ",".join(x.hex() for x in sorted([share12, alt12])), None))
    c.append(("wrong_session_header", cfg, 2, tag[2], [(1, with_header(good, session=cfg2.session))], "absent", 2))
    c.append(("sender_zero", cfg, 2, tag[2], [(1, with_header(good, i=0))], "absent", 2))
    c.append(("sender_n_plus_1", cfg, 2, tag[2], [(1, with_header(good, i=4))], "absent", 2))
    c.append(("self_envelope_i_equals_j", cfg, 2, tag[2], [(2, seal_pt("self", share12, i=2, j=2))], "absent", 2))
    c.append(("wrong_recipient_header_seen_by_2", cfg, 2, tag[2], [(1, with_header(good, j=3))], "absent", 2))
    c.append(("wrong_recipient_header_opened_by_3", cfg, 3, tag[3], [(1, with_header(good, j=3))], "absent", 5))
    c.append(("wrong_sender_header_auth_mismatch", cfg, 2, tag[2], [(1, with_header(good, i=3))], "absent", 3))
    c.append(("unauthenticated", cfg, 2, tag[2], [(None, good)], "absent", 3))
    c.append(("reposted_by_other_sender", cfg, 2, tag[2], [(3, with_header(good, i=3))], "absent", 5))
    c.append(("wrong_recipient_key", cfg, 2, tag[2], [(1, seal_pt("wrong_key", share12, pk=rk[3].pk))], "absent", 5))
    c.append(("tampered_enc_byte0", cfg, 2, tag[2], [(1, flip(good, E_ENC))], "absent", 5))
    c.append(("tampered_ct_byte0", cfg, 2, tag[2], [(1, flip(good, E_CT))], "absent", 5))
    c.append(("tampered_tag_last_byte", cfg, 2, tag[2], [(1, flip(good, ENVELOPE_LEN - 1))], "absent", 5))
    c.append(("truncated_222", cfg, 2, tag[2], [(1, good[:-1])], "absent", 1))
    c.append(("extended_224", cfg, 2, tag[2], [(1, good + b"\x00")], "absent", 1))
    c.append(("wrong_tag_first_byte", cfg, 2, tag[2], [(1, flip(good, 0))], "absent", 1))
    c.append(("tag_of_announce", cfg, 2, tag[2], [(1, TAG_A + good[len(TAG_E):])], "absent", 1))
    pkE = x25519_pub(skE_good)
    nc255 = adversarial(set_bit255(pkE), dh(skE_good, pkR2))
    ncp9 = adversarial(le32(P25519 + 9), pkR2)            # X25519(skR, 9) = pkR: DH is public
    c.append(("non_canonical_enc_bit255_set", cfg, 2, tag[2], [(1, nc255)], "absent", 4))
    c.append(("non_canonical_enc_u_p_plus_9", cfg, 2, tag[2], [(1, ncp9)], "absent", 4))
    c.append(("canonical_enc_u_9_control", cfg, 2, tag[2], [(1, adversarial(BASE9, pkR2))], ok_hex, None))
    for k, u in enumerate(small_order_u, 1):
        c.append(("small_order_enc_%d" % k, cfg, 2, tag[2], [(1, adversarial(le32(u), ZERO32))], "absent", 5))
    c.append(("non_canonical_small_order_enc_u_p", cfg, 2, tag[2], [(1, adversarial(le32(P25519), ZERO32))], "absent", 4))
    c.append(("non_canonical_small_order_enc_u_p_plus_1", cfg, 2, tag[2],
              [(1, adversarial(le32(P25519 + 1), ZERO32))], "absent", 4))
    c.append(("cross_attempt_replay", cfg2, 2, tag2, [(1, good)], "absent", 2))
    c.append(("cross_attempt_replay_header_rewritten", cfg2, 2, tag2,
              [(1, with_header(good, session=cfg2.session))], "absent", 5))
    c.append(("cross_attempt_replay_header_rewritten_key_reused", cfg2, 2, tag[2],
              [(1, with_header(good, session=cfg2.session))], "absent", 5))
    c.append(("plaintext_answer_message", cfg, 2, tag[2],
              [(1, seal_pt("pt_answer", T.m_answer(cfg, 1, 2, s12, sp12)))], "absent", 6))
    rnd = hashlib.sha256(b"envelope.random.0").digest() * 4
    c.append(("plaintext_random_100_bytes", cfg, 2, tag[2], [(1, seal_pt("pt_random", rnd[:100]))], "absent", 6))
    c.append(("plaintext_share_wrong_sender", cfg, 2, tag[2],
              [(1, seal_pt("pt_wrong_sender", T.m_share(cfg, 3, 2, dl[3]["s"][2], dl[3]["sp"][2])))], "absent", 6))
    c.append(("plaintext_share_wrong_subject", cfg, 2, tag[2],
              [(1, seal_pt("pt_wrong_subject", T.m_share(cfg, 1, 3, dl[1]["s"][3], dl[1]["sp"][3])))], "absent", 6))
    c.append(("plaintext_share_other_session", cfg, 2, tag[2],
              [(1, seal_pt("pt_other_session", T.m_share(cfg2, 1, 2, s12, sp12)))], "absent", 6))
    c.append(("plaintext_share_scalar_not_below_l", cfg, 2, tag[2],
              [(1, seal_pt("pt_scalar_l", T.m_share(cfg, 1, 2, T.L, sp12)))], "absent", 6))
    c.append(("plaintext_99_bytes", cfg, 2, tag[2], [(1, seal_pt("pt_99", share12[:-1]))], "absent", 1))
    for name, ccfg, j, ktag, envs, intended, step in c:
        key = RecipientKey(ccfg.session, j, sk_tag(ktag))
        got = envelope_outcome(ccfg, j, key, envs)
        steps = sorted({open_envelope(ccfg, j, key, e, a)[1] or 0 for a, e in envs})
        got_step = None if 0 in steps else steps[0]       # multi: None if any envelope accepted
        chk("envelope.%s" % name, got == intended and got_step == step)
        items = [("config", config_str(ccfg)), ("recipient", str(j)), ("recipient_key_tag", ktag)]
        if len(envs) == 1:
            items += [("auth", "none" if envs[0][0] is None else str(envs[0][0])), ("bytes", envs[0][1].hex())]
        else:
            for k, (a, e) in enumerate(envs, 1):
                items += [("auth.%d" % k, "none" if a is None else str(a)), ("bytes.%d" % k, e.hex())]
        items += [("expect", got), ("step", "none" if got_step is None else str(got_step))]
        if name == "good":
            items += good_items
        add_case("envelope", name, items, replay_envelope)
    chk("envelope.duplicate_unauthentic_copy_first.dedup_before_auth_would_lose_share",
        envelope_outcome_dedup_first(cfg, 2, rk[2], [(3, good), (1, good)]) == "absent")
    # The checks are what refuse these: without them, OpenBase would deliver the share.
    chk("envelope.non_canonical_enc_bit255_set.opens_without_step4",
        open_unchecked(nc255[E_ENC:E_CT], sk_tag(tag[2]), info12, b"", nc255[E_CT:]) == share12)
    chk("envelope.non_canonical_enc_u_p_plus_9.opens_without_step4",
        open_unchecked(ncp9[E_ENC:E_CT], sk_tag(tag[2]), info12, b"", ncp9[E_CT:]) == share12)
    chk("envelope.small_order_enc.all_open_without_zero_check",
        all(open_unchecked(le32(u), sk_tag(tag[2]), info12, b"",
                           adversarial(le32(u), ZERO32)[E_CT:]) == share12 for u in small_order_u))
    # §7 lifecycle, as far as an API model can show it.
    k2 = RecipientKey(cfg.session, 2, sk_tag(tag[2]))
    before = open_envelope(cfg, 2, k2, good, 1)[0] == share12
    k2.destroy()
    chk("lifecycle.open_after_destroy_refused", before and open_envelope(cfg, 2, k2, good, 1) == (None, 5))
    k_other = RecipientKey(cfg2.session, 2, sk_tag(tag[2]))
    chk("lifecycle.key_bound_to_other_session_refused", open_envelope(cfg, 2, k_other, good, 1) == (None, 5))
    k_wrong_j = RecipientKey(cfg.session, 3, sk_tag(tag[2]))
    chk("lifecycle.key_bound_to_other_recipient_refused",
        open_envelope(cfg, 2, k_wrong_j, good, 1) == (None, 5))
    chk("profile.threshold_decode_refuses_envelope", T.parse(cfg, good)[0] is None)


# ---------------------------------------------------------------- board families


def replay_board_case(items):
    return replay_board(items)


def add_board_case(family, name, scn, posts, out, intent):
    """Emit a board vector; `intent` maps expect.* keys to the values this case is built to show."""
    items = board_items(scn, posts) + outcome_items(out, scn.cfg.n)
    got = dict(items)
    ok = all(got.get(k) == v for k, v in intent.items())
    if not ok:
        for k, v in intent.items():
            if got.get(k) != v:
                sys.stderr.write("intent mismatch %s.%s %s: got %s want %s\n" % (family, name, k, got.get(k), v))
    chk("%s.%s.intended_outcome" % (family, name), ok)
    chk("%s.%s.no_wrong_reconstruction" % (family, name), not out["recovered_wrong"])
    chk("%s.%s.no_self_envelope" % (family, name),
        all(p.data[E_I] != p.data[E_J] for p in posts if p.data.startswith(TAG_E)))
    add_case(family, name, items, replay_board_case)
    return got


def directory_family(cfgs):
    cfg = cfgs["honest-3of5"]
    other = cfgs["honest-3of5-attempt2"]
    # Participant 5 is corrupted: it announces a copy of 1's key and, deviating, does not apply
    # T1 (its directory key is not the key it holds).
    scn = Scenario("directory", cfg, "directory", corrupted=[5], no_t1=[5])
    rk = scn.rk
    s = cfg.session
    scn.extra0 = [
        Post(5, 2, "announce.2.copy", make_announce(s, 2, rk[2].pk)),
        Post(3, 1, "announce.forged_for_2", make_announce(s, 2, x25519_pub(sk_tag("directory.forged.2")))),
        Post(2, 3, "announce.3.second", make_announce(s, 3, x25519_pub(sk_tag("directory.recipient.3.second")))),
        Post(2, 5, "announce.5.malformed", make_announce(s, 5, set_bit255(rk[5].pk))),
        Post(4, 1, "announce.1.other_session",
             make_announce(other.session, 1, x25519_pub(sk_tag("directory.other_session.1")))),
        Post(11, 1, "announce.1.late", make_announce(s, 1, x25519_pub(sk_tag("directory.recipient.1.late")))),
    ]
    scn.ann_time = {4: 12}                 # participant 4's only announcement misses the cutoff
    scn.ann_pk = {5: rk[1].pk}             # participant 5 copies participant 1's key
    posts = generate_board(scn)
    out = evaluate_board(scn, posts)
    intent = {"expect.directory.1": rk[1].pk.hex(), "expect.directory.2": rk[2].pk.hex(),
              "expect.directory.3": "none", "expect.directory.4": "none",
              "expect.directory.5": rk[1].pk.hex(), "expect.t1": "3,4",
              "expect.commitments": "1,2,5", "expect.complaints": "5->1,5->2",
              "expect.answers": "1->5,2->5", "expect.qual": "1,2,5",
              "expect.aborts": "1:none,2:none,3:T1,4:T1,5:none",
              "expect.honest_answers_at_corrupted_indices_only": "true"}
    add_board_case("directory", "mixed_window_3of5", scn, posts, out, intent)
    # Two conflicts at 2-of-3: both participants abort with T1, R1 leaves |QUAL| = 1 < n - t (A1).
    c3 = cfgs["honest-2of3"]
    scn3 = Scenario("directory2", c3, "directory.conflicts")
    scn3.extra0 = [Post(2, j, "announce.%d.second" % j,
                        make_announce(c3.session, j, x25519_pub(sk_tag("directory.conflicts.recipient.%d.second" % j))))
                   for j in (2, 3)]
    posts3 = generate_board(scn3)
    out3 = evaluate_board(scn3, posts3)
    add_board_case("directory", "two_conflicts_2of3_A1", scn3, posts3, out3,
                   {"expect.directory.1": scn3.rk[1].pk.hex(), "expect.directory.2": "none",
                    "expect.directory.3": "none", "expect.t1": "2,3", "expect.commitments": "1",
                    "expect.complaints": "", "expect.qual": "1", "expect.public_abort": "A1",
                    "expect.aborts": "1:A1,2:T1,3:T1", "expect.y": "none"})
    # §3.3 (second revision): a key for j other than the one j holds triggers T1. Participant
    # 2's genuine announcement misses the cutoff, and a substitute authenticated as 2 (a misused
    # roster key) is in the window.
    for name, t1 in (("substituted_key_T1_2of3", True), ("substituted_key_without_T1_negative_control", False)):
        sub = Scenario(name, c3, "directory." + name, t1=t1, ann_time={2: 10})
        sub_pk = x25519_pub(sk_tag("directory.%s.substitute.2" % name))
        sub.extra0 = [Post(3, 2, "announce.2.substitute", make_announce(c3.session, 2, sub_pk))]
        sp = generate_board(sub)
        so = evaluate_board(sub, sp)
        intent = {"expect.directory.2": sub_pk.hex()}
        if t1:
            intent.update({"expect.t1": "2", "expect.commitments": "1,3", "expect.complaints": "",
                           "expect.answers": "", "expect.qual": "1,3",
                           "expect.aborts": "1:none,2:T1,3:none"})
        else:
            intent.update({"expect.t1": "", "expect.complaints": "2->1,2->3",
                           "expect.answers": "1->2,3->2",
                           "expect.honest_answers_at_corrupted_indices_only": "false"})
        add_board_case("directory", name, sub, sp, so, intent)
    # D4: a copied key only hurts the copier. The victim can decrypt envelopes to the copier
    # (they are sealed to its key), but cannot be made to accept one as its own.
    env25 = next((p.data for p in posts if p.label == "envelope.2.5"), None)
    if not chk("directory.copied_key.envelope_2_to_5_sealed_to_copied_key", env25 is not None):
        return
    pt = open_base(env25[E_ENC:E_CT], sk_tag(scn.key_tags[1]), make_info(s, 2, 5), b"", env25[E_CT:])
    emit("info.directory.copied_key.victim_can_decrypt_envelope_2_to_5", pt is not None)
    chk("directory.copied_key.victim_cannot_be_given_copier_share",
        open_envelope(cfg, 1, rk[1], with_header(env25, j=1), 2) == (None, 5))
    chk("directory.copied_key.copier_cannot_open", open_envelope(cfg, 5, rk[5], env25, 2) == (None, 5))


RUNS = {}


def run_family(cfgs):
    pins = {"honest-2of3": ("2af7f7eae154833d51861bae276448b396eae5479a074a833a31a9fb9aa46023",
                            "14acdc488055720e853cbb6b613d2c7f52aee2fa8e7f37b410b1fa9093082658"),
            "honest-3of5": (None, "89eeef65017eb8f1a18e38a5b9fc0efb971386181e0db4649c60941cd5a6c425"),
            "honest-4of7": ("9b6a52fe5b0fb06feb875b82cb37871e64bc235b01de384ba54a06f96c24431b", None)}
    # This profile's §9.3 table (second revision). Its values were copied from this reference's
    # output, so these are drift checks, not independent evidence.
    s93 = {"honest-2of3": ("2af7f7eae154833d51861bae276448b396eae5479a074a833a31a9fb9aa46023",
                           "14acdc488055720e853cbb6b613d2c7f52aee2fa8e7f37b410b1fa9093082658"),
           "honest-3of5": ("edd7aa9f589992e9801d76987611d293ff921e046da81c3790121d767ffdcf71",
                           "89eeef65017eb8f1a18e38a5b9fc0efb971386181e0db4649c60941cd5a6c425"),
           "honest-4of7": ("9b6a52fe5b0fb06feb875b82cb37871e64bc235b01de384ba54a06f96c24431b",
                           "ba8011aef2b5f23231919caf1c3c901626e7c970436e98386d46b01713616a63")}
    for F in ("honest-2of3", "honest-3of5", "honest-4of7"):
        cfg = cfgs[F]
        a, b, dl = dealing(cfg)
        scn = Scenario(F, cfg, F)
        posts = generate_board(scn)
        out = evaluate_board(scn, posts)
        ideal = T.simulate(cfg, a, b)
        ir, er = ideal["res"], out["sim"]["res"]
        RUNS[F] = (scn, posts, out)
        n = cfg.n
        chk("run.%s.digest_equals_ideal_channels" % F, er["digest"] == ir["digest"])
        chk("run.%s.qual_y_Y_x_equal_ideal" % F,
            er["qual"] == ir["qual"] and er["y"] == ir["y"] and er["Y"] == ir["Y"] and
            out["sim"]["x"] == ideal["x"])
        chk("run.%s.confirmations_equal_ideal" % F, out["sim"]["conf"] == ideal["conf"])
        chk("run.%s.no_aborts_no_complaints" % F,
            all(v == "none" for v in out["aborts"].values()) and not out["complaints"])
        chk("spec_match.s9_3.run.%s.digest" % F, er["digest"].hex() == s93[F][0])
        chk("spec_match.s9_3.run.%s.y" % F, T.encode(er["y"]).hex() == s93[F][1])
        dg, yp = pins[F]
        if dg:
            chk("run.%s.digest_matches_threshold_spec_s11_pin" % F, er["digest"].hex() == dg)
        if yp:
            chk("run.%s.y_matches_threshold_spec_s11_pin" % F, T.encode(er["y"]).hex() == yp)
        envs = {(p.data[E_I], p.data[E_J]): p for p in posts if p.data.startswith(TAG_E)}
        anns = {p.author: p for p in posts if p.data.startswith(TAG_A)}
        chk("run.%s.envelope_count_n_times_n_minus_1" % F, len(envs) == n * (n - 1))
        chk("run.%s.threshold_decode_refuses_transport_posts" % F,
            all(T.parse(cfg, p.data)[0] is None for p in list(envs.values()) + list(anns.values())))
        chk("run.%s.threshold_delivered_round_drops_transport_posts" % F,
            T.delivered_round(cfg, [p.data for p in posts], 1) ==
            sorted([p.data for p in posts if p.label.startswith("commitments")],
                   key=lambda r: T.sort_key(T.parse(cfg, r)[0])))
        same_pt = True
        items = [("config", config_str(cfg)), ("coefficients", "threshold spec §11 tags")]
        for j in range(1, n + 1):
            items += [("recipient_key_tag.%d" % j, scn.key_tags[j]), ("pk.%d" % j, scn.rk[j].pk.hex()),
                      ("announce.%d" % j, anns[j].data.hex())]
        for (i, j), p in sorted(envs.items()):
            pt, _ = open_envelope(cfg, j, scn.rk[j], p.data, i)
            ideal_pt = T.m_share(cfg, i, j, dl[i]["s"][j], dl[i]["sp"][j])
            same_pt &= pt == ideal_pt
            items += [("ephemeral_tag.%d.%d" % (i, j), "%s.ephemeral.%d.%d" % (F, i, j)),
                      ("envelope.%d.%d" % (i, j), p.data.hex()), ("share.%d.%d" % (i, j), pt.hex())]
        chk("run.%s.every_plaintext_is_the_ideal_SHARE" % F, same_pt)
        items += [("expect.digest", er["digest"].hex()), ("expect.qual", ids(er["qual"])),
                  ("expect.y", T.encode(er["y"]).hex())]
        items += [("expect.Y.%d" % j, T.encode(er["Y"][j]).hex()) for j in range(1, n + 1)]
        items += [("expect.ideal_channels_equal", "true" if er["digest"] == ir["digest"] else "false")]
        add_case("run", F, items, replay_run)


def replay_run(items):
    d = dict(items)
    cfg = cfg_from_str(d["config"])
    a, b, _ = dealing(cfg)
    n = cfg.n
    rk = {j: RecipientKey(cfg.session, j, sk_tag(d["recipient_key_tag.%d" % j])) for j in range(1, n + 1)}
    ann = directory(cfg, [(j, bytes.fromhex(d["announce.%d" % j])) for j in range(1, n + 1)])
    ok = all(ann[j] == rk[j].pk for j in range(1, n + 1))
    sc = T.Script()
    for i in range(1, n + 1):
        for j in range(1, n + 1):
            if i != j:
                pt, _ = open_envelope(cfg, j, rk[j], bytes.fromhex(d["envelope.%d.%d" % (i, j)]), i)
                ok = ok and pt is not None and pt.hex() == d["share.%d.%d" % (i, j)]
                sc.private_raw[(i, j)] = [pt] if pt else []
    sim = T.simulate(cfg, a, b, sc=sc)
    ideal = T.simulate(cfg, a, b)
    r = sim["res"]
    ok = ok and r["digest"].hex() == d["expect.digest"] and ids(r["qual"]) == d["expect.qual"]
    ok = ok and T.encode(r["y"]).hex() == d["expect.y"]
    ok = ok and all(T.encode(r["Y"][j]).hex() == d["expect.Y.%d" % j] for j in range(1, n + 1))
    return ok and (r["digest"] == ideal["res"]["digest"]) == (d["expect.ideal_channels_equal"] == "true")


def timing_family(cfgs):
    c3, c5 = cfgs["honest-2of3"], cfgs["honest-3of5"]
    ideal3 = T.simulate(c3, *dealing(c3)[:2])["res"]["digest"].hex()
    ideal5 = T.simulate(c5, *dealing(c5)[:2])["res"]["digest"].hex()
    specs = [
        # (name, cfg, scenario kwargs, intent)
        ("late_processing_with_barrier", c3,
         dict(env_delay={(1, 2): 8, (2, 1): 8},
              lag={(2, "envelope.1.2"): 10, (1, "envelope.2.1"): 10}, corrupted=[3]),
         {"expect.complaints": "", "expect.answers": "", "expect.qual": "1,2,3",
          "expect.digest": ideal3, "expect.coalition_recovers_x": "false",
          "expect.aborts": "1:none,2:none,3:none"}),
        ("late_processing_without_barrier_negative_control", c3,
         dict(barrier=False, env_delay={(1, 2): 8, (2, 1): 8},
              lag={(2, "envelope.1.2"): 10, (1, "envelope.2.1"): 10}, corrupted=[3]),
         {"expect.complaints": "1->2,2->1", "expect.answers": "1->2,2->1", "expect.qual": "1,2,3",
          "expect.coalition_recovers_x": "true",
          "expect.honest_answers_at_corrupted_indices_only": "false",
          "expect.aborts": "1:none,2:none,3:none"}),
        ("delayed_announcement_with_barrier", c3,
         dict(ann_time={2: 9}, lag={(1, "announce.2"): 5, (3, "announce.2"): 5}, corrupted=[3]),
         {"expect.complaints": "", "expect.answers": "", "expect.qual": "1,2,3",
          "expect.digest": ideal3, "expect.t1": ""}),
        ("delayed_announcement_without_barrier_negative_control", c3,
         dict(barrier=False, ann_time={2: 9}, lag={(1, "announce.2"): 5, (3, "announce.2"): 5},
              corrupted=[3]),
         {"expect.complaints": "2->1,2->3", "expect.answers": "1->2,3->2",
          "expect.honest_answers_at_corrupted_indices_only": "false", "expect.t1": ""}),
        ("own_announcement_missing_T1", c3,
         dict(ann_time={2: 10}, corrupted=[3]),
         {"expect.directory.2": "none", "expect.t1": "2", "expect.commitments": "1,3",
          "expect.complaints": "", "expect.answers": "", "expect.qual": "1,3",
          "expect.aborts": "1:none,2:T1,3:none"}),
        ("own_announcement_missing_without_T1_negative_control", c3,
         dict(ann_time={2: 10}, t1=False, corrupted=[3]),
         {"expect.directory.2": "none", "expect.t1": "", "expect.commitments": "1,2,3",
          "expect.complaints": "2->1,2->3", "expect.answers": "1->2,3->2",
          "expect.honest_answers_at_corrupted_indices_only": "false"}),
        ("envelopes_excluded_by_cutoff_D7a", c5,
         dict(env_delay={(5, 1): 12, (5, 2): 12}, corrupted=[3, 4]),
         {"expect.commitments": "1,2,3,4", "expect.complaints": "", "expect.answers": "",
          "expect.qual": "1,2,3,4", "expect.coalition_recovers_x": "false",
          "expect.aborts": "1:none,2:none,3:none,4:none,5:A2"}),
        ("envelopes_excluded_by_cutoff_without_D7a_negative_control", c5,
         dict(d7a=False, env_delay={(5, 1): 12, (5, 2): 12}, corrupted=[3, 4]),
         {"expect.commitments": "1,2,3,4,5", "expect.complaints": "1->5,2->5",
          "expect.answers": "5->1,5->2", "expect.qual": "1,2,3,4,5",
          "expect.coalition_recovers_x": "false",
          "expect.honest_answers_at_corrupted_indices_only": "false"}),
        ("adversarial_complaint_timely_I15", c3,
         dict(corrupted=[3], extra_complaints=[(3, 1)]),
         {"expect.complaints": "3->1", "expect.answers": "1->3", "expect.qual": "1,2,3",
          "expect.coalition_recovers_x": "false",
          "expect.honest_answers_at_corrupted_indices_only": "true",
          "expect.aborts": "1:none,2:none,3:none"}),
        ("adversarial_complaint_withheld_commitments_I15", c3,
         dict(env_delay={(2, 1): 12}, corrupted=[3], extra_complaints=[(3, 2)]),
         {"expect.commitments": "1,3", "expect.complaints": "3->2", "expect.answers": "2->3",
          "expect.qual": "1,3", "expect.aborts": "1:none,2:A2,3:none",
          "expect.coalition_recovers_x": "false",
          "expect.honest_answers_at_corrupted_indices_only": "true"}),
    ]
    dl3 = dealing(c3)[2]
    specs += [
        ("front_run_envelope_copies", c3,
         dict(corrupted=[3], front_run=[("envelope.1.2", 3), ("envelope.2.1", 3)]),
         {"expect.complaints": "", "expect.answers": "", "expect.qual": "1,2,3",
          "expect.digest": ideal3, "expect.coalition_recovers_x": "false",
          "expect.aborts": "1:none,2:none,3:none"}),
        ("front_run_envelope_copies_dedup_before_auth_negative_control", c3,
         dict(corrupted=[3], front_run=[("envelope.1.2", 3), ("envelope.2.1", 3)],
              dedup_before_auth=True),
         {"expect.complaints": "1->2,2->1", "expect.answers": "1->2,2->1",
          "expect.coalition_recovers_x": "true",
          "expect.honest_answers_at_corrupted_indices_only": "false"}),
        ("front_run_commitments_copy", c3,
         dict(corrupted=[3], front_run=[("commitments.1", 3)]),
         {"expect.commitments": "1,2,3", "expect.qual": "1,2,3", "expect.digest": ideal3,
          "expect.aborts": "1:none,2:none,3:none", "expect.complaints": ""}),
        ("front_run_commitments_copy_dedup_before_auth_negative_control", c3,
         dict(corrupted=[3], front_run=[("commitments.1", 3)], dedup_before_auth=True),
         {"expect.commitments": "2,3", "expect.qual": "2,3",
          "expect.aborts": "1:A2,2:none,3:none"}),
        ("early_commitments_in_round0_S1", c3,
         dict(suppress=["commitments.1"],
              extra0=[Post(5, 1, "commitments.1.early", T.m_commitments(c3, 1, dl3[1]["C"]))]),
         {"expect.commitments": "2,3", "expect.qual": "2,3", "expect.complaints": "",
          "expect.aborts": "1:A2,2:none,3:none"}),
        ("extraction_withheld_dealer_reconstructed", c3,
         dict(withhold_extraction=[3]),
         {"expect.qual": "1,2,3", "expect.marked": "3", "expect.complaints": "",
          "expect.aborts": "1:none,2:none,3:A8", "expect.y": T.encode(
              T.smul(sum(dl3[i]["a"][0] for i in (1, 2, 3)) % T.L, T.G)).hex()}),
    ]
    outs = {}
    for name, cfg, kw, intent in specs:
        scn = Scenario(name, cfg, "timing." + name, **kw)
        posts = generate_board(scn)
        out = evaluate_board(scn, posts)
        outs[name] = (scn, posts, out)
        add_board_case("timing", name, scn, posts, out, intent)
        emit("info.timing.%s.ideal_digest_equal" % name, out["digest"].hex() in (ideal3, ideal5))
        emit("info.timing.%s.coalition_recovered_dealers" % name, ids(out["recovered_dealers"]))
    # Specific statements of ADR-0054 / spec §5 on these traces.
    _, _, o = outs["envelopes_excluded_by_cutoff_without_D7a_negative_control"]
    chk("timing.without_D7a.dealer5_exposed_in_qual", 5 in o["recovered_dealers"] and 5 in o["qual"])
    _, _, o = outs["envelopes_excluded_by_cutoff_D7a"]
    chk("timing.D7a.no_honest_complaint_about_excluded_dealer",
        not any(d == 5 for (_, d) in o["complaints"]) and 5 not in o["qual"])
    _, posts, o = outs["adversarial_complaint_withheld_commitments_I15"]
    chk("timing.withheld_commitments.answer_before_A2_at_corrupted_index",
        o["answers"] == [(2, 3)] and o["aborts"][2] == "A2" and 2 not in o["qual"])
    _, posts, o = outs["own_announcement_missing_T1"]
    chk("timing.T1.participant_posts_nothing_after_round0",
        not any(p.author == 2 and not p.label.startswith("announce") for p in posts) and
        not any(m[34] == 2 for m in o["sim"]["bc"]))
    # Counting rule cross-check on every trace: rule says exposed iff the coalition recovers.
    ok = True
    for name, (scn, posts, o) in sorted(outs.items()):
        if o["marked"]:
            continue                                   # rounds 5-6 disclosures: exposure family
        C = set(scn.corrupted)
        for i in o["qual"]:
            known = set(C) if i not in C else set(range(1, scn.cfg.n + 1))
            known |= {c for (d, c) in o["answers"] if d == i}
            ok &= (len(known) >= scn.cfg.t + 1) == (i in o["recovered_dealers"])
    chk("timing.counting_rule_matches_actual_recovery_on_every_trace", ok)
    return outs


# ---------------------------------------------------------------- exposure (spec §6)


def counting_rule(n, t, qual, leaked, corrupted, answers, sent, published, reconstructed):
    """Spec §6 (second revision): dealer i's known indices are leaked keys j ≠ i to which i sent
    an envelope, the corrupted participants, the public answers for i, the pairs published for i
    in rounds 5-6, and all indices if i was reconstructed in round 6 or is corrupted."""
    per = {}
    for i in qual:
        if i in corrupted or i in reconstructed:
            known = set(range(1, n + 1))
        else:
            known = {k for k in leaked if k != i and (i, k) in sent}
            known |= set(corrupted)
            known |= {j for (d, j) in answers if d == i}
            known |= {j for (d, j) in published if d == i}
        per[i] = (len(known) >= t + 1, sorted(known))
    return per, all(per[i][0] for i in qual)


def board_disclosures(posts, out):
    """The counting-rule inputs a board and its transcript fix: envelopes sent (authentic posts,
    in or out of a window: a late envelope is still public), the round-3 answers, the pairs
    published in rounds 5-6, and the dealers reconstructed in round 6."""
    sent = sorted({(p.data[E_I], p.data[E_J]) for p in posts
                   if p.data.startswith(TAG_E) and len(p.data) == ENVELOPE_LEN and p.author == p.data[E_I]})
    dv = out["sim"]["res"]["dv"]
    published = sorted({(m.subject, m.sender) for r in (5, 6) for m in dv.ordered(r)})
    return sent, out["answers"], published, out["reconstructed"]


def actual_exposure(scn, posts, out, leaked, corrupted, answers):
    """Reconstruct from what the adversary actually holds: authentic envelopes (any time) opened
    with leaked or corrupted recipients' keys, the given answers, the pairs published in rounds
    5-6, and corrupted dealers' polynomials. Values are checked against the dealing."""
    cfg = scn.cfg
    _, _, dl = dealing(cfg)
    t = cfg.t
    envs = {(p.data[E_I], p.data[E_J]): p.data for p in posts
            if p.data.startswith(TAG_E) and len(p.data) == ENVELOPE_LEN and p.author == p.data[E_I]}
    dv = out["sim"]["res"]["dv"]
    pub = {}
    for r in (5, 6):
        for m in dv.ordered(r):
            pub.setdefault(m.subject, {})[m.sender] = m.pair[0]
    per, ok_values, zsum = {}, True, 0
    for i in out["qual"]:
        if i in corrupted:
            per[i] = True
            zsum += dl[i]["a"][0]
            continue
        pts = dict(pub.get(i, {}))
        for k in sorted(set(leaked) | set(corrupted)):
            if k != i and (i, k) in envs:
                pt, _ = open_envelope(cfg, k, scn.rk[k], envs[(i, k)], i)
                if pt is not None:
                    pts[k] = int.from_bytes(pt[36:68], "big")
        for (d, j) in answers:
            if d == i:
                pts[j] = dl[i]["s"][j]
        per[i] = len(pts) >= t + 1
        if per[i]:
            coeffs = T.interpolate(sorted(pts.items())[:t + 1])
            ok_values &= coeffs[0] == dl[i]["a"][0]
            ok_values &= all(T.poly_eval(coeffs, x) == y for x, y in pts.items())
            zsum += coeffs[0]
    x_exposed = all(per[i] for i in out["qual"])
    if x_exposed:
        ok_values &= zsum % T.L == sum(dl[i]["a"][0] for i in out["qual"]) % T.L
    return per, x_exposed, ok_values


def replay_exposure(items):
    d = dict(items)
    t, n = int(d["config"].split(",")[0]), int(d["config"].split(",")[1])
    parse_ids = lambda s_: [int(x) for x in s_.split(",") if x]
    parse_pairs = lambda s_: [tuple(int(y) for y in x.split("->")) for x in s_.split(",") if x]
    per, x = counting_rule(n, t, parse_ids(d["qual"]), parse_ids(d["leaked"]), parse_ids(d["corrupted"]),
                           parse_pairs(d["answers"]), set(parse_pairs(d["sent"])),
                           parse_pairs(d["published"]), parse_ids(d["reconstructed"]))
    ok = all(d["expect.dealer.%d" % i] == ("exposed" if per[i][0] else "unexposed") for i in per)
    ok = ok and all(d["known.%d" % i] == ids(per[i][1]) for i in per)
    return ok and d["expect.x"] == ("exposed" if x else "unexposed")


def exposure_family(timing_outs):
    def one(fam_name, scn, posts, out, leaked, C, answers, source, intent_x=None, intent=None,
            intent_known=None):
        n, t, qual = scn.cfg.n, scn.cfg.t, out["qual"]
        sent, _, published, recon = board_disclosures(posts, out)
        per, x = counting_rule(n, t, qual, leaked, C, answers, set(sent), published, recon)
        aper, ax, okv = actual_exposure(scn, posts, out, leaked, C, answers)
        chk("exposure.%s.rule_matches_reconstruction" % fam_name,
            all(per[i][0] == aper[i] for i in qual) and x == ax and okv)
        if intent is not None:
            chk("exposure.%s.intended_outcome" % fam_name,
                all(per[i][0] == v for i, v in intent.items()) and x == intent_x and
                all(per[i][1] == v for i, v in (intent_known or {}).items()))
        items = [("config", config_str(scn.cfg)), ("qual", ids(qual)), ("leaked", ids(leaked)),
                 ("corrupted", ids(C)), ("answers", pairs_str(answers)), ("sent", pairs_str(sent)),
                 ("published", pairs_str(published)), ("reconstructed", ids(recon)),
                 ("source", source)]
        for i in qual:
            items += [("known.%d" % i, ids(per[i][1])),
                      ("expect.dealer.%d" % i, "exposed" if per[i][0] else "unexposed")]
        items.append(("expect.x", "exposed" if x else "unexposed"))
        add_case("exposure", fam_name, items, replay_exposure)

    scenarios = {
        "honest-2of3": [
            ("keys_1_2_adr_example", [1, 2], [], []),
            ("keys_t_plus_2_all", [1, 2, 3], [], []),
            ("corrupt_3_key_1", [1], [3], []),
            ("corrupt_3_keys_1_2", [1, 2], [3], []),
            ("corrupt_3_key_1_answer_1_at_honest_2", [1], [3], [(1, 2)]),
            ("corrupt_3_key_1_answer_1_at_corrupted_3", [1], [3], [(1, 3)]),
            ("answers_only_at_honest_indices", [], [3], [(1, 2), (2, 1)]),
            ("corrupt_1_key_3", [3], [1], []),
        ],
        "honest-3of5": [
            ("keys_t_plus_1", [1, 2, 3], [], []),
            ("keys_t_plus_2", [1, 2, 3, 4], [], []),
            ("corrupt_4_5_key_1", [1], [4, 5], []),
            ("corrupt_4_5_keys_1_2", [1, 2], [4, 5], []),
            ("corrupt_4_5_key_1_answer_1_at_honest_2_adr_example", [1], [4, 5], [(1, 2)]),
            ("corrupt_4_5_key_1_answer_1_at_corrupted_4", [1], [4, 5], [(1, 4)]),
        ],
        "honest-4of7": [
            ("keys_t_plus_1", [1, 2, 3, 4], [], []),
            ("keys_t_plus_2", [1, 2, 3, 4, 5], [], []),
            ("corrupt_5_6_7_key_1", [1], [5, 6, 7], []),
            ("corrupt_5_6_7_keys_1_2", [1, 2], [5, 6, 7], []),
            ("corrupt_5_6_7_key_1_answer_1_at_honest_2", [1], [5, 6, 7], [(1, 2)]),
            ("corrupt_5_6_7_key_1_answers_at_corrupted", [1], [5, 6, 7], [(1, 5), (2, 6), (3, 7)]),
        ],
    }
    for F, lst in scenarios.items():
        scn, posts, out = RUNS[F]
        for name, leaked, C, answers in lst:
            one("%s.%s" % (F, name), scn, posts, out, leaked, C, answers, "case.run.%s" % F)
    # Second revision, rounds 5-6: dealer 3's EXTRACTION is withheld, R4 marks it, and 1 and 2
    # publish RECONSTRUCTION pairs: z_3 is public with no leak and no corruption (former S2).
    scn, posts, out = timing_outs["extraction_withheld_dealer_reconstructed"]
    one("late_extraction.no_leak", scn, posts, out, [], [], [],
        "case.timing.extraction_withheld_dealer_reconstructed",
        intent_x=False, intent={1: False, 2: False, 3: True}, intent_known={3: [1, 2, 3], 1: [], 2: []})
    one("late_extraction.key_1_leaked", scn, posts, out, [1], [], [],
        "case.timing.extraction_withheld_dealer_reconstructed",
        intent_x=False, intent={1: False, 2: False, 3: True})
    # One corruption and one leaked key expose x only because dealer 3 is public; the same
    # inputs on the plain run (honest-2of3.corrupt_1_key_3) leave x unexposed.
    one("late_extraction.corrupt_1_key_3", scn, posts, out, [3], [1], [],
        "case.timing.extraction_withheld_dealer_reconstructed",
        intent_x=True, intent={1: True, 2: True, 3: True})
    # Second revision, "to which i actually sent an envelope": participant 2 aborted with T1 and
    # has no key, so no dealer sealed to it; its leaked private key reveals nothing.
    scn, posts, out = timing_outs["own_announcement_missing_T1"]
    one("t1_participant_key_leaked_reveals_nothing", scn, posts, out, [2], [3], [],
        "case.timing.own_announcement_missing_T1",
        intent_x=False, intent={1: False, 3: True})

    # ADR-0054 threat-model enumeration (counting model only, every subset, every envelope sent).
    for n, t in ((3, 1), (5, 2), (7, 3)):
        Q = list(range(1, n + 1))
        sent_all = {(i, j) for i in Q for j in Q if i != j}
        tag = "n%d_t%d" % (n, t)
        x_of = lambda L_, C_, A_: counting_rule(n, t, Q, L_, C_, A_, sent_all, [], [])[1]
        chk("exposure.enumeration.%s.keys_t_plus_1_never" % tag,
            not any(x_of(L_, [], []) for L_ in itertools.combinations(Q, t + 1)))
        chk("exposure.enumeration.%s.keys_t_plus_2_always" % tag,
            all(x_of(L_, [], []) for L_ in itertools.combinations(Q, t + 2)))
        one_, two, ans_h, ans_c = True, True, True, True
        for C in itertools.combinations(Q, t):
            H = [q for q in Q if q not in C]
            for hk in H:
                one_ &= not x_of([hk], C, [])
                for h2 in H:
                    if h2 != hk:
                        ans_h &= x_of([hk], C, [(hk, h2)])
                ans_c &= not x_of([hk], C, [(d, c) for d in Q for c in C if d != c])
            for L_ in itertools.combinations(H, 2):
                two &= x_of(list(L_), C, [])
        chk("exposure.enumeration.%s.t_corrupted_one_leaked_honest_key_never" % tag, one_)
        chk("exposure.enumeration.%s.t_corrupted_two_leaked_honest_keys_always" % tag, two)
        chk("exposure.enumeration.%s.t_corrupted_one_key_one_honest_index_answer_always" % tag, ans_h)
        chk("exposure.enumeration.%s.t_corrupted_one_key_answers_only_at_corrupted_never" % tag, ans_c)


# =============================================================================
# Main
# =============================================================================


def main():
    emit("profile", "dkg-share-delivery-hpke-v1")
    emit("profile.suite", "mode=0x00,kem=0x0020,kdf=0x0001,aead=0x0003")
    for name, tag in (("TAG_A", TAG_A), ("TAG_I", TAG_I), ("TAG_E", TAG_E)):
        emit("profile.%s" % name, tag.hex())
        emit("profile.%s.length" % name, len(tag))
    emit("profile.PROBE", PROBE.hex())
    emit("profile.test_key_prefix", TEST_PREFIX.decode("ascii"))
    chk("profile.tag_lengths_41_37_41", (len(TAG_A), len(TAG_I), len(TAG_E)) == (41, 37, 41))
    tags = [TAG_A, TAG_I, TAG_E]
    chk("profile.no_tag_is_prefix_of_another",
        not any(x != y and y.startswith(x) for x in tags for y in tags))

    kat_rfc7748()
    zero_pub, nonzero_pub = kat_wycheproof_x25519()
    kat_rfc8439_and_wycheproof()
    kat_rfc5869_and_wycheproof()
    kat_rfc9180_a21()
    small_order_u = small_order_section(zero_pub, nonzero_pub)

    cfgs = make_cfgs()
    for k, c in sorted(cfgs.items()):
        emit("session.%s" % k, c.session.hex())
    announce_family(cfgs, small_order_u)
    envelope_family(cfgs, small_order_u)
    directory_family(cfgs)
    run_family(cfgs)
    timing_outs = timing_family(cfgs)
    exposure_family(timing_outs)

    # §7 lifecycle across everything this run sealed or announced.
    chk("lifecycle.ephemeral_tags_never_reused", len(EPHEMERAL_TAGS) == len(set(EPHEMERAL_TAGS)))
    eph_sks = [KEY_REGISTRY[t_] for t_ in EPHEMERAL_TAGS]
    chk("lifecycle.ephemeral_keys_distinct", len(set(eph_sks)) == len(eph_sks))
    chk("lifecycle.all_test_keys_distinct", len(set(KEY_REGISTRY.values())) == len(KEY_REGISTRY))
    rec = [(F, j) for F in RUNS for j in RUNS[F][0].rk]
    chk("lifecycle.recipient_keys_never_roster_keys",
        all(RUNS[F][0].rk[j].pk != T.roster(RUNS[F][0].cfg.n)[j - 1] and
            KEY_REGISTRY[RUNS[F][0].key_tags[j]] != T.roster(RUNS[F][0].cfg.n)[j - 1] for F, j in rec))

    # Vectors: emit and replay each from its own keys.
    fams = {}
    bad = []
    for fam, name, items, replay in CASES:
        fams[fam] = fams.get(fam, 0) + 1
        for k, v in items:
            emit("case.%s.%s.%s" % (fam, name, k), v)
        if not replay(items):
            bad.append("%s.%s" % (fam, name))
    for fam in sorted(fams):
        emit("info.case_count.%s" % fam, fams[fam])
    emit("info.case_count", len(CASES))
    emit("info.case_replay_failures", ",".join(bad))
    chk("case_vectors_replay_self_consistent", not bad)

    emit("info.check_count", len(CHECKS))
    emit("info.failed_checks", len(FAILED))
    emit("result", "pass" if not FAILED else "fail")
    text = "".join("%s=%s\n" % (k, OUT[k]) for k in sorted(OUT))
    sys.stdout.write(text)
    with open(os.path.join(HERE, "reference-output.txt"), "w", encoding="utf-8") as fh:
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
