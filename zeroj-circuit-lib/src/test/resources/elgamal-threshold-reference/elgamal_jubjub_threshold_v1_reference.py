#!/usr/bin/env python3
"""
Independent reference for the ZeroJ profile `elgamal-jubjub-threshold-v1`.

Written only from:
  - docs/specs/elgamal-jubjub-threshold-v1.md (the spec under test),
  - docs/specs/elgamal-jubjub-v1.md and docs/specs/pedersen-jubjub-v1.md (curve, G, H,
    point encoding, sampler, encryption, decryption),
  - Gennaro, Jarecki, Krawczyk, Rabin, "Secure Distributed Key Generation for Discrete-Log
    Based Cryptosystems", J. Cryptology 20:51-83 (2007): Pedersen-VSS (Sec. 2.2, Lemma 1)
    and New-DKG (Sec. 4, Fig. 2).

No ZeroJ source code (Java or otherwise) was read. Python 3 standard library only.
The algorithms are deliberately simple: affine twisted-Edwards arithmetic with modular
inverses, double-and-add, direct (non-Horner) evaluation of sum_k [j^k]C_ik, Lagrange
interpolation with modular inverses, and a linear discrete-log search.

Run from this directory:

    python3 elgamal_jubjub_threshold_v1_reference.py

It prints key=value lines and rewrites reference-output.txt. Exit status 0 iff every check
passes; 1 otherwise (the failing keys are listed on stderr).
"""

import hashlib
import itertools
import os
import platform
import random
import sys

# =============================================================================
# Output bookkeeping
# =============================================================================

LINES = []
FAILED = []


def emit(key, value):
    if isinstance(value, bool):
        value = "true" if value else "false"
    LINES.append("%s=%s" % (key, value))


def chk(key, cond):
    cond = bool(cond)
    emit(key, cond)
    if not cond:
        FAILED.append(key)
    return cond


def fe(x):
    """Field element or scalar: 0x + 64 lowercase hex digits."""
    return "0x%064x" % x


def ids(xs):
    return ",".join(str(x) for x in xs)


def subset_name(xs):
    return "-".join(str(x) for x in xs)


# =============================================================================
# Curve (pedersen-jubjub-v1 §1). p and l are inputs; d is re-derived.
# =============================================================================

P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
L = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7
D_PIN = 0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1
A_EDW = P - 1                                    # a = -1
D = (-10240 * pow(10241, -1, P)) % P             # d = -10240/10241 mod p

O = (0, 1)                                       # identity


def on_curve(pt):
    u, v = pt
    if not (0 <= u < P and 0 <= v < P):
        return False
    uu = u * u % P
    vv = v * v % P
    return (A_EDW * uu + vv - 1 - D * uu % P * vv) % P == 0


def padd(p1, p2):
    """Unified affine twisted-Edwards addition, a = -1 (complete on Jubjub)."""
    u1, v1 = p1
    u2, v2 = p2
    t = D * u1 % P * u2 % P * v1 % P * v2 % P
    u3 = (u1 * v2 + v1 * u2) * pow((1 + t) % P, -1, P) % P
    v3 = (v1 * v2 - A_EDW * u1 * u2) * pow((1 - t) % P, -1, P) % P
    return (u3, v3)


def pneg(pt):
    return ((-pt[0]) % P, pt[1])


def psub(p1, p2):
    return padd(p1, pneg(p2))


_MUL_CACHE = {}


def pmul(k, pt):
    """[k]·P for an integer k >= 0, plain double-and-add (no reduction of k)."""
    if k < 0:
        raise ValueError("negative scalar")
    big = k.bit_length() > 16
    if big:
        hit = _MUL_CACHE.get((k, pt))
        if hit is not None:
            return hit
    r = O
    a = pt
    kk = k
    while kk:
        if kk & 1:
            r = padd(r, a)
        kk >>= 1
        if kk:
            a = padd(a, a)
    if big:
        _MUL_CACHE[(k, pt)] = r
    return r


def smul(k, pt):
    """[k mod l]·P, the spec's scalar multiplication."""
    return pmul(k % L, pt)


def in_subgroup(pt):
    return on_curve(pt) and pmul(L, pt) == O


def psum(points):
    acc = O
    for q in points:
        acc = padd(acc, q)
    return acc


# --- square roots (Tonelli-Shanks) -------------------------------------------

def sqrt_mod(a):
    a %= P
    if a == 0:
        return 0
    if pow(a, (P - 1) // 2, P) != 1:
        return None
    q, s = P - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (P - 1) // 2, P) != P - 1:
        z += 1
    m, c, t, r = s, pow(z, q, P), pow(a, q, P), pow(a, (q + 1) // 2, P)
    while t != 1:
        i, t2 = 1, t * t % P
        while t2 != 1:
            t2 = t2 * t2 % P
            i += 1
        b = pow(c, 1 << (m - i - 1), P)
        m, c = i, b * b % P
        t, r = t * c % P, r * b % P
    assert r * r % P == a
    return r


# --- point encoding (pedersen-jubjub-v1 §4) -----------------------------------

def encode(pt):
    u, v = pt
    return (v | ((u & 1) << 255)).to_bytes(32, "little")


def decode(b):
    """Returns (point, None) or (None, reason). Canonical-only, with the ZIP 216 rule."""
    if len(b) != 32:
        return None, "length"
    x = int.from_bytes(b, "little")
    sign = x >> 255
    v = x & ((1 << 255) - 1)
    if v >= P:
        return None, "noncanonical_v"
    den = (D * v * v + 1) % P
    if den == 0:
        return None, "den_zero"
    w = (v * v - 1) * pow(den, -1, P) % P
    u = sqrt_mod(w)
    if u is None:
        return None, "non_square"
    if u == 0 and sign == 1:
        return None, "u_zero_sign_set"
    if (u & 1) != sign:
        u = P - u
    return (u, v), None


# =============================================================================
# Bases (pedersen-jubjub-v1 §2.1, §2.3)
# =============================================================================

G_FULL = (0x62EDCBB8BF3787C88B0F03DDD60A8187CAF55D1B29BF81AFE4B3D35DF1A7ADFE, 11)
G = pmul(8, G_FULL)

G_U_PIN = 0x3EA5C4673A121CA35ED37EE3B172F5EE04315C657FBE375F512DFEA318D56FE5
G_V_PIN = 0x57137B83EA6EDB4F78F7D30D3F616CB3B9AA6E8E40808413C10CEA38D50C55CB
G_ENC_PIN = "cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7"

# H is taken from the values pinned in pedersen-jubjub-v1 §2.3 (not re-derived: that would
# need the Poseidon instance, which the pedersen-reference already reproduces).
H_U_PIN = 0x72963E7766B3CD553A1525A17DA810E6B4CDEB70541DAC5B52A3210F5C372DB6
H_V_PIN = 0x60BB97D81759E04503194AEB9EB8FAA23B0092C941D1139BFE99907794C8E37D
H_ENC_PIN = "7de3c894779099fe9b13d141c992003ba2fab89eeb4a190345e05917d897bb60"
H = (H_U_PIN, H_V_PIN)

# =============================================================================
# Hashes, integers, test scalars
# =============================================================================


def blake2b256(data):
    # BLAKE2b with digest length parameter 32 (RFC 7693), unkeyed, no salt/personal.
    return hashlib.blake2b(data, digest_size=32).digest()


def u8(x):
    assert 0 <= x < 1 << 8
    return x.to_bytes(1, "big")


def u16(x):
    assert 0 <= x < 1 << 16
    return x.to_bytes(2, "big")


def u32(x):
    assert 0 <= x < 1 << 32
    return x.to_bytes(4, "big")


def u64(x):
    assert 0 <= x < 1 << 64
    return x.to_bytes(8, "big")


def i2osp32(x):
    assert 0 <= x < 1 << 256
    return x.to_bytes(32, "big")


SCALAR_PREFIX = "zeroj.elgamal.threshold.v1.test."
SCALARS_USED = {}


def scalar(tag):
    """§11: OS2IP(SHA-256(UTF-8(prefix + tag))) mod l."""
    v = int.from_bytes(hashlib.sha256((SCALAR_PREFIX + tag).encode("utf-8")).digest(), "big") % L
    SCALARS_USED[tag] = v
    return v


def reference_only_scalar(tag):
    """A scalar this reference invents for its own negative tests (never a spec value)."""
    return int.from_bytes(hashlib.sha256(("zeroj.elgamal.threshold.v1.reference-only." + tag)
                                         .encode("utf-8")).digest(), "big") % L


def scalar_v1(tag):
    """elgamal-jubjub-v1 §12 test scalar, used only to cross-check against its pins."""
    return int.from_bytes(hashlib.sha256(("zeroj.elgamal.v1.test." + tag).encode("utf-8"))
                          .digest(), "big") % L


# =============================================================================
# Polynomials mod l
# =============================================================================


def poly_eval(coeffs, z):
    """Direct sum of c_k * z^k (not Horner)."""
    return sum(c * pow(z, k, L) for k, c in enumerate(coeffs)) % L


def poly_mul(f, g):
    out = [0] * (len(f) + len(g) - 1)
    for i, a in enumerate(f):
        for j, b in enumerate(g):
            out[i + j] = (out[i + j] + a * b) % L
    return out


def interpolate(points):
    """Coefficients (degree <= len-1) of the polynomial through `points`, mod l (Lagrange)."""
    n = len(points)
    coeffs = [0] * n
    for m, (xm, ym) in enumerate(points):
        num, den = [1], 1
        for q, (xq, _) in enumerate(points):
            if q == m:
                continue
            num = poly_mul(num, [(-xq) % L, 1])
            den = den * ((xm - xq) % L) % L
        f = ym * pow(den, -1, L) % L
        for k in range(n):
            coeffs[k] = (coeffs[k] + f * num[k]) % L
    return coeffs


def lagrange_at_zero(S, j):
    """§9: λ_j = Π_{m ∈ S, m ≠ j} m · (m − j)⁻¹ mod l."""
    r = 1
    for m in S:
        if m != j:
            r = r * m % L * pow((m - j) % L, -1, L) % L
    return r


def lagrange_at(S, j, e):
    """§9: L_{j,S}(e) = Π_{m ∈ S, m ≠ j} (e − m) · (j − m)⁻¹ mod l."""
    r = 1
    for m in S:
        if m != j:
            r = r * ((e - m) % L) % L * pow((j - m) % L, -1, L) % L
    return r


# =============================================================================
# §1, §2: parameters, configuration, session
# =============================================================================

DST_S = "zeroj.elgamal-jubjub-threshold.v1.session".encode("utf-8")
DST_T = "zeroj.elgamal-jubjub-threshold.v1.transcript".encode("utf-8")


def validate_params(t, n, ctx, attempt, keys):
    if not (t >= 1):
        raise ValueError("t < 1")
    if not (n >= 2 * t + 1):
        raise ValueError("n < 2t+1")
    if not (n <= 64):
        raise ValueError("n > 64")
    if len(keys) != n:
        raise ValueError("roster size != n")
    for k in keys:
        if not (1 <= len(k) <= 65535):
            raise ValueError("key length")
    if len(set(keys)) != len(keys):
        raise ValueError("roster keys not pairwise distinct")
    if not (0 <= len(ctx) <= 65535):
        raise ValueError("ctx length")
    if not (0 <= attempt < 1 << 64):
        raise ValueError("attempt range")


class Config:
    def __init__(self, t, n, ctx, attempt, keys):
        validate_params(t, n, ctx, attempt, keys)
        self.t, self.n, self.ctx, self.attempt, self.keys = t, n, ctx, attempt, list(keys)
        pre = DST_S + u16(len(ctx)) + ctx + u64(attempt) + u8(t) + u8(n)
        for k in keys:
            pre += u16(len(k)) + k
        self.preimage = pre
        self.session = blake2b256(pre)


def roster(n):
    """§11 'key_j = 32 bytes of value j' read as 32 bytes each equal to j (finding F1)."""
    return [bytes([j]) * 32 for j in range(1, n + 1)]


# =============================================================================
# §4: messages
# =============================================================================

KIND_ROUND = {1: 1, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5, 7: 6, 8: 7}
KIND_NAME = {1: "COMMITMENTS", 2: "SHARE", 3: "COMPLAINT", 4: "ANSWER", 5: "EXTRACTION",
             6: "EXTRACTION_COMPLAINT", 7: "RECONSTRUCTION", 8: "CONFIRMATION"}
SUBJECT_ZERO = (1, 5, 8)
PAIR_KINDS = (2, 4, 6, 7)


def payload_len(kind, t):
    if kind in (1, 5):
        return 32 * (t + 1)
    if kind == 3:
        return 0
    return 64          # kinds 2, 4, 6, 7 (pair) and 8 (digest ‖ encode(y))


def hdr(cfg, kind, sender, subject):
    return cfg.session + u8(KIND_ROUND[kind]) + u8(kind) + u8(sender) + u8(subject)


def m_commitments(cfg, i, pts):
    return hdr(cfg, 1, i, 0) + b"".join(encode(q) for q in pts)


def m_share(cfg, i, j, s, sp):
    return hdr(cfg, 2, i, j) + i2osp32(s) + i2osp32(sp)


def m_complaint(cfg, j, i):
    return hdr(cfg, 3, j, i)


def m_answer(cfg, i, j, s, sp):
    return hdr(cfg, 4, i, j) + i2osp32(s) + i2osp32(sp)


def m_extraction(cfg, i, pts):
    return hdr(cfg, 5, i, 0) + b"".join(encode(q) for q in pts)


def m_ext_complaint(cfg, j, i, s, sp):
    return hdr(cfg, 6, j, i) + i2osp32(s) + i2osp32(sp)


def m_reconstruction(cfg, j, i, s, sp):
    return hdr(cfg, 7, j, i) + i2osp32(s) + i2osp32(sp)


def m_confirmation(cfg, j, digest, y):
    return hdr(cfg, 8, j, 0) + digest + encode(y)


class Msg:
    __slots__ = ("raw", "round", "kind", "sender", "subject", "points", "pair", "digest", "y")

    def key(self):
        return (self.kind, self.sender, self.subject)


def parse(cfg, raw):
    """§4 well-formedness. Returns (Msg, None) or (None, reason)."""
    if len(raw) < 36:
        return None, "length"
    rnd, kind, sender, subject = raw[32], raw[33], raw[34], raw[35]
    if kind not in KIND_ROUND or KIND_ROUND[kind] != rnd:
        return None, "round_kind"
    if len(raw) != 36 + payload_len(kind, cfg.t):
        return None, "length"
    if raw[:32] != cfg.session:
        return None, "session"
    if not (1 <= sender <= cfg.n):
        return None, "sender"
    if kind in SUBJECT_ZERO:
        if subject != 0:
            return None, "subject"
    else:
        # "recipient/accused/complainer/reconstructed j ≠ sender"; 1..n implied (finding F9).
        if not (1 <= subject <= cfg.n) or subject == sender:
            return None, "subject"
    m = Msg()
    m.raw, m.round, m.kind, m.sender, m.subject = raw, rnd, kind, sender, subject
    m.points = m.pair = m.digest = m.y = None
    pl = raw[36:]
    if kind in PAIR_KINDS:
        s = int.from_bytes(pl[:32], "big")
        sp = int.from_bytes(pl[32:], "big")
        if s >= L or sp >= L:
            return None, "scalar_range"
        m.pair = (s, sp)
    elif kind in (1, 5):
        pts = []
        for k in range(cfg.t + 1):
            q, why = decode(pl[32 * k:32 * k + 32])
            if q is None:
                return None, "point_" + why
            if not in_subgroup(q):
                return None, "point_subgroup"
            pts.append(q)
        m.points = pts
    elif kind == 8:
        q, why = decode(pl[32:])
        if q is None:
            return None, "point_" + why
        if not in_subgroup(q):
            return None, "point_subgroup"
        m.digest, m.y = pl[:32], q
    return m, None


def sort_key(m):
    return (m.kind, m.sender, m.subject, m.raw)


class Delivered:
    """Delivered broadcast sets of rounds 1-6 (SHARE and CONFIRMATION are excluded)."""

    def __init__(self, cfg, raw_list):
        self.by_round = {r: {} for r in range(1, 7)}
        self.rejected = []
        for raw in raw_list:
            m, why = parse(cfg, raw)
            if m is None:
                self.rejected.append((raw, why))
                continue
            if m.kind in (2, 8):
                continue
            self.by_round[m.round][raw] = m          # byte-identical copies count once
        self.ident = {r: {} for r in range(1, 7)}
        for r in range(1, 7):
            for m in self.by_round[r].values():
                self.ident[r].setdefault(m.key(), []).append(m)

    def unique(self, r, key):
        """The message with this identity, or None if absent or in conflict."""
        lst = self.ident[r].get(key, [])
        return lst[0] if len(lst) == 1 else None

    def ordered(self, r):
        return sorted(self.by_round[r].values(), key=sort_key)


# =============================================================================
# §6: transcript
# =============================================================================


def transcript_bytes(cfg, dv):
    out = DST_T + cfg.session + u8(cfg.t) + u8(cfg.n)
    for r in range(1, 7):
        ms = dv.ordered(r)
        out += u32(len(ms))
        for m in ms:
            out += u16(len(m.raw)) + m.raw
    return out


# =============================================================================
# §3: equations (4) and (5) -- right-hand sides evaluated directly, not by Horner
# =============================================================================


def eq4(cfg, Cs, j, s, sp, Hb):
    lhs = padd(smul(s, G), smul(sp, Hb))
    rhs = O
    for k in range(cfg.t + 1):
        rhs = padd(rhs, smul(pow(j, k, L), Cs[k]))
    return lhs == rhs


def eq5(cfg, As, j, s):
    lhs = smul(s, G)
    rhs = O
    for k in range(cfg.t + 1):
        rhs = padd(rhs, smul(pow(j, k, L), As[k]))
    return lhs == rhs


# =============================================================================
# §5: public recomputation from the delivered broadcast sets
# =============================================================================


def recompute(cfg, raw_broadcast, Hb=None, stop_after=None):
    Hb = Hb or H
    t, n = cfg.t, cfg.n
    dv = Delivered(cfg, raw_broadcast)
    R = {"dv": dv, "abort": None, "abort_detail": None}
    tb = transcript_bytes(cfg, dv)
    R["transcript"], R["digest"] = tb, blake2b256(tb)

    # R1
    C, dq = {}, {}
    for i in range(1, n + 1):
        m = dv.unique(1, (1, i, 0))
        if m is None:
            dq[i] = "R1"
        else:
            C[i] = m.points
    # R2 (a set of senders: duplicates count once)
    complaints = {i: set() for i in range(1, n + 1)}
    for m in dv.by_round[2].values():
        complaints[m.subject].add(m.sender)
    # R3
    for i in range(1, n + 1):
        if i in dq:
            continue
        if len(complaints[i]) > t:
            dq[i] = "R3_more_than_t_complaints"
            continue
        for j in sorted(complaints[i]):
            a = dv.unique(3, (4, i, j))
            if a is None:
                dq[i] = "R3_answer_absent_or_conflict"
                break
            if not eq4(cfg, C[i], j, a.pair[0], a.pair[1], Hb):
                dq[i] = "R3_answer_fails_eq4"
                break
    qual = [i for i in range(1, n + 1) if i not in dq]
    R.update(C=C, dq=dq, complaints=complaints, qual=qual)
    if len(qual) < n - t:
        R["abort"] = "A1"
        return R
    if stop_after == "R3":
        return R

    # R4
    A, marked = {}, {}
    for i in qual:
        m = dv.unique(4, (5, i, 0))
        if m is None:
            marked[i] = "R4"
        else:
            A[i] = list(m.points)
    A_published = {i: list(v) for i, v in A.items()}
    # R5 (each well-formed complaint evaluated on its own; finding F10)
    valid_ec = []
    for m in dv.ordered(5):
        i, j = m.subject, m.sender
        if i not in qual or i not in A_published:
            continue
        s, sp = m.pair
        if eq4(cfg, C[i], j, s, sp, Hb) and not eq5(cfg, A_published[i], j, s):
            valid_ec.append((j, i))
            marked.setdefault(i, "R5")
    R.update(A_published=A_published, marked=marked, valid_ec=valid_ec)
    if stop_after == "R5":
        return R

    # R6
    recon = {}
    for i in sorted(marked):
        valid = []
        for j in range(1, n + 1):
            lst = dv.ident[6].get((7, j, i), [])
            if len(lst) != 1:
                continue                               # absent or in conflict
            s, sp = lst[0].pair
            if eq4(cfg, C[i], j, s, sp, Hb):
                valid.append((j, s, sp))
        if len(valid) < t + 1:
            R["abort"], R["abort_detail"] = "A3", "dealer %d has %d valid pairs" % (i, len(valid))
            return R
        base = valid[:t + 1]
        a = interpolate([(j, s) for j, s, _ in base])
        b = interpolate([(j, sp) for j, _, sp in base])
        for j, s, sp in valid[t + 1:]:
            if poly_eval(a, j) != s or poly_eval(b, j) != sp:
                R["abort"], R["abort_detail"] = "A4", "off_polynomial dealer %d pair %d" % (i, j)
                return R
        for k in range(t + 1):
            if padd(smul(a[k], G), smul(b[k], Hb)) != C[i][k]:
                R["abort"], R["abort_detail"] = "A4", "commitment_mismatch dealer %d k %d" % (i, k)
                return R
        A[i] = [smul(a[k], G) for k in range(t + 1)]
        recon[i] = {"valid": [j for j, _, _ in valid], "used": [j for j, _, _ in base],
                    "a": a, "b": b}
    y = psum(A[i][0] for i in qual)
    Y = {}
    for j in range(1, n + 1):
        acc = O
        for i in qual:
            for k in range(t + 1):
                acc = padd(acc, smul(pow(j, k, L), A[i][k]))
        Y[j] = acc
    R.update(A=A, recon=recon, y=y, Y=Y)
    if y == O:
        R["abort"] = "A5"
    return R


# =============================================================================
# Dealing (§3) and a scripted run of the participants' logic (§5 private outputs)
# =============================================================================


def deal(cfg, a, b, Hb):
    out = {}
    for i in range(1, cfg.n + 1):
        Ai = [smul(a[i][k], G) for k in range(cfg.t + 1)]
        Ci = [padd(Ai[k], smul(b[i][k], Hb)) for k in range(cfg.t + 1)]
        s = {j: poly_eval(a[i], j) for j in range(1, cfg.n + 1)}
        sp = {j: poly_eval(b[i], j) for j in range(1, cfg.n + 1)}
        out[i] = {"a": a[i], "b": b[i], "A": Ai, "C": Ci, "s": s, "sp": sp}
    return out


class Script:
    """Deviations from honest behaviour. Defaults: everybody follows §5."""

    def __init__(self):
        self.commit = {}          # i -> list of point lists (one message each); [] = withhold
        self.share = {}           # (i, j) -> (s, s') sent instead, or None = withhold
        self.share_extra = {}     # (i, j) -> extra pairs also sent privately (SHARE conflict)
        self.private_raw = {}     # (i, j) -> raw messages delivered privately instead (§4 channels)
        self.complaint_ok = lambda j, i: True
        self.answer = {}          # (i, j) -> (s, s') sent instead, or None = withhold
        self.extraction = {}      # i -> list of point lists; [] = withhold (delivered to nobody)
        self.ec_senders = None    # None = every participant whose check fails; else a set
        self.ec_pair = {}         # (j, i) -> pair sent instead
        self.recon_ok = lambda j, i: True
        self.recon_pair = {}      # (j, i) -> pair sent instead
        self.drop = set()         # identities (kind, sender, subject) never delivered
        self.extra = {}           # round -> list of raw messages also delivered (any sender)


def simulate(cfg, a, b, Hb=None, sc=None, a8=True):
    """One run with a common delivered set per round (broadcast agreement).

    Participant aborts (§5.1) run as rounds close: A9 at R2, A1/A2 at R3, A8 at R5 (before
    any RECONSTRUCTION), A3-A6 at R6, A7 at R7. A participant that aborts sends nothing
    afterwards. `a8=False` reproduces the pre-revision behaviour (no A8) for the F14
    comparison only.
    """
    Hb = Hb or H
    sc = sc or Script()
    t, n = cfg.t, cfg.n
    dl = deal(cfg, a, b, Hb)
    bc = []
    aborted = {}

    def live(j):
        return j not in aborted

    def put(raw):
        if (raw[33], raw[34], raw[35]) not in sc.drop:
            bc.append(raw)

    def extras(r):
        for raw in sc.extra.get(r, []):
            bc.append(raw)

    # Round 1: COMMITMENTS (broadcast) and SHARE (private)
    for i in range(1, n + 1):
        for pts in sc.commit.get(i, [dl[i]["C"]]):
            put(m_commitments(cfg, i, pts))
    priv = {}
    for i in range(1, n + 1):
        for j in range(1, n + 1):
            if i == j:
                continue
            pair = sc.share.get((i, j), (dl[i]["s"][j], dl[i]["sp"][j]))
            msgs = [] if pair is None else [m_share(cfg, i, j, *pair)]
            msgs += [m_share(cfg, i, j, *p) for p in sc.share_extra.get((i, j), [])]
            priv[(i, j)] = sc.private_raw.get((i, j), msgs)
    extras(1)

    # Round 2: participants check (4) and complain
    dv = Delivered(cfg, bc)
    Cview = {}
    for i in range(1, n + 1):
        m = dv.unique(1, (1, i, 0))
        if m is not None:
            Cview[i] = m.points
    received = {}
    sent_complaints = []
    for j in range(1, n + 1):
        for i in range(1, n + 1):
            if i == j or i not in Cview:
                continue           # R2: no complaint when COMMITMENTS is absent or in conflict
            # §4 channels: on the private channel from i, accept only a SHARE from i to j.
            wf_raws = set()
            for raw in priv[(i, j)]:
                pm, _ = parse(cfg, raw)
                if pm is not None and pm.kind == 2 and pm.sender == i and pm.subject == j:
                    wf_raws.add(raw)
            pair = parse(cfg, next(iter(wf_raws)))[0].pair if len(wf_raws) == 1 else None
            if pair is not None and eq4(cfg, Cview[i], j, pair[0], pair[1], Hb):
                received[(i, j)] = pair
            elif sc.complaint_ok(j, i):        # absent, in conflict, or fails (4)
                raw = m_complaint(cfg, j, i)
                sent_complaints.append((j, raw))
                put(raw)
    extras(2)
    for j, raw in sent_complaints:             # R2 closes: A9 (own COMPLAINT not delivered)
        if raw not in bc and live(j):
            aborted[j] = "A9"

    # Round 3: dealers answer complaints
    dv = Delivered(cfg, bc)
    compl = {i: set() for i in range(1, n + 1)}
    for m in dv.by_round[2].values():
        compl[m.subject].add(m.sender)
    for i in range(1, n + 1):
        if not live(i):
            continue
        for j in sorted(compl[i]):
            pair = sc.answer.get((i, j), (dl[i]["s"][j], dl[i]["sp"][j]))
            if pair is not None:
                put(m_answer(cfg, i, j, *pair))
    extras(3)
    st3 = recompute(cfg, bc, Hb, stop_after="R3")
    qual = st3["qual"]
    dv3 = st3["dv"]
    for j in range(1, n + 1):                  # R3 closes: A1 (public), A2 (participant)
        if not live(j):
            continue
        if st3["abort"] is not None:
            aborted[j] = st3["abort"]
        elif j not in qual:
            aborted[j] = "A2"

    # Pairs held by participant j from dealer i ("its pair")
    own = {}
    for j in range(1, n + 1):
        for i in range(1, n + 1):
            if i == j:
                own[(i, j)] = (dl[i]["s"][j], dl[i]["sp"][j])      # kept, not sent
            elif (i, j) in received:
                own[(i, j)] = received[(i, j)]
            elif i in Cview:
                ans = dv3.unique(3, (4, i, j))
                if ans is not None and eq4(cfg, Cview[i], j, ans.pair[0], ans.pair[1], Hb):
                    own[(i, j)] = ans.pair

    # Round 4: EXTRACTION from live QUAL dealers
    for i in qual:
        if live(i):
            for pts in sc.extraction.get(i, [dl[i]["A"]]):
                put(m_extraction(cfg, i, pts))
    extras(4)

    # Round 5: live participants check (5) and complain with their pairs
    dv = Delivered(cfg, bc)
    for j in range(1, n + 1):
        if not live(j):
            continue
        for i in qual:
            if i == j:
                continue
            m = dv.unique(4, (5, i, 0))
            pair = own.get((i, j))
            if m is None or pair is None:
                continue
            if not eq5(cfg, m.points, j, pair[0]):
                if sc.ec_senders is None or j in sc.ec_senders:
                    put(m_ext_complaint(cfg, j, i, *sc.ec_pair.get((j, i), pair)))
    extras(5)
    st5 = recompute(cfg, bc, Hb, stop_after="R5")
    marked = st5.get("marked", {})
    if a8:                                     # R5 closes: A8 (participant)
        for j in sorted(marked):
            if live(j):
                aborted[j] = "A8"

    # Round 6: live participants reconstruct every marked dealer i != j
    for i in sorted(marked):
        for j in range(1, n + 1):
            if j == i or not live(j) or not sc.recon_ok(j, i):
                continue
            pair = sc.recon_pair.get((j, i), own.get((i, j)))
            if pair is not None:
                put(m_reconstruction(cfg, j, i, *pair))
    extras(6)

    res = recompute(cfg, bc, Hb)

    # Outputs and the remaining checks (A3/A4/A5 public, A6 participant)
    x = {}
    for j in range(1, n + 1):
        if all((i, j) in own for i in res["qual"]):
            x[j] = sum(own[(i, j)][0] for i in res["qual"]) % L
        else:
            x[j] = None
        if not live(j):
            continue
        if res["abort"] is not None:
            aborted[j] = res["abort"]
        elif x[j] is None or smul(x[j], G) != res["Y"][j]:
            aborted[j] = "A6"
    conf = {}
    if res["abort"] is None:
        for j in res["qual"]:
            if live(j):
                conf[j] = m_confirmation(cfg, j, res["digest"], res["y"])
    r7 = [raw for raw in conf.values() if (raw[33], raw[34], raw[35]) not in sc.drop] + sc.extra.get(7, [])
    for j in sorted(conf):                     # R7 closes: A7
        if confirmation_check(cfg, res, r7, j) is not None:
            aborted[j] = "A7"
    pab = {j: aborted.get(j) for j in range(1, n + 1)}
    return {"cfg": cfg, "dl": dl, "bc": bc, "priv": priv, "own": own, "x": x,
            "res": res, "pab": pab, "conf": conf, "Hb": Hb}


# =============================================================================
# R7 / §5.1 A7, §8 admission (authenticate/roundClosed modelled as always true)
# =============================================================================


def conf_sets(cfg, qual, digest, y, conf_raws):
    """Distinct QUAL senders whose authenticated, well-formed (this session) CONFIRMATIONs
    match (digest, y), and those that differ. A sender with two different confirmations is an
    equivocator and counts as differing only. Inputs may be raw bytes (authenticated) or
    (raw, authenticated) tuples; unauthenticated ones are dropped."""
    by_sender = {}
    for item in conf_raws:
        raw, auth = item if isinstance(item, tuple) else (item, True)
        if not auth:
            continue
        m, _ = parse(cfg, raw)
        if m is None or m.kind != 8 or m.sender not in qual:
            continue
        by_sender.setdefault(m.sender, set()).add(raw)
    matching, differing = set(), set()
    for j, raws in by_sender.items():
        if len(raws) == 1:
            m = parse(cfg, next(iter(raws)))[0]
            if m.digest == digest and m.y == y:
                matching.add(j)
                continue
        differing.add(j)
    return matching, differing


def confirmation_check(cfg, res, conf_raws, self_j):
    """§5.1 A7 for participant self_j, run when R7 closes over its delivered round-7 view
    `conf_raws`: abort if at least t + 1 distinct QUAL members differ from its own (digest, y),
    or if fewer than t + 1 distinct members sent one equal to it. Its own confirmation counts
    only if it was delivered back to it, like any other. Up to t lies are ignored."""
    matching, differing = conf_sets(cfg, res["qual"], res["digest"], res["y"], conf_raws)
    if len(differing) >= cfg.t + 1 or len(matching) < cfg.t + 1:
        return "A7"
    return None


def round7_list(cfg, conf_raws):
    """§8 step 6: the canonical list of authenticated, well-formed CONFIRMATIONs for this
    session from any sender, byte-identical copies once, in §6 order."""
    ms = {}
    for item in conf_raws:
        raw, auth = item if isinstance(item, tuple) else (item, True)
        if not auth:
            continue
        m, _ = parse(cfg, raw)
        if m is not None and m.kind == 8:
            ms[raw] = m
    return [m.raw for m in sorted(ms.values(), key=sort_key)]


def delivered_round(cfg, posts, r):
    """§8 step 4: a round's delivered set from its board posts: drop anything malformed, for
    another session or round, a SHARE, or unauthenticated; byte-identical copies once; §6
    order. Posts are raw bytes (authenticated) or (raw, authenticated) tuples."""
    ms = {}
    for item in posts:
        raw, auth = item if isinstance(item, tuple) else (item, True)
        if not auth:
            continue
        m, _ = parse(cfg, raw)
        if m is None or m.round != r or m.kind == 2:
            continue
        ms[raw] = m
    return [m.raw for m in sorted(ms.values(), key=sort_key)]


def refusal_step(reason):
    """The §8 step at which `admit` refused."""
    if reason in ("malformed_transcript_message", "non_broadcast_transcript_message"):
        return 2
    if reason == "unauthenticated_transcript_message":
        return 3
    if reason in ("A1", "A3", "A4", "A5"):
        return 5
    if reason.startswith("round") and reason != "round7_not_closed":
        return 4
    return 6                                       # counting, or round-7 closure


def board_closure(cfg, boards, unauth=frozenset()):
    """The closure model of the replay vectors: roundClosed(r, list) is true iff list equals
    the delivered set (§8 step 4) of the posted board of round r (r = 1..7), where posts in
    `unauth` fail authentication."""
    lists = {r: delivered_round(cfg, [p for p in boards.get(r, []) if p not in unauth], r)
             for r in range(1, 8)}
    return lambda cfg_, r, lst: lst == lists[r]


def admit(cfg, transcript_msgs, conf_raws, Hb=None, round_closed=None, boards=None,
          unauth=frozenset()):
    """§8 steps 2-6. Returns ("admit" | "refuse", reason).

    `authenticate(bytes)` is false iff bytes is in `unauth` (it also accepts the legacy
    (raw, False) tuples on confirmations). With `boards` ({round: posts}), the transcript is
    each round's delivered set (the library's deliveredRound). `round_closed(cfg, r, list)`
    models the application's roundClosed for r = 1..7; None means always true.
    """
    if boards is not None:
        transcript_msgs = [raw for r in range(1, 7)
                           for raw in delivered_round(cfg, [p for p in boards.get(r, []) if p not in unauth], r)]
    for raw in transcript_msgs:                    # step 2: well-formed for this session,
        m, _ = parse(cfg, raw)                     # and a broadcast of rounds 1-6
        if m is None:
            return "refuse", "malformed_transcript_message"
        if m.kind in (2, 8):                       # a misplaced SHARE or CONFIRMATION
            return "refuse", "non_broadcast_transcript_message"
    for raw in transcript_msgs:                    # step 3: authenticate every transcript message
        if raw in unauth:
            return "refuse", "unauthenticated_transcript_message"
    if round_closed is not None:                   # step 4
        for r in range(1, 7):
            if not round_closed(cfg, r, delivered_round(cfg, transcript_msgs, r)):
                return "refuse", "round%d_not_closed" % r
    res = recompute(cfg, transcript_msgs, Hb)      # step 5
    if res["abort"] in ("A1", "A3", "A4", "A5"):
        return "refuse", res["abort"]
    confs = [c for c in conf_raws if (c[0] if isinstance(c, tuple) else c) not in unauth]
    if round_closed is not None and not round_closed(cfg, 7, round7_list(cfg, confs)):
        return "refuse", "round7_not_closed"       # step 6
    matching, differing = conf_sets(cfg, res["qual"], res["digest"], res["y"], confs)
    if len(differing) >= cfg.t + 1:
        return "refuse", "differing_t_plus_1"      # mirrors A7
    if len(matching) < cfg.t + 1:
        return "refuse", "fewer_than_t_plus_1_matching"
    return "admit", "ok"


# =============================================================================
# §9: threshold decryption
# =============================================================================


class CombineError(Exception):
    pass


def encrypt(m, k, pk):
    """elgamal-jubjub-v1 §4: A = [k]G, B = [m]G + [k]PK."""
    return smul(k, G), padd(smul(m, G), smul(k, pk))


def dlog(M, bound):
    acc = O
    for t in range(bound + 1):
        if acc == M:
            return t
        acc = padd(acc, G)
    return None


def combine(t, qual, Bc, shares, bound):
    ids_ = sorted(shares)
    if len(ids_) < t + 1:
        raise CombineError("fewer than t+1 shares")
    if any(j not in qual for j in ids_):
        raise CombineError("share from outside QUAL")
    S = ids_[:t + 1]
    M = Bc
    for j in S:
        M = psub(M, smul(lagrange_at_zero(S, j), shares[j]))
    for e in ids_[t + 1:]:
        expect = psum(smul(lagrange_at(S, j, e), shares[j]) for j in S)
        if expect != shares[e]:
            raise CombineError("extra share %d inconsistent" % e)
    m = dlog(M, bound)
    if m is None:
        raise CombineError("no plaintext in range")
    return m


# =============================================================================
# Replayable case vectors (review finding R7)
# =============================================================================

CASES = []


def config_str(cfg):
    return "%d,%d,%s,%d" % (cfg.t, cfg.n, cfg.ctx.hex(), cfg.attempt)


def public_expect(cfg, posts, Hb=None):
    """The outcome a replay of the public rules must reproduce."""
    res = recompute(cfg, posts, Hb)
    if res["abort"] in ("A1", "A3", "A4", "A5"):
        return "abort=" + res["abort"]
    return "qual=%s;marked=%s;y=%s" % (ids(res["qual"]), ids(sorted(res["marked"])),
                                       encode(res["y"]).hex())


def add_case(name, items):
    """`items` is an ordered list of (suffix, value) emitted as case.<name>.<suffix>."""
    CASES.append((name, items))


def transcript_items(cfg, posts, Hb=None):
    items = [("config", config_str(cfg))]
    if Hb is not None and Hb != H:
        items.append(("H", encode(Hb).hex()))
    dv = Delivered(cfg, posts)
    canon = [m.raw for r in range(1, 7) for m in dv.ordered(r)]
    items += [("msg.%d" % k, raw.hex()) for k, raw in enumerate(canon, 1)]
    if len(posts) != len(canon) or set(posts) != set(canon):
        items += [("raw.%d" % k, raw.hex()) for k, raw in enumerate(posts, 1)]
    return items


def add_public_case(name, cfg, posts, Hb=None):
    add_case(name, transcript_items(cfg, posts, Hb) + [("expect", public_expect(cfg, posts, Hb))])


def roster_from_spec(spec, n):
    """`standard`: key_j = 32 bytes of j; `lengths:L1,..`: key_j = byte j repeated L_j times
    (pairwise distinct); `hex:k1,..`: the keys given in hex."""
    if spec == "standard":
        return roster(n)
    if spec.startswith("lengths:"):
        return [bytes([j]) * int(x) for j, x in enumerate(spec[len("lengths:"):].split(","), 1)]
    if spec.startswith("hex:"):
        return [bytes.fromhex(x) for x in spec[len("hex:"):].split(",")]
    raise ValueError("roster spec")


def replay_case(items):
    """Re-derive a case's outcome from its emitted items only (vector self-consistency)."""
    d = dict(items)
    t_, n_, ctx_hex, att = d["config"].split(",")
    t_, n_, att = int(t_), int(n_), int(att)
    ctx_ = bytes.fromhex(ctx_hex)
    if "params" in d:
        try:
            c = Config(t_, n_, ctx_, att, roster_from_spec(d["roster"], n_))
            return d["params"] == "accept" and d.get("session") == c.session.hex()
        except ValueError:
            return d["params"] == "reject" and "session" not in d
    cfg_ = Config(t_, n_, ctx_, att, roster(n_))
    if "decode" in d:
        return ("accept" if parse(cfg_, bytes.fromhex(d["msg.1"]))[0] is not None else "reject") == d["decode"]
    if "ciphertext" in d:
        ct = bytes.fromhex(d["ciphertext"])
        shares = {int(k.split(".")[1]): decode(bytes.fromhex(v))[0] for k, v in items if k.startswith("share.")}
        qual_ = [int(x) for x in d["qual"].split(",")]
        try:
            got = "plaintext:%d" % combine(t_, qual_, decode(ct[32:])[0], shares, int(d["bound"]))
        except CombineError:
            got = "error"
        if d["expect"].startswith("not_plaintext:"):
            return got != "plaintext:" + d["expect"][len("not_plaintext:"):]
        return got == d["expect"]
    Hb = decode(bytes.fromhex(d["H"]))[0] if "H" in d else H
    msgs = [bytes.fromhex(v) for k, v in items if k.startswith("msg.")]
    raws = [bytes.fromhex(v) for k, v in items if k.startswith("raw.")]
    confs = [bytes.fromhex(v) for k, v in items if k.startswith("confirmation.")]
    unauth = frozenset(bytes.fromhex(v) for k, v in items if k.startswith("unauthenticated."))
    boards = {}
    for k, v in items:
        if k.startswith("board."):
            boards.setdefault(int(k.split(".")[1]), []).append(bytes.fromhex(v))
    if d["expect"] in ("admit", "refuse"):
        closure = board_closure(cfg_, boards, unauth) if d.get("closure") == "board" else None
        v, r = admit(cfg_, msgs, confs, Hb, round_closed=closure, unauth=unauth)
        if v != d["expect"]:
            return False
        return v == "admit" and "step" not in d or v == "refuse" and d.get("step") == str(refusal_step(r))
    ok = public_expect(cfg_, msgs, Hb) == d["expect"]
    if raws:
        ok = ok and public_expect(cfg_, raws, Hb) == d["expect"]
    return ok


CASE_FAMILIES = ("abort.", "rule.", "finding.", "wf.")


def emit_cases():
    bad = []
    for name, items in CASES:
        for suffix, value in items:
            emit("case.%s.%s" % (name, suffix), value)
        if not replay_case(items):
            bad.append(name)
    vectored = {name for name, _ in CASES}
    internal = []
    for line in LINES:
        key = line.split("=", 1)[0]
        if key.startswith(CASE_FAMILIES) and key not in vectored and key not in internal:
            internal.append(key)
    emit("info.case_count", len(CASES))
    for fam in CASE_FAMILIES:
        emit("info.case_count.%s" % fam[:-1], sum(1 for n, _ in CASES if n.startswith(fam)))
    emit("info.case_internal_only", ",".join(internal))
    emit("info.case_replay_failures", ",".join(bad))
    chk("check.case_vectors_replay_self_consistent", not bad)


# =============================================================================
# Fixture emission helpers
# =============================================================================

HONEST_CTX = b"zeroj.test.honest"


def coeffs_from_tags(n, t):
    a = {i: [scalar("a.%d.%d" % (i, k)) for k in range(t + 1)] for i in range(1, n + 1)}
    b = {i: [scalar("b.%d.%d" % (i, k)) for k in range(t + 1)] for i in range(1, n + 1)}
    return a, b


def emit_run(F, sim):
    cfg, dl, res = sim["cfg"], sim["dl"], sim["res"]
    t, n = cfg.t, cfg.n
    emit(F + ".t", t)
    emit(F + ".n", n)
    emit(F + ".ctx", cfg.ctx.hex())
    emit(F + ".attempt", cfg.attempt)
    emit(F + ".session", cfg.session.hex())
    emit(F + ".qual", ids(res["qual"]))
    emit(F + ".disqualified", ",".join("%d:%s" % (i, r) for i, r in sorted(res["dq"].items())))
    emit(F + ".marked", ids(sorted(res.get("marked", {}))))
    emit(F + ".marked_by", ",".join("%d:%s" % (i, r) for i, r in sorted(res.get("marked", {}).items())))
    for i in range(1, n + 1):
        for k in range(t + 1):
            emit("%s.a.%d.%d" % (F, i, k), fe(dl[i]["a"][k]))
    for i in range(1, n + 1):
        for k in range(t + 1):
            emit("%s.b.%d.%d" % (F, i, k), fe(dl[i]["b"][k]))
    for i in range(1, n + 1):
        for k in range(t + 1):
            emit("%s.C.%d.%d" % (F, i, k), encode(dl[i]["C"][k]).hex())
    for i in range(1, n + 1):
        for k in range(t + 1):
            emit("%s.A.%d.%d" % (F, i, k), encode(dl[i]["A"][k]).hex())
    for i in range(1, n + 1):
        for j in range(1, n + 1):
            emit("%s.s.%d.%d" % (F, i, j), fe(dl[i]["s"][j]))
    for i in range(1, n + 1):
        for j in range(1, n + 1):
            emit("%s.sp.%d.%d" % (F, i, j), fe(dl[i]["sp"][j]))
    for j in range(1, n + 1):
        if sim["x"][j] is not None:
            emit("%s.x.%d" % (F, j), fe(sim["x"][j]))
    emit(F + ".y", encode(res["y"]).hex())
    for j in range(1, n + 1):
        emit("%s.Y.%d" % (F, j), encode(res["Y"][j]).hex())
        emit("%s.Y.%d.identity" % (F, j), res["Y"][j] == O)
    dv = res["dv"]
    for r in range(1, 7):
        for m in dv.ordered(r):
            emit("%s.msg.%d.%d.%d.%d" % (F, m.round, m.kind, m.sender, m.subject), m.raw.hex())
    for kind in range(1, 8):
        if kind == 2:
            continue
        emit("%s.count.%s" % (F, KIND_NAME[kind]), len(dv.by_round[KIND_ROUND[kind]]))
    emit(F + ".counts", ",".join(str(len(dv.by_round[r])) for r in range(1, 7)))
    emit(F + ".transcript", res["transcript"].hex())
    emit(F + ".digest", res["digest"].hex())
    for j in res["qual"]:
        if j in sim["conf"]:
            emit("%s.confirmation.%d" % (F, j), sim["conf"][j].hex())
    for j in range(1, n + 1):
        emit("%s.participant_abort.%d" % (F, j), sim["pab"][j] or "none")


def common_checks(F, sim, true_qual):
    cfg, dl, res = sim["cfg"], sim["dl"], sim["res"]
    t, n = cfg.t, cfg.n
    chk(F + ".check.public_abort_none", res["abort"] is None)
    chk(F + ".check.qual_expected", res["qual"] == true_qual)
    y_ref = smul(sum(dl[i]["a"][0] for i in true_qual) % L, G)
    chk(F + ".check.y_equals_sum_of_true_a_i0", res["y"] == y_ref)
    ok_Y = all(res["Y"][j] == smul(sum(dl[i]["s"][j] for i in true_qual) % L, G)
               for j in range(1, n + 1))
    chk(F + ".check.Y_equals_true_polynomials", ok_Y)
    ok_x = all(sim["x"][j] == sum(dl[i]["s"][j] for i in true_qual) % L for j in range(1, n + 1))
    chk(F + ".check.x_equals_sum_of_true_shares", ok_x)
    for j in range(1, n + 1):
        chk("%s.check.A6.%d" % (F, j), smul(sim["x"][j], G) == res["Y"][j])
    chk(F + ".check.all_broadcasts_well_formed", all(parse(cfg, r)[0] is not None for r in sim["bc"]))
    chk(F + ".check.all_shares_well_formed",
        all(parse(cfg, r)[0] is not None for lst in sim["priv"].values() for r in lst))
    pts = [res["y"]] + list(res["Y"].values()) + [q for i in dl for q in dl[i]["C"] + dl[i]["A"]]
    chk(F + ".check.encode_decode_roundtrip", all(decode(encode(q))[0] == q for q in pts))
    chk(F + ".check.all_points_in_subgroup", all(in_subgroup(q) for q in pts))
    # Arrival-order independence: shuffle the delivered broadcasts, add byte-identical copies.
    same = True
    for seed in (1, 2, 3):
        msgs = list(sim["bc"]) + [sim["bc"][0], sim["bc"][-1], sim["bc"][len(sim["bc"]) // 2]]
        random.Random(seed).shuffle(msgs)
        r2 = recompute(cfg, msgs, sim["Hb"])
        same = same and r2["digest"] == res["digest"] and r2["qual"] == res["qual"] \
            and r2["y"] == res["y"] and r2["Y"] == res["Y"]
    chk(F + ".check.digest_independent_of_arrival_order", same)
    sent = list(sim["conf"].values())
    chk(F + ".check.confirmations_sent_by_live_qual_members",
        sorted(sim["conf"]) == [j for j in res["qual"] if sim["pab"][j] is None])
    chk(F + ".check.confirmations_agree_A7_none",
        all(confirmation_check(cfg, res, sent, j) is None for j in sim["conf"]))
    chk(F + ".check.admission_accepts", admit(cfg, sim["bc"], sent, sim["Hb"])[0] == "admit")


def decryption_block(F, sim, m, width):
    cfg, res = sim["cfg"], sim["res"]
    t, qual = cfg.t, res["qual"]
    bound = (1 << width) - 1
    k = scalar("enc.k")
    Ac, Bc = encrypt(m, k, res["y"])
    emit(F + ".enc.m", m)
    emit(F + ".enc.width", width)
    emit(F + ".enc.A", encode(Ac).hex())
    emit(F + ".enc.B", encode(Bc).hex())
    Dsh = {}
    for j in qual:
        Dsh[j] = smul(sim["x"][j], Ac)
        emit("%s.D.%d" % (F, j), encode(Dsh[j]).hex())
    # DLEQ relation (X = A, P = Y_j, D = D_j) holds with witness x_j (local share = verified)
    chk(F + ".check.dleq_relations",
        all(smul(sim["x"][j], G) == res["Y"][j] and smul(sim["x"][j], Ac) == Dsh[j] for j in qual))
    x_secret = sum(sim["dl"][i]["a"][0] for i in qual) % L
    for S in itertools.combinations(qual, t + 1):
        sn = subset_name(S)
        for j in S:
            emit("%s.lagrange.%s.%d" % (F, sn, j), fe(lagrange_at_zero(S, j)))
    for S in itertools.combinations(qual, t + 1):
        sn = subset_name(S)
        try:
            got = combine(t, qual, Bc, {j: Dsh[j] for j in S}, bound)
        except CombineError as e:
            got = "error:" + str(e)
        emit("%s.decrypt.%s" % (F, sn), got)
        chk("%s.check.decrypt.%s" % (F, sn), got == m)
        chk("%s.check.sum_lambda_x.%s" % (F, sn),
            sum(lagrange_at_zero(S, j) * sim["x"][j] for j in S) % L == x_secret)
    try:
        got = combine(t, qual, Bc, dict(Dsh), bound)
    except CombineError as e:
        got = "error:" + str(e)
    emit(F + ".decrypt.all", got)
    chk(F + ".check.extra_shares_consistent", got == m)
    return Ac, Bc, Dsh


# =============================================================================
# Main
# =============================================================================


def main():
    t0 = __import__("time").time()
    emit_header = [
        "# profile: elgamal-jubjub-threshold-v1 (independent reference, ADR-0053 M0)",
        "# command: python3 elgamal_jubjub_threshold_v1_reference.py",
        "# Python: %s" % platform.python_version(),
        "# independence: written from docs/specs/elgamal-jubjub-threshold-v1.md, elgamal-jubjub-v1.md,"
        " pedersen-jubjub-v1.md and GJKR07 (Fig. 2, Sec. 2.2, Sec. 4) only; no ZeroJ source code was read",
    ]
    emit("profile", "elgamal-jubjub-threshold-v1")

    # ---------------------------------------------------------------- curve and bases
    emit("curve.p", fe(P))
    emit("curve.l", fe(L))
    emit("curve.d", fe(D))
    chk("check.d_derived_matches_pin", D == D_PIN)
    chk("check.d_nonsquare", pow(D, (P - 1) // 2, P) == P - 1)
    chk("check.minus_one_square", pow(P - 1, (P - 1) // 2, P) == 1)
    chk("check.g_full_on_curve", on_curve(G_FULL))
    chk("check.g_full_not_in_subgroup", pmul(L, G_FULL) != O)
    emit("G.u", fe(G[0]))
    emit("G.v", fe(G[1]))
    emit("G.encoding", encode(G).hex())
    chk("spec_match.G.u", G[0] == G_U_PIN)
    chk("spec_match.G.v", G[1] == G_V_PIN)
    chk("spec_match.G.encoding", encode(G).hex() == G_ENC_PIN)
    chk("check.G_in_subgroup_not_identity", in_subgroup(G) and G != O)
    emit("H.u", fe(H[0]))
    emit("H.v", fe(H[1]))
    emit("H.encoding", encode(H).hex())
    chk("spec_match.H.encoding", encode(H).hex() == H_ENC_PIN)
    chk("spec_match.H.decode", decode(bytes.fromhex(H_ENC_PIN))[0] == H)
    chk("check.H_in_subgroup_not_identity_not_G", in_subgroup(H) and H != O and H != G)
    # Cross-checks of G, H, Enc and the scalar convention against the referenced specs' pins.
    sk = scalar_v1("sk")
    pk = smul(sk, G)
    chk("spec_match.elgamal_v1.scalar_sk",
        sk == 0x0281799C40FB5BCA4F8CC6AF4812FAE96CDF7113E1AB203EA4D73FB7027E8343)
    chk("spec_match.elgamal_v1.pk_encoding",
        encode(pk).hex() == "36d7d5a69ac65a6761ac10fd3338bd4692939aefc4f5d5a1eb37477b29423e68")
    a1, b1 = encrypt(1, scalar_v1("k1"), pk)
    chk("spec_match.elgamal_v1.enc_1_k1",
        (encode(a1) + encode(b1)).hex() ==
        "5c60657a3d709bbc2e68f03e5146b357b45066b21f21e914decbddefef876ea2"
        "0115a214bbe47745f99a8130d1bd2b48b788883d95d468069d0677081dc5f772")
    chk("spec_match.pedersen_v1.c_42_12345",
        encode(padd(smul(42, G), smul(12345, H))).hex() ==
        "57d3e074295e7feb8231baa675b3da817c6d45929590ce747b17b7e73bc387e3")
    # BLAKE2b-256 is the digest-length-32 instance, not truncated BLAKE2b-512.
    chk("check.blake2b256_abc_kat", blake2b256(b"abc").hex() ==
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")
    chk("check.blake2b256_is_not_truncated_blake2b512",
        blake2b256(b"abc") != hashlib.blake2b(b"abc").digest()[:32])

    # ---------------------------------------------------------------- sessions (§2)
    session_fixtures = [
        ("session", 1, 3, b"zeroj.test.election", 1),
        ("honest-2of3", 1, 3, HONEST_CTX, 1),
        ("honest-3of5", 2, 5, HONEST_CTX, 1),
        ("honest-4of7", 3, 7, HONEST_CTX, 1),
        ("zero-share", 1, 3, b"zeroj.test.zero-share", 1),
        ("equal-shares", 1, 3, b"zeroj.test.equal-shares", 1),
        ("adversarial-4of7", 3, 7, b"zeroj.test.adversarial", 7),
    ]
    cfgs = {}
    for name, t, n, ctx, att in session_fixtures:
        cfgs[name] = Config(t, n, ctx, att, roster(n))
        emit("session.%s" % name, cfgs[name].session.hex())
    emit("session.session.preimage", cfgs["session"].preimage.hex())
    emit("session.session.key_1", roster(3)[0].hex())
    chk("check.sessions_distinct", len({c.session for c in cfgs.values()}) == len(cfgs))
    chk("check.session_attempt_changes_session",
        Config(1, 3, b"zeroj.test.election", 2, roster(3)).session != cfgs["session"].session)

    # ---------------------------------------------------------------- honest fixtures
    honest_sims = {}
    for name, t, n in (("honest-2of3", 1, 3), ("honest-3of5", 2, 5), ("honest-4of7", 3, 7)):
        cfg = cfgs[name]
        a, b = coeffs_from_tags(n, t)
        sim = simulate(cfg, a, b)
        honest_sims[name] = sim
        emit_run(name, sim)
        common_checks(name, sim, list(range(1, n + 1)))
        dv = sim["res"]["dv"]
        chk(name + ".check.rounds_2_3_5_6_empty",
            [len(dv.by_round[r]) for r in range(1, 7)] == [n, 0, 0, n, 0, 0])
        chk(name + ".check.no_marks", not sim["res"]["marked"])
        decryption_block(name, sim, 5, 3)

    # ---------------------------------------------------------------- zero-share, equal-shares
    special_sims = {}
    for name, slopes in (("zero-share", (1, 2, L - 6)), ("equal-shares", (1, 2, L - 3))):
        cfg = cfgs[name]
        a = {i: [1, slopes[i - 1]] for i in (1, 2, 3)}
        b = {i: [scalar("b.%d.%d" % (i, k)) for k in range(2)] for i in (1, 2, 3)}
        sim = simulate(cfg, a, b)
        special_sims[name] = sim
        emit_run(name, sim)
        common_checks(name, sim, [1, 2, 3])
        Fc = [sum(a[i][k] for i in (1, 2, 3)) % L for k in range(2)]
        emit(name + ".F_coeffs", ",".join(fe(c) for c in Fc))
        res = sim["res"]
        chk(name + ".check.y_is_3G", res["y"] == smul(3, G))
        if name == "zero-share":
            chk(name + ".check.F_is_3_minus_3z", Fc == [3, L - 3])
            chk(name + ".check.x_1_is_zero", sim["x"][1] == 0)
            chk(name + ".check.Y_1_identity", res["Y"][1] == O)
            chk(name + ".check.Y_j_is_F_j_G",
                all(res["Y"][j] == smul(3 - 3 * j, G) for j in (1, 2, 3)))
        else:
            chk(name + ".check.F_is_3", Fc == [3, 0])
            chk(name + ".check.all_Y_equal_3G", all(res["Y"][j] == smul(3, G) for j in (1, 2, 3)))
            chk(name + ".check.all_x_equal_3", all(sim["x"][j] == 3 for j in (1, 2, 3)))
        _, _, Dsh = decryption_block(name, sim, 1, 1)
        if name == "zero-share":
            chk(name + ".check.D_1_identity", Dsh[1] == O)

    # ---------------------------------------------------------------- adversarial-4of7
    # Deviations of dealers 1, 3 and 5 only; everyone else (and the deviators otherwise)
    # follows §5, and an aborting participant sends nothing afterwards.
    F = "adversarial-4of7"
    cfg = cfgs[F]
    a, b = coeffs_from_tags(7, 3)
    dl = deal(cfg, a, b, H)
    sc = Script()
    sc.share[(1, 2)] = ((dl[1]["s"][2] + 1) % L, dl[1]["sp"][2])      # R1 deviation, dealer 1
    sc.share[(3, 4)] = ((dl[3]["s"][4] + 1) % L, dl[3]["sp"][4])      # R1 deviation, dealer 3
    sc.answer[(3, 4)] = None                                           # R3: dealer 3 silent
    sc.extraction[1] = []                                              # R4: dealer 1 withholds
    sc.extraction[5] = [[dl[5]["A"][0], padd(dl[5]["A"][1], G)] + dl[5]["A"][2:]]   # R4: forged
    sim = simulate(cfg, a, b, H, sc)
    res = sim["res"]
    emit_run(F, sim)
    emit(F + ".share.1.2", sim["priv"][(1, 2)][0].hex())
    emit(F + ".share.3.4", sim["priv"][(3, 4)][0].hex())
    emit(F + ".A_broadcast.5.1", encode(padd(dl[5]["A"][1], G)).hex())
    for i in sorted(res["recon"]):
        rc = res["recon"][i]
        emit("%s.recon.%d.valid_senders" % (F, i), ids(rc["valid"]))
        emit("%s.recon.%d.used_senders" % (F, i), ids(rc["used"]))
        for k in range(cfg.t + 1):
            emit("%s.recon.%d.a.%d" % (F, i, k), fe(rc["a"][k]))
            emit("%s.recon.%d.b.%d" % (F, i, k), fe(rc["b"][k]))
            emit("%s.recon.%d.A.%d" % (F, i, k), encode(res["A"][i][k]).hex())
    common_checks(F, sim, [1, 2, 4, 5, 6, 7])
    dv = res["dv"]
    chk(F + ".check.qual_is_1_2_4_5_6_7", res["qual"] == [1, 2, 4, 5, 6, 7])
    chk(F + ".check.dealer3_disqualified", res["dq"] == {3: "R3_answer_absent_or_conflict"})
    chk(F + ".check.dealer1_marked", res["marked"].get(1) == "R4")
    chk(F + ".check.dealer5_marked", res["marked"].get(5) == "R5")
    chk(F + ".check.ext_complaints_1_2_4_6_7_valid",
        res["valid_ec"] == [(1, 5), (2, 5), (4, 5), (6, 5), (7, 5)])
    chk(F + ".check.complaints_are_2_to_1_and_4_to_3",
        sorted(m.key() for m in dv.by_round[2].values()) == [(3, 2, 1), (3, 4, 3)])
    chk(F + ".check.answer_is_1_to_2",
        sorted(m.key() for m in dv.by_round[3].values()) == [(4, 1, 2)])
    chk(F + ".check.extractions_from_2_4_5_6_7",
        sorted(m.sender for m in dv.by_round[4].values()) == [2, 4, 5, 6, 7])
    chk(F + ".check.reconstructions_from_2_4_6_7",
        sorted((m.subject, m.sender) for m in dv.by_round[6].values()) ==
        [(1, j) for j in (2, 4, 6, 7)] + [(5, j) for j in (2, 4, 6, 7)])
    chk(F + ".check.reconstruction_uses_exactly_t_plus_1",
        all(res["recon"][i]["valid"] == [2, 4, 6, 7] == res["recon"][i]["used"] for i in (1, 5)))
    counts = [len(dv.by_round[r]) for r in range(1, 7)]
    chk(F + ".check.message_counts_7_2_1_5_5_8", counts == [7, 2, 1, 5, 5, 8])
    y_ref = psum(smul(a[i][0], G) for i in (1, 2, 4, 5, 6, 7))
    chk(F + ".y_equals_reference", res["y"] == y_ref)
    chk(F + ".check.dealers_1_5_contributions_kept",
        res["A"][1] == dl[1]["A"] and res["A"][5] == dl[5]["A"])
    chk(F + ".check.bad_shares_fail_eq4",
        not eq4(cfg, dl[1]["C"], 2, *parse(cfg, sim["priv"][(1, 2)][0])[0].pair, H) and
        not eq4(cfg, dl[3]["C"], 4, *parse(cfg, sim["priv"][(3, 4)][0])[0].pair, H))
    chk(F + ".check.participant2_adopted_answer", sim["own"][(1, 2)] == (dl[1]["s"][2], dl[1]["sp"][2]))
    chk(F + ".check.participant_aborts_A8_none_A2_none_A8_none_none",
        [sim["pab"][j] for j in range(1, 8)] == ["A8", None, "A2", None, "A8", None, None])
    chk(F + ".check.confirmations_from_2_4_6_7", sorted(sim["conf"]) == [2, 4, 6, 7])
    chk(F + ".check.deviators_are_exactly_t", len({1, 3, 5}) == cfg.t)
    # A7 and admission: the deviators' lies (QUAL members 1 and 5 confirming another record,
    # participant 3 outside QUAL) are at most t, so they are ignored and the run is admitted.
    good = [sim["conf"][j] for j in (2, 4, 6, 7)]
    junk3 = m_confirmation(cfg, 3, b"\x00" * 32, G)
    junk1 = m_confirmation(cfg, 1, b"\x00" * 32, G)
    junk5 = m_confirmation(cfg, 5, b"\x00" * 32, G)
    lies = [junk1, junk3, junk5]
    chk(F + ".check.A7_ignores_deviator_lies",
        all(confirmation_check(cfg, res, good + lies, j) is None for j in (2, 4, 6, 7)))
    chk(F + ".check.admission_ignores_deviator_lies", admit(cfg, sim["bc"], good + lies) == ("admit", "ok"))
    chk(F + ".check.admission_t_matching_refused",
        admit(cfg, sim["bc"], good[:3] + lies) == ("refuse", "fewer_than_t_plus_1_matching"))
    # t + 1 differing QUAL confirmations (1, 5 and two honest members on another board): A7.
    other = [m_confirmation(cfg, j, b"\x22" * 32, res["y"]) for j in (6, 7)]
    chk(F + ".check.A7_on_t_plus_1_differing",
        confirmation_check(cfg, res, good[:2] + other + [junk1, junk5], 2) == "A7")
    # Second A7 clause: if participant 7's confirmation is lost, 2, 4 and 6 see only 3 < t + 1
    # matching (themselves included) and abort.
    chk(F + ".check.A7_on_fewer_than_t_plus_1_matching",
        all(confirmation_check(cfg, res, good[:3], j) == "A7" for j in (2, 4, 6)))
    decryption_block(F, sim, 5, 3)
    adv_sim = sim

    # ---------------------------------------------------------------- negative / abort cases
    base = honest_sims["honest-3of5"]
    c3 = base["cfg"]
    a3, b3 = coeffs_from_tags(5, 2)
    d3 = base["dl"]

    def outcome(sim_, j=None):
        r = sim_["res"]
        if j is not None:
            return sim_["pab"][j] or "none"
        return r["abort"] or "none"

    def case(name, got, expected, prefix="abort", vec=None):
        emit("%s.%s" % (prefix, name), got)
        chk("check.%s.%s" % (prefix, name), got == expected)
        if vec is not None:
            add_public_case("%s.%s" % (prefix, name), vec["cfg"], vec["bc"], vec["Hb"])


    # A1: t+1 dealers silent -> |QUAL| = n - t - 1
    sc = Script()
    for i in (1, 2, 3):
        sc.commit[i] = []
    s_ = simulate(c3, a3, b3, H, sc)
    case("A1_t_plus_1_dealers_silent", outcome(s_), "A1", vec=s_)
    chk("check.abort.A1_qual", s_["res"]["qual"] == [4, 5])
    chk("check.abort.A1_every_participant_aborts", all(s_["pab"][j] == "A1" for j in range(1, 6)))
    chk("check.abort.A1_admission_refuses", admit(c3, s_["bc"], []) == ("refuse", "A1"))
    # A1 boundary: t dealers silent -> |QUAL| = n - t, no abort
    sc = Script()
    for i in (1, 2):
        sc.commit[i] = []
    s_ = simulate(c3, a3, b3, H, sc)
    case("A1_boundary_t_dealers_silent", outcome(s_), "none", vec=s_)
    chk("check.abort.A1_boundary_y", s_["res"]["y"] == psum(d3[i]["A"][0] for i in (3, 4, 5)))
    case("A2_boundary_silent_dealer_1_participant_check", outcome(s_, 1), "A2", vec=s_)

    # A2: dealer 1's correct ANSWER is lost (not delivered) -> participant 1 sees itself out
    sc = Script()
    sc.share[(1, 2)] = ((d3[1]["s"][2] + 1) % L, d3[1]["sp"][2])
    sc.drop.add((4, 1, 2))
    s_ = simulate(c3, a3, b3, H, sc)
    case("A2_own_answer_not_delivered", outcome(s_, 1), "A2", vec=s_)
    chk("check.abort.A2_public_no_abort", s_["res"]["abort"] is None and s_["res"]["qual"] == [2, 3, 4, 5])
    chk("check.abort.A2_participant_sends_nothing_after",
        not any(m[34] == 1 and m[32] >= 4 for m in s_["bc"]) and 1 not in s_["conf"])

    # A3: dealer 5 withholds EXTRACTION; only t participants reconstruct
    sc = Script()
    sc.extraction[5] = []
    sc.recon_ok = lambda j, i: j in (1, 2)
    s_ = simulate(c3, a3, b3, H, sc)
    case("A3_only_t_reconstructions", outcome(s_), "A3", vec=s_)
    chk("check.abort.A3_admission_refuses", admit(c3, s_["bc"], []) == ("refuse", "A3"))
    # A3: t+1 reconstructions but one fails (4)
    sc = Script()
    sc.extraction[5] = []
    sc.recon_ok = lambda j, i: j in (1, 2, 3)
    sc.recon_pair[(3, 5)] = ((d3[5]["s"][3] + 1) % L, d3[5]["sp"][3])
    s_ = simulate(c3, a3, b3, H, sc)
    case("A3_one_of_t_plus_1_reconstructions_fails_eq4", outcome(s_), "A3", vec=s_)
    # control: t+1 valid reconstructions succeed and keep the contribution; dealer 5 aborts A8
    sc = Script()
    sc.extraction[5] = []
    sc.recon_ok = lambda j, i: j in (1, 2, 3)
    s_ = simulate(c3, a3, b3, H, sc)
    case("A3_control_t_plus_1_valid_reconstructions", outcome(s_), "none", vec=s_)
    chk("check.abort.A3_control_y", s_["res"]["y"] == base["res"]["y"] and s_["res"]["Y"] == base["res"]["Y"])
    case("A8_withheld_extraction_dealer_aborts", outcome(s_, 5), "A8", vec=s_)
    chk("check.abort.A8_others_confirm", sorted(s_["conf"]) == [1, 2, 3, 4])
    # R6: a conflicting RECONSTRUCTION is excluded, the remaining t+1 suffice
    sc = Script()
    sc.extraction[5] = []
    sc.recon_ok = lambda j, i: j in (1, 2, 3, 4)
    sc.extra[6] = [m_reconstruction(c3, 1, 5, (d3[5]["s"][1] + 7) % L, d3[5]["sp"][1])]
    s_ = simulate(c3, a3, b3, H, sc)
    case("R6_conflicting_reconstruction_excluded", outcome(s_), "none", prefix="rule", vec=s_)
    chk("check.rule.R6_conflicting_reconstruction_senders", s_["res"]["recon"][5]["valid"] == [2, 3, 4])

    # A4: needs a pair satisfying (4) that is off the polynomial, i.e. knowledge of log_G H.
    # Exercised with a reference-only trapdoor base H' = [w]G (NOT the profile's H).
    w = reference_only_scalar("trapdoor.w")
    Ht = smul(w, G)
    dt = deal(c3, a3, b3, Ht)
    forged4 = ((dt[5]["s"][4] - w) % L, (dt[5]["sp"][4] + 1) % L)
    forged1 = ((dt[5]["s"][1] - w) % L, (dt[5]["sp"][1] + 1) % L)
    chk("check.abort.A4_forged_pair_satisfies_eq4_under_trapdoor",
        eq4(c3, dt[5]["C"], 4, forged4[0], forged4[1], Ht) and forged4 != (dt[5]["s"][4], dt[5]["sp"][4]))
    sc = Script()
    sc.extraction[5] = []
    sc.recon_pair[(4, 5)] = forged4
    s_ = simulate(c3, a3, b3, Ht, sc)
    case("A4_trapdoor_forged_extra_pair", outcome(s_), "A4", vec=s_)
    emit("info.abort.A4_trapdoor_forged_extra_pair.detail", s_["res"]["abort_detail"])
    sc = Script()
    sc.extraction[5] = []
    sc.recon_pair[(1, 5)] = forged1
    s_ = simulate(c3, a3, b3, Ht, sc)
    case("A4_trapdoor_forged_base_pair", outcome(s_), "A4", vec=s_)
    emit("info.abort.A4_trapdoor_forged_base_pair.detail", s_["res"]["abort_detail"])
    chk("check.abort.A4_fires_only_via_off_polynomial_clause",
        s_["res"]["abort_detail"].startswith("off_polynomial"))
    # The C_ik clause of R6 is implied by (4) on the t+1 base pairs (linearity), even when a
    # base pair is forged with the trapdoor: interpolate base {1(forged),2,3} and compare.
    base_pairs = [(1,) + forged1, (2, dt[5]["s"][2], dt[5]["sp"][2]), (3, dt[5]["s"][3], dt[5]["sp"][3])]
    ai = interpolate([(j, s) for j, s, _ in base_pairs])
    bi = interpolate([(j, sp) for j, _, sp in base_pairs])
    chk("check.r6_commitment_clause_implied_by_eq4",
        all(padd(smul(ai[k], G), smul(bi[k], Ht)) == dt[5]["C"][k] for k in range(3))
        and ai[0] != dt[5]["a"][0])
    # Same construction under the profile's H: the pair simply fails (4) and is not valid.
    forgedH = ((d3[5]["s"][4] - w) % L, (d3[5]["sp"][4] + 1) % L)
    sc = Script()
    sc.extraction[5] = []
    sc.recon_pair[(4, 5)] = forgedH
    s_ = simulate(c3, a3, b3, H, sc)
    case("A4_same_construction_under_profile_H", outcome(s_), "none", vec=s_)
    chk("check.abort.A4_profile_H_pair_excluded", s_["res"]["recon"][5]["valid"] == [1, 2, 3])

    # A5: constant terms 1, 2, l-3 -> y = O
    c2 = cfgs["honest-2of3"]
    a2, b2 = coeffs_from_tags(3, 1)
    a5 = {i: list(a2[i]) for i in a2}
    a5[1][0], a5[2][0], a5[3][0] = 1, 2, L - 3
    s_ = simulate(c2, a5, b2)
    case("A5_constant_terms_sum_to_zero", outcome(s_), "A5", vec=s_)
    chk("check.abort.A5_y_identity", s_["res"]["y"] == O)
    chk("check.abort.A5_admission_refuses", admit(c2, s_["bc"], []) == ("refuse", "A5"))

    # A6: dealer 5 publishes A_51 + G and no EXTRACTION_COMPLAINT is delivered
    sc = Script()
    sc.extraction[5] = [[d3[5]["A"][0], padd(d3[5]["A"][1], G), d3[5]["A"][2]]]
    sc.ec_senders = set()
    s_ = simulate(c3, a3, b3, H, sc)
    case("A6_extraction_complaints_not_delivered",
         ",".join(outcome(s_, j) for j in range(1, 6)), "A6,A6,A6,A6,A6", vec=s_)
    chk("check.abort.A6_public_y_still_correct", s_["res"]["y"] == base["res"]["y"])

    # A7: abort if >= t + 1 distinct QUAL members differ, or < t + 1 match (own confirmation
    # counted only if delivered back). The checking participant is the first argument's owner.
    def lie(cfg_, res_, j, kind):
        if kind == "digest":
            return m_confirmation(cfg_, j, bytes([res_["digest"][0] ^ 1]) + res_["digest"][1:], res_["y"])
        return m_confirmation(cfg_, j, res_["digest"], padd(res_["y"], G))

    def a7(cfg_, res_, view, j):
        return confirmation_check(cfg_, res_, view, j) or "none"

    r2_ = honest_sims["honest-2of3"]["res"]
    conf2 = honest_sims["honest-2of3"]["conf"]
    case("A7_2of3_one_lie_ignored", a7(c2, r2_, [conf2[1], lie(c2, r2_, 2, "digest"), conf2[3]], 1), "none")
    case("A7_2of3_t_plus_1_digest_differs",
         a7(c2, r2_, [conf2[1], lie(c2, r2_, 2, "digest"), lie(c2, r2_, 3, "digest")], 1), "A7")
    case("A7_2of3_t_plus_1_y_differs", a7(c2, r2_, [conf2[1], lie(c2, r2_, 2, "y"), lie(c2, r2_, 3, "y")], 1), "A7")
    case("A7_2of3_t_plus_1_mixed_digest_and_y",
         a7(c2, r2_, [conf2[1], lie(c2, r2_, 2, "digest"), lie(c2, r2_, 3, "y")], 1), "A7")
    case("A7_2of3_same_liar_twice_counts_once",
         a7(c2, r2_, [conf2[1], lie(c2, r2_, 2, "digest"), lie(c2, r2_, 2, "y"), conf2[3]], 1), "none")
    case("A7_control_all_agree", a7(c2, r2_, list(conf2.values()), 1), "none")
    case("A7_2of3_own_and_one_other_suffice", a7(c2, r2_, [conf2[1], conf2[2]], 1), "none")
    case("A7_2of3_only_own_delivered_too_few_matching", a7(c2, r2_, [conf2[1]], 1), "A7")
    case("A7_2of3_own_not_delivered_back_too_few_matching", a7(c2, r2_, [conf2[2]], 1), "A7")
    case("A7_2of3_own_not_delivered_back_but_two_others", a7(c2, r2_, [conf2[2], conf2[3]], 1), "none")
    r3c = base["res"]
    conf3c = base["conf"]
    case("A7_3of5_t_lies_ignored",
         a7(c3, r3c, [conf3c[j] for j in (1, 2, 3)] + [lie(c3, r3c, 4, "digest"), lie(c3, r3c, 5, "y")], 1), "none")
    case("A7_3of5_t_plus_1_differing",
         a7(c3, r3c, [conf3c[1], conf3c[2]] + [lie(c3, r3c, j, "digest") for j in (3, 4, 5)], 1), "A7")
    case("A7_3of5_two_silent_members_too_few_matching", a7(c3, r3c, [conf3c[1], conf3c[2]], 1), "A7")
    stale_cfg = Config(2, 5, b"zeroj.test.honest", 2, roster(5))
    stale = [m_confirmation(stale_cfg, j, r3c["digest"], padd(r3c["y"], G)) for j in (3, 4, 5)]
    case("A7_3of5_stale_session_confirmations_ignored",
         a7(c3, r3c, [conf3c[j] for j in (1, 2, 3)] + stale, 1), "none")
    case("A7_3of5_malformed_confirmations_ignored",
         a7(c3, r3c, [conf3c[j] for j in (1, 2, 3)] + [lie(c3, r3c, j, "digest")[:-1] for j in (4, 5)], 1), "none")
    case("A7_3of5_unauthenticated_confirmations_ignored",
         a7(c3, r3c, [conf3c[j] for j in (1, 2, 3)] + [(lie(c3, r3c, j, "digest"), False) for j in (4, 5)] +
            [(conf3c[4], False)], 1), "none")
    # Equivocation: 3 and 4 each send a matching and a differing confirmation, 5 a differing
    # one: three distinct differing senders reach t + 1.
    case("A7_3of5_equivocators_count_as_differing",
         a7(c3, r3c, [conf3c[1], conf3c[2], conf3c[3], conf3c[4], lie(c3, r3c, 3, "digest"),
                      lie(c3, r3c, 4, "digest"), lie(c3, r3c, 5, "y")], 1), "A7")
    # An equivocator never counts as matching: 1, 2 match, 3 equivocates -> 2 < t + 1 matching.
    case("A7_3of5_equivocator_not_matching",
         a7(c3, r3c, [conf3c[1], conf3c[2], conf3c[3], lie(c3, r3c, 3, "y")], 1), "A7")

    # ---------------------------------------------------------------- R1-R6 rule cases
    # Conflicting COMMITMENTS disqualify (R1); both messages stay in the transcript.
    sc = Script()
    sc.commit[2] = [d3[2]["C"], [d3[2]["C"][0], padd(d3[2]["C"][1], G), d3[2]["C"][2]]]
    s_ = simulate(c3, a3, b3, H, sc)
    case("R1_conflicting_commitments", "%s;qual=%s" % (s_["res"]["dq"].get(2), ids(s_["res"]["qual"])),
         "R1;qual=1,3,4,5", prefix="rule", vec=s_)
    chk("check.rule.R1_conflict_both_in_transcript",
        len(s_["res"]["dv"].by_round[1]) == 6 and
        sum(1 for m in s_["res"]["dv"].by_round[1].values() if m.sender == 2) == 2)
    chk("check.rule.R2_no_complaint_against_conflicting_commitments",
        not any(m.subject == 2 for m in s_["res"]["dv"].by_round[2].values()))
    # Malformed COMMITMENTS counts as absent (R1); no complaints against that dealer (R2).
    sc = Script()
    sc.commit[2] = []
    sc.extra[1] = [m_commitments(c3, 2, d3[2]["C"])[:-1]]
    s_ = simulate(c3, a3, b3, H, sc)
    case("R1_malformed_commitments_absent", s_["res"]["dq"].get(2), "R1", prefix="rule", vec=s_)
    chk("check.rule.R2_no_complaint_against_absent_commitments", len(s_["res"]["dv"].by_round[2]) == 0)
    # Two different SHAREs from a dealer to one recipient are a conflict: the recipient
    # complains (R2), the dealer answers correctly and stays, the answer is adopted.
    sc = Script()
    sc.share_extra[(1, 2)] = [((d3[1]["s"][2] + 9) % L, d3[1]["sp"][2])]
    s_ = simulate(c3, a3, b3, H, sc)
    case("R2_conflicting_share_complaint", "complaints=%s;qual=%s;x_ok=%s" % (
        ",".join("%d->%d" % (m.sender, m.subject) for m in s_["res"]["dv"].ordered(2)),
        ids(s_["res"]["qual"]), str(s_["x"] == base["x"]).lower()),
        "complaints=2->1;qual=1,2,3,4,5;x_ok=true", prefix="rule", vec=s_)
    # Duplicate byte-identical complaints count once.
    sc = Script()
    sc.share[(1, 2)] = ((d3[1]["s"][2] + 1) % L, d3[1]["sp"][2])
    sc.share[(1, 3)] = ((d3[1]["s"][3] + 1) % L, d3[1]["sp"][3])
    s_ref = simulate(c3, a3, b3, H, sc)
    sc.extra[2] = [m_complaint(c3, 2, 1), m_complaint(c3, 2, 1)]
    s_ = simulate(c3, a3, b3, H, sc)
    case("R2_duplicate_identical_complaints", "complaints=%d;qual=%s" % (
        len(s_["res"]["complaints"][1]), ids(s_["res"]["qual"])), "complaints=2;qual=1,2,3,4,5", prefix="rule", vec=s_)
    chk("check.rule.R2_duplicates_once_in_transcript",
        len(s_["res"]["dv"].by_round[2]) == 2 and s_["res"]["digest"] == s_ref["res"]["digest"])
    chk("check.rule.R2_answered_complaints_keep_contribution", s_["res"]["y"] == base["res"]["y"])
    chk("check.rule.R2_participants_adopt_answers", s_["x"] == base["x"])
    # More than t complaints disqualify even when answered.
    sc = Script()
    for j in (2, 3, 4):
        sc.share[(1, j)] = ((d3[1]["s"][j] + 1) % L, d3[1]["sp"][j])
    s_ = simulate(c3, a3, b3, H, sc)
    case("R3_more_than_t_complaints", s_["res"]["dq"].get(1), "R3_more_than_t_complaints", prefix="rule", vec=s_)
    # Unanswered complaint disqualifies.
    sc = Script()
    sc.share[(1, 2)] = ((d3[1]["s"][2] + 1) % L, d3[1]["sp"][2])
    sc.answer[(1, 2)] = None
    s_ = simulate(c3, a3, b3, H, sc)
    case("R3_unanswered_complaint", s_["res"]["dq"].get(1), "R3_answer_absent_or_conflict", prefix="rule", vec=s_)
    # Answer failing (4) disqualifies.
    sc = Script()
    sc.share[(1, 2)] = ((d3[1]["s"][2] + 1) % L, d3[1]["sp"][2])
    sc.answer[(1, 2)] = ((d3[1]["s"][2] + 1) % L, d3[1]["sp"][2])
    s_ = simulate(c3, a3, b3, H, sc)
    case("R3_answer_fails_eq4", s_["res"]["dq"].get(1), "R3_answer_fails_eq4", prefix="rule", vec=s_)
    # Conflicting answers disqualify, even if one of them is correct.
    sc = Script()
    sc.share[(1, 2)] = ((d3[1]["s"][2] + 1) % L, d3[1]["sp"][2])
    sc.extra[3] = [m_answer(c3, 1, 2, (d3[1]["s"][2] + 5) % L, d3[1]["sp"][2])]
    s_ = simulate(c3, a3, b3, H, sc)
    case("R3_conflicting_answers", s_["res"]["dq"].get(1), "R3_answer_absent_or_conflict", prefix="rule", vec=s_)
    # An ANSWER without a matching complaint has no effect (but is in the transcript).
    sc = Script()
    sc.extra[3] = [m_answer(c3, 1, 3, (d3[1]["s"][3] + 5) % L, d3[1]["sp"][3])]
    s_ = simulate(c3, a3, b3, H, sc)
    case("R3_answer_without_complaint", "qual=%s;round3=%d" % (
        ids(s_["res"]["qual"]), len(s_["res"]["dv"].by_round[3])), "qual=1,2,3,4,5;round3=1", prefix="rule", vec=s_)
    chk("check.rule.R3_unsolicited_answer_changes_digest_only",
        s_["res"]["digest"] != base["res"]["digest"] and s_["res"]["y"] == base["res"]["y"])
    # Conflicting EXTRACTION marks (R4); reconstruction keeps the contribution.
    sc = Script()
    sc.extraction[5] = [d3[5]["A"], [d3[5]["A"][0], d3[5]["A"][1], padd(d3[5]["A"][2], G)]]
    s_ = simulate(c3, a3, b3, H, sc)
    case("R4_conflicting_extraction", "%s;y_ok=%s" % (s_["res"]["marked"].get(5),
         str(s_["res"]["y"] == base["res"]["y"]).lower()), "R4;y_ok=true", prefix="rule", vec=s_)
    # Invalid extraction complaints have no effect.
    sc = Script()
    sc.extra[5] = [m_ext_complaint(c3, 3, 1, (d3[1]["s"][3] + 1) % L, d3[1]["sp"][3]),   # fails (4)
                   m_ext_complaint(c3, 4, 1, d3[1]["s"][4], d3[1]["sp"][4])]               # (5) holds
    s_ = simulate(c3, a3, b3, H, sc)
    case("R5_invalid_extraction_complaints", "marked=%s;round5=%d" % (
        ids(sorted(s_["res"]["marked"])), len(s_["res"]["dv"].by_round[5])), "marked=;round5=2", prefix="rule", vec=s_)
    # Conflicting EXTRACTION_COMPLAINTs are each evaluated on their own: one valid pair marks.
    sc = Script()
    sc.extraction[5] = [[d3[5]["A"][0], padd(d3[5]["A"][1], G), d3[5]["A"][2]]]
    sc.ec_senders = set()
    sc.extra[5] = [m_ext_complaint(c3, 3, 5, d3[5]["s"][3], d3[5]["sp"][3]),               # valid
                   m_ext_complaint(c3, 3, 5, (d3[5]["s"][3] + 1) % L, d3[5]["sp"][3])]     # fails (4)
    s_ = simulate(c3, a3, b3, H, sc)
    case("R5_conflicting_complaints_each_evaluated", "marked_by=%s;round5=%d;y_ok=%s" % (
        s_["res"]["marked"].get(5), len(s_["res"]["dv"].by_round[5]),
        str(s_["res"]["y"] == base["res"]["y"]).lower()), "marked_by=R5;round5=2;y_ok=true", prefix="rule", vec=s_)
    # Extraction complaint against a dealer whose EXTRACTION is absent: invalid (R5 needs a
    # well-formed, non-conflicting EXTRACTION); the dealer is marked by R4 only.
    sc = Script()
    sc.extraction[5] = []
    sc.extra[5] = [m_ext_complaint(c3, 1, 5, d3[5]["s"][1], d3[5]["sp"][1])]
    s_ = simulate(c3, a3, b3, H, sc)
    case("R5_complaint_against_dealer_without_extraction", "marked_by=%s;valid=%d;abort=%s" % (
        s_["res"]["marked"].get(5), len(s_["res"]["valid_ec"]), s_["res"]["abort"] or "none"),
        "marked_by=R4;valid=0;abort=none", prefix="rule", vec=s_)
    # Extraction complaint against a dealer outside QUAL has no effect.
    sc = Script()
    sc.commit[1] = []
    sc.extra[5] = [m_ext_complaint(c3, 3, 1, d3[1]["s"][3], d3[1]["sp"][3])]
    s_ = simulate(c3, a3, b3, H, sc)
    case("R5_complaint_against_non_qual", "marked=%s" % ids(sorted(s_["res"]["marked"])), "marked=", prefix="rule", vec=s_)

    # ---------------------------------------------------------------- F14 / A8 demonstration
    x_true = sum(d3[i]["a"][0] for i in range(1, 6)) % L

    def f14_summary(s_):
        rr = s_["res"]
        recon = rr.get("recon", {})
        x_pub = len(recon) == 5 and sum(recon[i]["a"][0] for i in recon) % L == x_true
        return "abort=%s;marked=%s;participant_aborts=%s;reconstructions=%d;confirmations=%d;" \
               "x_public=%s;admission=%s" % (
                   rr["abort"] or "none", ids(sorted(rr.get("marked", {}))),
                   ",".join(s_["pab"][j] or "none" for j in range(1, 6)),
                   len(rr["dv"].by_round[6]), len(s_["conf"]), str(x_pub).lower(),
                   admit(c3, s_["bc"], list(s_["conf"].values()))[0])

    # Every EXTRACTION is late (outside the synchrony assumption). With A8 every dealer aborts
    # when R5 closes, nobody reconstructs (the public recomputation then ends in A3), no
    # confirmation is sent, and admission refuses.
    sc = Script()
    for i in range(1, 6):
        sc.extraction[i] = []
    s_ = simulate(c3, a3, b3, H, sc)
    case("F14_all_extractions_late", f14_summary(s_),
         "abort=A3;marked=1,2,3,4,5;participant_aborts=A8,A8,A8,A8,A8;reconstructions=0;"
         "confirmations=0;x_public=false;admission=refuse", prefix="finding", vec=s_)
    # The same run under the pre-revision rules (no A8): x public, admitted.
    s_ = simulate(c3, a3, b3, H, sc, a8=False)
    case("F14_all_extractions_late_pre_revision_without_A8", f14_summary(s_),
         "abort=none;marked=1,2,3,4,5;participant_aborts=none,none,none,none,none;reconstructions=20;"
         "confirmations=5;x_public=true;admission=admit", prefix="finding", vec=s_)
    # Faulty participants 1 and 2 (= t) ignore A8 and reconstruct anyway: t pairs per dealer.
    sc2 = Script()
    for i in range(1, 6):
        sc2.extraction[i] = []
    sc2.recon_ok = lambda j, i: j in (1, 2)
    s_ = simulate(c3, a3, b3, H, sc2, a8=False)
    case("F14_all_late_only_t_faulty_reconstruct", f14_summary(s_),
         "abort=A3;marked=1,2,3,4,5;participant_aborts=A3,A3,A3,A3,A3;reconstructions=8;"
         "confirmations=0;x_public=false;admission=refuse", prefix="finding", vec=s_)
    # Partial: honest dealers 3 and 4 late, dealer 5 on time (faulty 1, 2 follow §5). 3 and 4
    # abort A8 and are reconstructed; 1, 2, 5 confirm (t+1) and admission accepts; z_5 stays
    # hidden, so x is not computable from the transcript.
    sc = Script()
    sc.extraction[3] = []
    sc.extraction[4] = []
    s_ = simulate(c3, a3, b3, H, sc)
    case("F14_partial_two_honest_late", f14_summary(s_),
         "abort=none;marked=3,4;participant_aborts=none,none,A8,A8,none;reconstructions=6;"
         "confirmations=3;x_public=false;admission=admit", prefix="finding", vec=s_)
    chk("check.finding.F14_partial_y_correct", s_["res"]["y"] == base["res"]["y"])
    # A8 is checked when R5 closes, before R6: a dealer marked only by R5 still complains in R5.
    sc = Script()
    sc.extraction[1] = []
    sc.extraction[5] = [[d3[5]["A"][0], padd(d3[5]["A"][1], G), d3[5]["A"][2]]]
    s_ = simulate(c3, a3, b3, H, sc)
    case("A8_timing_marked_dealer_still_complains_in_R5",
         "ec_senders=%s;recon_senders=%s;aborts=%s" % (
             ids(sorted({m.sender for m in s_["res"]["dv"].by_round[5].values()})),
             ids(sorted({m.sender for m in s_["res"]["dv"].by_round[6].values()})),
             ",".join(s_["pab"][j] or "none" for j in range(1, 6))),
         "ec_senders=1,2,3,4;recon_senders=2,3,4;aborts=A8,none,none,none,A8", vec=s_)

    # ---------------------------------------------------------------- A9 and §4 channel rules
    # A9: participant 2's COMPLAINT against dealer 1 (bad SHARE) is not delivered. It aborts at
    # R2 close and falls silent; it stays in QUAL (nobody complained against it), its
    # EXTRACTION is absent, so it is marked and its z_2 is published by reconstruction, while x
    # stays secret (§5.1).
    sc = Script()
    sc.share[(1, 2)] = ((d3[1]["s"][2] + 1) % L, d3[1]["sp"][2])
    sc.drop.add((3, 2, 1))
    s_ = simulate(c3, a3, b3, H, sc)
    rr = s_["res"]
    case("A9_own_complaint_not_delivered", "aborts=%s;qual=%s;marked=%s;confirmations=%s;z2_published=%s;"
         "admission=%s" % (",".join(s_["pab"][j] or "none" for j in range(1, 6)), ids(rr["qual"]),
                           ids(sorted(rr["marked"])), ids(sorted(s_["conf"])),
                           str(rr["recon"].get(2, {}).get("a", [None])[0] == d3[2]["a"][0]).lower(),
                           admit(c3, s_["bc"], list(s_["conf"].values()))[0]),
         "aborts=none,A9,none,none,none;qual=1,2,3,4,5;marked=2;confirmations=1,3,4,5;z2_published=true;"
         "admission=admit", vec=s_)
    chk("check.abort.A9_y_correct", rr["y"] == base["res"]["y"])
    chk("check.abort.A9_participant_silent_after_R2",
        not any(m[34] == 2 and m[32] >= 3 for m in s_["bc"]) and 2 not in s_["conf"])
    # §4: a SHARE posted on the broadcast board is ignored (not in the transcript).
    sc = Script()
    sc.extra[1] = [m_share(c3, 1, 2, d3[1]["s"][2], d3[1]["sp"][2])]
    s_ = simulate(c3, a3, b3, H, sc)
    case("channel_share_on_broadcast_ignored", "digest_unchanged=%s" % str(
        s_["res"]["digest"] == base["res"]["digest"]).lower(), "digest_unchanged=true", prefix="rule", vec=s_)
    # §4: any other kind on the private channel is refused: the SHARE counts as absent.
    sc = Script()
    sc.private_raw[(1, 2)] = [m_answer(c3, 1, 2, d3[1]["s"][2], d3[1]["sp"][2])]
    s_ = simulate(c3, a3, b3, H, sc)
    case("channel_non_share_on_private_refused", "complaints=%s;qual=%s" % (
        ",".join("%d->%d" % (m.sender, m.subject) for m in s_["res"]["dv"].ordered(2)), ids(s_["res"]["qual"])),
        "complaints=2->1;qual=1,2,3,4,5", prefix="rule", vec=s_)
    # §4: a SHARE whose subject is not the recipient is refused.
    sc = Script()
    sc.private_raw[(1, 2)] = [m_share(c3, 1, 3, d3[1]["s"][3], d3[1]["sp"][3])]
    s_ = simulate(c3, a3, b3, H, sc)
    case("channel_share_for_other_recipient_refused", "complaints=%s;qual=%s" % (
        ",".join("%d->%d" % (m.sender, m.subject) for m in s_["res"]["dv"].ordered(2)), ids(s_["res"]["qual"])),
        "complaints=2->1;qual=1,2,3,4,5", prefix="rule", vec=s_)

    # ---------------------------------------------------------------- §5.2 demonstration
    # Documented model limitation (§5.2): late private SHAREs. Faulty coalition {1, 2} (= t);
    # each honest dealer 3, 4, 5 has one SHARE to an honest participant arrive late (3->4,
    # 4->5, 5->3). Each recipient complains, the honest dealer answers in public, and that
    # public pair is the (t + 1)-th point of its polynomial for the coalition. The coalition
    # recovers every z_i and hence x. Nothing aborts and admission accepts.
    sc = Script()
    for i, j in ((3, 4), (4, 5), (5, 3)):
        sc.share[(i, j)] = None
    s_ = simulate(c3, a3, b3, H, sc)
    rr = s_["res"]
    x_rec = (d3[1]["a"][0] + d3[2]["a"][0]) % L
    for m in rr["dv"].ordered(3):
        i, j = m.sender, m.subject
        pts = [(1, d3[i]["s"][1]), (2, d3[i]["s"][2]), (j, m.pair[0])]
        x_rec = (x_rec + interpolate(pts)[0]) % L
    x_true = sum(d3[i]["a"][0] for i in range(1, 6)) % L
    case("S52_late_shares_reveal_key", "aborts=%s;qual=%s;answers=%d;admission=%s;coalition_recovers_x=%s" % (
        ",".join(s_["pab"][j] or "none" for j in range(1, 6)), ids(rr["qual"]), len(rr["dv"].by_round[3]),
        admit(c3, s_["bc"], list(s_["conf"].values()))[0], str(x_rec == x_true).lower()),
        "aborts=none,none,none,none,none;qual=1,2,3,4,5;answers=3;admission=admit;coalition_recovers_x=true",
        prefix="finding", vec=s_)
    emit("info.finding.S52_late_shares_reveal_key", "documented model limitation (spec §5.2), not a defect")

    # ---------------------------------------------------------------- combine negatives (§9)
    r3_ = base["res"]
    Ac, Bc = encrypt(5, scalar("enc.k"), r3_["y"])
    Dsh = {j: smul(base["x"][j], Ac) for j in r3_["qual"]}
    bad = dict(Dsh)
    bad[5] = padd(bad[5], G)

    case("combine_extra_share_mismatch", _combine_status(2, r3_["qual"], Bc, bad), "error", prefix="rule")
    case("combine_too_few_shares", _combine_status(2, r3_["qual"], Bc, {1: Dsh[1], 2: Dsh[2]}),
         "error", prefix="rule")
    # An unverified bad share inside S is not caught by the extra-share check (there is none):
    # the result is not 5. This is why §9 requires DLEQ-verified shares.
    case("combine_unverified_bad_share_in_S_not_5",
         _combine_status(2, r3_["qual"], Bc, {1: Dsh[1], 2: Dsh[2], 5: bad[5]}) != "5", True,
         prefix="rule")
    adv_r = adv_sim["res"]
    Aa, Ba = encrypt(5, scalar("enc.k"), adv_r["y"])
    adv_sh = {j: smul(adv_sim["x"][j], Aa) for j in (2, 3, 4, 6)}
    case("combine_share_from_non_qual", _combine_status(3, adv_r["qual"], Ba, adv_sh), "error",
         prefix="rule")

    def combine_case(name, cfg_, qual_, A_, B_, shares, bound, expect=None):
        st = _combine_status(cfg_.t, qual_, B_, shares)
        items = [("config", config_str(cfg_)), ("qual", ids(qual_)), ("bound", bound),
                 ("ciphertext", (encode(A_) + encode(B_)).hex())]
        items += [("share.%d" % j, encode(shares[j]).hex()) for j in sorted(shares)]
        add_case("rule." + name, items + [("expect", expect or ("error" if st == "error" else "plaintext:" + st))])

    combine_case("combine_extra_share_mismatch", c3, r3_["qual"], Ac, Bc, bad, 7)
    combine_case("combine_too_few_shares", c3, r3_["qual"], Ac, Bc, {1: Dsh[1], 2: Dsh[2]}, 7)
    combine_case("combine_share_from_non_qual", adv_sim["cfg"], adv_r["qual"], Aa, Ba, adv_sh, 7)
    combine_case("combine_all_verified_shares", c3, r3_["qual"], Ac, Bc, Dsh, 7)
    combine_case("combine_unverified_bad_share_in_S_not_5", c3, r3_["qual"], Ac, Bc,
                 {1: Dsh[1], 2: Dsh[2], 5: bad[5]}, 7, expect="not_plaintext:5")

    # ---------------------------------------------------------------- admission (§8 step 6)
    # Each case also yields a replay vector: the transcript messages, the confirmations, the
    # unauthenticated bytes, the raw boards (closure cases) and admit/refuse with its step.
    def adm(name, cfg_, msgs, confs, expected, reason=None, order="transcript", boards=None,
            derive=False, unauth=frozenset(), family="rule"):
        """Run admission, check it, and emit its replay vector.

        order: "transcript" (msg.* = §6 transcript), "all_kinds" (every submitted well-formed
        message, misplaced kinds included, in §6 sort order) or "submission" (as submitted,
        for unparsable messages). boards ({1..7: posts}) switches on the board closure model;
        derive=True submits each round's delivered set of the board (deliveredRound)."""
        closure = board_closure(cfg_, boards, unauth) if boards is not None else None
        if derive:
            msgs = [raw for r in range(1, 7)
                    for raw in delivered_round(cfg_, [x for x in boards.get(r, []) if x not in unauth], r)]
        v, r = admit(cfg_, msgs, confs, round_closed=closure, unauth=unauth)
        emit("%s.%s" % (family, name), v)
        emit("info.%s.%s.reason" % (family, name), r)
        chk("check.%s.%s" % (family, name), v == expected and (reason is None or r == reason))
        items = [("config", config_str(cfg_))]
        if order == "all_kinds":
            ms = {raw: parse(cfg_, raw)[0] for raw in msgs}
            items += [("msg.%d" % k, m.raw.hex()) for k, m in enumerate(sorted(ms.values(), key=sort_key), 1)]
        elif order == "submission":
            items += [("order", "submission")]
            items += [("msg.%d" % k, raw.hex()) for k, raw in enumerate(msgs, 1)]
        else:
            items = transcript_items(cfg_, msgs)
        items += [("confirmation.%d" % k, raw.hex()) for k, raw in enumerate(confs, 1)]
        items += [("unauthenticated.%d" % k, raw.hex()) for k, raw in enumerate(sorted(unauth), 1)]
        if boards is not None:
            items += [("closure", "board")]
            for rr in range(1, 8):
                items += [("board.%d.%d" % (rr, k), raw.hex()) for k, raw in enumerate(boards.get(rr, []), 1)]
        items += [("expect", v)]
        if v == "refuse":
            items += [("step", str(refusal_step(r)))]
        add_case("%s.%s" % (family, name), items)

    conf3 = base["conf"]
    q = r3_["qual"]
    B = base["bc"]
    adm("admission_all_confirmations", c3, B, [conf3[j] for j in q], "admit")
    adm("admission_t_plus_1_confirmations", c3, B, [conf3[j] for j in (1, 3, 5)], "admit")
    adm("admission_t_confirmations", c3, B, [conf3[j] for j in (1, 3)], "refuse", "fewer_than_t_plus_1_matching")
    adm("admission_duplicate_sender_counts_once", c3, B, [conf3[1], conf3[1], conf3[3]], "refuse",
        "fewer_than_t_plus_1_matching")
    adm("admission_byte_identical_duplicate_ok", c3, B, [conf3[1], conf3[1], conf3[2], conf3[3]], "admit")
    lie4, lie5 = lie(c3, r3_, 4, "digest"), lie(c3, r3_, 5, "y")
    adm("admission_one_lie_ignored", c3, B, [conf3[j] for j in (1, 2, 3, 4)] + [lie5], "admit")
    adm("admission_t_plus_1_matching_plus_one_lie", c3, B, [conf3[1], conf3[2], conf3[3], lie5], "admit")
    adm("admission_t_lies_ignored", c3, B, [conf3[1], conf3[2], conf3[3], lie4, lie5], "admit")
    adm("admission_t_matching_plus_lie", c3, B, [conf3[1], conf3[3], lie5], "refuse", "fewer_than_t_plus_1_matching")
    adm("admission_t_plus_1_differing_3of5", c3, B,
        [conf3[1], conf3[2]] + [lie(c3, r3_, j, "digest") for j in (3, 4, 5)], "refuse", "differing_t_plus_1")
    # n = 2t + 1 cannot isolate the differing rule; a reference-only 2-of-4 configuration does.
    c4 = Config(1, 4, b"zeroj.test.reference-only.2of4", 1, roster(4))
    a24, b24 = coeffs_from_tags(4, 1)
    s24 = simulate(c4, a24, b24)
    r24, cf24 = s24["res"], s24["conf"]
    B4 = s24["bc"]
    adm("admission_2of4_matching_and_t_plus_1_differing", c4, B4,
        [cf24[1], cf24[2], lie(c4, r24, 3, "digest"), lie(c4, r24, 4, "y")], "refuse", "differing_t_plus_1")
    adm("admission_2of4_matching_and_t_differing", c4, B4, [cf24[1], cf24[2], cf24[3], lie(c4, r24, 4, "y")],
        "admit")
    case("A7_2of4_t_plus_1_differing_with_t_plus_1_matching",
         a7(c4, r24, [cf24[1], cf24[2], lie(c4, r24, 3, "digest"), lie(c4, r24, 4, "y")], 1), "A7")
    # Equivocation counts as differing only.
    adm("admission_2of4_equivocator_differing_only", c4, B4, [cf24[1], cf24[2], lie(c4, r24, 2, "digest")],
        "refuse", "fewer_than_t_plus_1_matching")
    adm("admission_2of4_two_equivocators_t_plus_1_differing", c4, B4,
        [cf24[j] for j in (1, 2, 3, 4)] + [lie(c4, r24, 3, "digest"), lie(c4, r24, 4, "y")],
        "refuse", "differing_t_plus_1")
    adm("admission_2of4_one_equivocator_ignored", c4, B4, [cf24[j] for j in (1, 2, 3, 4)] + [lie(c4, r24, 4, "y")],
        "admit")
    case("A7_2of4_one_equivocator_ignored",
         a7(c4, r24, [cf24[j] for j in (1, 2, 3, 4)] + [lie(c4, r24, 4, "y")], 1), "none")
    adm("admission_3of5_equivocators_differing_only", c3, B,
        [conf3[1], conf3[2], conf3[3], lie(c3, r3_, 1, "digest"), lie(c3, r3_, 2, "y")], "refuse",
        "fewer_than_t_plus_1_matching")
    adm("admission_3of5_one_equivocator_among_all", c3, B, [conf3[j] for j in q] + [lie(c3, r3_, 1, "digest")],
        "admit")
    # Ignored inputs: other session, malformed, not a CONFIRMATION, outside QUAL.
    stale_cfg = Config(2, 5, b"zeroj.test.honest", 2, roster(5))
    stale = [m_confirmation(stale_cfg, j, r3_["digest"], padd(r3_["y"], G)) for j in (3, 4, 5)]
    adm("admission_stale_session_confirmations_ignored", c3, B, [conf3[j] for j in (1, 2, 3)] + stale, "admit")
    adm("admission_stale_session_only_refused", c3, B,
        [m_confirmation(stale_cfg, j, r3_["digest"], r3_["y"]) for j in (1, 2, 3)], "refuse",
        "fewer_than_t_plus_1_matching")
    adm("admission_malformed_confirmations_ignored", c3, B,
        [conf3[j] for j in (1, 2, 3)] + [lie(c3, r3_, j, "y")[:-1] for j in (4, 5)], "admit")
    adm("admission_non_confirmation_ignored", c3, B, [conf3[j] for j in (1, 2, 3)] + [m_complaint(c3, 4, 5), B[0]],
        "admit")
    # Unauthenticated confirmations are dropped (authenticate false iff bytes are listed).
    lies45 = [lie(c3, r3_, j, "digest") for j in (4, 5)]
    adm("admission_unauthenticated_confirmations_ignored", c3, B, [conf3[j] for j in (1, 2, 3)] + lies45,
        "admit", unauth=frozenset(lies45))
    adm("admission_unauthenticated_matching_not_counted", c3, B, [conf3[1], conf3[2], conf3[3]], "refuse",
        "fewer_than_t_plus_1_matching", unauth=frozenset([conf3[3]]))
    # R14: t + 1 well-formed differing confirmations from QUAL members 1, 2, 3 that fail
    # authentication are ignored (not differing): admit. The same lies authenticated make 1, 2
    # and 3 equivocators (differing t + 1): refuse at step 6.
    lies123 = [lie(c3, r3_, j, "digest") for j in (1, 2, 3)]
    adm("admission_t_plus_1_unauthenticated_lies_ignored", c3, B, [conf3[j] for j in q] + lies123, "admit",
        unauth=frozenset(lies123))
    adm("admission_t_plus_1_authenticated_lies_refused", c3, B, [conf3[j] for j in q] + lies123, "refuse",
        "differing_t_plus_1")
    # Step 3: a transcript message whose authentication fails refuses.
    adm("admission_unauthenticated_transcript_message_refused", c3, B, [conf3[j] for j in q], "refuse",
        "unauthenticated_transcript_message", unauth=frozenset([B[0]]))
    # Byte-identical duplicates among the submitted transcript messages count once (step 2).
    adm("admission_duplicate_transcript_messages_count_once", c3, B + [B[0], B[-1]], [conf3[j] for j in q],
        "admit", order="submission")
    # Step 2: a transcript message that is not a well-formed rounds 1-6 broadcast refuses.
    adm("admission_malformed_transcript_message_refused", c3, B + [B[0][:-1]], [conf3[j] for j in q],
        "refuse", "malformed_transcript_message", order="submission")
    adm("admission_other_session_transcript_message_refused", c3, B + [m_complaint(stale_cfg, 2, 1)],
        [conf3[j] for j in q], "refuse", "malformed_transcript_message", order="submission")
    adm("admission_share_in_transcript_refused", c3, B + [m_share(c3, 1, 2, d3[1]["s"][2], d3[1]["sp"][2])],
        [conf3[j] for j in q], "refuse", "non_broadcast_transcript_message", order="all_kinds")
    adm("admission_confirmation_in_transcript_refused", c3, B + [conf3[1]], [conf3[j] for j in q],
        "refuse", "non_broadcast_transcript_message", order="all_kinds")
    # Omitted messages (roundClosed true): an omitted EXTRACTION marks the dealer with no
    # reconstructions (A3); an omitted COMMITMENTS changes QUAL, y and the digest.
    adm("admission_omitted_extraction", c3, [m for m in B if not (m[33] == 5 and m[34] == 4)],
        [conf3[j] for j in q], "refuse", "A3")
    adm("admission_omitted_commitments", c3, [m for m in B if not (m[33] in (1, 5) and m[34] == 4)],
        [conf3[j] for j in q], "refuse", "differing_t_plus_1")

    # roundClosed(config, r, list) for r = 1..7 is modelled as "the list equals the delivered set
    # (§8 step 4) of the posted board of round r"; board 7 holds the posted confirmations.
    confs_all = [conf3[j] for j in q]
    true_boards = {r: [m for m in B if m[32] == r] for r in range(1, 7)}
    true_boards[7] = list(confs_all)
    junk_unauth = frozenset([m_complaint(c3, 3, 1), m_complaint(c3, 4, 1), lie(c3, r3_, 5, "y")])
    junk_boards = {r: list(v) for r, v in true_boards.items()}
    junk_boards[1] += [B[0][:-1],                                        # malformed
                       m_complaint(stale_cfg, 2, 1),                     # other session
                       m_share(c3, 1, 2, d3[1]["s"][2], d3[1]["sp"][2]),  # SHARE on the board
                       m_complaint(c3, 2, 1),                            # round-2 message in round 1
                       m_complaint(c3, 3, 1)]                            # unauthenticated
    junk_boards[2] = [m_complaint(c3, 4, 1), B[0]]                      # unauthenticated, other round
    junk_boards[7] = list(confs_all) + [lie(c3, r3_, 5, "y"), conf3[1][:-1]]   # unauthenticated, malformed
    adm("admission_junk_posts_do_not_veto", c3, None, confs_all, "admit", boards=junk_boards, derive=True,
        unauth=junk_unauth)
    chk("check.rule.delivered_round_drops_junk",
        all(delivered_round(c3, [x for x in junk_boards[r] if x not in junk_unauth], r) ==
            delivered_round(c3, true_boards[r], r) for r in range(1, 8)))
    adm("admission_round_omitted_refused", c3, [m for m in B if m[32] != 4], confs_all, "refuse",
        "round4_not_closed", boards=true_boards)
    adm("admission_round7_closed_honest_run", c3, B, confs_all, "admit", boards=true_boards)
    adm("admission_round7_confirmation_omitted_refused", c3, B, confs_all[:4], "refuse", "round7_not_closed",
        boards=true_boards)
    chk("check.round7_list_canonical_order_and_dedupe",
        round7_list(c3, [conf3[5], conf3[1], conf3[3], conf3[1], conf3[5][:-1], (conf3[2], False)]) ==
        [conf3[1], conf3[3], conf3[5]])
    # N6: outside the agreement assumption (honest 1, 2 saw one board; honest 3 and faulty 4
    # confirm another), 1 and 2 abort with A7; admission refuses the full set (differing t + 1)
    # and roundClosed(7) refuses a subset that omits the differing confirmations.
    all24 = [cf24[1], cf24[2], lie(c4, r24, 3, "digest"), lie(c4, r24, 4, "digest")]
    boards24 = {r: [m for m in B4 if m[32] == r] for r in range(1, 7)}
    boards24[7] = list(all24)
    case("N6_round7_closure", "participants_1_2=%s,%s;admit_all=%s;admit_subset=%s" % (
        a7(c4, r24, all24, 1), a7(c4, r24, all24, 2),
        "/".join(admit(c4, B4, all24, round_closed=board_closure(c4, boards24))),
        "/".join(admit(c4, B4, all24[:2], round_closed=board_closure(c4, boards24)))),
        "participants_1_2=A7,A7;admit_all=refuse/differing_t_plus_1;admit_subset=refuse/round7_not_closed",
        prefix="finding")
    adm("N6_round7_closure_full_set", c4, B4, all24, "refuse", "differing_t_plus_1", boards=boards24,
        family="finding")
    adm("N6_round7_closure_subset", c4, B4, all24[:2], "refuse", "round7_not_closed", boards=boards24,
        family="finding")
    # adversarial-4of7 admission vectors
    adv_good = [adv_sim["conf"][j] for j in (2, 4, 6, 7)]
    ca = adv_sim["cfg"]
    adv_lies = [m_confirmation(ca, j, b"\x00" * 32, G) for j in (1, 3, 5)]
    adm("admission_adversarial_4of7_with_deviator_lies", ca, adv_sim["bc"], adv_good + adv_lies, "admit")
    adm("admission_adversarial_4of7_t_matching", ca, adv_sim["bc"], adv_good[:3] + adv_lies, "refuse",
        "fewer_than_t_plus_1_matching")
    # R15: the round-7 list holds authenticated well-formed confirmations from any sender. On
    # adversarial-4of7, participant 3 (outside QUAL) posts a confirmation; it is in board 7 and
    # must be in the submitted list (it is ignored for counting). Omitting it fails closure.
    conf_p3 = m_confirmation(ca, 3, adv_sim["res"]["digest"], adv_sim["res"]["y"])
    adv_boards = {r: [m for m in adv_sim["bc"] if m[32] == r] for r in range(1, 7)}
    adv_boards[7] = adv_good + [conf_p3]
    adm("admission_adversarial_4of7_round7_list_includes_non_qual", ca, adv_sim["bc"], adv_good + [conf_p3],
        "admit", boards=adv_boards)
    adm("admission_adversarial_4of7_round7_non_qual_omitted_refused", ca, adv_sim["bc"], adv_good, "refuse",
        "round7_not_closed", boards=adv_boards)
    # The refusal step of each kind of refusal, stated independently of refusal_step().
    expected_steps = {"admission_malformed_transcript_message_refused": "2",
                      "admission_other_session_transcript_message_refused": "2",
                      "admission_share_in_transcript_refused": "2",
                      "admission_confirmation_in_transcript_refused": "2",
                      "admission_unauthenticated_transcript_message_refused": "3",
                      "admission_round_omitted_refused": "4",
                      "admission_omitted_extraction": "5",
                      "admission_t_confirmations": "6",
                      "admission_t_plus_1_differing_3of5": "6",
                      "admission_round7_confirmation_omitted_refused": "6",
                      "admission_t_plus_1_authenticated_lies_refused": "6",
                      "admission_adversarial_4of7_round7_non_qual_omitted_refused": "6"}
    got_steps = {n[len("rule."):]: dict(items).get("step") for n, items in CASES if n.startswith("rule.admission_")}
    chk("check.rule.admission_refusal_steps", all(got_steps.get(k) == v for k, v in expected_steps.items()))

    # ---------------------------------------------------------------- §1 parameters
    def param_case(name, expected, t_, n_, ctx=b"c", attempt=0, rspec="standard"):
        """§1 validation. rspec: "standard", "lengths:L1,.." (key_j = byte j repeated L_j
        times) or "hex:k1,.."; the vector carries the same spec, and the session if accepted."""
        try:
            c = Config(t_, n_, ctx, attempt, roster_from_spec(rspec, n_))
            got = "accept"
        except ValueError:
            c, got = None, "reject"
        case(name, got, expected, prefix="rule")
        items = [("config", "%d,%d,%s,%d" % (t_, n_, ctx.hex(), attempt)), ("roster", rspec), ("params", got)]
        if c is not None:
            items.append(("session", c.session.hex()))
        add_case("rule." + name, items)

    for nm, args, exp in (("t0_n3", (0, 3), "reject"), ("t1_n2", (1, 2), "reject"),
                          ("t2_n4", (2, 4), "reject"), ("t1_n3", (1, 3), "accept"),
                          ("t31_n64", (31, 64), "accept"), ("t32_n64", (32, 64), "reject"),
                          ("t1_n65", (1, 65), "reject")):
        param_case("param_" + nm, exp, *args)
    param_case("param_empty_key", "reject", 1, 3, rspec="lengths:0,1,1")
    param_case("param_key_65535", "accept", 1, 3, rspec="lengths:65535,1,1")
    param_case("param_key_65536", "reject", 1, 3, rspec="lengths:65536,1,1")
    param_case("param_ctx_65536", "reject", 1, 3, ctx=b"c" * 65536)
    param_case("param_ctx_empty", "accept", 1, 3, ctx=b"")
    param_case("param_attempt_2_64", "reject", 1, 3, attempt=1 << 64)
    param_case("param_attempt_2_64_minus_1", "accept", 1, 3, attempt=(1 << 64) - 1)
    param_case("param_duplicate_keys", "reject", 1, 3, rspec="hex:01,01,03")
    param_case("param_distinct_hex_keys", "accept", 1, 3, rspec="hex:01,02,03")
    param_case("param_duplicate_keys_standard_length", "reject", 2, 5,
               rspec="hex:" + ",".join(k.hex() for k in roster(4)) + "," + roster(1)[0].hex())

    # ---------------------------------------------------------------- §4 well-formedness
    good_commit = m_commitments(c3, 1, d3[1]["C"])
    good_answer = m_answer(c3, 1, 2, d3[1]["s"][2], d3[1]["sp"][2])
    order2 = (0, P - 1)
    small = []
    # find a point outside the subgroup that decodes: G + (0, -1)
    G_plus_t2 = padd(G, order2)

    def wf(name, raw, expect_accept):
        m, why = parse(c3, raw)
        got = "accept" if m is not None else "reject"
        emit("wf.%s" % name, got)
        if m is None:
            emit("info.wf.%s.reason" % name, why)
        chk("check.wf.%s" % name, got == ("accept" if expect_accept else "reject"))
        add_case("wf." + name, [("config", config_str(c3)), ("msg.1", raw.hex()), ("decode", got)])

    def with_point(raw, k, enc32):
        off = 36 + 32 * k
        return raw[:off] + enc32 + raw[off + 32:]

    def set_hdr(raw, pos, val):
        b_ = bytearray(raw)
        b_[pos] = val
        return bytes(b_)

    wf("commitments_ok", good_commit, True)
    wf("commitments_identity_point_ok", with_point(good_commit, 1, encode(O)), True)
    wf("commitments_short", good_commit[:-1], False)
    wf("commitments_long", good_commit + b"\x00", False)
    wf("commitments_wrong_session", set_hdr(good_commit, 0, good_commit[0] ^ 1), False)
    wf("commitments_round_kind_mismatch", set_hdr(good_commit, 32, 2), False)
    wf("commitments_unknown_kind", set_hdr(set_hdr(good_commit, 33, 9), 32, 1), False)
    wf("commitments_sender_0", set_hdr(good_commit, 34, 0), False)
    wf("commitments_sender_n_plus_1", set_hdr(good_commit, 34, 6), False)
    wf("commitments_subject_nonzero", set_hdr(good_commit, 35, 1), False)
    pv = (P).to_bytes(32, "little")
    wf("commitments_v_equals_p", with_point(good_commit, 0, pv), False)
    nsq = None
    for v in range(2, 100):
        if decode(v.to_bytes(32, "little"))[1] == "non_square":
            nsq = v
            break
    wf("commitments_non_square_v", with_point(good_commit, 0, nsq.to_bytes(32, "little")), False)
    ident_sign = bytearray(encode(O))
    ident_sign[31] |= 0x80
    wf("commitments_identity_sign_set", with_point(good_commit, 0, bytes(ident_sign)), False)
    wf("commitments_order2_point", with_point(good_commit, 0, encode(order2)), False)
    wf("commitments_G_plus_order2", with_point(good_commit, 0, encode(G_plus_t2)), False)
    wf("answer_ok", good_answer, True)
    wf("answer_s_equals_l", m_answer(c3, 1, 2, 0, 0)[:36] + i2osp32(L) + i2osp32(0), False)
    wf("answer_sp_equals_l", m_answer(c3, 1, 2, 0, 0)[:36] + i2osp32(0) + i2osp32(L), False)
    wf("answer_s_l_minus_1", m_answer(c3, 1, 2, L - 1, L - 1), True)
    wf("answer_subject_equals_sender", set_hdr(good_answer, 35, 1), False)
    wf("answer_subject_0", set_hdr(good_answer, 35, 0), False)
    wf("answer_subject_n_plus_1", set_hdr(good_answer, 35, 6), False)
    wf("complaint_ok", m_complaint(c3, 2, 1), True)
    wf("complaint_with_payload", m_complaint(c3, 2, 1) + b"\x00", False)
    wf("complaint_subject_equals_sender", set_hdr(m_complaint(c3, 2, 1), 35, 2), False)
    wf("share_ok", m_share(c3, 1, 2, 3, 4), True)
    wf("share_subject_equals_sender", set_hdr(m_share(c3, 1, 2, 3, 4), 35, 1), False)
    wf("confirmation_ok", m_confirmation(c3, 1, b"\x00" * 32, G), True)
    wf("confirmation_short", m_confirmation(c3, 1, b"\x00" * 32, G)[:-1], False)
    wf("confirmation_y_not_in_subgroup", m_confirmation(c3, 1, b"\x00" * 32, G_plus_t2), False)
    wf("reconstruction_round_7", set_hdr(m_reconstruction(c3, 1, 2, 1, 1), 32, 7), False)

    # ---------------------------------------------------------------- §11 pinned table
    # The spec's §11 table was filled from this reference's earlier output, so these are drift
    # checks, not independent evidence.
    pins = (("session", cfgs["session"].session.hex(),
             "27ee85d2f50e766a65a3bd49b4dd532f7ad7967bde49c912b2e6b6b5c932af0c"),
            ("honest-2of3.session", cfgs["honest-2of3"].session.hex(),
             "a86eca15ae74ef0f48adbf82186ad6eee552c578c3ffa1dcd3f6a0f0ed73ea03"),
            ("honest-2of3.y", encode(honest_sims["honest-2of3"]["res"]["y"]).hex(),
             "14acdc488055720e853cbb6b613d2c7f52aee2fa8e7f37b410b1fa9093082658"),
            ("honest-2of3.digest", honest_sims["honest-2of3"]["res"]["digest"].hex(),
             "2af7f7eae154833d51861bae276448b396eae5479a074a833a31a9fb9aa46023"),
            ("honest-3of5.y", encode(honest_sims["honest-3of5"]["res"]["y"]).hex(),
             "89eeef65017eb8f1a18e38a5b9fc0efb971386181e0db4649c60941cd5a6c425"),
            ("honest-4of7.digest", honest_sims["honest-4of7"]["res"]["digest"].hex(),
             "9b6a52fe5b0fb06feb875b82cb37871e64bc235b01de384ba54a06f96c24431b"),
            ("zero-share.Y.1", encode(special_sims["zero-share"]["res"]["Y"][1]).hex(),
             "0100000000000000000000000000000000000000000000000000000000000000"),
            ("zero-share.digest", special_sims["zero-share"]["res"]["digest"].hex(),
             "8864e81db8467449ab695f59e82ca31608edf753370c46b912b2b936e43fd43d"),
            ("equal-shares.Y", ",".join(encode(special_sims["equal-shares"]["res"]["Y"][j]).hex() for j in (1, 2, 3)),
             ",".join(["c5295dd1cb37a4ae58005ac7019c958df01d0e5256e17e81ba9d94a2db339cc7"] * 3)),
            ("adversarial-4of7.qual_marked", "%s;%s" % (ids(adv_sim["res"]["qual"]), ids(sorted(adv_sim["res"]["marked"]))),
             "1,2,4,5,6,7;1,5"),
            ("adversarial-4of7.counts", ",".join(str(len(adv_sim["res"]["dv"].by_round[r])) for r in range(1, 7)),
             "7,2,1,5,5,8"),
            ("adversarial-4of7.y", encode(adv_sim["res"]["y"]).hex(),
             "0b881774fb4c7fd67485a8c737cb78d787a46c87c7d2d6af3b588b4409ceec54"),
            ("adversarial-4of7.digest", adv_sim["res"]["digest"].hex(),
             "92ddd0e587537bec6cfcffdc0d4d90d8fa4145bdfa5200107f6c3766caa134a0"))
    for nm, got, pin in pins:
        chk("spec_match.table.%s" % nm, got == pin)

    # ---------------------------------------------------------------- replay vectors
    emit_cases()

    # ---------------------------------------------------------------- scalar family
    for tag in sorted(SCALARS_USED):
        emit("scalar.%s" % tag, fe(SCALARS_USED[tag]))
    chk("check.scalars_nonzero", all(v != 0 for v in SCALARS_USED.values()))

    emit("info.failed_checks", len(FAILED))
    emit("result", "pass" if not FAILED else "fail")

    text = "\n".join(emit_header + LINES) + "\n"
    sys.stdout.write(text)
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "reference-output.txt"), "w", encoding="utf-8") as fh:
        fh.write(text)
    if FAILED:
        for k in FAILED:
            sys.stderr.write("FAILED: %s\n" % k)
        sys.stderr.write("elapsed %.1fs\n" % (__import__("time").time() - t0))
        return 1
    sys.stderr.write("all checks passed (%.1fs)\n" % (__import__("time").time() - t0))
    return 0


def _combine_status(t, qual, Bc, shares):
    try:
        return str(combine(t, qual, Bc, shares, 7))
    except CombineError:
        return "error"


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:                       # a crash is a failure: keep the partial output
        import traceback
        traceback.print_exc()
        LINES.append("result=fail")
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "reference-output.txt"), "w", encoding="utf-8") as fh:
            fh.write("# crashed; partial output\n" + "\n".join(LINES) + "\n")
        for k in FAILED:
            sys.stderr.write("FAILED: %s\n" % k)
        sys.exit(1)
