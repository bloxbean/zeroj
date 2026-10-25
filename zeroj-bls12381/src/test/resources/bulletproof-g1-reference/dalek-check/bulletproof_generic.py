#!/usr/bin/env python3
"""Group- and transcript-generic single-value Bulletproof range proof.

ADR-0061 M2 external algebra check.  Written from Buenz et al., *Bulletproofs*
(ePrint 2017/1066, revision 2022-04-14): Section 4.1 lines (40)-(63), Section
4.2, the inner-product argument of Section 3 (Protocol 1 with Protocol 2,
lines (6)-(9) and (14)-(35)), and the optimized verifier of Section 6.2,
equations (97)-(105), evaluated as TWO SEPARATE checks (no random weight).

Nothing in this file knows a curve, an encoding or a hash.  Everything
concrete is a parameter:

  (a) ``group``      order, identity(), add, neg, mul, eq, is_identity, encode
                     (optionally double); scalars are integers mod group.order.
  (b) ``transcript`` one object per proof, with
                       bind_statement(n, V)          instance / commitment binding
                       absorb_point(label, P)
                       absorb_scalar(label, s)
                       challenge(label) -> int in [0, order)
                       begin_inner_product(n)        hook before the first IPA round
                     Generic labels used here: "A" "S" "y" "z" "T1" "T2" "x"
                     "t_hat" "tau_x" "mu" "ipa_base" "L" "R" "x_j".  A binding maps
                     them to its own labels (or ignores them).
  (c) ``Setup``      generator vectors G_vec, H_vec and the Pedersen bases B
                     (value) and B_blind (blinding).
  (d) the inner-product base: ``Setup.ipa_base``.  The IPA element is
                     u' = [c]·ipa_base, with c = transcript.challenge("ipa_base").
                     ipa_base = an independent generator U gives the paper's
                     Protocol 1 (c = x_u); ipa_base = B gives dalek's Q = w·B.
  (e) ``codec``      encode(proof) -> bytes, decode(bytes, n) -> RangeProof
                     (raising ProofFormatError); FixedLayoutCodec below covers
                     the A S T1 T2 t_hat tau_x mu (L R)^k a b layout with any
                     element codecs.

Test use only.  Not constant-time.  Never use with real secrets.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ProofFormatError(ValueError):
    """A proof (or V) failed decoding.  ``cls`` is the error class, ``layer`` where."""

    def __init__(self, cls: str, layer: str, detail: str = ""):
        super().__init__(f"{cls} at {layer}: {detail}")
        self.cls = cls
        self.layer = layer
        self.detail = detail


class RestartRequired(Exception):
    """The prover hit an identity prover message or a zero challenge."""


@dataclass(frozen=True)
class Setup:
    group: object
    G_vec: tuple
    H_vec: tuple
    B: object          # value base (paper g)
    B_blind: object    # blinding base (paper h)
    ipa_base: object   # U (paper Protocol 1) or B (dalek Q = w·B)
    allow_identity_commitment: bool = False


@dataclass
class RangeProof:
    A: object
    S: object
    T1: object
    T2: object
    t_hat: int
    tau_x: int
    mu: int
    L: list
    R: list
    a: int
    b: int


@dataclass
class VerifyResult:
    ok: bool
    layer: str            # "accept", "statement", "challenge", "check1", "check2"
    check1: bool | None = None
    check2: bool | None = None
    challenges: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# Generic helpers (group-agnostic)
# --------------------------------------------------------------------------

def _double(group, p):
    d = getattr(group, "double", None)
    return d(p) if d is not None else group.add(p, p)


def msm(group, scalars, points, window: int = 4):
    """Sum of [s_i]·P_i by interleaved fixed-window Straus.  Uses add/double only."""
    q = group.order
    ks = [s % q for s in scalars]
    pts = list(points)
    if len(ks) != len(pts):
        raise ValueError("msm length mismatch")
    if not ks:
        return group.identity()
    tables = []
    for p in pts:
        t = [group.identity(), p]
        for _ in range(2, 1 << window):
            t.append(group.add(t[-1], p))
        tables.append(t)
    nbits = max(k.bit_length() for k in ks)
    nwin = (nbits + window - 1) // window
    acc = group.identity()
    mask = (1 << window) - 1
    for w in range(nwin - 1, -1, -1):
        for _ in range(window):
            acc = _double(group, acc)
        shift = w * window
        for k, t in zip(ks, tables):
            d = (k >> shift) & mask
            if d:
                acc = group.add(acc, t[d])
    return acc


def inner(a, b, q):
    if len(a) != len(b):
        raise ValueError("inner product length mismatch")
    return sum(x * y for x, y in zip(a, b)) % q


def powers(c, n, q):
    out = [1] * n
    for i in range(1, n):
        out[i] = out[i - 1] * c % q
    return out


def inv(x, q):
    if x % q == 0:
        raise ZeroDivisionError("inverse of 0")
    return pow(x, -1, q)


def delta(y, z, n, q):
    """Paper (39)/(97): (z - z^2)·<1^n, y^n> - z^3·<1^n, 2^n>."""
    sum_y = sum(powers(y, n, q)) % q
    sum_2 = (2 ** n - 1) % q
    return ((z - z * z) * sum_y - z * z % q * z * sum_2) % q


def challenge_products(xs, n, q):
    """Paper (99)/(101): s_i = prod_j x_j^{e(i,j)}, e = +1 iff bit (k - j) of i is set.

    xs = (x_1, ..., x_k) in round order.  Returns (s, s_inv)."""
    k = len(xs)
    if n != 1 << k:
        raise ValueError("n must be 2^k")
    xinv = [inv(x, q) for x in xs]
    s, s_inv = [], []
    for i in range(n):
        p, pinv = 1, 1
        for j in range(1, k + 1):
            if (i >> (k - j)) & 1:
                p = p * xs[j - 1] % q
                pinv = pinv * xinv[j - 1] % q
            else:
                p = p * xinv[j - 1] % q
                pinv = pinv * xs[j - 1] % q
        s.append(p)
        s_inv.append(pinv)
    return s, s_inv


def _check_n(setup: Setup, n: int):
    if n < 1 or n & (n - 1):
        raise ValueError("n must be a power of two")
    if len(setup.G_vec) < n or len(setup.H_vec) < n:
        raise ValueError("not enough generators for n")


# --------------------------------------------------------------------------
# Prover (paper 4.1 (40)-(63), 4.2, Protocols 1-2)
# --------------------------------------------------------------------------

def prove(setup: Setup, transcript, v: int, gamma: int, n: int, nonces):
    """One proving attempt.  ``nonces()`` returns the next nonce scalar; they are drawn in
    the order alpha, rho, s_L[0..n-1], s_R[0..n-1], tau_1, tau_2.

    Returns (V, proof, trace).  Raises RestartRequired on an identity prover message or a
    zero challenge (the caller retries with fresh nonces and a fresh transcript)."""
    g = setup.group
    q = g.order
    _check_n(setup, n)
    if not (0 <= v < 2 ** n):
        raise ValueError("v out of range")
    if not (0 <= gamma < q):
        raise ValueError("gamma not canonical")
    Gs = list(setup.G_vec[:n])
    Hs = list(setup.H_vec[:n])

    alpha = nonces() % q
    rho = nonces() % q
    s_L = [nonces() % q for _ in range(n)]
    s_R = [nonces() % q for _ in range(n)]
    tau1 = nonces() % q
    tau2 = nonces() % q

    V = msm(g, [v, gamma], [setup.B, setup.B_blind])
    if g.is_identity(V) and not setup.allow_identity_commitment:
        raise ValueError("V is the identity")
    transcript.bind_statement(n, V)

    a_L = [(v >> i) & 1 for i in range(n)]
    a_R = [(x - 1) % q for x in a_L]
    # (44), (47)
    A = msm(g, [alpha] + a_L + a_R, [setup.B_blind] + Gs + Hs)
    S = msm(g, [rho] + s_L + s_R, [setup.B_blind] + Gs + Hs)
    if g.is_identity(A) or g.is_identity(S):
        raise RestartRequired("A or S is the identity")
    transcript.absorb_point("A", A)
    transcript.absorb_point("S", S)
    y = transcript.challenge("y")
    z = transcript.challenge("z")
    if y == 0 or z == 0:
        raise RestartRequired("zero y or z")

    yn = powers(y, n, q)
    twon = powers(2, n, q)
    zz = z * z % q
    l0 = [(a_L[i] - z) % q for i in range(n)]
    l1 = list(s_L)
    r0 = [(yn[i] * (a_R[i] + z) + zz * twon[i]) % q for i in range(n)]
    r1 = [yn[i] * s_R[i] % q for i in range(n)]
    t1 = (inner(l0, r1, q) + inner(l1, r0, q)) % q
    t2 = inner(l1, r1, q)
    # (53)
    T1 = msm(g, [t1, tau1], [setup.B, setup.B_blind])
    T2 = msm(g, [t2, tau2], [setup.B, setup.B_blind])
    if g.is_identity(T1) or g.is_identity(T2):
        raise RestartRequired("T1 or T2 is the identity")
    transcript.absorb_point("T1", T1)
    transcript.absorb_point("T2", T2)
    x = transcript.challenge("x")
    if x == 0:
        raise RestartRequired("zero x")

    # (58)-(62)
    l = [(l0[i] + x * l1[i]) % q for i in range(n)]
    r = [(r0[i] + x * r1[i]) % q for i in range(n)]
    t_hat = inner(l, r, q)
    tau_x = (tau2 * x % q * x + tau1 * x + zz * gamma) % q
    mu = (alpha + rho * x) % q
    transcript.absorb_scalar("t_hat", t_hat)
    transcript.absorb_scalar("tau_x", tau_x)
    transcript.absorb_scalar("mu", mu)
    c_u = transcript.challenge("ipa_base")
    if c_u == 0:
        raise RestartRequired("zero inner-product base challenge")
    u_prime = g.mul(c_u, setup.ipa_base)        # Protocol 1 (8)-(9)

    # (64): h'_i = [y^{-i}]·H_i
    y_inv = inv(y, q)
    yinv_n = powers(y_inv, n, q)
    gv = Gs
    hv = [g.mul(yinv_n[i], Hs[i]) for i in range(n)]
    av, bv = l, r
    transcript.begin_inner_product(n)
    Ls, Rs, xs = [], [], []
    t = n
    while t > 1:                                 # Protocol 2 (18)-(35)
        h = t // 2
        cL = inner(av[:h], bv[h:], q)
        cR = inner(av[h:], bv[:h], q)
        Lj = msm(g, av[:h] + bv[h:] + [cL], gv[h:] + hv[:h] + [u_prime])
        Rj = msm(g, av[h:] + bv[:h] + [cR], gv[:h] + hv[h:] + [u_prime])
        if g.is_identity(Lj) or g.is_identity(Rj):
            raise RestartRequired("L_j or R_j is the identity")
        transcript.absorb_point("L", Lj)
        transcript.absorb_point("R", Rj)
        xj = transcript.challenge("x_j")
        if xj == 0:
            raise RestartRequired("zero x_j")
        xj_inv = inv(xj, q)
        gv = [msm(g, [xj_inv, xj], [gv[i], gv[h + i]]) for i in range(h)]   # (29)
        hv = [msm(g, [xj, xj_inv], [hv[i], hv[h + i]]) for i in range(h)]   # (30)
        av = [(av[i] * xj + av[h + i] * xj_inv) % q for i in range(h)]     # (33)
        bv = [(bv[i] * xj_inv + bv[h + i] * xj) % q for i in range(h)]     # (34)
        Ls.append(Lj)
        Rs.append(Rj)
        xs.append(xj)
        t = h
    proof = RangeProof(A, S, T1, T2, t_hat, tau_x, mu, Ls, Rs, av[0], bv[0])
    trace = {"y": y, "z": z, "x": x, "ipa_base": c_u, "x_j": xs}
    return V, proof, trace


def prove_with_restarts(setup, new_transcript, v, gamma, n, new_nonces, attempts=8):
    """Restart loop: each attempt gets a fresh transcript and a fresh nonce stream."""
    last = None
    for _ in range(attempts):
        try:
            return prove(setup, new_transcript(), v, gamma, n, new_nonces())
        except RestartRequired as e:
            last = e
    raise RuntimeError(f"prover restarts exhausted: {last}")


# --------------------------------------------------------------------------
# Verifier (paper 6.2, (95)-(105); the two checks evaluated separately)
# --------------------------------------------------------------------------

def verify(setup: Setup, transcript, V, proof: RangeProof, n: int) -> VerifyResult:
    g = setup.group
    q = g.order
    _check_n(setup, n)
    k = n.bit_length() - 1
    if len(proof.L) != k or len(proof.R) != k:
        raise ProofFormatError("MALFORMED_ENCODING", "length", "wrong number of rounds")
    if g.is_identity(V) and not setup.allow_identity_commitment:
        return VerifyResult(False, "statement")

    # (96): recompute the challenges in transcript order.
    transcript.bind_statement(n, V)
    transcript.absorb_point("A", proof.A)
    transcript.absorb_point("S", proof.S)
    y = transcript.challenge("y")
    z = transcript.challenge("z")
    transcript.absorb_point("T1", proof.T1)
    transcript.absorb_point("T2", proof.T2)
    x = transcript.challenge("x")
    transcript.absorb_scalar("t_hat", proof.t_hat)
    transcript.absorb_scalar("tau_x", proof.tau_x)
    transcript.absorb_scalar("mu", proof.mu)
    c_u = transcript.challenge("ipa_base")
    transcript.begin_inner_product(n)
    xs = []
    for Lj, Rj in zip(proof.L, proof.R):
        transcript.absorb_point("L", Lj)
        transcript.absorb_point("R", Rj)
        xs.append(transcript.challenge("x_j"))
    chal = {"y": y, "z": z, "x": x, "ipa_base": c_u, "x_j": list(xs)}
    if 0 in (y, z, x, c_u) or 0 in xs:
        return VerifyResult(False, "challenge", challenges=chal)

    zz = z * z % q
    # Check 1, paper (98): [t_hat - delta]·B + [tau_x]·B_blind + [-z^2]·V + [-x]·T1 + [-x^2]·T2 = O
    c1 = msm(g,
             [(proof.t_hat - delta(y, z, n, q)) % q, proof.tau_x, (-zz) % q, (-x) % q,
              (-x * x) % q],
             [setup.B, setup.B_blind, V, proof.T1, proof.T2])
    ok1 = g.is_identity(c1)

    # Check 2, paper (99)-(105) with u' = [c_u]·ipa_base:
    #   sum_i [a·s_i + z]·G_i + sum_i [y^{-i}·(b·s_i^{-1} - z^2·2^i) - z]·H_i
    #   + [c_u·(a·b - t_hat)]·ipa_base + [mu]·B_blind - A - [x]·S
    #   - sum_j ([x_j^2]·L_j + [x_j^{-2}]·R_j) = O
    s, s_inv = challenge_products(xs, n, q)
    yinv_n = powers(inv(y, q), n, q)
    twon = powers(2, n, q)
    scal, pts = [], []
    for i in range(n):
        scal.append((proof.a * s[i] + z) % q)
        pts.append(setup.G_vec[i])
    for i in range(n):
        scal.append((yinv_n[i] * (proof.b * s_inv[i] - zz * twon[i]) - z) % q)
        pts.append(setup.H_vec[i])
    scal += [c_u * (proof.a * proof.b - proof.t_hat) % q, proof.mu, q - 1, (-x) % q]
    pts += [setup.ipa_base, setup.B_blind, proof.A, proof.S]
    for xj, Lj, Rj in zip(xs, proof.L, proof.R):
        xj_inv = inv(xj, q)
        scal += [(-xj * xj) % q, (-xj_inv * xj_inv) % q]
        pts += [Lj, Rj]
    c2 = msm(g, scal, pts)
    ok2 = g.is_identity(c2)

    layer = "accept" if (ok1 and ok2) else ("check1" if not ok1 else "check2")
    return VerifyResult(ok1 and ok2, layer, ok1, ok2, chal)


def verify_ipa_recursive(setup: Setup, V, proof: RangeProof, n: int, chal: dict) -> bool:
    """Independent cross-check of check 2: build P per paper (66) and run Protocol 1/2
    literally (fold generators round by round, no s_i rule), with the given challenges."""
    g = setup.group
    q = g.order
    y, z, x, c_u, xs = chal["y"], chal["z"], chal["x"], chal["ipa_base"], chal["x_j"]
    yinv_n = powers(inv(y, q), n, q)
    yn = powers(y, n, q)
    twon = powers(2, n, q)
    zz = z * z % q
    gv = list(setup.G_vec[:n])
    hv = [g.mul(yinv_n[i], setup.H_vec[i]) for i in range(n)]
    # (66) P = A·S^x·g^{-z}·h'^{z·y^n + z^2·2^n};  P·h^{-mu} is the IPA commitment (4.2)
    P = msm(g, [1, x] + [(-z) % q] * n + [(z * yn[i] + zz * twon[i]) % q for i in range(n)]
            + [(-proof.mu) % q],
            [proof.A, proof.S] + gv + hv + [setup.B_blind])
    u_prime = g.mul(c_u, setup.ipa_base)
    P = g.add(P, g.mul(proof.t_hat, u_prime))       # Protocol 1 (8)
    for xj, Lj, Rj in zip(xs, proof.L, proof.R):    # Protocol 2 (29)-(31)
        h = len(gv) // 2
        xi = inv(xj, q)
        gv = [msm(g, [xi, xj], [gv[i], gv[h + i]]) for i in range(h)]
        hv = [msm(g, [xj, xi], [hv[i], hv[h + i]]) for i in range(h)]
        P = msm(g, [xj * xj % q, 1, xi * xi % q], [Lj, P, Rj])
    # (16)
    rhs = msm(g, [proof.a, proof.b, proof.a * proof.b % q], [gv[0], hv[0], u_prime])
    return g.eq(P, rhs)


# --------------------------------------------------------------------------
# Generic fixed-layout proof codec
# --------------------------------------------------------------------------

class FixedLayoutCodec:
    """A ‖ S ‖ T1 ‖ T2 ‖ t_hat ‖ tau_x ‖ mu ‖ (L_j ‖ R_j)_{j=1..k} ‖ a ‖ b.

    Element codecs are parameters: encode_point(P) -> bytes, decode_point(bytes) -> P
    (raising ProofFormatError), and the same for scalars.  Fields are decoded in proof
    order after an exact-length check; the first failure is raised."""

    def __init__(self, point_len, scalar_len, encode_point, decode_point,
                 encode_scalar, decode_scalar):
        self.pl = point_len
        self.sl = scalar_len
        self.ep, self.dp = encode_point, decode_point
        self.es, self.ds = encode_scalar, decode_scalar

    def length(self, n: int) -> int:
        k = n.bit_length() - 1
        return self.pl * (4 + 2 * k) + self.sl * 5

    def encode(self, p: RangeProof) -> bytes:
        out = b"".join(self.ep(P) for P in (p.A, p.S, p.T1, p.T2))
        out += b"".join(self.es(s) for s in (p.t_hat, p.tau_x, p.mu))
        for Lj, Rj in zip(p.L, p.R):
            out += self.ep(Lj) + self.ep(Rj)
        return out + self.es(p.a) + self.es(p.b)

    def decode(self, data: bytes, n: int) -> RangeProof:
        data = bytes(data)
        if len(data) != self.length(n):
            raise ProofFormatError("MALFORMED_ENCODING", "length", f"{len(data)} octets")
        k = n.bit_length() - 1
        pos = 0

        def pt():
            nonlocal pos
            b = data[pos:pos + self.pl]
            pos += self.pl
            return self.dp(b)

        def sc():
            nonlocal pos
            b = data[pos:pos + self.sl]
            pos += self.sl
            return self.ds(b)

        A, S, T1, T2 = pt(), pt(), pt(), pt()
        t_hat, tau_x, mu = sc(), sc(), sc()
        Ls, Rs = [], []
        for _ in range(k):
            Ls.append(pt())
            Rs.append(pt())
        a, b = sc(), sc()
        return RangeProof(A, S, T1, T2, t_hat, tau_x, mu, Ls, Rs, a, b)
