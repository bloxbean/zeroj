#!/usr/bin/env python3
"""Independent reference implementation of the ZeroJ `pedersen-jubjub-v1` profile.

Written from docs/specs/pedersen-jubjub-v1.md (and jubjub-eddsa-v1.md section 1) only.
The Poseidon constant generator and permutation are a port of the independent SageMath
reference in ../poseidon-sage/poseidon_bls12_381_reference.sage. No ZeroJ Java source was
read while writing this file. See README.md in this directory.

Python 3 standard library only. Run:

    python3 pedersen_jubjub_v1_reference.py

The script prints key=value lines to stdout, writes the same lines to reference-output.txt
next to this file, and exits non-zero if any self-check, internal check or spec-pinned value
fails.
"""

import os
import platform
import sys

# --------------------------------------------------------------------------------------
# Section 1 constants (spec section 1; identical to jubjub-eddsa-v1.md section 1)
# --------------------------------------------------------------------------------------

P = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001  # base field
L = 0x0E7DB4EA6533AFA906673B0101343B00A6682093CCC81082D0970E5ED6F72CB7  # subgroup order
D = 0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1  # Edwards d
A_EDWARDS = P - 1  # Edwards a = -1 mod p
COFACTOR = 8

G_FULL = (0x62EDCBB8BF3787C88B0F03DDD60A8187CAF55D1B29BF81AFE4B3D35DF1A7ADFE, 11)

TAG = "zeroj.pedersen.v1.H"
H_COUNTER_BOUND = 1_000_000

# --------------------------------------------------------------------------------------
# Values pinned by the spec, transcribed by hand from docs/specs/pedersen-jubjub-v1.md.
# They are compared against, never used as inputs.
# --------------------------------------------------------------------------------------

SPEC = {
    # section 2.1
    "g_u": 0x3EA5C4673A121CA35ED37EE3B172F5EE04315C657FBE375F512DFEA318D56FE5,
    "g_v": 0x57137B83EA6EDB4F78F7D30D3F616CB3B9AA6E8E40808413C10CEA38D50C55CB,
    "g_encoding": "cb550cd538ea0cc1138480408e6eaab9b36c613f0dd3f7784fdb6eea837b13d7",
    # section 2.2 known answers
    "poseidon2_0_0": 0x57C7E6CEA4C40C3956E13AE6F8D644EDFF6F14577A581058EAA651B4675C7156,
    "poseidon2_1_2": 0x28CE19420FC246A05553AD1E8C98F5C9D67166BE2C18E9E4CB4B4E317DD2A78A,
    "poseidon2_123_456": 0x6EADB49364FF22D841D40765EF4AC418F19467E8511541850AEBF2936338A0FA,
    # section 2.3
    "h_a": 0x7A65726F6A2E706564657273656E2E76312E48,
    "h_counter": 1,
    "h_u": 0x72963E7766B3CD553A1525A17DA810E6B4CDEB70541DAC5B52A3210F5C372DB6,
    "h_v": 0x60BB97D81759E04503194AEB9EB8FAA23B0092C941D1139BFE99907794C8E37D,
    "h_encoding": "7de3c894779099fe9b13d141c992003ba2fab89eeb4a190345e05917d897bb60",
    # section 8
    "c_42_12345_u": 0x478A0BD6A0EEBDFFC610618AD979B39D6237F240125534886D38720CBD76A025,
    "c_42_12345_v": 0x6387C33BE7B7177B74CE909592456D7C81DAB375A6BA3182EB7F5E2974E0D357,
    "c_42_12345_encoding": "57d3e074295e7feb8231baa675b3da817c6d45929590ce747b17b7e73bc387e3",
}

HERE = os.path.dirname(os.path.abspath(__file__))
SAGE_OUTPUT = os.path.join(HERE, "..", "poseidon-sage", "sage-reference-output.txt")
OUTPUT_FILE = os.path.join(HERE, "reference-output.txt")


class SelfCheckError(Exception):
    pass


def require(cond, message):
    if not cond:
        raise SelfCheckError(message)


# --------------------------------------------------------------------------------------
# F_p arithmetic
# --------------------------------------------------------------------------------------

def inv(x):
    x %= P
    if x == 0:
        raise ZeroDivisionError("inverse of zero in F_p")
    return pow(x, P - 2, P)


def is_square(x):
    """Euler's criterion. Zero counts as a square."""
    x %= P
    return x == 0 or pow(x, (P - 1) // 2, P) == 1


def _find_non_residue():
    z = 2
    while pow(z, (P - 1) // 2, P) != P - 1:
        z += 1
    return z


def sqrt_mod(n):
    """Tonelli-Shanks. Returns some square root of n, or None if n is a non-residue."""
    n %= P
    if n == 0:
        return 0
    if pow(n, (P - 1) // 2, P) != 1:
        return None
    q, s = P - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = _find_non_residue()
    m, c, t, r = s, pow(z, q, P), pow(n, q, P), pow(n, (q + 1) // 2, P)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % P
            i += 1
            if i == m:
                raise SelfCheckError("Tonelli-Shanks failed to converge")
        b = pow(c, 1 << (m - i - 1), P)
        m, c, t, r = i, b * b % P, t * b * b % P, r * b % P
    require(r * r % P == n, "sqrt_mod produced a wrong root")
    return r


# --------------------------------------------------------------------------------------
# Poseidon (t=3, alpha=5, RF=8, RP=57) — port of poseidon_bls12_381_reference.sage
# --------------------------------------------------------------------------------------

FIELD_SIZE = 255
NUM_CELLS = 3
ALPHA = 5
R_F = 8
R_P = 57


class Grain:
    """hadeshash Grain LFSR in self-shrinking mode, as in the Sage reference."""

    def __init__(self, field, sbox, n, t, r_f, r_p):
        def bits(value, width):
            return [int(ch) for ch in bin(value)[2:].zfill(width)]

        self.state = (bits(field, 2) + bits(sbox, 4) + bits(n, 12) + bits(t, 12)
                      + bits(r_f, 10) + bits(r_p, 10) + [1] * 30)
        assert len(self.state) == 80
        for _ in range(160):
            self._step()

    def _step(self):
        s = self.state
        new_bit = s[62] ^ s[51] ^ s[38] ^ s[23] ^ s[13] ^ s[0]
        s.pop(0)
        s.append(new_bit)
        return new_bit

    def next_bit(self):
        # Identical control flow to grain_sr_generator() in the Sage reference.
        new_bit = self._step()
        while new_bit == 0:
            self._step()
            new_bit = self._step()
        return self._step()

    def random_bits(self, num_bits):
        value = 0
        for _ in range(num_bits):
            value = (value << 1) | self.next_bit()  # first bit is the most significant
        return value


def poseidon_parameters():
    grain = Grain(1, 0, FIELD_SIZE, NUM_CELLS, R_F, R_P)  # arguments "1 0 255 3 8 57 <p>"
    constants = []
    for _ in range((R_F + R_P) * NUM_CELLS):
        value = grain.random_bits(FIELD_SIZE)
        while value >= P:
            value = grain.random_bits(FIELD_SIZE)
        constants.append(value)
    while True:  # create_mds_p
        rand_list = [grain.random_bits(FIELD_SIZE) % P for _ in range(2 * NUM_CELLS)]
        while len(rand_list) != len(set(rand_list)):
            rand_list = [grain.random_bits(FIELD_SIZE) % P for _ in range(2 * NUM_CELLS)]
        xs, ys = rand_list[:NUM_CELLS], rand_list[NUM_CELLS:]
        if any((x + y) % P == 0 for x in xs for y in ys):
            continue
        mds = [[inv(xs[i] + ys[j]) for j in range(NUM_CELLS)] for i in range(NUM_CELLS)]
        return constants, mds


def poseidon2(a, b, constants, mds, column_vector=True):
    """Spec section 2.2. column_vector=True multiplies M * state (the Sage convention);
    False multiplies state * M and exists only to show which orientation the KATs pin."""
    state = [0, a % P, b % P]
    for r in range(R_F + R_P):
        for j in range(NUM_CELLS):
            state[j] = (state[j] + constants[r * NUM_CELLS + j]) % P
        if r < R_F // 2 or r >= R_F // 2 + R_P:
            state = [pow(x, ALPHA, P) for x in state]
        else:
            state[0] = pow(state[0], ALPHA, P)
        if column_vector:
            state = [sum(mds[i][j] * state[j] for j in range(NUM_CELLS)) % P
                     for i in range(NUM_CELLS)]
        else:
            state = [sum(state[i] * mds[i][j] for i in range(NUM_CELLS)) % P
                     for j in range(NUM_CELLS)]
    return state[0]


def load_sage_reference():
    if not os.path.isfile(SAGE_OUTPUT):
        raise SelfCheckError("Sage reference output not found: " + SAGE_OUTPUT)
    rc, mds, kat = {}, {}, {}
    with open(SAGE_OUTPUT, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("C[") and "=" in line:
                idx = int(line[2:line.index("]")])
                rc[idx] = int(line.split("=")[1].strip(), 16)
            elif line.startswith("M[") and "=" in line:
                i = int(line[2])
                j = int(line[5])
                mds[(i, j)] = int(line.split("=")[1].strip(), 16)
            elif line.startswith("Poseidon(") and "=" in line:
                args = line[len("Poseidon("):line.index(")")]
                a_str, b_str = [s.strip() for s in args.split(",")]
                kat[(int(a_str), int(b_str))] = int(line.split("=")[1].strip(), 16)
    require(sorted(rc) == list(range(6)), "Sage output: expected C[0..5]")
    require(len(mds) == 9, "Sage output: expected a 3x3 MDS matrix")
    require(sorted(kat) == [(0, 0), (1, 2), (123, 456)], "Sage output: expected 3 KATs")
    return rc, mds, kat


# --------------------------------------------------------------------------------------
# Jubjub arithmetic (affine twisted Edwards, a = -1). Points are (u, v) tuples.
# --------------------------------------------------------------------------------------

IDENTITY = (0, 1)


def on_curve(pt):
    u, v = pt
    uu, vv = u * u % P, v * v % P
    return (A_EDWARDS * uu + vv - 1 - D * uu * vv) % P == 0


def point_add(p1, p2):
    """Unified affine addition: u3 = (u1 v2 + v1 u2)/(1 + d u1 u2 v1 v2),
    v3 = (v1 v2 - a u1 u2)/(1 - d u1 u2 v1 v2)."""
    u1, v1 = p1
    u2, v2 = p2
    t = D * u1 * u2 % P * v1 * v2 % P
    u3 = (u1 * v2 + v1 * u2) * inv(1 + t) % P
    v3 = (v1 * v2 - A_EDWARDS * u1 * u2) * inv(1 - t) % P
    return (u3, v3)


def point_double(pt):
    """Dedicated doubling: u3 = 2uv/(a u^2 + v^2), v3 = (v^2 - a u^2)/(2 - a u^2 - v^2)."""
    u, v = pt
    au2 = A_EDWARDS * u * u % P
    vv = v * v % P
    u3 = 2 * u * v * inv(au2 + vv) % P
    v3 = (vv - au2) * inv(2 - au2 - vv) % P
    return (u3, v3)


def point_neg(pt):
    return ((-pt[0]) % P, pt[1])


def scalar_mul(k, pt):
    """Left-to-right double-and-add for k >= 0."""
    if k < 0:
        raise ValueError("negative scalar")
    acc = IDENTITY
    for bit in bin(k)[2:]:
        acc = point_double(acc)
        if bit == "1":
            acc = point_add(acc, pt)
    return acc


def scalar_mul_add_only(k, pt):
    """Right-to-left multiplication that never calls point_double (differential check)."""
    acc, base = IDENTITY, pt
    while k:
        if k & 1:
            acc = point_add(acc, base)
        base = point_add(base, base)
        k >>= 1
    return acc


def in_subgroup(pt):
    return scalar_mul(L, pt) == IDENTITY


def point_order(pt):
    for k in (1, 2, 4, 8, L, 2 * L, 4 * L, 8 * L):
        if scalar_mul(k, pt) == IDENTITY:
            return k
    raise SelfCheckError("point order does not divide 8*l")


# --------------------------------------------------------------------------------------
# Spec section 4: encoding
# --------------------------------------------------------------------------------------

def encode(pt):
    u, v = pt
    out = bytearray(v.to_bytes(32, "little"))
    if u & 1:
        out[31] |= 0x80
    return bytes(out)


def decode(data):
    """Returns (point, "ok") or (None, reason). Rules in the order spec section 4 lists them."""
    if len(data) != 32:
        return None, "reject_length"
    sign = data[31] >> 7
    buf = bytearray(data)
    buf[31] &= 0x7F
    v = int.from_bytes(buf, "little")
    if v >= P:
        return None, "reject_noncanonical_v"
    vv = v * v % P
    den = (D * vv + 1) % P
    if den == 0:
        return None, "reject_denominator_zero"
    w = (vv - 1) * inv(den) % P
    u = sqrt_mod(w)
    if u is None:
        return None, "reject_non_square"
    if u == 0 and sign == 1:
        return None, "reject_u_zero_sign_set"
    if (u & 1) != sign:
        u = P - u
    return (u, v), "ok"


# --------------------------------------------------------------------------------------
# Spec section 2.3: derivation of H
# --------------------------------------------------------------------------------------

def derive_h(constants, mds):
    a = int.from_bytes(TAG.encode("utf-8"), "big") % P
    trace = []
    for counter in range(H_COUNTER_BOUND):
        v = poseidon2(a, counter, constants, mds)
        num = (v * v - 1) % P
        den = (D * v * v + 1) % P
        if den == 0:
            trace.append((counter, v, "denominator_zero"))
            continue
        w = num * inv(den) % P
        if w != 0 and not is_square(w):
            trace.append((counter, v, "non_residue"))
            continue
        u = sqrt_mod(w)  # 0 when w == 0
        u = min(u, P - u)
        preimage = (u, v)
        require(on_curve(preimage), "H preimage is not on the curve")
        point = scalar_mul(COFACTOR, preimage)
        if point == IDENTITY:
            trace.append((counter, v, "identity_after_clearing"))
            continue
        trace.append((counter, v, "success"))
        return a, counter, preimage, point, trace
    raise SelfCheckError("H derivation did not succeed below the counter bound")


# --------------------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------------------

def fe_hex(x):
    """Field element / coordinate: 0x + 64 lowercase hex digits."""
    return "0x%064x" % x


def int_hex(x):
    """Integer: 0x + minimal lowercase hex."""
    return "0x%x" % x


def b_hex(data):
    return data.hex()


def tf(flag):
    return "true" if flag else "false"


def main():
    lines = []
    failures = []

    def out(key, value):
        lines.append("%s=%s" % (key, value))

    def check(key, flag):
        out(key, tf(flag))
        if not flag:
            failures.append(key)

    # ---------------- curve sanity ----------------
    out("profile", "pedersen-jubjub-v1")
    out("curve.p", fe_hex(P))
    out("curve.l", fe_hex(L))
    out("curve.a", fe_hex(A_EDWARDS))
    out("curve.d", fe_hex(D))
    out("curve.cofactor", int_hex(COFACTOR))
    check("check.d_equals_minus_10240_div_10241", D == (-10240) * inv(10241) % P)
    check("check.d_is_non_square", not is_square(D))
    check("check.minus_one_is_square", is_square(P - 1))
    # Rule 3 of section 4 needs v^2 = -1/d, which is a square iff d is (since -1 is a square).
    check("check.decode_rule3_unreachable", not is_square((P - 1) * inv(D)))

    # ---------------- Poseidon self-check (fails loudly) ----------------
    constants, mds = poseidon_parameters()
    sage_rc, sage_mds, sage_kat = load_sage_reference()
    out("poseidon.round_constants_count", int_hex(len(constants)))
    for i in range(6):
        out("poseidon.rc.%d" % i, fe_hex(constants[i]))
    for i in range(3):
        for j in range(3):
            out("poseidon.mds.%d.%d" % (i, j), fe_hex(mds[i][j]))
    rc_ok = all(constants[i] == sage_rc[i] for i in range(6))
    mds_ok = all(mds[i][j] == sage_mds[(i, j)] for i in range(3) for j in range(3))
    kat = {k: poseidon2(k[0], k[1], constants, mds) for k in sorted(sage_kat)}
    for (a, b), h in kat.items():
        out("poseidon2.%d_%d" % (a, b), fe_hex(h))
    kat_ok = all(kat[k] == sage_kat[k] for k in sage_kat)
    out("selfcheck.poseidon_round_constants", tf(rc_ok))
    out("selfcheck.poseidon_mds", tf(mds_ok))
    out("selfcheck.poseidon_kat", tf(kat_ok))
    if not (rc_ok and mds_ok and kat_ok):
        sys.stdout.write("\n".join(lines) + "\n")
        raise SelfCheckError("Poseidon port does not reproduce sage-reference-output.txt")
    row_vector_ok = all(poseidon2(a, b, constants, mds, column_vector=False) == sage_kat[(a, b)]
                        for (a, b) in sage_kat)
    out("info.poseidon_state_times_m_matches_kat", tf(row_vector_ok))

    # ---------------- Jubjub arithmetic self-checks ----------------
    check("check.g_full_on_curve", on_curve(G_FULL))
    g_full_order = point_order(G_FULL)
    out("g_full.u", fe_hex(G_FULL[0]))
    out("g_full.v", fe_hex(G_FULL[1]))
    out("g_full.order", int_hex(g_full_order))
    check("selfcheck.double_vs_add_differential",
          all(scalar_mul(k, G_FULL) == scalar_mul_add_only(k, G_FULL)
              for k in (0, 1, 2, 3, 8, 12345, L - 1, L, L + 1)))
    check("selfcheck.p_plus_neg_p_is_identity",
          point_add(G_FULL, point_neg(G_FULL)) == IDENTITY)

    # ---------------- section 2.1: G ----------------
    G = scalar_mul(COFACTOR, G_FULL)
    out("g.u", fe_hex(G[0]))
    out("g.v", fe_hex(G[1]))
    out("g.encoding", b_hex(encode(G)))
    check("check.g_on_curve", on_curve(G))
    check("check.g_in_subgroup", in_subgroup(G))
    check("check.g_not_identity", G != IDENTITY)

    # ---------------- section 2.3: H ----------------
    a, counter, preimage, H, trace = derive_h(constants, mds)
    out("h.tag", TAG)
    out("h.tag_utf8", b_hex(TAG.encode("utf-8")))
    out("h.a", int_hex(a))
    for c, v, outcome in trace:
        out("h.attempt.%d.v" % c, fe_hex(v))
        out("h.attempt.%d.outcome" % c, outcome)
    out("h.counter", int_hex(counter))
    out("h.preimage.u", fe_hex(preimage[0]))
    out("h.preimage.v", fe_hex(preimage[1]))
    out("h.u", fe_hex(H[0]))
    out("h.v", fe_hex(H[1]))
    out("h.encoding", b_hex(encode(H)))
    check("check.h_on_curve", on_curve(H))
    check("check.h_in_subgroup", in_subgroup(H))
    check("check.h_not_identity", H != IDENTITY)
    check("check.h_not_g", H != G)

    # ---------------- section 3: commitments ----------------
    def commit(v, r):
        return point_add(scalar_mul(v % L, G), scalar_mul(r % L, H))

    big_r = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCD
    cases = [
        ("c_42_12345", 42, 12345),
        ("c_0_0", 0, 0),
        ("c_1_0", 1, 0),
        ("c_0_1", 0, 1),
        ("c_lm1_17", L - 1, 17),
        ("c_1_23", 1, 23),
        ("c_0_40", 0, 40),
        ("c_2p64m1_bigr", 2 ** 64 - 1, big_r),
        ("c_l_5", L, 5),
        ("c_0_5", 0, 5),
    ]
    commits = {}
    computed_points = [("g_full", G_FULL), ("g", G), ("h", H)]
    for name, v, r in cases:
        C = commit(v, r)
        commits[name] = C
        out("commit.%s.value" % name, int_hex(v))
        out("commit.%s.blinding" % name, int_hex(r))
        out("commit.%s.value_mod_l" % name, int_hex(v % L))
        out("commit.%s.blinding_mod_l" % name, int_hex(r % L))
        out("commit.%s.u" % name, fe_hex(C[0]))
        out("commit.%s.v" % name, fe_hex(C[1]))
        out("commit.%s.encoding" % name, b_hex(encode(C)))
        computed_points.append(("commit." + name, C))
    check("check.c_0_0_is_identity", commits["c_0_0"] == IDENTITY)
    check("check.c_1_0_equals_g", commits["c_1_0"] == G)
    check("check.c_0_1_equals_h", commits["c_0_1"] == H)
    check("check.homomorphic_c_lm1_17_plus_c_1_23_equals_c_0_40",
          point_add(commits["c_lm1_17"], commits["c_1_23"]) == commits["c_0_40"])
    check("check.residue_c_l_5_equals_c_0_5", commits["c_l_5"] == commits["c_0_5"])
    check("check.commits_in_subgroup", all(in_subgroup(C) for C in commits.values()))

    # ---------------- section 4: round trips ----------------
    for name, pt in computed_points:
        decoded, reason = decode(encode(pt))
        check("roundtrip.%s" % name, reason == "ok" and decoded == pt)

    # ---------------- section 4: negative / subgroup decode vectors ----------------
    # Small-order points, constructed independently of the decoder.
    t2 = (0, P - 1)                                   # order 2
    i_root = sqrt_mod(P - 1)
    t4 = (i_root if i_root % 2 == 0 else P - i_root, 0)  # order 4, even u
    t8 = scalar_mul(L, G_FULL)                        # order 8 if G_full has order 8*l
    require(on_curve(t2) and on_curve(t4) and on_curve(t8), "torsion point not on curve")
    require(point_order(t2) == 2, "t2 order")
    require(point_order(t4) == 4, "t4 order")
    require(point_order(t8) == 8, "t8 order (G_full is expected to have order 8*l)")
    g_plus_t8 = point_add(G, t8)

    def first_non_square_v():
        v = 2
        while True:
            vv = v * v % P
            w = (vv - 1) * inv(D * vv + 1) % P
            if not is_square(w):
                return v
            v += 1

    ns_v = first_non_square_v()
    identity_sign_set = bytearray(encode(IDENTITY))
    identity_sign_set[31] |= 0x80
    t2_sign_set = bytearray(encode(t2))
    t2_sign_set[31] |= 0x80

    negatives = [
        ("length_31", bytes(31), "reject_length", None),
        ("length_33", bytes(33), "reject_length", None),
        ("v_equals_p", P.to_bytes(32, "little"), "reject_noncanonical_v", None),
        ("v_equals_p_plus_1", (P + 1).to_bytes(32, "little"), "reject_noncanonical_v", None),
        ("v_all_ones", b"\xff" * 32, "reject_noncanonical_v", None),
        ("v_non_square", ns_v.to_bytes(32, "little"), "reject_non_square", None),
        ("identity_sign_set", bytes(identity_sign_set), "reject_u_zero_sign_set", None),
        ("order2_sign_set", bytes(t2_sign_set), "reject_u_zero_sign_set", None),
        ("order2_point", encode(t2), "decodes_fails_subgroup", t2),
        ("order4_point", encode(t4), "decodes_fails_subgroup", t4),
        ("order8_point", encode(t8), "decodes_fails_subgroup", t8),
        ("g_plus_order8", encode(g_plus_t8), "decodes_fails_subgroup", g_plus_t8),
    ]
    for name, data, expected, point in negatives:
        decoded, reason = decode(data)
        if reason == "ok":
            observed = "decodes_in_subgroup" if in_subgroup(decoded) else "decodes_fails_subgroup"
        else:
            observed = reason
        out("decode_neg.%s.input" % name, b_hex(data))
        if name == "v_non_square":
            out("decode_neg.%s.v" % name, int_hex(ns_v))
        out("decode_neg.%s.expected" % name, expected)
        out("decode_neg.%s.observed" % name, observed)
        if point is not None:
            out("decode_neg.%s.u" % name, fe_hex(point[0]))
            out("decode_neg.%s.v" % name, fe_hex(point[1]))
            out("decode_neg.%s.order" % name, int_hex(point_order(point)))
            if reason == "ok" and decoded != point:
                observed = "decoded_to_wrong_point"
        check("decode_neg.%s.match" % name, observed == expected)

    # ---------------- comparison against values pinned in the spec ----------------
    computed = {
        "g_u": G[0], "g_v": G[1], "g_encoding": b_hex(encode(G)),
        "poseidon2_0_0": kat[(0, 0)], "poseidon2_1_2": kat[(1, 2)],
        "poseidon2_123_456": kat[(123, 456)],
        "h_a": a, "h_counter": counter,
        "h_u": H[0], "h_v": H[1], "h_encoding": b_hex(encode(H)),
        "c_42_12345_u": commits["c_42_12345"][0],
        "c_42_12345_v": commits["c_42_12345"][1],
        "c_42_12345_encoding": b_hex(encode(commits["c_42_12345"])),
    }
    for key in SPEC:
        check("spec_match_%s" % key, computed[key] == SPEC[key])

    out("result", "pass" if not failures else "fail")

    header = [
        "# pedersen-jubjub-v1 independent reference output (ADR-0051 M0).",
        "# Produced by: python3 pedersen_jubjub_v1_reference.py (run in this directory)",
        "# Python: %s %s, standard library only" % (platform.python_implementation(),
                                                    platform.python_version()),
        "# Written from docs/specs/pedersen-jubjub-v1.md and the Poseidon Sage reference only;",
        "# no ZeroJ Java source was read. See README.md.",
        "# Format: key=value. 0x + 64 hex digits = field element; 0x + minimal hex = integer;",
        "# bare lowercase hex = byte string; true/false = boolean check.",
    ]
    text = "\n".join(header + lines) + "\n"
    sys.stdout.write(text)
    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)

    if failures:
        sys.stderr.write("FAILED checks: %s\n" % ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SelfCheckError as exc:
        sys.stderr.write("SELF-CHECK FAILURE: %s\n" % exc)
        sys.exit(2)
