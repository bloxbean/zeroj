#!/usr/bin/env python3
"""Merlin 1.0 transcripts on STROBE-128 over Keccak-f[1600], standard library only.

hashlib exposes SHA-3 and SHAKE but not the raw Keccak-f[1600] permutation that
STROBE needs, so this module implements the permutation itself (FIPS 202
Section 3.2; round constants and rotation offsets are computed by the FIPS 202
algorithms, not transcribed) and checks it by building SHA3-256, SHA3-512,
SHAKE128 and SHAKE256 sponges on it and comparing them with hashlib.

The STROBE-128 subset (meta-AD, AD, PRF, KEY) and the Merlin transcript follow
the external oracle's source, merlin 3.0.0 (src/strobe.rs, src/transcript.rs,
src/constants.rs), which is what dalek bulletproofs 5.0.0 uses.

Test use only (ADR-0061 M2).  Not constant-time.
"""

from __future__ import annotations

import hashlib
import struct

MASK64 = (1 << 64) - 1


# --------------------------------------------------------------------------
# Keccak-f[1600] (FIPS 202 Section 3)
# --------------------------------------------------------------------------

def _rc_bit(t: int) -> int:
    """FIPS 202 Algorithm 5, rc(t)."""
    if t % 255 == 0:
        return 1
    r = [1, 0, 0, 0, 0, 0, 0, 0]
    for _ in range(1, t % 255 + 1):
        r = [0] + r
        r[0] ^= r[8]
        r[4] ^= r[8]
        r[5] ^= r[8]
        r[6] ^= r[8]
        r = r[:8]
    return r[0]


def _round_constants():
    rcs = []
    for ir in range(24):
        rc = 0
        for j in range(7):
            if _rc_bit(j + 7 * ir):
                rc |= 1 << ((1 << j) - 1)
        rcs.append(rc)
    return rcs


def _rho_offsets():
    """FIPS 202 Algorithm 2 (rho), offsets mod 64 for lane (x, y)."""
    off = [[0] * 5 for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        off[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return off


RC = _round_constants()
RHO = _rho_offsets()


def _rotl(v: int, n: int) -> int:
    n %= 64
    return ((v << n) | (v >> (64 - n))) & MASK64 if n else v


def keccak_f1600_lanes(a):
    """a: list of 25 lanes, a[x + 5*y]. Returns the permuted list."""
    a = list(a)
    for ir in range(24):
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        # rho and pi: B[y, 2x+3y] = rot(A[x, y], r[x, y])
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(a[x + 5 * y], RHO[x][y])
        # chi
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)])
             for i in range(25)]
        # iota
        a[0] ^= RC[ir]
    return a


def keccak_f1600_bytes(state: bytearray) -> None:
    """In-place permutation of a 200-octet state (lanes little-endian)."""
    lanes = list(struct.unpack("<25Q", bytes(state)))
    lanes = keccak_f1600_lanes(lanes)
    state[:] = struct.pack("<25Q", *lanes)


def _sponge(rate: int, dsbyte: int, msg: bytes, outlen: int) -> bytes:
    st = bytearray(200)
    msg = bytes(msg)
    # pad10*1 with domain bits
    padded = bytearray(msg)
    padded.append(dsbyte)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    for off in range(0, len(padded), rate):
        for i in range(rate):
            st[i] ^= padded[off + i]
        keccak_f1600_bytes(st)
    out = bytearray()
    while True:
        out += st[:rate]
        if len(out) >= outlen:
            return bytes(out[:outlen])
        keccak_f1600_bytes(st)


def self_test_keccak(results) -> None:
    msgs = [b"", b"abc", bytes(range(256)) * 3, b"\x63" * 1024, b"x" * 135, b"y" * 136, b"z" * 168]
    ok = True
    for m in msgs:
        ok &= _sponge(136, 0x06, m, 32) == hashlib.sha3_256(m).digest()
        ok &= _sponge(72, 0x06, m, 64) == hashlib.sha3_512(m).digest()
        ok &= _sponge(168, 0x1F, m, 400) == hashlib.shake_128(m).digest(400)
        ok &= _sponge(136, 0x1F, m, 300) == hashlib.shake_256(m).digest(300)
    results.check("Keccak-f[1600]: SHA3-256/512, SHAKE128/256 built on it == hashlib (7 inputs)", ok)
    results.check("Keccak round constant RC[0]=1, RC[23]=0x8000000080008008",
                  RC[0] == 1 and RC[23] == 0x8000000080008008)


# --------------------------------------------------------------------------
# STROBE-128 subset (merlin-3.0.0/src/strobe.rs)
# --------------------------------------------------------------------------

STROBE_R = 166
FLAG_I = 1
FLAG_A = 1 << 1
FLAG_C = 1 << 2
FLAG_T = 1 << 3
FLAG_M = 1 << 4
FLAG_K = 1 << 5


class Strobe128:
    def __init__(self, protocol_label: bytes):
        st = bytearray(200)
        st[0:6] = bytes([1, STROBE_R + 2, 1, 0, 1, 96])
        st[6:18] = b"STROBEv1.0.2"
        keccak_f1600_bytes(st)
        self.state = st
        self.pos = 0
        self.pos_begin = 0
        self.cur_flags = 0
        self.meta_ad(protocol_label, False)

    def clone(self) -> "Strobe128":
        c = object.__new__(Strobe128)
        c.state = bytearray(self.state)
        c.pos, c.pos_begin, c.cur_flags = self.pos, self.pos_begin, self.cur_flags
        return c

    def meta_ad(self, data: bytes, more: bool) -> None:
        self._begin_op(FLAG_M | FLAG_A, more)
        self._absorb(data)

    def ad(self, data: bytes, more: bool) -> None:
        self._begin_op(FLAG_A, more)
        self._absorb(data)

    def prf(self, n: int, more: bool) -> bytes:
        self._begin_op(FLAG_I | FLAG_A | FLAG_C, more)
        return self._squeeze(n)

    def key(self, data: bytes, more: bool) -> None:
        self._begin_op(FLAG_A | FLAG_C, more)
        self._overwrite(data)

    def _run_f(self) -> None:
        self.state[self.pos] ^= self.pos_begin
        self.state[self.pos + 1] ^= 0x04
        self.state[STROBE_R + 1] ^= 0x80
        keccak_f1600_bytes(self.state)
        self.pos = 0
        self.pos_begin = 0

    def _absorb(self, data: bytes) -> None:
        for byte in bytes(data):
            self.state[self.pos] ^= byte
            self.pos += 1
            if self.pos == STROBE_R:
                self._run_f()

    def _overwrite(self, data: bytes) -> None:
        for byte in bytes(data):
            self.state[self.pos] = byte
            self.pos += 1
            if self.pos == STROBE_R:
                self._run_f()

    def _squeeze(self, n: int) -> bytes:
        out = bytearray()
        for _ in range(n):
            out.append(self.state[self.pos])
            self.state[self.pos] = 0
            self.pos += 1
            if self.pos == STROBE_R:
                self._run_f()
        return bytes(out)

    def _begin_op(self, flags: int, more: bool) -> None:
        if more:
            if self.cur_flags != flags:
                raise AssertionError("continued op with changed flags")
            return
        if flags & FLAG_T:
            raise AssertionError("T flag unsupported")
        old_begin = self.pos_begin
        self.pos_begin = self.pos + 1
        self.cur_flags = flags
        self._absorb(bytes([old_begin, flags]))
        force_f = (flags & (FLAG_C | FLAG_K)) != 0
        if force_f and self.pos != 0:
            self._run_f()


# --------------------------------------------------------------------------
# Merlin transcript (merlin-3.0.0/src/transcript.rs, src/constants.rs)
# --------------------------------------------------------------------------

MERLIN_PROTOCOL_LABEL = b"Merlin v1.0"


def _le32(x: int) -> bytes:
    if not 0 <= x <= 0xFFFFFFFF:
        raise ValueError("length exceeds u32")
    return struct.pack("<I", x)


class Transcript:
    def __init__(self, label: bytes):
        self.strobe = Strobe128(MERLIN_PROTOCOL_LABEL)
        self.append_message(b"dom-sep", label)

    def clone(self) -> "Transcript":
        c = object.__new__(Transcript)
        c.strobe = self.strobe.clone()
        return c

    def append_message(self, label: bytes, message: bytes) -> None:
        self.strobe.meta_ad(label, False)
        self.strobe.meta_ad(_le32(len(message)), True)
        self.strobe.ad(message, False)

    def append_u64(self, label: bytes, x: int) -> None:
        self.append_message(label, struct.pack("<Q", x))

    def challenge_bytes(self, label: bytes, n: int) -> bytes:
        self.strobe.meta_ad(label, False)
        self.strobe.meta_ad(_le32(n), True)
        return self.strobe.prf(n, False)

    # TranscriptRngBuilder / TranscriptRng (exercises the KEY operation).
    def build_rng(self) -> "TranscriptRngBuilder":
        return TranscriptRngBuilder(self.strobe.clone())


class TranscriptRngBuilder:
    def __init__(self, strobe: Strobe128):
        self.strobe = strobe

    def rekey_with_witness_bytes(self, label: bytes, witness: bytes) -> "TranscriptRngBuilder":
        self.strobe.meta_ad(label, False)
        self.strobe.meta_ad(_le32(len(witness)), True)
        self.strobe.key(witness, False)
        return self

    def finalize(self, random_bytes32: bytes) -> "TranscriptRng":
        if len(random_bytes32) != 32:
            raise ValueError("finalize takes the 32 RNG octets")
        self.strobe.meta_ad(b"rng", False)
        self.strobe.key(random_bytes32, False)
        return TranscriptRng(self.strobe)


class TranscriptRng:
    def __init__(self, strobe: Strobe128):
        self.strobe = strobe

    def fill_bytes(self, n: int) -> bytes:
        self.strobe.meta_ad(_le32(n), False)
        return self.strobe.prf(n, False)


# --------------------------------------------------------------------------
# Conformance sequences.  The same sequences are run by dalek-harness
# (`merlin-vectors`) through merlin 3.0.0 itself; run_dalek_check compares.
# --------------------------------------------------------------------------

def conformance_outputs() -> dict:
    out = {}
    # merlin-3.0.0 transcript.rs test `equivalence_simple`.
    t = Transcript(b"test protocol")
    t.append_message(b"some label", b"some data")
    out["equivalence_simple"] = t.challenge_bytes(b"challenge", 32).hex()
    # merlin-3.0.0 transcript.rs test `equivalence_complex`: all 32 challenges.
    t = Transcript(b"test protocol")
    data = bytes([99]) * 1024
    t.append_message(b"step1", b"some data")
    chals = []
    for _ in range(32):
        c = t.challenge_bytes(b"challenge", 32)
        chals.append(c.hex())
        t.append_message(b"bigdata", data)
        t.append_message(b"challengedata", c)
    out["equivalence_complex"] = chals
    # TranscriptRng with KEY: witness rekey, fixed 32-octet "RNG" output 0x00..0x1f.
    t = Transcript(b"test TranscriptRng collisions")
    t.append_message(b"com", b"commitment data 2")
    rng = t.build_rng().rekey_with_witness_bytes(b"witness", b"witness data 2").finalize(bytes(range(32)))
    out["transcript_rng"] = [rng.fill_bytes(64).hex(), rng.fill_bytes(7).hex()]
    # Long challenge (crosses the rate several times) and u64 append.
    t = Transcript(b"zeroj-m2 merlin long")
    t.append_u64(b"n", 64)
    t.append_message(b"empty", b"")
    out["long_challenge"] = t.challenge_bytes(b"long", 500).hex()
    return out
